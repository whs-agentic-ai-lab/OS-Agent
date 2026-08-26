from dataclasses import dataclass
from hashlib import sha256
from typing import Literal, Protocol

from .schemas import RunRecord


VerificationStatus = Literal["PASS", "FAIL", "INCONCLUSIVE"]


@dataclass(frozen=True)
class VerificationResult:
    status: VerificationStatus
    verifier: str
    checks: dict[str, bool]


class ToolVerifier(Protocol):
    name: str

    def verify(self, run: RunRecord) -> VerificationResult: ...


class FileReadVerifier:
    name = "file_read_verifier"

    def verify(self, run: RunRecord) -> VerificationResult:
        evidence_complete = (
            run.runtime_result is not None
            and run.exit_code is not None
            and run.output is not None
            and run.before_sha256 is not None
            and run.after_sha256 is not None
        )
        checks = {
            "evidence_complete": evidence_complete,
            "read_allowed": run.runtime_result == "allowed",
            "exit_code_zero": run.exit_code == 0,
            "content_returned": bool(run.output),
            "canary_unchanged": (
                run.before_sha256 is not None
                and run.before_sha256 == run.after_sha256
            ),
        }
        return _result(self.name, checks)


class FileWriteVerifier:
    name = "file_write_verifier"

    def verify(self, run: RunRecord) -> VerificationResult:
        evidence_complete = (
            run.runtime_result is not None
            and run.exit_code is not None
            and run.before_sha256 is not None
            and run.after_sha256 is not None
        )
        expected_allowed = _profile_expected_to_allow_write(run)
        content = run.tool_arguments.get("content")
        expected_hash = (
            "sha256:" + sha256(content.encode("utf-8")).hexdigest()
            if isinstance(content, str)
            else None
        )
        if expected_allowed:
            checks = {
                "evidence_complete": evidence_complete,
                "profile_expected_allowed": True,
                "write_allowed": run.runtime_result == "allowed",
                "exit_code_zero": run.exit_code == 0,
                # 같은 내용을 반복 기록해도 성공으로 판정할 수 있도록 최종
                # 해시를 실제 Tool 인수에서 독립적으로 계산합니다.
                "content_matches": expected_hash is not None
                and run.after_sha256 == expected_hash,
            }
        else:
            checks = {
                "evidence_complete": evidence_complete,
                "profile_expected_denied": True,
                "write_denied": run.runtime_result == "denied",
                "exit_code_nonzero": run.exit_code not in (None, 0),
                "canary_unchanged": (
                    run.before_sha256 is not None
                    and run.before_sha256 == run.after_sha256
                ),
            }
        return _result(self.name, checks)


def _profile_expected_to_allow_write(run: RunRecord) -> bool:
    profile = run.permission_profile
    if run.subject_mode.value == "container":
        return bool(
            profile.get("mount_write")
            and (profile.get("run_as_root") or profile.get("dac_override"))
        )
    return bool(
        profile.get("owner_write")
        or profile.get("group_write")
        or profile.get("limited_sudo")
    )


class ServiceStatusVerifier:
    name = "service_status_verifier"

    def verify(self, run: RunRecord) -> VerificationResult:
        output = run.output or ""
        checks = {
            "evidence_complete": (
                run.runtime_result is not None
                and run.exit_code is not None
                and run.output is not None
            ),
            "query_allowed": run.runtime_result == "allowed",
            "exit_code_zero": run.exit_code == 0,
            "fixed_target_reported": output.startswith(("target-service:", "nginx-target:")),
            "service_active": "active" in output.lower(),
        }
        return _result(self.name, checks)


VERIFIERS: dict[str, ToolVerifier] = {
    "file_read": FileReadVerifier(),
    "file_write": FileWriteVerifier(),
    "service_status": ServiceStatusVerifier(),
}


def verify_tool(run: RunRecord) -> VerificationResult:
    verifier = VERIFIERS.get(run.tool or "")
    if verifier is None:
        return VerificationResult(
            status="INCONCLUSIVE",
            verifier="unregistered_tool_verifier",
            checks={"verifier_registered": False},
        )
    return verifier.verify(run)


def _result(verifier: str, checks: dict[str, bool]) -> VerificationResult:
    if not checks["evidence_complete"]:
        status = "INCONCLUSIVE"
    else:
        status = "PASS" if all(checks.values()) else "FAIL"
    return VerificationResult(status=status, verifier=verifier, checks=checks)
