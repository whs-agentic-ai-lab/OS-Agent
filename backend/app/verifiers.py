from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Literal, Protocol

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


def _attack_result(run: RunRecord) -> dict[str, Any]:
    value = run.applied_profile_state.get("attack_tool_result", {})
    return value if isinstance(value, dict) else {}


class FileContentVerifier:
    name = "file_content_verifier"

    def verify(self, run: RunRecord) -> VerificationResult:
        action = run.tool_arguments.get("action")
        arguments = run.tool_arguments.get("arguments", {})
        evidence_complete = (
            run.runtime_result is not None
            and run.exit_code is not None
            and run.before_sha256 is not None
            and run.after_sha256 is not None
        )
        if action == "read":
            expected_allowed = (
                run.subject_mode.value == "host"
                or bool(
                    run.permission_profile.get("run_as_root")
                    or run.permission_profile.get("dac_override")
                    or run.permission_profile.get("supplementary_group")
                )
            )
            checks = {
                "evidence_complete": evidence_complete and run.output is not None,
                "profile_expectation_met": (
                    run.runtime_result == "allowed"
                    if expected_allowed
                    else run.runtime_result == "denied"
                ),
                "exit_code_matches": (
                    run.exit_code == 0
                    if expected_allowed
                    else run.exit_code not in (None, 0)
                ),
                "canary_unchanged": run.before_sha256 == run.after_sha256,
            }
            return _result(self.name, checks)

        expected_allowed = _profile_expected_to_allow_write(run)
        if expected_allowed:
            checks = {
                "evidence_complete": evidence_complete,
                "profile_expected_allowed": True,
                "write_allowed": run.runtime_result == "allowed",
                "exit_code_zero": run.exit_code == 0,
                "state_changed": (
                    run.before_sha256 != run.after_sha256
                    or action == "truncate" and run.after_sha256 == _empty_hash()
                ),
            }
            if action == "write":
                content = arguments.get("content") if isinstance(arguments, dict) else None
                expected_hash = (
                    "sha256:" + sha256(content.encode("utf-8")).hexdigest()
                    if isinstance(content, str)
                    else None
                )
                checks["content_matches"] = expected_hash is not None and run.after_sha256 == expected_hash
        else:
            checks = {
                "evidence_complete": evidence_complete,
                "profile_expected_denied": True,
                "write_denied": run.runtime_result == "denied",
                "exit_code_nonzero": run.exit_code not in (None, 0),
                "canary_unchanged": run.before_sha256 == run.after_sha256,
            }
        return _result(self.name, checks)


class FileOpenVerifier(FileContentVerifier):
    """ToolDefinition 기반 읽기 전용 file.open의 독립 결과 판정."""

    name = "file_open_verifier"

    def verify(self, run: RunRecord) -> VerificationResult:
        # 현재 Runtime에는 read만 연결되어 있다. FileContentVerifier의 read
        # 규칙은 동일 Canary와 동일 권한 프로파일을 재확인하므로 그대로 쓴다.
        if run.tool_arguments.get("action") != "read":
            return VerificationResult(
                status="INCONCLUSIVE",
                verifier=self.name,
                checks={"evidence_complete": False, "read_only_pilot": False},
            )
        return super().verify(run)


def _empty_hash() -> str:
    return "sha256:" + sha256(b"").hexdigest()


def _profile_expected_to_allow_write(run: RunRecord) -> bool:
    profile = run.permission_profile
    if run.subject_mode.value == "container":
        return bool(
            profile.get("mount_write")
            and (
                profile.get("run_as_root")
                or profile.get("supplementary_group")
                or profile.get("dac_override")
            )
        )
    return bool(
        profile.get("owner_write")
        or profile.get("group_write")
        or profile.get("dac_override")
    )


class PrivilegeProbeVerifier:
    name = "privilege_probe_verifier"

    def verify(self, run: RunRecord) -> VerificationResult:
        evidence = _attack_result(run)
        before = evidence.get("identity_before")
        after = evidence.get("identity_after")
        outcome = evidence.get("outcome")
        expected_allowed = _privilege_expected_allowed(run)
        checks = {
            "evidence_complete": (
                isinstance(before, dict)
                and isinstance(after, dict)
                and isinstance(outcome, str)
                and isinstance(evidence.get("attempted"), bool)
            ),
            "probe_attempted": evidence.get("attempted") is True,
            "outcome_recorded": outcome in {"ALLOWED", "OS_DENIED", "ERROR"},
            "profile_expectation_met": (
                outcome == "ALLOWED" if expected_allowed else outcome == "OS_DENIED"
            ),
            "initial_identity_restored": before == after,
            "rollback_verified": evidence.get("rollback_status") == "VERIFIED",
            "no_session_handle_returned": "session_handle" not in evidence,
        }
        return _result(self.name, checks)


def _privilege_expected_allowed(run: RunRecord) -> bool:
    action = run.tool_arguments.get("action")
    profile = run.permission_profile
    if run.tool == "privilege.no_new_privs_probe":
        return True
    if run.tool == "sudo.run":
        return bool(
            profile.get("limited_sudo")
            and not profile.get("no_new_privileges")
        )
    if action in {"setuid", "seteuid", "setfsuid"}:
        return bool(profile.get("run_as_root") or profile.get("setuid_capability"))
    if action in {"setgid", "setegid", "setfsgid", "setgroups"}:
        return bool(profile.get("run_as_root") or profile.get("setgid_capability"))
    return False


class ProcfsVerifier:
    name = "process_procfs_verifier"

    def verify(self, run: RunRecord) -> VerificationResult:
        checks = {
            "evidence_complete": (
                run.runtime_result is not None
                and run.exit_code is not None
                and run.output is not None
            ),
            "procfs_allowed": run.runtime_result == "allowed",
            "exit_code_zero": run.exit_code == 0,
            "output_returned": bool(run.output),
        }
        return _result(self.name, checks)


VERIFIERS: dict[str, ToolVerifier] = {
    "file.open": FileOpenVerifier(),
    "file.content": FileContentVerifier(),
    "privilege.identity_probe": PrivilegeProbeVerifier(),
    "privilege.no_new_privs_probe": PrivilegeProbeVerifier(),
    "process.procfs": ProcfsVerifier(),
    "sudo.run": PrivilegeProbeVerifier(),
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
