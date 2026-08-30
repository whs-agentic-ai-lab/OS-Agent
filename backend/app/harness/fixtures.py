from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from typing import Any

from .models import (
    ActionCandidate,
    HarnessBudgetState,
    HarnessRunRequest,
    PlannerDecision,
    ResetRecord,
    ToolExecution,
    VerificationRecord,
)
from .ports import HarnessComponents


FIXTURE_PROFILES: dict[str, dict[str, Any]] = {
    "fixture-container-readonly": {
        "subject_mode": "container",
        "can_read": True,
        "can_write": False,
        "can_query_service": True,
    },
    "fixture-container-write": {
        "subject_mode": "container",
        "can_read": True,
        "can_write": True,
        "can_query_service": True,
    },
    "fixture-host-readonly": {
        "subject_mode": "host",
        "can_read": True,
        "can_write": False,
        "can_query_service": True,
    },
    "fixture-host-write": {
        "subject_mode": "host",
        "can_read": True,
        "can_write": True,
        "can_query_service": True,
    },
}

DEFAULT_FIXTURE_PROFILE: dict[str, str] = {
    "container": "fixture-container-readonly",
    "host": "fixture-host-readonly",
}


@dataclass
class FixtureRuntimeState:
    baseline: str = "OS_AGENT_HARNESS_FIXTURE_BASELINE"

    def __post_init__(self) -> None:
        self.canary = self.baseline
        self.service_active = True
        self.lock = Lock()

    def restore(self) -> None:
        with self.lock:
            self.canary = self.baseline


class FixturePermissionProvider:
    def __init__(self, runtime: FixtureRuntimeState) -> None:
        self.runtime = runtime

    def snapshot(self, request: HarnessRunRequest) -> dict[str, Any]:
        profile_id = request.permission_profile_id or DEFAULT_FIXTURE_PROFILE[
            request.subject_mode.value
        ]
        profile = FIXTURE_PROFILES.get(profile_id)
        if profile is None:
            raise ValueError("등록되지 않은 Fixture 권한 프로파일입니다.")
        if profile["subject_mode"] != request.subject_mode.value:
            raise ValueError("Fixture 권한 프로파일의 실행 경계가 요청과 다릅니다.")
        self.runtime.restore()
        return {
            "provider": "fixture",
            "profile_id": profile_id,
            **profile,
        }


class FixtureToolCatalog:
    _definitions: tuple[ActionCandidate, ...] = (
        ActionCandidate(
            candidate_id="fixture-read-canary",
            tool_name="fixture_file_read",
            arguments={"resource_id": "fixture-canary"},
            argument_schema={
                "type": "object",
                "properties": {"resource_id": {"type": "string"}},
                "required": ["resource_id"],
                "additionalProperties": False,
            },
            target_resource="fixture-canary",
            risk_level="observe",
            required_evidence=["fixture-read-evidence"],
            verifier_id="fixture-independent-verifier",
        ),
        ActionCandidate(
            candidate_id="fixture-write-canary",
            tool_name="fixture_file_write",
            arguments={
                "resource_id": "fixture-canary",
                "content": "OS_AGENT_HARNESS_FIXTURE_WRITE",
            },
            argument_schema={
                "type": "object",
                "properties": {
                    "resource_id": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["resource_id", "content"],
                "additionalProperties": False,
            },
            target_resource="fixture-canary",
            risk_level="reversible",
            changes_state=True,
            required_evidence=["fixture-write-evidence"],
            verifier_id="fixture-independent-verifier",
            resetter_id="fixture-exact-change-resetter",
        ),
        ActionCandidate(
            candidate_id="fixture-service-status",
            tool_name="fixture_service_status",
            arguments={"service_id": "fixture-service"},
            argument_schema={
                "type": "object",
                "properties": {"service_id": {"type": "string"}},
                "required": ["service_id"],
                "additionalProperties": False,
            },
            target_resource="fixture-service",
            risk_level="observe",
            required_evidence=["fixture-service-evidence"],
            verifier_id="fixture-independent-verifier",
        ),
    )

    def candidates(self, state: dict[str, Any]) -> list[ActionCandidate]:
        completed = {
            item["candidate_id"]
            for item in state.get("history", [])
        }
        return [
            candidate.model_copy(deep=True)
            for candidate in self._definitions
            if candidate.candidate_id not in completed
        ]


class FixturePlanner:
    def select(
        self,
        state: dict[str, Any],
        candidates: list[ActionCandidate],
        budget: HarnessBudgetState,
    ) -> PlannerDecision:
        del state, budget
        return PlannerDecision(
            candidate_id=candidates[0].candidate_id,
            rationale="Fixture Planner는 미실행 Candidate를 등록 순서대로 선택합니다.",
    )
class FixtureExecutor:
    def __init__(self, runtime: FixtureRuntimeState) -> None:
        self.runtime = runtime

    def execute(
        self,
        run_id: str,
        candidate: ActionCandidate,
        state: dict[str, Any],
    ) -> ToolExecution:
        del run_id
        permission = state["permission_snapshot"]
        with self.runtime.lock:
            if candidate.tool_name == "fixture_file_read":
                allowed = bool(permission["can_read"])
                return ToolExecution(
                    success=allowed,
                    output=self.runtime.canary if allowed else "permission denied",
                    error_code=None if allowed else "ACCESS_DENIED",
                    error_message=None if allowed else "permission denied",
                    evidence={
                        "evidence_id": "fixture-runtime-read",
                        "resource_id": "fixture-canary",
                        "value": self.runtime.canary if allowed else None,
                    },
                )

            if candidate.tool_name == "fixture_file_write":
                before = self.runtime.canary
                allowed = bool(permission["can_write"])
                if allowed:
                    self.runtime.canary = str(candidate.arguments["content"])
                return ToolExecution(
                    success=allowed,
                    output="fixture written" if allowed else "permission denied",
                    error_code=None if allowed else "ACCESS_DENIED",
                    error_message=None if allowed else "permission denied",
                    evidence={
                        "evidence_id": "fixture-runtime-write",
                        "resource_id": "fixture-canary",
                        "before": before,
                        "after": self.runtime.canary,
                    },
                )

            if candidate.tool_name == "fixture_service_status":
                allowed = bool(permission["can_query_service"])
                return ToolExecution(
                    success=allowed,
                    output=(
                        "fixture-service: active"
                        if allowed and self.runtime.service_active
                        else "permission denied"
                    ),
                    error_code=None if allowed else "ACCESS_DENIED",
                    error_message=None if allowed else "permission denied",
                    evidence={
                        "evidence_id": "fixture-runtime-service",
                        "resource_id": "fixture-service",
                        "active": self.runtime.service_active if allowed else None,
                    },
                )

        raise ValueError("Fixture Executor에 등록되지 않은 Tool입니다.")


class FixtureVerifier:
    def verify(
        self,
        run_id: str,
        candidate: ActionCandidate,
        execution: ToolExecution,
        state: dict[str, Any],
    ) -> VerificationRecord:
        del run_id
        permission = state["permission_snapshot"]
        expected_allowed = {
            "fixture_file_read": bool(permission["can_read"]),
            "fixture_file_write": bool(permission["can_write"]),
            "fixture_service_status": bool(permission["can_query_service"]),
        }.get(candidate.tool_name)
        if expected_allowed is None:
            return VerificationRecord(
                status="INCONCLUSIVE",
                evidence_refs=["fixture-verifier-unknown"],
                checks={"tool_registered": False},
            )

        outcome_matches = execution.success is expected_allowed
        denial_is_structured = (
            expected_allowed or execution.error_code == "ACCESS_DENIED"
        )
        effect_matches = True
        if candidate.tool_name == "fixture_file_write":
            before = execution.evidence.get("before")
            after = execution.evidence.get("after")
            effect_matches = (
                before != after if expected_allowed else before == after
            )
        if candidate.tool_name == "fixture_service_status" and expected_allowed:
            effect_matches = execution.evidence.get("active") is True

        checks = {
            "outcome_matches_permission": outcome_matches,
            "denial_is_structured": denial_is_structured,
            "effect_matches": effect_matches,
        }
        return VerificationRecord(
            status="VERIFIED" if all(checks.values()) else "REJECTED",
            evidence_refs=[f"fixture-verifier-{candidate.candidate_id}"],
            checks=checks,
        )


class FixtureResetter:
    def __init__(self, runtime: FixtureRuntimeState) -> None:
        self.runtime = runtime

    def reset(
        self,
        run_id: str,
        candidate: ActionCandidate,
        execution: ToolExecution,
        state: dict[str, Any],
    ) -> ResetRecord:
        del run_id, state
        if candidate.tool_name != "fixture_file_write" or not execution.success:
            return ResetRecord(status="NOT_REQUIRED")
        self.runtime.restore()
        return ResetRecord(
            status="RESET",
            recovery_kind="tool_reset",
            strategy_id="fixture-exact-change-resetter",
            evidence_refs=["fixture-reset-canary"],
            restored_state={"resource_id": "fixture-canary", "value": self.runtime.baseline},
        )


def create_fixture_harness_components() -> HarnessComponents:
    runtime = FixtureRuntimeState()
    return HarnessComponents(
        permission_provider=FixturePermissionProvider(runtime),
        tool_catalog=FixtureToolCatalog(),
        planner=FixturePlanner(),
        executor=FixtureExecutor(runtime),
        verifier=FixtureVerifier(),
        resetter=FixtureResetter(runtime),
    )
