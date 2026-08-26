from __future__ import annotations

from typing import Any

from ..catalog import build_profile_id, resolve_trust_boundary
from ..model_gateway import ModelGateway
from ..runtime_client import EnvironmentRuntime
from ..schemas import (
    RunRecord,
    RuntimeAgentResult,
    RuntimeDispatchRequest,
    RuntimeResetRequest,
    SubjectMode,
)
from ..verifiers import verify_tool
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


RUNTIME_ACTION_TOOL = "environment_runtime_agent"
ALLOWED_RUNTIME_TOOLS = {"file_read", "file_write", "service_status"}


class _RuntimeBackedAdapter:
    def __init__(self, runtime: EnvironmentRuntime) -> None:
        self.runtime = runtime

    def is_ready(self) -> bool:
        return self.runtime.is_available()


class OsPermissionProvider(_RuntimeBackedAdapter):
    def snapshot(self, request: HarnessRunRequest) -> dict[str, Any]:
        if not self.runtime.is_available(request.subject_mode):
            raise RuntimeError("선택한 OS Runtime을 사용할 수 없습니다.")
        if request.permission_profile is None:
            raise ValueError("Live Harness에는 완전한 권한 프로파일이 필요합니다.")

        profile = dict(request.permission_profile)
        profile_id = build_profile_id(request.subject_mode, profile)
        boundary = resolve_trust_boundary(
            request.subject_mode,
            request.trust_boundary_id,
        )
        if (
            request.permission_profile_id is not None
            and request.permission_profile_id != profile_id
        ):
            raise ValueError("permission_profile_id가 실제 권한 프로파일과 일치하지 않습니다.")
        return {
            "provider": "os-runtime",
            "subject_mode": request.subject_mode.value,
            "trust_boundary_id": boundary.id,
            "source_environment": boundary.source_environment.value,
            "target_environment": boundary.target_environment.value,
            "profile_id": profile_id,
            "permissions": profile,
            "verified_at_execution": True,
        }


class OsToolCatalog(_RuntimeBackedAdapter):
    def candidates(self, state: dict[str, Any]) -> list[ActionCandidate]:
        if state.get("history"):
            return []
        return [
            ActionCandidate(
                candidate_id="delegate-to-environment-runtime",
                tool_name=RUNTIME_ACTION_TOOL,
                arguments={
                    "objective": state["objective"],
                    "allowed_tools": sorted(ALLOWED_RUNTIME_TOOLS),
                },
                target_resource=f"{state['subject_mode']}-runtime-agent",
                risk_level="reversible",
                changes_state=True,
                required_evidence=[
                    "applied_profile_state",
                    "runtime_result",
                    "tool_output",
                ],
            )
        ]


class OsRuntimePlanner(_RuntimeBackedAdapter):
    def select(
        self,
        state: dict[str, Any],
        candidates: list[ActionCandidate],
        budget: HarnessBudgetState,
    ) -> PlannerDecision:
        del state, budget
        if not candidates:
            return PlannerDecision(
                stop_reason="실행할 Runtime Candidate가 없습니다.",
                rationale="Harness Frontier가 비었습니다.",
            )
        return PlannerDecision(
            candidate_id=candidates[0].candidate_id,
            rationale=(
                "Harness가 Candidate를 선택하고 Backend Model Gateway가 실제 Tool Call을 생성합니다."
            ),
        )


class OsRuntimeExecutor(_RuntimeBackedAdapter):
    def __init__(
        self,
        runtime: EnvironmentRuntime,
        model_gateway: ModelGateway | None = None,
    ) -> None:
        super().__init__(runtime)
        self.model_gateway = model_gateway

    def execute(
        self,
        run_id: str,
        candidate: ActionCandidate,
        state: dict[str, Any],
    ) -> ToolExecution:
        if candidate.tool_name != RUNTIME_ACTION_TOOL:
            raise ValueError("OS Runtime Adapter에 등록되지 않은 Candidate입니다.")
        snapshot = state["permission_snapshot"]
        try:
            boundary = resolve_trust_boundary(
                SubjectMode(state["subject_mode"]),
                snapshot["trust_boundary_id"],
            )
            tool_decision = (
                self.model_gateway.decide(state["objective"], boundary)
                if self.model_gateway is not None
                else ModelGateway._local_decision(state["objective"])
            )
            planner_mode = (
                self.model_gateway.planner_mode
                if self.model_gateway is not None
                else "local"
            )
            result = self.runtime.execute(
                RuntimeDispatchRequest(
                    run_id=run_id,
                    prompt=state["objective"],
                    subject_mode=SubjectMode(state["subject_mode"]),
                    trust_boundary_id=boundary.id,
                    source_environment=boundary.source_environment,
                    target_environment=boundary.target_environment,
                    permission_profile=snapshot["permissions"],
                    profile_id=snapshot["profile_id"],
                    tool_decision=tool_decision,
                    planner_mode=planner_mode,
                )
            )
            if result.trust_boundary_id == "UNASSIGNED":
                result = result.model_copy(
                    update={
                        "trust_boundary_id": boundary.id,
                        "source_environment": boundary.source_environment,
                        "target_environment": boundary.target_environment,
                    }
                )
        except Exception as exc:
            return ToolExecution(
                success=False,
                output=str(exc),
                error_code="RUNTIME_DISPATCH_FAILED",
                retryable=False,
                evidence={
                    "runtime_error": str(exc),
                    "reset_required": True,
                },
            )

        error_code = (
            None
            if result.runtime_result == "allowed"
            else "ACCESS_DENIED"
            if result.runtime_result == "denied"
            else "RUNTIME_ERROR"
        )
        return ToolExecution(
            success=result.runtime_result == "allowed",
            output=result.output,
            error_code=error_code,
            retryable=False,
            evidence={
                "runtime_result": result.model_dump(mode="json"),
                "reset_required": True,
            },
        )


class OsIndependentVerifier(_RuntimeBackedAdapter):
    def verify(
        self,
        run_id: str,
        candidate: ActionCandidate,
        execution: ToolExecution,
        state: dict[str, Any],
    ) -> VerificationRecord:
        del candidate
        raw_result = execution.evidence.get("runtime_result")
        if not isinstance(raw_result, dict):
            return VerificationRecord(
                status="INCONCLUSIVE",
                evidence_refs=[f"runtime:{run_id}:missing"],
                checks={"runtime_evidence_present": False},
            )

        result = RuntimeAgentResult.model_validate(raw_result)
        snapshot = state["permission_snapshot"]
        profile = snapshot["permissions"]
        record = RunRecord(
            run_id=run_id,
            status="VERIFYING",
            prompt=state["objective"],
            subject_mode=SubjectMode(state["subject_mode"]),
            trust_boundary_id=snapshot["trust_boundary_id"],
            source_environment=snapshot["source_environment"],
            target_environment=snapshot["target_environment"],
            permission_profile=profile,
            requested_profile=snapshot["profile_id"],
            applied_profile=result.applied_profile,
            applied_profile_state=result.applied_profile_state,
            planner_mode=result.planner_mode,
            runtime_agent=result.runtime_agent,
            tool=result.tool,
            tool_arguments=result.tool_arguments,
            policy_decision=result.policy_decision,
            authorization_result=result.runtime_result,
            runtime_result=result.runtime_result,
            output=result.output,
            exit_code=result.exit_code,
            before_sha256=result.before_sha256,
            after_sha256=result.after_sha256,
        )
        tool_verification = verify_tool(record)
        checks = {
            "runtime_run_id_matches": result.run_id == run_id,
            "runtime_boundary_matches": result.subject_mode.value == state["subject_mode"],
            "trust_boundary_matches": (
                result.trust_boundary_id == snapshot["trust_boundary_id"]
                and result.source_environment is not None
                and result.source_environment.value == snapshot["source_environment"]
                and result.target_environment is not None
                and result.target_environment.value == snapshot["target_environment"]
            ),
            "profile_id_matches": result.applied_profile == snapshot["profile_id"],
            "profile_state_matches": (
                result.applied_profile_state.get("permissions") == profile
            ),
            "tool_allowlisted": result.tool in ALLOWED_RUNTIME_TOOLS,
            **{
                f"tool_{name}": passed
                for name, passed in tool_verification.checks.items()
            },
        }
        if tool_verification.status == "INCONCLUSIVE":
            status = "INCONCLUSIVE"
        else:
            status = "VERIFIED" if all(checks.values()) else "REJECTED"
        return VerificationRecord(
            status=status,
            evidence_refs=[
                f"runtime:{run_id}:{result.tool}",
                f"verifier:{tool_verification.verifier}",
            ],
            checks=checks,
        )


class OsRuntimeResetter(_RuntimeBackedAdapter):
    def reset(
        self,
        run_id: str,
        candidate: ActionCandidate,
        execution: ToolExecution,
        state: dict[str, Any],
    ) -> ResetRecord:
        del candidate, execution
        try:
            result = self.runtime.reset_harness(
                RuntimeResetRequest(
                    run_id=run_id,
                    subject_mode=SubjectMode(state["subject_mode"]),
                    trust_boundary_id=state.get("trust_boundary_id"),
                    target_environment=state.get("target_environment"),
                )
            )
        except Exception as exc:
            return ResetRecord(
                status="RESET_FAILED",
                evidence_refs=[f"reset:{run_id}:failed"],
                restored_state={"error": str(exc)},
            )
        return ResetRecord(
            status=result.status,
            evidence_refs=result.evidence_refs,
            restored_state=result.restored_state,
        )


def create_os_harness_components(
    runtime: EnvironmentRuntime,
    model_gateway: ModelGateway | None = None,
) -> HarnessComponents:
    return HarnessComponents(
        permission_provider=OsPermissionProvider(runtime),
        tool_catalog=OsToolCatalog(runtime),
        planner=OsRuntimePlanner(runtime),
        executor=OsRuntimeExecutor(runtime, model_gateway),
        verifier=OsIndependentVerifier(runtime),
        resetter=OsRuntimeResetter(runtime),
    )
