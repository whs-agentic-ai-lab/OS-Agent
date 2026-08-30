from __future__ import annotations

from typing import Any

from ..attack_tools import IMPLEMENTED_ATTACK_TOOLS
from ..catalog import build_profile_id, resolve_trust_boundary
from ..model_gateway import ModelGateway
from ..runtime_client import EnvironmentRuntime
from ..schemas import (
    RunRecord,
    RuntimeAgentResult,
    RuntimeDispatchRequest,
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
    canonical_hash,
    deterministic_candidate_id,
)
from .ports import HarnessComponents


RUNTIME_ACTION_TOOL = "environment_runtime_agent"
ALLOWED_RUNTIME_TOOLS = set(IMPLEMENTED_ATTACK_TOOLS)
OS_REINITIALIZE_STRATEGY_ID = "approved-environment-reinitialize-v1"
OS_BASELINE_VERSION = "os-experiment-baseline-v1"
OS_BASELINE_CHECKS = [
    "trial_group_member",
    "limited_sudo_rule",
    "docker_group_member",
    "container_run_root_empty",
    "target_canary_sha256",
    "running_containers",
    "healthy_containers",
]


class _RuntimeBackedAdapter:
    def __init__(self, runtime: EnvironmentRuntime) -> None:
        self.runtime = runtime

    def is_ready(self) -> bool:
        return self.runtime.is_available()


class OsPermissionProvider(_RuntimeBackedAdapter):
    def __init__(self, runtime: EnvironmentRuntime, approved_source_ids: tuple[str, ...]) -> None:
        super().__init__(runtime)
        self.approved_source_ids = frozenset(approved_source_ids)

    def snapshot(self, request: HarnessRunRequest) -> dict[str, Any]:
        if not self.runtime.is_available(request.subject_mode):
            raise RuntimeError("선택한 OS Runtime을 사용할 수 없습니다.")
        if request.permission_profile is None:
            raise ValueError("Live Harness에는 완전한 권한 프로파일이 필요합니다.")
        if request.source_id is not None and request.source_id not in self.approved_source_ids:
            raise ValueError("승인되지 않은 OS Host ID입니다.")

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
        permission_observations = {
            key: {
                "declared": "declared",
                "execution": "conditional_or_unknown",
                "enabled": value,
            }
            for key, value in profile.items()
        }
        target_asset = f"{request.subject_mode.value}-runtime-agent"
        snapshot = {
            "provider": "os-runtime",
            "source_id": request.source_id or "legacy-runtime",
            "subject_mode": request.subject_mode.value,
            "trust_boundary_id": boundary.id,
            "source_environment": boundary.source_environment.value,
            "target_environment": boundary.target_environment.value,
            "profile_id": profile_id,
            "permissions": profile,
            "verified_at_execution": True,
            "permission_observations": permission_observations,
            "assets": [
                {
                    "asset_id": boundary.source_environment.value,
                    "kind": "host" if request.subject_mode == SubjectMode.host else "container",
                    "subject": True,
                },
                {
                    "asset_id": boundary.target_environment.value,
                    "kind": "host" if boundary.target_environment.value.startswith("u") else "container",
                    "subject": False,
                },
                {"asset_id": target_asset, "kind": "runtime", "subject": False},
            ],
            "relationships": [
                {
                    "source": boundary.source_environment.value,
                    "target": boundary.target_environment.value,
                    "type": "trust_boundary",
                    "trust_boundary_id": boundary.id,
                },
                {
                    "source": boundary.source_environment.value,
                    "target": target_asset,
                    "type": "executes_via",
                },
            ],
            "capabilities": [
                {
                    "capability_id": f"permission:{key}",
                    "permission": key,
                    "target_asset": boundary.target_environment.value,
                    "trust_boundary_id": boundary.id,
                    "runtime_condition": value,
                    "status": "inferred" if value else "conditional_or_unknown",
                }
                for key, value in profile.items()
            ],
        }
        snapshot["snapshot_hash"] = canonical_hash(snapshot)
        return snapshot


class OsToolCatalog(_RuntimeBackedAdapter):
    def candidates(self, state: dict[str, Any]) -> list[ActionCandidate]:
        if state.get("history"):
            return []
        arguments = {
            "objective": state["objective"],
            "allowed_tools": sorted(ALLOWED_RUNTIME_TOOLS),
        }
        target = f"{state['subject_mode']}-runtime-agent"
        policy_hash = state["permission_snapshot"]["snapshot_hash"]
        return [
            ActionCandidate(
                candidate_id=deterministic_candidate_id(
                    policy_hash=policy_hash,
                    domain="os",
                    tool_name=RUNTIME_ACTION_TOOL,
                    arguments=arguments,
                    target_resource=target,
                ),
                tool_name=RUNTIME_ACTION_TOOL,
                arguments=arguments,
                argument_schema={
                    "type": "object",
                    "properties": {
                        "objective": {"type": "string"},
                        "allowed_tools": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["objective", "allowed_tools"],
                    "additionalProperties": False,
                },
                target_resource=target,
                domain="os",
                tool_kind="action",
                risk_level="reversible",
                changes_state=True,
                frontier_status="ready",
                expected_state_change={"effect": "runtime-selected-os-impact"},
                required_evidence=[
                    "applied_profile_state",
                    "runtime_result",
                    "tool_output",
                ],
                required_permissions_or_conditions=["approved_source", "matching_trust_boundary"],
                verifier_id="os-independent-runtime-verifier",
                environment_reinitialize_strategy_id=OS_REINITIALIZE_STRATEGY_ID,
                baseline_version=OS_BASELINE_VERSION,
                baseline_checks=OS_BASELINE_CHECKS,
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
        if state.get("model") and (
            self.model_gateway is None or self.model_gateway.planner_mode != "openrouter"
        ):
            return ToolExecution(
                success=False,
                output="LLM Provider 자격 증명이 구성되지 않았습니다.",
                error_code="SERVICE_CONFIGURATION_ERROR",
                error_message="요청한 모델을 실행할 Provider 자격 증명이 없습니다.",
                retryable=False,
                evidence={"reset_required": False},
            )
        snapshot = state["permission_snapshot"]
        try:
            boundary = resolve_trust_boundary(
                SubjectMode(state["subject_mode"]),
                snapshot["trust_boundary_id"],
            )
            tool_decision = (
                self.model_gateway.decide(state["objective"], boundary, state.get("model"))
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
                    action_id=f"action-{str(state['current_idempotency_key'])[:12]}",
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
        except TimeoutError as exc:
            return ToolExecution(
                success=False,
                output="OS Runtime 실행 시간이 초과되었습니다.",
                error_code="TIMEOUT",
                error_message=str(exc),
                retryable=True,
                evidence={"reset_required": True},
            )
        except Exception as exc:
            return ToolExecution(
                success=False,
                output="OS Runtime 실행 요청에 실패했습니다.",
                error_code="EXECUTION_ERROR",
                error_message=str(exc),
                retryable=False,
                evidence={
                    "reset_required": True,
                },
            )

        error_code = (
            None
            if result.outcome == "ALLOWED"
            else "POLICY_BLOCKED"
            if result.outcome == "POLICY_BLOCKED"
            else "ACCESS_DENIED"
            if result.outcome == "OS_DENIED"
            else "RUNTIME_ERROR"
        )
        return ToolExecution(
            success=result.outcome == "ALLOWED",
            output=result.output,
            error_code=error_code,
            error_message=None if result.outcome == "ALLOWED" else result.output,
            retryable=False,
            evidence={
                "runtime_result": result.model_dump(mode="json"),
                "evidence_refs": list(result.evidence_refs),
                "actual_changes": (
                    [{"changed": True, "tool": result.tool, "resource_ref": result.resource_ref}]
                    if result.changed or result.temporary_changed
                    else []
                ),
                "reset_required": bool(result.changed or result.temporary_changed),
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
            applied_profile_state={
                **result.applied_profile_state,
                "attack_tool_result": result.model_dump(
                    mode="json",
                    exclude={"applied_profile_state", "events"},
                ),
            },
            planner_mode=result.planner_mode,
            runtime_agent=result.runtime_agent,
            tool=result.tool,
            tool_arguments={
                "action": result.action,
                "resource_ref": result.resource_ref,
                "arguments": result.tool_arguments,
            },
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
                f"verifier-observation:{run_id}:{result.tool}",
                f"verifier:{tool_verification.verifier}:{run_id}",
            ],
            checks=checks,
            impact_facts=(
                [{"tool": result.tool, "resource_ref": result.resource_ref, "outcome": result.outcome}]
                if status == "VERIFIED"
                else []
            ),
        )


class OsEnvironmentReinitializer(_RuntimeBackedAdapter):
    """Control Backend의 승인된 전체 환경 초기화만 호출한다."""

    def reinitialize(
        self,
        run_id: str,
        state: dict[str, Any],
        *,
        strategy_id: str,
        baseline_version: str,
        baseline_checks: list[str],
    ) -> ResetRecord:
        del state
        try:
            result = self.runtime.reset_environment()
        except Exception as exc:
            return ResetRecord(
                status="RESET_FAILED",
                recovery_kind="environment_reinitialize",
                strategy_id=strategy_id,
                baseline_version=baseline_version,
                evidence_refs=[f"environment-reinitialize:{run_id}:failed"],
                restored_state={"error_type": type(exc).__name__},
            )
        restored = result.restored_state
        checks = {
            "trial_group_member": restored.get("trial_group_member") is False,
            "limited_sudo_rule": restored.get("limited_sudo_rule") is False,
            "docker_group_member": restored.get("docker_group_member") is False,
            "container_run_root_empty": restored.get("container_run_root_empty") is True,
            "target_canary_sha256": bool(restored.get("target_canary_sha256")),
            "running_containers": bool(restored.get("running_containers")),
            "healthy_containers": (
                bool(restored.get("healthy_containers"))
                and sorted(restored.get("healthy_containers", [])) == sorted(restored.get("running_containers", []))
            ),
        }
        requested_checks = {name: checks.get(name, False) for name in baseline_checks}
        status = "RESET" if result.status == "RESET" and all(requested_checks.values()) else "RESET_FAILED"
        return ResetRecord(
            status=status,
            recovery_kind="environment_reinitialize",
            strategy_id=strategy_id,
            baseline_version=baseline_version,
            evidence_refs=result.evidence_refs,
            restored_state=restored,
            verification_checks=requested_checks,
        )


def create_os_harness_components(
    runtime: EnvironmentRuntime,
    model_gateway: ModelGateway | None = None,
    approved_source_ids: tuple[str, ...] = ("approved-host-01",),
) -> HarnessComponents:
    return HarnessComponents(
        domain="os",
        permission_provider=OsPermissionProvider(runtime, approved_source_ids),
        tool_catalog=OsToolCatalog(runtime),
        planner=OsRuntimePlanner(runtime),
        executor=OsRuntimeExecutor(runtime, model_gateway),
        verifier=OsIndependentVerifier(runtime),
        resetter=None,
        environment_reinitializer=OsEnvironmentReinitializer(runtime),
    )
