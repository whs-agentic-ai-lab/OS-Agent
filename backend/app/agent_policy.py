from __future__ import annotations

from dataclasses import dataclass

from .attack_tools import validate_attack_tool_call
from .schemas import AgentRunRecord, TbScenario, ToolDecision, TrustBoundaryOption


class AgentPolicyViolation(RuntimeError):
    pass


@dataclass(frozen=True)
class CompiledToolCall:
    runtime_entrypoint: str
    tool: str
    action: str
    resource_ref: str
    arguments: dict


class AgentPolicyGate:
    implemented_tools = {
        "file.content",
        "privilege.identity_probe",
        "privilege.no_new_privs_probe",
        "process.procfs",
        "sudo.run",
    }

    def validate(
        self,
        run: AgentRunRecord,
        boundary: TrustBoundaryOption,
        scenario: TbScenario,
        decision: ToolDecision,
    ) -> None:
        from .agent_orchestrator import permission_profile_hash

        violations: list[str] = []
        if run.scope != "all_trust_boundaries":
            violations.append("scope")
        if scenario.trust_boundary_id != boundary.id:
            violations.append("trust_boundary")
        if permission_profile_hash(run.fixed_permission_profiles.model_dump()) != run.profile_hash:
            violations.append("profile_hash")
        if decision.name not in self.implemented_tools:
            violations.append("implemented_tool")
        if len(scenario.steps) > run.budget.max_steps_per_tb:
            violations.append("step_budget")
        if run.budget.max_tool_calls_per_tb < 1:
            violations.append("tool_budget")
        approved = any(
            step.type == "execute"
            and step.tool == decision.name
            and step.action == decision.action
            and step.resource_ref == decision.resource_ref
            for step in scenario.steps
        )
        if not approved:
            violations.append("approved_plan_step")
        if not any(step.type == "rollback" for step in scenario.steps):
            violations.append("rollback")
        if violations:
            raise AgentPolicyViolation(
                "Agent Policy Gate 차단: " + ", ".join(violations)
            )


class CommandCompiler:
    """구조화된 호출을 고정 Runtime 진입점 계약으로 컴파일합니다."""

    @staticmethod
    def compile(decision: ToolDecision) -> CompiledToolCall:
        arguments = validate_attack_tool_call(
            decision.name,
            decision.action,
            decision.resource_ref,
            decision.arguments,
        )
        return CompiledToolCall(
            runtime_entrypoint="runtime_agent.runtime",
            tool=decision.name,
            action=decision.action,
            resource_ref=decision.resource_ref,
            arguments=arguments,
        )
