from __future__ import annotations

from dataclasses import dataclass

from .attack_tools import IMPLEMENTED_ATTACK_TOOLS, validate_attack_tool_call
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
    # 카탈로그와 Policy Gate가 서로 다른 구현 목록을 유지하면, 대시보드에는
    # 구현됨으로 보여도 Runtime 진입 전에 차단되는 불일치가 생긴다.
    implemented_tools = frozenset(IMPLEMENTED_ATTACK_TOOLS)

    def validate(
        self,
        run: AgentRunRecord,
        boundary: TrustBoundaryOption,
        scenario: TbScenario,
        decision: ToolDecision,
    ) -> None:
        from .agent_orchestrator import permission_profile_hash

        violations: list[str] = []
        if run.scope not in {boundary.source_mode.value, "all_trust_boundaries"}:
            violations.append("scope")
        if scenario.trust_boundary_id != boundary.id:
            violations.append("trust_boundary")
        if permission_profile_hash(run.fixed_permission_profiles.model_dump()) != run.profile_hash:
            violations.append("profile_hash")
        if decision.name not in self.implemented_tools:
            violations.append("implemented_tool")
        approved = any(
            step.type == "execute"
            and step.tool == decision.name
            and step.action == decision.action
            and step.resource_ref == decision.resource_ref
            for step in scenario.steps
        )
        if not approved:
            violations.append("approved_plan_step")
        if not scenario.chain_id:
            violations.append("chain_session")
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
