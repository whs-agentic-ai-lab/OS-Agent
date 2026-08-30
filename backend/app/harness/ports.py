from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .models import (
    ActionCandidate,
    HarnessBudgetState,
    HarnessComponentName,
    HarnessRunRequest,
    PlannerDecision,
    ResetRecord,
    ToolExecution,
    VerificationRecord,
)


class PermissionProvider(Protocol):
    def snapshot(self, request: HarnessRunRequest) -> dict[str, Any]: ...


class ToolCatalog(Protocol):
    def candidates(self, state: dict[str, Any]) -> list[ActionCandidate]: ...


class Planner(Protocol):
    def select(
        self,
        state: dict[str, Any],
        candidates: list[ActionCandidate],
        budget: HarnessBudgetState,
    ) -> PlannerDecision: ...


class ActionExecutor(Protocol):
    def execute(
        self,
        run_id: str,
        candidate: ActionCandidate,
        state: dict[str, Any],
    ) -> ToolExecution: ...


class IndependentVerifier(Protocol):
    def verify(
        self,
        run_id: str,
        candidate: ActionCandidate,
        execution: ToolExecution,
        state: dict[str, Any],
    ) -> VerificationRecord: ...


class ActionResetter(Protocol):
    def reset(
        self,
        run_id: str,
        candidate: ActionCandidate,
        execution: ToolExecution,
        state: dict[str, Any],
    ) -> ResetRecord: ...


class EnvironmentReinitializer(Protocol):
    """OS 전용 전체 실험환경 초기화 포트. Tool 단위 Reset과 분리한다."""

    def reinitialize(
        self,
        run_id: str,
        state: dict[str, Any],
        *,
        strategy_id: str,
        baseline_version: str,
        baseline_checks: list[str],
    ) -> ResetRecord: ...


@dataclass(frozen=True)
class HarnessComponents:
    domain: str = "generic"
    permission_provider: PermissionProvider | None = None
    tool_catalog: ToolCatalog | None = None
    planner: Planner | None = None
    executor: ActionExecutor | None = None
    verifier: IndependentVerifier | None = None
    resetter: ActionResetter | None = None
    environment_reinitializer: EnvironmentReinitializer | None = None

    def missing(self) -> list[HarnessComponentName]:
        required = [
            HarnessComponentName.permission_provider,
            HarnessComponentName.tool_catalog,
            HarnessComponentName.planner,
            HarnessComponentName.executor,
            HarnessComponentName.verifier,
            (
                HarnessComponentName.environment_reinitializer
                if self.domain == "os"
                else HarnessComponentName.resetter
            ),
        ]
        return [name for name in required if not self._ready(getattr(self, name.value))]

    @staticmethod
    def _ready(component: object | None) -> bool:
        if component is None:
            return False
        readiness = getattr(component, "is_ready", None)
        if readiness is None:
            return True
        try:
            return bool(readiness())
        except Exception:
            return False
