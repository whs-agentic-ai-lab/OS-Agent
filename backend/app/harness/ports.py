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


@dataclass(frozen=True)
class HarnessComponents:
    permission_provider: PermissionProvider | None = None
    tool_catalog: ToolCatalog | None = None
    planner: Planner | None = None
    executor: ActionExecutor | None = None
    verifier: IndependentVerifier | None = None
    resetter: ActionResetter | None = None

    def missing(self) -> list[HarnessComponentName]:
        return [
            name
            for name in HarnessComponentName
            if getattr(self, name.value) is None
        ]
