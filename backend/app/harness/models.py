from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from ..schemas import EnvironmentNode, PROFILE_KEYS, SubjectMode


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class HarnessComponentName(str, Enum):
    permission_provider = "permission_provider"
    tool_catalog = "tool_catalog"
    planner = "planner"
    executor = "executor"
    verifier = "verifier"
    resetter = "resetter"


REQUIRED_COMPONENTS: tuple[HarnessComponentName, ...] = tuple(HarnessComponentName)


class HarnessComponentStatus(BaseModel):
    name: HarnessComponentName
    ready: bool


class HarnessStatus(BaseModel):
    version: Literal["os-harness-v1"] = "os-harness-v1"
    status: Literal["ready", "waiting_for_components"]
    ready: bool
    preserves_legacy_run_api: Literal[True] = True
    components: list[HarnessComponentStatus]
    missing_components: list[HarnessComponentName] = Field(default_factory=list)


class HarnessBudgetConfig(BaseModel):
    max_iterations: int = Field(default=6, ge=1, le=100)
    max_tool_calls: int = Field(default=12, ge=1, le=200)
    max_elapsed_seconds: int = Field(default=120, ge=1, le=3600)
    max_no_progress_iterations: int = Field(default=2, ge=1, le=20)


class HarnessBudgetState(HarnessBudgetConfig):
    used_iterations: int = 0
    used_tool_calls: int = 0
    no_progress_iterations: int = 0


class HarnessRunRequest(BaseModel):
    objective: str = Field(min_length=1, max_length=4000)
    subject_mode: SubjectMode
    trust_boundary_id: str | None = None
    scenario_id: str = Field(default="unassigned", min_length=1, max_length=128)
    permission_profile: dict[str, bool] | None = None
    permission_profile_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=160,
    )
    budget: HarnessBudgetConfig = Field(default_factory=HarnessBudgetConfig)

    @model_validator(mode="after")
    def validate_permission_profile(self) -> "HarnessRunRequest":
        if self.permission_profile is None:
            return self
        expected = set(PROFILE_KEYS[self.subject_mode])
        actual = set(self.permission_profile)
        if actual != expected:
            missing = ", ".join(sorted(expected - actual)) or "없음"
            extra = ", ".join(sorted(actual - expected)) or "없음"
            raise ValueError(
                "Harness 권한 프로파일은 선택 환경의 세 항목을 모두 포함해야 합니다. "
                f"누락: {missing}; 잘못된 항목: {extra}"
            )
        return self


class ActionCandidate(BaseModel):
    candidate_id: str = Field(min_length=1, max_length=160)
    tool_name: str = Field(min_length=1, max_length=160)
    arguments: dict[str, Any] = Field(default_factory=dict)
    target_resource: str = Field(min_length=1, max_length=256)
    risk_level: Literal["observe", "safe", "reversible"] = "observe"
    changes_state: bool = False
    required_evidence: list[str] = Field(default_factory=list)


class PlannerDecision(BaseModel):
    candidate_id: str | None = Field(default=None, min_length=1, max_length=160)
    stop_reason: str | None = Field(default=None, min_length=1, max_length=500)
    rationale: str = Field(default="", max_length=2000)

    @model_validator(mode="after")
    def require_candidate_or_stop(self) -> "PlannerDecision":
        if (self.candidate_id is None) == (self.stop_reason is None):
            raise ValueError("Planner는 candidate_id 또는 stop_reason 중 하나만 반환해야 합니다.")
        return self


class ToolExecution(BaseModel):
    success: bool
    output: str = Field(default="", max_length=8192)
    error_code: str | None = None
    retryable: bool = False
    evidence: dict[str, Any] = Field(default_factory=dict)


class VerificationRecord(BaseModel):
    status: Literal["VERIFIED", "REJECTED", "INCONCLUSIVE"]
    evidence_refs: list[str] = Field(default_factory=list)
    checks: dict[str, bool] = Field(default_factory=dict)


class ResetRecord(BaseModel):
    status: Literal["RESET", "RESET_FAILED", "NOT_REQUIRED"]
    evidence_refs: list[str] = Field(default_factory=list)
    restored_state: dict[str, Any] = Field(default_factory=dict)


class HarnessActionRecord(BaseModel):
    sequence: int
    candidate: ActionCandidate
    execution: ToolExecution
    verification: VerificationRecord
    reset: ResetRecord


class HarnessEvent(BaseModel):
    sequence: int
    source: Literal[
        "harness",
        "permission_provider",
        "tool_catalog",
        "planner",
        "executor",
        "verifier",
        "resetter",
    ]
    event_type: str
    message: str
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class HarnessRunRecord(BaseModel):
    run_id: str
    harness_version: Literal["os-harness-v1"] = "os-harness-v1"
    status: Literal["RECEIVED", "RUNNING", "COMPLETED", "BLOCKED", "FAILED"]
    objective: str
    subject_mode: SubjectMode
    trust_boundary_id: str | None = None
    source_environment: EnvironmentNode | None = None
    target_environment: EnvironmentNode | None = None
    scenario_id: str
    state_version: int = 0
    state: dict[str, Any] = Field(default_factory=dict)
    budget: HarnessBudgetState
    missing_components: list[HarnessComponentName] = Field(default_factory=list)
    actions: list[HarnessActionRecord] = Field(default_factory=list)
    events: list[HarnessEvent] = Field(default_factory=list)
    termination_reason: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
