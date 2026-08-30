from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator

from ..permission_controls import PROFILE_DEFAULTS, PROFILE_KEYS
from ..schemas import EnvironmentNode, SubjectMode


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def deterministic_candidate_id(*, policy_hash: str, domain: str, tool_name: str, arguments: dict[str, Any], target_resource: str) -> str:
    digest = canonical_hash({"policy_hash": policy_hash, "domain": domain, "tool_name": tool_name, "arguments": arguments, "target_resource": target_resource})
    return f"candidate-{digest[:24]}"


class HarnessComponentName(str, Enum):
    permission_provider = "permission_provider"
    tool_catalog = "tool_catalog"
    planner = "planner"
    executor = "executor"
    verifier = "verifier"
    resetter = "resetter"
    environment_reinitializer = "environment_reinitializer"


class HarnessComponentStatus(BaseModel):
    name: HarnessComponentName
    ready: bool


class HarnessStatus(BaseModel):
    version: Literal["os-harness-v1"] = "os-harness-v1"
    contract_version: Literal["common-os-contract-v1"] = "common-os-contract-v1"
    status: Literal["ready", "waiting_for_components"]
    ready: bool
    preserves_legacy_run_api: Literal[True] = True
    recovery_mode: Literal["tool_reset", "environment_reinitialize"]
    components: list[HarnessComponentStatus]
    missing_components: list[HarnessComponentName] = Field(default_factory=list)


class HarnessBudgetConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_iterations: int = Field(default=6, ge=1, le=100)
    max_tool_calls: int = Field(default=12, ge=1, le=200)
    max_elapsed_seconds: int = Field(default=120, ge=1, le=3600)
    max_no_progress_iterations: int = Field(default=2, ge=1, le=20)
    max_retry_attempts: int = Field(default=1, ge=0, le=3)


class HarnessBudgetState(HarnessBudgetConfig):
    used_iterations: int = 0
    used_tool_calls: int = 0
    used_retries: int = 0
    no_progress_iterations: int = 0


class HarnessRunRequest(BaseModel):
    """Strict PM OS input plus a compatibility mapping for legacy field names."""

    model_config = ConfigDict(extra="forbid")
    environment: Literal["os"] = "os"
    source_id: str | None = Field(default=None, min_length=1, max_length=128)
    objective: str = Field(min_length=1, max_length=4000)
    subject_mode: SubjectMode | None = None
    os_subject_mode: SubjectMode | None = None
    trust_boundary_id: str | None = Field(default=None, max_length=128)
    os_trust_boundary_id: str | None = Field(default=None, max_length=128)
    scenario_id: str = Field(default="unassigned", min_length=1, max_length=128)
    permission_profile: dict[str, StrictBool] | None = None
    os_permission_profile: dict[str, StrictBool] | None = None
    permission_profile_id: str | None = Field(default=None, min_length=1, max_length=160)
    model: str | None = Field(default=None, min_length=1, max_length=160)
    max_iterations: int | None = Field(default=None, ge=1, le=100)
    result_limit: int = Field(default=20, ge=1, le=100)
    reset_after_run: bool = True
    risk_ceiling: Literal["observe", "safe", "reversible"] = "reversible"
    frozen_scenario: bool = False
    frozen_tool_sequence: list[str] = Field(default_factory=list, max_length=100)
    frozen_target_resources: list[str] = Field(default_factory=list, max_length=100)
    budget: HarnessBudgetConfig = Field(default_factory=HarnessBudgetConfig)

    @model_validator(mode="after")
    def normalize_os_contract(self) -> "HarnessRunRequest":
        using_os_contract = any(value is not None for value in (self.source_id, self.os_subject_mode, self.os_trust_boundary_id, self.os_permission_profile))
        if self.subject_mode is not None and self.os_subject_mode is not None and self.subject_mode != self.os_subject_mode:
            raise ValueError("subject_mode와 os_subject_mode가 일치하지 않습니다.")
        resolved_mode = self.os_subject_mode or self.subject_mode
        if resolved_mode is None:
            raise ValueError("OS Subject Mode가 필요합니다.")
        self.subject_mode = resolved_mode
        self.os_subject_mode = resolved_mode

        if self.trust_boundary_id and self.os_trust_boundary_id and self.trust_boundary_id != self.os_trust_boundary_id:
            raise ValueError("trust_boundary_id와 os_trust_boundary_id가 일치하지 않습니다.")
        resolved_boundary = self.os_trust_boundary_id or self.trust_boundary_id
        self.trust_boundary_id = resolved_boundary
        self.os_trust_boundary_id = resolved_boundary

        if self.permission_profile is not None and self.os_permission_profile is not None and self.permission_profile != self.os_permission_profile:
            raise ValueError("permission_profile과 os_permission_profile이 일치하지 않습니다.")
        profile = self.os_permission_profile if self.os_permission_profile is not None else self.permission_profile
        if profile is not None and not all(type(value) is bool for value in profile.values()):
            raise ValueError("OS 권한 프로파일 값은 실제 Boolean이어야 합니다.")
        expected = set(PROFILE_KEYS[resolved_mode])
        actual = set(profile or {})
        extra = actual - expected
        if extra:
            raise ValueError("Harness 권한 프로파일에 선택 환경과 맞지 않는 항목이 있습니다. 잘못된 항목: " + ", ".join(sorted(extra)))

        if using_os_contract:
            missing_contract = [name for name, value in (("source_id", self.source_id), ("os_subject_mode", self.os_subject_mode), ("os_trust_boundary_id", self.os_trust_boundary_id), ("os_permission_profile", self.os_permission_profile)) if value is None]
            if missing_contract:
                raise ValueError("OS 실행 입력에 필수 필드가 누락되었습니다: " + ", ".join(missing_contract))
            missing_keys = expected - actual
            if missing_keys:
                raise ValueError("OS 권한 프로파일에 필수 키가 누락되었습니다: " + ", ".join(sorted(missing_keys)))
            normalized = dict(profile or {})
        else:
            normalized = {**PROFILE_DEFAULTS[resolved_mode], **(profile or {})}

        if resolved_mode == SubjectMode.container and normalized["privileged"] and not normalized["run_as_root"]:
            raise ValueError("privileged 실험은 UID 축을 고정하기 위해 run_as_root=ON이 필요합니다.")
        self.permission_profile = normalized
        self.os_permission_profile = normalized
        if self.max_iterations is not None:
            self.budget = self.budget.model_copy(update={"max_iterations": self.max_iterations})
        else:
            self.max_iterations = self.budget.max_iterations
        if self.frozen_scenario:
            if not self.frozen_tool_sequence:
                raise ValueError("Frozen Scenario에는 하나 이상의 Tool 순서가 필요합니다.")
            if len(self.frozen_tool_sequence) != len(self.frozen_target_resources):
                raise ValueError("Frozen Scenario의 Tool과 대상 목록 길이가 일치해야 합니다.")
        return self


class ActionCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    candidate_id: str = Field(min_length=1, max_length=160)
    tool_name: str = Field(min_length=1, max_length=160)
    arguments: dict[str, Any] = Field(default_factory=dict)
    argument_schema: dict[str, Any] = Field(default_factory=lambda: {"type": "object", "properties": {}, "additionalProperties": False})
    target_resource: str = Field(min_length=1, max_length=256)
    domain: Literal["generic", "os"] = "generic"
    tool_kind: Literal["recon", "action"] = "action"
    risk_level: Literal["observe", "safe", "reversible"] = "observe"
    changes_state: bool = False
    frontier_status: Literal["ready", "conditional", "blocked"] = "ready"
    expected_state_change: dict[str, Any] = Field(default_factory=dict)
    required_evidence: list[str] = Field(default_factory=list)
    required_permissions_or_conditions: list[str] = Field(default_factory=list)
    verifier_id: str | None = None
    resetter_id: str | None = None
    environment_reinitialize_strategy_id: str | None = None
    baseline_version: str | None = None
    baseline_checks: list[str] = Field(default_factory=list)
    depends_on_candidate_id: str | None = None
    argument_bindings: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_contract(self) -> "ActionCandidate":
        if self.argument_schema.get("type") != "object" or self.argument_schema.get("additionalProperties") is not False:
            raise ValueError("Action 입력 스키마는 additionalProperties=false인 객체여야 합니다.")
        properties = self.argument_schema.get("properties", {})
        required = set(self.argument_schema.get("required", []))
        if not isinstance(properties, dict) or set(self.arguments) - set(properties):
            raise ValueError("Action 인자에 등록 스키마 밖의 필드가 있습니다.")
        if required - set(self.arguments):
            raise ValueError("Action 인자에 등록 스키마의 필수 필드가 누락되었습니다.")
        if self.tool_kind == "action" and not self.verifier_id:
            raise ValueError("자율 실행 Action에는 독립 Verifier가 필요합니다.")
        if self.domain == "os":
            if self.resetter_id is not None:
                raise ValueError("OS Action은 Tool Resetter를 등록할 수 없습니다.")
            if self.changes_state and (not self.environment_reinitialize_strategy_id or not self.baseline_version or not self.baseline_checks):
                raise ValueError("OS 상태 변경 Action에는 환경 초기화 전략과 Baseline 검증 계약이 필요합니다.")
        elif self.changes_state and not self.resetter_id:
            raise ValueError("일반 도메인의 가역 변경 Action에는 Tool Resetter가 필요합니다.")
        return self

    @property
    def semantic_key(self) -> str:
        return canonical_hash({"domain": self.domain, "tool": self.tool_name, "arguments": self.arguments, "target": self.target_resource, "effect": self.expected_state_change})


class PlannerDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    candidate_id: str | None = Field(default=None, min_length=1, max_length=160)
    stop_reason: str | None = Field(default=None, min_length=1, max_length=500)
    rationale: str = Field(default="", max_length=2000)

    @model_validator(mode="after")
    def require_candidate_or_stop(self) -> "PlannerDecision":
        if (self.candidate_id is None) == (self.stop_reason is None):
            raise ValueError("Planner는 candidate_id 또는 stop_reason 중 하나만 반환해야 합니다.")
        return self


RETRYABLE_ERROR_CODES = frozenset({"TIMEOUT", "THROTTLED"})


class ToolExecution(BaseModel):
    success: bool
    output: str = Field(default="", max_length=8192)
    error_code: str | None = None
    error_message: str | None = Field(default=None, max_length=2000)
    retryable: bool = False
    evidence: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_result(self) -> "ToolExecution":
        if self.success and (self.error_code is not None or self.error_message is not None):
            raise ValueError("성공한 Tool 결과에는 오류가 없어야 합니다.")
        if not self.success and (not self.error_code or not (self.error_message or self.output)):
            raise ValueError("실패한 Tool 결과에는 오류 코드와 메시지가 필요합니다.")
        if self.retryable and self.error_code not in RETRYABLE_ERROR_CODES:
            raise ValueError("TIMEOUT과 THROTTLED만 자동 재시도할 수 있습니다.")
        return self


class VerificationRecord(BaseModel):
    status: Literal["VERIFIED", "REJECTED", "INCONCLUSIVE"]
    evidence_refs: list[str] = Field(default_factory=list)
    checks: dict[str, bool] = Field(default_factory=dict)
    impact_facts: list[dict[str, Any]] = Field(default_factory=list)


class ResetRecord(BaseModel):
    status: Literal["RESET", "RESET_FAILED", "NOT_REQUIRED", "STATE_PRESERVED"]
    recovery_kind: Literal["tool_reset", "environment_reinitialize", "none"] = "none"
    strategy_id: str | None = None
    baseline_version: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    restored_state: dict[str, Any] = Field(default_factory=dict)
    verification_checks: dict[str, bool] = Field(default_factory=dict)


class ActionReceipt(BaseModel):
    execution_target: str
    actual_changes: list[dict[str, Any]] = Field(default_factory=list)
    created_identifiers: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class HarnessActionRecord(BaseModel):
    sequence: int
    idempotency_key: str
    candidate: ActionCandidate
    execution: ToolExecution
    receipt: ActionReceipt
    verification: VerificationRecord
    reset: ResetRecord = Field(default_factory=lambda: ResetRecord(status="NOT_REQUIRED"))


class HarnessEvent(BaseModel):
    sequence: int
    source: Literal["harness", "permission_provider", "tool_catalog", "planner", "guardrail", "executor", "verifier", "resetter", "environment_reinitializer", "evidence"]
    event_type: str
    message: str
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class HarnessRunRecord(BaseModel):
    run_id: str
    harness_version: Literal["os-harness-v1"] = "os-harness-v1"
    contract_version: Literal["common-os-contract-v1"] = "common-os-contract-v1"
    status: Literal["RECEIVED", "RUNNING", "COMPLETED", "BLOCKED", "FAILED"]
    current_stage: str = "queued"
    error_code: str | None = None
    final_result: Literal["SUCCESS", "FAILURE", "INCONCLUSIVE", "STATE_PRESERVED"] | None = None
    objective: str
    environment: Literal["os"] = "os"
    source_id: str | None = None
    subject_mode: SubjectMode
    trust_boundary_id: str | None = None
    source_environment: EnvironmentNode | None = None
    target_environment: EnvironmentNode | None = None
    scenario_id: str
    reset_after_run: bool = True
    state_version: int = 0
    state: dict[str, Any] = Field(default_factory=dict)
    budget: HarnessBudgetState
    missing_components: list[HarnessComponentName] = Field(default_factory=list)
    actions: list[HarnessActionRecord] = Field(default_factory=list)
    environment_reset: ResetRecord | None = None
    events: list[HarnessEvent] = Field(default_factory=list)
    contract_hash: str = ""
    catalog_hash: str = ""
    evidence_bundle_path: str | None = None
    evidence_manifest: dict[str, Any] = Field(default_factory=dict)
    termination_reason: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
