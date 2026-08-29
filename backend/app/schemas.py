from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SubjectMode(str, Enum):
    container = "container"
    host = "host"


class EnvironmentNode(str, Enum):
    u1 = "u1"
    u2 = "u2"
    c1 = "c1"
    c2 = "c2"
    c3 = "c3"


class BoundaryType(str, Enum):
    hh = "HH"
    hc = "HC"
    cc = "CC"


class PermissionTest(BaseModel):
    id: str
    label: str
    description: str
    off_profile: str
    on_profile: str
    off_description: str = ""
    on_description: str = ""
    catalog_ids: list[str] = Field(default_factory=list)
    axis: str = "UNCLASSIFIED"
    default_enabled: bool = False


class SubjectOption(BaseModel):
    id: SubjectMode
    label: str
    description: str
    enabled: bool = True


class ToolOption(BaseModel):
    id: str
    label: str
    description: str
    family: str = "legacy"
    actions: list[str] = Field(default_factory=list)
    implemented: bool = False
    implemented_actions: list[str] = Field(default_factory=list)


class TrustBoundaryOption(BaseModel):
    id: str
    boundary_type: BoundaryType
    source_mode: SubjectMode
    source_environment: EnvironmentNode
    target_environment: EnvironmentNode
    label: str
    description: str


class PermissionCatalogSummary(BaseModel):
    source_version: str
    total_entries: int
    independent_permission_count: int | None = None
    policy: str


PlannerModel = Literal[
    "openai/gpt-5-mini",
    "z-ai/glm-5.3-flash",
    "deepseek/deepseek-v4-flash-0731",
]


class PlannerModelOption(BaseModel):
    id: PlannerModel
    label: str
    description: str


class OptionsResponse(BaseModel):
    subject_modes: list[SubjectOption]
    permission_tests: dict[str, list[PermissionTest]]
    tools: list[ToolOption]
    trust_boundaries: list[TrustBoundaryOption]
    permission_catalog_summary: PermissionCatalogSummary
    planner_mode: Literal["local", "openrouter"] = "local"
    planner_models: list[PlannerModelOption] = Field(default_factory=list)


class PermissionSelection(BaseModel):
    permission_id: str
    enabled: bool


class RunRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=4000)
    subject_mode: SubjectMode
    trust_boundary_id: str | None = None
    permission_profile: dict[str, bool] = Field(default_factory=dict)
    planner_model: PlannerModel | None = None
    # v1 로그/클라이언트를 읽기 위한 호환 필드입니다. 신규 요청의 기준은
    # permission_profile 객체 하나이며 목록 단위 실행은 하지 않습니다.
    permissions: list[PermissionSelection] = Field(default_factory=list)
    # 구버전 클라이언트 호환 필드. 새 클라이언트는 permissions만 전송합니다.
    permission_id: str | None = None
    permission_enabled: bool | None = None

    @model_validator(mode="after")
    def normalize_permissions(self) -> "RunRequest":
        from .permission_controls import PROFILE_DEFAULTS, PROFILE_KEYS

        if not self.permission_profile and self.permissions:
            self.permission_profile = {
                item.permission_id: item.enabled for item in self.permissions
            }
        if (
            not self.permission_profile
            and self.permission_id
            and self.permission_enabled is not None
        ):
            # 단일 권한만 가진 v1 요청은 더 이상 새 통합 Run으로 실행할 수 없다.
            # 명시적인 오류를 내기 위해 아래 exact-key 검증으로 넘긴다.
            self.permissions = [
                PermissionSelection(
                    permission_id=self.permission_id,
                    enabled=self.permission_enabled,
                )
            ]
            self.permission_profile = {
                self.permission_id: self.permission_enabled,
            }
        expected_keys = set(PROFILE_KEYS[self.subject_mode])
        actual_keys = set(self.permission_profile)
        if actual_keys - expected_keys:
            extra = ", ".join(sorted(actual_keys - expected_keys)) or "없음"
            raise ValueError(
                "권한 프로파일에 선택 환경과 맞지 않는 항목이 있습니다. "
                f"잘못된 항목: {extra}"
            )
        self.permission_profile = {
            **PROFILE_DEFAULTS[self.subject_mode],
            **self.permission_profile,
        }
        if (
            self.subject_mode == SubjectMode.container
            and self.permission_profile["privileged"]
            and not self.permission_profile["run_as_root"]
        ):
            raise ValueError(
                "privileged 실험은 UID 축을 고정하기 위해 run_as_root=ON이 필요합니다."
            )
        self.permissions = [
            PermissionSelection(permission_id=key, enabled=self.permission_profile[key])
            for key in PROFILE_KEYS[self.subject_mode]
        ]
        self.permission_id = "profile_bundle"
        self.permission_enabled = True
        return self


class RunEvent(BaseModel):
    sequence: int
    source: Literal[
        "profile",
        "model",
        "tool_runner",
        "executor",
        "runtime_agent",
        "supervisor",
        "verifier",
        "orchestrator",
        "recon",
        "analyzer",
        "planner",
        "policy",
        "rollback",
        "minimizer",
    ]
    event_type: str
    message: str
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class ToolDecision(BaseModel):
    name: str
    action: str
    resource_ref: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class PlannerNextAction(BaseModel):
    kind: Literal["tool", "finish"]
    decision: ToolDecision | None = None
    rationale: str = ""
    termination_reason: Literal[
        "MAX_IMPACT_VERIFIED",
        "NO_FEASIBLE_ACTION",
    ] | None = None

    @model_validator(mode="after")
    def validate_shape(self) -> "PlannerNextAction":
        if self.kind == "tool" and self.decision is None:
            raise ValueError("tool 다음 행동에는 구조화 Tool 결정이 필요합니다.")
        if self.kind == "finish" and self.termination_reason is None:
            raise ValueError("finish 다음 행동에는 종료 사유가 필요합니다.")
        return self


class PermissionRunResult(BaseModel):
    permission_id: str
    permission_enabled: bool
    requested_profile: str
    applied_profile: str | None = None
    resource_id: str
    runtime_result: Literal["allowed", "denied", "error"] | None = None
    output: str | None = None
    exit_code: int | None = None
    before_sha256: str | None = None
    after_sha256: str | None = None
    verifier_name: str = "UNIMPLEMENTED"
    verifier_effect: dict[str, bool] = Field(default_factory=dict)
    test_result: Literal["PASS", "FAIL", "INCONCLUSIVE"] | None = None


class RuntimeDispatchRequest(BaseModel):
    run_id: str
    action_id: str
    prompt: str
    subject_mode: SubjectMode
    trust_boundary_id: str
    source_environment: EnvironmentNode
    target_environment: EnvironmentNode
    permission_profile: dict[str, bool]
    profile_id: str
    tool_decision: ToolDecision | None = None
    planner_mode: Literal["local", "openrouter"] = "local"
    chain_id: str | None = None
    chain_step: int = Field(default=0, ge=0)
    preserve_state: bool = False


class RuntimeResetRequest(BaseModel):
    run_id: str
    subject_mode: SubjectMode
    trust_boundary_id: str | None = None
    target_environment: EnvironmentNode | None = None


class RuntimeResetResult(BaseModel):
    status: Literal["RESET", "RESET_FAILED"]
    evidence_refs: list[str] = Field(default_factory=list)
    restored_state: dict[str, Any] = Field(default_factory=dict)


class ExperimentEnvironmentResetRequest(BaseModel):
    confirmation: Literal["RESET_EXPERIMENT_ENVIRONMENT"]


class ExperimentEnvironmentResetResult(BaseModel):
    status: Literal["RESET", "RESET_FAILED"]
    duration_ms: int = Field(ge=0)
    reset_scopes: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    restored_state: dict[str, Any] = Field(default_factory=dict)


class RuntimeAgentResult(BaseModel):
    run_id: str
    subject_mode: SubjectMode
    trust_boundary_id: str = "UNASSIGNED"
    source_environment: EnvironmentNode | None = None
    target_environment: EnvironmentNode | None = None
    applied_profile: str
    applied_profile_state: dict[str, Any]
    runtime_agent: str
    planner_mode: Literal["local", "openrouter"]
    action_id: str
    executor_mode: SubjectMode
    source: EnvironmentNode
    target: EnvironmentNode
    tool: str
    action: str
    resource_ref: str
    tool_arguments: dict[str, Any] = Field(default_factory=dict)
    policy_decision: Literal["allowed", "denied"] = "allowed"
    runtime_result: Literal["allowed", "denied", "error"]
    outcome: Literal["ALLOWED", "OS_DENIED", "ERROR", "POLICY_BLOCKED"]
    attempted: bool
    errno: int | None = None
    escalation_possible: bool = False
    temporary_changed: bool = False
    changed: bool = False
    identity_before: dict[str, Any] = Field(default_factory=dict)
    identity_reached: dict[str, Any] | None = None
    identity_after: dict[str, Any] = Field(default_factory=dict)
    rollback_status: Literal["NOT_REQUIRED", "VERIFIED", "FAILED"] = "NOT_REQUIRED"
    evidence_refs: list[str] = Field(default_factory=list)
    output: str
    exit_code: int
    before_sha256: str | None = None
    after_sha256: str | None = None
    events: list[RunEvent] = Field(default_factory=list)


class RunRecord(BaseModel):
    run_id: str
    status: str
    prompt: str
    subject_mode: SubjectMode
    trust_boundary_id: str = "UNASSIGNED"
    source_environment: EnvironmentNode | None = None
    target_environment: EnvironmentNode | None = None
    permission_id: str = "profile_bundle"
    permission_enabled: bool = True
    permission_profile: dict[str, bool] = Field(default_factory=dict)
    permissions: list[PermissionSelection] = Field(default_factory=list)
    # v1 과거 로그 호환 전용. v2 신규 Run은 단일 Runtime 결과만 저장합니다.
    permission_results: list[PermissionRunResult] = Field(default_factory=list)
    requested_profile: str
    applied_profile: str | None = None
    applied_profile_state: dict[str, Any] = Field(default_factory=dict)
    result_format_version: Literal["common-minimum-v1", "common-minimum-v2"] = "common-minimum-v2"
    profile_version: str = "UNIMPLEMENTED"
    workload_type: Literal["normal", "attack", "UNIMPLEMENTED"] = "UNIMPLEMENTED"
    action_path_id: str = "UNIMPLEMENTED"
    changed_variable: str = "UNIMPLEMENTED"
    planner_mode: Literal["local", "openrouter"]
    planner_model: PlannerModel | None = None
    runtime_agent: str = "UNIMPLEMENTED"
    tool: str | None = None
    tool_arguments: dict[str, Any] = Field(default_factory=dict)
    policy_decision: Literal["allowed", "denied", "UNIMPLEMENTED"] = "UNIMPLEMENTED"
    authentication_result: Literal["succeeded", "failed", "UNIMPLEMENTED"] = "UNIMPLEMENTED"
    authorization_result: Literal["allowed", "denied", "error", "UNIMPLEMENTED"] = "UNIMPLEMENTED"
    runtime_result: Literal["allowed", "denied", "error"] | None = None
    output: str | None = None
    exit_code: int | None = None
    before_sha256: str | None = None
    after_sha256: str | None = None
    verifier_name: str = "UNIMPLEMENTED"
    verifier_effect: dict[str, bool] = Field(default_factory=dict)
    evidence_references: list[str] = Field(default_factory=list)
    test_result: Literal["PASS", "FAIL", "INCONCLUSIVE"] | None = None
    events: list[RunEvent] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None

    @model_validator(mode="before")
    @classmethod
    def restore_changed_variable(cls, value: Any) -> Any:
        """구버전 실행 기록의 권한 변경 값을 원본 요청 필드로 복원합니다."""
        if not isinstance(value, dict):
            return value

        permissions = value.get("permissions")
        permission_profile = value.get("permission_profile")
        permission_id = value.get("permission_id")
        permission_enabled = value.get("permission_enabled")
        if not permissions and isinstance(permission_id, str) and isinstance(permission_enabled, bool):
            permissions = [{"permission_id": permission_id, "enabled": permission_enabled}]
            value = {**value, "permissions": permissions}

        if not permission_profile and permissions:
            permission_profile = {
                item["permission_id"]: item["enabled"] for item in permissions
            }
            value = {**value, "permission_profile": permission_profile}

        changed_variable = value.get("changed_variable")
        if (
            changed_variable in (None, "", "UNIMPLEMENTED")
            and isinstance(permission_id, str)
            and isinstance(permission_enabled, bool)
        ):
            return {
                **value,
                "changed_variable": f"{permission_id}:{'ON' if permission_enabled else 'OFF'}",
            }
        if changed_variable in (None, "", "UNIMPLEMENTED") and permissions:
            return {
                **value,
                "changed_variable": ", ".join(
                    f"{item['permission_id']}:{'ON' if item['enabled'] else 'OFF'}"
                    for item in permissions
                ),
            }
        return value


class RunListResponse(BaseModel):
    items: list[RunRecord]
    total: int
    page: int
    page_size: int


class RunDeleteResponse(BaseModel):
    run_id: str
    deleted: bool


class AgentBudget(BaseModel):
    # max_steps_per_tb는 안전 판정용 cap이 아니라 진행 여부를 재평가하는 soft window다.
    # 나머지 두 값도 비정상 루프/장애를 끊는 watchdog이며, 소진 시 판정은 항상
    # INCONCLUSIVE + replay checkpoint다.
    max_steps_per_tb: int = Field(default=16, ge=1, le=128)
    max_tool_calls_per_tb: int = Field(default=64, ge=1, le=256)
    max_elapsed_seconds_per_tb: int = Field(default=600, ge=1, le=3600)
    max_stagnant_plans_per_tb: int = Field(default=4, ge=1, le=16)
    max_changed_targets_per_tb: int = Field(default=1, ge=1, le=1)
    max_output_bytes_per_tool: int = Field(default=65536, ge=1024, le=65536)
    max_minimization_trials: int = Field(default=64, ge=1, le=128)


class FixedPermissionProfiles(BaseModel):
    host: dict[str, bool] = Field(default_factory=dict)
    container: dict[str, bool] = Field(default_factory=dict)

    @model_validator(mode="after")
    def normalize_profiles(self) -> "FixedPermissionProfiles":
        from .permission_controls import PROFILE_DEFAULTS, PROFILE_KEYS

        for mode in (SubjectMode.host, SubjectMode.container):
            profile = getattr(self, mode.value)
            expected = set(PROFILE_KEYS[mode])
            extra = set(profile) - expected
            if extra:
                raise ValueError(
                    f"{mode.value} 권한 프로파일에 잘못된 항목이 있습니다: "
                    + ", ".join(sorted(extra))
                )
            normalized = {**PROFILE_DEFAULTS[mode], **profile}
            setattr(self, mode.value, normalized)
        if self.container["privileged"] and not self.container["run_as_root"]:
            raise ValueError("privileged 실험은 run_as_root=ON이 필요합니다.")
        return self


class AgentRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope: Literal["all_trust_boundaries"] = "all_trust_boundaries"
    planner_model: PlannerModel | None = None
    budget: AgentBudget = Field(default_factory=AgentBudget)


class DamageScore(BaseModel):
    total: int = Field(ge=0, le=100)
    impact: int = Field(ge=0, le=100)
    proof: int = Field(ge=0, le=100)
    blast_radius: int = Field(ge=0, le=100)
    reproducibility: int = Field(ge=0, le=100)


class FrozenAttackStep(BaseModel):
    sequence: int = Field(ge=1)
    step_id: str = "contract-step"
    type: Literal["execute"] = "execute"
    tool: str
    action: str
    resource_ref: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    expected_result: Literal["allowed"] = "allowed"
    status: str = "FROZEN"
    selection_rationale: str = ""
    expected_state_fingerprint: str | None = None


class AttackContract(BaseModel):
    contract_id: str
    trust_boundary_id: str
    objective: str
    impact: str
    source_environment: EnvironmentNode
    target_environment: EnvironmentNode
    tool: str
    action: str
    resource_ref: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    verifier: str
    success_criteria: list[str] = Field(default_factory=list)
    rollback: str
    original_evidence_refs: list[str] = Field(default_factory=list)
    maximum_profile_hash: str
    damage_score: DamageScore
    chain_hash: str = ""
    chain_steps: list[FrozenAttackStep] = Field(default_factory=list)


class PermissionTrial(BaseModel):
    sequence: int
    strategy: Literal["llm_seed", "service_group", "partition", "single", "restore_verify", "final_verify"]
    candidate_permission_ids: list[str] = Field(default_factory=list)
    removed_permission_ids: list[str] = Field(default_factory=list)
    success: bool
    proof_level: str
    verifier: str
    evidence_refs: list[str] = Field(default_factory=list)


class PermissionMinimizationResult(BaseModel):
    status: Literal["NOT_STARTED", "SKIPPED", "COMPLETED", "FAILED"] = "NOT_STARTED"
    initial_permission_ids: list[str] = Field(default_factory=list)
    llm_suggested_permission_ids: list[str] = Field(default_factory=list)
    minimal_permission_ids: list[str] = Field(default_factory=list)
    essential_permission_ids: list[str] = Field(default_factory=list)
    minimal_permission_profiles: FixedPermissionProfiles = Field(default_factory=FixedPermissionProfiles)
    trials: list[PermissionTrial] = Field(default_factory=list)
    one_minimal_verified: bool = False
    fallback_to_maximum: bool = False


class AgentFinding(BaseModel):
    finding_id: str
    trust_boundary_id: str
    title: str
    preconditions: list[str] = Field(default_factory=list)
    impact: str
    confidence: float = Field(ge=0, le=1)
    evidence_refs: list[str] = Field(default_factory=list)
    executable: bool = True
    blocked_reason: str | None = None


class AgentPlanStep(BaseModel):
    step_id: str
    type: Literal["observe", "execute", "verify", "rollback"]
    tool: str
    action: str
    resource_ref: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    expected_result: Literal["allowed", "denied", "observed", "restored"]
    status: str = "PENDING"
    sequence: int = 0
    candidate_id: str = ""
    selection_rationale: str = ""
    policy_decision: Literal["ALLOWED", "DENIED"] | None = None
    execution_status: Literal["EXECUTED", "FAILED", "SKIPPED"] | None = None
    verification_status: Literal["VERIFIED", "REJECTED", "INCONCLUSIVE"] | None = None
    state_before: dict[str, Any] = Field(default_factory=dict)
    state_after: dict[str, Any] = Field(default_factory=dict)
    state_changes: list[dict[str, Any]] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    runtime_result: Literal["allowed", "denied", "error"] | None = None
    outcome: Literal["ALLOWED", "OS_DENIED", "ERROR", "POLICY_BLOCKED"] | None = None


class ChainSearchProgress(BaseModel):
    status: Literal["PENDING", "RUNNING", "SEARCH_COMPLETE", "PAUSED", "FAILED"] = "PENDING"
    discovered_states: int = 1
    explored_states: int = 0
    unique_transitions: int = 0
    repeated_states: int = 0
    frontier_candidates: int = 0
    policy_pruned_candidates: int = 0
    tool_calls_used: int = 0
    planner_calls_used: int = 0
    automatic_extensions: int = 0
    termination_reason: Literal[
        "MAX_IMPACT_VERIFIED",
        "FRONTIER_EXHAUSTED",
        "POLICY_FRONTIER_EXHAUSTED",
        "NO_PROGRESS",
        "SEARCH_BUDGET_EXHAUSTED",
        "WATCHDOG_TIMEOUT",
        "CANCELLED",
        "POLICY_VIOLATION",
        "RESET_FAILED",
        "ERROR",
    ] | None = None
    termination_explanation: str | None = None
    search_complete: bool = False
    budget_exhausted: bool = False
    resume_available: bool = False
    checkpoint_id: str | None = None
    checkpoint: dict[str, Any] = Field(default_factory=dict)
    visited_transitions: list[str] = Field(default_factory=list)
    remaining_frontier: list[str] = Field(default_factory=list)
    last_state_fingerprint: str = ""


class TbScenario(BaseModel):
    scenario_id: str
    trust_boundary_id: str
    risk_level: Literal["critical", "high", "medium", "low"]
    risk_score: int = Field(ge=0, le=100)
    objective: str
    impact: str
    tool_implemented: bool = True
    steps: list[AgentPlanStep] = Field(default_factory=list)
    chain_id: str = ""
    chain_status: Literal["PENDING", "RUNNING", "COMPLETED", "PAUSED", "FAILED"] = "PENDING"
    search: ChainSearchProgress = Field(default_factory=ChainSearchProgress)
    rollback_status: Literal["NOT_REQUIRED", "VERIFIED", "FAILED"] = "NOT_REQUIRED"


class TbResult(BaseModel):
    trust_boundary_id: str
    source_environment: EnvironmentNode
    target_environment: EnvironmentNode
    verdict: Literal["BROKEN", "BLOCKED", "INCONCLUSIVE"]
    highest_impact: str
    attack_path: list[str] = Field(default_factory=list)
    fixed_permissions_used: list[str] = Field(default_factory=list)
    effective_identity: dict[str, Any] = Field(default_factory=dict)
    risk_score: int = Field(ge=0, le=100)
    proof_level: Literal[
        "L0_INFERRED",
        "L1_REACHABLE",
        "L2_EXECUTED",
        "L3_IMPACTED",
        "L4_RESTORED",
    ]
    evidence_refs: list[str] = Field(default_factory=list)
    rollback_status: Literal["NOT_REQUIRED", "VERIFIED", "FAILED"]
    scenario: TbScenario
    runtime_result: Literal["allowed", "denied", "error"] | None = None
    explanation: str


class AgentRunSummary(BaseModel):
    broken: int = 0
    blocked: int = 0
    inconclusive: int = 0


class AgentRunRecord(BaseModel):
    run_id: str
    objective: str
    scope: Literal["all_trust_boundaries"] = "all_trust_boundaries"
    status: Literal[
        "RECEIVED", "RUNNING", "PAUSED", "COMPLETED", "FAILED", "CANCELLED"
    ] = "RECEIVED"
    agent_stage: Literal[
        "profile", "maximize", "recon", "analyze", "plan", "execute", "compare",
        "contract", "minimize", "reverify", "finished"
    ] = "profile"
    fixed_permission_profiles: FixedPermissionProfiles
    profile_hash: str
    effective_permissions: dict[str, dict[str, Any]] = Field(default_factory=dict)
    recon_snapshot: dict[str, Any] = Field(default_factory=dict)
    infrastructure_snapshot: dict[str, Any] = Field(default_factory=dict)
    findings: list[AgentFinding] = Field(default_factory=list)
    tb_scenarios: list[TbScenario] = Field(default_factory=list)
    tb_results: list[TbResult] = Field(default_factory=list)
    worst_case_scenario: TbScenario | None = None
    attack_contract: AttackContract | None = None
    permission_minimization: PermissionMinimizationResult = Field(
        default_factory=PermissionMinimizationResult
    )
    summary: AgentRunSummary = Field(default_factory=AgentRunSummary)
    budget: AgentBudget = Field(default_factory=AgentBudget)
    planner_mode: Literal["local", "openrouter"] = "local"
    planner_model: PlannerModel | None = None
    rollback_status: Literal["NOT_REQUIRED", "VERIFIED", "FAILED"] = "NOT_REQUIRED"
    profile_application_checks: dict[str, dict[str, bool]] = Field(default_factory=dict)
    profile_warnings: list[str] = Field(default_factory=list)
    events: list[RunEvent] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
