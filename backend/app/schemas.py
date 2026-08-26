from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


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


class SubjectOption(BaseModel):
    id: SubjectMode
    label: str
    description: str
    enabled: bool = True


class ToolOption(BaseModel):
    id: str
    label: str
    description: str


class TrustBoundaryOption(BaseModel):
    id: str
    boundary_type: BoundaryType
    source_mode: SubjectMode
    source_environment: EnvironmentNode
    target_environment: EnvironmentNode
    label: str
    description: str


class OptionsResponse(BaseModel):
    subject_modes: list[SubjectOption]
    permission_tests: dict[str, list[PermissionTest]]
    tools: list[ToolOption]
    trust_boundaries: list[TrustBoundaryOption]
    planner_mode: Literal["local", "openrouter"] = "local"


class PermissionSelection(BaseModel):
    permission_id: str
    enabled: bool


PROFILE_KEYS: dict[SubjectMode, tuple[str, str, str]] = {
    SubjectMode.container: ("mount_write", "run_as_root", "dac_override"),
    SubjectMode.host: ("owner_write", "group_write", "limited_sudo"),
}


class RunRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=4000)
    subject_mode: SubjectMode
    trust_boundary_id: str | None = None
    permission_profile: dict[str, bool] = Field(default_factory=dict)
    # v1 로그/클라이언트를 읽기 위한 호환 필드입니다. 신규 요청의 기준은
    # permission_profile 객체 하나이며 목록 단위 실행은 하지 않습니다.
    permissions: list[PermissionSelection] = Field(default_factory=list)
    # 구버전 클라이언트 호환 필드. 새 클라이언트는 permissions만 전송합니다.
    permission_id: str | None = None
    permission_enabled: bool | None = None

    @model_validator(mode="after")
    def normalize_permissions(self) -> "RunRequest":
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
        if actual_keys != expected_keys:
            missing = ", ".join(sorted(expected_keys - actual_keys)) or "없음"
            extra = ", ".join(sorted(actual_keys - expected_keys)) or "없음"
            raise ValueError(
                "권한 프로파일 묶음은 선택 환경의 세 항목을 모두 포함해야 합니다. "
                f"누락: {missing}; 잘못된 항목: {extra}"
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
    ]
    event_type: str
    message: str
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class ToolDecision(BaseModel):
    name: Literal["file_read", "file_write", "service_status"]
    arguments: dict[str, Any]


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
    prompt: str
    subject_mode: SubjectMode
    trust_boundary_id: str
    source_environment: EnvironmentNode
    target_environment: EnvironmentNode
    permission_profile: dict[str, bool]
    profile_id: str
    tool_decision: ToolDecision | None = None
    planner_mode: Literal["local", "openrouter"] = "local"


class RuntimeResetRequest(BaseModel):
    run_id: str
    subject_mode: SubjectMode
    trust_boundary_id: str | None = None
    target_environment: EnvironmentNode | None = None


class RuntimeResetResult(BaseModel):
    status: Literal["RESET", "RESET_FAILED"]
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
    tool: Literal["file_read", "file_write", "service_status"]
    tool_arguments: dict[str, Any] = Field(default_factory=dict)
    policy_decision: Literal["allowed", "denied"] = "allowed"
    runtime_result: Literal["allowed", "denied", "error"]
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
