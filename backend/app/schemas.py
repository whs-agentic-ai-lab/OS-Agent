from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SubjectMode(str, Enum):
    container = "container"
    host = "host"


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


class OptionsResponse(BaseModel):
    subject_modes: list[SubjectOption]
    permission_tests: dict[str, list[PermissionTest]]
    tools: list[ToolOption]
    planner_mode: Literal["local", "openrouter"]


class PermissionSelection(BaseModel):
    permission_id: str
    enabled: bool


class RunRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=4000)
    subject_mode: SubjectMode
    permissions: list[PermissionSelection] = Field(default_factory=list)
    # 구버전 클라이언트 호환 필드. 새 클라이언트는 permissions만 전송합니다.
    permission_id: str | None = None
    permission_enabled: bool | None = None

    @model_validator(mode="after")
    def normalize_permissions(self) -> "RunRequest":
        if not self.permissions and self.permission_id and self.permission_enabled is not None:
            self.permissions = [
                PermissionSelection(
                    permission_id=self.permission_id,
                    enabled=self.permission_enabled,
                )
            ]
        if not self.permissions:
            raise ValueError("하나 이상의 권한 프로파일을 선택하세요.")
        permission_ids = [item.permission_id for item in self.permissions]
        if len(permission_ids) != len(set(permission_ids)):
            raise ValueError("같은 권한 항목을 중복 선택할 수 없습니다.")
        if self.permission_id is None:
            self.permission_id = self.permissions[0].permission_id
            self.permission_enabled = self.permissions[0].enabled
        return self


class RunEvent(BaseModel):
    sequence: int
    source: Literal["profile", "model", "tool_runner", "executor", "verifier"]
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


class RunRecord(BaseModel):
    run_id: str
    status: str
    prompt: str
    subject_mode: SubjectMode
    permission_id: str
    permission_enabled: bool
    permissions: list[PermissionSelection] = Field(default_factory=list)
    permission_results: list[PermissionRunResult] = Field(default_factory=list)
    requested_profile: str
    applied_profile: str | None = None
    result_format_version: Literal["common-minimum-v1"] = "common-minimum-v1"
    profile_version: str = "UNIMPLEMENTED"
    workload_type: Literal["normal", "attack", "UNIMPLEMENTED"] = "UNIMPLEMENTED"
    action_path_id: str = "UNIMPLEMENTED"
    changed_variable: str = "UNIMPLEMENTED"
    planner_mode: Literal["local", "openrouter"]
    tool: str | None = None
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
        permission_id = value.get("permission_id")
        permission_enabled = value.get("permission_enabled")
        if not permissions and isinstance(permission_id, str) and isinstance(permission_enabled, bool):
            permissions = [{"permission_id": permission_id, "enabled": permission_enabled}]
            value = {**value, "permissions": permissions}

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
