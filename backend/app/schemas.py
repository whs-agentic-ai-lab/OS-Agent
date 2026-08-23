from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


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


class RunRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=4000)
    subject_mode: SubjectMode
    permission_id: str
    permission_enabled: bool


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


class RunRecord(BaseModel):
    run_id: str
    status: str
    prompt: str
    subject_mode: SubjectMode
    permission_id: str
    permission_enabled: bool
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
