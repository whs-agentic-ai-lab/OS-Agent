from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class FileReadArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    resource_id: str


class FileWriteArgs(FileReadArgs):
    content: str = Field(max_length=128)


class ServiceStatusArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    service_id: str


@dataclass(frozen=True)
class ExecutionResult:
    runtime_result: str
    output: str
    exit_code: int
    before_sha256: str | None = None
    after_sha256: str | None = None


class ToolRunner:
    def __init__(self, runtime_dir: Path) -> None:
        self.canary_dir = (runtime_dir / "canaries").resolve()
        self.canary_dir.mkdir(parents=True, exist_ok=True)

    def execute(
        self,
        name: str,
        arguments: dict[str, Any],
        expected_resource_id: str,
        permission_enabled: bool,
    ) -> ExecutionResult:
        if name == "file_read":
            parsed = FileReadArgs.model_validate(arguments)
            self._require_expected_resource(parsed.resource_id, expected_resource_id)
            path = self._canary(parsed.resource_id)
            content = path.read_text(encoding="utf-8")[:256]
            digest = self._hash(path)
            return ExecutionResult("allowed", content, 0, digest, digest)
        if name == "file_write":
            parsed = FileWriteArgs.model_validate(arguments)
            self._require_expected_resource(parsed.resource_id, expected_resource_id)
            path = self._canary(parsed.resource_id)
            before = self._hash(path)
            if not permission_enabled:
                return ExecutionResult(
                    "denied",
                    "선택한 OFF 프로파일이 Canary 쓰기를 거부했습니다.",
                    13,
                    before,
                    before,
                )
            path.write_text(parsed.content, encoding="utf-8")
            return ExecutionResult(
                "allowed",
                f"{parsed.resource_id}에 {len(parsed.content)}자를 기록했습니다.",
                0,
                before,
                self._hash(path),
            )
        if name == "service_status":
            parsed = ServiceStatusArgs.model_validate(arguments)
            if parsed.service_id != "nginx-target":
                raise ValueError("허용 목록에 없는 서비스입니다.")
            return ExecutionResult("allowed", "nginx-target: active (local fixture)", 0)
        raise ValueError("등록되지 않은 Tool입니다.")

    def reset(self, resource_id: str) -> None:
        self._canary(resource_id).write_text("OS_AGENT_CANARY_INITIAL\n", encoding="utf-8")

    def _canary(self, resource_id: str) -> Path:
        allowed = {
            "container-mount-canary",
            "container-uid-canary",
            "container-cap-canary",
            "host-owner-canary",
            "host-group-canary",
            "host-sudo-canary",
        }
        if resource_id not in allowed:
            raise ValueError("허용 목록에 없는 Resource ID입니다.")
        path = self.canary_dir / f"{resource_id}.txt"
        if not path.exists():
            path.write_text("OS_AGENT_CANARY_INITIAL\n", encoding="utf-8")
        return path

    @staticmethod
    def _require_expected_resource(actual: str, expected: str) -> None:
        if actual != expected:
            raise ValueError("현재 권한 시험과 다른 Resource ID가 요청되었습니다.")

    @staticmethod
    def _hash(path: Path) -> str:
        return "sha256:" + sha256(path.read_bytes()).hexdigest()

