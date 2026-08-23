from pathlib import Path
from typing import Any, Protocol

import httpx

from .tools import ExecutionResult


class HostRunner(Protocol):
    def is_available(self) -> bool: ...

    def apply_profile(self, profile_id: str) -> str: ...

    def execute(
        self,
        name: str,
        arguments: dict[str, Any],
        expected_resource_id: str,
        profile_id: str,
    ) -> ExecutionResult: ...

    def execute_integrated(
        self,
        profile_ids: list[str],
        executions: list[dict[str, Any]],
    ) -> tuple[list[str], list[ExecutionResult]]: ...


class HostSupervisorClient:
    """Narrow client for the root-owned supervisor's Unix socket API."""

    def __init__(self, socket_path: Path, timeout: float = 10.0) -> None:
        self.socket_path = socket_path
        self.timeout = timeout

    def is_available(self) -> bool:
        return self.socket_path.is_socket()

    def apply_profile(self, profile_id: str) -> str:
        body = self._post("/v1/profiles/apply", {"profile_id": profile_id})
        applied = body.get("applied_profile")
        if applied != profile_id:
            raise RuntimeError("Host Supervisor가 요청과 다른 프로파일을 적용했습니다.")
        return applied

    def execute(
        self,
        name: str,
        arguments: dict[str, Any],
        expected_resource_id: str,
        profile_id: str,
    ) -> ExecutionResult:
        body = self._post(
            "/v1/execute",
            {
                "profile_id": profile_id,
                "tool": name,
                "arguments": arguments,
                "expected_resource_id": expected_resource_id,
            },
        )
        return ExecutionResult(
            runtime_result=str(body["runtime_result"]),
            output=str(body["output"]),
            exit_code=int(body["exit_code"]),
            before_sha256=body.get("before_sha256"),
            after_sha256=body.get("after_sha256"),
        )

    def execute_integrated(
        self,
        profile_ids: list[str],
        executions: list[dict[str, Any]],
    ) -> tuple[list[str], list[ExecutionResult]]:
        body = self._post(
            "/v1/execute-integrated",
            {"profile_ids": profile_ids, "executions": executions},
        )
        applied = body.get("applied_profiles")
        raw_results = body.get("results")
        if applied != profile_ids or not isinstance(raw_results, list):
            raise RuntimeError("Host Supervisor 통합 실행 응답이 올바르지 않습니다.")
        return applied, [
            ExecutionResult(
                runtime_result=str(item["runtime_result"]),
                output=str(item["output"]),
                exit_code=int(item["exit_code"]),
                before_sha256=item.get("before_sha256"),
                after_sha256=item.get("after_sha256"),
            )
            for item in raw_results
        ]

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.socket_path.exists():
            raise RuntimeError(
                "Host Supervisor 소켓이 없습니다. AWS Host 런타임에서 실행하세요."
            )
        transport = httpx.HTTPTransport(uds=str(self.socket_path))
        try:
            with httpx.Client(
                transport=transport,
                base_url="http://host-supervisor",
                timeout=self.timeout,
            ) as client:
                response = client.post(path, json=payload)
                response.raise_for_status()
                body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            detail = ""
            if isinstance(exc, httpx.HTTPStatusError):
                try:
                    detail = str(exc.response.json().get("detail", ""))
                except (ValueError, AttributeError):
                    detail = exc.response.text
            suffix = f": {detail}" if detail else ""
            raise RuntimeError(f"Host Supervisor 요청에 실패했습니다{suffix}") from exc
        if not isinstance(body, dict):
            raise RuntimeError("Host Supervisor 응답 형식이 올바르지 않습니다.")
        return body
