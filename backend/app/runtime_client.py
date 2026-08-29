from pathlib import Path
from typing import Protocol

import httpx

from .schemas import (
    ExperimentEnvironmentResetResult,
    RuntimeAgentResult,
    RuntimeDispatchRequest,
    RuntimeResetRequest,
    RuntimeResetResult,
    SubjectMode,
)


class EnvironmentRuntime(Protocol):
    """Control Backend가 의존하는 유일한 환경 실행 계약."""

    def is_available(self, subject_mode: SubjectMode | None = None) -> bool: ...

    def execute(self, request: RuntimeDispatchRequest) -> RuntimeAgentResult: ...

    def reset_harness(self, request: RuntimeResetRequest) -> RuntimeResetResult: ...

    def reset_environment(self) -> ExperimentEnvironmentResetResult: ...


class SupervisorRuntimeClient:
    """Root Supervisor에 Run을 위임하되 Tool 실행에는 관여하지 않습니다."""

    def __init__(self, socket_path: Path, timeout: float = 45.0) -> None:
        self.socket_path = socket_path
        self.timeout = timeout

    def is_available(self, subject_mode: SubjectMode | None = None) -> bool:
        del subject_mode
        return self.socket_path.is_socket()

    def execute(self, request: RuntimeDispatchRequest) -> RuntimeAgentResult:
        if not self.socket_path.exists():
            raise RuntimeError(
                "환경 Runtime Supervisor 소켓이 없습니다. SSM으로 EC2 Runtime에 연결하세요."
            )
        transport = httpx.HTTPTransport(uds=str(self.socket_path))
        try:
            with httpx.Client(
                transport=transport,
                base_url="http://environment-runtime",
                timeout=self.timeout,
            ) as client:
                response = client.post(
                    "/v2/runs",
                    json=request.model_dump(mode="json"),
                )
                response.raise_for_status()
                payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            detail = ""
            if isinstance(exc, httpx.HTTPStatusError):
                try:
                    detail = str(exc.response.json().get("detail", ""))
                except (ValueError, AttributeError):
                    detail = exc.response.text
            suffix = f": {detail}" if detail else ""
            raise RuntimeError(f"환경 Runtime 실행 요청에 실패했습니다{suffix}") from exc
        return RuntimeAgentResult.model_validate(payload)

    def reset_harness(self, request: RuntimeResetRequest) -> RuntimeResetResult:
        if not self.socket_path.exists():
            raise RuntimeError(
                "환경 Runtime Supervisor 소켓이 없습니다. SSM으로 EC2 Runtime에 연결하세요."
            )
        transport = httpx.HTTPTransport(uds=str(self.socket_path))
        try:
            with httpx.Client(
                transport=transport,
                base_url="http://environment-runtime",
                timeout=self.timeout,
            ) as client:
                response = client.post(
                    "/v2/harness/reset",
                    json=request.model_dump(mode="json"),
                )
                response.raise_for_status()
                payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            detail = ""
            if isinstance(exc, httpx.HTTPStatusError):
                try:
                    detail = str(exc.response.json().get("detail", ""))
                except (ValueError, AttributeError):
                    detail = exc.response.text
            suffix = f": {detail}" if detail else ""
            raise RuntimeError(f"환경 Runtime Reset 요청에 실패했습니다{suffix}") from exc
        return RuntimeResetResult.model_validate(payload)

    def reset_environment(self) -> ExperimentEnvironmentResetResult:
        if not self.socket_path.exists():
            raise RuntimeError(
                "환경 Runtime Supervisor 소켓이 없습니다. SSM으로 EC2 Runtime에 연결하세요."
            )
        transport = httpx.HTTPTransport(uds=str(self.socket_path))
        try:
            with httpx.Client(
                transport=transport,
                base_url="http://environment-runtime",
                timeout=45.0,
            ) as client:
                response = client.post(
                    "/v2/environment/reset",
                    json={"confirmation": "RESET_EXPERIMENT_ENVIRONMENT"},
                )
                response.raise_for_status()
                payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            detail = ""
            if isinstance(exc, httpx.HTTPStatusError):
                try:
                    detail = str(exc.response.json().get("detail", ""))
                except (ValueError, AttributeError):
                    detail = exc.response.text
            suffix = f": {detail}" if detail else ""
            raise RuntimeError(f"실험 환경 초기화 요청에 실패했습니다{suffix}") from exc
        return ExperimentEnvironmentResetResult.model_validate(payload)
