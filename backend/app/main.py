import json

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from .catalog import PERMISSION_TESTS, SUBJECT_MODES, TOOLS
from .config import Settings, get_settings
from .deployment import (
    DeploymentManager,
    DeploymentRequest,
    DeploymentStatus,
    DestroyRequest,
    InitializeRequest,
    TerminateInstanceRequest,
)
from .executor import RunCoordinator
from .harness import (
    HarnessComponents,
    HarnessCoordinator,
    HarnessRunRecord,
    HarnessRunRequest,
    HarnessStatus,
    InMemoryHarnessRunRepository,
    create_fixture_harness_components,
)
from .repository import create_run_repository
from .runtime_client import EnvironmentRuntime, SupervisorRuntimeClient
from .schemas import (
    OptionsResponse,
    RunDeleteResponse,
    RunEvent,
    RunListResponse,
    RunRecord,
    RunRequest,
)
from .tunnel import SsmTunnelManager, TunnelRequest, TunnelStatus, TunnelStopRequest


def create_app(
    settings: Settings | None = None,
    runtime_client: EnvironmentRuntime | None = None,
    harness_components: HarnessComponents | None = None,
) -> FastAPI:
    active_settings = settings or get_settings()
    repository = create_run_repository(
        active_settings.supabase_url,
        active_settings.supabase_secret_key,
    )
    active_runtime = runtime_client or SupervisorRuntimeClient(
        active_settings.host_supervisor_socket
    )
    coordinator = RunCoordinator(active_runtime, repository)
    harness_repository = InMemoryHarnessRunRepository()
    harness_coordinator = HarnessCoordinator(
        harness_components or HarnessComponents(),
        harness_repository,
    )
    fixture_harness_repository = InMemoryHarnessRunRepository()
    fixture_harness_coordinator = HarnessCoordinator(
        create_fixture_harness_components(),
        fixture_harness_repository,
    )
    deployment_manager = DeploymentManager(active_settings)
    tunnel_manager = SsmTunnelManager(active_settings)

    application = FastAPI(title="OS Agent Minimum Test API", version="0.1.0")
    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(active_settings.allowed_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Content-Type"],
    )
    application.add_event_handler("shutdown", tunnel_manager.close)

    @application.get("/api/health")
    def health() -> dict[str, str]:
        return {
            "status": "ok",
            "run_api_version": "profile-runtime-v2",
            "harness_api_version": "os-harness-v1",
            "planner": "environment-runtime",
            "storage": repository.storage_name,
            "host_supervisor": (
                "connected" if active_runtime.is_available() else "unavailable"
            ),
        }

    @application.get("/api/options", response_model=OptionsResponse)
    def options() -> OptionsResponse:
        return OptionsResponse(
            subject_modes=[
                mode.model_copy(
                    update={
                        "enabled": active_runtime.is_available(mode.id)
                    }
                )
                for mode in SUBJECT_MODES
            ],
            permission_tests={key.value: value for key, value in PERMISSION_TESTS.items()},
            tools=TOOLS,
            planner_mode="environment",
        )

    @application.get("/api/harness/status", response_model=HarnessStatus)
    def harness_status() -> HarnessStatus:
        return harness_coordinator.get_status()

    @application.post("/api/harness/runs", response_model=HarnessRunRecord)
    def create_harness_run(request: HarnessRunRequest) -> HarnessRunRecord:
        return harness_coordinator.run(request)

    @application.get("/api/harness/runs/{run_id}", response_model=HarnessRunRecord)
    def get_harness_run(run_id: str) -> HarnessRunRecord:
        run = harness_repository.get(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Harness 실행 기록을 찾을 수 없습니다.")
        return run

    @application.get("/api/harness/fixtures/status", response_model=HarnessStatus)
    def fixture_harness_status() -> HarnessStatus:
        return fixture_harness_coordinator.get_status()

    @application.post(
        "/api/harness/fixture-runs",
        response_model=HarnessRunRecord,
    )
    def create_fixture_harness_run(
        request: HarnessRunRequest,
    ) -> HarnessRunRecord:
        return fixture_harness_coordinator.run(request)

    @application.get(
        "/api/harness/fixture-runs/{run_id}",
        response_model=HarnessRunRecord,
    )
    def get_fixture_harness_run(run_id: str) -> HarnessRunRecord:
        run = fixture_harness_repository.get(run_id)
        if run is None:
            raise HTTPException(
                status_code=404,
                detail="Fixture Harness 실행 기록을 찾을 수 없습니다.",
            )
        return run

    @application.get("/api/deployments/current", response_model=DeploymentStatus)
    def get_deployment() -> DeploymentStatus:
        return deployment_manager.refresh_prerequisites()

    @application.post("/api/deployments", response_model=DeploymentStatus)
    def create_deployment(request: DeploymentRequest) -> DeploymentStatus:
        try:
            return deployment_manager.start(request)
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @application.post("/api/deployments/initialize", response_model=DeploymentStatus)
    def initialize_deployment(request: InitializeRequest) -> DeploymentStatus:
        del request
        try:
            return deployment_manager.initialize()
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @application.post("/api/deployments/destroy", response_model=DeploymentStatus)
    def destroy_deployment(request: DestroyRequest) -> DeploymentStatus:
        try:
            return deployment_manager.destroy(request)
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @application.post("/api/deployments/instances/terminate", response_model=DeploymentStatus)
    def terminate_instance(request: TerminateInstanceRequest) -> DeploymentStatus:
        try:
            return deployment_manager.terminate_instance(request)
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @application.get("/api/tunnel", response_model=TunnelStatus)
    def get_tunnel() -> TunnelStatus:
        return tunnel_manager.refresh()

    @application.post("/api/tunnel", response_model=TunnelStatus)
    def start_tunnel(request: TunnelRequest) -> TunnelStatus:
        try:
            return tunnel_manager.start(
                deployment_manager.get_trial_instance_id(request.target_instance_id)
            )
        except (RuntimeError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @application.post("/api/tunnel/stop", response_model=TunnelStatus)
    def stop_tunnel(request: TunnelStopRequest) -> TunnelStatus:
        del request
        return tunnel_manager.stop()

    def remote_request(method: str, path: str, payload: dict | None = None) -> dict:
        tunnel = tunnel_manager.refresh()
        if tunnel.status != "connected":
            raise HTTPException(status_code=409, detail="SSM 터널을 먼저 연결하세요.")
        try:
            response = httpx.request(
                method,
                f"http://127.0.0.1:{tunnel.local_port}{path}",
                json=payload,
                timeout=30,
            )
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail=f"AWS 백엔드 연결 실패: {exc}") from exc
        if not response.is_success:
            detail = response.text
            try:
                detail = response.json().get("detail", detail)
            except (ValueError, AttributeError):
                pass
            raise HTTPException(status_code=response.status_code, detail=detail)
        return response.json()

    @application.get("/api/remote/health")
    def remote_health() -> dict:
        return remote_request("GET", "/api/health")

    @application.get("/api/remote/options", response_model=OptionsResponse)
    def remote_options() -> OptionsResponse:
        return OptionsResponse.model_validate(remote_request("GET", "/api/options"))

    @application.post("/api/remote/runs", response_model=RunRecord)
    def remote_run(request: RunRequest) -> RunRecord:
        remote_health_payload = remote_request("GET", "/api/health")
        if remote_health_payload.get("run_api_version") != "profile-runtime-v2":
            raise HTTPException(
                status_code=409,
                detail=(
                    "AWS 백엔드가 환경 Runtime v2 API를 지원하지 않습니다. "
                    "원격 Backend 이미지와 Supervisor를 먼저 갱신하세요."
                ),
            )
        run = RunRecord.model_validate(
            remote_request(
                "POST",
                "/api/runs",
                request.model_dump(
                    mode="json",
                    exclude={"permission_id", "permission_enabled", "permissions"},
                ),
            )
        )
        if run.permission_profile != request.permission_profile:
            raise HTTPException(
                status_code=502,
                detail="AWS Runtime이 요청한 권한 프로파일 묶음과 다른 결과를 반환했습니다.",
            )
        # Supabase Secret Key는 EC2 Agent 런타임에 전달하지 않는다. 신뢰된 로컬
        # 제어 백엔드가 SSM으로 받은 결과를 영구 저장한다.
        repository.save(run)
        return run

    @application.get("/api/remote/runs/{run_id}", response_model=RunRecord)
    def remote_get_run(run_id: str) -> RunRecord:
        stored_run = repository.get(run_id)
        if stored_run is not None:
            return stored_run
        return RunRecord.model_validate(remote_request("GET", f"/api/runs/{run_id}"))

    @application.post("/api/runs", response_model=RunRecord)
    def create_run(request: RunRequest) -> RunRecord:
        if not active_runtime.is_available(request.subject_mode):
            raise HTTPException(
                status_code=409,
                detail="실제 권한 실험은 SSM으로 연결된 AWS 환경 Runtime에서만 실행할 수 있습니다.",
            )
        try:
            return coordinator.run(request)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @application.get("/api/runs", response_model=RunListResponse)
    def list_runs(
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=20, ge=1, le=100),
    ) -> RunListResponse:
        items, total = repository.list_runs(page, page_size)
        return RunListResponse(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
        )

    @application.get("/api/runs/{run_id}", response_model=RunRecord)
    def get_run(run_id: str) -> RunRecord:
        run = repository.get(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="실행 기록을 찾을 수 없습니다.")
        return run

    @application.delete("/api/runs/{run_id}", response_model=RunDeleteResponse)
    def delete_run(run_id: str) -> RunDeleteResponse:
        if not repository.delete(run_id):
            raise HTTPException(status_code=404, detail="삭제할 실행 기록을 찾을 수 없습니다.")
        return RunDeleteResponse(run_id=run_id, deleted=True)

    @application.get("/api/runs/{run_id}/events", response_model=list[RunEvent])
    def get_events(run_id: str) -> list[RunEvent]:
        run = repository.get(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="실행 기록을 찾을 수 없습니다.")
        return run.events

    return application


app = create_app()
