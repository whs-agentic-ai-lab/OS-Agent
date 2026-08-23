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
from .executor import AgentExecutor
from .host_client import HostRunner, HostSupervisorClient
from .planner import LocalPlanner, OpenRouterPlanner
from .repository import create_run_repository
from .schemas import (
    OptionsResponse,
    RunDeleteResponse,
    RunEvent,
    RunListResponse,
    RunRecord,
    RunRequest,
)
from .tools import ToolRunner
from .tunnel import SsmTunnelManager, TunnelRequest, TunnelStatus, TunnelStopRequest


def create_app(
    settings: Settings | None = None,
    host_runner: HostRunner | None = None,
) -> FastAPI:
    active_settings = settings or get_settings()
    repository = create_run_repository(
        active_settings.supabase_url,
        active_settings.supabase_secret_key,
    )
    tool_runner = ToolRunner(active_settings.runtime_dir)
    planner = (
        OpenRouterPlanner(active_settings.openrouter_api_key, active_settings.openrouter_model)
        if active_settings.openrouter_api_key
        else LocalPlanner()
    )
    active_host_runner = host_runner or HostSupervisorClient(
        active_settings.host_supervisor_socket
    )
    executor = AgentExecutor(planner, tool_runner, repository, active_host_runner)
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
            "run_api_version": "integrated-v1",
            "planner": planner.mode,
            "storage": repository.storage_name,
            "host_supervisor": (
                "connected" if active_host_runner.is_available() else "unavailable"
            ),
        }

    @application.get("/api/options", response_model=OptionsResponse)
    def options() -> OptionsResponse:
        return OptionsResponse(
            subject_modes=[
                mode.model_copy(
                    update={
                        "enabled": mode.id.value != "host"
                        or active_host_runner.is_available()
                    }
                )
                for mode in SUBJECT_MODES
            ],
            permission_tests={key.value: value for key, value in PERMISSION_TESTS.items()},
            tools=TOOLS,
            planner_mode=planner.mode,
        )

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
        if remote_health_payload.get("run_api_version") != "integrated-v1":
            raise HTTPException(
                status_code=409,
                detail=(
                    "AWS 백엔드가 통합 Run API를 지원하지 않습니다. "
                    "원격 백엔드 이미지와 Host Supervisor를 먼저 갱신하세요."
                ),
            )
        run = RunRecord.model_validate(
            remote_request(
                "POST",
                "/api/runs",
                request.model_dump(
                    mode="json",
                    exclude={"permission_id", "permission_enabled"},
                ),
            )
        )
        requested_permissions = [item.model_dump() for item in request.permissions]
        returned_permissions = [item.model_dump() for item in run.permissions]
        if (
            returned_permissions != requested_permissions
            or len(run.permission_results) != len(request.permissions)
        ):
            raise HTTPException(
                status_code=502,
                detail="AWS 백엔드가 통합 권한 결과를 완전하게 반환하지 않았습니다.",
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
        if request.subject_mode.value == "host" and not active_host_runner.is_available():
            raise HTTPException(
                status_code=409,
                detail="Ubuntu Host 실험은 SSM으로 연결된 AWS 런타임에서만 실행할 수 있습니다.",
            )
        try:
            return executor.run(request)
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
