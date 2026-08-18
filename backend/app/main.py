from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .catalog import PERMISSION_TESTS, SUBJECT_MODES, TOOLS
from .config import Settings, get_settings
from .deployment import DeploymentManager, DeploymentRequest, DeploymentStatus
from .executor import AgentExecutor
from .planner import LocalPlanner, OpenRouterPlanner
from .repository import InMemoryRunRepository
from .schemas import OptionsResponse, RunEvent, RunRecord, RunRequest
from .tools import ToolRunner


def create_app(settings: Settings | None = None) -> FastAPI:
    active_settings = settings or get_settings()
    repository = InMemoryRunRepository()
    tool_runner = ToolRunner(active_settings.runtime_dir)
    planner = (
        OpenRouterPlanner(active_settings.openrouter_api_key, active_settings.openrouter_model)
        if active_settings.openrouter_api_key
        else LocalPlanner()
    )
    executor = AgentExecutor(planner, tool_runner, repository)
    deployment_manager = DeploymentManager(active_settings)

    application = FastAPI(title="OS Agent Minimum Test API", version="0.1.0")
    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(active_settings.allowed_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

    @application.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "planner": planner.mode, "storage": "memory"}

    @application.get("/api/options", response_model=OptionsResponse)
    def options() -> OptionsResponse:
        return OptionsResponse(
            subject_modes=SUBJECT_MODES,
            permission_tests={key.value: value for key, value in PERMISSION_TESTS.items()},
            tools=TOOLS,
            planner_mode=planner.mode,
        )

    @application.get("/api/deployments/current", response_model=DeploymentStatus)
    def get_deployment() -> DeploymentStatus:
        return deployment_manager.refresh_prerequisites()

    @application.post("/api/deployments", response_model=DeploymentStatus)
    def create_deployment(request: DeploymentRequest) -> DeploymentStatus:
        del request
        try:
            return deployment_manager.start()
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @application.post("/api/runs", response_model=RunRecord)
    def create_run(request: RunRequest) -> RunRecord:
        try:
            return executor.run(request)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @application.get("/api/runs/{run_id}", response_model=RunRecord)
    def get_run(run_id: str) -> RunRecord:
        run = repository.get(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="실행 기록을 찾을 수 없습니다.")
        return run

    @application.get("/api/runs/{run_id}/events", response_model=list[RunEvent])
    def get_events(run_id: str) -> list[RunEvent]:
        run = repository.get(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="실행 기록을 찾을 수 없습니다.")
        return run.events

    return application


app = create_app()
