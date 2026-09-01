import json

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from .catalog import (
    PERMISSION_TESTS,
    SUBJECT_MODES,
    TOOLS,
    TRUST_BOUNDARIES,
    resolve_trust_boundary,
)
from .agent_jobs import AgentRunJobManager
from .agent_orchestrator import ATTACK_AGENT_MISSION, AgentOrchestrator
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
from .execution_gate import ExclusiveExecutorGate, ExecutorBusyError
from .evidence import create_evidence_router
from .model_gateway import ModelGateway
from .harness import (
    HarnessComponents,
    HarnessCoordinator,
    HarnessRunRecord,
    HarnessRunRequest,
    HarnessStatus,
    InMemoryHarnessRunRepository,
    create_os_harness_components,
)
from .repository import create_agent_run_repository, create_run_repository
from .runtime_client import EnvironmentRuntime, SupervisorRuntimeClient
from .schemas import (
    AgentFinding,
    AttackContract,
    CampaignSearchState,
    AgentRunRecord,
    AgentRunRequest,
    ExperimentEnvironmentResetRequest,
    ExperimentEnvironmentResetResult,
    OptionsResponse,
    PermissionCatalogSummary,
    PermissionMinimizationResult,
    PlannerModelOption,
    RunDeleteResponse,
    RunEvent,
    RunListResponse,
    RunRecord,
    RunRequest,
    SubjectMode,
)
from .tunnel import SsmTunnelManager, TunnelRequest, TunnelStatus, TunnelStopRequest


def build_remote_agent_payload(
    request: AgentRunRequest,
    remote_agent_version: str,
) -> dict:
    payload = request.model_dump(mode="json")
    if remote_agent_version in {
        "os-agent-orchestrator-v1",
        "os-agent-orchestrator-v2",
    }:
        from .permission_minimizer import collect_maximum_permission_profiles

        payload["fixed_permission_profiles"] = (
            collect_maximum_permission_profiles().model_dump(mode="json")
        )
    if remote_agent_version == "os-agent-orchestrator-v1":
        payload["prompt"] = ATTACK_AGENT_MISSION
    return payload


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
    agent_repository = create_agent_run_repository(
        active_settings.supabase_url,
        active_settings.supabase_secret_key,
    )
    active_runtime = runtime_client or SupervisorRuntimeClient(
        active_settings.host_supervisor_socket
    )
    model_gateway = ModelGateway(active_settings)
    coordinator = RunCoordinator(active_runtime, repository, model_gateway)
    agent_orchestrator = AgentOrchestrator(
        active_runtime,
        agent_repository,
        model_gateway,
    )
    executor_gate = ExclusiveExecutorGate()
    agent_run_jobs = AgentRunJobManager(executor_gate)
    harness_repository = InMemoryHarnessRunRepository()
    harness_coordinator = HarnessCoordinator(
        harness_components
        or create_os_harness_components(
            active_runtime,
            model_gateway,
            active_settings.approved_os_source_ids,
        ),
        harness_repository,
        evidence_root=active_settings.runtime_dir / "evidence-bundles",
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
    application.add_event_handler("shutdown", agent_run_jobs.close)
    application.include_router(create_evidence_router(active_settings))
    application.state.agent_orchestrator = agent_orchestrator
    application.state.agent_run_jobs = agent_run_jobs

    @application.get("/api/health")
    def health() -> dict[str, str | bool | None]:
        active_executor = executor_gate.active_mode
        return {
            "status": "ok",
            "run_api_version": "permission-control-runtime-v6",
            "agent_run_api_version": "os-agent-orchestrator-v7",
            "harness_api_version": "os-harness-v1",
            "build_git_sha": active_settings.build_git_sha,
            "build_source_dirty": active_settings.build_source_dirty,
            "planner": model_gateway.planner_mode,
            "storage": repository.storage_name,
            "host_supervisor": (
                "connected" if active_runtime.is_available() else "unavailable"
            ),
            "active_executor": (
                active_executor.value if active_executor is not None else None
            ),
            "active_agent_run_id": agent_run_jobs.active_run_id,
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
            permission_catalog_summary=PermissionCatalogSummary(
                source_version="OS팀_권한카탈로그-2026.08.27",
                total_entries=307,
                independent_permission_count=None,
                policy=(
                    "307개 원천 항목은 독립 권한 수가 아닙니다. 핵심 축 중 Runtime에서 "
                    "실제 적용·검증 가능한 항목만 제어값으로 제공합니다."
                ),
            ),
            tools=TOOLS,
            trust_boundaries=TRUST_BOUNDARIES,
            planner_mode=model_gateway.planner_mode,
            planner_models=[
                PlannerModelOption(
                    id="deepseek/deepseek-v4-flash-0731",
                    label="DeepSeek V4 Flash",
                    description="비용 효율이 높은 기본 Tool Call 모델",
                ),
                PlannerModelOption(
                    id="z-ai/glm-5.3-flash",
                    label="GLM-5.3-Flash",
                    description="긴 코딩·에이전트 작업 균형형 모델",
                ),
                PlannerModelOption(
                    id="openai/gpt-5-mini",
                    label="GPT-5 Mini",
                    description="중요 Tool Call의 지시 준수 우선 모델",
                ),
            ],
        )

    @application.get("/api/harness/status", response_model=HarnessStatus)
    def harness_status() -> HarnessStatus:
        return harness_coordinator.get_status()

    @application.post("/api/harness/runs", response_model=HarnessRunRecord)
    def create_harness_run(request: HarnessRunRequest) -> HarnessRunRecord:
        if (
            request.source_id is not None
            and request.source_id not in active_settings.approved_os_source_ids
        ):
            raise HTTPException(
                status_code=422,
                detail={"code": "INVALID_SOURCE_ID", "message": "승인되지 않은 OS Host ID입니다."},
            )
        try:
            resolve_trust_boundary(request.subject_mode, request.trust_boundary_id)
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail={"code": "INVALID_TRUST_BOUNDARY", "message": str(exc)},
            ) from exc
        if request.model is not None and not active_settings.openrouter_api_key:
            raise HTTPException(
                status_code=503,
                detail={"code": "SERVICE_CONFIGURATION_ERROR", "message": "요청한 LLM Provider 자격 증명이 구성되지 않았습니다."},
            )
        try:
            with executor_gate.claim(request.subject_mode):
                return harness_coordinator.run(request)
        except ExecutorBusyError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @application.get("/api/harness/runs/{run_id}", response_model=HarnessRunRecord)
    def get_harness_run(run_id: str) -> HarnessRunRecord:
        run = harness_repository.get(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Harness 실행 기록을 찾을 수 없습니다.")
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

    @application.post(
        "/api/experiment-environment/reset",
        response_model=ExperimentEnvironmentResetResult,
    )
    def reset_experiment_environment(
        request: ExperimentEnvironmentResetRequest,
    ) -> ExperimentEnvironmentResetResult:
        del request
        if not active_runtime.is_available():
            raise HTTPException(status_code=409, detail="환경 Runtime Supervisor가 연결되지 않았습니다.")
        try:
            with executor_gate.claim_all():
                return active_runtime.reset_environment()
        except ExecutorBusyError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

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

    def remote_request(
        method: str,
        path: str,
        payload: dict | None = None,
        timeout: float = 30,
    ) -> dict:
        tunnel = tunnel_manager.refresh()
        if tunnel.status != "connected":
            raise HTTPException(status_code=409, detail="SSM 터널을 먼저 연결하세요.")
        try:
            response = httpx.request(
                method,
                f"http://127.0.0.1:{tunnel.local_port}{path}",
                json=payload,
                timeout=timeout,
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

    @application.post(
        "/api/remote/experiment-environment/reset",
        response_model=ExperimentEnvironmentResetResult,
    )
    def remote_reset_experiment_environment(
        request: ExperimentEnvironmentResetRequest,
    ) -> ExperimentEnvironmentResetResult:
        try:
            with executor_gate.claim_all():
                return ExperimentEnvironmentResetResult.model_validate(
                    remote_request(
                        "POST",
                        "/api/experiment-environment/reset",
                        request.model_dump(mode="json"),
                        timeout=60,
                    )
                )
        except ExecutorBusyError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @application.get("/api/remote/options", response_model=OptionsResponse)
    def remote_options() -> OptionsResponse:
        return OptionsResponse.model_validate(remote_request("GET", "/api/options"))

    @application.get("/api/remote/harness/status", response_model=HarnessStatus)
    def remote_harness_status() -> HarnessStatus:
        return HarnessStatus.model_validate(
            remote_request("GET", "/api/harness/status")
        )

    @application.post(
        "/api/remote/harness/runs",
        response_model=HarnessRunRecord,
    )
    def remote_harness_run(request: HarnessRunRequest) -> HarnessRunRecord:
        remote_health_payload = remote_request("GET", "/api/health")
        if remote_health_payload.get("harness_api_version") != "os-harness-v1":
            raise HTTPException(
                status_code=409,
                detail=(
                    "AWS 백엔드가 OS Harness API를 지원하지 않습니다. "
                    "원격 Backend와 Supervisor를 먼저 갱신하세요."
                ),
            )
        try:
            with executor_gate.claim(request.subject_mode):
                return HarnessRunRecord.model_validate(
                    remote_request(
                        "POST",
                        "/api/harness/runs",
                        request.model_dump(mode="json"),
                        timeout=request.budget.max_elapsed_seconds + 15,
                    )
                )
        except ExecutorBusyError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @application.get(
        "/api/remote/harness/runs/{run_id}",
        response_model=HarnessRunRecord,
    )
    def remote_get_harness_run(run_id: str) -> HarnessRunRecord:
        return HarnessRunRecord.model_validate(
            remote_request("GET", f"/api/harness/runs/{run_id}")
        )

    @application.post("/api/remote/runs", response_model=RunRecord)
    def remote_run(request: RunRequest) -> RunRecord:
        remote_health_payload = remote_request("GET", "/api/health")
        if remote_health_payload.get("run_api_version") != "permission-control-runtime-v6":
            raise HTTPException(
                status_code=409,
                detail=(
                    "AWS 백엔드가 권한 카탈로그 Runtime v5 API를 지원하지 않습니다. "
                    "원격 Backend 이미지와 Supervisor를 먼저 갱신하세요."
                ),
            )
        try:
            with executor_gate.claim(request.subject_mode):
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
        except ExecutorBusyError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
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

    @application.post("/api/remote/agent-runs", response_model=AgentRunRecord)
    def remote_agent_run(request: AgentRunRequest) -> AgentRunRecord:
        remote_health_payload = remote_request("GET", "/api/health")
        if remote_health_payload.get("planner") != "openrouter":
            raise HTTPException(
                status_code=409,
                detail=(
                    "AWS Runtime에 OpenRouter AI Planner가 연결되지 않았습니다. "
                    "규칙형 fallback으로 실험하지 않습니다."
                ),
            )
        remote_agent_version = remote_health_payload.get("agent_run_api_version")
        if remote_agent_version != "os-agent-orchestrator-v7":
            raise HTTPException(
                status_code=409,
                detail="AWS 백엔드가 Host/Container 분리 실행 API를 지원하지 않습니다. 원격 코드를 갱신하세요.",
            )
        remote_payload = build_remote_agent_payload(request, remote_agent_version)
        try:
            if remote_agent_version == "os-agent-orchestrator-v7":
                remote_run_payload = remote_request(
                    "POST",
                    "/api/agent-runs",
                    remote_payload,
                    timeout=30,
                )
            else:
                with executor_gate.claim_all():
                    remote_run_payload = remote_request(
                        "POST",
                        "/api/agent-runs",
                        remote_payload,
                        timeout=request.budget.max_elapsed_seconds_per_tb * 8 + 90,
                    )
            if "objective" not in remote_run_payload:
                remote_run_payload["objective"] = remote_run_payload.get(
                    "prompt", ATTACK_AGENT_MISSION
                )
            run = AgentRunRecord.model_validate(remote_run_payload)
        except ExecutorBusyError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if run.profile_hash != agent_orchestrator_hash(request):
            raise HTTPException(status_code=502, detail="AWS Runtime의 고정 권한 profile_hash가 요청과 다릅니다.")
        agent_repository.save(run)
        return run

    @application.get("/api/remote/agent-runs/{run_id}", response_model=AgentRunRecord)
    def remote_get_agent_run(run_id: str) -> AgentRunRecord:
        stored = agent_repository.get(run_id)
        try:
            run = AgentRunRecord.model_validate(
                remote_request("GET", f"/api/agent-runs/{run_id}")
            )
        except HTTPException:
            if stored is not None:
                return stored
            raise
        agent_repository.save(run)
        return run

    @application.post("/api/remote/agent-runs/{run_id}/cancel", response_model=AgentRunRecord)
    def remote_cancel_agent_run(run_id: str) -> AgentRunRecord:
        run = AgentRunRecord.model_validate(
            remote_request("POST", f"/api/agent-runs/{run_id}/cancel", {})
        )
        agent_repository.save(run)
        return run

    @application.post("/api/remote/agent-runs/{run_id}/rollback", response_model=AgentRunRecord)
    def remote_rollback_agent_run(run_id: str) -> AgentRunRecord:
        try:
            with executor_gate.claim_all():
                run = AgentRunRecord.model_validate(
                    remote_request("POST", f"/api/agent-runs/{run_id}/rollback", {}, timeout=120)
                )
        except ExecutorBusyError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        agent_repository.save(run)
        return run

    @application.post("/api/remote/agent-runs/{run_id}/resume", response_model=AgentRunRecord)
    def remote_resume_agent_run(run_id: str) -> AgentRunRecord:
        stored = get_agent_record(run_id)
        remote_health_payload = remote_request("GET", "/api/health")
        remote_agent_version = remote_health_payload.get("agent_run_api_version")
        try:
            if remote_agent_version == "os-agent-orchestrator-v7":
                run = AgentRunRecord.model_validate(
                    remote_request(
                        "POST",
                        f"/api/agent-runs/{run_id}/resume",
                        {},
                        timeout=30,
                    )
                )
            else:
                with executor_gate.claim_all():
                    run = AgentRunRecord.model_validate(
                        remote_request(
                            "POST",
                            f"/api/agent-runs/{run_id}/resume",
                            {},
                            timeout=stored.budget.max_elapsed_seconds_per_tb + 180,
                        )
                    )
        except ExecutorBusyError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        agent_repository.save(run)
        return run

    @application.post("/api/agent-runs", response_model=AgentRunRecord)
    def create_agent_run(request: AgentRunRequest) -> AgentRunRecord:
        selected_mode = SubjectMode(request.scope)
        if not active_runtime.is_available(selected_mode):
            label = "U1 Host" if selected_mode == SubjectMode.host else "C1 Container"
            raise HTTPException(status_code=409, detail=f"선택한 {label} Runtime이 준비되어야 실행할 수 있습니다.")
        prepared = agent_orchestrator.prepare_run(request)
        response_snapshot = prepared.model_copy(deep=True)
        worker_run = prepared.model_copy(deep=True)
        try:
            agent_run_jobs.start(
                prepared.run_id,
                selected_mode,
                lambda: agent_orchestrator.run(request, prepared_run=worker_run),
                on_error=lambda exc: agent_orchestrator.mark_failed(prepared.run_id, exc),
            )
        except ExecutorBusyError as exc:
            agent_orchestrator.mark_failed(prepared.run_id, exc)
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return response_snapshot

    def get_agent_record(run_id: str) -> AgentRunRecord:
        run = agent_repository.get(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="AgentRun 기록을 찾을 수 없습니다.")
        return run

    @application.get("/api/agent-runs/{run_id}", response_model=AgentRunRecord)
    def get_agent_run(run_id: str) -> AgentRunRecord:
        return get_agent_record(run_id)

    @application.get("/api/agent-runs/{run_id}/events", response_model=list[RunEvent])
    def get_agent_run_events(run_id: str) -> list[RunEvent]:
        return get_agent_record(run_id).events

    @application.get("/api/agent-runs/{run_id}/recon")
    def get_agent_run_recon(run_id: str) -> dict:
        return get_agent_record(run_id).recon_snapshot

    @application.get("/api/agent-runs/{run_id}/findings", response_model=list[AgentFinding])
    def get_agent_run_findings(run_id: str) -> list[AgentFinding]:
        return get_agent_record(run_id).findings

    @application.get("/api/agent-runs/{run_id}/plan", response_model=CampaignSearchState)
    def get_agent_run_plan(run_id: str) -> CampaignSearchState:
        return get_agent_record(run_id).campaign_search

    @application.get("/api/agent-runs/{run_id}/search-graph")
    def get_agent_run_search_graph(run_id: str) -> dict:
        return get_agent_record(run_id).campaign_search.model_dump(mode="json")

    @application.get("/api/agent-runs/{run_id}/attack-contract", response_model=AttackContract | None)
    def get_agent_run_attack_contract(run_id: str) -> AttackContract | None:
        return get_agent_record(run_id).attack_contract

    @application.get(
        "/api/agent-runs/{run_id}/permission-minimization",
        response_model=PermissionMinimizationResult,
    )
    def get_agent_run_permission_minimization(
        run_id: str,
    ) -> PermissionMinimizationResult:
        return get_agent_record(run_id).permission_minimization

    @application.post("/api/agent-runs/{run_id}/cancel", response_model=AgentRunRecord)
    def cancel_agent_run(run_id: str) -> AgentRunRecord:
        run = get_agent_record(run_id)
        if run.status in {"COMPLETED", "FAILED", "CANCELLED"}:
            return run
        run.status = "CANCELLED"
        agent_repository.save(run)
        return run

    @application.post("/api/agent-runs/{run_id}/rollback", response_model=AgentRunRecord)
    def rollback_agent_run(run_id: str) -> AgentRunRecord:
        run = get_agent_record(run_id)
        try:
            claim = (
                executor_gate.claim(SubjectMode(run.scope))
                if run.scope in {"host", "container"}
                else executor_gate.claim_all()
            )
            with claim:
                return agent_orchestrator.rollback(run)
        except ExecutorBusyError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @application.post("/api/agent-runs/{run_id}/resume", response_model=AgentRunRecord)
    def resume_agent_run(run_id: str) -> AgentRunRecord:
        original = get_agent_record(run_id)
        original_snapshot = original.model_copy(deep=True)
        try:
            prepared = agent_orchestrator.prepare_resume(original)
            response_snapshot = prepared.model_copy(deep=True)
            worker_run = prepared.model_copy(deep=True)
            agent_run_jobs.start(
                run_id,
                (
                    SubjectMode(prepared.scope)
                    if prepared.scope in {"host", "container"}
                    else None
                ),
                lambda: agent_orchestrator.resume(worker_run),
                on_error=lambda exc: agent_orchestrator.mark_failed(run_id, exc),
            )
            return response_snapshot
        except ExecutorBusyError as exc:
            # 재개 레인을 얻지 못한 것은 기존 PAUSED 실험의 실패가 아니다.
            agent_repository.save(original_snapshot)
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except Exception:
            agent_repository.save(original_snapshot)
            raise

    @application.post("/api/runs", response_model=RunRecord)
    def create_run(request: RunRequest) -> RunRecord:
        if not active_runtime.is_available(request.subject_mode):
            raise HTTPException(
                status_code=409,
                detail="실제 권한 실험은 SSM으로 연결된 AWS 환경 Runtime에서만 실행할 수 있습니다.",
            )
        try:
            with executor_gate.claim(request.subject_mode):
                return coordinator.run(request)
        except ExecutorBusyError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @application.get("/api/runs", response_model=RunListResponse)
    def list_runs(
        subject_mode: SubjectMode,
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=20, ge=1, le=100),
    ) -> RunListResponse:
        items, total = repository.list_runs(subject_mode, page, page_size)
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


def agent_orchestrator_hash(request: AgentRunRequest) -> str:
    from .agent_orchestrator import permission_profile_hash
    from .permission_minimizer import collect_maximum_permission_profiles

    return permission_profile_hash(collect_maximum_permission_profiles().model_dump())


app = create_app()
