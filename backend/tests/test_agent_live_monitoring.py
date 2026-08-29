from __future__ import annotations

from pathlib import Path
from threading import Event, Thread
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from app.agent_orchestrator import ATTACK_AGENT_MISSION, AgentOrchestrator
from app.config import Settings
from app.main import agent_orchestrator_hash, create_app
from app.permission_minimizer import collect_maximum_permission_profiles
from app.repository import InMemoryAgentRunRepository
from app.schemas import (
    AgentRunRecord,
    AgentRunRequest,
    ExperimentEnvironmentResetResult,
    RunEvent,
    RuntimeAgentResult,
    RuntimeDispatchRequest,
    RuntimeResetRequest,
    RuntimeResetResult,
    SubjectMode,
    utc_now,
)
from app.tunnel import SsmTunnelManager, TunnelStatus


class BlockingRuntime:
    """첫 Runtime Tool 호출만 Event로 멈추는 결정적 테스트 Runtime입니다."""

    def __init__(self, *, fail_after_release: bool = False) -> None:
        self.entered = Event()
        self.release = Event()
        self.fail_after_release = fail_after_release
        self.requests: list[RuntimeDispatchRequest] = []
        self.reset_requests: list[RuntimeResetRequest] = []

    @staticmethod
    def is_available(subject_mode: SubjectMode | None = None) -> bool:
        del subject_mode
        return True

    def execute(self, request: RuntimeDispatchRequest) -> RuntimeAgentResult:
        self.requests.append(request)
        if len(self.requests) == 1:
            self.entered.set()
            if not self.release.wait(timeout=5):
                raise TimeoutError("테스트가 차단된 Runtime을 해제하지 않았습니다.")
            if self.fail_after_release:
                raise RuntimeError("의도적으로 발생시킨 Runtime 실패")

        decision = request.tool_decision
        assert decision is not None
        identity = {
            "uid": 10003,
            "euid": 10003,
            "gid": 10003,
            "egid": 10003,
            "capabilities": [],
            "docker_socket": {"accessible": False},
        }
        return RuntimeAgentResult(
            run_id=request.run_id,
            action_id=request.action_id,
            subject_mode=request.subject_mode,
            executor_mode=request.subject_mode,
            trust_boundary_id=request.trust_boundary_id,
            source_environment=request.source_environment,
            target_environment=request.target_environment,
            source=request.source_environment,
            target=request.target_environment,
            applied_profile=request.profile_id,
            applied_profile_state={
                "permissions": request.permission_profile,
                "effective_identity": identity,
                "application_checks": {"permissions_match": True},
            },
            runtime_agent=f"{request.subject_mode.value}-live-test-runtime",
            planner_mode="local",
            tool=decision.name,
            action=decision.action,
            resource_ref=decision.resource_ref,
            tool_arguments=decision.arguments,
            policy_decision="allowed",
            runtime_result="allowed",
            outcome="ALLOWED",
            attempted=True,
            identity_before=identity,
            identity_reached=identity,
            identity_after=identity,
            rollback_status="NOT_REQUIRED",
            evidence_refs=[f"action:{request.action_id}:runtime"],
            output="live monitoring probe completed",
            exit_code=0,
            before_sha256="sha256:before",
            after_sha256="sha256:before",
        )

    def reset_harness(self, request: RuntimeResetRequest) -> RuntimeResetResult:
        self.reset_requests.append(request)
        return RuntimeResetResult(
            status="RESET",
            evidence_refs=[f"reset:{request.trust_boundary_id}"],
            restored_state={"target_environment": request.target_environment},
        )

    @staticmethod
    def reset_environment() -> ExperimentEnvironmentResetResult:
        return ExperimentEnvironmentResetResult(
            status="RESET",
            duration_ms=1,
            reset_scopes=["live-test"],
            evidence_refs=["experiment-environment:baseline"],
            restored_state={"baseline": True},
        )


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        openrouter_api_key=None,
        openrouter_model="test-model",
        allowed_origins=("http://127.0.0.1:5173",),
        runtime_dir=tmp_path,
    )


def _observe_agent_saves(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Event, list[str]]:
    terminal_saved = Event()
    saved_statuses: list[str] = []
    original_save = InMemoryAgentRunRepository.save

    def observed_save(
        repository: InMemoryAgentRunRepository,
        run: AgentRunRecord,
    ) -> None:
        original_save(repository, run)
        saved_statuses.append(run.status)
        if run.status in {"COMPLETED", "FAILED", "CANCELLED"} and run.completed_at:
            terminal_saved.set()

    monkeypatch.setattr(InMemoryAgentRunRepository, "save", observed_save)
    return terminal_saved, saved_statuses


def _install_short_success_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Recon 이후 무관한 장시간 Agent 단계를 제거해 비동기 계약만 시험합니다."""

    original_dispatch = AgentOrchestrator._dispatch

    def persist_before_dispatch(
        orchestrator: AgentOrchestrator,
        run: AgentRunRecord,
        *args: Any,
        **kwargs: Any,
    ) -> RuntimeAgentResult:
        # Runtime이 차단된 동안 GET으로 RECON_STARTED까지 관찰할 수 있게 합니다.
        orchestrator.repository.save(run)
        return original_dispatch(orchestrator, run, *args, **kwargs)

    monkeypatch.setattr(AgentOrchestrator, "_dispatch", persist_before_dispatch)
    monkeypatch.setattr(
        AgentOrchestrator,
        "_collect_infrastructure",
        lambda _self, _run: None,
    )
    monkeypatch.setattr(
        AgentOrchestrator,
        "_analyze_and_plan",
        lambda _self, _run: None,
    )
    monkeypatch.setattr(AgentOrchestrator, "_execute_all", lambda _self, _run: None)
    monkeypatch.setattr(AgentOrchestrator, "_compare", lambda _self, _run: None)
    monkeypatch.setattr(
        AgentOrchestrator,
        "_all_tb_searches_complete",
        staticmethod(lambda _run: True),
    )


def _post_agent_run_in_thread(
    client: TestClient,
) -> tuple[Thread, Event, dict[str, Any]]:
    returned = Event()
    result: dict[str, Any] = {}

    def request_run() -> None:
        try:
            result["response"] = client.post("/api/agent-runs", json={})
        except BaseException as exc:  # pragma: no cover - 호출 스레드 오류 전달용
            result["error"] = exc
        finally:
            returned.set()

    thread = Thread(target=request_run, name="agent-run-post-test", daemon=True)
    thread.start()
    return thread, returned, result


def _require_post_returned_while_runtime_blocked(
    runtime: BlockingRuntime,
    post_thread: Thread,
    returned: Event,
    result: dict[str, Any],
) -> Any:
    entered = runtime.entered.wait(timeout=2)
    if not entered:
        runtime.release.set()
        post_thread.join(timeout=2)
        pytest.fail("Agent worker가 Runtime Tool 실행을 시작하지 않았습니다.")

    returned_before_release = returned.wait(timeout=1)
    if not returned_before_release:
        runtime.release.set()
        post_thread.join(timeout=2)
        pytest.fail("POST /api/agent-runs가 Runtime 완료를 기다렸습니다.")

    if "error" in result:
        raise result["error"]
    return result["response"]


def test_agent_post_returns_while_worker_runs_and_get_exposes_live_progress(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = BlockingRuntime()
    terminal_saved, saved_statuses = _observe_agent_saves(monkeypatch)
    _install_short_success_path(monkeypatch)
    with TestClient(create_app(_settings(tmp_path), runtime_client=runtime)) as client:
        post_thread, returned, result = _post_agent_run_in_thread(client)

        response = _require_post_returned_while_runtime_blocked(
            runtime,
            post_thread,
            returned,
            result,
        )
        try:
            assert response.status_code == 200
            accepted = response.json()
            assert accepted["run_id"].startswith("os-")
            assert accepted["status"] in {"RECEIVED", "RUNNING"}

            live = client.get(f"/api/agent-runs/{accepted['run_id']}")
            assert live.status_code == 200
            assert live.json()["status"] == "RUNNING"
            assert live.json()["agent_stage"] == "recon"

            events = client.get(f"/api/agent-runs/{accepted['run_id']}/events")
            assert events.status_code == 200
            assert {"RECON_STARTED", "RUNTIME_DISPATCHED"} <= {
                event["event_type"] for event in events.json()
            }
        finally:
            runtime.release.set()

        post_thread.join(timeout=2)
        assert terminal_saved.wait(timeout=5)
        completed = client.get(f"/api/agent-runs/{accepted['run_id']}")
        assert completed.status_code == 200
        assert completed.json()["status"] == "COMPLETED"
        assert completed.json()["completed_at"] is not None
        assert "RECEIVED" in saved_statuses
        assert "RUNNING" in saved_statuses
    assert "COMPLETED" in saved_statuses


def test_cancel_stays_live_until_current_tool_is_reset_and_worker_finishes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = BlockingRuntime()
    terminal_saved, _ = _observe_agent_saves(monkeypatch)
    _install_short_success_path(monkeypatch)
    client = TestClient(create_app(_settings(tmp_path), runtime_client=runtime))
    post_thread, returned, result = _post_agent_run_in_thread(client)

    response = _require_post_returned_while_runtime_blocked(
        runtime,
        post_thread,
        returned,
        result,
    )
    assert response.status_code == 200
    run_id = response.json()["run_id"]

    cancelling = client.post(f"/api/agent-runs/{run_id}/cancel", json={})
    assert cancelling.status_code == 200
    assert cancelling.json()["status"] == "CANCELLED"
    assert cancelling.json()["completed_at"] is None

    runtime.release.set()
    post_thread.join(timeout=2)
    assert terminal_saved.wait(timeout=5)

    cancelled = client.get(f"/api/agent-runs/{run_id}")
    assert cancelled.status_code == 200
    body = cancelled.json()
    assert body["status"] == "CANCELLED"
    assert body["agent_stage"] == "finished"
    assert body["completed_at"] is not None
    assert len(runtime.requests) == 1
    assert runtime.reset_requests
    assert "RUN_FINISHED" in {
        event["event_type"] for event in body["events"]
    }


def test_agent_worker_failure_is_persisted_and_visible_through_get(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = BlockingRuntime(fail_after_release=True)
    terminal_saved, saved_statuses = _observe_agent_saves(monkeypatch)
    _install_short_success_path(monkeypatch)
    with TestClient(create_app(_settings(tmp_path), runtime_client=runtime)) as client:
        post_thread, returned, result = _post_agent_run_in_thread(client)

        response = _require_post_returned_while_runtime_blocked(
            runtime,
            post_thread,
            returned,
            result,
        )
        assert response.status_code == 200
        run_id = response.json()["run_id"]
        runtime.release.set()

        post_thread.join(timeout=2)
        assert terminal_saved.wait(timeout=5)
        failed = client.get(f"/api/agent-runs/{run_id}")
        assert failed.status_code == 200
        assert failed.json()["status"] == "FAILED"
        assert failed.json()["completed_at"] is not None
        assert "FAILED" in saved_statuses
        assert {event["event_type"] for event in failed.json()["events"]} >= {
            "RUN_FAILED",
            "RUN_FINISHED",
        }


def _remote_record(
    run_id: str,
    profile_hash: str,
    *,
    status: str,
) -> AgentRunRecord:
    terminal = status in {"COMPLETED", "FAILED", "CANCELLED"}
    return AgentRunRecord(
        run_id=run_id,
        objective=ATTACK_AGENT_MISSION,
        status=status,
        agent_stage="finished" if terminal else "recon",
        fixed_permission_profiles=collect_maximum_permission_profiles(),
        profile_hash=profile_hash,
        planner_mode="openrouter",
        planner_model="openai/gpt-5-mini",
        events=[
            RunEvent(
                sequence=1,
                source="orchestrator",
                event_type="RUN_FINISHED" if terminal else "RECON_STARTED",
                message=status,
                payload={"profile_hash": profile_hash},
            )
        ],
        completed_at=utc_now() if terminal else None,
    )


def test_remote_v5_post_returns_active_run_and_get_prefers_latest_remote_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = AgentRunRequest(planner_model="openai/gpt-5-mini")
    profile_hash = agent_orchestrator_hash(request)
    run_id = "os-remote-live"
    active = _remote_record(run_id, profile_hash, status="RUNNING")
    completed = _remote_record(run_id, profile_hash, status="COMPLETED")
    calls: list[tuple[str, str]] = []
    saved_statuses: list[str] = []
    original_save = InMemoryAgentRunRepository.save

    def observed_save(
        repository: InMemoryAgentRunRepository,
        run: AgentRunRecord,
    ) -> None:
        original_save(repository, run)
        saved_statuses.append(run.status)

    def connected(_manager: SsmTunnelManager) -> TunnelStatus:
        return TunnelStatus(status="connected", local_port=8001, remote_port=8000)

    def remote_http(
        method: str,
        url: str,
        *,
        json: dict[str, Any] | None = None,
        timeout: float = 30,
    ) -> httpx.Response:
        del json, timeout
        path = httpx.URL(url).path
        calls.append((method, path))
        if path == "/api/health":
            payload: dict[str, Any] = {
                "status": "ok",
                "planner": "openrouter",
                "agent_run_api_version": "os-agent-orchestrator-v5",
            }
        elif method == "POST" and path == "/api/agent-runs":
            payload = active.model_dump(mode="json")
        elif method == "GET" and path == f"/api/agent-runs/{run_id}":
            payload = completed.model_dump(mode="json")
        else:  # pragma: no cover - 예상하지 못한 프록시 요청 진단용
            raise AssertionError(f"예상하지 못한 원격 요청: {method} {path}")
        return httpx.Response(
            200,
            json=payload,
            request=httpx.Request(method, url),
        )

    monkeypatch.setattr(InMemoryAgentRunRepository, "save", observed_save)
    monkeypatch.setattr(SsmTunnelManager, "refresh", connected)
    monkeypatch.setattr("app.main.httpx.request", remote_http)
    with TestClient(
        create_app(_settings(tmp_path), runtime_client=BlockingRuntime())
    ) as client:
        accepted = client.post(
            "/api/remote/agent-runs",
            json={"planner_model": "openai/gpt-5-mini"},
        )
        assert accepted.status_code == 200
        assert accepted.json()["run_id"] == run_id
        assert accepted.json()["status"] == "RUNNING"

        latest = client.get(f"/api/remote/agent-runs/{run_id}")
        assert latest.status_code == 200
        assert latest.json()["status"] == "COMPLETED"
        assert latest.json()["completed_at"] is not None
        assert ("GET", f"/api/agent-runs/{run_id}") in calls
        assert saved_statuses[-2:] == ["RUNNING", "COMPLETED"]
