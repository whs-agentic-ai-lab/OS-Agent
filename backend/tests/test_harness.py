from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.harness import (
    HarnessComponents,
    HarnessCoordinator,
    InMemoryHarnessRunRepository,
    create_fixture_harness_components,
)
from app.harness.models import (
    ActionCandidate,
    HarnessRunRequest,
    PlannerDecision,
    ResetRecord,
    ToolExecution,
    VerificationRecord,
)
from app.main import create_app


class FakePermissionProvider:
    def snapshot(self, request: HarnessRunRequest) -> dict:
        return {
            "subject_mode": request.subject_mode.value,
            "profile": "fixture-profile",
        }


class OneActionCatalog:
    def candidates(self, state: dict) -> list[ActionCandidate]:
        if state["history"]:
            return []
        return [
            ActionCandidate(
                candidate_id="candidate-1",
                tool_name="fixture_tool",
                target_resource="fixture-resource",
                risk_level="reversible",
                changes_state=True,
                required_evidence=["fixture-evidence"],
            )
        ]


class FirstCandidatePlanner:
    def select(self, state: dict, candidates: list[ActionCandidate], budget):
        del state, budget
        return PlannerDecision(
            candidate_id=candidates[0].candidate_id,
            rationale="deterministic fixture",
        )


class UnknownCandidatePlanner:
    def select(self, state: dict, candidates: list[ActionCandidate], budget):
        del state, candidates, budget
        return PlannerDecision(candidate_id="not-in-frontier")


class FakeExecutor:
    def execute(self, run_id: str, candidate: ActionCandidate, state: dict):
        del run_id, candidate, state
        return ToolExecution(
            success=True,
            output="fixture executed",
            evidence={"evidence_id": "runtime-1"},
        )


class FakeVerifier:
    def verify(self, run_id: str, candidate: ActionCandidate, execution, state: dict):
        del run_id, candidate, execution, state
        return VerificationRecord(
            status="VERIFIED",
            evidence_refs=["verifier-1"],
            checks={"effect_observed": True},
        )


class FakeResetter:
    def reset(self, run_id: str, candidate: ActionCandidate, execution, state: dict):
        del run_id, candidate, execution, state
        return ResetRecord(
            status="RESET",
            evidence_refs=["reset-1"],
            restored_state={"fixture": "baseline"},
        )


def complete_components(planner=None) -> HarnessComponents:
    return HarnessComponents(
        permission_provider=FakePermissionProvider(),
        tool_catalog=OneActionCatalog(),
        planner=planner or FirstCandidatePlanner(),
        executor=FakeExecutor(),
        verifier=FakeVerifier(),
        resetter=FakeResetter(),
    )


def settings(tmp_path: Path) -> Settings:
    return Settings(
        openrouter_api_key=None,
        openrouter_model="test-model",
        allowed_origins=("http://127.0.0.1:5173",),
        runtime_dir=tmp_path,
        host_supervisor_socket=tmp_path / "missing.sock",
    )


def test_harness_status_lists_unconnected_domain_components(tmp_path: Path) -> None:
    client = TestClient(create_app(settings(tmp_path)))

    response = client.get("/api/harness/status")

    assert response.status_code == 200
    body = response.json()
    assert body["version"] == "os-harness-v1"
    assert body["status"] == "waiting_for_components"
    assert body["ready"] is False
    assert body["preserves_legacy_run_api"] is True
    assert len(body["components"]) == 6
    assert set(body["missing_components"]) == {
        "permission_provider",
        "tool_catalog",
        "planner",
        "executor",
        "verifier",
        "resetter",
    }


def test_harness_run_blocks_safely_until_os_adapters_are_connected(tmp_path: Path) -> None:
    client = TestClient(create_app(settings(tmp_path)))

    response = client.post(
        "/api/harness/runs",
        json={"objective": "승인된 OS 경계에서 가능한 영향을 확인한다.", "subject_mode": "host"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "BLOCKED"
    assert body["termination_reason"] == "MISSING_REQUIRED_COMPONENTS"
    assert body["actions"] == []
    assert body["events"][-1]["event_type"] == "RUN_FINISHED"

    stored = client.get(f"/api/harness/runs/{body['run_id']}")
    assert stored.status_code == 200
    assert stored.json()["run_id"] == body["run_id"]


def test_harness_core_runs_full_lifecycle_with_injected_adapters() -> None:
    repository = InMemoryHarnessRunRepository()
    coordinator = HarnessCoordinator(complete_components(), repository)

    run = coordinator.run(
        HarnessRunRequest(
            objective="fixture lifecycle",
            subject_mode="container",
        )
    )

    assert run.status == "COMPLETED"
    assert run.termination_reason == "FRONTIER_EXHAUSTED"
    assert run.state["permission_snapshot"]["profile"] == "fixture-profile"
    assert run.state_version == 2
    assert run.budget.used_iterations == 1
    assert run.budget.used_tool_calls == 1
    assert len(run.actions) == 1
    assert run.actions[0].verification.status == "VERIFIED"
    assert run.actions[0].reset.status == "RESET"
    assert repository.get(run.run_id) is not None


def test_harness_rejects_planner_candidate_outside_frontier() -> None:
    coordinator = HarnessCoordinator(
        complete_components(planner=UnknownCandidatePlanner()),
        InMemoryHarnessRunRepository(),
    )

    run = coordinator.run(
        HarnessRunRequest(
            objective="invalid planner selection",
            subject_mode="host",
        )
    )

    assert run.status == "FAILED"
    assert run.termination_reason == "HARNESS_ERROR"
    assert run.actions == []
    assert any(event.event_type == "RUN_FAILED" for event in run.events)


@pytest.mark.parametrize(
    ("subject_mode", "profile_id", "write_allowed"),
    [
        ("container", "fixture-container-readonly", False),
        ("container", "fixture-container-write", True),
        ("host", "fixture-host-readonly", False),
        ("host", "fixture-host-write", True),
    ],
)
def test_fixture_adapters_cover_permission_tool_verifier_and_reset_paths(
    subject_mode: str,
    profile_id: str,
    write_allowed: bool,
) -> None:
    coordinator = HarnessCoordinator(
        create_fixture_harness_components(),
        InMemoryHarnessRunRepository(),
    )

    run = coordinator.run(
        HarnessRunRequest(
            objective="Fixture Tool 세 개를 실행하고 검증한다.",
            subject_mode=subject_mode,
            permission_profile_id=profile_id,
        )
    )

    assert run.status == "COMPLETED"
    assert run.termination_reason == "FRONTIER_EXHAUSTED"
    assert run.state["permission_snapshot"]["profile_id"] == profile_id
    assert [action.candidate.tool_name for action in run.actions] == [
        "fixture_file_read",
        "fixture_file_write",
        "fixture_service_status",
    ]
    assert all(action.verification.status == "VERIFIED" for action in run.actions)
    write_action = run.actions[1]
    assert write_action.execution.success is write_allowed
    assert write_action.execution.error_code == (
        None if write_allowed else "ACCESS_DENIED"
    )
    assert write_action.reset.status == (
        "RESET" if write_allowed else "NOT_REQUIRED"
    )


def test_fixture_components_can_be_injected_into_harness_api(tmp_path: Path) -> None:
    client = TestClient(
        create_app(
            settings(tmp_path),
            harness_components=create_fixture_harness_components(),
        )
    )

    status = client.get("/api/harness/status")
    assert status.status_code == 200
    assert status.json()["ready"] is True
    assert status.json()["missing_components"] == []

    response = client.post(
        "/api/harness/runs",
        json={
            "objective": "Fixture Harness API를 검증한다.",
            "subject_mode": "host",
            "permission_profile_id": "fixture-host-write",
        },
    )
    assert response.status_code == 200
    assert response.json()["status"] == "COMPLETED"
    assert len(response.json()["actions"]) == 3


def test_fixture_permission_profile_rejects_cross_boundary_selection() -> None:
    coordinator = HarnessCoordinator(
        create_fixture_harness_components(),
        InMemoryHarnessRunRepository(),
    )

    run = coordinator.run(
        HarnessRunRequest(
            objective="잘못된 경계 Profile을 거부한다.",
            subject_mode="host",
            permission_profile_id="fixture-container-write",
        )
    )

    assert run.status == "FAILED"
    assert run.termination_reason == "HARNESS_ERROR"
    assert run.actions == []
