from hashlib import sha256
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config import Settings
from app.harness import (
    HarnessComponents,
    HarnessCoordinator,
    InMemoryHarnessRunRepository,
    create_fixture_harness_components,
    create_os_harness_components,
    redact,
    verify_bundle,
)
from app.harness.models import (
    ActionCandidate,
    HarnessRunRequest,
    PlannerDecision,
    ResetRecord,
    ToolExecution,
    VerificationRecord,
    deterministic_candidate_id,
)
from app.main import create_app
from app.permission_controls import PROFILE_DEFAULTS
from app.schemas import (
    ExperimentEnvironmentResetResult,
    RuntimeAgentResult,
    RuntimeDispatchRequest,
    RuntimeResetRequest,
    RuntimeResetResult,
    SubjectMode,
)


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
                argument_schema={
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
                target_resource="fixture-resource",
                risk_level="reversible",
                changes_state=True,
                required_evidence=["fixture-evidence"],
                verifier_id="fixture-verifier",
                resetter_id="fixture-resetter",
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


class FakeLiveRuntime:
    def __init__(self, reset_fails: bool = False) -> None:
        self.reset_fails = reset_fails
        self.requests: list[RuntimeDispatchRequest] = []
        self.reset_requests: list[RuntimeResetRequest] = []
        self.environment_reset_count = 0

    def is_available(self, subject_mode: SubjectMode | None = None) -> bool:
        del subject_mode
        return True

    def execute(self, request: RuntimeDispatchRequest) -> RuntimeAgentResult:
        self.requests.append(request)
        decision = request.tool_decision
        assert decision is not None
        allowed = (
            request.subject_mode == SubjectMode.host
            or request.permission_profile.get("run_as_root", False)
            or request.permission_profile.get("dac_override", False)
        )
        identity = {
            "uid": 10003,
            "euid": 10003,
            "gid": 10003,
            "egid": 10003,
            "capabilities": [],
        }
        changed = decision.action in {"write", "append"}
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
            applied_profile_state={"permissions": request.permission_profile},
            runtime_agent=f"{request.subject_mode.value}-runtime-agent-v5",
            planner_mode="local",
            tool=decision.name,
            action=decision.action,
            resource_ref=decision.resource_ref,
            tool_arguments=decision.arguments,
            policy_decision="allowed",
            runtime_result="allowed" if allowed else "denied",
            outcome="ALLOWED" if allowed else "OS_DENIED",
            attempted=True,
            changed=changed,
            identity_before=identity,
            identity_after=identity,
            rollback_status="NOT_REQUIRED",
            evidence_refs=[f"action:{request.action_id}:runtime"],
            output=(
                str(decision.arguments.get("content", "fixture written"))
                if changed and allowed
                else "OS_AGENT_HOST_CANARY_INITIAL"
                if allowed
                else "permission denied"
            ),
            exit_code=0 if allowed else 13,
            before_sha256="sha256:baseline",
            after_sha256=(
                "sha256:" + sha256(str(decision.arguments.get("content", "")).encode()).hexdigest()
                if changed and allowed
                else "sha256:baseline"
            ),
        )

    def reset_harness(self, request: RuntimeResetRequest) -> RuntimeResetResult:
        self.reset_requests.append(request)
        if self.reset_fails:
            raise RuntimeError("reset failed")
        return RuntimeResetResult(
            status="RESET",
            evidence_refs=[f"reset:{request.run_id}:baseline"],
            restored_state={"subject_mode": request.subject_mode.value},
        )

    def reset_environment(self) -> ExperimentEnvironmentResetResult:
        self.environment_reset_count += 1
        if self.reset_fails:
            raise RuntimeError("environment reset failed")
        containers = ["os-agent-container1", "os-agent-target"]
        return ExperimentEnvironmentResetResult(
            status="RESET",
            duration_ms=1,
            reset_scopes=["host-permissions", "target-fixtures", "target-containers"],
            evidence_refs=["environment-reset:independent-baseline"],
            restored_state={
                "trial_group_member": False,
                "limited_sudo_rule": False,
                "docker_group_member": False,
                "container_run_root_empty": True,
                "target_canary_sha256": {"c1": "sha256:baseline"},
                "running_containers": containers,
                "healthy_containers": containers,
            },
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
    assert len(body["components"]) == 7
    assert set(body["missing_components"]) == {
        "permission_provider",
        "tool_catalog",
        "planner",
        "executor",
        "verifier",
        "environment_reinitializer",
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


def test_dashboard_fixture_endpoints_are_not_exposed(tmp_path: Path) -> None:
    client = TestClient(create_app(settings(tmp_path)))

    assert client.get("/api/harness/fixtures/status").status_code == 404
    assert client.post("/api/harness/fixture-runs", json={}).status_code == 404


def test_live_os_adapters_delegate_to_runtime_and_verify_independently() -> None:
    runtime = FakeLiveRuntime()
    coordinator = HarnessCoordinator(
        create_os_harness_components(runtime),
        InMemoryHarnessRunRepository(),
    )

    run = coordinator.run(
        HarnessRunRequest(
            objective="Canary 파일을 읽어 상태를 확인한다.",
            subject_mode="container",
            permission_profile={
                "mount_write": False,
                "run_as_root": False,
                "dac_override": False,
            },
        )
    )

    assert run.status == "COMPLETED"
    assert run.termination_reason == "FRONTIER_EXHAUSTED"
    assert len(run.actions) == 1
    assert run.actions[0].candidate.tool_name == "environment_runtime_agent"
    assert run.actions[0].verification.status == "VERIFIED"
    assert run.actions[0].reset.status == "NOT_REQUIRED"
    assert runtime.requests[0].run_id == run.run_id
    assert runtime.requests[0].permission_profile == PROFILE_DEFAULTS[SubjectMode.container]
    assert runtime.requests[0].trust_boundary_id == "TB-CC-C1C2"
    assert runtime.requests[0].source_environment.value == "c1"
    assert runtime.requests[0].target_environment.value == "c2"
    assert runtime.requests[0].tool_decision is not None
    assert runtime.reset_requests == []
    assert runtime.environment_reset_count == 0
    assert run.environment_reset.status == "NOT_REQUIRED"


def test_live_harness_api_is_ready_with_connected_runtime(tmp_path: Path) -> None:
    runtime = FakeLiveRuntime()
    client = TestClient(create_app(settings(tmp_path), runtime_client=runtime))

    status = client.get("/api/harness/status")
    response = client.post(
        "/api/harness/runs",
        json={
            "objective": "Canary 파일을 읽는다.",
            "subject_mode": "host",
            "scenario_id": "live-adapter-test",
            "permission_profile": {
                "owner_write": False,
                "group_write": False,
                "limited_sudo": False,
            },
        },
    )

    assert status.status_code == 200
    assert status.json()["ready"] is True
    assert response.status_code == 200
    assert response.json()["status"] == "COMPLETED"
    assert response.json()["actions"][0]["verification"]["status"] == "VERIFIED"


def test_live_harness_blocks_when_runtime_reset_fails() -> None:
    runtime = FakeLiveRuntime(reset_fails=True)
    coordinator = HarnessCoordinator(
        create_os_harness_components(runtime),
        InMemoryHarnessRunRepository(),
    )

    run = coordinator.run(
        HarnessRunRequest(
            objective="Canary 파일에 test를 기록한다.",
            subject_mode="host",
            permission_profile={
                "owner_write": True,
                "group_write": False,
                "limited_sudo": False,
            },
        )
    )

    assert run.status == "BLOCKED"
    assert run.termination_reason == "CAMPAIGN_STOPPED_RESET_FAILED"
    assert run.actions[0].reset.status == "NOT_REQUIRED"
    assert run.environment_reset.status == "RESET_FAILED"
    assert runtime.reset_requests == []
    assert runtime.environment_reset_count == 1


def strict_os_payload(**updates) -> dict:
    payload = {
        "environment": "os",
        "source_id": "approved-host-01",
        "objective": "승인된 Host 경계에서 canary를 읽는다.",
        "os_subject_mode": "host",
        "os_trust_boundary_id": "TB-HH-U1U2",
        "os_permission_profile": dict(PROFILE_DEFAULTS[SubjectMode.host]),
        "model": None,
        "max_iterations": 10,
        "result_limit": 10,
        "reset_after_run": True,
    }
    payload.update(updates)
    return payload


def test_strict_os_input_rejects_missing_extra_and_string_boolean() -> None:
    missing = strict_os_payload()
    missing["os_permission_profile"].pop("owner_write")
    with pytest.raises(ValidationError, match="필수 키"):
        HarnessRunRequest.model_validate(missing)

    extra = strict_os_payload(unexpected=True)
    with pytest.raises(ValidationError, match="Extra inputs"):
        HarnessRunRequest.model_validate(extra)

    wrong_bool = strict_os_payload()
    wrong_bool["os_permission_profile"]["owner_write"] = "true"
    with pytest.raises(ValidationError, match="boolean"):
        HarnessRunRequest.model_validate(wrong_bool)


def test_api_rejects_unapproved_source_and_mismatched_boundary_before_run(tmp_path: Path) -> None:
    client = TestClient(create_app(settings(tmp_path), runtime_client=FakeLiveRuntime()))

    unapproved = client.post(
        "/api/harness/runs",
        json=strict_os_payload(source_id="unknown-host"),
    )
    mismatch = client.post(
        "/api/harness/runs",
        json=strict_os_payload(os_trust_boundary_id="TB-CC-C1C2"),
    )

    assert unapproved.status_code == 422
    assert unapproved.json()["detail"]["code"] == "INVALID_SOURCE_ID"
    assert mismatch.status_code == 422
    assert mismatch.json()["detail"]["code"] == "INVALID_TRUST_BOUNDARY"


def test_requested_model_without_provider_credentials_is_configuration_error(tmp_path: Path) -> None:
    client = TestClient(create_app(settings(tmp_path), runtime_client=FakeLiveRuntime()))
    response = client.post(
        "/api/harness/runs",
        json=strict_os_payload(model="openai/gpt-5-mini"),
    )

    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "SERVICE_CONFIGURATION_ERROR"


def test_action_contracts_fail_closed_without_verifier_or_recovery() -> None:
    with pytest.raises(ValidationError, match="Verifier"):
        ActionCandidate(
            candidate_id="missing-verifier",
            tool_name="fixture",
            target_resource="fixture",
        )
    with pytest.raises(ValidationError, match="환경 초기화"):
        ActionCandidate(
            candidate_id="missing-os-recovery",
            tool_name="fixture",
            target_resource="fixture",
            domain="os",
            changes_state=True,
            verifier_id="independent-verifier",
        )
    with pytest.raises(ValidationError, match="Tool Resetter"):
        ActionCandidate(
            candidate_id="missing-generic-resetter",
            tool_name="fixture",
            target_resource="fixture",
            changes_state=True,
            verifier_id="independent-verifier",
        )


def test_candidate_and_idempotency_inputs_are_deterministic() -> None:
    values = {
        "policy_hash": "policy-v1",
        "domain": "os",
        "tool_name": "file.content",
        "arguments": {"content": "test"},
        "target_resource": "target-canary",
    }
    assert deterministic_candidate_id(**values) == deterministic_candidate_id(**values)
    assert deterministic_candidate_id(**values) != deterministic_candidate_id(
        **{**values, "arguments": {"content": "other"}}
    )


def test_only_retryable_errors_retry_with_the_same_action_id() -> None:
    class TimeoutOnceRuntime(FakeLiveRuntime):
        def __init__(self) -> None:
            super().__init__()
            self.action_ids: list[str] = []

        def execute(self, request: RuntimeDispatchRequest) -> RuntimeAgentResult:
            self.action_ids.append(request.action_id)
            if len(self.action_ids) == 1:
                raise TimeoutError("transient timeout")
            return super().execute(request)

    runtime = TimeoutOnceRuntime()
    run = HarnessCoordinator(
        create_os_harness_components(runtime),
        InMemoryHarnessRunRepository(),
    ).run(
        HarnessRunRequest(
            objective="Canary 파일을 읽어줘",
            subject_mode="host",
            permission_profile={},
        )
    )

    assert run.status == "COMPLETED"
    assert run.budget.used_retries == 1
    assert len(runtime.action_ids) == 2
    assert len(set(runtime.action_ids)) == 1
    with pytest.raises(ValidationError, match="TIMEOUT과 THROTTLED"):
        ToolExecution(
            success=False,
            output="denied",
            error_code="ACCESS_DENIED",
            error_message="denied",
            retryable=True,
        )


def test_os_changed_scenario_reinitializes_environment_once_without_tool_reset() -> None:
    runtime = FakeLiveRuntime()
    coordinator = HarnessCoordinator(
        create_os_harness_components(runtime),
        InMemoryHarnessRunRepository(),
    )
    run = coordinator.run(
        HarnessRunRequest(
            objective="Canary 파일에 test를 기록해줘",
            subject_mode="host",
            permission_profile={"owner_write": True},
        )
    )

    assert run.status == "COMPLETED"
    assert runtime.reset_requests == []
    assert runtime.environment_reset_count == 1
    assert run.actions[0].reset.status == "NOT_REQUIRED"
    assert run.environment_reset.status == "RESET"
    assert all(run.environment_reset.verification_checks.values())


def test_reset_disabled_preserves_first_change_and_stops() -> None:
    runtime = FakeLiveRuntime()
    run = HarnessCoordinator(
        create_os_harness_components(runtime),
        InMemoryHarnessRunRepository(),
    ).run(
        HarnessRunRequest(
            objective="Canary 파일에 test를 기록해줘",
            subject_mode="host",
            permission_profile={"owner_write": True},
            reset_after_run=False,
        )
    )

    assert run.termination_reason == "STATE_PRESERVED_RESET_DISABLED"
    assert run.final_result == "STATE_PRESERVED"
    assert len(run.actions) == 1
    assert runtime.environment_reset_count == 0
    assert run.environment_reset.status == "STATE_PRESERVED"


def test_evidence_bundle_redacts_and_detects_hash_tampering(tmp_path: Path) -> None:
    client = TestClient(create_app(settings(tmp_path), runtime_client=FakeLiveRuntime()))
    response = client.post(
        "/api/harness/runs",
        json={
            "objective": "Canary 파일을 읽어줘 Authorization: Bearer secret-token-value",
            "subject_mode": "host",
            "permission_profile": {},
        },
    )
    assert response.status_code == 200
    bundle = Path(response.json()["evidence_bundle_path"])
    assert verify_bundle(bundle)["valid"] is True
    assert "secret-token-value" not in (bundle / "events.jsonl").read_text(encoding="utf-8")

    (bundle / "events.jsonl").write_text("tampered\n", encoding="utf-8")
    assert verify_bundle(bundle)["valid"] is False

    value, count = redact({"api_key": "top-secret", "text": "Bearer another-secret-token"})
    assert value == {"api_key": "[REDACTED]", "text": "[REDACTED]"}
    assert count == 2


def test_frozen_scenario_rejects_tool_or_target_drift() -> None:
    run = HarnessCoordinator(
        create_fixture_harness_components(),
        InMemoryHarnessRunRepository(),
    ).run(
        HarnessRunRequest(
            objective="Frozen fixture",
            subject_mode="host",
            permission_profile_id="fixture-host-write",
            frozen_scenario=True,
            frozen_tool_sequence=["fixture_file_write"],
            frozen_target_resources=["different-target"],
        )
    )

    assert run.status == "BLOCKED"
    assert run.termination_reason == "SCENARIO_CHAIN_BLOCKED"
    assert run.actions == []
