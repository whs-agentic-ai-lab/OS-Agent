import json
from pathlib import Path
from time import monotonic, sleep
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from app.config import Settings
from app.deployment import (
    AwsCallerIdentity,
    AwsInstanceSummary,
    DeploymentManager,
    EnvironmentContext,
)
from app.main import build_remote_agent_payload, create_app
from app.catalog import build_profile_id
from app.permission_controls import PROFILE_DEFAULTS
from app.schemas import (
    AgentRunRequest,
    ExperimentEnvironmentResetResult,
    RuntimeAgentResult,
    RuntimeDispatchRequest,
    RuntimeResetRequest,
    RuntimeResetResult,
    SubjectMode,
)


class FakeRuntime:
    def __init__(self) -> None:
        self.requests: list[RuntimeDispatchRequest] = []
        self.reset_requests: list[RuntimeResetRequest] = []
        self.operations: list[tuple[str, str | None, int, str | None]] = []

    @staticmethod
    def is_available(subject_mode: SubjectMode | None = None) -> bool:
        del subject_mode
        return True

    def execute(self, request: RuntimeDispatchRequest) -> RuntimeAgentResult:
        from hashlib import sha256

        self.requests.append(request)
        self.operations.append(
            (
                "execute",
                request.chain_id,
                request.chain_step,
                request.trust_boundary_id,
            )
        )
        decision = request.tool_decision
        assert decision is not None
        profile = request.permission_profile
        if decision.name == "file.content":
            is_read = decision.action == "read"
            allowed = (
                profile["run_as_root"] or profile["supplementary_group"] or profile["dac_override"]
                if is_read and request.subject_mode == SubjectMode.container
                else True
                if is_read
                else profile["mount_write"] and (
                    profile["run_as_root"] or profile["supplementary_group"] or profile["dac_override"]
                )
                if request.subject_mode == SubjectMode.container
                else profile["owner_write"] or profile["group_write"] or profile["dac_override"]
            )
            content = decision.arguments.get("content", "")
            after = (
                "sha256:" + sha256(content.encode()).hexdigest()
                if allowed and decision.action == "write"
                else "sha256:before"
            )
            output = "content" if is_read and allowed else "written" if allowed else "permission denied"
        elif decision.name == "sudo.run":
            allowed = (
                request.subject_mode == SubjectMode.host
                and profile["limited_sudo"]
                and not profile["no_new_privileges"]
            )
            after = "sha256:" + sha256(b"test").hexdigest() if allowed else "sha256:before"
            output = "sudo probe succeeded" if allowed else "permission denied"
        elif decision.name == "privilege.identity_probe":
            capability = (
                "setgid_capability"
                if "gid" in decision.action
                else "setuid_capability"
            )
            allowed = profile[capability]
            after = "sha256:before"
            output = "identity probe succeeded" if allowed else "permission denied"
        else:
            allowed = True
            after = "sha256:before"
            output = "probe completed"
        outcome = "ALLOWED" if allowed else "OS_DENIED"
        identity = {"uid": 10003, "euid": 10003, "gid": 10003, "egid": 10003, "capabilities": []}
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
            applied_profile_state={"permissions": profile},
            runtime_agent=f"{request.subject_mode.value}-runtime-agent-v5",
            planner_mode="local",
            tool=decision.name,
            action=decision.action,
            resource_ref=decision.resource_ref,
            tool_arguments=decision.arguments,
            policy_decision="allowed",
            runtime_result="allowed" if allowed else "denied",
            outcome=outcome,
            attempted=True,
            escalation_possible=decision.name.endswith("probe") and allowed,
            temporary_changed=decision.name.endswith("probe") and allowed,
            changed=after != "sha256:before",
            identity_before=identity,
            identity_reached=identity if allowed else None,
            identity_after=identity,
            rollback_status="VERIFIED" if "probe" in decision.name or decision.name == "sudo.run" else "NOT_REQUIRED",
            evidence_refs=[f"action:{request.action_id}:runtime"],
            output=output,
            exit_code=0 if allowed else 13,
            before_sha256="sha256:before",
            after_sha256=after,
        )

    def reset_harness(self, request: RuntimeResetRequest) -> RuntimeResetResult:
        self.reset_requests.append(request)
        self.operations.append(
            ("reset", None, 0, request.trust_boundary_id)
        )
        return RuntimeResetResult(
            status="RESET",
            evidence_refs=[f"reset:{request.trust_boundary_id}"],
            restored_state={"target_environment": request.target_environment},
        )

    def reset_environment(self) -> ExperimentEnvironmentResetResult:
        self.operations.append(("environment-reset", None, 0, None))
        return ExperimentEnvironmentResetResult(
            status="RESET",
            duration_ms=1200,
            reset_scopes=["target-fixtures", "target-containers"],
            evidence_refs=["experiment-environment:baseline"],
            restored_state={"container_run_root_empty": True},
        )


def profile_for(mode: str, **updates: bool) -> dict[str, bool]:
    profile = dict(PROFILE_DEFAULTS[SubjectMode(mode)])
    profile.update(updates)
    return profile


def run_payload(prompt: str, mode: str, **updates: bool) -> dict:
    return {
        "prompt": prompt,
        "subject_mode": mode,
        "permission_profile": profile_for(mode, **updates),
    }


def make_client(tmp_path: Path) -> TestClient:
    settings = Settings(
        openrouter_api_key=None,
        openrouter_model="test-model",
        allowed_origins=("http://127.0.0.1:5173",),
        runtime_dir=tmp_path,
    )
    return TestClient(create_app(settings, runtime_client=FakeRuntime()))


def wait_for_agent_run(
    client: TestClient,
    run_id: str,
    *,
    timeout: float = 10,
) -> dict:
    deadline = monotonic() + timeout
    terminal_statuses = {"PAUSED", "COMPLETED", "FAILED", "CANCELLED"}
    last_body: dict = {}
    while monotonic() < deadline:
        response = client.get(f"/api/agent-runs/{run_id}")
        assert response.status_code == 200
        last_body = response.json()
        if last_body["status"] in terminal_statuses:
            return last_body
        sleep(0.01)
    raise AssertionError(
        f"AgentRun {run_id}이 {timeout}초 안에 종료되지 않았습니다: "
        f"{last_body.get('status', 'UNKNOWN')}"
    )


def test_options_have_two_executors_eight_boundaries_and_attack_tool_catalog(tmp_path: Path) -> None:
    response = make_client(tmp_path).get("/api/options")
    assert response.status_code == 200
    body = response.json()
    assert len(body["subject_modes"]) == 2
    assert len(body["permission_tests"]["container"]) == 15
    assert len(body["permission_tests"]["host"]) == 9
    assert body["permission_catalog_summary"]["total_entries"] == 307
    assert body["permission_catalog_summary"]["independent_permission_count"] is None
    assert len(body["tools"]) == 129
    assert {item["id"] for item in body["tools"] if item["implemented"]} == {
        "file.open",
        "file.content",
        "privilege.identity_probe",
        "privilege.no_new_privs_probe",
        "process.procfs",
        "sudo.run",
    }
    assert [item["id"] for item in body["planner_models"]] == [
        "deepseek/deepseek-v4-flash-0731",
        "z-ai/glm-5.3-flash",
        "openai/gpt-5-mini",
    ]
    assert {item["id"] for item in body["trust_boundaries"]} == {
        "TB-HH-U1U2",
        "TB-HC-U1C1",
        "TB-HC-U1C2",
        "TB-HC-U1C3",
        "TB-HC-C1U1",
        "TB-HC-C1U2",
        "TB-CC-C1C2",
        "TB-CC-C1C3",
    }


def test_health_advertises_profile_runtime_api(tmp_path: Path) -> None:
    response = make_client(tmp_path).get("/api/health")

    assert response.status_code == 200
    assert response.json()["run_api_version"] == "permission-control-runtime-v6"
    assert response.json()["agent_run_api_version"] == "os-agent-orchestrator-v5"


def test_agent_run_recons_and_tests_all_eight_boundaries_with_one_profile_hash(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    settings = Settings(
        openrouter_api_key=None,
        openrouter_model="test-model",
        allowed_origins=("http://127.0.0.1:5173",),
        runtime_dir=tmp_path,
    )
    client = TestClient(create_app(settings, runtime_client=runtime))

    response = client.post(
        "/api/agent-runs",
        json={},
    )

    assert response.status_code == 200
    accepted = response.json()
    assert accepted["status"] in {"RECEIVED", "RUNNING"}
    run_id = accepted["run_id"]
    body = wait_for_agent_run(client, run_id)
    assert body["status"] == "COMPLETED"
    assert "공격 가설을 스스로 생성" in body["objective"]
    assert body["profile_hash"].startswith("sha256:")
    assert len(body["tb_results"]) == 8
    assert body["summary"] == {"broken": 2, "blocked": 0, "inconclusive": 6}
    assert {item["proof_level"] for item in body["tb_results"]} == {
        "L1_REACHABLE",
        "L4_RESTORED",
    }
    assert len(runtime.requests) > 10
    main_chain_ids = {
        request.chain_id
        for request in runtime.requests
        if request.preserve_state
        and request.chain_id is not None
        and request.chain_id.startswith("chain-")
    }
    minimization_chain_ids = {
        request.chain_id
        for request in runtime.requests
        if request.preserve_state
        and request.chain_id is not None
        and request.chain_id.startswith("min-")
    }
    assert len(main_chain_ids) == 2
    assert len(runtime.reset_requests) == (
        2 + len(body["tb_scenarios"]) + len(minimization_chain_ids)
    )
    recon_positions = [
        index
        for index, operation in enumerate(runtime.operations)
        if operation[0] == "execute" and operation[1] is None
    ]
    assert len(recon_positions) == 2
    for position in recon_positions:
        assert runtime.operations[position + 1] == (
            "reset",
            None,
            0,
            runtime.operations[position][3],
        )
    for chain_id in main_chain_ids | minimization_chain_ids:
        positions = [
            index
            for index, operation in enumerate(runtime.operations)
            if operation[0] == "execute" and operation[1] == chain_id
        ]
        assert positions
        assert positions == list(range(positions[0], positions[-1] + 1))
        assert [runtime.operations[index][2] for index in positions] == list(
            range(1, len(positions) + 1)
        )
        assert runtime.operations[positions[-1] + 1] == (
            "reset",
            None,
            0,
            runtime.operations[positions[-1]][3],
        )
    assert body["attack_contract"]["trust_boundary_id"] == "TB-HH-U1U2"
    assert body["permission_minimization"]["status"] == "COMPLETED"
    assert body["permission_minimization"]["one_minimal_verified"] is True
    assert body["permission_minimization"]["minimal_permission_ids"] == [
        "host:limited_sudo",
        "host:no_new_privileges=OFF",
    ]
    assert all(
        event["payload"]["profile_hash"] == body["profile_hash"]
        for event in body["events"]
    )
    assert body["run_id"] == run_id
    assert client.get(f"/api/agent-runs/{run_id}").status_code == 200
    findings = client.get(f"/api/agent-runs/{run_id}/findings").json()
    assert len([finding for finding in findings if finding["executable"]]) == 8
    assert len(client.get(f"/api/agent-runs/{run_id}/plan").json()) == 8
    assert client.get(f"/api/agent-runs/{run_id}/attack-contract").json()[
        "contract_id"
    ].startswith("contract-")
    assert client.get(
        f"/api/agent-runs/{run_id}/permission-minimization"
    ).json()["one_minimal_verified"] is True


def test_agent_run_uses_selected_openrouter_model_for_each_boundary(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    settings = Settings(
        openrouter_api_key="test-openrouter-key",
        openrouter_model="openai/gpt-5-mini",
        allowed_origins=("http://127.0.0.1:5173",),
        runtime_dir=tmp_path,
    )
    host_model_response = Mock()
    host_model_response.raise_for_status.return_value = None
    host_model_response.json.return_value = {
        "choices": [
            {
                "message": {
                    "tool_calls": [
                        {
                            "function": {
                                "name": "sudo_run",
                                "arguments": json.dumps(
                                    {
                                        "action": "run_probe",
                                        "resource_ref": "target-canary",
                                        "arguments": {"content": "model-planned"},
                                    }
                                ),
                            }
                        }
                    ]
                }
            }
        ]
    }
    container_model_response = Mock()
    container_model_response.raise_for_status.return_value = None
    container_model_response.json.return_value = {
        "choices": [
            {
                "message": {
                    "tool_calls": [
                        {
                            "function": {
                                "name": "privilege_identity_probe",
                                "arguments": json.dumps(
                                    {
                                        "action": "seteuid",
                                        "resource_ref": "identity-root",
                                        "arguments": {},
                                    }
                                ),
                            }
                        }
                    ]
                }
            }
        ]
    }
    minimizer_response = Mock()
    minimizer_response.raise_for_status.return_value = None
    minimizer_response.json.return_value = {
        "choices": [
            {
                "message": {
                    "tool_calls": [
                        {
                            "function": {
                                "name": "select_permission_ids",
                                "arguments": json.dumps(
                                    {
                                        "permission_ids": [
                                            "container:mount_write",
                                            "container:supplementary_group",
                                        ]
                                    }
                                ),
                            }
                        }
                    ]
                }
            }
        ]
    }

    def openrouter_response(*args, **kwargs):
        del args
        function_name = kwargs["json"]["tools"][0]["function"]["name"]
        if function_name == "select_permission_ids":
            return minimizer_response
        user_message = kwargs["json"]["messages"][1]["content"]
        return host_model_response if "(u1 ->" in user_message else container_model_response

    with patch("app.model_gateway.httpx.post", side_effect=openrouter_response) as openrouter_post:
        with TestClient(create_app(settings, runtime_client=runtime)) as client:
            response = client.post(
                "/api/agent-runs",
                json={
                    "planner_model": "z-ai/glm-5.3-flash",
                },
            )
            assert response.status_code == 200
            accepted = response.json()
            assert accepted["status"] in {"RECEIVED", "RUNNING"}
            body = wait_for_agent_run(client, accepted["run_id"])

    assert body["status"] == "COMPLETED"
    assert body["planner_mode"] == "openrouter"
    assert body["planner_model"] == "z-ai/glm-5.3-flash"
    planner_calls = [
        call
        for call in openrouter_post.call_args_list
        if call.kwargs["json"]["tools"][0]["function"]["name"]
        != "select_permission_ids"
    ]
    # Only the two Trust Boundaries represented by the validated Tool contracts
    # have an executable Attack frontier. The remaining six complete without
    # asking the model to invent an out-of-contract action.
    assert len(planner_calls) >= 2
    assert any(
        call.kwargs["json"]["tools"][0]["function"]["name"]
        == "select_permission_ids"
        for call in openrouter_post.call_args_list
    )
    assert all(
        call.kwargs["json"]["model"] == "z-ai/glm-5.3-flash"
        for call in openrouter_post.call_args_list
    )
    executed_scenarios = {
        scenario["trust_boundary_id"]: [
            step["tool"] for step in scenario["steps"] if step["type"] == "execute"
        ]
        for scenario in body["tb_scenarios"]
        if any(step["type"] == "execute" for step in scenario["steps"])
    }
    assert set(executed_scenarios) == {"TB-HH-U1U2", "TB-CC-C1C2"}
    assert all(
        call.kwargs["json"]["tools"][0]["function"]["name"] == "validated_attack"
        for call in planner_calls
    )
    assert all(request.planner_mode == "openrouter" for request in runtime.requests)


def test_agent_run_rejects_user_supplied_prompt(tmp_path: Path) -> None:
    response = make_client(tmp_path).post(
        "/api/agent-runs",
        json={"prompt": "사용자가 공격 명령을 선택한다"},
    )

    assert response.status_code == 422


def test_agent_run_rejects_user_supplied_permission_profile(tmp_path: Path) -> None:
    response = make_client(tmp_path).post(
        "/api/agent-runs",
        json={"fixed_permission_profiles": {"host": {}, "container": {}}},
    )

    assert response.status_code == 422


def test_v3_remote_agent_payload_does_not_send_legacy_manual_profile() -> None:
    request = AgentRunRequest(planner_model="openai/gpt-5-mini")

    payload = build_remote_agent_payload(request, "os-agent-orchestrator-v3")

    assert payload == {
        "scope": "all_trust_boundaries",
        "planner_model": "openai/gpt-5-mini",
        "budget": request.budget.model_dump(mode="json"),
    }
    assert "fixed_permission_profiles" not in payload


def test_v2_remote_agent_payload_keeps_legacy_profile_compatibility() -> None:
    request = AgentRunRequest()

    payload = build_remote_agent_payload(request, "os-agent-orchestrator-v2")

    assert "fixed_permission_profiles" in payload
    assert "prompt" not in payload


def test_local_backend_disables_host_without_supervisor_socket(tmp_path: Path) -> None:
    settings = Settings(
        openrouter_api_key=None,
        openrouter_model="test-model",
        allowed_origins=("http://127.0.0.1:5173",),
        runtime_dir=tmp_path,
        host_supervisor_socket=tmp_path / "missing.sock",
    )
    client = TestClient(create_app(settings))

    options = client.get("/api/options").json()
    host_option = next(mode for mode in options["subject_modes"] if mode["id"] == "host")
    assert host_option["enabled"] is False

    response = client.post(
        "/api/runs",
        json=run_payload("Canary 파일에 test를 기록해줘", "host", owner_write=True),
    )
    assert response.status_code == 409


def test_off_profile_denies_file_write_and_passes_boundary_test(tmp_path: Path) -> None:
    response = make_client(tmp_path).post(
        "/api/runs",
        json=run_payload("Canary 파일에 test를 기록해줘", "container"),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["runtime_result"] == "denied"
    assert body["before_sha256"] == body["after_sha256"]
    assert body["test_result"] == "PASS"


def test_on_profile_writes_file_and_passes_boundary_test(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    response = client.post(
        "/api/runs",
        json=run_payload("Canary 파일에 test를 기록해줘", "host", group_write=True),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["runtime_result"] == "allowed"
    assert body["before_sha256"] != body["after_sha256"]
    assert body["test_result"] == "PASS"
    assert body["result_format_version"] == "common-minimum-v2"
    assert body["profile_version"] == "UNIMPLEMENTED"
    assert body["workload_type"] == "UNIMPLEMENTED"
    assert body["action_path_id"] == "UNIMPLEMENTED"
    assert body["changed_variable"] == ", ".join(
        f"{key}:{'ON' if value else 'OFF'}"
        for key, value in profile_for("host", group_write=True).items()
    )
    assert body["policy_decision"] == "allowed"
    assert body["authentication_result"] == "UNIMPLEMENTED"
    assert body["authorization_result"] == "allowed"
    assert body["verifier_name"] == "file_content_verifier"
    assert body["verifier_effect"]
    attack_result = body["applied_profile_state"]["attack_tool_result"]
    assert attack_result["action_id"].startswith("action-")
    assert attack_result["tool"] == "file.content"
    assert attack_result["action"] == "write"
    assert attack_result["resource_ref"] == "target-canary"
    assert attack_result["outcome"] == "ALLOWED"
    assert attack_result["attempted"] is True
    assert body["evidence_references"] == [
        f"action:{attack_result['action_id']}:runtime"
    ]
    assert client.get(f"/api/runs/{body['run_id']}").json()["run_id"] == body["run_id"]
    assert client.get(f"/api/runs/{body['run_id']}/events").json()[-1]["event_type"] == "RUN_FINISHED"


def test_profile_bundle_creates_one_run_with_one_runtime_result(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    response = client.post(
        "/api/runs",
        json=run_payload(
            "Canary 파일에 test를 기록해줘",
            "container",
            mount_write=True,
            dac_override=True,
        ),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["run_id"].startswith("os-")
    expected_profile = profile_for("container", mount_write=True, dac_override=True)
    assert body["permission_profile"] == expected_profile
    assert body["permission_results"] == []
    assert body["changed_variable"] == ", ".join(
        f"{key}:{'ON' if value else 'OFF'}" for key, value in expected_profile.items()
    )
    assert body["requested_profile"] == build_profile_id(SubjectMode.container, expected_profile)
    assert body["test_result"] == "PASS"
    assert body["verifier_name"] == "file_content_verifier"
    assert client.get("/api/runs?subject_mode=container").json()["total"] == 1


def test_host_profile_bundle_is_dispatched_once_to_environment_runtime(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    settings = Settings(
        openrouter_api_key=None,
        openrouter_model="test-model",
        allowed_origins=("http://127.0.0.1:5173",),
        runtime_dir=tmp_path,
    )
    client = TestClient(create_app(settings, runtime_client=runtime))

    response = client.post(
        "/api/runs",
        json=run_payload(
            "Canary 파일에 test를 기록해줘",
            "host",
            owner_write=True,
            group_write=True,
        ),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["permission_results"] == []
    assert len(runtime.requests) == 1
    assert runtime.requests[0].permission_profile == profile_for(
        "host", owner_write=True, group_write=True
    )
    assert runtime.requests[0].trust_boundary_id == "TB-HH-U1U2"
    assert runtime.requests[0].source_environment.value == "u1"
    assert runtime.requests[0].target_environment.value == "u2"
    assert runtime.requests[0].tool_decision is not None


def test_boundary_must_start_at_selected_executor(tmp_path: Path) -> None:
    payload = run_payload("Canary 파일을 읽어줘", "host")
    payload["trust_boundary_id"] = "TB-CC-C1C2"

    response = make_client(tmp_path).post("/api/runs", json=payload)

    assert response.status_code == 422
    assert "host Executor" in response.json()["detail"]


def test_run_log_list_is_paginated_and_links_to_full_detail(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    created_ids = []
    for prompt in ("Canary 파일을 읽어줘", "Nginx 상태를 확인해줘"):
        response = client.post(
            "/api/runs",
            json=run_payload(prompt, "container"),
        )
        assert response.status_code == 200
        created_ids.append(response.json()["run_id"])

    response = client.get("/api/runs?subject_mode=container&page=1&page_size=1")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert body["page"] == 1
    assert body["page_size"] == 1
    assert len(body["items"]) == 1
    assert body["items"][0]["run_id"] in created_ids
    assert body["items"][0]["events"] == []

    detail = client.get(f"/api/runs/{body['items'][0]['run_id']}")
    assert detail.status_code == 200
    assert detail.json()["events"]


def test_run_logs_are_listed_in_separate_executor_lanes(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    container_run = client.post(
        "/api/runs",
        json=run_payload("Container 결과", "container"),
    ).json()
    host_run = client.post(
        "/api/runs",
        json=run_payload("Host 결과", "host"),
    ).json()

    container_logs = client.get("/api/runs?subject_mode=container").json()
    host_logs = client.get("/api/runs?subject_mode=host").json()

    assert container_logs["total"] == 1
    assert [item["run_id"] for item in container_logs["items"]] == [
        container_run["run_id"]
    ]
    assert host_logs["total"] == 1
    assert [item["run_id"] for item in host_logs["items"]] == [host_run["run_id"]]


def test_run_log_can_be_deleted_by_exact_run_id(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    created = client.post(
        "/api/runs",
        json=run_payload("삭제할 테스트 로그를 기록해줘", "container"),
    ).json()

    response = client.delete(f"/api/runs/{created['run_id']}")

    assert response.status_code == 200
    assert response.json() == {"run_id": created["run_id"], "deleted": True}
    assert client.get(f"/api/runs/{created['run_id']}").status_code == 404
    assert client.get(f"/api/runs/{created['run_id']}/events").status_code == 404
    assert client.delete(f"/api/runs/{created['run_id']}").status_code == 404


def test_host_off_profile_is_applied_and_os_denial_is_verified(tmp_path: Path) -> None:
    response = make_client(tmp_path).post(
        "/api/runs",
        json=run_payload("Canary 파일에 test를 기록해줘", "host"),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["applied_profile"] == build_profile_id(
        SubjectMode.host, profile_for("host")
    )
    assert body["runtime_result"] == "denied"
    assert body["exit_code"] == 13
    assert body["test_result"] == "PASS"


def test_unmatched_prompt_falls_back_to_registered_canary_read(tmp_path: Path) -> None:
    response = make_client(tmp_path).post(
        "/api/runs",
        json=run_payload("Nginx가 실행 중인지 상태를 확인해줘", "container"),
    )
    body = response.json()
    assert body["tool"] == "file.content"
    assert body["tool_arguments"] == {
        "action": "read",
        "resource_ref": "target-canary",
        "arguments": {},
    }
    assert body["test_result"] == "PASS"


def test_cross_boundary_permission_is_rejected(tmp_path: Path) -> None:
    response = make_client(tmp_path).post(
        "/api/runs",
        json={
            "prompt": "Canary 파일에 test를 기록해줘",
            "subject_mode": "container",
            "permission_profile": {
                "mount_write": False,
                "run_as_root": False,
                "limited_sudo": True,
            },
        },
    )
    assert response.status_code == 422


def test_deployment_is_available_by_default(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    status = client.get("/api/deployments/current")
    assert status.status_code == 200
    assert status.json()["status"] != "disabled"
    assert "enabled" not in status.json()


def test_deployment_rejects_missing_confirmation(tmp_path: Path) -> None:
    response = make_client(tmp_path).post(
        "/api/deployments",
        json={"confirmation": "yes"},
    )
    assert response.status_code == 422


def test_initialize_rejects_missing_confirmation(tmp_path: Path) -> None:
    response = make_client(tmp_path).post(
        "/api/deployments/initialize",
        json={"confirmation": "yes"},
    )
    assert response.status_code == 422


def test_destroy_requires_environment_id(tmp_path: Path) -> None:
    response = make_client(tmp_path).post(
        "/api/deployments/destroy",
        json={
            "confirmation": "DESTROY_FIXED_OS_ENVIRONMENT",
            "environment_name": "trial",
        },
    )
    assert response.status_code == 422


def test_experiment_environment_reset_requires_confirmation(tmp_path: Path) -> None:
    response = make_client(tmp_path).post(
        "/api/experiment-environment/reset",
        json={"confirmation": "yes"},
    )

    assert response.status_code == 422


def test_experiment_environment_reset_returns_verified_result(tmp_path: Path) -> None:
    response = make_client(tmp_path).post(
        "/api/experiment-environment/reset",
        json={"confirmation": "RESET_EXPERIMENT_ENVIRONMENT"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "RESET"
    assert response.json()["restored_state"]["container_run_root_empty"] is True


def test_reconcile_imports_existing_orphaned_flow_log_group(tmp_path: Path) -> None:
    manager = DeploymentManager(
        Settings(
            openrouter_api_key=None,
            openrouter_model="test-model",
            allowed_origins=("http://127.0.0.1:5173",),
            runtime_dir=tmp_path,
            terraform_dir=tmp_path,
            backend_context=tmp_path,
        )
    )
    manager._capture = Mock(
        side_effect=[
            "",
            '{"logGroups":[{"logGroupName":"/os-agent-test-vinny-abc123-permission/vpc-flow-logs"}]}',
        ]
    )
    manager._command = Mock()
    manager._append = Mock()
    state_path = tmp_path / "terraform.tfstate"
    state_path.write_text("{}", encoding="utf-8")
    environment = EnvironmentContext(
        environment_name="permission",
        environment_id="os-agent-test-vinny-abc123-permission",
        created_by="vinny",
        owner_arn="arn:aws:sts::123456789012:assumed-role/Admin/vinny",
        account_id="123456789012",
    )

    manager._reconcile_flow_log_group(
        "terraform", "aws", tmp_path, environment, state_path
    )

    manager._command.assert_called_once_with(
        [
            "terraform",
            "import",
            f"-state={state_path}",
            "-input=false",
            "-var=project_name=os-agent",
            "-var=environment_id=os-agent-test-vinny-abc123-permission",
            "-var=created_by=vinny",
            "-var=owner_arn=arn:aws:sts::123456789012:assumed-role/Admin/vinny",
            "-var=aws_profile=whs-team",
            "-var=confirm_new_state=true",
            "-var=openrouter_api_key_parameter_name=",
            "aws_cloudwatch_log_group.vpc_flow_logs[0]",
            "/os-agent-test-vinny-abc123-permission/vpc-flow-logs",
        ],
        tmp_path,
    )


def test_deploy_reconfigures_default_local_backend_and_uses_three_digest_images(
    tmp_path: Path,
) -> None:
    manager = DeploymentManager(
        Settings(
            openrouter_api_key="test-openrouter-key",
            openrouter_model="test-model",
            allowed_origins=("http://127.0.0.1:5173",),
            runtime_dir=tmp_path / "runtime",
            terraform_dir=tmp_path / "terraform",
            backend_context=tmp_path / "backend",
        )
    )
    manager._executables = {
        "terraform": "terraform",
        "aws": "aws",
        "docker": "docker",
    }
    manager._reconcile_flow_log_group = Mock()
    manager._put_openrouter_parameter = Mock()
    manager._command = Mock()
    digest = "sha256:" + "a" * 64
    manager._capture = Mock(
        side_effect=[
            "ami-0123456789abcdef0\n",
            json.dumps(
                {
                    "runtime": "123.dkr.ecr.us-east-1.amazonaws.com/test-runtime",
                    "container1": "123.dkr.ecr.us-east-1.amazonaws.com/test-container1",
                    "target": "123.dkr.ecr.us-east-1.amazonaws.com/test-target",
                }
            ),
            "ecr-password",
            digest,
            digest,
            digest,
            json.dumps({"trial_ec2_instance_id": {"value": "i-0123456789abcdef0"}}),
        ]
    )
    environment = EnvironmentContext(
        environment_name="0005",
        environment_id="os-agent-test-hanbin-074709-0005",
        created_by="hanbin",
        owner_arn="arn:aws:iam::123456789012:user/hanbin",
        account_id="123456789012",
    )

    manager._deploy(environment)

    commands = [call.args[0] for call in manager._command.call_args_list]
    assert ["terraform", "init", "-reconfigure", "-input=false"] in commands
    assert any("-target=aws_ecr_repository.images" in command for command in commands)
    build_commands = [command for command in commands if command[:2] == ["docker", "build"]]
    assert len(build_commands) == 3
    assert all("linux/amd64" in command for command in build_commands)
    final_apply = [
        command
        for command in commands
        if command[:2] == ["terraform", "apply"]
        and "-target=aws_ecr_repository.images" not in command
    ]
    assert len(final_apply) == 1
    assert f"-var=runtime_image_digest={digest}" in final_apply[0]
    assert f"-var=container1_image_digest={digest}" in final_apply[0]
    assert f"-var=target_image_digest={digest}" in final_apply[0]
    assert (
        "-var=openrouter_api_key_parameter_name="
        "/os-agent/os-agent-test-hanbin-074709-0005/openrouter-api-key"
    ) in final_apply[0]
    manager._put_openrouter_parameter.assert_called_once_with(
        "aws",
        "/os-agent/os-agent-test-hanbin-074709-0005/openrouter-api-key",
        "test-openrouter-key",
    )
    assert manager.get_status().status == "succeeded"


def test_openrouter_key_is_written_via_redacted_securestring_payload(tmp_path: Path) -> None:
    manager = DeploymentManager(
        Settings(
            openrouter_api_key="super-secret-test-key",
            openrouter_model="test-model",
            allowed_origins=("http://127.0.0.1:5173",),
            runtime_dir=tmp_path / "runtime",
            terraform_dir=tmp_path / "terraform",
            backend_context=tmp_path,
        )
    )
    manager._append = Mock()
    observed: dict[str, object] = {}

    def inspect_secure_payload(args, **kwargs):
        del kwargs
        payload_path = Path(next(value for value in args if value.startswith("file://"))[7:])
        observed["path"] = payload_path
        observed["payload"] = json.loads(payload_path.read_text(encoding="utf-8"))
        observed["args"] = args
        return Mock(returncode=0, stdout="{}", stderr="")

    with patch("app.deployment.subprocess.run", side_effect=inspect_secure_payload):
        manager._put_openrouter_parameter(
            "aws",
            "/os-agent/test/openrouter-api-key",
            "super-secret-test-key",
        )

    assert observed["payload"] == {
        "Name": "/os-agent/test/openrouter-api-key",
        "Description": "OS Agent OpenRouter API key",
        "Value": "super-secret-test-key",
        "Type": "SecureString",
        "Overwrite": True,
        "Tier": "Standard",
    }
    assert "super-secret-test-key" not in " ".join(observed["args"])
    assert not observed["path"].exists()
    assert all(
        "super-secret-test-key" not in str(call)
        for call in manager._append.call_args_list
    )


def test_destroy_without_state_is_a_safe_noop(tmp_path: Path) -> None:
    manager = DeploymentManager(
        Settings(
            openrouter_api_key=None,
            openrouter_model="test-model",
            allowed_origins=("http://127.0.0.1:5173",),
            runtime_dir=tmp_path / "runtime",
            terraform_dir=tmp_path / "terraform",
            backend_context=tmp_path / "backend",
        )
    )
    manager._executables = {"terraform": "terraform", "aws": "aws"}
    manager._command = Mock()
    manager._delete_orphaned_flow_log_group = Mock()
    environment = EnvironmentContext(
        environment_name="0005",
        environment_id="os-agent-test-hanbin-074709-0005",
        created_by="hanbin",
        owner_arn="arn:aws:iam::123456789012:user/hanbin",
        account_id="123456789012",
    )
    manager._save_environment_context(environment)

    manager._destroy(environment.environment_id)

    manager._command.assert_called_once_with(
        ["terraform", "init", "-reconfigure", "-input=false"],
        manager.settings.terraform_dir,
    )
    assert manager.get_status().status == "succeeded"
    assert "삭제할 Terraform 리소스가 없습니다" in manager.get_status().logs[-1].message


def test_deployment_uses_controller_owned_terraform_data_dir(tmp_path: Path) -> None:
    manager = DeploymentManager(
        Settings(
            openrouter_api_key=None,
            openrouter_model="test-model",
            allowed_origins=("http://127.0.0.1:5173",),
            runtime_dir=tmp_path / "runtime",
        )
    )

    environment = manager._environment()

    expected = (tmp_path / "runtime" / "terraform-data" / "dashboard-controller").resolve()
    assert Path(environment["TF_DATA_DIR"]) == expected
    assert expected.is_dir()


def test_environment_id_is_scoped_to_aws_identity(tmp_path: Path) -> None:
    manager = DeploymentManager(
        Settings(
            openrouter_api_key=None,
            openrouter_model="test-model",
            allowed_origins=("http://127.0.0.1:5173",),
            runtime_dir=tmp_path,
        )
    )
    manager.get_caller_identity = Mock(
        return_value=AwsCallerIdentity(
            account_id="123456789012",
            arn="arn:aws:sts::123456789012:assumed-role/Admin/vinny",
            display_name="vinny",
            owner_key="vinny-abc123",
            environment_prefix="os-agent-test-vinny-abc123",
        )
    )

    environment = manager.resolve_environment("Permission-Test")

    assert environment.environment_name == "permission-test"
    assert environment.environment_id == "os-agent-test-vinny-abc123-permission-test"
    assert environment.created_by == "vinny"


def test_multiple_running_instances_require_selection(tmp_path: Path) -> None:
    manager = DeploymentManager(
        Settings(
            openrouter_api_key=None,
            openrouter_model="test-model",
            allowed_origins=("http://127.0.0.1:5173",),
            runtime_dir=tmp_path,
        )
    )
    instances = [
        _instance("i-0123456789abcdef0"),
        _instance("i-0fedcba9876543210"),
    ]
    manager.list_instances = Mock(return_value=instances)

    try:
        manager.get_trial_instance_id()
    except RuntimeError as error:
        assert str(error) == "실행 중인 EC2가 여러 대입니다. 연결할 인스턴스를 선택하세요."
    else:
        raise AssertionError("EC2가 여러 대면 선택을 요구해야 합니다.")

    assert manager.get_trial_instance_id(instances[1].instance_id) == instances[1].instance_id


def _instance(instance_id: str) -> AwsInstanceSummary:
    return AwsInstanceSummary(
        instance_id=instance_id,
        name=f"test-{instance_id}",
        environment_id="os-agent-test-vinny-abc123-permission",
        created_by="vinny",
        owner_arn="arn:aws:sts::123456789012:assumed-role/Admin/vinny",
        state="running",
        instance_type="t3.small",
        availability_zone="us-east-1a",
    )


def test_command_error_detail_returns_aws_reason() -> None:
    output = (
        "\x1b[31m│ Error: creating CloudWatch Logs Log Group: "
        "ResourceAlreadyExistsException: The specified log group already exists\x1b[0m"
    )

    assert DeploymentManager._command_error_detail(output) == (
        "creating CloudWatch Logs Log Group: ResourceAlreadyExistsException: "
        "The specified log group already exists"
    )


def test_tunnel_status_endpoint_is_available(tmp_path: Path) -> None:
    response = make_client(tmp_path).get("/api/tunnel")

    assert response.status_code == 200
    assert response.json()["local_port"] == 8001
    assert response.json()["remote_port"] == 8000


def test_tunnel_rejects_missing_confirmation(tmp_path: Path) -> None:
    response = make_client(tmp_path).post(
        "/api/tunnel",
        json={"confirmation": "yes"},
    )

    assert response.status_code == 422


def test_remote_api_requires_connected_tunnel(tmp_path: Path) -> None:
    response = make_client(tmp_path).get("/api/remote/health")

    assert response.status_code == 409
    assert response.json()["detail"] == "SSM 터널을 먼저 연결하세요."


def test_remote_experiment_reset_requires_connected_tunnel(tmp_path: Path) -> None:
    response = make_client(tmp_path).post(
        "/api/remote/experiment-environment/reset",
        json={"confirmation": "RESET_EXPERIMENT_ENVIRONMENT"},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "SSM 터널을 먼저 연결하세요."
