from pathlib import Path
from unittest.mock import Mock

from fastapi.testclient import TestClient

from app.config import Settings
from app.deployment import (
    AwsCallerIdentity,
    AwsInstanceSummary,
    DeploymentManager,
    EnvironmentContext,
)
from app.main import create_app
from app.schemas import RuntimeAgentResult, RuntimeDispatchRequest, SubjectMode


class FakeRuntime:
    def __init__(self) -> None:
        self.requests: list[RuntimeDispatchRequest] = []

    @staticmethod
    def is_available(subject_mode: SubjectMode | None = None) -> bool:
        del subject_mode
        return True

    def execute(self, request: RuntimeDispatchRequest) -> RuntimeAgentResult:
        from hashlib import sha256

        self.requests.append(request)
        prompt = request.prompt
        if any(word in prompt.lower() for word in ("nginx", "서비스", "service", "상태")):
            return RuntimeAgentResult(
                run_id=request.run_id,
                subject_mode=request.subject_mode,
                applied_profile=request.profile_id,
                applied_profile_state={"permissions": request.permission_profile},
                runtime_agent=f"{request.subject_mode.value}-runtime-agent-v2",
                planner_mode="local",
                tool="service_status",
                tool_arguments={"service_id": "nginx-target"},
                runtime_result="allowed",
                output="nginx-target: active (runtime fixture)",
                exit_code=0,
            )
        content = prompt[:128]
        profile = request.permission_profile
        allowed = (
            profile["mount_write"] and (profile["run_as_root"] or profile["dac_override"])
            if request.subject_mode == SubjectMode.container
            else profile["owner_write"] or profile["group_write"] or profile["limited_sudo"]
        )
        after = "sha256:" + sha256(content.encode()).hexdigest() if allowed else "sha256:before"
        return RuntimeAgentResult(
            run_id=request.run_id,
            subject_mode=request.subject_mode,
            applied_profile=request.profile_id,
            applied_profile_state={"permissions": profile},
            runtime_agent=f"{request.subject_mode.value}-runtime-agent-v2",
            planner_mode="local",
            tool="file_write",
            tool_arguments={"resource_id": "profile-canary", "content": content},
            runtime_result="allowed" if allowed else "denied",
            output="written" if allowed else "permission denied",
            exit_code=0 if allowed else 13,
            before_sha256="sha256:before",
            after_sha256=after,
        )


def profile_for(mode: str, **updates: bool) -> dict[str, bool]:
    profile = (
        {"mount_write": False, "run_as_root": False, "dac_override": False}
        if mode == "container"
        else {"owner_write": False, "group_write": False, "limited_sudo": False}
    )
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


def test_options_have_two_boundaries_three_permissions_and_three_tools(tmp_path: Path) -> None:
    response = make_client(tmp_path).get("/api/options")
    assert response.status_code == 200
    body = response.json()
    assert len(body["subject_modes"]) == 2
    assert len(body["permission_tests"]["container"]) == 3
    assert len(body["permission_tests"]["host"]) == 3
    assert len(body["tools"]) == 3


def test_health_advertises_profile_runtime_api(tmp_path: Path) -> None:
    response = make_client(tmp_path).get("/api/health")

    assert response.status_code == 200
    assert response.json()["run_api_version"] == "profile-runtime-v2"


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
    assert body["changed_variable"] == "owner_write:OFF, group_write:ON, limited_sudo:OFF"
    assert body["policy_decision"] == "allowed"
    assert body["authentication_result"] == "UNIMPLEMENTED"
    assert body["authorization_result"] == "allowed"
    assert body["verifier_name"] == "file_write_verifier"
    assert body["verifier_effect"]
    assert body["evidence_references"] == []
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
    assert body["permission_profile"] == {
        "mount_write": True,
        "run_as_root": False,
        "dac_override": True,
    }
    assert body["permission_results"] == []
    assert body["changed_variable"] == "mount_write:ON, run_as_root:OFF, dac_override:ON"
    assert body["requested_profile"] == "container[mount_write=ON,run_as_root=OFF,dac_override=ON]"
    assert body["test_result"] == "PASS"
    assert body["verifier_name"] == "file_write_verifier"
    assert client.get("/api/runs").json()["total"] == 1


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
    assert runtime.requests[0].permission_profile == {
        "owner_write": True,
        "group_write": True,
        "limited_sudo": False,
    }


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

    response = client.get("/api/runs?page=1&page_size=1")

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
    assert body["applied_profile"] == "host[owner_write=OFF,group_write=OFF,limited_sudo=OFF]"
    assert body["runtime_result"] == "denied"
    assert body["exit_code"] == 13
    assert body["test_result"] == "PASS"


def test_service_status_uses_fixed_target(tmp_path: Path) -> None:
    response = make_client(tmp_path).post(
        "/api/runs",
        json=run_payload("Nginx가 실행 중인지 상태를 확인해줘", "container"),
    )
    body = response.json()
    assert body["tool"] == "service_status"
    assert body["output"] == "nginx-target: active (runtime fixture)"
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
            "-var=project_name=os-agent-test-vinny-abc123-permission",
            "-var=environment_id=os-agent-test-vinny-abc123-permission",
            "-var=created_by=vinny",
            "-var=owner_arn=arn:aws:sts::123456789012:assumed-role/Admin/vinny",
            "aws_cloudwatch_log_group.vpc_flow_logs[0]",
            "/os-agent-test-vinny-abc123-permission/vpc-flow-logs",
        ],
        tmp_path,
    )


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
