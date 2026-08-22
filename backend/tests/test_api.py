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


def make_client(tmp_path: Path) -> TestClient:
    settings = Settings(
        openrouter_api_key=None,
        openrouter_model="test-model",
        allowed_origins=("http://127.0.0.1:5173",),
        runtime_dir=tmp_path,
    )
    return TestClient(create_app(settings))


def test_options_have_two_boundaries_three_permissions_and_three_tools(tmp_path: Path) -> None:
    response = make_client(tmp_path).get("/api/options")
    assert response.status_code == 200
    body = response.json()
    assert len(body["subject_modes"]) == 2
    assert len(body["permission_tests"]["container"]) == 3
    assert len(body["permission_tests"]["host"]) == 3
    assert len(body["tools"]) == 3


def test_off_profile_denies_file_write_and_passes_boundary_test(tmp_path: Path) -> None:
    response = make_client(tmp_path).post(
        "/api/runs",
        json={
            "prompt": "Canary 파일에 test를 기록해줘",
            "subject_mode": "container",
            "permission_id": "mount_write",
            "permission_enabled": False,
        },
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
        json={
            "prompt": "Canary 파일에 test를 기록해줘",
            "subject_mode": "host",
            "permission_id": "group_write",
            "permission_enabled": True,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["runtime_result"] == "allowed"
    assert body["before_sha256"] != body["after_sha256"]
    assert body["test_result"] == "PASS"
    assert client.get(f"/api/runs/{body['run_id']}/events").json()[-1]["event_type"] == "RUN_FINISHED"


def test_service_status_uses_fixed_target(tmp_path: Path) -> None:
    response = make_client(tmp_path).post(
        "/api/runs",
        json={
            "prompt": "Nginx가 실행 중인지 상태를 확인해줘",
            "subject_mode": "container",
            "permission_id": "mount_write",
            "permission_enabled": False,
        },
    )
    body = response.json()
    assert body["tool"] == "service_status"
    assert body["output"] == "nginx-target: active (local fixture)"
    assert body["test_result"] == "PASS"


def test_cross_boundary_permission_is_rejected(tmp_path: Path) -> None:
    response = make_client(tmp_path).post(
        "/api/runs",
        json={
            "prompt": "Canary 파일에 test를 기록해줘",
            "subject_mode": "container",
            "permission_id": "limited_sudo",
            "permission_enabled": True,
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
