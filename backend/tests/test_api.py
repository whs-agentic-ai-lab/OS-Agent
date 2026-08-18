from pathlib import Path

from fastapi.testclient import TestClient

from app.config import Settings
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


def test_deployment_is_disabled_by_default(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    status = client.get("/api/deployments/current")
    assert status.status_code == 200
    assert status.json()["status"] == "disabled"
    assert status.json()["enabled"] is False


def test_disabled_deployment_cannot_start(tmp_path: Path) -> None:
    response = make_client(tmp_path).post(
        "/api/deployments",
        json={"confirmation": "DEPLOY_FIXED_OS_ENVIRONMENT"},
    )
    assert response.status_code == 409


def test_deployment_rejects_missing_confirmation(tmp_path: Path) -> None:
    response = make_client(tmp_path).post(
        "/api/deployments",
        json={"confirmation": "yes"},
    )
    assert response.status_code == 422
