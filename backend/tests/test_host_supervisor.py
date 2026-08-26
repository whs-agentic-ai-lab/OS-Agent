from __future__ import annotations

import json
import socketserver
import subprocess
import sys
import types

# host_supervisor는 Ubuntu 전용 모듈이지만 이 회귀 테스트는 Windows 개발
# 환경에서도 Docker 명령 조립만 검증할 수 있어야 한다.
sys.modules.setdefault("grp", types.ModuleType("grp"))
sys.modules.setdefault("pwd", types.ModuleType("pwd"))
if not hasattr(socketserver, "UnixStreamServer"):
    socketserver.UnixStreamServer = socketserver.TCPServer  # type: ignore[attr-defined]

from host_runtime import host_supervisor


def test_container_runtime_keeps_stdin_open_for_dispatch_payload(
    monkeypatch,
    tmp_path,
) -> None:
    container_runs = tmp_path / "container-runs"
    targets = tmp_path / "targets"
    container_runs.mkdir()
    targets.mkdir()
    captured: dict[str, object] = {}

    def fake_run(command: list[str], *, input_text: str | None = None):
        captured["command"] = command
        captured["input_text"] = input_text
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(
                {
                    "run_id": "harness-aaaaaaaaaaaa",
                    "subject_mode": "container",
                    "trust_boundary_id": "TB-CC-C1C2",
                    "source_environment": "c1",
                    "target_environment": "c2",
                    "applied_profile": (
                        "container[mount_write=OFF,run_as_root=OFF,dac_override=OFF]"
                    ),
                    "applied_profile_state": {},
                    "runtime_agent": "c1-executor-v3",
                    "planner_mode": "local",
                    "tool": "service_status",
                    "tool_arguments": {"resource_id": "target-service"},
                    "policy_decision": "allowed",
                    "runtime_result": "allowed",
                    "output": "target-service: active",
                    "exit_code": 0,
                    "before_sha256": None,
                    "after_sha256": None,
                    "events": [],
                }
            ),
            stderr="",
        )

    monkeypatch.setattr(host_supervisor, "CONTAINER_RUN_ROOT", container_runs)
    monkeypatch.setattr(host_supervisor, "TARGET_ROOT", targets)
    monkeypatch.setattr(host_supervisor, "_run", fake_run)
    monkeypatch.setattr(host_supervisor.os, "chown", lambda *args: None, raising=False)

    payload = {
        "run_id": "harness-aaaaaaaaaaaa",
        "prompt": "서비스 상태 확인",
        "subject_mode": "container",
        "trust_boundary_id": "TB-CC-C1C2",
        "source_environment": "c1",
        "target_environment": "c2",
        "permission_profile": {
            "mount_write": False,
            "run_as_root": False,
            "dac_override": False,
        },
        "profile_id": "container[mount_write=OFF,run_as_root=OFF,dac_override=OFF]",
        "tool_decision": {
            "name": "service_status",
            "arguments": {"resource_id": "target-service"},
        },
        "planner_mode": "local",
    }

    host_supervisor._execute_container_runtime(payload)

    command = captured["command"]
    assert isinstance(command, list)
    assert "--interactive" in command
    assert json.loads(str(captured["input_text"])) == payload
