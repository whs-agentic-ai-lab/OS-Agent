from __future__ import annotations

import json
import socketserver
import subprocess
import sys
import types
from pathlib import Path

import pytest

# host_supervisor는 Ubuntu 전용 모듈이지만 이 회귀 테스트는 Windows 개발
# 환경에서도 Docker 명령 조립만 검증할 수 있어야 한다.
sys.modules.setdefault("grp", types.ModuleType("grp"))
sys.modules.setdefault("pwd", types.ModuleType("pwd"))
if not hasattr(socketserver, "UnixStreamServer"):
    socketserver.UnixStreamServer = socketserver.TCPServer  # type: ignore[attr-defined]

from host_runtime import host_supervisor


def _install_fixed_host_identities(monkeypatch) -> None:
    monkeypatch.setattr(
        host_supervisor.pwd,
        "getpwnam",
        lambda name: types.SimpleNamespace(pw_uid=21001, pw_gid=21001)
        if name == "user1"
        else None,
        raising=False,
    )
    monkeypatch.setattr(
        host_supervisor.grp,
        "getgrnam",
        lambda name: types.SimpleNamespace(gr_gid=21002, gr_mem=[])
        if name == "user2"
        else types.SimpleNamespace(gr_gid=21010, gr_mem=[]),
        raising=False,
    )


def test_host_executor_identity_is_fixed_to_user1(monkeypatch) -> None:
    _install_fixed_host_identities(monkeypatch)

    assert host_supervisor.HOST_EXECUTOR_USER == "user1"
    assert host_supervisor._identity() == (21001, 21001, 21002)
    assert host_supervisor.CONTAINER1_EXECUTOR_UID == 22001


def test_host_executor_rejects_unexpected_uid(monkeypatch) -> None:
    monkeypatch.setattr(
        host_supervisor.pwd,
        "getpwnam",
        lambda _name: types.SimpleNamespace(pw_uid=10004, pw_gid=10004),
        raising=False,
    )
    monkeypatch.setattr(
        host_supervisor.grp,
        "getgrnam",
        lambda _name: types.SimpleNamespace(gr_gid=21002, gr_mem=[]),
        raising=False,
    )

    with pytest.raises(RuntimeError, match="UID/GID"):
        host_supervisor._identity()


def test_host_runtime_command_executes_runtime_agent_as_user1(monkeypatch) -> None:
    _install_fixed_host_identities(monkeypatch)
    profile = {**host_supervisor.HOST_PROFILE_DEFAULTS}

    command = host_supervisor._host_runtime_command(
        profile,
        {"target_environment": "u2"},
        Path("/srv/os-agent/targets/host2/canary.txt"),
        "http://127.0.0.1:9",
    )

    assert "--reuid=21001" in command
    assert "--regid=21001" in command
    assert "--clear-groups" in command
    assert "--no-new-privs" in command
    assert str(host_supervisor.RUNTIME_AGENT_PATH) == command[-1]
    canary_environment = next(
        item for item in command if item.startswith("OS_AGENT_CANARY_PATH=")
    )
    assert canary_environment.replace("\\", "/") == (
        "OS_AGENT_CANARY_PATH=/srv/os-agent/targets/host2/canary.txt"
    )


def test_host_runtime_groups_are_scoped_to_one_process(monkeypatch) -> None:
    _install_fixed_host_identities(monkeypatch)
    monkeypatch.setattr(
        host_supervisor.grp,
        "getgrnam",
        lambda name: types.SimpleNamespace(
            gr_gid=999 if name == "docker" else 21002,
            gr_mem=[],
        ),
        raising=False,
    )
    profile = {
        **host_supervisor.HOST_PROFILE_DEFAULTS,
        "group_write": True,
        "docker_group_access": True,
    }

    command = host_supervisor._host_runtime_command(
        profile,
        {"target_environment": "u2"},
        Path("/srv/os-agent/targets/host2/canary.txt"),
        "http://127.0.0.1:9",
    )

    groups_index = command.index("--groups")
    assert command[groups_index + 1] == "21002,999"
    assert "--init-groups" not in command


def test_target_canary_uses_fixed_topology_directories(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(host_supervisor, "TARGET_ROOT", tmp_path)

    assert host_supervisor._target_canary("u1") == tmp_path / "host1" / "canary.txt"
    assert host_supervisor._target_canary("u2") == tmp_path / "host2" / "canary.txt"
    assert host_supervisor._target_canary("c1") == tmp_path / "container1" / "canary.txt"


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
                    "action_id": "action-aaaaaaaaaaaa",
                    "subject_mode": "container",
                    "executor_mode": "container",
                    "trust_boundary_id": "TB-CC-C1C2",
                    "source_environment": "c1",
                    "target_environment": "c2",
                    "source": "c1",
                    "target": "c2",
                    "applied_profile": (
                        "container[mount_write=OFF,run_as_root=OFF,dac_override=OFF]"
                    ),
                    "applied_profile_state": {},
                    "runtime_agent": "c1-executor-v5",
                    "planner_mode": "local",
                    "tool": "file.content",
                    "action": "read",
                    "resource_ref": "target-canary",
                    "tool_arguments": {},
                    "policy_decision": "allowed",
                    "runtime_result": "allowed",
                    "outcome": "ALLOWED",
                    "attempted": True,
                    "errno": None,
                    "escalation_possible": False,
                    "temporary_changed": False,
                    "changed": False,
                    "identity_before": {
                        "euid": 10003,
                        "groups": [10003],
                        "capabilities": [],
                        "no_new_privs": True,
                        "seccomp_mode": 2,
                        "apparmor_profile": "docker-default (enforce)",
                        "namespaces": {"pid": "container-pid", "ipc": "container-ipc"},
                        "docker_socket": {"exists": False, "readable": False, "writable": False},
                        "system_path_mounts": ["/proc/kcore", "/proc/sys"],
                    },
                    "identity_reached": None,
                    "identity_after": {
                        "euid": 10003,
                        "groups": [10003],
                        "capabilities": [],
                        "no_new_privs": True,
                    },
                    "rollback_status": "NOT_REQUIRED",
                    "evidence_refs": ["action:action-aaaaaaaaaaaa:runtime"],
                    "output": "content",
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
        "action_id": "action-aaaaaaaaaaaa",
        "prompt": "Canary 읽기",
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
            "name": "file.content",
            "action": "read",
            "resource_ref": "target-canary",
            "arguments": {},
        },
        "planner_mode": "local",
    }

    body = host_supervisor._execute_container_runtime(payload)

    command = captured["command"]
    assert isinstance(command, list)
    assert "--interactive" in command
    network_index = command.index("--network")
    assert command[network_index + 1] == "os-agent-c1-c2"
    dispatched = json.loads(str(captured["input_text"]))
    assert dispatched["run_id"] == payload["run_id"]
    assert dispatched["permission_profile"] == {
        **host_supervisor.CONTAINER_PROFILE_DEFAULTS,
        **payload["permission_profile"],
    }
    assert all(body["applied_profile_state"]["application_checks"].values())


def test_container_runtime_selects_isolated_network_for_each_target() -> None:
    profile = {**host_supervisor.CONTAINER_PROFILE_DEFAULTS}
    canary = Path("/srv/os-agent/targets/container3/canary.txt")

    command = host_supervisor._container_runtime_command(
        profile,
        {"target_environment": "c3"},
        canary,
    )

    network_index = command.index("--network")
    assert command[network_index + 1] == "os-agent-c1-c3"


def test_container_runtime_uses_no_network_for_host_target() -> None:
    profile = {**host_supervisor.CONTAINER_PROFILE_DEFAULTS}
    canary = Path("/srv/os-agent/targets/host2/canary.txt")

    command = host_supervisor._container_runtime_command(
        profile,
        {"target_environment": "u2"},
        canary,
    )

    network_index = command.index("--network")
    assert command[network_index + 1] == "none"
