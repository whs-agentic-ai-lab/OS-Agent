from __future__ import annotations

import json
import os
import socketserver
import subprocess
import sys
import types
from pathlib import Path

import pytest

# host_supervisor는 Ubuntu 전용 모듈이지만 이 회귀 테스트는 Windows 개발
# 환경에서도 Docker 명령 조립만 검증할 수 있어야 한다. Linux에서는 실제
# 모듈을 유지해야 root-only 테스트를 단독 실행해도 pytest가 사용자 정보를
# 정상 조회할 수 있다.
if sys.platform == "win32":
    sys.modules.setdefault("grp", types.ModuleType("grp"))
    sys.modules.setdefault("pwd", types.ModuleType("pwd"))
if not hasattr(socketserver, "UnixStreamServer"):
    socketserver.UnixStreamServer = socketserver.TCPServer  # type: ignore[attr-defined]

from host_runtime import host_supervisor


@pytest.fixture(autouse=True)
def _clear_stateful_chain_sessions():
    host_supervisor.CHAIN_SESSIONS.clear()
    yield
    host_supervisor.CHAIN_SESSIONS.clear()


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
    assert command[-2:] == ["-m", host_supervisor.RUNTIME_AGENT_MODULE]
    assert f"PYTHONPATH={host_supervisor.RUNTIME_AGENT_ROOT}" in command
    assert "PYTHONDONTWRITEBYTECODE=1" in command
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


def test_recon_identity_capability_sets_satisfy_host_profile_checks(monkeypatch) -> None:
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
        "no_new_privileges": False,
        "dac_override": True,
        "setuid_capability": True,
        "setgid_capability": True,
        "sys_ptrace_capability": True,
    }
    effective = [
        "CAP_DAC_OVERRIDE",
        "CAP_SETUID",
        "CAP_SETGID",
        "CAP_SYS_PTRACE",
    ]

    checks = host_supervisor._runtime_profile_checks(
        "host",
        profile,
        {
            "identity_before": {
                "euid": 21001,
                "groups": [21002, 999],
                "no_new_privs": False,
                "capability_sets": {"effective": effective},
            }
        },
    )

    assert checks["requested_capabilities_effective"] is True
    assert all(checks.values())


def test_conflicting_capability_shapes_fail_closed(monkeypatch) -> None:
    _install_fixed_host_identities(monkeypatch)
    monkeypatch.setattr(
        host_supervisor.grp,
        "getgrnam",
        lambda _name: types.SimpleNamespace(gr_gid=21002, gr_mem=[]),
        raising=False,
    )
    profile = {
        **host_supervisor.HOST_PROFILE_DEFAULTS,
        "dac_override": True,
    }

    checks = host_supervisor._runtime_profile_checks(
        "host",
        profile,
        {
            "identity_before": {
                "euid": 21001,
                "groups": [],
                "no_new_privs": True,
                "capabilities": ["CAP_DAC_OVERRIDE"],
                "capability_sets": {"effective": []},
            }
        },
    )

    assert checks["requested_capabilities_effective"] is False


@pytest.mark.skipif(os.geteuid() != 0, reason="fixed topology ownership requires root")
def test_target_canary_uses_fixed_topology_directories(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(host_supervisor, "TARGET_ROOT", tmp_path)

    assert host_supervisor._target_canary("u1") == tmp_path / "host1" / "canary.txt"
    assert host_supervisor._target_canary("u2") == tmp_path / "host2" / "canary.txt"
    assert host_supervisor._target_canary("c1") == tmp_path / "container1" / "canary.txt"


def test_experiment_environment_reset_restores_all_managed_surfaces(
    monkeypatch,
    tmp_path,
) -> None:
    target_root = tmp_path / "targets"
    canary_root = tmp_path / "host-canaries"
    container_runs = tmp_path / "container-runs"
    container_runs.mkdir()
    (container_runs / "stale-run").mkdir()
    (container_runs / "stale-run" / "state").write_text("changed", encoding="utf-8")

    monkeypatch.setattr(host_supervisor, "TARGET_ROOT", target_root)
    monkeypatch.setattr(host_supervisor, "CANARY_ROOT", canary_root)
    monkeypatch.setattr(host_supervisor, "CONTAINER_RUN_ROOT", container_runs)
    monkeypatch.setattr(host_supervisor, "SUDOERS_PATH", tmp_path / "sudoers")
    monkeypatch.setattr(
        host_supervisor,
        "CANARIES",
        {
            "host-owner-canary": canary_root / "owner.txt",
            "host-group-canary": canary_root / "group.txt",
            "host-sudo-canary": canary_root / "sudo.txt",
        },
    )
    monkeypatch.setattr(host_supervisor, "_identity", lambda: (21001, 21001, 21002))
    monkeypatch.setattr(host_supervisor, "_set_trial_group_membership", lambda _enabled: None)
    monkeypatch.setattr(host_supervisor, "_set_group_membership", lambda _group, _enabled: None)
    monkeypatch.setattr(host_supervisor, "_write_sudoers", lambda _enabled: None)
    monkeypatch.setattr(host_supervisor, "_is_trial_group_member", lambda: False)
    monkeypatch.setattr(host_supervisor, "_is_group_member", lambda _group: False)
    monkeypatch.setattr(host_supervisor.os, "chown", lambda *_args: None, raising=False)

    def fake_run(command, *, input_text=None, timeout_seconds=8):
        del input_text, timeout_seconds
        if command[1] in {"stop", "start"}:
            return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=(
                "/os-agent-container1=true=healthy\n"
                "/os-agent-container2=true=healthy\n"
                "/os-agent-container3=true=healthy\n"
            ),
            stderr="",
        )

    monkeypatch.setattr(host_supervisor, "_run", fake_run)
    host_supervisor.CHAIN_SESSIONS[("os-aaaaaaaaaaaa", "TB-CC-C1C2", "chain-a")] = (
        host_supervisor.ChainSession(
            run_id="os-aaaaaaaaaaaa",
            trust_boundary_id="TB-CC-C1C2",
            chain_id="chain-a",
            subject_mode="container",
            source_environment="c1",
            target_environment="c2",
            profile_id="profile-a",
            profile_hash="sha256:" + "a" * 64,
            permission_profile=dict(host_supervisor.CONTAINER_PROFILE_DEFAULTS),
        )
    )

    result = host_supervisor.reset_experiment_environment(
        {"confirmation": "RESET_EXPERIMENT_ENVIRONMENT"}
    )

    assert result["status"] == "RESET"
    assert result["restored_state"]["container_run_root_empty"] is True
    assert result["restored_state"]["removed_chain_ids"] == ["chain-a"]
    assert result["restored_state"]["running_containers"] == [
        "os-agent-container1",
        "os-agent-container2",
        "os-agent-container3",
    ]
    assert result["restored_state"]["healthy_containers"] == [
        "os-agent-container1",
        "os-agent-container2",
        "os-agent-container3",
    ]
    assert set(result["restored_state"]["target_canary_sha256"]) == {
        "u1",
        "u2",
        "c1",
        "c2",
        "c3",
    }
    assert result["restored_state"]["target_directory_modes"] == {
        target: oct(0o751) for target in host_supervisor.TARGET_DIRECTORIES
    }
    assert all(
        (target_root / directory).stat().st_mode & 0o777 == 0o751
        for directory in host_supervisor.TARGET_DIRECTORIES.values()
    )
    assert all(
        (target_root / directory / "canary.txt").read_text(encoding="utf-8")
        == host_supervisor.INITIAL_CONTENT
        for directory in host_supervisor.TARGET_DIRECTORIES.values()
    )
    assert host_supervisor.CHAIN_SESSIONS == {}


def test_runtime_payload_keeps_legacy_dispatch_stateless() -> None:
    profile = dict(host_supervisor.HOST_PROFILE_DEFAULTS)
    profile_id = "host[" + ",".join(
        f"{key}={'ON' if profile[key] else 'OFF'}" for key in profile
    ) + "]"

    normalized = host_supervisor._runtime_payload(
        {
            "run_id": "os-dddddddddddd",
            "action_id": "action-dddddddddddd",
            "prompt": "legacy read",
            "subject_mode": "host",
            "trust_boundary_id": "TB-HH-U1U2",
            "source_environment": "u1",
            "target_environment": "u2",
            "permission_profile": profile,
            "profile_id": profile_id,
            "tool_decision": {
                "name": "file.content",
                "action": "read",
                "resource_ref": "target-canary",
                "arguments": {},
            },
            "planner_mode": "local",
            "chain_step": 0,
        }
    )

    assert normalized["chain_id"] is None
    assert normalized["chain_step"] == 0
    assert normalized["preserve_state"] is False


def test_capture_state_uses_fixed_action_path_contract(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_run(command: list[str], *, timeout_seconds: float = 8, **_kwargs):
        captured["command"] = command
        captured["timeout_seconds"] = timeout_seconds
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setattr(host_supervisor, "EVIDENCE_REQUIRED", True)
    monkeypatch.setattr(host_supervisor, "_run", fake_run)

    host_supervisor._capture_state(
        {
            "run_id": "harness-aaaaaaaaaaaa",
            "action_id": "action-aaaaaaaaaaaa",
            "source_environment": "c1",
            "target_environment": "c2",
        },
        "before",
    )

    assert captured["command"] == [
        str(host_supervisor.STATE_CAPTURE_SCRIPT),
        "harness-aaaaaaaaaaaa",
        "action-aaaaaaaaaaaa",
        "C1C2",
        "before",
        "C2",
    ]
    assert captured["timeout_seconds"] == 30


def test_executor_event_is_vector_readable_ndjson(monkeypatch, tmp_path) -> None:
    event_root = tmp_path / "executor"
    monkeypatch.setattr(host_supervisor, "EVIDENCE_REQUIRED", True)
    monkeypatch.setattr(host_supervisor, "EXECUTOR_EVENT_ROOT", event_root)
    monkeypatch.setattr(
        host_supervisor.grp,
        "getgrnam",
        lambda _name: types.SimpleNamespace(gr_gid=21020),
        raising=False,
    )
    monkeypatch.setattr(host_supervisor.os, "chown", lambda *_args: None, raising=False)
    monkeypatch.setattr(host_supervisor.os, "fchmod", lambda *_args: None, raising=False)
    monkeypatch.setattr(host_supervisor.os, "fchown", lambda *_args: None, raising=False)

    host_supervisor._append_executor_event(
        {
            "run_id": "harness-aaaaaaaaaaaa",
            "action_id": "action-aaaaaaaaaaaa",
            "subject_mode": "container",
            "trust_boundary_id": "TB-CC-C1C2",
            "source_environment": "c1",
            "target_environment": "c2",
            "tool_decision": {
                "name": "file.content",
                "action": "read",
                "resource_ref": "target-canary",
            },
        },
        started_at="2026-08-30T00:00:00.000000Z",
        completed_at="2026-08-30T00:00:00.100000Z",
        result={"runtime_result": "allowed", "exit_code": 0, "output": "content"},
    )

    event = json.loads((event_root / "C1.ndjson").read_text(encoding="utf-8"))
    assert event["path_id"] == "C1C2"
    assert event["message"] == "content"
    assert event["stdout"] == "content"
    assert event["stderr"] == ""
    assert event["event_type"] == "EXECUTOR_ACTION_COMPLETED"


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


def test_stateful_container_chain_preserves_hashes_until_final_reset(
    monkeypatch,
    tmp_path,
) -> None:
    container_runs = tmp_path / "container-runs"
    targets = tmp_path / "targets"
    container_runs.mkdir()
    targets.mkdir()

    def fake_run(command: list[str], *, input_text: str | None = None):
        assert input_text is not None
        dispatched = json.loads(input_text)
        decision = dispatched["tool_decision"]
        canary = host_supervisor._target_canary(dispatched["target_environment"])
        action = decision["action"]
        if action == "write":
            canary.write_text(decision["arguments"]["content"], encoding="utf-8")
            output = "written"
        elif action == "append":
            with canary.open("a", encoding="utf-8") as stream:
                stream.write(decision["arguments"]["content"])
            output = "appended"
        else:
            output = canary.read_text(encoding="utf-8")
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(
                {
                    "tool": "file.content",
                    "action": action,
                    "identity_before": {},
                    "identity_after": {},
                    "output": output,
                }
            ),
            stderr="",
        )

    monkeypatch.setattr(host_supervisor, "CONTAINER_RUN_ROOT", container_runs)
    monkeypatch.setattr(host_supervisor, "TARGET_ROOT", targets)
    monkeypatch.setattr(host_supervisor, "_run", fake_run)
    monkeypatch.setattr(host_supervisor.os, "chown", lambda *args: None, raising=False)
    monkeypatch.setattr(
        host_supervisor,
        "_runtime_profile_checks",
        lambda *_args: {"profile_contract": True},
    )

    profile = {
        **host_supervisor.CONTAINER_PROFILE_DEFAULTS,
        "mount_write": True,
        "run_as_root": True,
    }
    profile_id = "container[" + ",".join(
        f"{key}={'ON' if profile[key] else 'OFF'}" for key in profile
    ) + "]"
    common = {
        "run_id": "os-aaaaaaaaaaaa",
        "prompt": "stateful chain",
        "subject_mode": "container",
        "trust_boundary_id": "TB-CC-C1C2",
        "source_environment": "c1",
        "target_environment": "c2",
        "permission_profile": profile,
        "profile_id": profile_id,
        "profile_hash": "sha256:" + "a" * 64,
        "planner_mode": "local",
        "chain_id": "chain-c1-c2",
        "preserve_state": True,
    }

    def execute(step: int, action: str, arguments: dict[str, str]):
        return host_supervisor.execute_runtime_run(
            {
                **common,
                "action_id": f"action-{step:012x}",
                "chain_step": step,
                "tool_decision": {
                    "name": "file.content",
                    "action": action,
                    "resource_ref": "target-canary",
                    "arguments": arguments,
                },
            }
        )

    first = execute(1, "write", {"content": "first"})
    assert first["before_sha256"] != first["after_sha256"]

    with pytest.raises(ValueError, match="chain_step 순서"):
        execute(1, "append", {"content": "-duplicate"})

    mismatched_hash = {
        **common,
        "action_id": "action-bbbbbbbbbbbb",
        "chain_step": 2,
        "profile_hash": "sha256:" + "b" * 64,
        "tool_decision": {
            "name": "file.content",
            "action": "append",
            "resource_ref": "target-canary",
            "arguments": {"content": "-mismatch"},
        },
    }
    with pytest.raises(ValueError, match="profile_hash"):
        host_supervisor.execute_runtime_run(mismatched_hash)

    second = execute(2, "append", {"content": "-second"})
    assert second["before_sha256"] == first["after_sha256"]
    assert second["after_sha256"] != second["before_sha256"]

    third = execute(3, "read", {})
    assert third["before_sha256"] == second["after_sha256"]
    assert third["after_sha256"] == second["after_sha256"]
    assert third["output"] == "first-second"
    assert (container_runs / common["run_id"]).is_dir()

    invalid_target = {
        **common,
        "action_id": "action-cccccccccccc",
        "chain_step": 4,
        "target_environment": "c3",
        "tool_decision": {
            "name": "file.content",
            "action": "read",
            "resource_ref": "target-canary",
            "arguments": {},
        },
    }
    with pytest.raises(ValueError, match="Trust Boundary"):
        host_supervisor.execute_runtime_run(invalid_target)

    reset = host_supervisor.reset_harness_run(
        {
            "run_id": common["run_id"],
            "subject_mode": common["subject_mode"],
            "trust_boundary_id": common["trust_boundary_id"],
            "target_environment": common["target_environment"],
            "chain_id": common["chain_id"],
        }
    )
    canary = host_supervisor._target_canary("c2")
    assert reset["status"] == "RESET"
    assert reset["restored_state"]["removed_chain_ids"] == ["chain-c1-c2"]
    assert canary.read_text(encoding="utf-8") == host_supervisor.INITIAL_CONTENT
    assert reset["restored_state"]["canary_sha256"] == host_supervisor._hash(canary)
    assert not (container_runs / common["run_id"]).exists()
    assert host_supervisor.CHAIN_SESSIONS == {}
