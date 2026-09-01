from __future__ import annotations

import socketserver
import sys
import types
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.modules.setdefault("grp", types.ModuleType("grp"))
sys.modules.setdefault("pwd", types.ModuleType("pwd"))
if not hasattr(socketserver, "UnixStreamServer"):
    socketserver.UnixStreamServer = socketserver.TCPServer  # type: ignore[attr-defined]

from app.permission_controls import (  # noqa: E402
    PERMISSION_CONTROLS,
    PROFILE_DEFAULTS,
    PROFILE_KEYS,
)
from app.schemas import RunRequest, SubjectMode  # noqa: E402
from host_runtime import host_supervisor  # noqa: E402


def test_permission_catalog_controls_have_stable_ids_and_safe_defaults() -> None:
    assert len(PERMISSION_CONTROLS[SubjectMode.container]) == 15
    assert len(PERMISSION_CONTROLS[SubjectMode.host]) == 9
    for mode, controls in PERMISSION_CONTROLS.items():
        assert len(PROFILE_KEYS[mode]) == len(set(PROFILE_KEYS[mode]))
        assert all(control.catalog_ids for control in controls)
        assert all(control.axis.startswith("AX-") for control in controls)
        assert PROFILE_DEFAULTS[mode]["no_new_privileges"] is True
    for dangerous in (
        "privileged", "docker_socket_access", "apparmor_unconfined",
        "seccomp_unconfined", "systempaths_unconfined", "pid_namespace_host",
        "ipc_namespace_host",
    ):
        assert PROFILE_DEFAULTS[SubjectMode.container][dangerous] is False
    assert PROFILE_DEFAULTS[SubjectMode.host]["docker_group_access"] is False


def test_old_minimal_profile_is_completed_with_catalog_defaults() -> None:
    request = RunRequest(
        prompt="Canary를 읽는다.",
        subject_mode=SubjectMode.container,
        permission_profile={
            "mount_write": False,
            "run_as_root": False,
            "dac_override": False,
        },
    )

    assert request.permission_profile == PROFILE_DEFAULTS[SubjectMode.container]
    assert len(request.permissions) == 15


def test_cross_environment_permission_is_rejected() -> None:
    with pytest.raises(ValidationError, match="선택 환경과 맞지 않는"):
        RunRequest(
            prompt="Canary를 읽는다.",
            subject_mode=SubjectMode.container,
            permission_profile={"limited_sudo": True},
        )


def test_container_control_profile_maps_to_real_docker_run_options() -> None:
    profile = {
        **PROFILE_DEFAULTS[SubjectMode.container],
        "mount_write": True,
        "run_as_root": True,
        "supplementary_group": True,
        "dac_override": True,
        "setuid_capability": True,
        "setgid_capability": True,
        "sys_ptrace_capability": True,
        "no_new_privileges": False,
        "pid_namespace_host": True,
        "ipc_namespace_host": True,
        "apparmor_unconfined": True,
        "seccomp_unconfined": True,
        "systempaths_unconfined": True,
        "docker_socket_access": True,
    }
    command = host_supervisor._container_runtime_command(
        profile,
        {"target_environment": "u2"},
        Path("/opt/trial/targets/u2/canary.txt"),
    )

    rendered = " ".join(command)
    assert "--interactive" in command
    assert "--user 0:0" in rendered
    assert "--group-add 10005" in rendered
    assert "--cap-add DAC_OVERRIDE" in rendered
    assert "--cap-add SETUID" in rendered
    assert "--cap-add SETGID" in rendered
    assert "--cap-add SYS_PTRACE" in rendered
    assert "--pid host" in rendered
    assert "--ipc host" in rendered
    assert "apparmor=unconfined" in command
    assert "seccomp=unconfined" in command
    assert "systempaths=unconfined" in command
    assert "/run/docker.sock:/run/docker.sock" in command
    assert "no-new-privileges" not in command


def test_container_baseline_keeps_confinement_and_drops_capabilities() -> None:
    command = host_supervisor._container_runtime_command(
        PROFILE_DEFAULTS[SubjectMode.container],
        {"target_environment": "c2"},
        Path("/opt/trial/targets/c2/canary.txt"),
    )

    rendered = " ".join(command)
    assert "--user 10003:10003" in rendered
    assert "--cap-drop ALL" in rendered
    assert "no-new-privileges" in command
    assert "--privileged" not in command
    assert "/var/run/docker.sock:/var/run/docker.sock" not in command


def test_nonroot_capability_uses_bootstrap_wrapper_and_drops_bootstrap_caps() -> None:
    profile = {
        **PROFILE_DEFAULTS[SubjectMode.container],
        "setuid_capability": True,
    }
    command = host_supervisor._container_runtime_command(
        profile,
        {"target_environment": "u2"},
        Path("/opt/trial/targets/u2/canary.txt"),
    )
    rendered = " ".join(command)

    assert "--user 0:0" in rendered
    assert "--cap-add SETPCAP" in rendered
    assert "--cap-add SETUID" in rendered
    assert "--cap-add SETGID" in rendered
    assert "/usr/bin/setpriv --reuid=10003 --regid=10003" in rendered
    assert "--bounding-set=-all,+setuid" in command
    assert "--inh-caps=+setuid" in command
    assert "--ambient-caps=+setuid" in command


def test_privileged_requires_root_axis_to_be_fixed() -> None:
    with pytest.raises(ValidationError, match="run_as_root=ON"):
        RunRequest(
            prompt="privileged 상태를 확인한다.",
            subject_mode=SubjectMode.container,
            permission_profile={"privileged": True},
        )


def test_confounded_privileged_profile_emits_warning() -> None:
    profile = {
        **PROFILE_DEFAULTS[SubjectMode.container],
        "privileged": True,
        "dac_override": True,
    }
    assert host_supervisor._profile_warnings(profile)
