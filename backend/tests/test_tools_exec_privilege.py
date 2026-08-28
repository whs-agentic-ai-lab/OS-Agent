"""OS-tool 5.3 실행·특권 전환 등록과 Tool Verifier 연결 테스트."""
from __future__ import annotations

import os

import pytest

from runtime_agent.tools import ToolContext, dispatch, known_tools, verify
from runtime_agent.tools import base


EXPECTED = {
    "exec.run": {"binary", "script", "interpreter", "path_lookup"},
    "exec.with_environment": {"run"},
    "exec.privilege_transition": {"suid_exec", "sgid_exec", "filecap_exec"},
    "filecap.manage": {"get", "set_probe", "remove_probe"},
    "sudo.run": {"list", "run_probe"},
    "polkit.invoke": {"check", "invoke"},
    "dbus.call": {"call"},
    "supervisor.request": {"request"},
    "toolchain.build": {"compile", "interpret"},
    "chroot.run": {"create", "run"},
}


@pytest.fixture
def context(tmp_path):
    executable = "/usr/bin/true" if os.path.isfile("/usr/bin/true") else "/bin/true"
    return ToolContext(
        run_id="test-run", action_id="test-action", executor_mode="host",
        trust_boundary_id="TB-HH-U1U2", source="u1", target="u2",
        allowed_targets=frozenset({"executable", "workdir"}),
        resource_paths={"executable": executable, "workdir": str(tmp_path)},
    )


def test_all_execution_tools_actions_and_verifiers_are_registered():
    tools = known_tools()
    assert len(EXPECTED) == 10
    assert sum(map(len, EXPECTED.values())) == 21
    for tool_id, actions in EXPECTED.items():
        assert set(tools[tool_id]) == actions
        for action in actions:
            assert (tool_id, action) in base._VERIFIERS


def test_inline_filecap_probes_have_reset_callbacks():
    assert ("filecap.manage", "set_probe") in base._RESETS
    assert ("filecap.manage", "remove_probe") in base._RESETS


def test_registered_binary_executes_without_raw_command(context):
    outcome = dispatch("exec.run", "binary", {"resource_ref": "executable", "args": []}, context)
    assert outcome.outcome == "ALLOWED"
    assert outcome.attempted is True
    assert verify("exec.run", "binary", outcome) is True


def test_execution_rejects_raw_command(context):
    outcome = dispatch(
        "exec.run", "binary",
        {"resource_ref": "executable", "args": [], "command": "id"}, context,
    )
    assert outcome.outcome == "POLICY_BLOCKED"
    assert outcome.attempted is False
