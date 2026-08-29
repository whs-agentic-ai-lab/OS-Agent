"""OS-tool 5.3 실행·특권 전환 등록과 Tool Verifier 연결 테스트."""
from __future__ import annotations

import os
import sys

import pytest

if sys.platform != "linux":
    pytest.skip("runtime_agent.tools 계약 테스트는 Linux syscall 환경에서만 실행합니다.", allow_module_level=True)

from runtime_agent.tools import (
    ToolContext,
    execute_tool_action,
    get_definition,
    known_definitions,
)


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


def _evidence_writer(run_id: str, action_id: str, kind: str, payload: dict) -> str:
    del run_id, action_id, payload
    return f"evidence:{kind}"


@pytest.fixture
def context(tmp_path):
    executable = "/usr/bin/true" if os.path.isfile("/usr/bin/true") else "/bin/true"
    return ToolContext(
        run_id="test-run", action_id="test-action", executor_mode="host",
        trust_boundary_id="TB-HH-U1U2", source="u1", target="u2",
        allowed_targets=frozenset({"executable", "workdir"}),
        resource_paths={"executable": executable, "workdir": str(tmp_path)},
        evidence_writer=_evidence_writer,
    )


def test_all_execution_tools_actions_and_verifiers_are_registered():
    tools = known_definitions()
    assert len(EXPECTED) == 10
    assert sum(map(len, EXPECTED.values())) == 21
    for tool_id, actions in EXPECTED.items():
        assert set(tools[tool_id]) == actions
        for action in actions:
            definition = get_definition(tool_id, action)
            assert definition is not None
            assert callable(definition.handler)
            assert callable(definition.verifier)
            assert callable(definition.resetter)


def test_inline_filecap_probes_have_reset_callbacks():
    for action in {"set_probe", "remove_probe"}:
        definition = get_definition("filecap.manage", action)
        assert definition is not None
        assert definition.spec.reversible is True
        assert callable(definition.resetter)


def test_registered_binary_executes_without_raw_command(context):
    execution = execute_tool_action(
        "exec.run", "binary", {"resource_ref": "executable"}, context,
    )
    assert execution.result.outcome == "ALLOWED"
    assert execution.result.attempted is True
    assert execution.verification.status == "VERIFIED_NO_CHANGE"
    assert execution.reset.status == "NOT_REQUIRED"


def test_execution_rejects_raw_command(context):
    execution = execute_tool_action(
        "exec.run", "binary",
        {"resource_ref": "executable", "command": "id"}, context,
    )
    assert execution.result.outcome == "POLICY_BLOCKED"
    assert execution.result.attempted is False
