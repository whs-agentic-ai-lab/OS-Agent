"""OS-tool 5.3 실행·특권 전환 등록과 Tool Verifier 연결 테스트."""
from __future__ import annotations

import os
import socket
import sys
import threading

import pytest

if sys.platform != "linux":
    pytest.skip("runtime_agent.tools 계약 테스트는 Linux syscall 환경에서만 실행합니다.", allow_module_level=True)

from runtime_agent.tools import (
    ToolContext,
    execute_tool_action,
    get_definition,
    known_definitions,
)
from runtime_agent.tools.exec_privilege import _supervisor_exchange


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


def test_chroot_policy_block_has_safe_verifier_and_resetter(tmp_path) -> None:
    target = tmp_path / "not-a-directory"
    target.write_text("fixture", encoding="utf-8")
    context = ToolContext(
        run_id="test-run", action_id="chroot-policy", executor_mode="host",
        trust_boundary_id="TB-HH-U1U2", source="u1", target="u2",
        allowed_targets=frozenset({"target"}), resource_paths={"target": str(target)},
        destructive_enabled=True, evidence_writer=_evidence_writer,
    )

    execution = execute_tool_action(
        "chroot.run", "create", {"resource_ref": "target"}, context,
    )

    assert execution.result.outcome == "POLICY_BLOCKED"
    assert execution.verification.status == "VERIFIED_NO_CHANGE"
    assert execution.reset.status == "NOT_REQUIRED"
    assert context.run_guard is not None
    assert context.run_guard.aborted is False


def test_supervisor_exchange_uses_bounded_http_response(tmp_path) -> None:
    socket_path = tmp_path / "supervisor.sock"
    ready = threading.Event()

    def serve() -> None:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(socket_path))
        server.listen(1)
        ready.set()
        connection, _ = server.accept()
        try:
            request = connection.recv(4096)
            assert request.startswith(b"POST /v2/runs HTTP/1.1\r\n")
            body = b'{"detail":"fixture"}'
            connection.sendall(
                b"HTTP/1.1 422 Unprocessable Entity\r\n"
                b"Date: ignored-by-verifier\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode()
                + body
            )
        finally:
            connection.close()
            server.close()

    worker = threading.Thread(target=serve)
    worker.start()
    assert ready.wait(timeout=2)
    observed = _supervisor_exchange(
        str(socket_path),
        b"POST /v2/runs HTTP/1.1\r\nHost: host-supervisor\r\n"
        b"Content-Type: application/json\r\nContent-Length: 2\r\n"
        b"Connection: close\r\n\r\n{}",
    )
    worker.join(timeout=2)
    assert observed["status"] == 422
    assert observed["reply_size"] > 0
    assert len(observed["reply_sha256"]) == 64
