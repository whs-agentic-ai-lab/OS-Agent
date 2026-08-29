"""OStool 5.5 프로세스·IPC Tool 단위 테스트.

계약만 검증한다(3.1/7절). 부작용이 있는 Action은 self/자식 대상 또는 즉시 원복하는
probe로만 실행한다. 권한 의존 Action은 "구조화된 outcome이 오는지"만 본다.
"""
from __future__ import annotations

import os
import sys
from types import SimpleNamespace

import pytest

if sys.platform != "linux":
    pytest.skip("runtime_agent.tools 계약 테스트는 Linux syscall 환경에서만 실행합니다.", allow_module_level=True)

from runtime_agent.tools import ToolContext, dispatch, get_definition, known_tools, verify


@pytest.fixture
def context(tmp_path):
    acct = tmp_path / "acct"
    acct.write_bytes(b"")
    return ToolContext(
        run_id="test-run",
        action_id="test-action",
        executor_mode="host",
        trust_boundary_id="TB-HH-U1U2",
        source="u1",
        target="u1",
        allowed_targets=frozenset({"acct-file", "sock-a"}),
        resource_paths={"acct-file": str(acct)},
    )


STRUCTURED = {"ALLOWED", "OS_DENIED", "ERROR"}


def test_all_5_5_tools_registered():
    tools = known_tools()
    expected = {
        "process.spawn": {"spawn"},
        "process.signal": {"send_pid", "send_group", "send_session"},
        "process.ptrace": {"attach", "read", "write", "trace_syscalls", "detach"},
        "process.memory": {"read", "write"},
        "process.procfs": {
            "read_environ", "read_cmdline", "read_maps", "read_mem",
            "list_fd", "read_root", "read_cwd",
        },
        "process.security_state": {"set_dumpable", "set_ptracer", "set_name", "set_core_limit"},
        "process.pidfd": {"open", "signal", "wait", "getfd"},
        "process.schedule": {"set_nice", "set_priority", "set_scheduler", "set_affinity"},
        "memory.lock": {"mlock", "mlockall", "hugepage"},
        "unix_socket.manage": {"listen", "connect", "send", "receive", "peer"},
        "unix_socket.fd_transfer": {"send_fd", "receive_fd", "send_credential", "receive_credential"},
        "ipc.sysv": {"create", "access", "remove"},
        "ipc.posix": {"create", "access", "remove"},
        "process.accounting": {"status", "start", "stop"},
    }
    for tool_id, actions in expected.items():
        assert tool_id in tools, f"{tool_id} 미등록"
        assert set(tools[tool_id]) == actions, f"{tool_id} action 불일치"
    assert len(expected) == 14
    assert sum(map(len, expected.values())) == 51


@pytest.mark.skipif(not os.path.isdir("/proc/self"), reason="Linux procfs가 필요한 테스트")
@pytest.mark.parametrize(
    "action",
    ["read_environ", "read_cmdline", "read_maps", "read_mem", "list_fd", "read_root", "read_cwd"],
)
def test_procfs_self_actions_are_registered_and_verified(context, action):
    outcome = dispatch("process.procfs", action, {}, context)
    assert outcome.attempted is True
    assert outcome.outcome in {"ALLOWED", "OS_DENIED", "ERROR"}
    if outcome.outcome in {"ALLOWED", "OS_DENIED"}:
        assert verify("process.procfs", action, outcome) is True


def test_spawn_allowed(context):
    outcome = dispatch("process.spawn", "spawn", {}, context)
    assert outcome.attempted is True
    assert outcome.outcome == "ALLOWED"
    assert "spawned" in outcome.output


def test_signal_zero_to_self_allowed(context):
    outcome = dispatch("process.signal", "send_pid", {"pid": os.getpid(), "signal": 0}, context)
    assert outcome.attempted is True
    assert outcome.outcome == "ALLOWED"


def test_signal_unregistered_pid_blocked(tmp_path):
    ctx = ToolContext(
        run_id="r", action_id="a", executor_mode="host", trust_boundary_id="TB",
        source="u1", target="u1", allowed_targets=frozenset({"pid:9999"}),
    )
    outcome = dispatch("process.signal", "send_pid", {"pid": 1, "signal": 0}, ctx)
    assert outcome.outcome == "POLICY_BLOCKED"
    assert outcome.attempted is False


def test_signal_out_of_range_blocked(context):
    outcome = dispatch("process.signal", "send_pid", {"pid": os.getpid(), "signal": 999}, context)
    assert outcome.outcome == "POLICY_BLOCKED"


def test_raw_arg_blocked(context):
    outcome = dispatch("process.signal", "send_pid", {"pid": 1, "command": "rm"}, context)
    assert outcome.outcome == "POLICY_BLOCKED"


def test_set_dumpable_probe_rolls_back(context):
    outcome = dispatch("process.security_state", "set_dumpable", {"value": "0"}, context)
    assert outcome.attempted is True
    if outcome.outcome == "ALLOWED":
        assert outcome.rollback_status == "VERIFIED"


def test_set_name_probe_rolls_back(context):
    outcome = dispatch("process.security_state", "set_name", {"name": "osprobe"}, context)
    assert outcome.attempted is True
    if outcome.outcome == "ALLOWED":
        assert outcome.rollback_status == "VERIFIED"


def test_set_affinity_probe_rolls_back(context):
    before = os.sched_getaffinity(0)
    outcome = dispatch("process.schedule", "set_affinity", {"cpus": [0]}, context)
    assert outcome.attempted is True
    if outcome.outcome == "ALLOWED":
        assert outcome.rollback_status == "VERIFIED"
        assert os.sched_getaffinity(0) == before
        # 상태 스냅샷이 실제로 도달 상태를 담아야 한다(evidence fidelity).
        assert outcome.state_reached.get("affinity") == [0]
        if before != {0}:
            assert outcome.temporary_changed is True
            assert outcome.escalation_possible is True


def test_set_nice_probe(context):
    # setpriority는 비특권 프로세스가 값을 올릴 수는 있어도 되돌리는 건 EPERM으로 실패한다
    # (POSIX). 그래서 이 tool은 자식 프로세스에서만 시도하고 버리는 _in_child_probe 방식으로
    # 구현되어 있다 — 부모(에이전트) 상태가 애초에 안 바뀌므로 rollback이 NOT_REQUIRED다.
    outcome = dispatch("process.schedule", "set_nice", {"nice": 5}, context)
    assert outcome.attempted is True
    assert outcome.outcome in STRUCTURED
    if outcome.outcome == "ALLOWED":
        assert outcome.rollback_status == "NOT_REQUIRED"
        # 부모 프로세스의 실제 nice 값은 자식 시도와 무관하게 그대로여야 한다.
        assert os.getpriority(os.PRIO_PROCESS, 0) == 0


def test_set_priority_probe(context):
    outcome = dispatch("process.schedule", "set_priority", {"priority": 3}, context)
    assert outcome.attempted is True
    assert outcome.outcome in STRUCTURED
    if outcome.outcome == "ALLOWED":
        assert outcome.rollback_status == "NOT_REQUIRED"
        assert os.getpriority(os.PRIO_PROCESS, 0) == 0


def test_mlock_probe(context):
    outcome = dispatch("memory.lock", "mlock", {"size": 4096}, context)
    assert outcome.attempted is True
    assert outcome.outcome in STRUCTURED


def test_unix_socket_listen_allowed(context):
    outcome = dispatch("unix_socket.manage", "listen", {"resource_ref": "sock-a"}, context)
    assert outcome.attempted is True
    assert outcome.outcome in STRUCTURED


def test_unix_fd_transfer_roundtrip(context):
    fd = os.open("/dev/null", os.O_RDONLY)
    try:
        outcome = dispatch("unix_socket.fd_transfer", "receive_fd", {"fd": fd}, context)
        assert outcome.outcome == "ALLOWED"
    finally:
        os.close(fd)


def test_ipc_sysv_create_structured(context):
    outcome = dispatch("ipc.sysv", "create", {"kind": "shm"}, context)
    assert outcome.attempted is True
    assert outcome.outcome in STRUCTURED


def test_ipc_posix_shm_structured(context):
    outcome = dispatch("ipc.posix", "create", {"kind": "shm"}, context)
    assert outcome.attempted is True
    assert outcome.outcome in STRUCTURED


def test_ptrace_attach_self_child_structured(context):
    # 자식을 만들어 attach 시도. yama ptrace_scope에 따라 OS_DENIED일 수 있다.
    pid = os.fork()
    if pid == 0:
        import time
        time.sleep(2)
        os._exit(0)
    try:
        outcome = dispatch("process.ptrace", "attach", {"pid": pid}, context)
        assert outcome.attempted is True
        assert outcome.outcome in STRUCTURED
    finally:
        try:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
        except OSError:
            pass


def test_ptrace_read_resetter_reports_verified_detach(monkeypatch):
    from runtime_agent.tools import process_ipc

    monkeypatch.setattr(process_ipc, "_ptrace", lambda *args: 0)
    monkeypatch.setattr(
        process_ipc,
        "_proc_observation",
        lambda pid: {"pid": pid, "exists": True, "TracerPid": "0"},
    )
    definition = get_definition("process.ptrace", "read")
    state = {"pid": 1234, "attached": True}

    reset_result = definition.resetter(
        state, None, SimpleNamespace(outcome="ALLOWED"), None,
    )

    assert reset_result.status == "VERIFIED"
    assert reset_result.checks == {"detached": True}


def test_pidfd_open_self_structured(context):
    outcome = dispatch("process.pidfd", "open", {"pid": os.getpid()}, context)
    assert outcome.attempted is True
    assert outcome.outcome in STRUCTURED


def test_accounting_status_structured(context):
    outcome = dispatch("process.accounting", "status", {}, context)
    assert outcome.attempted is True
    assert outcome.outcome in STRUCTURED


def test_common_return_fields_present(context):
    d = dispatch("process.spawn", "spawn", {}, context).to_dict()
    for key in ("identity_before", "identity_reached", "identity_after", "rollback_status", "evidence_refs"):
        assert key in d
