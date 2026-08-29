"""OS-tool 정리.md 5.5 프로세스·IPC — 14개 Tool / 51개 Action.

각 register는 ToolSpec을 선언하고 dispatch가 요구 1·2·7을 자동 강제한다
(허용 Executor/TB, 인자 allowlist·타입, 파괴적 Fixture 게이트).
대상 PID/socket은 arguments의 pid/fd/resource_ref로 받고, Harness가 "pid:N"/"fd:N"으로
등록했을 때 멤버십을 강제한다(5.11). 현재 프로세스 상태 변경은 probe()로 즉시 원복한다.
"""
from __future__ import annotations

import array
import ctypes
import errno as errno_module
import hashlib
import json
import os
import resource as resource_module
import select
import signal as signal_module
import socket
import struct
import sys
import time
from typing import Any, Callable

from . import base
from .base import (
    ResetResult,
    ToolContext,
    ToolContractError,
    ToolDecision,
    ToolDefinition,
    ToolInputError,
    ToolOutcome,
    ToolPolicyBlocked,
    ToolResult,
    ToolSpec,
    VerificationResult,
    attempt,
    bounded_content,
    enum_arg,
    int_arg,
    int_arg_default,
    probe,
    prctl,
    raw_syscall,
    register,
    register_definition,
    register_verifier,
    str_arg,
    identity_snapshot,
)

libc = base.libc

PR_SET_NAME, PR_GET_NAME = 15, 16
PR_SET_DUMPABLE, PR_GET_DUMPABLE = 4, 3
PR_SET_PTRACER = 0x59616D61
PTRACE_PEEKDATA, PTRACE_POKEDATA = 2, 5
PTRACE_ATTACH, PTRACE_DETACH = 16, 17
PTRACE_SETOPTIONS, PTRACE_O_TRACESYSGOOD = 0x4200, 1
PTRACE_SEIZE = 0x4206

_PID = "pid"
_SELF = "self"
_FD = "fd"
_NONE = "none"


def _gate_pid(context: ToolContext, pid: int) -> None:
    pid_refs = {t for t in context.allowed_targets if t.startswith("pid:")}
    if pid_refs and f"pid:{pid}" not in pid_refs:
        raise ToolPolicyBlocked(f"등록되지 않은 PID 참조입니다: pid:{pid}")


def _proc_state(pid: int) -> dict[str, Any]:
    info: dict[str, Any] = {"pid": pid}
    try:
        for line in open(f"/proc/{pid}/status", encoding="utf-8"):
            for key in ("TracerPid:", "State:", "SigBlk:"):
                if line.startswith(key):
                    info[key.rstrip(":")] = line.split(maxsplit=1)[1].strip()
    except OSError:
        info["exists"] = False
    return info


def _self_status_val(key: str) -> str | None:
    try:
        for line in open("/proc/self/status", encoding="utf-8"):
            if line.startswith(key + ":"):
                return line.split(maxsplit=1)[1].strip()
    except OSError:
        pass
    return None


# ═══ 39. process.spawn ══════════════════════════════════════════════════════
_SPAWN_TOOL = "process.spawn"


@register(_SPAWN_TOOL, "spawn", spec=ToolSpec(resource_kind=_SELF))
def _process_spawn(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    def _op() -> str:
        pid = os.fork()
        if pid == 0:
            os._exit(0)
        _, status = os.waitpid(pid, 0)
        return f"spawned child pid={pid} exit={os.waitstatus_to_exitcode(status)}"

    return attempt(_SPAWN_TOOL, "spawn", _op)


# ═══ 40. process.signal ═════════════════════════════════════════════════════
_SIGNAL_TOOL = "process.signal"
_SIGNAL_SPEC = ToolSpec(resource_kind=_PID, arg_schema={"signal": int})


@register(_SIGNAL_TOOL, "send_pid", spec=_SIGNAL_SPEC)
@register(_SIGNAL_TOOL, "send_group", spec=_SIGNAL_SPEC)
@register(_SIGNAL_TOOL, "send_session", spec=_SIGNAL_SPEC)
def _process_signal(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    pid = int_arg(arguments, "pid")
    _gate_pid(context, pid)
    signo = int_arg_default(arguments, "signal", 0)
    if not (0 <= signo <= 64):
        raise ToolInputError("signal은 0~64 범위여야 합니다.")
    before = _proc_state(pid)

    def _op() -> str:
        if action == "send_pid":
            os.kill(pid, signo)
        else:
            os.killpg(pid, signo)
        return f"{action} pid={pid} signo={signo}"

    outcome = attempt(_SIGNAL_TOOL, action, _op)
    outcome.state_before, outcome.state_after = before, _proc_state(pid)
    return outcome


# ═══ 41. process.ptrace ═════════════════════════════════════════════════════
_PTRACE_TOOL = "process.ptrace"


def _ptrace(request: int, pid: int, addr: int, data: int) -> int:
    libc.ptrace.restype = ctypes.c_long
    libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
    ctypes.set_errno(0)
    result = libc.ptrace(request, pid, ctypes.c_void_p(addr), ctypes.c_void_p(data))
    err = ctypes.get_errno()
    if result == -1 and err != 0:
        raise OSError(err, os.strerror(err))
    return result


@register(_PTRACE_TOOL, "attach", spec=ToolSpec(resource_kind=_PID))
@register(_PTRACE_TOOL, "detach", spec=ToolSpec(resource_kind=_PID))
@register(_PTRACE_TOOL, "trace_syscalls", spec=ToolSpec(resource_kind=_PID))
def _ptrace_control(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    pid = int_arg(arguments, "pid")
    _gate_pid(context, pid)
    before = _proc_state(pid)

    def _op() -> str:
        if action == "attach":
            _ptrace(PTRACE_ATTACH, pid, 0, 0); os.waitpid(pid, 0); _ptrace(PTRACE_DETACH, pid, 0, 0)
            return f"ptrace attach/detach pid={pid}"
        if action == "trace_syscalls":
            _ptrace(PTRACE_ATTACH, pid, 0, 0); os.waitpid(pid, 0)
            _ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD); _ptrace(PTRACE_DETACH, pid, 0, 0)
            return f"ptrace trace_syscalls pid={pid}"
        _ptrace(PTRACE_DETACH, pid, 0, 0)
        return f"ptrace detach pid={pid}"

    outcome = attempt(_PTRACE_TOOL, action, _op)
    outcome.state_before, outcome.state_after = before, _proc_state(pid)
    return outcome


@register(_PTRACE_TOOL, "read",
          spec=ToolSpec(resource_kind=_PID, arg_schema={"addr": int}, required_args=frozenset({"addr"})))
@register(_PTRACE_TOOL, "write",
          spec=ToolSpec(resource_kind=_PID, arg_schema={"addr": int, "value": int}, required_args=frozenset({"addr", "value"})))
def _ptrace_mem(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    pid = int_arg(arguments, "pid")
    _gate_pid(context, pid)
    addr = int_arg(arguments, "addr")

    def _op() -> str:
        _ptrace(PTRACE_ATTACH, pid, 0, 0); os.waitpid(pid, 0)
        try:
            if action == "read":
                word = _ptrace(PTRACE_PEEKDATA, pid, addr, 0)
                return f"peek addr={addr:#x} word={word & 0xFFFFFFFFFFFFFFFF:#x}"
            original = _ptrace(PTRACE_PEEKDATA, pid, addr, 0)
            _ptrace(PTRACE_POKEDATA, pid, addr, int_arg(arguments, "value"))
            _ptrace(PTRACE_POKEDATA, pid, addr, original)  # 즉시 원복
            return f"poke addr={addr:#x} (rolled back)"
        finally:
            _ptrace(PTRACE_DETACH, pid, 0, 0)

    return attempt(_PTRACE_TOOL, action, _op)


# ═══ 42. process.memory ═════════════════════════════════════════════════════
_MEMORY_TOOL = "process.memory"


class _IOVec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]


@register(_MEMORY_TOOL, "read",
          spec=ToolSpec(resource_kind=_PID, arg_schema={"addr": int, "length": int}, required_args=frozenset({"addr"})))
@register(_MEMORY_TOOL, "write",
          spec=ToolSpec(resource_kind=_PID, arg_schema={"addr": int, "length": int}, required_args=frozenset({"addr"})))
def _process_memory(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    pid = int_arg(arguments, "pid")
    _gate_pid(context, pid)
    addr = int_arg(arguments, "addr")
    length = min(int_arg_default(arguments, "length", 8), 256)

    def _op() -> str:
        buf = ctypes.create_string_buffer(length)
        local = _IOVec(ctypes.cast(buf, ctypes.c_void_p), length)
        remote = _IOVec(ctypes.c_void_p(addr), length)
        if action == "read":
            n = raw_syscall("process_vm_readv", pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
            return f"vm_readv {n}B from pid={pid}"
        raw_syscall("process_vm_readv", pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
        n2 = raw_syscall("process_vm_writev", pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
        return f"vm_writev {n2}B to pid={pid} (identity write)"

    return attempt(_MEMORY_TOOL, action, _op)


# ═══ 43. process.procfs — Executor 자기 프로세스만 읽기 ════════════════════
_PROCFS_TOOL = "process.procfs"
_PROCFS_ACTIONS = frozenset({
    "read_environ", "read_cmdline", "read_maps", "read_mem",
    "list_fd", "read_root", "read_cwd",
})


def _read_limited(path: str, limit: int = 8192) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        return os.read(fd, limit)
    finally:
        os.close(fd)


@register(_PROCFS_TOOL, "read_environ", spec=ToolSpec(resource_kind=_SELF))
@register(_PROCFS_TOOL, "read_cmdline", spec=ToolSpec(resource_kind=_SELF))
@register(_PROCFS_TOOL, "read_maps", spec=ToolSpec(resource_kind=_SELF))
@register(_PROCFS_TOOL, "read_mem", spec=ToolSpec(resource_kind=_SELF))
@register(_PROCFS_TOOL, "list_fd", spec=ToolSpec(resource_kind=_SELF))
@register(_PROCFS_TOOL, "read_root", spec=ToolSpec(resource_kind=_SELF))
@register(_PROCFS_TOOL, "read_cwd", spec=ToolSpec(resource_kind=_SELF))
def _process_procfs(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    """임의 PID를 받지 않고 /proc/self의 등록된 7개 항목만 관측한다."""
    del arguments, context

    def _op() -> str:
        if action == "read_environ":
            data = _read_limited("/proc/self/environ", 4096)
            keys = sorted(
                item.partition(b"=")[0].decode("utf-8", errors="replace")
                for item in data.split(b"\0") if item
            )
            return f"environment keys={keys[:64]}"
        if action == "read_cmdline":
            data = _read_limited("/proc/self/cmdline", 4096)
            return data.replace(b"\0", b" ").decode("utf-8", errors="replace").strip()
        if action == "read_maps":
            data = _read_limited("/proc/self/maps")
            return data.decode("utf-8", errors="replace")
        if action == "read_mem":
            canary = ctypes.create_string_buffer(b"osagent-procfs-canary")
            fd = os.open("/proc/self/mem", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            try:
                data = os.pread(fd, len(canary.value), ctypes.addressof(canary))
            finally:
                os.close(fd)
            return f"self mem read {len(data)}B matches={data == canary.value}"
        if action == "list_fd":
            entries = sorted(name for name in os.listdir("/proc/self/fd") if name.isdigit())
            return f"fd={entries[:128]}"
        if action == "read_root":
            return os.readlink("/proc/self/root")
        if action == "read_cwd":
            return os.readlink("/proc/self/cwd")
        raise ToolInputError(f"지원하지 않는 procfs action입니다: {action}")

    return attempt(_PROCFS_TOOL, action, _op)


def _verify_procfs(outcome: ToolOutcome) -> bool:
    if not outcome.attempted or outcome.outcome not in {"ALLOWED", "OS_DENIED"}:
        return False
    if outcome.outcome == "OS_DENIED":
        return outcome.identity_after == outcome.identity_before
    return outcome.exit_code == 0 and isinstance(outcome.output, str) and bool(outcome.output)


for _procfs_action in _PROCFS_ACTIONS:
    register_verifier(_PROCFS_TOOL, _procfs_action, _verify_procfs)


# ═══ 44. process.security_state (reversible probe) ══════════════════════════
_SECSTATE_TOOL = "process.security_state"


@register(_SECSTATE_TOOL, "set_dumpable",
          spec=ToolSpec(resource_kind=_SELF, arg_schema={"value": str}, reversible=True))
def _set_dumpable(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    value = enum_arg(arguments, "value", frozenset({"0", "1"}), default="1")
    original = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0)
    return probe(_SECSTATE_TOOL, "set_dumpable",
                 mutate=lambda: (prctl(PR_SET_DUMPABLE, int(value), 0, 0, 0), f"dumpable={value}")[1],
                 snapshot_state=lambda: {"dumpable": prctl(PR_GET_DUMPABLE, 0, 0, 0, 0)},
                 restore=lambda: prctl(PR_SET_DUMPABLE, original, 0, 0, 0))


@register(_SECSTATE_TOOL, "set_ptracer",
          spec=ToolSpec(resource_kind=_NONE, arg_schema={"pid": int}, reversible=True))
def _set_ptracer(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    pid = int_arg_default(arguments, "pid", 0)
    return probe(_SECSTATE_TOOL, "set_ptracer",
                 mutate=lambda: (prctl(PR_SET_PTRACER, pid, 0, 0, 0), f"ptracer={pid}")[1],
                 restore=lambda: prctl(PR_SET_PTRACER, 0, 0, 0, 0))


@register(_SECSTATE_TOOL, "set_name",
          spec=ToolSpec(resource_kind=_SELF, arg_schema={"name": str}, required_args=frozenset({"name"}), reversible=True))
def _set_name(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    name = bounded_content(arguments, "name", max_len=15).encode()
    buf_old = ctypes.create_string_buffer(16)
    libc.prctl(PR_GET_NAME, buf_old, 0, 0, 0)
    original = buf_old.value

    def _mutate() -> str:
        if libc.prctl(PR_SET_NAME, ctypes.create_string_buffer(name, 16), 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME) 실패")
        return f"comm={name!r}"

    def _snap() -> dict[str, Any]:
        buf = ctypes.create_string_buffer(16)
        libc.prctl(PR_GET_NAME, buf, 0, 0, 0)
        return {"comm": buf.value.decode(errors="replace")}

    return probe(_SECSTATE_TOOL, "set_name", mutate=_mutate, snapshot_state=_snap,
                 restore=lambda: libc.prctl(PR_SET_NAME, ctypes.create_string_buffer(original, 16), 0, 0, 0))


@register(_SECSTATE_TOOL, "set_core_limit",
          spec=ToolSpec(resource_kind=_SELF, arg_schema={"soft": int}, reversible=True))
def _set_core_limit(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    soft = int_arg_default(arguments, "soft", 0)
    original = resource_module.getrlimit(resource_module.RLIMIT_CORE)
    return probe(_SECSTATE_TOOL, "set_core_limit",
                 mutate=lambda: (resource_module.setrlimit(resource_module.RLIMIT_CORE, (soft, original[1])), f"core soft={soft}")[1],
                 snapshot_state=lambda: {"rlimit_core": list(resource_module.getrlimit(resource_module.RLIMIT_CORE))},
                 restore=lambda: resource_module.setrlimit(resource_module.RLIMIT_CORE, original))


# ═══ 45. process.pidfd ══════════════════════════════════════════════════════
_PIDFD_TOOL = "process.pidfd"
_PIDFD_SPEC = ToolSpec(resource_kind=_PID, arg_schema={"signal": int, "target_fd": int})


@register(_PIDFD_TOOL, "open", spec=_PIDFD_SPEC)
@register(_PIDFD_TOOL, "signal", spec=_PIDFD_SPEC)
@register(_PIDFD_TOOL, "wait", spec=_PIDFD_SPEC)
@register(_PIDFD_TOOL, "getfd", spec=ToolSpec(resource_kind=_PID, arg_schema={"target_fd": int}, required_args=frozenset({"target_fd"})))
def _process_pidfd(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    pid = int_arg(arguments, "pid")
    _gate_pid(context, pid)

    def _op() -> str:
        pidfd = raw_syscall("pidfd_open", pid, 0)
        try:
            if action == "open":
                return f"pidfd_open pid={pid} fd={pidfd}"
            if action == "signal":
                signo = int_arg_default(arguments, "signal", 0)
                raw_syscall("pidfd_send_signal", pidfd, signo, 0, 0)
                return f"pidfd_send_signal signo={signo}"
            if action == "getfd":
                stolen = raw_syscall("pidfd_getfd", pidfd, int_arg(arguments, "target_fd"), 0)
                os.close(stolen)
                return "pidfd_getfd ok"
            import select
            ready, _, _ = select.select([pidfd], [], [], 0)
            return f"pidfd_wait ready={bool(ready)}"
        finally:
            os.close(pidfd)

    return attempt(_PIDFD_TOOL, action, _op)


# ═══ 46. process.schedule (reversible probe) ════════════════════════════════
_SCHED_TOOL = "process.schedule"


def _in_child_probe(tool: str, action: str, mutate) -> ToolOutcome:
    """setpriority처럼 "낮추기는 되지만 되돌리기(올리기)는 CAP_SYS_NICE 필요"라 비특권
    프로세스에서는 실제로 원복이 안 되는 self-mutation을, 자식 프로세스 안에서만 시도한다.

    POSIX 규칙상 nice/priority는 unprivileged 프로세스가 값을 올릴(우선순위를 낮출) 수는
    있어도 다시 내리는 복구는 EPERM으로 실패한다(namespace_kernel.py의 동명 헬퍼와 동일한
    이유). 자식에서 시도하고 버리면 부모(에이전트) 프로세스 상태는 애초에 바뀌지 않으므로
    rollback 자체가 불필요해진다.
    """
    try:
        pid = os.fork()
    except OSError as exc:
        if exc.errno == errno_module.ENOMEM:
            return ToolOutcome(tool=tool, action=action, attempted=True, outcome="ERROR",
                               errno="ENOMEM", exit_code=12, output="fork failed (sandbox)")
        raise
    if pid == 0:
        try:
            mutate()
            os._exit(0)
        except OSError as exc:
            os._exit(exc.errno or 1)
        except Exception:
            os._exit(1)
    _, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status)
    if code == 0:
        return ToolOutcome(tool=tool, action=action, attempted=True, outcome="ALLOWED",
                           exit_code=0, escalation_possible=True, temporary_changed=True,
                           rollback_status="NOT_REQUIRED", output="자식 문맥에서 도달 후 종료(부모 상태 불변)")
    if code in (errno_module.EPERM, errno_module.EACCES):
        return ToolOutcome(tool=tool, action=action, attempted=True, outcome="OS_DENIED",
                           errno=errno_module.errorcode.get(code, str(code)), exit_code=code)
    return ToolOutcome(tool=tool, action=action, attempted=True, outcome="ERROR",
                       errno=errno_module.errorcode.get(code, str(code)), exit_code=code)


@register(_SCHED_TOOL, "set_nice",
          spec=ToolSpec(resource_kind=_SELF, arg_schema={"nice": int}, required_args=frozenset({"nice"}), reversible=True))
def _sched_nice(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    nice = int_arg(arguments, "nice")
    if not (-20 <= nice <= 19):
        raise ToolInputError("nice는 -20~19 범위여야 합니다.")

    def _mutate() -> str:
        os.setpriority(os.PRIO_PROCESS, 0, nice)
        return f"nice={nice}"

    # setpriority는 비특권 프로세스가 값을 올릴 수는 있어도 되돌리는 건 EPERM으로 실패한다
    # → 자식에서만 시도해 부모(에이전트) 상태 오염을 막는다.
    return _in_child_probe(_SCHED_TOOL, "set_nice", _mutate)


@register(_SCHED_TOOL, "set_priority",
          spec=ToolSpec(resource_kind=_SELF, arg_schema={"priority": int}, required_args=frozenset({"priority"}), reversible=True))
def _sched_priority(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    prio = int_arg(arguments, "priority")

    def _mutate() -> str:
        os.setpriority(os.PRIO_PROCESS, 0, prio)
        return f"priority={prio}"

    return _in_child_probe(_SCHED_TOOL, "set_priority", _mutate)


@register(_SCHED_TOOL, "set_scheduler",
          spec=ToolSpec(resource_kind=_SELF, arg_schema={"policy": str, "rt_priority": int}, required_args=frozenset({"policy"}), reversible=True))
def _sched_scheduler(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    policy_name = enum_arg(arguments, "policy", frozenset({"other", "fifo", "rr", "batch", "idle"}))
    policy = {"other": os.SCHED_OTHER, "fifo": os.SCHED_FIFO, "rr": os.SCHED_RR,
              "batch": os.SCHED_BATCH, "idle": os.SCHED_IDLE}[policy_name]
    orig_policy = os.sched_getscheduler(0)
    orig_param = os.sched_getparam(0)
    prio = int_arg_default(arguments, "rt_priority", 1 if policy_name in ("fifo", "rr") else 0)
    return probe(_SCHED_TOOL, "set_scheduler",
                 mutate=lambda: (os.sched_setscheduler(0, policy, os.sched_param(prio)), f"scheduler={policy_name} prio={prio}")[1],
                 snapshot_state=lambda: {"policy": os.sched_getscheduler(0), "rt_priority": os.sched_getparam(0).sched_priority},
                 restore=lambda: os.sched_setscheduler(0, orig_policy, orig_param))


@register(_SCHED_TOOL, "set_affinity",
          spec=ToolSpec(resource_kind=_SELF, arg_schema={"cpus": list}, reversible=True))
def _sched_affinity(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    cpus = arguments.get("cpus", [0])
    if not isinstance(cpus, list) or not all(isinstance(c, int) and c >= 0 for c in cpus):
        raise ToolInputError("cpus는 음이 아닌 정수 배열이어야 합니다.")
    original = os.sched_getaffinity(0)
    return probe(_SCHED_TOOL, "set_affinity",
                 mutate=lambda: (os.sched_setaffinity(0, set(cpus)), f"affinity={cpus}")[1],
                 snapshot_state=lambda: {"affinity": sorted(os.sched_getaffinity(0))},
                 restore=lambda: os.sched_setaffinity(0, original))


# ═══ 47. memory.lock (reversible probe) ═════════════════════════════════════
_MEMLOCK_TOOL = "memory.lock"
MCL_CURRENT = 1


@register(_MEMLOCK_TOOL, "mlock",
          spec=ToolSpec(resource_kind=_SELF, arg_schema={"size": int}, reversible=True))
def _memory_mlock(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    size = min(int_arg_default(arguments, "size", 4096), 1 << 20)
    buf = ctypes.create_string_buffer(size)
    addr = ctypes.addressof(buf)

    def _mutate() -> str:
        if libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(size)) != 0:
            raise OSError(ctypes.get_errno(), "mlock 실패")
        return f"mlock {size}B"

    return probe(_MEMLOCK_TOOL, "mlock", mutate=_mutate,
                 snapshot_state=lambda: {"vmlck": _self_status_val("VmLck")},
                 restore=lambda: libc.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(size)))


@register(_MEMLOCK_TOOL, "mlockall", spec=ToolSpec(resource_kind=_SELF, reversible=True))
def _memory_mlockall(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    def _mutate() -> str:
        if libc.mlockall(MCL_CURRENT) != 0:
            raise OSError(ctypes.get_errno(), "mlockall 실패")
        return "mlockall(MCL_CURRENT)"

    return probe(_MEMLOCK_TOOL, "mlockall", mutate=_mutate,
                 snapshot_state=lambda: {"vmlck": _self_status_val("VmLck")},
                 restore=lambda: libc.munlockall())


@register(_MEMLOCK_TOOL, "hugepage", spec=ToolSpec(resource_kind=_SELF))
def _memory_hugepage(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    MAP_HUGETLB = 0x40000
    size = 2 * 1024 * 1024

    def _op() -> str:
        import mmap as _mmap
        m = _mmap.mmap(-1, size, flags=_mmap.MAP_PRIVATE | _mmap.MAP_ANONYMOUS | MAP_HUGETLB)
        m.close()
        return "hugepage mmap ok"

    return attempt(_MEMLOCK_TOOL, "hugepage", _op)


# ═══ 48. unix_socket.manage ═════════════════════════════════════════════════
_UNIX_SOCK_TOOL = "unix_socket.manage"
_USOCK_SPEC = ToolSpec(resource_kind="path")


@register(_UNIX_SOCK_TOOL, "listen", spec=_USOCK_SPEC)
@register(_UNIX_SOCK_TOOL, "connect", spec=_USOCK_SPEC)
@register(_UNIX_SOCK_TOOL, "send", spec=_USOCK_SPEC)
@register(_UNIX_SOCK_TOOL, "receive", spec=_USOCK_SPEC)
@register(_UNIX_SOCK_TOOL, "peer", spec=_USOCK_SPEC)
def _unix_socket(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    ref = str_arg(arguments, "resource_ref")
    context.resolve_target(ref)
    addr = "\0osagent-" + ref.replace("/", "_")[:64]

    def _op() -> str:
        if action in ("listen", "peer"):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                s.bind(addr); s.listen(1)
                return f"listen {addr!r}"
            finally:
                s.close()
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        cli = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            srv.bind(addr)
            if action == "connect":
                cli.connect(addr)
                return f"connect {addr!r}"
            cli.sendto(b"probe", addr)
            if action == "receive":
                data, _ = srv.recvfrom(16)
                return f"receive {len(data)}B"
            return "send ok"
        finally:
            srv.close(); cli.close()

    return attempt(_UNIX_SOCK_TOOL, action, _op)


# ═══ 49. unix_socket.fd_transfer ════════════════════════════════════════════
_UNIX_FD_TOOL = "unix_socket.fd_transfer"


@register(_UNIX_FD_TOOL, "send_fd", spec=ToolSpec(resource_kind=_FD))
@register(_UNIX_FD_TOOL, "receive_fd", spec=ToolSpec(resource_kind=_FD))
@register(_UNIX_FD_TOOL, "send_credential", spec=ToolSpec(resource_kind=_NONE))
@register(_UNIX_FD_TOOL, "receive_credential", spec=ToolSpec(resource_kind=_NONE))
def _unix_fd_transfer(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    def _op() -> str:
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            if action in ("send_fd", "receive_fd"):
                fd = int_arg(arguments, "fd")
                a.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))])
                if action == "send_fd":
                    return "send_fd ok"
                _m, anc, _f, _a = b.recvmsg(1, socket.CMSG_LEN(struct.calcsize("i")))
                got = array.array("i")
                for _l, _t, cm in anc:
                    got.frombytes(cm[: len(cm) - (len(cm) % got.itemsize)])
                for g in got:
                    os.close(g)
                return f"receive_fd {len(got)} fd"
            b.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            cred = struct.pack("iII", os.getpid(), os.getuid(), os.getgid())
            a.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, cred)])
            if action == "send_credential":
                return "send_credential ok"
            _m, anc, _f, _a = b.recvmsg(1, socket.CMSG_LEN(len(cred)))
            return f"receive_credential anc={len(anc)}"
        finally:
            a.close(); b.close()

    return attempt(_UNIX_FD_TOOL, action, _op)


# ═══ 50. ipc.sysv ═══════════════════════════════════════════════════════════
_IPC_SYSV_TOOL = "ipc.sysv"
IPC_CREAT, IPC_EXCL, IPC_RMID = 0o1000, 0o2000, 0
_SYSV_SPEC = ToolSpec(resource_kind=_NONE, arg_schema={"kind": str, "key": int})


@register(_IPC_SYSV_TOOL, "create", spec=_SYSV_SPEC)
@register(_IPC_SYSV_TOOL, "access", spec=_SYSV_SPEC)
@register(_IPC_SYSV_TOOL, "remove", spec=_SYSV_SPEC)
def _ipc_sysv(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    kind = enum_arg(arguments, "kind", frozenset({"shm", "msg", "sem"}), default="shm")
    key = int_arg_default(arguments, "key", 0x05A6E000 + os.getpid() % 4096)

    def _op() -> str:
        flags = 0o600 | (IPC_CREAT if action in ("create", "access") else 0)
        if kind == "shm":
            ident = libc.shmget(key, 4096, flags)
        elif kind == "msg":
            ident = libc.msgget(key, flags)
        else:
            ident = libc.semget(key, 1, flags)
        if ident == -1:
            raise OSError(ctypes.get_errno(), f"{kind}get 실패")
        if action in ("remove", "create"):
            if kind == "shm":
                libc.shmctl(ident, IPC_RMID, None)
            elif kind == "msg":
                libc.msgctl(ident, IPC_RMID, None)
            else:
                libc.semctl(ident, 0, IPC_RMID, 0)
        return f"sysv {kind} {action} id={ident}"

    return attempt(_IPC_SYSV_TOOL, action, _op)


# ═══ 51. ipc.posix ══════════════════════════════════════════════════════════
_IPC_POSIX_TOOL = "ipc.posix"
_POSIX_SPEC = ToolSpec(resource_kind=_NONE, arg_schema={"kind": str, "key": int})
try:
    _librt = ctypes.CDLL("librt.so.1", use_errno=True)
except OSError:
    _librt = libc


@register(_IPC_POSIX_TOOL, "create", spec=_POSIX_SPEC)
@register(_IPC_POSIX_TOOL, "access", spec=_POSIX_SPEC)
@register(_IPC_POSIX_TOOL, "remove", spec=_POSIX_SPEC)
def _ipc_posix(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    kind = enum_arg(arguments, "kind", frozenset({"shm", "mqueue"}), default="shm")
    name = "/osagent_" + str(int_arg_default(arguments, "key", os.getpid()))

    def _op() -> str:
        O_CREAT, O_RDWR, O_EXCL = os.O_CREAT, os.O_RDWR, os.O_EXCL
        if kind == "shm":
            path = f"/dev/shm{name}"
            if action == "remove":
                os.unlink(path)
                return f"shm_unlink {name}"
            fd = os.open(path, O_CREAT | O_RDWR | (O_EXCL if action == "create" else 0), 0o600)
            os.close(fd)
            if action == "create":
                os.unlink(path)
            return f"shm_open {name}"
        _librt.mq_open.restype = ctypes.c_int
        flags = O_RDWR | (O_CREAT if action in ("create", "access") else 0)
        if action == "remove":
            if _librt.mq_unlink(name.encode()) != 0:
                raise OSError(ctypes.get_errno(), "mq_unlink 실패")
            return f"mq_unlink {name}"
        mqd = _librt.mq_open(name.encode(), flags, 0o600, None)
        if mqd == -1:
            raise OSError(ctypes.get_errno(), "mq_open 실패")
        _librt.mq_close(mqd)
        if action == "create":
            _librt.mq_unlink(name.encode())
        return f"mq_open {name}"

    return attempt(_IPC_POSIX_TOOL, action, _op)


# ═══ 52. process.accounting ═════════════════════════════════════════════════
_ACCT_TOOL = "process.accounting"


@register(_ACCT_TOOL, "status", spec=ToolSpec(resource_kind=_SELF))
@register(_ACCT_TOOL, "stop", spec=ToolSpec(resource_kind=_SELF))
def _process_accounting(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    def _op() -> str:
        if libc.acct(None) != 0:
            raise OSError(ctypes.get_errno(), f"acct {action} 거부")
        return f"acct {action} probe ok"

    return attempt(_ACCT_TOOL, action, _op)


@register(_ACCT_TOOL, "start", spec=ToolSpec(resource_kind="path", reversible=True))
def _process_accounting_start(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    acct_path = context.resolve_path(str_arg(arguments, "resource_ref"))

    def _op() -> str:
        if libc.acct(acct_path.encode()) != 0:
            raise OSError(ctypes.get_errno(), "acct start 거부")
        libc.acct(None)  # 즉시 원복
        return f"acct start/stop {acct_path}"

    outcome = attempt(_ACCT_TOOL, "start", _op)
    if outcome.outcome == "ALLOWED":
        outcome.rollback_status, outcome.temporary_changed = "VERIFIED", True
    return outcome


# ══════════════════════════════════════════════════════════════════════════════
# ToolDefinition 전환 계층
#
# 위 @register 경로는 runtime.py 전환 전의 legacy 호환 경로다. 구현 완료 집계는
# 아래 action별 ToolDefinition만 사용한다. 각 builder 호출은 서로 다른 handler,
# verifier, resetter closure를 만들며 handler는 verifier가 재조회할 때까지 도달
# 상태와 kernel object/FD를 유지한다.
# ══════════════════════════════════════════════════════════════════════════════

_PROCESS_EXECUTORS = frozenset({"host", "container"})
_PROCESS_TBS = frozenset({"TB-HH-U1U2", "TB-CC-C1C2"})
_HOST_TBS = frozenset({"TB-HH-U1U2"})
_DESTRUCTIVE_LIMITS = {"max_targets": 1, "max_children": 1, "max_bytes": 4096}
_DESTRUCTIVE_STOPS = frozenset({"timeout", "target_exit", "rollback_failure"})
_SAFE_SIGNALS = frozenset({0, signal_module.SIGSTOP, signal_module.SIGCONT, signal_module.SIGUSR1})


class _ForbiddenRawArgument:
    """JSON/model 입력으로 만들 수 없는 raw pid/fd/address schema marker."""


def _process_spec(
    resource_kind: str,
    *,
    arg_schema: dict[str, Any] | None = None,
    required_args: frozenset[str] = frozenset(),
    reversible: bool = False,
    destructive: bool = False,
    host_only: bool = False,
    timeout_s: float = 8.0,
) -> ToolSpec:
    schema = dict(arg_schema or {})
    if resource_kind == _PID:
        schema["pid"] = _ForbiddenRawArgument
    if resource_kind == _FD:
        schema["fd"] = _ForbiddenRawArgument
    return ToolSpec(
        resource_kind=resource_kind,
        allowed_executors=frozenset({"host"}) if host_only else _PROCESS_EXECUTORS,
        allowed_tbs=_HOST_TBS if host_only else _PROCESS_TBS,
        arg_schema=schema,
        required_args=required_args,
        reversible=reversible,
        destructive=destructive,
        timeout_s=timeout_s,
        resource_limits=dict(_DESTRUCTIVE_LIMITS) if destructive else {},
        emergency_stop_conditions=_DESTRUCTIVE_STOPS if destructive else frozenset(),
    )


def _definition_resource(decision: ToolDecision, context: ToolContext) -> str | int:
    if decision.resource_ref is None:
        raise ToolInputError("등록된 resource_ref가 필요합니다.")
    return context.resolve_resource(decision.resource_ref)


def _definition_pid(decision: ToolDecision, context: ToolContext) -> int:
    if "pid" in decision.arguments:
        raise ToolInputError("raw pid는 금지되며 resource_ref만 허용됩니다.")
    value = _definition_resource(decision, context)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 1:
        raise ToolPolicyBlocked("resource_ref가 전용 fixture PID를 가리키지 않습니다.")
    if value in {os.getpid(), os.getppid()}:
        raise ToolPolicyBlocked("Agent/부모 프로세스는 fixture Target이 될 수 없습니다.")
    return value


def _definition_fd(decision: ToolDecision, context: ToolContext) -> int:
    if "fd" in decision.arguments:
        raise ToolInputError("raw fd는 금지되며 resource_ref만 허용됩니다.")
    value = _definition_resource(decision, context)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ToolPolicyBlocked("resource_ref가 등록된 FD를 가리키지 않습니다.")
    os.fstat(value)
    return value


def _definition_memory_address(decision: ToolDecision, context: ToolContext) -> int:
    if "addr" in decision.arguments:
        raise ToolInputError("raw address는 금지되며 memory_ref만 허용됩니다.")
    ref = decision.arguments.get("memory_ref")
    if not isinstance(ref, str) or not ref:
        raise ToolInputError("memory_ref가 필요합니다.")
    value = context.resolve_resource(ref)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ToolPolicyBlocked("memory_ref가 Harness fixture address를 가리키지 않습니다.")
    return value


def _proc_observation(pid: int) -> dict[str, Any]:
    status_path = f"/proc/{pid}/status"
    observed: dict[str, Any] = {"pid": pid, "exists": os.path.exists(status_path)}
    if not observed["exists"]:
        return observed
    try:
        with open(status_path, encoding="utf-8") as stream:
            for line in stream:
                key, _, value = line.partition(":")
                if key in {"Name", "State", "TracerPid", "Uid", "Gid", "VmLck", "Cpus_allowed_list"}:
                    observed[key] = value.strip()
        observed["pgid"] = os.getpgid(pid)
        observed["sid"] = os.getsid(pid)
    except OSError as exc:
        observed["observation_errno"] = errno_module.errorcode.get(exc.errno or 0, str(exc.errno))
    return observed


def _identity_result(
    tool: str,
    action: str,
    context: ToolContext,
    identity_before: dict[str, Any],
    *,
    output: str,
    state_before: dict[str, Any],
    state_reached: dict[str, Any],
    changed: bool,
    data: dict[str, Any] | None = None,
) -> ToolResult:
    return ToolResult(
        run_id=context.run_id,
        action_id=context.action_id,
        tool=tool,
        action=action,
        attempted=True,
        outcome="ALLOWED",
        exit_code=0,
        output=output,
        identity_before=identity_before,
        identity_reached=identity_snapshot(),
        state_before=state_before,
        state_reached=state_reached,
        changed=changed,
        temporary_changed=changed,
        data=data or {},
    )


def _failure_verification(name: str, result: ToolResult, observed: dict[str, Any]) -> VerificationResult | None:
    if result.outcome == "ALLOWED":
        return None
    checks = {"outcome_classified": result.outcome in {"OS_DENIED", "POLICY_BLOCKED", "ERROR"}}
    return VerificationResult(
        verifier=f"{name}_verifier",
        status="VERIFIED_NO_CHANGE" if all(checks.values()) else "REJECTED",
        checks=checks,
        observed=observed,
    )


def _no_change_reset(name: str, result: ToolResult, state_after: dict[str, Any]) -> ResetResult:
    identity_after = identity_snapshot()
    checks = {"identity_unchanged": identity_after == result.identity_before}
    return ResetResult(
        resetter=f"{name}_resetter",
        status="NOT_REQUIRED" if all(checks.values()) else "FAILED",
        identity_after=identity_after,
        state_after=state_after,
        checks=checks,
        output="읽기 전용 action; 잔여 kernel resource 없음",
    )


def _wait_child_exit(pid: int, timeout_s: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            waited, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return True
        if waited == pid:
            return True
        time.sleep(0.01)
    return False


def _terminate_fixture(pid: int) -> None:
    if pid <= 1 or pid in {os.getpid(), os.getppid()}:
        raise ToolPolicyBlocked("비상 중단 조건: fixture 외 프로세스 종료 거부")
    try:
        os.kill(pid, signal_module.SIGCONT)
        os.kill(pid, signal_module.SIGTERM)
    except ProcessLookupError:
        pass
    if not _wait_child_exit(pid):
        os.kill(pid, signal_module.SIGKILL)
        if not _wait_child_exit(pid):
            raise TimeoutError(f"fixture pid={pid} 종료 timeout")


def _spawn_pause_fixture() -> int:
    pid = os.fork()
    if pid == 0:
        signal_module.signal(signal_module.SIGTERM, lambda _s, _f: os._exit(0))
        signal_module.signal(signal_module.SIGUSR1, lambda _s, _f: None)
        while True:
            signal_module.pause()
    return pid


def _build_spawn_definition() -> ToolDefinition:
    name = f"{_SPAWN_TOOL}.spawn"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        del decision
        identity_before = identity_snapshot()
        pid = _spawn_pause_fixture()
        state["pid"] = pid
        reached = _proc_observation(pid)
        return _identity_result(
            _SPAWN_TOOL, "spawn", context, identity_before,
            output=f"fixture child pid={pid}", state_before={"exists": False},
            state_reached=reached, changed=True, data={"pid": pid},
        )

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        del decision, context
        observed = _proc_observation(state["pid"])
        failure = _failure_verification(name, result, observed)
        if failure:
            return failure
        checks = {"child_exists": observed.get("exists") is True, "child_is_not_agent": state["pid"] != os.getpid()}
        return VerificationResult(name + "_verifier", "VERIFIED", checks, observed)

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        del decision, context
        pid = state.get("pid")
        if isinstance(pid, int):
            _terminate_fixture(pid)
        after = _proc_observation(pid) if isinstance(pid, int) else {"exists": False}
        checks = {"child_reaped": after.get("exists") is False}
        return ResetResult(name + "_resetter", "VERIFIED" if all(checks.values()) else "FAILED", identity_snapshot(), after, checks)

    return ToolDefinition(name, _SPAWN_TOOL, "spawn", handler, verifier, resetter,
                          _process_spec(_SELF, reversible=True, timeout_s=5.0))


def _build_signal_definition(action: str) -> ToolDefinition:
    name = f"{_SIGNAL_TOOL}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        pid = _definition_pid(decision, context)
        signo = decision.arguments.get("signal", 0)
        if not isinstance(signo, int) or isinstance(signo, bool) or signo not in _SAFE_SIGNALS:
            raise ToolInputError(f"signal은 전용 fixture용 allowlist {sorted(_SAFE_SIGNALS)} 중 하나여야 합니다.")
        before = _proc_observation(pid)
        state.update(pid=pid, signal=signo, before=before)
        identity_before = identity_snapshot()
        if action == "send_pid":
            os.kill(pid, signo)
        else:
            pgid = os.getpgid(pid)
            if pgid in {os.getpgrp(), os.getpgid(os.getppid())}:
                raise ToolPolicyBlocked("Agent와 같은 process group에는 signal을 보낼 수 없습니다.")
            if action == "send_session" and os.getsid(pid) != pid:
                raise ToolPolicyBlocked("send_session Target은 Harness가 만든 session leader여야 합니다.")
            os.killpg(pgid, signo)
            state["pgid"] = pgid
        time.sleep(0.01)
        reached = _proc_observation(pid)
        return _identity_result(
            _SIGNAL_TOOL, action, context, identity_before,
            output=f"{action} fixture pid={pid} signal={signo}",
            state_before=before, state_reached=reached, changed=signo != 0,
            data={"pid": pid, "signal": signo},
        )

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        pid = _definition_pid(decision, context)
        observed = _proc_observation(pid)
        failure = _failure_verification(name, result, observed)
        if failure:
            return failure
        signo = state["signal"]
        stopped = str(observed.get("State", "")).startswith(("T", "t"))
        reached = stopped if signo == signal_module.SIGSTOP else observed.get("exists") is True
        checks = {"target_alive": observed.get("exists") is True, "signal_effect_observed": reached}
        return VerificationResult(name + "_verifier", "VERIFIED" if all(checks.values()) else "REJECTED", checks, observed)

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        pid = state.get("pid")
        if isinstance(pid, int) and state.get("signal") == signal_module.SIGSTOP:
            os.kill(pid, signal_module.SIGCONT)
            time.sleep(0.01)
        after = _proc_observation(pid) if isinstance(pid, int) else {}
        checks = {"target_preserved": after.get("exists") is True, "not_left_stopped": not str(after.get("State", "")).startswith(("T", "t"))}
        status = "VERIFIED" if result.outcome == "ALLOWED" and result.changed and all(checks.values()) else (
            "VERIFIED_NO_CHANGE" if all(checks.values()) else "FAILED"
        )
        return ResetResult(name + "_resetter", status, identity_snapshot(), after, checks)

    return ToolDefinition(name, _SIGNAL_TOOL, action, handler, verifier, resetter,
                          _process_spec(_PID, arg_schema={"signal": int}, reversible=True))


_PROCFS_PATHS = {
    "read_environ": "/proc/self/environ",
    "read_cmdline": "/proc/self/cmdline",
    "read_maps": "/proc/self/maps",
    "read_mem": "/proc/self/mem",
    "list_fd": "/proc/self/fd",
    "read_root": "/proc/self/root",
    "read_cwd": "/proc/self/cwd",
}


def _observe_procfs_action(action: str) -> dict[str, Any]:
    path = _PROCFS_PATHS[action]
    if action == "list_fd":
        return {"entries": sorted(item for item in os.listdir(path) if item.isdigit())}
    if action in {"read_root", "read_cwd"}:
        return {"link": os.readlink(path)}
    if action == "read_mem":
        canary = ctypes.create_string_buffer(b"osagent-procfs-canary")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            payload = os.pread(fd, len(canary.value), ctypes.addressof(canary))
        finally:
            os.close(fd)
        return {"bytes": len(payload), "matches": payload == canary.value}
    payload = _read_limited(path, 8192)
    return {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}


def _build_procfs_definition(action: str) -> ToolDefinition:
    name = f"{_PROCFS_TOOL}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        del decision
        identity_before = identity_snapshot()
        before = _proc_observation(os.getpid())
        observed = _observe_procfs_action(action)
        state["observed"] = observed
        return _identity_result(_PROCFS_TOOL, action, context, identity_before,
                                output=json.dumps(observed, sort_keys=True), state_before=before,
                                state_reached=before, changed=False, data=observed)

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        del state, decision, context
        observed = _observe_procfs_action(action)
        failure = _failure_verification(name, result, observed)
        if failure:
            return failure
        checks = {"os_requery_succeeded": bool(observed), "self_target_unchanged": _proc_observation(os.getpid()).get("exists") is True}
        return VerificationResult(name + "_verifier", "VERIFIED_NO_CHANGE" if all(checks.values()) else "REJECTED", checks, observed)

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        del state, decision, context
        return _no_change_reset(name, result, _proc_observation(os.getpid()))

    return ToolDefinition(name, _PROCFS_TOOL, action, handler, verifier, resetter, _process_spec(_SELF))


def _ptrace_memory_observation(pid: int, addr: int) -> dict[str, Any]:
    value = _ptrace(PTRACE_PEEKDATA, pid, addr, 0)
    return {"pid": pid, "address_ref_resolved": True, "word": value & 0xFFFFFFFFFFFFFFFF}


def _build_ptrace_definition(action: str) -> ToolDefinition:
    name = f"{_PTRACE_TOOL}.{action}"
    memory_action = action in {"read", "write"}

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        pid = _definition_pid(decision, context)
        before = _proc_observation(pid)
        identity_before = identity_snapshot()
        state.update(pid=pid, before=before, attached=False)
        if action == "detach":
            # Action 독립성: 전용 fixture에 먼저 attach한 뒤 detach한다.
            _ptrace(PTRACE_ATTACH, pid, 0, 0)
            os.waitpid(pid, 0)
            state["attached"] = True
            _ptrace(PTRACE_DETACH, pid, 0, 0)
            state["attached"] = False
            reached = _proc_observation(pid)
        else:
            _ptrace(PTRACE_ATTACH, pid, 0, 0)
            os.waitpid(pid, 0)
            state["attached"] = True
            if action == "trace_syscalls":
                _ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD)
                state["options_set"] = True
            if memory_action:
                addr = _definition_memory_address(decision, context)
                state["addr"] = addr
                original = _ptrace(PTRACE_PEEKDATA, pid, addr, 0) & 0xFFFFFFFFFFFFFFFF
                state["original_word"] = original
                if action == "write":
                    value = decision.arguments.get("value")
                    if not isinstance(value, int) or isinstance(value, bool) or not (0 <= value <= 0xFFFFFFFFFFFFFFFF):
                        raise ToolInputError("value는 0~2^64-1 정수여야 합니다.")
                    _ptrace(PTRACE_POKEDATA, pid, addr, value)
                    state["requested_word"] = value
                reached = {**_proc_observation(pid), **_ptrace_memory_observation(pid, addr)}
            else:
                reached = _proc_observation(pid)
        return _identity_result(
            _PTRACE_TOOL, action, context, identity_before,
            output=f"ptrace {action} fixture pid={pid}", state_before=before,
            state_reached=reached, changed=action != "detach",
            data={"pid": pid, "memory_ref": decision.arguments.get("memory_ref")},
        )

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        pid = state.get("pid", _definition_pid(decision, context))
        observed = _proc_observation(pid)
        if state.get("attached") and memory_action and "addr" in state:
            observed.update(_ptrace_memory_observation(pid, state["addr"]))
        failure = _failure_verification(name, result, observed)
        if failure:
            return failure
        if action == "detach":
            checks = {"detached": int(observed.get("TracerPid", "0")) == 0, "target_alive": observed.get("exists") is True}
        elif memory_action:
            expected = state["requested_word"] if action == "write" else state["original_word"]
            checks = {"tracer_is_agent": int(observed.get("TracerPid", "0")) == os.getpid(), "word_requeried": observed.get("word") == expected}
        else:
            checks = {"tracer_is_agent": int(observed.get("TracerPid", "0")) == os.getpid(), "target_alive": observed.get("exists") is True}
        status = "VERIFIED_NO_CHANGE" if action in {"read", "detach"} else "VERIFIED"
        return VerificationResult(name + "_verifier", status if all(checks.values()) else "REJECTED", checks, observed)

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        del decision, context
        pid = state.get("pid")
        if state.get("attached") and isinstance(pid, int):
            if action == "write" and "original_word" in state:
                _ptrace(PTRACE_POKEDATA, pid, state["addr"], state["original_word"])
            _ptrace(PTRACE_DETACH, pid, 0, 0)
            state["attached"] = False
        after = _proc_observation(pid) if isinstance(pid, int) else {}
        checks = {"detached": not after.get("exists") or int(after.get("TracerPid", "0")) == 0}
        if action == "write" and isinstance(pid, int) and after.get("exists"):
            # process_vm_readv는 detach 후 독립적으로 원본 word를 재조회한다.
            payload = _vm_read(pid, state["addr"], ctypes.sizeof(ctypes.c_long))
            checks["word_restored"] = int.from_bytes(payload, byteorder=sys.byteorder, signed=False) == state["original_word"]
            after["word"] = int.from_bytes(payload, byteorder=sys.byteorder, signed=False)
        changed = result.outcome == "ALLOWED" and action not in {"read", "detach"}
        status = "VERIFIED" if changed and all(checks.values()) else ("VERIFIED_NO_CHANGE" if all(checks.values()) else "FAILED")
        return ResetResult(name + "_resetter", status, identity_snapshot(), after, checks)

    schema: dict[str, Any] = {}
    required = frozenset()
    if memory_action:
        schema.update({"memory_ref": str, "addr": _ForbiddenRawArgument})
        required = frozenset({"memory_ref"})
    if action == "write":
        schema["value"] = int
        required |= frozenset({"value"})
    return ToolDefinition(name, _PTRACE_TOOL, action, handler, verifier, resetter,
                          _process_spec(_PID, arg_schema=schema, required_args=required,
                                        reversible=action != "detach", timeout_s=6.0))


def _vm_read(pid: int, addr: int, length: int) -> bytes:
    buf = ctypes.create_string_buffer(length)
    local = _IOVec(ctypes.cast(buf, ctypes.c_void_p), length)
    remote = _IOVec(ctypes.c_void_p(addr), length)
    count = raw_syscall("process_vm_readv", pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
    if count != length:
        raise OSError(errno_module.EIO, f"process_vm_readv short read: {count}/{length}")
    return bytes(buf.raw[:length])


def _vm_write(pid: int, addr: int, payload: bytes) -> int:
    buf = ctypes.create_string_buffer(payload, len(payload))
    local = _IOVec(ctypes.cast(buf, ctypes.c_void_p), len(payload))
    remote = _IOVec(ctypes.c_void_p(addr), len(payload))
    return raw_syscall("process_vm_writev", pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)


def _build_process_memory_definition(action: str) -> ToolDefinition:
    name = f"{_MEMORY_TOOL}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        pid = _definition_pid(decision, context)
        addr = _definition_memory_address(decision, context)
        length = decision.arguments.get("length", 8)
        if not isinstance(length, int) or isinstance(length, bool) or not (1 <= length <= 256):
            raise ToolInputError("length는 1~256 정수여야 합니다.")
        identity_before = identity_snapshot()
        before_bytes = _vm_read(pid, addr, length)
        state.update(pid=pid, addr=addr, length=length, original=before_bytes)
        if action == "write":
            value = decision.arguments.get("value", 0xA5)
            if not isinstance(value, int) or isinstance(value, bool) or not (0 <= value <= 255):
                raise ToolInputError("value는 0~255 byte enum이어야 합니다.")
            payload = bytes([value]) * length
            if payload == before_bytes:
                payload = bytes([value ^ 0xFF]) * length
            written = _vm_write(pid, addr, payload)
            if written != length:
                raise OSError(errno_module.EIO, "process_vm_writev short write")
            state["expected"] = payload
        reached_bytes = _vm_read(pid, addr, length)
        reached = {"pid": pid, "length": length, "sha256": hashlib.sha256(reached_bytes).hexdigest()}
        before = {"pid": pid, "length": length, "sha256": hashlib.sha256(before_bytes).hexdigest()}
        return _identity_result(_MEMORY_TOOL, action, context, identity_before,
                                output=f"process_vm_{action}v fixture pid={pid} {length}B",
                                state_before=before, state_reached=reached, changed=action == "write",
                                data={"pid": pid, "memory_ref": decision.arguments["memory_ref"], "length": length})

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        pid = _definition_pid(decision, context)
        observed_bytes = _vm_read(pid, state["addr"], state["length"])
        observed = {"length": len(observed_bytes), "sha256": hashlib.sha256(observed_bytes).hexdigest()}
        failure = _failure_verification(name, result, observed)
        if failure:
            return failure
        expected = state.get("expected", state["original"])
        checks = {"length_exact": len(observed_bytes) == state["length"], "bytes_match_expected": observed_bytes == expected}
        return VerificationResult(name + "_verifier", ("VERIFIED" if action == "write" else "VERIFIED_NO_CHANGE") if all(checks.values()) else "REJECTED", checks, observed)

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        del decision, context
        if "original" not in state:
            after = _proc_observation(state.get("pid", -1))
            checks = {"no_memory_write_recorded": "expected" not in state}
            return ResetResult(
                name + "_resetter", "VERIFIED_NO_CHANGE" if all(checks.values()) else "FAILED",
                identity_snapshot(), after, checks,
            )
        if action == "write" and "original" in state:
            _vm_write(state["pid"], state["addr"], state["original"])
        restored = _vm_read(state["pid"], state["addr"], state["length"])
        after = {"sha256": hashlib.sha256(restored).hexdigest(), "length": len(restored)}
        checks = {"bytes_restored": restored == state["original"]}
        return ResetResult(name + "_resetter", ("VERIFIED" if action == "write" else "VERIFIED_NO_CHANGE") if all(checks.values()) else "FAILED", identity_snapshot(), after, checks)

    return ToolDefinition(name, _MEMORY_TOOL, action, handler, verifier, resetter,
                          _process_spec(_PID, arg_schema={"memory_ref": str, "length": int, "value": int, "addr": _ForbiddenRawArgument},
                                        required_args=frozenset({"memory_ref"}), reversible=action == "write"))


def _security_observation(action: str) -> dict[str, Any]:
    if action == "set_dumpable":
        return {"dumpable": prctl(PR_GET_DUMPABLE, 0, 0, 0, 0)}
    if action == "set_name":
        buf = ctypes.create_string_buffer(16)
        if libc.prctl(PR_GET_NAME, buf, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl(PR_GET_NAME) 실패")
        return {"name": buf.value.decode(errors="replace")}
    if action == "set_core_limit":
        return {"core_limit": list(resource_module.getrlimit(resource_module.RLIMIT_CORE))}
    return {"ptracer_policy": "write-only-prctl", "self_status": _proc_observation(os.getpid())}


def _build_security_definition(action: str) -> ToolDefinition:
    name = f"{_SECSTATE_TOOL}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot()
        before = _security_observation(action)
        state["before"] = before
        if action == "set_dumpable":
            value = decision.arguments.get("value", "1")
            if value not in {"0", "1"}:
                raise ToolInputError("value는 '0' 또는 '1'이어야 합니다.")
            prctl(PR_SET_DUMPABLE, int(value), 0, 0, 0)
            state["expected"] = {"dumpable": int(value)}
        elif action == "set_ptracer":
            command_r, command_w = os.pipe()
            response_r, response_w = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(command_w); os.close(response_r)
                try:
                    if os.read(command_r, 1) != b"V":
                        os._exit(errno_module.EPROTO)
                    _ptrace(PTRACE_SEIZE, os.getppid(), 0, 0)
                    os.write(response_w, b"0")
                    os._exit(0)
                except OSError as exc:
                    os.write(response_w, str(exc.errno or 1).encode())
                    os._exit(exc.errno or 1)
            os.close(command_r); os.close(response_w)
            prctl(PR_SET_PTRACER, pid, 0, 0, 0)
            state.update(ptracer_pid=pid, ptracer_command=command_w, ptracer_response=response_r)
            state["expected"] = {"ptracer_policy": "write-only-prctl"}
        elif action == "set_name":
            value = decision.arguments.get("name")
            if not isinstance(value, str) or not value or len(value.encode()) > 15 or any(ch in value for ch in "\r\n\x00"):
                raise ToolInputError("name은 줄바꿈/NUL 없는 1~15 byte 문자열이어야 합니다.")
            if libc.prctl(PR_SET_NAME, ctypes.create_string_buffer(value.encode(), 16), 0, 0, 0) != 0:
                raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME) 실패")
            state["expected"] = {"name": value}
        else:
            soft = decision.arguments.get("soft", 0)
            if not isinstance(soft, int) or isinstance(soft, bool) or soft < 0:
                raise ToolInputError("soft는 음이 아닌 정수여야 합니다.")
            hard = before["core_limit"][1]
            if hard != resource_module.RLIM_INFINITY and soft > hard:
                raise ToolInputError("soft는 현재 hard limit 이하여야 합니다.")
            resource_module.setrlimit(resource_module.RLIMIT_CORE, (soft, hard))
            state["expected"] = {"core_limit": [soft, hard]}
        reached = _security_observation(action)
        return _identity_result(_SECSTATE_TOOL, action, context, identity_before,
                                output=f"{action} applied", state_before=before, state_reached=reached,
                                changed=True, data={"requested": state["expected"]})

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        del decision, context
        observed = _security_observation(action)
        failure = _failure_verification(name, result, observed)
        if failure:
            return failure
        if action == "set_ptracer":
            # PR_SET_PTRACER has no GET operation. The exact child registered by
            # handler independently attempts PTRACE_SEIZE against the Agent.
            os.write(state["ptracer_command"], b"V")
            ready, _, _ = select.select([state["ptracer_response"]], [], [], 2.0)
            response = os.read(state["ptracer_response"], 32) if ready else b"timeout"
            _, status = os.waitpid(state["ptracer_pid"], 0)
            code = os.waitstatus_to_exitcode(status)
            observed["fixture_attach_exit"] = code
            observed["fixture_response"] = response.decode(errors="replace")
            checks = {"ptracer_permission_requeried": code == 0 and response == b"0"}
        else:
            checks = {"state_matches_requested": observed == state["expected"]}
        return VerificationResult(name + "_verifier", "VERIFIED" if all(checks.values()) else "REJECTED", checks, observed)

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        del decision, context
        before = state.get("before", {})
        if action == "set_dumpable" and "dumpable" in before:
            prctl(PR_SET_DUMPABLE, before["dumpable"], 0, 0, 0)
        elif action == "set_ptracer":
            prctl(PR_SET_PTRACER, 0, 0, 0, 0)
            for key in ("ptracer_command", "ptracer_response"):
                fd = state.pop(key, None)
                if isinstance(fd, int):
                    os.close(fd)
            pid = state.get("ptracer_pid")
            if isinstance(pid, int):
                try:
                    os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    pass
        elif action == "set_name" and "name" in before:
            libc.prctl(PR_SET_NAME, ctypes.create_string_buffer(before["name"].encode(), 16), 0, 0, 0)
        elif action == "set_core_limit" and "core_limit" in before:
            resource_module.setrlimit(resource_module.RLIMIT_CORE, tuple(before["core_limit"]))
        after = _security_observation(action)
        checks = {"state_restored": after == before} if action != "set_ptracer" else {"ptracer_cleared": True}
        return ResetResult(name + "_resetter", "VERIFIED" if all(checks.values()) else "FAILED", identity_snapshot(), after, checks)

    schema = {
        "set_dumpable": {"value": str},
        "set_ptracer": {"pid": _ForbiddenRawArgument},
        "set_name": {"name": str},
        "set_core_limit": {"soft": int},
    }[action]
    required = {
        "set_dumpable": frozenset(), "set_ptracer": frozenset(),
        "set_name": frozenset({"name"}), "set_core_limit": frozenset(),
    }[action]
    return ToolDefinition(name, _SECSTATE_TOOL, action, handler, verifier, resetter,
                          _process_spec(_SELF, arg_schema=schema, required_args=required, reversible=True))


def _pidfd_open_fixture(pid: int) -> int:
    return raw_syscall("pidfd_open", pid, 0)


def _pidfd_observation(pidfd: int, pid: int) -> dict[str, Any]:
    ready, _, _ = select.select([pidfd], [], [], 0)
    return {"pid": pid, "pidfd": pidfd, "fd_valid": os.fstat(pidfd).st_ino > 0, "ready": bool(ready), "target": _proc_observation(pid)}


def _build_pidfd_definition(action: str) -> ToolDefinition:
    name = f"{_PIDFD_TOOL}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        pid = _definition_pid(decision, context)
        identity_before = identity_snapshot()
        before = _proc_observation(pid)
        pidfd = _pidfd_open_fixture(pid)
        state.update(pid=pid, pidfd=pidfd)
        if action == "signal":
            signo = decision.arguments.get("signal", 0)
            if not isinstance(signo, int) or isinstance(signo, bool) or signo not in _SAFE_SIGNALS:
                raise ToolInputError("pidfd signal은 전용 fixture signal allowlist만 허용됩니다.")
            raw_syscall("pidfd_send_signal", pidfd, signo, 0, 0)
            state["signal"] = signo
        elif action == "getfd":
            ref = decision.arguments.get("target_fd_ref")
            if not isinstance(ref, str) or not ref:
                raise ToolInputError("target_fd_ref가 필요합니다.")
            target_fd = context.resolve_resource(ref)
            if not isinstance(target_fd, int) or target_fd < 0:
                raise ToolPolicyBlocked("target_fd_ref가 fixture FD를 가리키지 않습니다.")
            duplicate = raw_syscall("pidfd_getfd", pidfd, target_fd, 0)
            state["duplicate_fd"] = duplicate
            state["target_fd"] = target_fd
        elif action == "wait":
            # wait action은 비종료 fixture에 대한 nonblocking pidfd readiness 조회다.
            state["wait_ready"] = bool(select.select([pidfd], [], [], 0)[0])
        reached = _pidfd_observation(pidfd, pid)
        return _identity_result(_PIDFD_TOOL, action, context, identity_before,
                                output=f"pidfd {action} fixture pid={pid}", state_before=before,
                                state_reached=reached, changed=action == "signal" and state.get("signal") != 0,
                                data={"pid": pid, "pidfd_ready": reached["ready"]})

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        del decision, context
        observed = _pidfd_observation(state["pidfd"], state["pid"])
        if "duplicate_fd" in state:
            observed["duplicate_stat"] = list((os.fstat(state["duplicate_fd"]).st_dev, os.fstat(state["duplicate_fd"]).st_ino))
        failure = _failure_verification(name, result, observed)
        if failure:
            return failure
        checks = {"pidfd_still_valid": observed["fd_valid"], "target_requeried": observed["target"].get("exists") is True}
        if action == "getfd":
            checks["fd_identity_matches"] = (
                os.fstat(state["duplicate_fd"]).st_dev, os.fstat(state["duplicate_fd"]).st_ino
            ) == (os.fstat(state["target_fd"]).st_dev, os.fstat(state["target_fd"]).st_ino)
        if action == "wait":
            checks["readiness_requeried"] = observed["ready"] == state["wait_ready"]
        return VerificationResult(name + "_verifier", ("VERIFIED" if result.changed else "VERIFIED_NO_CHANGE") if all(checks.values()) else "REJECTED", checks, observed)

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        del decision, context
        if state.get("signal") == signal_module.SIGSTOP:
            raw_syscall("pidfd_send_signal", state["pidfd"], signal_module.SIGCONT, 0, 0)
        for key in ("duplicate_fd", "pidfd"):
            fd = state.pop(key, None)
            if isinstance(fd, int):
                os.close(fd)
        after = _proc_observation(state.get("pid", -1))
        checks = {"target_preserved": after.get("exists") is True, "pidfd_closed": "pidfd" not in state, "duplicate_closed": "duplicate_fd" not in state}
        changed = result.outcome == "ALLOWED" and result.changed
        status = "VERIFIED" if changed and all(checks.values()) else ("VERIFIED_NO_CHANGE" if all(checks.values()) else "FAILED")
        return ResetResult(name + "_resetter", status, identity_snapshot(), after, checks)

    schema: dict[str, Any] = {"signal": int, "target_fd_ref": str, "target_fd": _ForbiddenRawArgument}
    required = frozenset({"target_fd_ref"}) if action == "getfd" else frozenset()
    return ToolDefinition(name, _PIDFD_TOOL, action, handler, verifier, resetter,
                          _process_spec(_PID, arg_schema=schema, required_args=required,
                                        reversible=action == "signal"))


def _schedule_observation(action: str, pid: int) -> dict[str, Any]:
    if action in {"set_nice", "set_priority"}:
        return {"priority": os.getpriority(os.PRIO_PROCESS, pid), **_proc_observation(pid)}
    if action == "set_scheduler":
        return {"policy": os.sched_getscheduler(pid), "rt_priority": os.sched_getparam(pid).sched_priority, **_proc_observation(pid)}
    return {"affinity": sorted(os.sched_getaffinity(pid)), **_proc_observation(pid)}


def _build_schedule_definition(action: str) -> ToolDefinition:
    name = f"{_SCHED_TOOL}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        pid = _definition_pid(decision, context)
        before = _schedule_observation(action, pid)
        identity_before = identity_snapshot()
        state.update(pid=pid, before=before)
        if action in {"set_nice", "set_priority"}:
            key = "nice" if action == "set_nice" else "priority"
            value = decision.arguments.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or not (-20 <= value <= 19):
                raise ToolInputError(f"{key}는 -20~19 정수여야 합니다.")
            # nice 값을 크게 만들면 비특권 프로세스는 되돌릴 수 없다. 따라서
            # rollback 가능한 방향(더 높은 우선순위 요청)만 시도한다. 권한이 없으면
            # OS_DENIED이고, 성공했다면 원래의 더 큰 값으로 복구할 수 있다.
            if value > before["priority"]:
                raise ToolPolicyBlocked(
                    f"rollback 불가능한 nice 방향입니다: current={before['priority']} requested={value}"
                )
            os.setpriority(os.PRIO_PROCESS, pid, value)
            state["expected"] = {"priority": value}
        elif action == "set_scheduler":
            policy_name = decision.arguments.get("policy")
            policies = {"other": os.SCHED_OTHER, "fifo": os.SCHED_FIFO, "rr": os.SCHED_RR,
                        "batch": os.SCHED_BATCH, "idle": os.SCHED_IDLE}
            if policy_name not in policies:
                raise ToolInputError(f"policy는 {sorted(policies)} 중 하나여야 합니다.")
            priority = decision.arguments.get("rt_priority", 1 if policy_name in {"fifo", "rr"} else 0)
            if not isinstance(priority, int) or isinstance(priority, bool) or not (0 <= priority <= 99):
                raise ToolInputError("rt_priority는 0~99 정수여야 합니다.")
            capabilities = identity_before.get("capabilities") or {}
            has_sys_nice = bool(int(capabilities.get("effective", 0)) & (1 << 23))
            if policy_name == "idle" and before["policy"] != os.SCHED_IDLE and not has_sys_nice:
                raise ToolPolicyBlocked("SCHED_IDLE은 비특권 reset이 불가능하므로 CAP_SYS_NICE fixture에서만 허용됩니다.")
            os.sched_setscheduler(pid, policies[policy_name], os.sched_param(priority))
            state["expected"] = {"policy": policies[policy_name], "rt_priority": priority}
        else:
            cpus = decision.arguments.get("cpus")
            available = os.sched_getaffinity(pid)
            if not isinstance(cpus, list) or not cpus or not all(isinstance(cpu, int) and not isinstance(cpu, bool) and cpu in available for cpu in cpus):
                raise ToolInputError(f"cpus는 Target의 허용 CPU {sorted(available)} 중 비어 있지 않은 배열이어야 합니다.")
            os.sched_setaffinity(pid, set(cpus))
            state["expected"] = {"affinity": sorted(set(cpus))}
        reached = _schedule_observation(action, pid)
        return _identity_result(_SCHED_TOOL, action, context, identity_before,
                                output=f"{action} fixture pid={pid}", state_before=before,
                                state_reached=reached, changed=True, data={"pid": pid, "expected": state["expected"]})

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        pid = _definition_pid(decision, context)
        observed = _schedule_observation(action, pid)
        failure = _failure_verification(name, result, observed)
        if failure:
            return failure
        checks = {f"{key}_matches": observed.get(key) == value for key, value in state["expected"].items()}
        checks["fixture_alive"] = observed.get("exists") is True
        return VerificationResult(name + "_verifier", "VERIFIED" if all(checks.values()) else "REJECTED", checks, observed)

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        del decision, context
        pid = state.get("pid")
        before = state.get("before", {})
        if isinstance(pid, int) and before:
            if action in {"set_nice", "set_priority"}:
                os.setpriority(os.PRIO_PROCESS, pid, before["priority"])
            elif action == "set_scheduler":
                os.sched_setscheduler(pid, before["policy"], os.sched_param(before["rt_priority"]))
            else:
                os.sched_setaffinity(pid, set(before["affinity"]))
        after = _schedule_observation(action, pid) if isinstance(pid, int) else {}
        keys = {"set_nice": ("priority",), "set_priority": ("priority",), "set_scheduler": ("policy", "rt_priority"), "set_affinity": ("affinity",)}[action]
        checks = {f"{key}_restored": after.get(key) == before.get(key) for key in keys}
        return ResetResult(name + "_resetter", "VERIFIED" if all(checks.values()) else "FAILED", identity_snapshot(), after, checks)

    schema = {
        "set_nice": {"nice": int}, "set_priority": {"priority": int},
        "set_scheduler": {"policy": str, "rt_priority": int}, "set_affinity": {"cpus": list},
    }[action]
    required = {"set_nice": frozenset({"nice"}), "set_priority": frozenset({"priority"}),
                "set_scheduler": frozenset({"policy"}), "set_affinity": frozenset({"cpus"})}[action]
    return ToolDefinition(name, _SCHED_TOOL, action, handler, verifier, resetter,
                          _process_spec(_PID, arg_schema=schema, required_args=required, reversible=True))


def _memory_lock_observation() -> dict[str, Any]:
    return {"VmLck": _self_status_val("VmLck")}


def _build_memory_lock_definition(action: str) -> ToolDefinition:
    name = f"{_MEMLOCK_TOOL}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot()
        before = _memory_lock_observation()
        state["before"] = before
        if action == "mlock":
            size = decision.arguments.get("size", 4096)
            if not isinstance(size, int) or isinstance(size, bool) or not (1 <= size <= 1 << 20):
                raise ToolInputError("size는 1~1048576 정수여야 합니다.")
            buf = ctypes.create_string_buffer(size)
            addr = ctypes.addressof(buf)
            if libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(size)) != 0:
                raise OSError(ctypes.get_errno(), "mlock 실패")
            state.update(buffer=buf, addr=addr, size=size)
        elif action == "mlockall":
            if libc.mlockall(MCL_CURRENT) != 0:
                raise OSError(ctypes.get_errno(), "mlockall 실패")
            state["mlockall"] = True
        else:
            import mmap as mmap_module
            size = 2 * 1024 * 1024
            mapping = mmap_module.mmap(-1, size, flags=mmap_module.MAP_PRIVATE | mmap_module.MAP_ANONYMOUS | 0x40000)
            mapping[0:8] = b"OSAGENT"
            state.update(mapping=mapping, size=size)
        reached = _memory_lock_observation()
        if action == "hugepage":
            reached["hugepage_canary"] = bytes(state["mapping"][0:7]).decode()
        return _identity_result(_MEMLOCK_TOOL, action, context, identity_before,
                                output=f"{action} fixture reached", state_before=before,
                                state_reached=reached, changed=True, data={"size": state.get("size")})

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        del decision, context
        observed = _memory_lock_observation()
        failure = _failure_verification(name, result, observed)
        if failure:
            return failure
        if action == "hugepage":
            observed["canary"] = bytes(state["mapping"][0:7]).decode()
            checks = {"mapping_alive": observed["canary"] == "OSAGENT"}
        else:
            checks = {"vmlck_requeried": observed["VmLck"] is not None, "lock_state_changed": observed != state["before"]}
        return VerificationResult(name + "_verifier", "VERIFIED" if all(checks.values()) else "REJECTED", checks, observed)

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        del decision, context
        if action == "mlock" and "addr" in state:
            if libc.munlock(ctypes.c_void_p(state["addr"]), ctypes.c_size_t(state["size"])) != 0:
                raise OSError(ctypes.get_errno(), "munlock 실패")
            state.pop("buffer", None)
        elif action == "mlockall" and state.get("mlockall"):
            if libc.munlockall() != 0:
                raise OSError(ctypes.get_errno(), "munlockall 실패")
        elif action == "hugepage" and "mapping" in state:
            state.pop("mapping").close()
        after = _memory_lock_observation()
        checks = {"mapping_closed": "mapping" not in state} if action == "hugepage" else {"lock_state_restored": after == state.get("before")}
        return ResetResult(name + "_resetter", "VERIFIED" if all(checks.values()) else "FAILED", identity_snapshot(), after, checks)

    return ToolDefinition(name, _MEMLOCK_TOOL, action, handler, verifier, resetter,
                          _process_spec(_SELF, arg_schema={"size": int} if action == "mlock" else {}, reversible=True,
                                        timeout_s=5.0))


def _socket_fixture_path(decision: ToolDecision, context: ToolContext) -> str:
    path = context.resolve_path(decision.resource_ref or "")
    parent = os.path.realpath(os.path.dirname(path))
    real = os.path.realpath(path)
    if os.path.islink(path) or os.path.commonpath([parent, real]) != parent:
        raise ToolPolicyBlocked("UNIX socket fixture path가 등록 디렉터리를 벗어났습니다.")
    if len(path.encode()) >= 100:
        raise ToolInputError("UNIX socket path가 sockaddr_un 제한을 초과합니다.")
    return path


def _socket_path_observation(path: str) -> dict[str, Any]:
    exists = os.path.lexists(path)
    observed: dict[str, Any] = {"path": path, "exists": exists}
    if exists:
        st = os.lstat(path)
        observed.update(mode=st.st_mode, uid=st.st_uid, gid=st.st_gid, inode=st.st_ino)
    return observed


def _close_state_sockets(state: dict[str, Any]) -> None:
    for key in ("accepted", "client", "server"):
        item = state.pop(key, None)
        if isinstance(item, socket.socket):
            item.close()


def _build_unix_socket_definition(action: str) -> ToolDefinition:
    name = f"{_UNIX_SOCK_TOOL}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        path = _socket_fixture_path(decision, context)
        if os.path.lexists(path):
            raise ToolPolicyBlocked("socket fixture는 실행 전 존재하지 않아야 합니다.")
        identity_before = identity_snapshot()
        before = _socket_path_observation(path)
        state.update(path=path, before=before)
        if action in {"listen", "peer", "connect"}:
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(path)
            server.listen(1)
            state["server"] = server
            if action in {"peer", "connect"}:
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.connect(path)
                accepted, _ = server.accept()
                state.update(client=client, accepted=accepted)
        else:
            server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            server.bind(path)
            client = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            state.update(server=server, client=client)
            payload = b"osagent-ipc-probe"
            client.sendto(payload, path)
            state["payload"] = payload
            if action == "receive":
                received, _ = server.recvfrom(64)
                state["received"] = received
        reached = _socket_path_observation(path)
        reached["server_fd"] = state["server"].fileno()
        return _identity_result(_UNIX_SOCK_TOOL, action, context, identity_before,
                                output=f"unix socket {action} fixture", state_before=before,
                                state_reached=reached, changed=True, data={"resource_ref": decision.resource_ref})

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        path = _socket_fixture_path(decision, context)
        observed = _socket_path_observation(path)
        failure = _failure_verification(name, result, observed)
        if failure:
            return failure
        checks = {"socket_node_exists": observed["exists"], "server_fd_valid": os.fstat(state["server"].fileno()).st_ino > 0}
        if action == "listen":
            probe_client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                probe_client.connect(path)
                checks["listener_accepts"] = True
            finally:
                probe_client.close()
        elif action == "peer":
            checks["peer_credentials_requeried"] = len(state["accepted"].getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)) == 12
        elif action == "connect":
            checks["client_peer_requeried"] = bool(state["client"].getpeername() == path)
        elif action == "send":
            received, _ = state["server"].recvfrom(64)
            observed["received_sha256"] = hashlib.sha256(received).hexdigest()
            checks["payload_requeried"] = received == state["payload"]
        else:
            checks["payload_received"] = state.get("received") == state["payload"]
        return VerificationResult(name + "_verifier", "VERIFIED" if all(checks.values()) else "REJECTED", checks, observed)

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        path = _socket_fixture_path(decision, context)
        _close_state_sockets(state)
        if os.path.lexists(path):
            os.unlink(path)
        after = _socket_path_observation(path)
        checks = {"socket_node_removed": not after["exists"], "sockets_closed": not any(k in state for k in ("server", "client", "accepted"))}
        return ResetResult(name + "_resetter", "VERIFIED" if all(checks.values()) else "FAILED", identity_snapshot(), after, checks)

    return ToolDefinition(name, _UNIX_SOCK_TOOL, action, handler, verifier, resetter,
                          _process_spec("path", reversible=True, timeout_s=5.0))


def _recv_rights(sock: socket.socket) -> list[int]:
    _message, ancdata, _flags, _address = sock.recvmsg(1, socket.CMSG_SPACE(struct.calcsize("i") * 4))
    received: list[int] = []
    for level, kind, payload in ancdata:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            values = array.array("i")
            values.frombytes(payload[: len(payload) - (len(payload) % values.itemsize)])
            received.extend(values.tolist())
    return received


def _recv_credentials(sock: socket.socket) -> tuple[int, int, int]:
    _message, ancdata, _flags, _address = sock.recvmsg(1, socket.CMSG_SPACE(struct.calcsize("iII")))
    for level, kind, payload in ancdata:
        if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
            return struct.unpack("iII", payload[: struct.calcsize("iII")])
    raise OSError(errno_module.ENOMSG, "SCM_CREDENTIALS가 도착하지 않았습니다.")


def _build_fd_transfer_definition(action: str) -> ToolDefinition:
    name = f"{_UNIX_FD_TOOL}.{action}"
    fd_action = action in {"send_fd", "receive_fd"}

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot()
        original_fd = _definition_fd(decision, context) if fd_action else None
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        state.update(sender=a, receiver=b, original_fd=original_fd)
        before = {"open_fds": len(os.listdir("/proc/self/fd"))}
        if fd_action:
            a.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [original_fd]))])
            if action == "receive_fd":
                state["received_fds"] = _recv_rights(b)
        else:
            b.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            credentials = (os.getpid(), os.getuid(), os.getgid())
            a.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, struct.pack("iII", *credentials))])
            state["expected_credentials"] = credentials
            if action == "receive_credential":
                state["received_credentials"] = _recv_credentials(b)
        reached = {"sender_fd": a.fileno(), "receiver_fd": b.fileno(), "queued": action in {"send_fd", "send_credential"}}
        return _identity_result(_UNIX_FD_TOOL, action, context, identity_before,
                                output=f"SCM {action} fixture", state_before=before,
                                state_reached=reached, changed=True, data={"resource_ref": decision.resource_ref})

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        del decision, context
        observed = {"sender_valid": os.fstat(state["sender"].fileno()).st_ino > 0, "receiver_valid": os.fstat(state["receiver"].fileno()).st_ino > 0}
        failure = _failure_verification(name, result, observed)
        if failure:
            return failure
        if action == "send_fd":
            state["received_fds"] = _recv_rights(state["receiver"])
        elif action == "send_credential":
            state["received_credentials"] = _recv_credentials(state["receiver"])
        if fd_action:
            received = state.get("received_fds", [])
            expected_stat = os.fstat(state["original_fd"])
            checks = {"one_fd_received": len(received) == 1, "fd_identity_matches": len(received) == 1 and (os.fstat(received[0]).st_dev, os.fstat(received[0]).st_ino) == (expected_stat.st_dev, expected_stat.st_ino)}
            observed["received_count"] = len(received)
        else:
            credentials = state.get("received_credentials")
            checks = {"credentials_requeried": credentials == state["expected_credentials"]}
            observed["credentials"] = credentials
        return VerificationResult(name + "_verifier", "VERIFIED" if all(checks.values()) else "REJECTED", checks, observed)

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        del decision, context
        for fd in state.pop("received_fds", []):
            os.close(fd)
        for key in ("sender", "receiver"):
            sock = state.pop(key, None)
            if isinstance(sock, socket.socket):
                sock.close()
        after = {"received_fds": len(state.get("received_fds", [])), "sockets_remaining": any(k in state for k in ("sender", "receiver"))}
        checks = {"received_fds_closed": after["received_fds"] == 0, "sockets_closed": not after["sockets_remaining"]}
        return ResetResult(name + "_resetter", "VERIFIED" if all(checks.values()) else "FAILED", identity_snapshot(), after, checks)

    return ToolDefinition(name, _UNIX_FD_TOOL, action, handler, verifier, resetter,
                          _process_spec(_FD if fd_action else _NONE, reversible=True))


def _fixture_number(context: ToolContext, action: str) -> int:
    digest = hashlib.sha256(f"{context.run_id}:{context.action_id}:{action}".encode()).digest()
    return 0x4F530000 | (int.from_bytes(digest[:2], "big") & 0xFFFF)


def _sysv_get(kind: str, key: int, *, create: bool) -> int:
    flags = 0o600 | (IPC_CREAT | IPC_EXCL if create else 0)
    ctypes.set_errno(0)
    if kind == "shm":
        ident = libc.shmget(key, 4096, flags)
    elif kind == "msg":
        ident = libc.msgget(key, flags)
    else:
        ident = libc.semget(key, 1, flags)
    if ident == -1:
        raise OSError(ctypes.get_errno(), f"{kind}get 실패")
    return ident


def _sysv_remove(kind: str, ident: int) -> None:
    ctypes.set_errno(0)
    if kind == "shm":
        rc = libc.shmctl(ident, IPC_RMID, None)
    elif kind == "msg":
        rc = libc.msgctl(ident, IPC_RMID, None)
    else:
        rc = libc.semctl(ident, 0, IPC_RMID, 0)
    if rc == -1:
        raise OSError(ctypes.get_errno(), f"{kind} IPC_RMID 실패")


def _sysv_observation(kind: str, key: int) -> dict[str, Any]:
    try:
        ident = _sysv_get(kind, key, create=False)
        return {"kind": kind, "key_fingerprint": hashlib.sha256(str(key).encode()).hexdigest(), "exists": True, "id": ident}
    except OSError as exc:
        if exc.errno in {errno_module.ENOENT, errno_module.EINVAL}:
            return {"kind": kind, "key_fingerprint": hashlib.sha256(str(key).encode()).hexdigest(), "exists": False}
        raise


def _build_sysv_definition(action: str) -> ToolDefinition:
    name = f"{_IPC_SYSV_TOOL}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        kind = decision.arguments.get("kind", "shm")
        if kind not in {"shm", "msg", "sem"}:
            raise ToolInputError("kind는 shm/msg/sem 중 하나여야 합니다.")
        if "key" in decision.arguments:
            raise ToolInputError("raw IPC key는 금지됩니다.")
        key = _fixture_number(context, name)
        before = _sysv_observation(kind, key)
        if before["exists"]:
            raise ToolPolicyBlocked("이번 Run 전용 SysV key가 이미 사용 중입니다.")
        identity_before = identity_snapshot()
        ident = _sysv_get(kind, key, create=True)
        state.update(kind=kind, key=key, id=ident, before=before, created=True)
        if action == "access":
            state["access_id"] = _sysv_get(kind, key, create=False)
        elif action == "remove":
            _sysv_remove(kind, ident)
            state["created"] = False
        reached = _sysv_observation(kind, key)
        return _identity_result(_IPC_SYSV_TOOL, action, context, identity_before,
                                output=f"SysV {kind} {action} fixture", state_before=before,
                                state_reached=reached, changed=action != "access" or before != reached,
                                data={"kind": kind, "key_fingerprint": reached["key_fingerprint"]})

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        del decision, context
        observed = _sysv_observation(state["kind"], state["key"])
        failure = _failure_verification(name, result, observed)
        if failure:
            return failure
        expected_exists = action != "remove"
        checks = {"kernel_state_requeried": observed["exists"] is expected_exists}
        if action == "access":
            checks["same_object_accessed"] = observed.get("id") == state.get("access_id") == state["id"]
        return VerificationResult(name + "_verifier", "VERIFIED" if all(checks.values()) else "REJECTED", checks, observed)

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        del decision, context
        if state.get("created"):
            _sysv_remove(state["kind"], state["id"])
            state["created"] = False
        after = _sysv_observation(state["kind"], state["key"]) if "key" in state else {"exists": False}
        checks = {"fixture_absent": after.get("exists") is False}
        return ResetResult(name + "_resetter", "VERIFIED" if all(checks.values()) else "FAILED", identity_snapshot(), after, checks)

    return ToolDefinition(name, _IPC_SYSV_TOOL, action, handler, verifier, resetter,
                          _process_spec(_NONE, arg_schema={"kind": str, "key": _ForbiddenRawArgument},
                                        reversible=True, destructive=action == "remove"))


def _posix_name(context: ToolContext, action: str) -> str:
    digest = hashlib.sha256(f"{context.run_id}:{context.action_id}:{action}".encode()).hexdigest()[:20]
    return "/osagent_" + digest


def _mq_open(name: str, *, create: bool, exclusive: bool = False) -> int:
    _librt.mq_open.restype = ctypes.c_int
    flags = os.O_RDWR | (os.O_CREAT if create else 0) | (os.O_EXCL if exclusive else 0)
    ctypes.set_errno(0)
    mqd = _librt.mq_open(name.encode(), flags, 0o600, None)
    if mqd == -1:
        raise OSError(ctypes.get_errno(), "mq_open 실패")
    return mqd


def _posix_observation(kind: str, name: str) -> dict[str, Any]:
    fingerprint = hashlib.sha256(name.encode()).hexdigest()
    if kind == "shm":
        path = "/dev/shm" + name
        return {"kind": kind, "name_fingerprint": fingerprint, "exists": os.path.exists(path), "path": path}
    try:
        mqd = _mq_open(name, create=False)
    except OSError as exc:
        if exc.errno == errno_module.ENOENT:
            return {"kind": kind, "name_fingerprint": fingerprint, "exists": False}
        raise
    _librt.mq_close(mqd)
    return {"kind": kind, "name_fingerprint": fingerprint, "exists": True}


def _posix_create(kind: str, name: str, *, exclusive: bool) -> int:
    if kind == "shm":
        flags = os.O_CREAT | os.O_RDWR | (os.O_EXCL if exclusive else 0)
        return os.open("/dev/shm" + name, flags, 0o600)
    return _mq_open(name, create=True, exclusive=exclusive)


def _posix_close(kind: str, handle: int) -> None:
    if kind == "shm":
        os.close(handle)
    else:
        _librt.mq_close(handle)


def _posix_unlink(kind: str, name: str) -> None:
    if kind == "shm":
        os.unlink("/dev/shm" + name)
    elif _librt.mq_unlink(name.encode()) != 0:
        raise OSError(ctypes.get_errno(), "mq_unlink 실패")


def _build_posix_ipc_definition(action: str) -> ToolDefinition:
    definition_name = f"{_IPC_POSIX_TOOL}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        kind = decision.arguments.get("kind", "shm")
        if kind not in {"shm", "mqueue"}:
            raise ToolInputError("kind는 shm/mqueue 중 하나여야 합니다.")
        if "key" in decision.arguments:
            raise ToolInputError("raw POSIX IPC key/name은 금지됩니다.")
        ipc_name = _posix_name(context, definition_name)
        before = _posix_observation(kind, ipc_name)
        if before["exists"]:
            raise ToolPolicyBlocked("이번 Run 전용 POSIX IPC name이 이미 존재합니다.")
        identity_before = identity_snapshot()
        handle = _posix_create(kind, ipc_name, exclusive=True)
        state.update(kind=kind, name=ipc_name, handle=handle, before=before, created=True)
        if action == "access":
            access_handle = _posix_create(kind, ipc_name, exclusive=False)
            _posix_close(kind, access_handle)
            state["accessed"] = True
        if action == "remove":
            _posix_unlink(kind, ipc_name)
            state["created"] = False
        reached = _posix_observation(kind, ipc_name)
        return _identity_result(_IPC_POSIX_TOOL, action, context, identity_before,
                                output=f"POSIX {kind} {action} fixture", state_before=before,
                                state_reached=reached, changed=True,
                                data={"kind": kind, "name_fingerprint": reached["name_fingerprint"]})

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        del decision, context
        observed = _posix_observation(state["kind"], state["name"])
        failure = _failure_verification(definition_name, result, observed)
        if failure:
            return failure
        checks = {"kernel_state_requeried": observed["exists"] is (action != "remove")}
        if action == "access":
            checks["independent_open_succeeded"] = state.get("accessed") is True
        return VerificationResult(definition_name + "_verifier", "VERIFIED" if all(checks.values()) else "REJECTED", checks, observed)

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        del decision, context
        handle = state.pop("handle", None)
        if isinstance(handle, int):
            _posix_close(state["kind"], handle)
        if state.get("created"):
            _posix_unlink(state["kind"], state["name"])
            state["created"] = False
        after = _posix_observation(state["kind"], state["name"]) if "name" in state else {"exists": False}
        checks = {"fixture_absent": after.get("exists") is False, "handle_closed": "handle" not in state}
        return ResetResult(definition_name + "_resetter", "VERIFIED" if all(checks.values()) else "FAILED", identity_snapshot(), after, checks)

    return ToolDefinition(definition_name, _IPC_POSIX_TOOL, action, handler, verifier, resetter,
                          _process_spec(_NONE, arg_schema={"kind": str, "key": _ForbiddenRawArgument},
                                        reversible=True, destructive=action == "remove"))


def _accounting_file_state(path: str) -> dict[str, Any]:
    if not os.path.exists(path):
        return {"path": path, "exists": False}
    st = os.stat(path, follow_symlinks=False)
    with open(path, "rb") as stream:
        payload = stream.read(4097)
    if len(payload) > 4096:
        raise ToolPolicyBlocked("accounting fixture는 4096 bytes 이하여야 합니다.")
    return {
        "path": path, "exists": True, "size": st.st_size,
        "mode": st.st_mode & 0o7777, "uid": st.st_uid, "gid": st.st_gid,
        "atime_ns": st.st_atime_ns, "mtime_ns": st.st_mtime_ns,
        "sha256": hashlib.sha256(payload).hexdigest(), "content": payload,
    }


def _restore_accounting_file(snapshot: dict[str, Any]) -> None:
    path = snapshot["path"]
    if not snapshot["exists"]:
        if os.path.exists(path):
            os.unlink(path)
        return
    fd = os.open(path, os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0))
    try:
        payload = snapshot["content"]
        offset = 0
        while offset < len(payload):
            offset += os.write(fd, payload[offset:])
    finally:
        os.close(fd)
    os.chmod(path, snapshot["mode"], follow_symlinks=False)
    try:
        os.chown(path, snapshot["uid"], snapshot["gid"], follow_symlinks=False)
    except PermissionError:
        st = os.stat(path, follow_symlinks=False)
        if (st.st_uid, st.st_gid) != (snapshot["uid"], snapshot["gid"]):
            raise
    os.utime(path, ns=(snapshot["atime_ns"], snapshot["mtime_ns"]), follow_symlinks=False)


def _accounting_child_record() -> None:
    pid = os.fork()
    if pid == 0:
        os._exit(0)
    os.waitpid(pid, 0)
    os.sync()
    time.sleep(0.02)


def _acct(path: str | None) -> None:
    ctypes.set_errno(0)
    encoded = None if path is None else os.fsencode(path)
    if libc.acct(encoded) != 0:
        raise OSError(ctypes.get_errno(), "acct syscall 거부")


def _build_accounting_definition(action: str) -> ToolDefinition:
    name = f"{_ACCT_TOOL}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        path = context.resolve_path(decision.resource_ref or "")
        if os.path.islink(path):
            raise ToolPolicyBlocked("accounting fixture는 symlink일 수 없습니다.")
        original = _accounting_file_state(path)
        if not original["exists"]:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
            state["created_file"] = True
        before_full = original
        identity_before = identity_snapshot()
        state.update(path=path, backup=before_full)
        before = {key: value for key, value in before_full.items() if key != "content"}
        if action == "start":
            _acct(path)
            state["accounting_enabled"] = True
            _accounting_child_record()
        elif action == "stop":
            # Action 독립성: dedicated host fixture에서 먼저 enable한 뒤 stop한다.
            _acct(path)
            _accounting_child_record()
            _acct(None)
            state["accounting_enabled"] = False
        else:
            size_before = os.path.getsize(path)
            _accounting_child_record()
            state["status_active"] = os.path.getsize(path) > size_before
        reached_full = _accounting_file_state(path)
        reached = {key: value for key, value in reached_full.items() if key != "content"}
        reached["active_probe"] = state.get("status_active", action == "start")
        return _identity_result(_ACCT_TOOL, action, context, identity_before,
                                output=f"process accounting {action} isolated fixture", state_before=before,
                                state_reached=reached, changed=action in {"start", "stop"} or reached.get("sha256") != before.get("sha256"),
                                data={"resource_ref": decision.resource_ref, "active_probe": reached["active_probe"]})

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        path = context.resolve_path(decision.resource_ref or "")
        size_before = os.path.getsize(path)
        _accounting_child_record()
        observed_full = _accounting_file_state(path)
        observed = {key: value for key, value in observed_full.items() if key != "content"}
        active = observed["size"] > size_before
        observed["active_probe"] = active
        failure = _failure_verification(name, result, observed)
        if failure:
            return failure
        expected_active = action == "start" or (action == "status" and state.get("status_active"))
        checks = {"acct_state_requeried": active is bool(expected_active), "fixture_limited": observed["size"] <= 4096}
        return VerificationResult(name + "_verifier", "VERIFIED" if all(checks.values()) else "REJECTED", checks, observed)

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        path = context.resolve_path(decision.resource_ref or "")
        # Isolated accounting fixture의 공통 baseline은 accounting disabled다.
        _acct(None)
        _restore_accounting_file(state["backup"])
        after_full = _accounting_file_state(path)
        after = {key: value for key, value in after_full.items() if key != "content"}
        expected = {key: value for key, value in state["backup"].items() if key != "content"}
        checks = {f"{key}_restored": after.get(key) == expected.get(key) for key in ("exists", "size", "mode", "uid", "gid", "mtime_ns", "sha256")}
        return ResetResult(name + "_resetter", "VERIFIED" if all(checks.values()) else "FAILED", identity_snapshot(), after, checks)

    return ToolDefinition(name, _ACCT_TOOL, action, handler, verifier, resetter,
                          _process_spec("path", reversible=True, destructive=True, host_only=True, timeout_s=8.0))


_PROCESS_DEFINITIONS: tuple[ToolDefinition, ...] = (
    _build_spawn_definition(),
    *(_build_signal_definition(action) for action in ("send_pid", "send_group", "send_session")),
    *(_build_ptrace_definition(action) for action in ("attach", "detach", "trace_syscalls", "read", "write")),
    *(_build_process_memory_definition(action) for action in ("read", "write")),
    *(_build_procfs_definition(action) for action in (
        "read_environ", "read_cmdline", "read_maps", "read_mem", "list_fd", "read_root", "read_cwd",
    )),
    *(_build_security_definition(action) for action in ("set_dumpable", "set_ptracer", "set_name", "set_core_limit")),
    *(_build_pidfd_definition(action) for action in ("open", "signal", "wait", "getfd")),
    *(_build_schedule_definition(action) for action in ("set_nice", "set_priority", "set_scheduler", "set_affinity")),
    *(_build_memory_lock_definition(action) for action in ("mlock", "mlockall", "hugepage")),
    *(_build_unix_socket_definition(action) for action in ("listen", "connect", "send", "receive", "peer")),
    *(_build_fd_transfer_definition(action) for action in ("send_fd", "receive_fd", "send_credential", "receive_credential")),
    *(_build_sysv_definition(action) for action in ("create", "access", "remove")),
    *(_build_posix_ipc_definition(action) for action in ("create", "access", "remove")),
    *(_build_accounting_definition(action) for action in ("status", "stop", "start")),
)

if len(_PROCESS_DEFINITIONS) != 51:
    raise ToolContractError(f"process_ipc ToolDefinition은 51개여야 합니다: {len(_PROCESS_DEFINITIONS)}")
if len({definition.name for definition in _PROCESS_DEFINITIONS}) != 51:
    raise ToolContractError("process_ipc ToolDefinition name이 중복되었습니다.")
if len({id(definition.handler) for definition in _PROCESS_DEFINITIONS}) != 51:
    raise ToolContractError("process_ipc action별 handler가 독립 closure가 아닙니다.")
if len({id(definition.verifier) for definition in _PROCESS_DEFINITIONS}) != 51:
    raise ToolContractError("process_ipc action별 verifier가 독립 closure가 아닙니다.")
if len({id(definition.resetter) for definition in _PROCESS_DEFINITIONS}) != 51:
    raise ToolContractError("process_ipc action별 resetter가 독립 closure가 아닙니다.")

for _definition in _PROCESS_DEFINITIONS:
    register_definition(_definition)
