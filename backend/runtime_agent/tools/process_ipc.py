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
import os
import resource as resource_module
import socket
import struct
from typing import Any

from . import base
from .base import (
    ToolContext,
    ToolInputError,
    ToolOutcome,
    ToolPolicyBlocked,
    ToolSpec,
    attempt,
    bounded_content,
    enum_arg,
    int_arg,
    int_arg_default,
    probe,
    prctl,
    raw_syscall,
    register,
    register_verifier,
    str_arg,
)

libc = base.libc

PR_SET_NAME, PR_GET_NAME = 15, 16
PR_SET_DUMPABLE, PR_GET_DUMPABLE = 4, 3
PR_SET_PTRACER = 0x59616D61
PTRACE_PEEKDATA, PTRACE_POKEDATA = 2, 5
PTRACE_ATTACH, PTRACE_DETACH = 16, 17
PTRACE_SETOPTIONS, PTRACE_O_TRACESYSGOOD = 0x4200, 1

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
IPC_CREAT, IPC_RMID = 0o1000, 0
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
