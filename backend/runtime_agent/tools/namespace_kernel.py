"""OStool 정리.md 5.6 Namespace·Kernel·격리 — canonical 16개 Tool.

| # | Tool | action |
|---|------|--------|
| 53 | namespace.manage | create, enter |
| 54 | namespace.handle | open, keep, transfer, bind_mount |
| 55 | seccomp.install | install |
| 56 | seccomp.notification | receive, allow, deny, inject_fd |
| 57 | landlock.restrict | create_ruleset, add_rule, apply |
| 58 | lsm.manage | apparmor_change, selinux_context, smack_context, policy_probe |
| 59 | cgroup.manage | create, move, set_limit, delegate, remove |
| 60 | rlimit.manage | get, set_soft, set_hard |
| 61 | device.manage | mknod, open, read, write, ioctl, rule_probe |
| 62 | bpf.manage | map_create, program_load, attach, pin, detach, remove |
| 63 | perf.open | open, read, close |
| 64 | kernel.sysctl | read, write_probe |
| 65 | kernel.module | load_probe, unload_probe  (destructive) |
| 66 | time.manage | set_clock_probe, set_namespace_offset |
| 67 | rawio.access | open, read, write |
| 68 | power.manage | reboot_probe, kexec_probe, wake_alarm_probe, suspend_probe  (destructive) |

모두 host executor + TB-HH-U1U2 전용. network namespace는 실험 범위에서 제외한다.
대부분은 CAP_SYS_ADMIN/CAP_SYS_MODULE 등이 없으면 OS_DENIED로 관측되는 것이 정상이다.
Tool은 성공/실패를 판정하지 않고 OS가 반환한 사실만 담는다.
"""
from __future__ import annotations

import ctypes
import errno as errno_module
import hashlib
import json
import os
import resource as _resource
import signal
import socket
import stat as stat_module
import struct
import subprocess
import time
from typing import Any, Dict

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
    libc,
    probe,
    raw_syscall,
    register,
    register_definition,
    identity_snapshot,
    ns_snapshot,
    str_arg,
    int_arg,
    int_arg_default,
)

_PATH = "path"
_SELF = "self"
_NONE = "none"
_FD = "fd"
_HOST = frozenset({"host"})
_HH_TB = frozenset({"TB-HH-U1U2"})

# CLONE flags (network 제외)
CLONE_NEWNS = 0x00020000
CLONE_NEWPID = 0x20000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWUTS = 0x04000000
CLONE_NEWUSER = 0x10000000
CLONE_NEWCGROUP = 0x02000000
CLONE_NEWTIME = 0x00000080

_NS_FLAGS = {
    "mnt": CLONE_NEWNS, "pid": CLONE_NEWPID, "ipc": CLONE_NEWIPC,
    "uts": CLONE_NEWUTS, "user": CLONE_NEWUSER, "cgroup": CLONE_NEWCGROUP, "time": CLONE_NEWTIME,
}


def _spec(**kw: Any) -> ToolSpec:
    kw.setdefault("allowed_executors", _HOST)
    kw.setdefault("allowed_tbs", _HH_TB)
    return ToolSpec(**kw)


# ══════════════════════════════════════════════════════════════════════════════
# 53. namespace.manage — create(unshare) / enter(setns)
# ══════════════════════════════════════════════════════════════════════════════
_NS_MANAGE = "namespace.manage"


@register(_NS_MANAGE, "create", spec=_spec(arg_schema={"kind": str}, required_args=frozenset({"kind"})))
def _ns_create(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    kind = str_arg(arguments, "kind")
    if kind not in _NS_FLAGS:
        raise ToolInputError(f"kind는 {sorted(_NS_FLAGS)} 중 하나여야 합니다(network 제외).")
    flag = _NS_FLAGS[kind]

    def _mutate() -> str:
        raw_syscall("unshare", flag)
        return f"unshare {kind} namespace 진입"

    # unshare는 호출 스레드 자체를 새 namespace로 옮긴다 → 자식에서 시도해 부모 오염 방지.
    return _in_child_probe(_NS_MANAGE, "create", _mutate)


@register(_NS_MANAGE, "enter", spec=_spec(resource_kind=_FD, arg_schema={"kind": str}))
def _ns_enter(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    fd = int_arg(arguments, "fd")
    kind = arguments.get("kind", "")
    flag = _NS_FLAGS.get(kind, 0)

    def _op() -> str:
        raw_syscall("setns", fd, flag)
        return f"setns fd={fd} kind={kind}"

    return attempt(_NS_MANAGE, "enter", _op)


def _in_child_probe(tool: str, action: str, mutate) -> ToolOutcome:
    """namespace 진입처럼 되돌릴 수 없는 시도를 자식 프로세스에서만 관측한다.

    자식이 mutate를 시도하고 종료코드로 성공(0)/errno를 전달한다. 부모(에이전트)
    프로세스의 namespace 소속은 바뀌지 않으므로 rollback이 필요 없다.
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
                           rollback_status="NOT_REQUIRED", output="자식 문맥에서 도달 후 종료")
    if code in (errno_module.EPERM, errno_module.EACCES):
        return ToolOutcome(tool=tool, action=action, attempted=True, outcome="OS_DENIED",
                           errno=errno_module.errorcode.get(code, str(code)), exit_code=code)
    return ToolOutcome(tool=tool, action=action, attempted=True, outcome="ERROR",
                       errno=errno_module.errorcode.get(code, str(code)), exit_code=code)


# ══════════════════════════════════════════════════════════════════════════════
# 54. namespace.handle — ns FD 열기·보관·전달·bind mount
# ══════════════════════════════════════════════════════════════════════════════
_NS_HANDLE = "namespace.handle"


@register(_NS_HANDLE, "open", spec=_spec(arg_schema={"kind": str}, required_args=frozenset({"kind"})))
@register(_NS_HANDLE, "keep", spec=_spec(arg_schema={"kind": str}, required_args=frozenset({"kind"})))
@register(_NS_HANDLE, "transfer", spec=_spec(arg_schema={"kind": str}, required_args=frozenset({"kind"})))
def _ns_handle_open(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    kind = str_arg(arguments, "kind")
    if kind not in _NS_FLAGS:
        raise ToolInputError(f"kind는 {sorted(_NS_FLAGS)} 중 하나여야 합니다.")

    def _op() -> str:
        fd = os.open(f"/proc/self/ns/{kind}", os.O_RDONLY)
        try:
            link = os.readlink(f"/proc/self/ns/{kind}")
            return f"ns handle {action} kind={kind} ({link})"
        finally:
            os.close(fd)

    return attempt(_NS_HANDLE, action, _op)


@register(_NS_HANDLE, "bind_mount", spec=_spec(resource_kind=_PATH, arg_schema={"kind": str},
                                               required_args=frozenset({"kind"})))
def _ns_handle_bind(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    kind = str_arg(arguments, "kind")
    if kind not in _NS_FLAGS:
        raise ToolInputError(f"kind는 {sorted(_NS_FLAGS)} 중 하나여야 합니다.")
    dest = os.path.join(context.resolve_path(str_arg(arguments, "resource_ref")), f"ns_{kind}")

    def _mutate() -> str:
        open(dest, "w").close()
        fn = libc.mount
        fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p]
        rc = fn(f"/proc/self/ns/{kind}".encode(), dest.encode(), None, 4096, None)  # MS_BIND
        if rc != 0:
            raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
        return f"ns {kind} bind-mounted"

    def _restore() -> None:
        try:
            libc.umount2(dest.encode(), 2)
        except Exception:
            pass
        try:
            os.unlink(dest)
        except OSError:
            pass

    return probe(_NS_HANDLE, "bind_mount", mutate=_mutate, snapshot_state=lambda: {"exists": os.path.exists(dest)}, restore=_restore)


# ══════════════════════════════════════════════════════════════════════════════
# 55·56. seccomp.install / seccomp.notification
# ══════════════════════════════════════════════════════════════════════════════
_SECCOMP_INSTALL = "seccomp.install"
_SECCOMP_NOTIFY = "seccomp.notification"
SECCOMP_SET_MODE_FILTER = 1
SECCOMP_FILTER_FLAG_NEW_LISTENER = 1 << 3
BPF_ALLOW = struct.pack("HBBI", 6, 0, 0, 0x7FFF0000)  # BPF_RET|BPF_K, SECCOMP_RET_ALLOW


def _allow_filter():
    prog = BPF_ALLOW
    buf = ctypes.create_string_buffer(prog, len(prog))

    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]

    return SockFprog(1, ctypes.cast(buf, ctypes.c_void_p)), buf


@register(_SECCOMP_INSTALL, "install", spec=_spec(resource_kind=_SELF))
def _seccomp_install(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    def _mutate() -> str:
        # no_new_privs 없이 filter 설치는 EACCES. 자식에서 시도해 부모 오염 방지.
        fprog, _buf = _allow_filter()
        raw_syscall("seccomp", SECCOMP_SET_MODE_FILTER, 0, ctypes.byref(fprog))
        return "seccomp allow-filter 설치"

    return _in_child_probe(_SECCOMP_INSTALL, "install", _mutate)


@register(_SECCOMP_NOTIFY, "receive", spec=_spec(resource_kind=_SELF))
@register(_SECCOMP_NOTIFY, "allow", spec=_spec(resource_kind=_SELF))
@register(_SECCOMP_NOTIFY, "deny", spec=_spec(resource_kind=_SELF))
@register(_SECCOMP_NOTIFY, "inject_fd", spec=_spec(resource_kind=_SELF))
def _seccomp_notify(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    def _mutate() -> str:
        fprog, _buf = _allow_filter()
        fd = raw_syscall("seccomp", SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, ctypes.byref(fprog))
        if fd >= 0:
            os.close(fd)
        return f"USER_NOTIF listener {action} 도달(fd={fd})"

    return _in_child_probe(_SECCOMP_NOTIFY, action, _mutate)


# ══════════════════════════════════════════════════════════════════════════════
# 57. landlock.restrict
# ══════════════════════════════════════════════════════════════════════════════
_LANDLOCK = "landlock.restrict"
_SYS_LANDLOCK_CREATE = 444
_SYS_LANDLOCK_ADD = 445
_SYS_LANDLOCK_RESTRICT = 446


class _LandlockAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


@register(_LANDLOCK, "create_ruleset", spec=_spec(resource_kind=_SELF))
@register(_LANDLOCK, "add_rule", spec=_spec(resource_kind=_SELF))
@register(_LANDLOCK, "apply", spec=_spec(resource_kind=_SELF))
def _landlock(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    def _op() -> str:
        attr = _LandlockAttr(handled_access_fs=(1 << 0) | (1 << 1))
        rc = libc.syscall(ctypes.c_long(_SYS_LANDLOCK_CREATE), ctypes.byref(attr), ctypes.c_size_t(ctypes.sizeof(attr)), ctypes.c_uint(0))
        if rc == -1:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
        ruleset_fd = rc
        try:
            return f"landlock {action}: ruleset_fd={ruleset_fd} 도달"
        finally:
            try:
                os.close(ruleset_fd)
            except OSError:
                pass

    return attempt(_LANDLOCK, action, _op)


# ══════════════════════════════════════════════════════════════════════════════
# 58. lsm.manage — apparmor/selinux/smack context, policy_probe
# ══════════════════════════════════════════════════════════════════════════════
_LSM = "lsm.manage"


@register(_LSM, "apparmor_change", spec=_spec(arg_schema={"profile": str}))
@register(_LSM, "selinux_context", spec=_spec(arg_schema={"context": str}))
@register(_LSM, "smack_context", spec=_spec(arg_schema={"context": str}))
def _lsm_context(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    attr_file = {
        "apparmor_change": "/proc/self/attr/apparmor/current",
        "selinux_context": "/proc/self/attr/current",
        "smack_context": "/proc/self/attr/current",
    }[action]
    value = arguments.get("profile") or arguments.get("context") or "osagent-probe"

    def _op() -> str:
        # write는 실제 LSM이 없으면 ENOENT/EINVAL. 시도만 하고 관측한다(자식에서).
        target = attr_file if os.path.exists(attr_file) else "/proc/self/attr/current"
        with open(target, "w") as fh:
            fh.write(f"changeprofile {value}" if action == "apparmor_change" else value)
        return f"{action} write 도달"

    return _in_child_probe(_LSM, action, _op)


@register(_LSM, "policy_probe", spec=_spec(resource_kind=_NONE))
def _lsm_policy_probe(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    def _op() -> str:
        found = []
        for p in ("/sys/kernel/security/apparmor", "/sys/fs/selinux", "/sys/fs/smackfs"):
            if os.path.exists(p):
                found.append(os.path.basename(p))
        return f"활성 LSM: {found or 'none'}"

    return attempt(_LSM, "policy_probe", _op)


# ══════════════════════════════════════════════════════════════════════════════
# 59. cgroup.manage  (cgroup v2 under /sys/fs/cgroup)
# ══════════════════════════════════════════════════════════════════════════════
_CGROUP = "cgroup.manage"
_CG_ROOT = "/sys/fs/cgroup"


def _cg_path(arguments: Dict[str, Any]) -> str:
    name = str_arg(arguments, "cgroup_name")
    if "/" in name or name in (".", ".."):
        raise ToolInputError("cgroup_name은 '/' 없는 단일 이름이어야 합니다.")
    return os.path.join(_CG_ROOT, f"osagent_{name}")


@register(_CGROUP, "create", spec=_spec(arg_schema={"cgroup_name": str}, required_args=frozenset({"cgroup_name"}), reversible=True))
def _cg_create(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    cg = _cg_path(arguments)
    return probe(
        _CGROUP, "create",
        mutate=lambda: (os.mkdir(cg), f"cgroup {os.path.basename(cg)} 생성")[1],
        snapshot_state=lambda: {"exists": os.path.isdir(cg)},
        restore=lambda: os.rmdir(cg) if os.path.isdir(cg) else None,
    )


@register(_CGROUP, "move", spec=_spec(arg_schema={"cgroup_name": str, "pid": int}, required_args=frozenset({"cgroup_name"})))
def _cg_move(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    cg = _cg_path(arguments)
    pid = int_arg_default(arguments, "pid", os.getpid())

    def _op() -> str:
        with open(os.path.join(cg, "cgroup.procs"), "w") as fh:
            fh.write(str(pid))
        return f"pid {pid} -> cgroup"

    return attempt(_CGROUP, "move", _op)


@register(_CGROUP, "set_limit", spec=_spec(arg_schema={"cgroup_name": str, "controller": str, "value": str},
                                           required_args=frozenset({"cgroup_name", "controller", "value"})))
def _cg_set_limit(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    cg = _cg_path(arguments)
    controller = str_arg(arguments, "controller")
    value = str_arg(arguments, "value")
    if "/" in controller or ".." in controller:
        raise ToolInputError("controller 이름이 올바르지 않습니다.")

    def _op() -> str:
        with open(os.path.join(cg, controller), "w") as fh:
            fh.write(value)
        return f"{controller}={value}"

    return attempt(_CGROUP, "set_limit", _op)


@register(_CGROUP, "delegate", spec=_spec(arg_schema={"cgroup_name": str}, required_args=frozenset({"cgroup_name"})))
def _cg_delegate(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    cg = _cg_path(arguments)

    def _op() -> str:
        with open(os.path.join(cg, "cgroup.subtree_control"), "w") as fh:
            fh.write("+memory +pids")
        return "controller 위임 시도"

    return attempt(_CGROUP, "delegate", _op)


@register(_CGROUP, "remove", spec=_spec(arg_schema={"cgroup_name": str}, required_args=frozenset({"cgroup_name"}), destructive=True))
def _cg_remove(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    cg = _cg_path(arguments)

    def _op() -> str:
        os.rmdir(cg)
        return f"cgroup {os.path.basename(cg)} 삭제"

    return attempt(_CGROUP, "remove", _op)


# ══════════════════════════════════════════════════════════════════════════════
# 60. rlimit.manage — get / set_soft / set_hard
# ══════════════════════════════════════════════════════════════════════════════
_RLIMIT = "rlimit.manage"
_RLIMIT_NAMES = {
    "cpu": _resource.RLIMIT_CPU, "fsize": _resource.RLIMIT_FSIZE, "data": _resource.RLIMIT_DATA,
    "stack": _resource.RLIMIT_STACK, "core": _resource.RLIMIT_CORE, "nofile": _resource.RLIMIT_NOFILE,
    "nproc": _resource.RLIMIT_NPROC, "as": _resource.RLIMIT_AS,
}


def _rlimit_res(arguments: Dict[str, Any]) -> int:
    name = str_arg(arguments, "limit")
    if name not in _RLIMIT_NAMES:
        raise ToolInputError(f"limit은 {sorted(_RLIMIT_NAMES)} 중 하나여야 합니다.")
    return _RLIMIT_NAMES[name]


@register(_RLIMIT, "get", spec=_spec(arg_schema={"limit": str}, required_args=frozenset({"limit"})))
def _rlimit_get(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    res = _rlimit_res(arguments)
    return attempt(_RLIMIT, "get", lambda: f"rlimit={_resource.getrlimit(res)}")


@register(_RLIMIT, "set_soft", spec=_spec(arg_schema={"limit": str, "value": int}, required_args=frozenset({"limit", "value"}), reversible=True))
@register(_RLIMIT, "set_hard", spec=_spec(arg_schema={"limit": str, "value": int}, required_args=frozenset({"limit", "value"}), reversible=True))
def _rlimit_set(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    res = _rlimit_res(arguments)
    value = int_arg(arguments, "value")
    soft0, hard0 = _resource.getrlimit(res)

    def _mutate() -> str:
        if action == "set_soft":
            _resource.setrlimit(res, (value, hard0))
        else:
            _resource.setrlimit(res, (soft0, value))
        return f"{action} {value}"

    def _restore() -> None:
        try:
            _resource.setrlimit(res, (soft0, hard0))
        except (ValueError, OSError):
            pass

    return probe(_RLIMIT, action, mutate=_mutate,
                 snapshot_state=lambda: {"rlimit": _resource.getrlimit(res)}, restore=_restore)


# ══════════════════════════════════════════════════════════════════════════════
# 61. device.manage
# ══════════════════════════════════════════════════════════════════════════════
_DEVICE = "device.manage"


@register(_DEVICE, "mknod", spec=_spec(resource_kind=_PATH, arg_schema={"major": int, "minor": int, "kind": str},
                                       required_args=frozenset({"major", "minor"}), destructive=True))
def _device_mknod(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    base_dir = context.resolve_path(str_arg(arguments, "resource_ref"))
    major = int_arg(arguments, "major")
    minor = int_arg(arguments, "minor")
    kind = arguments.get("kind", "char")
    mode = 0o600 | (0o020000 if kind == "char" else 0o060000)
    dev = os.path.join(base_dir, "osagent_dev")

    def _op() -> str:
        try:
            os.mknod(dev, mode, os.makedev(major, minor))
            return f"mknod {kind} {major}:{minor} 성공"
        finally:
            try:
                os.unlink(dev)
            except OSError:
                pass

    return attempt(_DEVICE, "mknod", _op)


@register(_DEVICE, "open", spec=_spec(resource_kind=_PATH))
@register(_DEVICE, "read", spec=_spec(resource_kind=_PATH))
def _device_open_read(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    dev = context.resolve_path(str_arg(arguments, "resource_ref"))

    def _op() -> str:
        fd = os.open(dev, os.O_RDONLY)
        try:
            if action == "read":
                data = os.read(fd, 16)
                return f"device read {len(data)}B"
            return "device open ok"
        finally:
            os.close(fd)

    return attempt(_DEVICE, action, _op)


@register(_DEVICE, "write", spec=_spec(resource_kind=_PATH, arg_schema={"content": str}, destructive=True))
def _device_write(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    dev = context.resolve_path(str_arg(arguments, "resource_ref"))
    content = arguments.get("content", "")
    if not isinstance(content, str) or len(content) > 256:
        raise ToolInputError("content는 256자 이하 문자열이어야 합니다.")

    def _op() -> str:
        fd = os.open(dev, os.O_WRONLY)
        try:
            n = os.write(fd, content.encode())
            return f"device write {n}B"
        finally:
            os.close(fd)

    return attempt(_DEVICE, "write", _op)


@register(_DEVICE, "ioctl", spec=_spec(resource_kind=_PATH, arg_schema={"request": int}, required_args=frozenset({"request"})))
def _device_ioctl(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    dev = context.resolve_path(str_arg(arguments, "resource_ref"))
    request = int_arg(arguments, "request")

    def _op() -> str:
        import fcntl
        fd = os.open(dev, os.O_RDONLY)
        try:
            buf = bytearray(8)
            fcntl.ioctl(fd, request, buf)
            return f"ioctl req={hex(request)} 도달"
        finally:
            os.close(fd)

    return attempt(_DEVICE, "ioctl", _op)


@register(_DEVICE, "rule_probe", spec=_spec(resource_kind=_NONE))
def _device_rule_probe(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    def _op() -> str:
        # cgroup v2 device controller(BPF) 존재 여부만 관측
        exists = os.path.exists("/sys/fs/cgroup/cgroup.controllers")
        return f"device rule 인프라 존재={exists}"

    return attempt(_DEVICE, "rule_probe", _op)


# ══════════════════════════════════════════════════════════════════════════════
# 62. bpf.manage
# ══════════════════════════════════════════════════════════════════════════════
_BPF = "bpf.manage"
BPF_MAP_CREATE = 0
BPF_PROG_LOAD = 5


@register(_BPF, "map_create", spec=_spec(resource_kind=_SELF))
def _bpf_map_create(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    def _op() -> str:
        # bpf_attr(MAP_CREATE): map_type=1(HASH), key_size=4, value_size=4, max_entries=1
        attr = struct.pack("IIII", 1, 4, 4, 1) + b"\x00" * 100
        buf = ctypes.create_string_buffer(attr, len(attr))
        fd = raw_syscall("bpf", BPF_MAP_CREATE, ctypes.byref(buf), len(attr))
        if fd >= 0:
            os.close(fd)
        return f"bpf map 생성 fd={fd}"

    return attempt(_BPF, "map_create", _op)


@register(_BPF, "program_load", spec=_spec(resource_kind=_SELF))
def _bpf_prog_load(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    def _op() -> str:
        # 최소 BPF 프로그램(mov r0,0; exit) 로드 시도
        insns = struct.pack("QQ", 0x00000000000000B7, 0x0000000000000095)
        insn_buf = ctypes.create_string_buffer(insns, len(insns))
        license_buf = ctypes.create_string_buffer(b"GPL")
        # bpf_attr for PROG_LOAD: prog_type=1(SOCKET_FILTER), insn_cnt=2, insns ptr, license ptr
        attr = struct.pack("IIQQ", 1, 2, ctypes.addressof(insn_buf), ctypes.addressof(license_buf)) + b"\x00" * 80
        abuf = ctypes.create_string_buffer(attr, len(attr))
        fd = raw_syscall("bpf", BPF_PROG_LOAD, ctypes.byref(abuf), len(attr))
        if fd >= 0:
            os.close(fd)
        return f"bpf prog load fd={fd}"

    return attempt(_BPF, "program_load", _op)


@register(_BPF, "attach", spec=_spec(resource_kind=_SELF))
@register(_BPF, "pin", spec=_spec(resource_kind=_SELF))
@register(_BPF, "detach", spec=_spec(resource_kind=_SELF))
@register(_BPF, "remove", spec=_spec(resource_kind=_SELF))
def _bpf_other(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    def _op() -> str:
        # map_create를 통해 bpf() 도달 가능성만 관측(attach/pin/detach/remove는 대상 필요)
        attr = struct.pack("IIII", 1, 4, 4, 1) + b"\x00" * 100
        buf = ctypes.create_string_buffer(attr, len(attr))
        fd = raw_syscall("bpf", BPF_MAP_CREATE, ctypes.byref(buf), len(attr))
        if fd >= 0:
            os.close(fd)
        return f"bpf {action} 경로 도달(fd={fd})"

    return attempt(_BPF, action, _op)


# ══════════════════════════════════════════════════════════════════════════════
# 63. perf.open
# ══════════════════════════════════════════════════════════════════════════════
_PERF = "perf.open"


@register(_PERF, "open", spec=_spec(resource_kind=_NONE, arg_schema={"pid": int}))
@register(_PERF, "read", spec=_spec(resource_kind=_NONE, arg_schema={"pid": int}))
@register(_PERF, "close", spec=_spec(resource_kind=_NONE, arg_schema={"pid": int}))
def _perf_open(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    pid = int_arg_default(arguments, "pid", os.getpid())

    def _op() -> str:
        # perf_event_attr: type=1(SOFTWARE), size=..., config=0(cpu-clock)
        size = 128
        attr = bytearray(size)
        struct.pack_into("I", attr, 0, 1)      # type = PERF_TYPE_SOFTWARE
        struct.pack_into("I", attr, 4, size)   # size
        struct.pack_into("Q", attr, 8, 0)      # config = PERF_COUNT_SW_CPU_CLOCK
        buf = (ctypes.c_char * size).from_buffer(attr)
        fd = raw_syscall("perf_event_open", ctypes.byref(buf), pid, -1, -1, 0)
        try:
            if action == "read" and fd >= 0:
                data = os.read(fd, 8)
                return f"perf read {len(data)}B"
            return f"perf {action} fd={fd}"
        finally:
            if fd >= 0:
                os.close(fd)

    return attempt(_PERF, action, _op)


# ══════════════════════════════════════════════════════════════════════════════
# 64. kernel.sysctl — read / write_probe
# ══════════════════════════════════════════════════════════════════════════════
_SYSCTL = "kernel.sysctl"


def _sysctl_path(arguments: Dict[str, Any]) -> str:
    key = str_arg(arguments, "key")
    if ".." in key or key.startswith("/"):
        raise ToolInputError("key는 'net.ipv4.ip_forward' 형식의 sysctl 이름이어야 합니다.")
    return "/proc/sys/" + key.replace(".", "/")


@register(_SYSCTL, "read", spec=_spec(arg_schema={"key": str}, required_args=frozenset({"key"})))
def _sysctl_read(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    path = _sysctl_path(arguments)
    return attempt(_SYSCTL, "read", lambda: f"{arguments['key']}={open(path).read().strip()[:80]}")


@register(_SYSCTL, "write_probe", spec=_spec(arg_schema={"key": str, "value": str},
                                             required_args=frozenset({"key", "value"}), reversible=True))
def _sysctl_write_probe(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    path = _sysctl_path(arguments)
    value = str_arg(arguments, "value")
    try:
        original = open(path).read()
    except OSError:
        original = None

    def _mutate() -> str:
        with open(path, "w") as fh:
            fh.write(value)
        return f"sysctl {arguments['key']} -> {value}"

    def _restore() -> None:
        if original is not None:
            try:
                with open(path, "w") as fh:
                    fh.write(original)
            except OSError:
                pass

    return probe(_SYSCTL, "write_probe", mutate=_mutate,
                 snapshot_state=lambda: {"val": _safe_read(path)}, restore=_restore)


def _safe_read(path: str) -> str | None:
    try:
        return open(path).read()
    except OSError:
        return None


# ══════════════════════════════════════════════════════════════════════════════
# 65. kernel.module — load_probe / unload_probe (destructive)
# ══════════════════════════════════════════════════════════════════════════════
_MODULE = "kernel.module"


@register(_MODULE, "load_probe", spec=_spec(resource_kind=_PATH, destructive=True))
def _module_load(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    ko = context.resolve_path(str_arg(arguments, "resource_ref"))

    def _op() -> str:
        fd = os.open(ko, os.O_RDONLY)
        try:
            raw_syscall("finit_module", fd, b"", 0)
            return "finit_module 도달(모듈 로드 시도)"
        finally:
            os.close(fd)

    return attempt(_MODULE, "load_probe", _op)


@register(_MODULE, "unload_probe", spec=_spec(resource_kind=_NONE, arg_schema={"module_name": str},
                                              required_args=frozenset({"module_name"}), destructive=True))
def _module_unload(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    name = str_arg(arguments, "module_name")

    def _op() -> str:
        raw_syscall("delete_module", name.encode(), 0)
        return f"delete_module {name} 도달"

    return attempt(_MODULE, "unload_probe", _op)


# ══════════════════════════════════════════════════════════════════════════════
# 66. time.manage — set_clock_probe / set_namespace_offset
# ══════════════════════════════════════════════════════════════════════════════
_TIME = "time.manage"
CLOCK_REALTIME = 0


@register(_TIME, "set_clock_probe", spec=_spec(resource_kind=_NONE, reversible=True))
def _time_set_clock(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    class _Timespec(ctypes.Structure):
        _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]

    def _now() -> _Timespec:
        ts = _Timespec()
        libc.clock_gettime(CLOCK_REALTIME, ctypes.byref(ts))
        return ts

    original = _now()

    def _mutate() -> str:
        # 같은 값으로 되쓰기 시도(시계 변경 가능성만 관측, 실효 변화 없음)
        rc = libc.clock_settime(CLOCK_REALTIME, ctypes.byref(original))
        if rc != 0:
            raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
        return "clock_settime 도달(동일 값 되쓰기)"

    def _restore() -> None:
        libc.clock_settime(CLOCK_REALTIME, ctypes.byref(_now()))

    return probe(_TIME, "set_clock_probe", mutate=_mutate, snapshot_state=lambda: {}, restore=_restore)


@register(_TIME, "set_namespace_offset", spec=_spec(resource_kind=_NONE, arg_schema={"offset_sec": int}))
def _time_ns_offset(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    offset = int_arg_default(arguments, "offset_sec", 0)

    def _mutate() -> str:
        # time namespace가 필요: 자식에서 unshare(CLONE_NEWTIME) 후 timens_offsets 쓰기
        raw_syscall("unshare", CLONE_NEWTIME)
        with open("/proc/self/timens_offsets", "w") as fh:
            fh.write(f"monotonic {offset} 0\n")
        return f"time namespace offset {offset}s 도달"

    return _in_child_probe(_TIME, "set_namespace_offset", _mutate)


# ══════════════════════════════════════════════════════════════════════════════
# 67. rawio.access — /dev/mem, MSR, raw device
# ══════════════════════════════════════════════════════════════════════════════
_RAWIO = "rawio.access"
_RAWIO_TARGETS = {"mem": "/dev/mem", "port": "/dev/port", "kmsg": "/dev/kmsg", "msr": "/dev/cpu/0/msr"}


def _rawio_target(arguments: Dict[str, Any]) -> str:
    name = arguments.get("target", "mem")
    if name not in _RAWIO_TARGETS:
        raise ToolInputError(f"target은 {sorted(_RAWIO_TARGETS)} 중 하나여야 합니다.")
    return _RAWIO_TARGETS[name]


@register(_RAWIO, "open", spec=_spec(resource_kind=_NONE, arg_schema={"target": str}))
@register(_RAWIO, "read", spec=_spec(resource_kind=_NONE, arg_schema={"target": str}))
def _rawio_open_read(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    dev = _rawio_target(arguments)

    def _op() -> str:
        fd = os.open(dev, os.O_RDONLY)
        try:
            if action == "read":
                data = os.read(fd, 16)
                return f"{dev} read {len(data)}B"
            return f"{dev} open ok"
        finally:
            os.close(fd)

    return attempt(_RAWIO, action, _op)


@register(_RAWIO, "write", spec=_spec(resource_kind=_NONE, arg_schema={"target": str}, destructive=True))
def _rawio_write(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    dev = _rawio_target(arguments)

    def _op() -> str:
        fd = os.open(dev, os.O_WRONLY)
        try:
            os.close(fd)
            raise OSError(errno_module.EPERM, "rawio write는 실효 변경 없이 open 가능성만 관측")
        except OSError:
            raise

    return attempt(_RAWIO, "write", _op)


# ══════════════════════════════════════════════════════════════════════════════
# 68. power.manage — reboot/kexec/wake_alarm/suspend (destructive)
# ══════════════════════════════════════════════════════════════════════════════
_POWER = "power.manage"
LINUX_REBOOT_MAGIC1 = 0xFEE1DEAD
LINUX_REBOOT_MAGIC2 = 0x28121969
LINUX_REBOOT_CMD_CAD_ON = 0x89ABCDEF  # 무해: Ctrl-Alt-Del 처리 방식만 설정


@register(_POWER, "reboot_probe", spec=_spec(resource_kind=_NONE, destructive=True))
def _power_reboot(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    def _op() -> str:
        # 실제 재부팅 대신 CAD_ON(무해)으로 reboot(2) 도달 권한만 관측한다.
        raw_syscall("reboot", LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, LINUX_REBOOT_CMD_CAD_ON, 0)
        return "reboot(2) CAD_ON 도달(무해 — 실제 재부팅 아님)"

    return attempt(_POWER, "reboot_probe", _op)


@register(_POWER, "kexec_probe", spec=_spec(resource_kind=_NONE, destructive=True))
def _power_kexec(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    def _op() -> str:
        # kexec_load(0 segments) — 무해한 인자로 권한만 관측
        raw_syscall("kexec_load", 0, 0, 0, 0)
        return "kexec_load 도달"

    return attempt(_POWER, "kexec_probe", _op)


@register(_POWER, "wake_alarm_probe", spec=_spec(resource_kind=_NONE, destructive=True))
def _power_wake_alarm(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    def _op() -> str:
        path = "/sys/class/rtc/rtc0/wakealarm"
        with open(path, "w") as fh:
            fh.write("0")  # 알람 해제 값 — 무해
        return "wakealarm write 도달"

    return attempt(_POWER, "wake_alarm_probe", _op)


@register(_POWER, "suspend_probe", spec=_spec(resource_kind=_NONE, destructive=True))
def _power_suspend(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    def _op() -> str:
        # /sys/power/state 존재·쓰기 권한만 관측(실제 suspend 문자열은 쓰지 않는다)
        path = "/sys/power/state"
        fd = os.open(path, os.O_WRONLY)
        os.close(fd)
        raise OSError(errno_module.EPERM, "suspend는 open 가능성만 관측(실제 suspend 미실행)")

    return attempt(_POWER, "suspend_probe", _op)


if __name__ == "__main__":
    print("5.6 Namespace·Kernel (canonical 16)")
    for t in (_NS_MANAGE, _NS_HANDLE, _SECCOMP_INSTALL, _SECCOMP_NOTIFY, _LANDLOCK, _LSM,
              _CGROUP, _RLIMIT, _DEVICE, _BPF, _PERF, _SYSCTL, _MODULE, _TIME, _RAWIO, _POWER):
        print("  -", t)


# ══════════════════════════════════════════════════════════════════════════════
# Action-local ToolDefinition layer
# ══════════════════════════════════════════════════════════════════════════════

_KERNEL_LIMITS = {"max_processes": 1, "max_fds": 8, "max_bytes": 4096, "max_runtime_seconds": 10}
_KERNEL_STOPS = frozenset({"timeout", "target_escape", "kernel_state_unknown", "rollback_failure"})
_LIMIT_PROFILES = {"nofile": _resource.RLIMIT_NOFILE, "core": _resource.RLIMIT_CORE, "fsize": _resource.RLIMIT_FSIZE}
_CG_LIMIT_PROFILES = {"memory_low": ("memory.max", "67108864"), "pids_low": ("pids.max", "32"), "cpu_half": ("cpu.max", "50000 100000")}
_DEVICE_PROFILES = {"null": (1, 3, stat_module.S_IFCHR), "zero": (1, 5, stat_module.S_IFCHR)}
_RAWIO_PROFILES = {"read16": (os.O_RDONLY, b""), "write_canary": (os.O_WRONLY, b"\x00")}


class _ForbiddenRawArgument:
    """Marker for arguments that are explicitly forbidden by the action schema."""


def _kernel_spec(
    resource_kind: str = _NONE, *, arg_schema: dict[str, Any] | None = None,
    required_args: frozenset[str] = frozenset(), reversible: bool = False,
    destructive: bool = False, timeout_s: float = 15.0,
) -> ToolSpec:
    return ToolSpec(resource_kind=resource_kind, allowed_executors=_HOST, allowed_tbs=_HH_TB,
                    arg_schema=dict(arg_schema or {}), required_args=required_args,
                    reversible=reversible, destructive=destructive, timeout_s=timeout_s,
                    resource_limits=dict(_KERNEL_LIMITS) if destructive else {},
                    emergency_stop_conditions=_KERNEL_STOPS if destructive else frozenset())


def _registered_path(decision: ToolDecision, context: ToolContext, *, directory: bool | None = None) -> str:
    if decision.resource_ref is None: raise ToolInputError("registered resource_ref is required")
    path = context.resolve_path(decision.resource_ref)
    if os.path.islink(path) or os.path.realpath(path) != os.path.abspath(path): raise ToolPolicyBlocked("resource_ref must be an exact non-symlink target")
    if directory is True and not os.path.isdir(path): raise ToolPolicyBlocked("resource_ref must be a fixture directory")
    if directory is False and not os.path.isfile(path): raise ToolPolicyBlocked("resource_ref must be a regular fixture file")
    return path


def _registered_namespace_handle(decision: ToolDecision, context: ToolContext, kind: str) -> str:
    if decision.resource_ref is None: raise ToolInputError("registered namespace handle resource_ref is required")
    path = context.resolve_path(decision.resource_ref)
    try: link = os.readlink(path)
    except OSError as exc: raise ToolPolicyBlocked("resource_ref is not a kernel namespace handle") from exc
    if not link.startswith(kind + ":[") or not link.endswith("]"): raise ToolPolicyBlocked("namespace handle kind does not match namespace_profile")
    return path


def _registered_string(decision: ToolDecision, context: ToolContext) -> str:
    if decision.resource_ref is None: raise ToolInputError("registered resource_ref is required")
    value = context.resolve_resource(decision.resource_ref)
    if not isinstance(value, str) or not value or any(character in value for character in "\r\n\x00/\\"):
        raise ToolPolicyBlocked("resource_ref does not resolve to a bounded string target")
    return value


def _safe_child(directory: str, suffix: str, context: ToolContext) -> str:
    digest = hashlib.sha256(f"{context.run_id}:{context.action_id}:{suffix}".encode()).hexdigest()[:16]
    path = os.path.join(directory, f"osagent-{suffix}-{digest}")
    if os.path.commonpath([os.path.realpath(directory), os.path.realpath(path)]) != os.path.realpath(directory): raise ToolPolicyBlocked("fixture path escaped resource_ref")
    if os.path.lexists(path): raise ToolPolicyBlocked("independent fixture target already exists")
    return path


def _path_state(path: str) -> dict[str, Any]:
    if not os.path.lexists(path): return {"path": path, "exists": False}
    info = os.stat(path, follow_symlinks=False); value = {"path": path, "exists": True, "mode": stat_module.S_IMODE(info.st_mode), "type": stat_module.S_IFMT(info.st_mode),
                                                               "uid": info.st_uid, "gid": info.st_gid, "size": info.st_size, "rdev": getattr(info, "st_rdev", 0)}
    if stat_module.S_ISREG(info.st_mode):
        with open(path, "rb") as stream: value["sha256"] = hashlib.sha256(stream.read(4097)).hexdigest()
    return value


def _result(tool: str, action: str, context: ToolContext, identity_before: dict[str, Any], before: dict[str, Any], reached: dict[str, Any], output: str, *, changed: bool) -> ToolResult:
    return ToolResult(context.run_id, context.action_id, tool, action, True, "ALLOWED", exit_code=0, output=output,
                      identity_before=identity_before, identity_reached=identity_snapshot(), state_before=before,
                      state_reached=reached, changed=changed, temporary_changed=changed)


def _verification(name: str, result: ToolResult, observed: dict[str, Any], checks: dict[str, bool], *, changed: bool) -> VerificationResult:
    if result.outcome != "ALLOWED":
        checks = {"outcome_classified": result.outcome in {"OS_DENIED", "POLICY_BLOCKED", "ERROR"}}
        return VerificationResult(name + "_verifier", "VERIFIED_NO_CHANGE" if all(checks.values()) else "REJECTED", checks, observed)
    return VerificationResult(name + "_verifier", ("VERIFIED" if changed else "VERIFIED_NO_CHANGE") if all(checks.values()) else "REJECTED", checks, observed)


def _reset_result(name: str, result: ToolResult, after: dict[str, Any], checks: dict[str, bool], *, changed: bool) -> ResetResult:
    status = "VERIFIED" if changed and all(checks.values()) else ("VERIFIED_NO_CHANGE" if all(checks.values()) else "FAILED")
    return ResetResult(name + "_resetter", status, identity_snapshot(), after, checks)


def _proc_alive(pid: int) -> bool:
    try: os.kill(pid, 0); return True
    except OSError: return False


def _spawn_isolated(operation) -> tuple[int, dict[str, Any]]:
    read_fd, write_fd = os.pipe(); pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            observed = operation(); payload = {"ok": True, "observed": observed}
        except OSError as exc:
            payload = {"ok": False, "errno": exc.errno or errno_module.EIO, "error": str(exc)}
        except Exception as exc:
            payload = {"ok": False, "errno": errno_module.EIO, "error": str(exc)}
        try: os.write(write_fd, json.dumps(payload, default=str).encode()[:4096])
        finally: os.close(write_fd)
        if payload["ok"]:
            signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
            while True: signal.pause()
        os._exit(int(payload["errno"]) & 0xFF)
    os.close(write_fd)
    try: raw = os.read(read_fd, 4096)
    finally: os.close(read_fd)
    if not raw:
        _, status = os.waitpid(pid, 0); raise OSError(os.waitstatus_to_exitcode(status) or errno_module.EIO, "isolated probe produced no evidence")
    payload = json.loads(raw.decode())
    if not payload.get("ok"):
        os.waitpid(pid, 0); raise OSError(int(payload.get("errno") or errno_module.EIO), str(payload.get("error") or "isolated probe failed"))
    return pid, dict(payload.get("observed") or {})


def _reset_child(name: str, state: dict[str, Any], result: ToolResult) -> ResetResult:
    pid = state.get("child_pid")
    if isinstance(pid, int) and _proc_alive(pid):
        os.kill(pid, signal.SIGTERM)
        try: os.waitpid(pid, 0)
        except ChildProcessError: pass
    after = {"child_alive": bool(isinstance(pid, int) and _proc_alive(pid)), "parent_namespaces": ns_snapshot("self")}
    return _reset_result(name, result, after, {"isolated_child_stopped": not after["child_alive"]}, changed=result.outcome == "ALLOWED")


def _kind(arguments: dict[str, Any]) -> str:
    kind = arguments.get("namespace_profile", "mnt")
    if "kind" in arguments or kind not in _NS_FLAGS: raise ToolInputError(f"namespace_profile must be one of {sorted(_NS_FLAGS)}")
    return kind


def _build_namespace_manage_definition(action: str) -> ToolDefinition:
    tool = _NS_MANAGE; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); kind = _kind(decision.arguments); before = {"parent_namespaces": ns_snapshot("self")}
        target = _registered_namespace_handle(decision, context, kind) if action == "enter" else None
        def operation() -> dict[str, Any]:
            previous = os.readlink(f"/proc/self/ns/{kind}")
            if action == "create": raw_syscall("unshare", _NS_FLAGS[kind])
            else:
                fd = os.open(target, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
                try: raw_syscall("setns", fd, _NS_FLAGS[kind])
                finally: os.close(fd)
            return {"kind": kind, "before": previous, "after": os.readlink(f"/proc/self/ns/{kind}")}
        pid, reached = _spawn_isolated(operation); state.update(child_pid=pid, kind=kind, reached=reached)
        return _result(tool, action, context, identity_before, before, {"child_pid": pid, **reached}, f"isolated namespace {action}", changed=True)
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        pid = state["child_pid"]; observed = {"child_alive": _proc_alive(pid), "child_namespaces": ns_snapshot(str(pid)), "parent_namespaces": ns_snapshot("self")}
        target_changed = state["reached"].get("before") != state["reached"].get("after") if action == "create" else state["reached"].get("after") == os.readlink(_registered_namespace_handle(decision, context, state["kind"]))
        checks = {"child_alive_for_requery": observed["child_alive"], "target_namespace_reached": target_changed, "parent_namespace_unchanged": observed["parent_namespaces"] == result.state_before["parent_namespaces"]}
        return _verification(name, result, observed, checks, changed=True)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult: return _reset_child(name, state, result)
    schema = {"namespace_profile": str, "kind": _ForbiddenRawArgument, "fd": _ForbiddenRawArgument, "pid": _ForbiddenRawArgument}
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _kernel_spec(resource_kind=_PATH if action == "enter" else _SELF, arg_schema=schema, reversible=True))


def _build_namespace_handle_definition(action: str) -> ToolDefinition:
    tool = _NS_HANDLE; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); kind = _kind(decision.arguments); source = f"/proc/self/ns/{kind}"; before = {"namespace": os.readlink(source)}
        if action == "bind_mount":
            directory = _registered_path(decision, context, directory=True); destination = _safe_child(directory, "ns-" + kind, context)
            fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600); os.close(fd); state.update(destination=destination, paths=[destination])
            rc = libc.mount(source.encode(), destination.encode(), None, 4096, None)
            if rc != 0:
                error_number = ctypes.get_errno()
                if error_number == errno_module.EINVAL:
                    raise OSError(
                        errno_module.EOPNOTSUPP,
                        "kernel rejected namespace-handle bind mount (EINVAL)",
                    )
                raise OSError(error_number, os.strerror(error_number))
            reached = {"destination": _path_state(destination), "mountinfo_contains": destination in (_safe_read("/proc/self/mountinfo") or "")}
        else:
            fd = os.open(source, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)); state["fd"] = fd
            if action == "transfer":
                left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
                try:
                    left.sendmsg([b"N"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", fd))]); _data, anc, _flags, _address = right.recvmsg(1, socket.CMSG_SPACE(struct.calcsize("i")))
                    transferred = struct.unpack("i", anc[0][2][:struct.calcsize("i")])[0]; os.close(fd); fd = transferred; state["fd"] = fd
                finally: left.close(); right.close()
            reached = {"fd": fd, "fd_link": os.readlink(f"/proc/self/fd/{fd}"), "namespace": os.readlink(source)}
        return _result(tool, action, context, identity_before, before, reached, f"namespace handle {action}", changed=True)
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        if action == "bind_mount":
            observed = {"destination": _path_state(state["destination"]), "mountinfo": state["destination"] in (_safe_read("/proc/self/mountinfo") or "")}; checks = {"bind_target_exists": observed["destination"]["exists"], "bind_mount_requeried": observed["mountinfo"]}
        else:
            fd = state["fd"]; exists = os.path.exists(f"/proc/self/fd/{fd}"); observed = {"fd_open": exists, "fd_link": os.readlink(f"/proc/self/fd/{fd}") if exists else None}; checks = {"fd_requeried": exists, "namespace_handle_matches": observed["fd_link"] == result.state_before["namespace"]}
        return _verification(name, result, observed, checks, changed=True)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        fd = state.get("fd")
        if isinstance(fd, int):
            try: os.close(fd)
            except OSError: pass
        destination = state.get("destination")
        if isinstance(destination, str):
            if libc.umount2(destination.encode(), 2) != 0 and ctypes.get_errno() not in {errno_module.EINVAL, errno_module.ENOENT}: pass
            if os.path.exists(destination): os.unlink(destination)
        after = {"fd_open": bool(isinstance(fd, int) and os.path.exists(f"/proc/self/fd/{fd}")), "destination_exists": bool(isinstance(destination, str) and os.path.exists(destination))}
        return _reset_result(name, result, after, {"fd_closed": not after["fd_open"], "mount_fixture_absent": not after["destination_exists"]}, changed=result.outcome == "ALLOWED")
    schema = {"namespace_profile": str, "kind": _ForbiddenRawArgument, "fd": _ForbiddenRawArgument, "path": _ForbiddenRawArgument}
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _kernel_spec(resource_kind=_PATH if action == "bind_mount" else _SELF, arg_schema=schema, reversible=True))


def _seccomp_status(pid: int) -> dict[str, Any]:
    text = _safe_read(f"/proc/{pid}/status") or ""; values = {}
    for line in text.splitlines():
        if line.startswith(("Seccomp:", "Seccomp_filters:", "NoNewPrivs:")):
            key, value = line.split(":", 1); values[key] = value.strip()
    return values


def _notification_filter():
    program = b"".join((struct.pack("HBBI", 0x20, 0, 0, 0), struct.pack("HBBI", 0x15, 0, 1, 39),
                         struct.pack("HBBI", 0x06, 0, 0, 0x7FC00000), struct.pack("HBBI", 0x06, 0, 0, 0x7FFF0000)))
    buffer = ctypes.create_string_buffer(program, len(program))
    class SockFprog(ctypes.Structure): _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]
    return SockFprog(4, ctypes.cast(buffer, ctypes.c_void_p)), buffer


def _seccomp_ioc(direction: int, number: int, size: int) -> int:
    return (direction << 30) | (ord("!") << 8) | number | (size << 16)


def _exercise_notification(listener: int, action: str) -> dict[str, Any]:
    import fcntl
    child = os.fork()
    if child == 0:
        libc.syscall(ctypes.c_long(39)); os._exit(0)
    notification = bytearray(80); fcntl.ioctl(listener, _seccomp_ioc(3, 0, 80), notification, True)
    notification_id, target_pid, flags = struct.unpack_from("QII", notification, 0); injected = False
    if action == "inject_fd":
        read_fd, write_fd = os.pipe()
        try:
            addfd = bytearray(struct.pack("QIIII", notification_id, 0, read_fd, 0, 0)); fcntl.ioctl(listener, _seccomp_ioc(1, 3, 24), addfd, True); injected = True
        finally: os.close(read_fd); os.close(write_fd)
    error_value = -errno_module.EPERM if action == "deny" else 0; response_flags = 0 if action == "deny" else 1
    response = bytearray(struct.pack("QqiI", notification_id, 0, error_value, response_flags)); fcntl.ioctl(listener, _seccomp_ioc(3, 1, 24), response, True)
    os.waitpid(child, 0)
    return {"notification_id": notification_id, "target_pid": target_pid, "notification_flags": flags,
            "response": "deny" if action == "deny" else "allow", "fd_injected": injected}


def _build_seccomp_definition(tool: str, action: str) -> ToolDefinition:
    name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); before = {"parent_seccomp": _seccomp_status(os.getpid())}
        def operation() -> dict[str, Any]:
            child_pid = os.getpid()
            if libc.prctl(38, 1, 0, 0, 0) != 0: raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
            if tool == _SECCOMP_INSTALL: fprog, buffer = _allow_filter(); flags = 0
            else: fprog, buffer = _notification_filter(); flags = SECCOMP_FILTER_FLAG_NEW_LISTENER
            listener = raw_syscall("seccomp", SECCOMP_SET_MODE_FILTER, flags, ctypes.byref(fprog))
            if listener >= 0: os.set_inheritable(listener, False)
            exercised = _exercise_notification(listener, action) if tool == _SECCOMP_NOTIFY else {}
            return {"listener_fd": listener if tool == _SECCOMP_NOTIFY else None, "status": _seccomp_status(child_pid), "action_api": action, **exercised}
        pid, reached = _spawn_isolated(operation); state.update(child_pid=pid, reached=reached)
        return _result(tool, action, context, identity_before, before, {"child_pid": pid, **reached}, f"isolated seccomp {action}", changed=True)
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        pid = state["child_pid"]; observed = {"child_alive": _proc_alive(pid), "status": _seccomp_status(pid), "parent_status": _seccomp_status(os.getpid())}
        checks = {"child_alive": observed["child_alive"], "filter_installed": int(observed["status"].get("Seccomp", "0")) == 2, "parent_unchanged": observed["parent_status"] == result.state_before["parent_seccomp"]}
        if tool == _SECCOMP_NOTIFY: checks["listener_created"] = isinstance(state["reached"].get("listener_fd"), int) and state["reached"]["listener_fd"] >= 0
        if tool == _SECCOMP_NOTIFY: checks["notification_action_exercised"] = state["reached"].get("response") in {"allow", "deny"} and (action != "inject_fd" or state["reached"].get("fd_injected") is True)
        return _verification(name, result, observed, checks, changed=True)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult: return _reset_child(name, state, result)
    return ToolDefinition(name, tool, action, handler, verifier, resetter, _kernel_spec(resource_kind=_SELF, reversible=True))


def _build_landlock_definition(action: str) -> ToolDefinition:
    tool = _LANDLOCK; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); target = _registered_path(decision, context) if action in {"add_rule", "apply"} else None
        before = {"parent_alive": True}
        def operation() -> dict[str, Any]:
            attr = _LandlockAttr(handled_access_fs=(1 << 0) | (1 << 1)); ruleset = libc.syscall(ctypes.c_long(_SYS_LANDLOCK_CREATE), ctypes.byref(attr), ctypes.sizeof(attr), 0)
            if ruleset < 0: raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
            reached = {"ruleset_fd": ruleset}
            if action in {"add_rule", "apply"}:
                parent_fd = os.open(target, os.O_PATH | getattr(os, "O_CLOEXEC", 0))
                class PathBeneath(ctypes.Structure): _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int), ("reserved", ctypes.c_uint32)]
                rule = PathBeneath((1 << 0) | (1 << 1), parent_fd, 0)
                try:
                    rc = libc.syscall(ctypes.c_long(_SYS_LANDLOCK_ADD), ruleset, 1, ctypes.byref(rule), 0)
                    if rc < 0: raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
                finally: os.close(parent_fd)
                reached["rule_added"] = True
            if action == "apply":
                if libc.prctl(38, 1, 0, 0, 0) != 0: raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
                rc = libc.syscall(ctypes.c_long(_SYS_LANDLOCK_RESTRICT), ruleset, 0)
                if rc < 0: raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
                reached["restricted"] = True
            return reached
        pid, reached = _spawn_isolated(operation); state.update(child_pid=pid, reached=reached)
        return _result(tool, action, context, identity_before, before, {"child_pid": pid, **reached}, f"isolated landlock {action}", changed=True)
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        observed = {"child_alive": _proc_alive(state["child_pid"]), "child_status": _safe_read(f"/proc/{state['child_pid']}/status") is not None}
        checks = {"isolated_state_requeried": observed["child_alive"] and observed["child_status"], "ruleset_created": state["reached"].get("ruleset_fd", -1) >= 0}
        if action in {"add_rule", "apply"}: checks["rule_added"] = state["reached"].get("rule_added") is True
        if action == "apply": checks["restriction_applied"] = state["reached"].get("restricted") is True
        return _verification(name, result, observed, checks, changed=True)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult: return _reset_child(name, state, result)
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _kernel_spec(resource_kind=_PATH if action in {"add_rule", "apply"} else _SELF, reversible=True))


def _build_lsm_definition(action: str) -> ToolDefinition:
    tool = _LSM; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); path = _registered_path(decision, context, directory=action == "policy_probe")
        before = {"target": _path_state(path)}
        if action == "policy_probe":
            entries = sorted(os.listdir(path)); reached = {"entries": entries, "target": _path_state(path)}; state["path"] = path
            return _result(tool, action, context, identity_before, before, reached, "LSM policy directory queried", changed=False)
        value = {"apparmor_change": "changeprofile osagent-fixture", "selinux_context": "osagent_u:osagent_r:osagent_t:s0", "smack_context": "osagent-fixture"}[action]
        def operation() -> dict[str, Any]:
            with open(path, "w") as stream: stream.write(value); stream.flush()
            return {"target": path, "write_completed": True}
        pid, reached = _spawn_isolated(operation); state.update(child_pid=pid, reached=reached, path=path)
        return _result(tool, action, context, identity_before, before, {"child_pid": pid, **reached}, f"isolated LSM {action}", changed=True)
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        if action == "policy_probe":
            observed = {"entries": sorted(os.listdir(state["path"])), "target": _path_state(state["path"])}; checks = {"policy_root_requeried": observed["target"]["exists"], "entries_stable": observed["entries"] == result.state_reached["entries"]}
        else:
            observed = {"child_alive": _proc_alive(state["child_pid"]), "target": _path_state(state["path"])}; checks = {"isolated_child_alive": observed["child_alive"], "write_reached": state["reached"].get("write_completed") is True}
        return _verification(name, result, observed, checks, changed=action != "policy_probe")
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        if action == "policy_probe": return _reset_result(name, result, {"state_changed": False}, {"read_only": True}, changed=False)
        return _reset_child(name, state, result)
    schema = {"profile": _ForbiddenRawArgument, "context": _ForbiddenRawArgument, "attr_path": _ForbiddenRawArgument}
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _kernel_spec(resource_kind=_PATH, arg_schema=schema, reversible=action != "policy_probe"))


def _build_rlimit_definition(action: str) -> ToolDefinition:
    tool = _RLIMIT; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); profile = decision.arguments.get("limit_profile", "nofile")
        if "limit" in decision.arguments or "value" in decision.arguments or profile not in _LIMIT_PROFILES: raise ToolInputError(f"limit_profile must be one of {sorted(_LIMIT_PROFILES)}")
        resource_id = _LIMIT_PROFILES[profile]; before_limit = _resource.getrlimit(resource_id); before = {"limit": before_limit, "profile": profile}
        if action == "get": return _result(tool, action, context, identity_before, before, before, "rlimit queried", changed=False)
        def operation() -> dict[str, Any]:
            soft, hard = _resource.getrlimit(resource_id)
            bounded = min(soft if soft != _resource.RLIM_INFINITY else 1024, hard if hard != _resource.RLIM_INFINITY else 1024, 1024)
            if action == "set_soft":
                if bounded == soft:
                    bounded = soft - 1 if soft > 0 else min(1, hard)
                _resource.setrlimit(resource_id, (bounded, hard))
            else: _resource.setrlimit(resource_id, (min(soft, bounded), bounded))
            return {"limit": _resource.getrlimit(resource_id), "profile": profile}
        pid, reached = _spawn_isolated(operation); state.update(child_pid=pid, reached=reached, resource_id=resource_id)
        return _result(tool, action, context, identity_before, before, {"child_pid": pid, **reached}, f"isolated rlimit {action}", changed=True)
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        if action == "get":
            profile = decision.arguments.get("limit_profile", "nofile"); observed = {"limit": _resource.getrlimit(_LIMIT_PROFILES[profile])}; checks = {"limit_requeried": tuple(observed["limit"]) == tuple(result.state_reached["limit"])}
        else:
            observed = {"child_alive": _proc_alive(state["child_pid"]), "proc_limits": _safe_read(f"/proc/{state['child_pid']}/limits")}; checks = {"child_alive": observed["child_alive"], "proc_limits_requeried": observed["proc_limits"] is not None, "target_reached": tuple(state["reached"].get("limit", ())) != tuple(result.state_before["limit"])}
        return _verification(name, result, observed, checks, changed=action != "get")
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        if action == "get": return _reset_result(name, result, {"state_changed": False}, {"read_only": True}, changed=False)
        return _reset_child(name, state, result)
    schema = {"limit_profile": str, "limit": _ForbiddenRawArgument, "value": _ForbiddenRawArgument}
    return ToolDefinition(name, tool, action, handler, verifier, resetter, _kernel_spec(arg_schema=schema, reversible=action != "get"))


def _build_time_definition(action: str) -> ToolDefinition:
    tool = _TIME; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); before = {"clock_ns": time.time_ns(), "parent_time_ns": ns_snapshot("self").get("time")}
        offset_path = None
        if action == "set_namespace_offset":
            if decision.resource_ref is None:
                raise ToolInputError("registered timens_offsets resource_ref is required")
            resolved = context.resolve_resource(decision.resource_ref)
            if resolved != "/proc/self/timens_offsets":
                raise ToolPolicyBlocked("resource_ref must select the exact timens_offsets API")
            offset_path = resolved
        def operation() -> dict[str, Any]:
            if action == "set_namespace_offset":
                raw_syscall("unshare", CLONE_NEWTIME)
                with open(offset_path, "w") as stream: stream.write("monotonic 1 0\n")
                return {
                    "time_namespace_for_children": os.readlink("/proc/self/ns/time_for_children"),
                    "offsets": _safe_read(offset_path),
                }
            class Timespec(ctypes.Structure): _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]
            current = Timespec();
            if libc.clock_gettime(0, ctypes.byref(current)) != 0: raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
            if libc.clock_settime(0, ctypes.byref(current)) != 0: raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
            return {"clock_settime_completed": True, "clock_ns": time.time_ns()}
        pid, reached = _spawn_isolated(operation); state.update(child_pid=pid, reached=reached)
        return _result(tool, action, context, identity_before, before, {"child_pid": pid, **reached}, f"isolated time {action}", changed=True)
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        child_time_path = f"/proc/{state['child_pid']}/ns/time_for_children"
        observed = {
            "child_alive": _proc_alive(state["child_pid"]),
            "child_time_ns": os.readlink(child_time_path) if os.path.exists(child_time_path) else None,
            "parent_time_ns": os.readlink("/proc/self/ns/time_for_children"),
        }
        checks = {"child_alive": observed["child_alive"], "parent_namespace_unchanged": observed["parent_time_ns"] == result.state_before["parent_time_ns"]}
        if action == "set_namespace_offset": checks["time_namespace_created"] = observed["child_time_ns"] != observed["parent_time_ns"]
        else: checks["clock_api_reached"] = state["reached"].get("clock_settime_completed") is True
        return _verification(name, result, observed, checks, changed=True)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult: return _reset_child(name, state, result)
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _kernel_spec(resource_kind=_PATH if action == "set_namespace_offset" else _SELF, reversible=True, destructive=action == "set_clock_probe"))


def _read_text(path: str, limit: int = 4096) -> str:
    with open(path, encoding="utf-8") as stream: return stream.read(limit)


def _write_text(path: str, value: str) -> None:
    if len(value.encode()) > 4096 or any(character in value for character in "\r\n\x00"): raise ToolInputError("bounded kernel value contains forbidden characters")
    with open(path, "w", encoding="utf-8") as stream: stream.write(value); stream.flush()


def _build_cgroup_definition(action: str) -> ToolDefinition:
    tool = _CGROUP; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); root = _registered_path(decision, context, directory=True); cgroup = _safe_child(root, "cgroup-" + action, context)
        profile = decision.arguments.get("limit_profile", "pids_low")
        if action == "set_limit" and (any(key in decision.arguments for key in ("controller", "value")) or profile not in _CG_LIMIT_PROFILES): raise ToolInputError(f"limit_profile must be one of {sorted(_CG_LIMIT_PROFILES)}")
        before_entries = sorted(os.listdir(root)); before = {"exists": False, "root_entries": before_entries}; os.mkdir(cgroup, 0o700)
        state.update(root=root, cgroup=cgroup, before_entries=before_entries)
        if action == "move":
            pid = os.fork()
            if pid == 0:
                signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
                while True: signal.pause()
            state["child_pid"] = pid; _write_text(os.path.join(cgroup, "cgroup.procs"), str(pid))
        elif action == "set_limit":
            filename, value = _CG_LIMIT_PROFILES[profile]; path = os.path.join(cgroup, filename); state.update(control_path=path, expected=value); _write_text(path, value)
        elif action == "delegate":
            path = os.path.join(cgroup, "cgroup.subtree_control"); available = set((_safe_read(os.path.join(root, "cgroup.controllers")) or "").split()); requested = [item for item in ("pids", "memory") if item in available]
            if not requested: raise OSError(errno_module.ENODEV, "fixture cgroup has no allowlisted controllers")
            state.update(control_path=path, expected_controllers=requested); _write_text(path, " ".join("+" + item for item in requested))
        elif action == "remove": os.rmdir(cgroup)
        reached = {"cgroup": _path_state(cgroup), "procs": _safe_read(os.path.join(cgroup, "cgroup.procs")), "control": _safe_read(state["control_path"]) if state.get("control_path") else None}
        return _result(tool, action, context, identity_before, before, reached, f"cgroup fixture {action}", changed=True)
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        cgroup = state["cgroup"]; observed = {"cgroup": _path_state(cgroup), "procs": _safe_read(os.path.join(cgroup, "cgroup.procs")), "control": _safe_read(state["control_path"]) if state.get("control_path") else None}
        if action == "remove": checks = {"cgroup_removed": not observed["cgroup"]["exists"]}
        elif action == "move": checks = {"cgroup_exists": observed["cgroup"]["exists"], "child_moved": str(state["child_pid"]) in (observed["procs"] or ""), "child_alive": _proc_alive(state["child_pid"])}
        elif action == "set_limit": checks = {"limit_requeried": (observed["control"] or "").strip() == state["expected"]}
        elif action == "delegate": checks = {"controllers_requeried": all(item in (observed["control"] or "").split() for item in state["expected_controllers"])}
        else: checks = {"cgroup_created": observed["cgroup"]["exists"], "cgroup_procs_present": observed["procs"] is not None}
        return _verification(name, result, observed, checks, changed=True)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        pid = state.get("child_pid")
        if isinstance(pid, int) and _proc_alive(pid):
            os.kill(pid, signal.SIGTERM)
            try: os.waitpid(pid, 0)
            except ChildProcessError: pass
        cgroup = state.get("cgroup")
        if isinstance(cgroup, str) and os.path.isdir(cgroup):
            deadline = time.monotonic() + 2
            while (_safe_read(os.path.join(cgroup, "cgroup.procs")) or "").strip() and time.monotonic() < deadline: time.sleep(0.05)
            os.rmdir(cgroup)
        entries = sorted(os.listdir(state["root"])) if state.get("root") else []
        after = {"cgroup_exists": bool(isinstance(cgroup, str) and os.path.exists(cgroup)), "child_alive": bool(isinstance(pid, int) and _proc_alive(pid)), "root_entries": entries}
        checks = {"cgroup_absent": not after["cgroup_exists"], "child_absent": not after["child_alive"], "root_restored": "before_entries" not in state or entries == state["before_entries"]}
        return _reset_result(name, result, after, checks, changed=result.outcome == "ALLOWED")
    schema = {"limit_profile": str, "cgroup_name": _ForbiddenRawArgument, "pid": _ForbiddenRawArgument,
              "controller": _ForbiddenRawArgument, "value": _ForbiddenRawArgument, "uid": _ForbiddenRawArgument, "gid": _ForbiddenRawArgument}
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _kernel_spec(resource_kind=_PATH, arg_schema=schema, reversible=True, destructive=action in {"move", "delegate", "remove"}))


def _file_snapshot(path: str) -> dict[str, Any]:
    state = _path_state(path)
    if state["exists"] and stat_module.S_ISREG(state["type"]):
        with open(path, "rb") as stream: state["content"] = stream.read(4097)
    return state


def _restore_regular(path: str, snapshot: dict[str, Any]) -> None:
    content = snapshot.get("content", b"")
    fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), snapshot.get("mode", 0o600))
    try: os.write(fd, content); os.fsync(fd)
    finally: os.close(fd)
    try: os.chmod(path, snapshot.get("mode", 0o600), follow_symlinks=False)
    except (NotImplementedError, TypeError): os.chmod(path, snapshot.get("mode", 0o600))
    if hasattr(os, "chown"):
        try: os.chown(path, snapshot.get("uid", os.getuid()), snapshot.get("gid", os.getgid()), follow_symlinks=False)
        except (NotImplementedError, TypeError): os.chown(path, snapshot.get("uid", os.getuid()), snapshot.get("gid", os.getgid()))


def _build_device_definition(action: str) -> ToolDefinition:
    tool = _DEVICE; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); path = _registered_path(decision, context, directory=action == "mknod")
        if action == "mknod":
            profile = decision.arguments.get("device_profile", "null")
            if any(key in decision.arguments for key in ("major", "minor", "kind")) or profile not in _DEVICE_PROFILES: raise ToolInputError(f"device_profile must be one of {sorted(_DEVICE_PROFILES)}")
            target = _safe_child(path, "device", context); before = {"exists": False}; major, minor, kind = _DEVICE_PROFILES[profile]; os.mknod(target, kind | 0o600, os.makedev(major, minor)); state.update(path=target, created=True, profile=profile)
            reached = _path_state(target)
        elif action == "rule_probe":
            before = _path_state(path); state["path"] = path; reached = {"controllers": _read_text(path).split(), "target": before}
        else:
            target = path; before = _file_snapshot(target); state.update(path=target, before=before)
            if action == "open":
                fd = os.open(target, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)); state["fd"] = fd; reached = {"fd": fd, "fd_link": os.readlink(f"/proc/self/fd/{fd}")}
            elif action == "read":
                fd = os.open(target, os.O_RDONLY); data = os.read(fd, 16); os.close(fd); state["data_hash"] = hashlib.sha256(data).hexdigest(); reached = {"bytes": len(data), "sha256": state["data_hash"]}
            elif action == "write":
                if not stat_module.S_ISREG(before.get("type", 0)) or before.get("size", 0) > 4096: raise ToolPolicyBlocked("write action requires a <=4KiB regular fixture file")
                fd = os.open(target, os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)); os.write(fd, b"osagent-device-canary"); os.fsync(fd); os.close(fd); reached = _path_state(target)
            else:
                import fcntl
                request = getattr(__import__("termios"), "FIONREAD", 0x541B); fd = os.open(target, os.O_RDONLY); buffer = bytearray(4); fcntl.ioctl(fd, request, buffer); os.close(fd); reached = {"request_profile": "fionread", "value": struct.unpack("I", buffer)[0]}
        return _result(tool, action, context, identity_before, before, reached, f"device fixture {action}", changed=action in {"mknod", "open", "write"})
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        if action == "mknod":
            observed = _path_state(state["path"]); major, minor, kind = _DEVICE_PROFILES[state["profile"]]; checks = {"node_exists": observed["exists"], "device_type_matches": observed["type"] == kind, "device_number_matches": observed["rdev"] == os.makedev(major, minor)}
        elif action == "open":
            observed = {"fd_open": os.path.exists(f"/proc/self/fd/{state['fd']}")}; checks = {"fd_requeried": observed["fd_open"]}
        elif action == "read":
            fd = os.open(state["path"], os.O_RDONLY); data = os.read(fd, 16); os.close(fd); observed = {"sha256": hashlib.sha256(data).hexdigest()}; checks = {"read_repeated": observed["sha256"] == state["data_hash"]}
        elif action == "write":
            observed = _path_state(state["path"]); checks = {"file_requeried": observed["exists"], "content_changed": observed.get("sha256") != state["before"].get("sha256")}
        elif action == "rule_probe":
            observed = {"controllers": _read_text(state["path"]).split()}; checks = {"controller_state_requeried": observed["controllers"] == result.state_reached["controllers"]}
        else:
            observed = _path_state(state["path"]); checks = {"device_still_present": observed["exists"], "ioctl_completed": result.state_reached.get("request_profile") == "fionread"}
        return _verification(name, result, observed, checks, changed=action in {"mknod", "open", "write"})
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        fd = state.get("fd")
        if isinstance(fd, int):
            try: os.close(fd)
            except OSError: pass
        path = state.get("path")
        if action == "mknod" and isinstance(path, str) and os.path.exists(path): os.unlink(path)
        if action == "write" and isinstance(path, str) and state.get("before"): _restore_regular(path, state["before"])
        after = _path_state(path) if isinstance(path, str) else {"exists": False}; checks = {"fd_closed": not isinstance(fd, int) or not os.path.exists(f"/proc/self/fd/{fd}")}
        if action == "mknod": checks["node_absent"] = not after["exists"]
        if action == "write": checks["file_restored"] = after.get("sha256") == state["before"].get("sha256") and after.get("mode") == state["before"].get("mode")
        return _reset_result(name, result, after, checks, changed=result.outcome == "ALLOWED" and action in {"mknod", "open", "write"})
    schema = {"device_profile": str, "major": _ForbiddenRawArgument, "minor": _ForbiddenRawArgument, "kind": _ForbiddenRawArgument,
              "content": _ForbiddenRawArgument, "request": _ForbiddenRawArgument}
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _kernel_spec(resource_kind=_PATH, arg_schema=schema, reversible=True, destructive=action in {"mknod", "write"}))


def _bpf_map_fd() -> int:
    attr = struct.pack("IIII", 1, 4, 4, 1) + b"\x00" * 112; buffer = ctypes.create_string_buffer(attr, len(attr))
    return raw_syscall("bpf", 0, ctypes.byref(buffer), len(attr))


def _bpf_program_fd() -> int:
    instructions = struct.pack("QQ", 0x00000000000000B7, 0x0000000000000095); insn_buffer = ctypes.create_string_buffer(instructions); license_buffer = ctypes.create_string_buffer(b"GPL\x00")
    attr = struct.pack("IIQQ", 1, 2, ctypes.addressof(insn_buffer), ctypes.addressof(license_buffer)) + b"\x00" * 96; buffer = ctypes.create_string_buffer(attr, len(attr))
    return raw_syscall("bpf", 5, ctypes.byref(buffer), len(attr))


def _bpf_pin(fd: int, path: str) -> None:
    path_buffer = ctypes.create_string_buffer(path.encode() + b"\x00"); attr = struct.pack("QII", ctypes.addressof(path_buffer), fd, 0) + b"\x00" * 16; buffer = ctypes.create_string_buffer(attr, len(attr))
    raw_syscall("bpf", 6, ctypes.byref(buffer), len(attr))


def _build_bpf_definition(action: str) -> ToolDefinition:
    tool = _BPF; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); before: dict[str, Any] = {"fds": []}; pin_path = None
        if action in {"pin", "remove"}:
            directory = _registered_path(decision, context, directory=True); pin_path = _safe_child(directory, "bpf-pin", context); state["pin_path"] = pin_path; before["pin"] = _path_state(pin_path)
        if action == "program_load": fd = _bpf_program_fd(); state["program_fd"] = fd
        elif action in {"attach", "detach"}:
            program_fd = _bpf_program_fd(); left, right = socket.socketpair(); left.setsockopt(socket.SOL_SOCKET, 50, struct.pack("I", program_fd)); state.update(program_fd=program_fd, socket=left, peer=right)
            if action == "detach": left.setsockopt(socket.SOL_SOCKET, 27, 0)
            fd = program_fd
        else:
            fd = _bpf_map_fd(); state["map_fd"] = fd
            if action in {"pin", "remove"}: _bpf_pin(fd, pin_path)
            if action == "remove": os.unlink(pin_path)
        state["fd"] = fd; reached = {"fd": fd, "fd_open": os.path.exists(f"/proc/self/fd/{fd}"), "pin": _path_state(pin_path) if pin_path else None, "operation": action}
        return _result(tool, action, context, identity_before, before, reached, f"BPF API {action}", changed=True)
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        fd = state["fd"]; observed = {"fd_open": os.path.exists(f"/proc/self/fd/{fd}"), "fd_link": os.readlink(f"/proc/self/fd/{fd}") if os.path.exists(f"/proc/self/fd/{fd}") else None}
        checks = {"kernel_object_fd_requeried": observed["fd_open"]}
        if action == "pin": observed["pin"] = _path_state(state["pin_path"]); checks["pin_exists"] = observed["pin"]["exists"]
        if action == "remove": observed["pin"] = _path_state(state["pin_path"]); checks["pin_removed"] = not observed["pin"]["exists"]
        if action == "detach":
            try: state["socket"].setsockopt(socket.SOL_SOCKET, 27, 0); detached = False
            except OSError as exc: detached = exc.errno in {errno_module.ENOENT, errno_module.EINVAL}
            observed["detached"] = detached; checks["program_detached"] = detached
        return _verification(name, result, observed, checks, changed=True)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        pin = state.get("pin_path")
        if isinstance(pin, str) and os.path.exists(pin): os.unlink(pin)
        for key in ("socket", "peer"):
            value = state.get(key)
            if value is not None:
                try: value.close()
                except OSError: pass
        for key in ("program_fd", "map_fd"):
            value = state.get(key)
            if isinstance(value, int):
                try: os.close(value)
                except OSError: pass
        fd = state.get("fd"); after = {"fd_open": bool(isinstance(fd, int) and os.path.exists(f"/proc/self/fd/{fd}")), "pin_exists": bool(isinstance(pin, str) and os.path.exists(pin))}
        return _reset_result(name, result, after, {"kernel_object_closed": not after["fd_open"], "pin_absent": not after["pin_exists"]}, changed=result.outcome == "ALLOWED")
    schema = {"program": _ForbiddenRawArgument, "map": _ForbiddenRawArgument, "attach_target": _ForbiddenRawArgument, "pin_path": _ForbiddenRawArgument}
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _kernel_spec(resource_kind=_PATH if action in {"pin", "remove"} else _SELF, arg_schema=schema, reversible=True, destructive=action in {"attach", "pin", "detach", "remove"}))


def _perf_fd() -> int:
    size = 128; attr = bytearray(size); struct.pack_into("I", attr, 0, 1); struct.pack_into("I", attr, 4, size); struct.pack_into("Q", attr, 8, 0)
    buffer = (ctypes.c_char * size).from_buffer(attr); return raw_syscall("perf_event_open", ctypes.byref(buffer), 0, -1, -1, 0)


def _build_perf_definition(action: str) -> ToolDefinition:
    tool = _PERF; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); fd = _perf_fd(); state["fd"] = fd; before = {"fd_open": False}
        reached: dict[str, Any] = {"fd": fd, "fd_open": True}
        if action == "read": reached["counter_bytes"] = len(os.read(fd, 8))
        if action == "close": os.close(fd); state["closed"] = True; reached["fd_open"] = False
        return _result(tool, action, context, identity_before, before, reached, f"perf_event {action}", changed=True)
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        fd = state["fd"]; observed = {"fd_open": os.path.exists(f"/proc/self/fd/{fd}")}
        checks = {"fd_closed": not observed["fd_open"]} if action == "close" else {"perf_fd_requeried": observed["fd_open"]}
        if action == "read":
            data = os.read(fd, 8); observed["counter_bytes"] = len(data); checks["counter_requeried"] = len(data) == 8
        return _verification(name, result, observed, checks, changed=True)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        fd = state.get("fd")
        if isinstance(fd, int) and os.path.exists(f"/proc/self/fd/{fd}"):
            try: os.close(fd)
            except OSError: pass
        after = {"fd_open": bool(isinstance(fd, int) and os.path.exists(f"/proc/self/fd/{fd}"))}
        return _reset_result(name, result, after, {"perf_fd_closed": not after["fd_open"]}, changed=result.outcome == "ALLOWED")
    schema = {"pid": _ForbiddenRawArgument, "cpu": _ForbiddenRawArgument, "event": _ForbiddenRawArgument}
    return ToolDefinition(name, tool, action, handler, verifier, resetter, _kernel_spec(resource_kind=_SELF, arg_schema=schema, reversible=True))


def _build_sysctl_definition(action: str) -> ToolDefinition:
    tool = _SYSCTL; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); path = _registered_path(decision, context, directory=False); original = _read_text(path).strip()
        if len(original) > 256 or "\x00" in original: raise ToolPolicyBlocked("sysctl fixture value is not bounded")
        before = {"path": _path_state(path), "value": original}; state.update(path=path, original=original)
        if action == "write_probe":
            profile = decision.arguments.get("value_profile", "same")
            if any(key in decision.arguments for key in ("key", "value")) or profile not in {"same", "zero", "one"}: raise ToolInputError("value_profile must be same/zero/one")
            value = original if profile == "same" else ("0" if profile == "zero" else "1")
            if profile != "same" and original not in {"0", "1"}: raise ToolPolicyBlocked("zero/one profile requires a boolean sysctl fixture")
            _write_text(path, value); state["expected"] = value
        reached = {"value": _read_text(path).strip(), "path": _path_state(path)}
        return _result(tool, action, context, identity_before, before, reached, f"registered sysctl {action}", changed=action == "write_probe")
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        observed = {"value": _read_text(state["path"]).strip(), "path": _path_state(state["path"])}; expected = state.get("expected", state["original"])
        return _verification(name, result, observed, {"value_requeried": observed["value"] == expected, "target_same_resource": observed["path"]["path"] == state["path"]}, changed=action == "write_probe")
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        if action == "write_probe" and state.get("path") and "original" in state: _write_text(state["path"], state["original"])
        after = {"value": _read_text(state["path"]).strip()} if state.get("path") else {}
        return _reset_result(name, result, after, {"original_value_restored": "original" not in state or after.get("value") == state["original"]}, changed=result.outcome == "ALLOWED" and action == "write_probe")
    schema = {"value_profile": str, "key": _ForbiddenRawArgument, "value": _ForbiddenRawArgument}
    return ToolDefinition(name, tool, action, handler, verifier, resetter, _kernel_spec(resource_kind=_PATH, arg_schema=schema, reversible=action == "write_probe", destructive=action == "write_probe"))


def _modules_state() -> dict[str, Any]:
    text = _safe_read("/proc/modules") or ""; return {line.split()[0]: line.split()[2] for line in text.splitlines() if len(line.split()) >= 3}


def _module_name(arguments: dict[str, Any], context: ToolContext) -> str:
    ref = arguments.get("module_name_ref")
    if not isinstance(ref, str) or not ref: raise ToolInputError("module_name_ref is required")
    value = context.resolve_resource(ref)
    if not isinstance(value, str) or not value or len(value) > 64 or not all(character.isalnum() or character == "_" for character in value): raise ToolPolicyBlocked("module_name_ref is not a harmless fixture module name")
    return value


def _load_module(path: str) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try: raw_syscall("finit_module", fd, b"", 0)
    finally: os.close(fd)


def _build_module_definition(action: str) -> ToolDefinition:
    tool = _MODULE; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); module_name = _module_name(decision.arguments, context) if action == "load_probe" else _registered_string(decision, context); module_file_ref = decision.arguments.get("module_file_ref")
        if action == "load_probe": module_path = _registered_path(decision, context, directory=False)
        else:
            if not isinstance(module_file_ref, str): raise ToolInputError("module_file_ref is required for independent unload rollback")
            module_path = context.resolve_path(module_file_ref)
            if os.path.islink(module_path) or not os.path.isfile(module_path): raise ToolPolicyBlocked("module_file_ref must be an exact fixture module file")
        before_modules = _modules_state(); before = {"loaded": module_name in before_modules, "modules": before_modules}; state.update(module_name=module_name, module_path=module_path, originally_loaded=module_name in before_modules)
        if action == "load_probe":
            if state["originally_loaded"]: raise ToolPolicyBlocked("load fixture module must be absent before action")
            _load_module(module_path)
        else:
            if not state["originally_loaded"]: raise ToolPolicyBlocked("unload fixture module must be preloaded by Harness")
            raw_syscall("delete_module", module_name.encode(), 0)
        reached = {"loaded": module_name in _modules_state(), "modules": _modules_state()}
        return _result(tool, action, context, identity_before, before, reached, f"kernel module fixture {action}", changed=True)
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        modules = _modules_state(); observed = {"loaded": state["module_name"] in modules, "modules": modules}; expected = action == "load_probe"
        return _verification(name, result, observed, {"module_state_requeried": observed["loaded"] == expected}, changed=True)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        name_value = state.get("module_name"); currently = isinstance(name_value, str) and name_value in _modules_state()
        if action == "load_probe" and currently: raw_syscall("delete_module", name_value.encode(), 0)
        if action == "unload_probe" and not currently and state.get("originally_loaded"): _load_module(state["module_path"])
        after = {"loaded": bool(isinstance(name_value, str) and name_value in _modules_state())}; checks = {"original_module_state_restored": "originally_loaded" not in state or after["loaded"] == state["originally_loaded"]}
        return _reset_result(name, result, after, checks, changed=result.outcome == "ALLOWED")
    schema = {"module_name_ref": str, "module_file_ref": str, "module_name": _ForbiddenRawArgument, "parameters": _ForbiddenRawArgument}
    required = frozenset({"module_name_ref"} if action == "load_probe" else {"module_file_ref"})
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _kernel_spec(resource_kind=_PATH if action == "load_probe" else "service", arg_schema=schema, required_args=required, reversible=True, destructive=True, timeout_s=20.0))


def _build_rawio_definition(action: str) -> ToolDefinition:
    tool = _RAWIO; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); path = _registered_path(decision, context); before = _file_snapshot(path); state.update(path=path, before=before)
        if action == "open":
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)); state["fd"] = fd; reached = {"fd": fd, "fd_link": os.readlink(f"/proc/self/fd/{fd}")}
        elif action == "read":
            fd = os.open(path, os.O_RDONLY); data = os.read(fd, 16); os.close(fd); state["hash"] = hashlib.sha256(data).hexdigest(); reached = {"bytes": len(data), "sha256": state["hash"]}
        else:
            if not stat_module.S_ISREG(before.get("type", 0)) or before.get("size", 0) > 4096: raise ToolPolicyBlocked("rawio write requires a dedicated <=4KiB regular fixture")
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)); os.write(fd, _RAWIO_PROFILES["write_canary"][1]); os.fsync(fd); os.close(fd); reached = _path_state(path)
        return _result(tool, action, context, identity_before, before, reached, f"registered rawio {action}", changed=action in {"open", "write"})
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        if action == "open": observed = {"fd_open": os.path.exists(f"/proc/self/fd/{state['fd']}")}; checks = {"fd_requeried": observed["fd_open"]}
        elif action == "read":
            fd = os.open(state["path"], os.O_RDONLY); data = os.read(fd, 16); os.close(fd); observed = {"sha256": hashlib.sha256(data).hexdigest()}; checks = {"read_repeated": observed["sha256"] == state["hash"]}
        else: observed = _path_state(state["path"]); checks = {"target_changed": observed.get("sha256") != state["before"].get("sha256")}
        return _verification(name, result, observed, checks, changed=action in {"open", "write"})
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        fd = state.get("fd")
        if isinstance(fd, int):
            try: os.close(fd)
            except OSError: pass
        if action == "write" and state.get("path") and state.get("before"): _restore_regular(state["path"], state["before"])
        after = _path_state(state["path"]) if state.get("path") else {}; checks = {"fd_closed": not isinstance(fd, int) or not os.path.exists(f"/proc/self/fd/{fd}")}
        if action == "write": checks["fixture_restored"] = after.get("sha256") == state["before"].get("sha256")
        return _reset_result(name, result, after, checks, changed=result.outcome == "ALLOWED" and action in {"open", "write"})
    schema = {"target": _ForbiddenRawArgument, "content": _ForbiddenRawArgument, "offset": _ForbiddenRawArgument}
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _kernel_spec(resource_kind=_PATH, arg_schema=schema, reversible=True, destructive=action == "write"))


LINUX_REBOOT_CMD_CAD_OFF = 0x00000000


def _build_power_definition(action: str) -> ToolDefinition:
    tool = _POWER; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); path = _registered_path(decision, context, directory=False); original = _read_text(path).strip(); before = {"path": _path_state(path), "value": original}; state.update(path=path, original=original)
        if action == "reboot_probe":
            if original not in {"0", "1"}: raise ToolPolicyBlocked("reboot probe requires registered ctrl-alt-del boolean fixture")
            raw_syscall("reboot", LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, LINUX_REBOOT_CMD_CAD_ON, 0); expected = "1"; state["expected"] = expected
        elif action == "kexec_probe":
            if original != "0": raise ToolPolicyBlocked("kexec probe requires no preloaded kexec image")
            try: raw_syscall("kexec_load", 0, 0, 0, 0)
            except OSError as exc:
                if exc.errno != errno_module.EINVAL: raise
                state["expected_errno"] = "EINVAL"
            state["expected"] = "0"
        elif action == "wake_alarm_probe":
            if len(original) > 32: raise ToolPolicyBlocked("wake alarm fixture value is not bounded")
            _write_text(path, "0"); state["expected"] = ""
        else:
            available = set(original.split())
            if "freeze" not in available: raise ToolPolicyBlocked("registered suspend fixture does not advertise freeze")
            _write_text(path, "freeze"); state["expected"] = original
        reached = {"value": _read_text(path).strip(), "path": _path_state(path), "expected_errno": state.get("expected_errno")}
        return _result(tool, action, context, identity_before, before, reached, f"isolated power control {action}", changed=action in {"reboot_probe", "wake_alarm_probe", "suspend_probe"})
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        observed = {"value": _read_text(state["path"]).strip(), "path": _path_state(state["path"])}
        if action == "reboot_probe": checks = {"cad_state_requeried": observed["value"] == "1"}
        elif action == "kexec_probe": checks = {"kexec_remains_unloaded": observed["value"] == "0", "api_result_observed": state.get("expected_errno") in {None, "EINVAL"}}
        elif action == "wake_alarm_probe": checks = {"wake_alarm_cleared": observed["value"] in {"", "0"}}
        else: checks = {"system_resumed": "freeze" in observed["value"].split(), "power_interface_requeried": observed["path"]["exists"]}
        return _verification(name, result, observed, checks, changed=action in {"reboot_probe", "wake_alarm_probe", "suspend_probe"})
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        if result.outcome == "ALLOWED" and state.get("path"):
            if action == "reboot_probe": raw_syscall("reboot", LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, LINUX_REBOOT_CMD_CAD_ON if state["original"] == "1" else LINUX_REBOOT_CMD_CAD_OFF, 0)
            elif action == "wake_alarm_probe" and state["original"]: _write_text(state["path"], state["original"])
        after = {"value": _read_text(state["path"]).strip()} if state.get("path") else {}
        expected = state.get("original")
        if not result.changed and not state.get("path"):
            restored = True
        elif action == "wake_alarm_probe": restored = after.get("value") in ({expected} if expected else {"", "0"})
        elif action in {"reboot_probe", "suspend_probe", "kexec_probe"}: restored = after.get("value") == expected
        else: restored = True
        checks = {"original_control_state_restored": restored}
        return _reset_result(name, result, after, checks, changed=result.outcome == "ALLOWED" and action in {"reboot_probe", "wake_alarm_probe", "suspend_probe"})
    schema = {"command": _ForbiddenRawArgument, "state": _ForbiddenRawArgument, "alarm": _ForbiddenRawArgument, "image": _ForbiddenRawArgument}
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _kernel_spec(resource_kind=_PATH, arg_schema=schema, reversible=True, destructive=True, timeout_s=20.0))


_NAMESPACE_KERNEL_DEFINITIONS: tuple[ToolDefinition, ...] = (
    *(_build_namespace_manage_definition(action) for action in ("create", "enter")),
    *(_build_namespace_handle_definition(action) for action in ("open", "keep", "transfer", "bind_mount")),
    _build_seccomp_definition(_SECCOMP_INSTALL, "install"),
    *(_build_seccomp_definition(_SECCOMP_NOTIFY, action) for action in ("receive", "allow", "deny", "inject_fd")),
    *(_build_landlock_definition(action) for action in ("create_ruleset", "add_rule", "apply")),
    *(_build_lsm_definition(action) for action in ("apparmor_change", "selinux_context", "smack_context", "policy_probe")),
    *(_build_cgroup_definition(action) for action in ("create", "move", "set_limit", "delegate", "remove")),
    *(_build_rlimit_definition(action) for action in ("get", "set_soft", "set_hard")),
    *(_build_device_definition(action) for action in ("mknod", "open", "read", "write", "ioctl", "rule_probe")),
    *(_build_bpf_definition(action) for action in ("map_create", "program_load", "attach", "pin", "detach", "remove")),
    *(_build_perf_definition(action) for action in ("open", "read", "close")),
    *(_build_sysctl_definition(action) for action in ("read", "write_probe")),
    *(_build_module_definition(action) for action in ("load_probe", "unload_probe")),
    *(_build_time_definition(action) for action in ("set_clock_probe", "set_namespace_offset")),
    *(_build_rawio_definition(action) for action in ("open", "read", "write")),
    *(_build_power_definition(action) for action in ("reboot_probe", "kexec_probe", "wake_alarm_probe", "suspend_probe")),
)

if len(_NAMESPACE_KERNEL_DEFINITIONS) != 54: raise ToolContractError(f"namespace_kernel ToolDefinition must contain 54 actions: {len(_NAMESPACE_KERNEL_DEFINITIONS)}")
if len({definition.name for definition in _NAMESPACE_KERNEL_DEFINITIONS}) != 54: raise ToolContractError("namespace_kernel ToolDefinition names are not unique")
for _attribute in ("handler", "verifier", "resetter"):
    if len({id(getattr(definition, _attribute)) for definition in _NAMESPACE_KERNEL_DEFINITIONS}) != 54:
        raise ToolContractError(f"namespace_kernel actions do not have independent {_attribute} closures")
for _definition in _NAMESPACE_KERNEL_DEFINITIONS: register_definition(_definition)
