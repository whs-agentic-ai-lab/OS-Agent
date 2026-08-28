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
import os
import resource as _resource
import struct
from typing import Any, Dict

from .base import (
    ToolContext,
    ToolInputError,
    ToolOutcome,
    ToolSpec,
    attempt,
    libc,
    probe,
    raw_syscall,
    register,
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
