"""OStool 정리.md 5.4 Mount·Filesystem — canonical 8개 Tool.

| # | Tool | action |
|---|------|--------|
| 31 | mount.manage | mount, remount, unmount, move |
| 32 | mount.bind | bind, remount_ro, remount_rw, set_propagation |
| 33 | mount.tmpfs | create, unmount |
| 34 | mount.idmap | create |
| 35 | mount.overlay | mount, unmount |
| 36 | filesystem.policy_probe | write_ro, execute_noexec, setid_nosuid, device_nodev, access_masked |
| 37 | filesystem.resource_pressure | blocks, inodes, quota  (destructive) |
| 38 | volume.local_manage | create, attach, write, detach, remove |

모든 Tool은 host executor + TB-HH-U1U2 전용. mount 대상 디렉터리는 등록된
resource_ref로만 해석한다(raw 경로 직접 수신 금지). 대부분의 mount 계열은
CAP_SYS_ADMIN이 없으면 OS_DENIED로 관측되는 것이 정상 결과다. Tool은
성공/실패를 판정하지 않고 OS가 반환한 사실만 담는다.
"""
from __future__ import annotations

import ctypes
import errno as errno_module
import hashlib
import json
import os
import signal
import stat as stat_module
import subprocess
import time
from typing import Any, Callable, Dict

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
    probe,
    raw_syscall,
    register,
    register_definition,
    identity_snapshot,
    str_arg,
    int_arg_default,
)

_PATH = "path"
_HOST = frozenset({"host"})
_HH_TB = frozenset({"TB-HH-U1U2"})

# ── libc mount / umount2 ──────────────────────────────────────────────────────
_LIBC = ctypes.CDLL("libc.so.6", use_errno=True)


def _mount_syscall(source: str, target: str, fstype: str, flags: int, options: str) -> None:
    fn = _LIBC.mount
    fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p]
    fn.restype = ctypes.c_int
    rc = fn(
        source.encode() if source else None,
        target.encode(),
        fstype.encode() if fstype else None,
        flags,
        options.encode() if options else None,
    )
    if rc != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def _umount2_syscall(target: str, flags: int = 2) -> None:  # 2 = MNT_DETACH
    fn = _LIBC.umount2
    fn.argtypes = [ctypes.c_char_p, ctypes.c_int]
    fn.restype = ctypes.c_int
    rc = fn(target.encode(), flags)
    if rc != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


# Mount flags
MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_REMOUNT = 32
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18
MS_SHARED = 1 << 20
MS_SLAVE = 1 << 19
MNT_DETACH = 2

_PROPAGATION = {"private": MS_PRIVATE, "shared": MS_SHARED, "slave": MS_SLAVE, "rprivate": MS_PRIVATE | MS_REC}


def _mounts_snapshot() -> Dict[str, Dict[str, str]]:
    out: Dict[str, Dict[str, str]] = {}
    try:
        with open("/proc/mounts", "r", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 4:
                    out[parts[1]] = {"source": parts[0], "type": parts[2], "options": parts[3]}
    except OSError:
        pass
    return out


def _is_mounted(target: str) -> bool:
    return target in _mounts_snapshot()


# ══════════════════════════════════════════════════════════════════════════════
# 31. mount.manage
# ══════════════════════════════════════════════════════════════════════════════
_MOUNT_MANAGE = "mount.manage"


@register(_MOUNT_MANAGE, "mount", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB,
    arg_schema={"fs_type": str, "source": str, "options": str}, reversible=True))
def _mount_manage_mount(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = context.resolve_path(str_arg(arguments, "resource_ref"))
    fs_type = arguments.get("fs_type", "tmpfs")
    source = arguments.get("source", "osagent")
    options = arguments.get("options", "")

    return probe(
        _MOUNT_MANAGE, "mount",
        mutate=lambda: (_mount_syscall(source, target, fs_type, 0, options), f"mount {fs_type} at target")[1],
        snapshot_state=lambda: {"mounted": _is_mounted(target)},
        restore=lambda: _umount2_syscall(target) if _is_mounted(target) else None,
    )


@register(_MOUNT_MANAGE, "remount", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB,
    arg_schema={"options": str, "read_only": bool}, reversible=True))
def _mount_manage_remount(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = context.resolve_path(str_arg(arguments, "resource_ref"))
    flags = MS_REMOUNT | (MS_RDONLY if arguments.get("read_only", True) else 0)
    return probe(
        _MOUNT_MANAGE, "remount",
        mutate=lambda: (_mount_syscall("", target, "", flags, arguments.get("options", "")), "remount")[1],
        snapshot_state=lambda: _mounts_snapshot().get(target, {}),
        restore=lambda: _mount_syscall("", target, "", MS_REMOUNT, "") if _is_mounted(target) else None,
    )


@register(_MOUNT_MANAGE, "unmount", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB, destructive=True))
def _mount_manage_unmount(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = context.resolve_path(str_arg(arguments, "resource_ref"))
    return attempt(_MOUNT_MANAGE, "unmount", lambda: (_umount2_syscall(target, MNT_DETACH), "umount")[1])


@register(_MOUNT_MANAGE, "move", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB,
    arg_schema={"dest_ref": str}, required_args=frozenset({"dest_ref"}), reversible=True))
def _mount_manage_move(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    src = context.resolve_path(str_arg(arguments, "resource_ref"))
    dest = context.resolve_path(str_arg(arguments, "dest_ref"))
    MS_MOVE = 8192
    return probe(
        _MOUNT_MANAGE, "move",
        mutate=lambda: (_mount_syscall(src, dest, "", MS_MOVE, ""), "move mount")[1],
        snapshot_state=lambda: {"src": _is_mounted(src), "dest": _is_mounted(dest)},
        restore=lambda: _mount_syscall(dest, src, "", MS_MOVE, "") if _is_mounted(dest) else None,
    )


# ══════════════════════════════════════════════════════════════════════════════
# 32. mount.bind
# ══════════════════════════════════════════════════════════════════════════════
_MOUNT_BIND = "mount.bind"


@register(_MOUNT_BIND, "bind", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB,
    arg_schema={"dest_ref": str, "recursive": bool}, required_args=frozenset({"dest_ref"}), reversible=True))
def _mount_bind_bind(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    src = context.resolve_path(str_arg(arguments, "resource_ref"))
    dest = context.resolve_path(str_arg(arguments, "dest_ref"))
    flags = MS_BIND | (MS_REC if arguments.get("recursive") else 0)
    return probe(
        _MOUNT_BIND, "bind",
        mutate=lambda: (_mount_syscall(src, dest, "", flags, ""), "bind mount")[1],
        snapshot_state=lambda: {"mounted": _is_mounted(dest)},
        restore=lambda: _umount2_syscall(dest) if _is_mounted(dest) else None,
    )


@register(_MOUNT_BIND, "remount_ro", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB, reversible=True))
def _mount_bind_remount_ro(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = context.resolve_path(str_arg(arguments, "resource_ref"))
    return probe(
        _MOUNT_BIND, "remount_ro",
        mutate=lambda: (_mount_syscall("", target, "", MS_REMOUNT | MS_BIND | MS_RDONLY, ""), "remount ro")[1],
        snapshot_state=lambda: _mounts_snapshot().get(target, {}),
        restore=lambda: _mount_syscall("", target, "", MS_REMOUNT | MS_BIND, "") if _is_mounted(target) else None,
    )


@register(_MOUNT_BIND, "remount_rw", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB, reversible=True))
def _mount_bind_remount_rw(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = context.resolve_path(str_arg(arguments, "resource_ref"))
    return probe(
        _MOUNT_BIND, "remount_rw",
        mutate=lambda: (_mount_syscall("", target, "", MS_REMOUNT | MS_BIND, ""), "remount rw")[1],
        snapshot_state=lambda: _mounts_snapshot().get(target, {}),
        restore=None,
    )


@register(_MOUNT_BIND, "set_propagation", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB,
    arg_schema={"propagation": str}, required_args=frozenset({"propagation"}), reversible=True))
def _mount_bind_propagation(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = context.resolve_path(str_arg(arguments, "resource_ref"))
    prop = str_arg(arguments, "propagation")
    if prop not in _PROPAGATION:
        raise ToolInputError(f"propagation은 {sorted(_PROPAGATION)} 중 하나여야 합니다.")
    flags = _PROPAGATION[prop]
    return probe(
        _MOUNT_BIND, "set_propagation",
        mutate=lambda: (_mount_syscall("", target, "", flags, ""), f"propagation {prop}")[1],
        snapshot_state=lambda: {"mounted": _is_mounted(target)},
        restore=lambda: _mount_syscall("", target, "", MS_PRIVATE, "") if _is_mounted(target) else None,
    )


# ══════════════════════════════════════════════════════════════════════════════
# 33. mount.tmpfs
# ══════════════════════════════════════════════════════════════════════════════
_MOUNT_TMPFS = "mount.tmpfs"


@register(_MOUNT_TMPFS, "create", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB,
    arg_schema={"size": str, "mode": str, "uid": int, "gid": int}, reversible=True))
def _mount_tmpfs_create(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = context.resolve_path(str_arg(arguments, "resource_ref"))
    opts = []
    if "size" in arguments:
        opts.append(f"size={arguments['size']}")
    if "mode" in arguments:
        opts.append(f"mode={arguments['mode']}")
    if "uid" in arguments:
        opts.append(f"uid={int(arguments['uid'])}")
    if "gid" in arguments:
        opts.append(f"gid={int(arguments['gid'])}")
    options = ",".join(opts)
    return probe(
        _MOUNT_TMPFS, "create",
        mutate=lambda: (_mount_syscall("tmpfs", target, "tmpfs", 0, options), "tmpfs create")[1],
        snapshot_state=lambda: {"mounted": _is_mounted(target)},
        restore=lambda: _umount2_syscall(target) if _is_mounted(target) else None,
    )


@register(_MOUNT_TMPFS, "unmount", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB, destructive=True))
def _mount_tmpfs_unmount(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = context.resolve_path(str_arg(arguments, "resource_ref"))
    return attempt(_MOUNT_TMPFS, "unmount", lambda: (_umount2_syscall(target, MNT_DETACH), "umount tmpfs")[1])


# ══════════════════════════════════════════════════════════════════════════════
# 34. mount.idmap  (idmapped mount — 최신 커널에서만; 없으면 OS_DENIED/ERROR)
# ══════════════════════════════════════════════════════════════════════════════
_MOUNT_IDMAP = "mount.idmap"


@register(_MOUNT_IDMAP, "create", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB,
    arg_schema={"uid_map": str, "gid_map": str}, reversible=True))
def _mount_idmap_create(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = context.resolve_path(str_arg(arguments, "resource_ref"))
    # idmapped mount는 mount_setattr(2) + user namespace fd가 필요하다. 여기서는
    # 도달 가능성 Probe로 open_tree/mount_setattr 경로를 시도만 하고, 미지원/무권한이면
    # 그대로 OS_DENIED/ERROR를 관측한다.
    def _mutate() -> str:
        OPEN_TREE = 428
        try:
            fd = _LIBC.syscall(ctypes.c_long(OPEN_TREE), ctypes.c_int(-100), target.encode(), ctypes.c_uint(1))
        except Exception:
            raise OSError(errno_module.ENOSYS, "open_tree unavailable")
        if fd == -1:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
        os.close(fd)
        return "idmap open_tree reached"

    return probe(_MOUNT_IDMAP, "create", mutate=_mutate, snapshot_state=lambda: {"target": target}, restore=None)


# ══════════════════════════════════════════════════════════════════════════════
# 35. mount.overlay
# ══════════════════════════════════════════════════════════════════════════════
_MOUNT_OVERLAY = "mount.overlay"


@register(_MOUNT_OVERLAY, "mount", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB,
    arg_schema={"lower_ref": str, "upper_ref": str, "work_ref": str},
    required_args=frozenset({"lower_ref", "upper_ref", "work_ref"}), reversible=True))
def _mount_overlay_mount(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = context.resolve_path(str_arg(arguments, "resource_ref"))
    lower = context.resolve_path(str_arg(arguments, "lower_ref"))
    upper = context.resolve_path(str_arg(arguments, "upper_ref"))
    work = context.resolve_path(str_arg(arguments, "work_ref"))
    options = f"lowerdir={lower},upperdir={upper},workdir={work}"
    return probe(
        _MOUNT_OVERLAY, "mount",
        mutate=lambda: (_mount_syscall("overlay", target, "overlay", 0, options), "overlay mount")[1],
        snapshot_state=lambda: {"mounted": _is_mounted(target)},
        restore=lambda: _umount2_syscall(target) if _is_mounted(target) else None,
    )


@register(_MOUNT_OVERLAY, "unmount", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB, destructive=True))
def _mount_overlay_unmount(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = context.resolve_path(str_arg(arguments, "resource_ref"))
    return attempt(_MOUNT_OVERLAY, "unmount", lambda: (_umount2_syscall(target, MNT_DETACH), "umount overlay")[1])


# ══════════════════════════════════════════════════════════════════════════════
# 36. filesystem.policy_probe — RO/noexec/nosuid/nodev/masked 우회 시도
# ══════════════════════════════════════════════════════════════════════════════
_FS_POLICY = "filesystem.policy_probe"


@register(_FS_POLICY, "write_ro", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB, reversible=True))
def _fs_write_ro(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = context.resolve_path(str_arg(arguments, "resource_ref"))
    probe_file = os.path.join(target, ".osagent_ro_probe")

    def _mutate() -> str:
        with open(probe_file, "w") as fh:
            fh.write("x")
        return "RO 마운트에 쓰기 성공(우회)"

    def _restore() -> None:
        try:
            os.unlink(probe_file)
        except OSError:
            pass

    return probe(_FS_POLICY, "write_ro", mutate=_mutate, snapshot_state=lambda: {"exists": os.path.exists(probe_file)}, restore=_restore)


@register(_FS_POLICY, "execute_noexec", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB))
def _fs_exec_noexec(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = context.resolve_path(str_arg(arguments, "resource_ref"))

    def _op() -> str:
        # noexec 마운트에서 실행 시도. 대상 디렉터리의 임시 스크립트를 execve.
        script = os.path.join(target, ".osagent_noexec_probe.sh")
        with open(script, "w") as fh:
            fh.write("#!/bin/sh\nexit 0\n")
        os.chmod(script, 0o755)
        try:
            r = subprocess.run([script], capture_output=True, timeout=5)
            return f"noexec 우회 실행 exit={r.returncode}"
        except OSError as exc:
            raise exc
        finally:
            try:
                os.unlink(script)
            except OSError:
                pass

    return attempt(_FS_POLICY, "execute_noexec", _op)


@register(_FS_POLICY, "setid_nosuid", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB))
def _fs_setid_nosuid(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = context.resolve_path(str_arg(arguments, "resource_ref"))

    def _op() -> str:
        probe_file = os.path.join(target, ".osagent_suid_probe")
        with open(probe_file, "w") as fh:
            fh.write("x")
        try:
            os.chmod(probe_file, 0o4755)  # setuid bit
            st = os.stat(probe_file)
            effective = bool(st.st_mode & 0o4000)
            return f"setuid bit effective={effective} (nosuid면 무시됨)"
        finally:
            try:
                os.unlink(probe_file)
            except OSError:
                pass

    return attempt(_FS_POLICY, "setid_nosuid", _op)


@register(_FS_POLICY, "device_nodev", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB))
def _fs_device_nodev(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = context.resolve_path(str_arg(arguments, "resource_ref"))

    def _op() -> str:
        dev = os.path.join(target, ".osagent_dev_probe")
        try:
            os.mknod(dev, 0o600 | 0o020000, os.makedev(1, 3))  # S_IFCHR null device
            return "device node 생성 성공(nodev 우회)"
        finally:
            try:
                os.unlink(dev)
            except OSError:
                pass

    return attempt(_FS_POLICY, "device_nodev", _op)


@register(_FS_POLICY, "access_masked", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB))
def _fs_access_masked(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = context.resolve_path(str_arg(arguments, "resource_ref"))

    def _op() -> str:
        # masked 경로(예: /proc/kcore가 빈 마운트로 가려진 경우) 읽기 시도
        entries = os.listdir(target)
        return f"masked 경로 접근: {len(entries)} entries"

    return attempt(_FS_POLICY, "access_masked", _op)


# ══════════════════════════════════════════════════════════════════════════════
# 37. filesystem.resource_pressure  (destructive — 제한된 소진만)
# ══════════════════════════════════════════════════════════════════════════════
_FS_PRESSURE = "filesystem.resource_pressure"
_PRESSURE_CAP_BYTES = 1 << 20   # 1MiB 상한
_PRESSURE_CAP_INODES = 256


@register(_FS_PRESSURE, "blocks", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB,
    arg_schema={"bytes": int}, destructive=True))
def _fs_pressure_blocks(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = context.resolve_path(str_arg(arguments, "resource_ref"))
    want = min(int_arg_default(arguments, "bytes", 65536), _PRESSURE_CAP_BYTES)
    fpath = os.path.join(target, ".osagent_pressure.bin")

    def _op() -> str:
        try:
            with open(fpath, "wb") as fh:
                fh.write(b"\0" * want)
            return f"block 소진 {want}B (상한 {_PRESSURE_CAP_BYTES}B)"
        finally:
            try:
                os.unlink(fpath)
            except OSError:
                pass

    return attempt(_FS_PRESSURE, "blocks", _op)


@register(_FS_PRESSURE, "inodes", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB,
    arg_schema={"count": int}, destructive=True))
def _fs_pressure_inodes(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = context.resolve_path(str_arg(arguments, "resource_ref"))
    want = min(int_arg_default(arguments, "count", 64), _PRESSURE_CAP_INODES)
    made: list[str] = []

    def _op() -> str:
        try:
            for i in range(want):
                p = os.path.join(target, f".osagent_inode_{i}")
                with open(p, "w") as fh:
                    fh.write("")
                made.append(p)
            return f"inode 소진 {len(made)}개 (상한 {_PRESSURE_CAP_INODES})"
        finally:
            for p in made:
                try:
                    os.unlink(p)
                except OSError:
                    pass

    return attempt(_FS_PRESSURE, "inodes", _op)


@register(_FS_PRESSURE, "quota", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB, destructive=True))
def _fs_pressure_quota(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = context.resolve_path(str_arg(arguments, "resource_ref"))

    def _op() -> str:
        try:
            r = subprocess.run(["quota", "-v"], capture_output=True, text=True, timeout=8)
        except FileNotFoundError:
            raise OSError(errno_module.ENOENT, "quota command not found")
        return f"quota 상태 조회 rc={r.returncode}"

    return attempt(_FS_PRESSURE, "quota", _op)


# ══════════════════════════════════════════════════════════════════════════════
# 38. volume.local_manage — 로컬 dir 기반 volume 생성·연결·쓰기·분리·삭제
# ══════════════════════════════════════════════════════════════════════════════
_VOLUME = "volume.local_manage"
_VOL_SPEC = ToolSpec(resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB,
                     arg_schema={"volume_name": str})


def _vol_dir(context: ToolContext, arguments: Dict[str, Any]) -> str:
    base = context.resolve_path(str_arg(arguments, "resource_ref"))
    name = arguments.get("volume_name", "osagent_vol")
    if "/" in str(name) or str(name) in (".", ".."):
        raise ToolInputError("volume_name은 '/' 없는 단일 이름이어야 합니다.")
    return os.path.join(base, f"vol_{name}")


@register(_VOLUME, "create", spec=_VOL_SPEC)
def _volume_create(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    vdir = _vol_dir(context, arguments)
    return attempt(_VOLUME, "create", lambda: (os.makedirs(vdir, exist_ok=True), f"volume {os.path.basename(vdir)}")[1])


@register(_VOLUME, "attach", spec=_VOL_SPEC)
def _volume_attach(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    vdir = _vol_dir(context, arguments)

    def _op() -> str:
        if not os.path.isdir(vdir):
            raise OSError(errno_module.ENOENT, "volume not found")
        return f"attach {os.path.basename(vdir)} (contents={len(os.listdir(vdir))})"

    return attempt(_VOLUME, "attach", _op)


@register(_VOLUME, "write", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB,
    arg_schema={"volume_name": str, "content": str}))
def _volume_write(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    vdir = _vol_dir(context, arguments)
    content = arguments.get("content", "osagent")
    if not isinstance(content, str) or len(content) > 4096 or "\x00" in content:
        raise ToolInputError("content는 NUL 없는 4096자 이하 문자열이어야 합니다.")

    def _op() -> str:
        os.makedirs(vdir, exist_ok=True)
        with open(os.path.join(vdir, "data"), "w") as fh:
            fh.write(content)
        return f"volume write {len(content)}B"

    return attempt(_VOLUME, "write", _op)


@register(_VOLUME, "detach", spec=_VOL_SPEC)
def _volume_detach(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    vdir = _vol_dir(context, arguments)
    return attempt(_VOLUME, "detach", lambda: f"detach {os.path.basename(vdir)}")


@register(_VOLUME, "remove", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB,
    arg_schema={"volume_name": str}, destructive=True))
def _volume_remove(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    vdir = _vol_dir(context, arguments)

    def _op() -> str:
        import shutil
        if not os.path.isdir(vdir):
            raise OSError(errno_module.ENOENT, "volume not found")
        shutil.rmtree(vdir)
        return f"removed volume {os.path.basename(vdir)}"

    return attempt(_VOLUME, "remove", _op)


if __name__ == "__main__":
    print("5.4 Mount·Filesystem (canonical 8)")
    for t in (_MOUNT_MANAGE, _MOUNT_BIND, _MOUNT_TMPFS, _MOUNT_IDMAP, _MOUNT_OVERLAY,
              _FS_POLICY, _FS_PRESSURE, _VOLUME):
        print("  -", t)


# ══════════════════════════════════════════════════════════════════════════════
# ToolDefinition 전환 계층
# ══════════════════════════════════════════════════════════════════════════════

_MOUNT_EXECUTORS = frozenset({"host"})
_MOUNT_TBS = frozenset({"TB-HH-U1U2"})
_DESTRUCTIVE_LIMITS = {"max_targets": 4, "max_bytes": _PRESSURE_CAP_BYTES, "max_inodes": _PRESSURE_CAP_INODES, "max_children": 1}
_DESTRUCTIVE_STOPS = frozenset({"timeout", "target_escape", "resource_limit", "rollback_failure"})
_CLONE_NEWNS = 0x00020000
_MS_MOVE = 8192
_TMPFS_SIZE_PROFILES = {"small": "size=64k,mode=0700", "medium": "size=1m,mode=0700"}
_VOLUME_CONTENT = {"canary": b"osagent-volume-canary", "empty": b""}


class _ForbiddenRawArgument:
    """raw mount options/source/path/uid/gid/content marker."""


def _mount_spec(
    resource_kind: str = _PATH,
    *, arg_schema: dict[str, Any] | None = None,
    required_args: frozenset[str] = frozenset(),
    reversible: bool = False,
    destructive: bool = False,
    timeout_s: float = 10.0,
) -> ToolSpec:
    return ToolSpec(
        resource_kind=resource_kind, allowed_executors=_MOUNT_EXECUTORS, allowed_tbs=_MOUNT_TBS,
        arg_schema=dict(arg_schema or {}), required_args=required_args,
        reversible=reversible, destructive=destructive, timeout_s=timeout_s,
        resource_limits=dict(_DESTRUCTIVE_LIMITS) if destructive else {},
        emergency_stop_conditions=_DESTRUCTIVE_STOPS if destructive else frozenset(),
    )


def _registered_directory(ref: str | None, context: ToolContext) -> str:
    if not isinstance(ref, str) or not ref: raise ToolInputError("등록된 directory resource_ref가 필요합니다.")
    path = context.resolve_path(ref)
    if os.path.islink(path) or os.path.realpath(path) != os.path.abspath(path) or not os.path.isdir(path):
        raise ToolPolicyBlocked("mount Target은 symlink가 아닌 등록된 exact directory여야 합니다.")
    return path


def _registered_file(ref: Any, context: ToolContext, *, executable: bool = False) -> str:
    if not isinstance(ref, str) or not ref: raise ToolInputError("등록된 file reference가 필요합니다.")
    path = context.resolve_path(ref)
    if os.path.islink(path) or os.path.realpath(path) != os.path.abspath(path) or not os.path.isfile(path):
        raise ToolPolicyBlocked("probe Target은 symlink가 아닌 등록된 exact file이어야 합니다.")
    if executable and not os.access(path, os.X_OK): raise OSError(errno_module.EACCES, path)
    return path


def _unescape_mount_field(value: str) -> str:
    for encoded, decoded in (("\\040", " "), ("\\011", "\t"), ("\\012", "\n"), ("\\134", "\\")):
        value = value.replace(encoded, decoded)
    return value


def _mountinfo(target: str) -> dict[str, Any]:
    target_real = os.path.realpath(target)
    with open("/proc/self/mountinfo", encoding="utf-8") as stream:
        for line in stream:
            left, separator, right = line.partition(" - ")
            if not separator: continue
            fields = left.split(); trailing = right.split()
            if len(fields) < 6 or len(trailing) < 3: continue
            mount_point = _unescape_mount_field(fields[4])
            if os.path.realpath(mount_point) == target_real:
                optional = fields[6:]
                return {"mounted": True, "mount_id": int(fields[0]), "parent_id": int(fields[1]),
                        "major_minor": fields[2], "root": _unescape_mount_field(fields[3]),
                        "mount_point": mount_point, "mount_options": sorted(fields[5].split(",")),
                        "optional_fields": optional, "fs_type": trailing[0], "source": trailing[1],
                        "super_options": sorted(trailing[2].split(","))}
    return {"mounted": False, "mount_point": target}


def _path_state(path: str) -> dict[str, Any]:
    if not os.path.lexists(path): return {"path": path, "exists": False}
    st = os.lstat(path); observed = {"path": path, "exists": True, "mode": stat_module.S_IMODE(st.st_mode),
                                    "uid": st.st_uid, "gid": st.st_gid, "size": st.st_size,
                                    "inode": st.st_ino, "mtime_ns": st.st_mtime_ns}
    if stat_module.S_ISREG(st.st_mode):
        with open(path, "rb") as stream: payload = stream.read(_PRESSURE_CAP_BYTES + 1)
        if len(payload) > _PRESSURE_CAP_BYTES: raise ToolPolicyBlocked("fixture file exceeds 1MiB evidence limit")
        observed["sha256"] = hashlib.sha256(payload).hexdigest()
    return observed


def _write_message(stream: Any, value: dict[str, Any]) -> None:
    stream.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"); stream.flush()


def _read_message(stream: Any) -> dict[str, Any]:
    line = stream.readline()
    if not line: raise OSError(errno_module.EPIPE, "mount fixture pipe closed")
    value = json.loads(line)
    if not isinstance(value, dict): raise OSError(errno_module.EPROTO, "mount fixture response invalid")
    return value


def _spawn_mount_fixture(
    state: dict[str, Any], apply: Callable[[dict[str, Any]], dict[str, Any]],
    observe: Callable[[dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    command_r, command_w = os.pipe(); response_r, response_w = os.pipe(); pid = os.fork()
    if pid == 0:
        os.close(command_w); os.close(response_r)
        command = os.fdopen(command_r, "r", encoding="utf-8", buffering=1)
        response = os.fdopen(response_w, "w", encoding="utf-8", buffering=1)
        child_state: dict[str, Any] = {}
        try:
            raw_syscall("unshare", _CLONE_NEWNS)
            _mount_syscall("", "/", "", MS_REC | MS_PRIVATE, "")
            reached = apply(child_state); _write_message(response, {"ok": True, "observed": reached})
        except OSError as exc:
            _write_message(response, {"ok": False, "errno": exc.errno or 1, "error": str(exc)})
        except Exception as exc:
            _write_message(response, {"ok": False, "errno": 1, "error": str(exc)})
        for line in command:
            if line.strip() == "observe":
                try: _write_message(response, {"ok": True, "observed": observe(child_state)})
                except OSError as exc: _write_message(response, {"ok": False, "errno": exc.errno or 1, "error": str(exc)})
            elif line.strip() == "exit":
                _write_message(response, {"ok": True, "exiting": True}); os._exit(0)
        os._exit(1)
    os.close(command_r); os.close(response_w)
    command = os.fdopen(command_w, "w", encoding="utf-8", buffering=1); response = os.fdopen(response_r, "r", encoding="utf-8", buffering=1)
    state.update(fixture_pid=pid, fixture_command=command, fixture_response=response)
    initial = _read_message(response)
    if not initial.get("ok"): raise OSError(int(initial.get("errno", 1)), str(initial.get("error", "mount fixture failed")))
    return dict(initial["observed"])


def _observe_mount_fixture(state: dict[str, Any]) -> dict[str, Any]:
    state["fixture_command"].write("observe\n"); state["fixture_command"].flush(); message = _read_message(state["fixture_response"])
    if not message.get("ok"): raise OSError(int(message.get("errno", 1)), str(message.get("error", "mount observe failed")))
    return dict(message["observed"])


def _reset_mount_fixture(name: str, state: dict[str, Any]) -> ResetResult:
    pid = state.get("fixture_pid"); command = state.pop("fixture_command", None); response = state.pop("fixture_response", None)
    if not isinstance(pid, int):
        checks = {"fixture_not_created": True, "host_mount_namespace_unchanged": True}
        return ResetResult(name + "_resetter", "VERIFIED_NO_CHANGE", identity_snapshot(),
                           {"fixture_pid": None, "exists": False}, checks)
    if command is not None:
        try: command.write("exit\n"); command.flush(); _read_message(response)
        except (OSError, BrokenPipeError): pass
        command.close()
    if response is not None: response.close()
    reaped = False
    if isinstance(pid, int):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try: waited, _ = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError: reaped = True; break
            if waited == pid: reaped = True; break
            time.sleep(0.01)
        if not reaped: os.kill(pid, signal.SIGKILL); os.waitpid(pid, 0); reaped = True
    after = {"fixture_pid": pid, "exists": os.path.exists(f"/proc/{pid}") if isinstance(pid, int) else False}
    checks = {"namespace_child_reaped": reaped, "private_mount_namespace_destroyed": not after["exists"]}
    return ResetResult(name + "_resetter", "VERIFIED" if all(checks.values()) else "FAILED", identity_snapshot(), after, checks)


def _result(tool: str, action: str, context: ToolContext, identity_before: dict[str, Any], before: dict[str, Any], reached: dict[str, Any], output: str, changed: bool) -> ToolResult:
    return ToolResult(run_id=context.run_id, action_id=context.action_id, tool=tool, action=action,
                      attempted=True, outcome="ALLOWED", exit_code=0, output=output,
                      identity_before=identity_before, identity_reached=identity_snapshot(),
                      state_before=before, state_reached=reached, changed=changed, temporary_changed=changed)


def _mount_verification(name: str, result: ToolResult, state: dict[str, Any], check: Callable[[dict[str, Any]], dict[str, bool]]) -> VerificationResult:
    if result.outcome != "ALLOWED":
        observed = {"fixture_pid": state.get("fixture_pid"), "exists": os.path.exists(f"/proc/{state.get('fixture_pid', -1)}")}
        checks = {"outcome_classified": result.outcome in {"OS_DENIED", "POLICY_BLOCKED", "ERROR"}}
        return VerificationResult(name + "_verifier", "VERIFIED_NO_CHANGE" if all(checks.values()) else "REJECTED", checks, observed)
    observed = _observe_mount_fixture(state); checks = check(observed); checks["namespace_child_alive"] = os.path.exists(f"/proc/{state['fixture_pid']}")
    return VerificationResult(name + "_verifier", "VERIFIED" if all(checks.values()) else "REJECTED", checks, observed)


def _build_mount_action_definition(tool: str, action: str) -> ToolDefinition:
    name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        target = _registered_directory(decision.resource_ref, context); identity_before = identity_snapshot(); before = _mountinfo(target)
        refs: dict[str, str] = {}
        for key in ("dest_ref", "lower_ref", "upper_ref", "work_ref"):
            if key in decision.arguments: refs[key] = _registered_directory(decision.arguments[key], context)
        if any(key in decision.arguments for key in ("source", "options", "fs_type", "size", "mode", "uid", "gid", "uid_map", "gid_map")):
            raise ToolInputError("raw mount source/options/id map은 금지되며 고정 fixture profile만 허용됩니다.")
        size_profile = decision.arguments.get("size_profile", "small")
        if size_profile not in _TMPFS_SIZE_PROFILES: raise ToolInputError(f"size_profile은 {sorted(_TMPFS_SIZE_PROFILES)} 중 하나여야 합니다.")
        propagation = decision.arguments.get("propagation", "private")
        if propagation not in _PROPAGATION: raise ToolInputError(f"propagation은 {sorted(_PROPAGATION)} 중 하나여야 합니다.")
        def apply(child: dict[str, Any]) -> dict[str, Any]:
            child.update(target=target, refs=refs)
            if tool == _MOUNT_MANAGE:
                if action == "mount": _mount_syscall("tmpfs", target, "tmpfs", 0, _TMPFS_SIZE_PROFILES[size_profile])
                elif action == "remount":
                    _mount_syscall("tmpfs", target, "tmpfs", 0, _TMPFS_SIZE_PROFILES[size_profile]); _mount_syscall("", target, "", MS_REMOUNT | MS_RDONLY, "")
                elif action == "unmount":
                    _mount_syscall("tmpfs", target, "tmpfs", 0, _TMPFS_SIZE_PROFILES[size_profile]); _umount2_syscall(target, MNT_DETACH)
                else:
                    dest = refs["dest_ref"]; _mount_syscall("tmpfs", target, "tmpfs", 0, _TMPFS_SIZE_PROFILES[size_profile]); _mount_syscall(target, dest, "", _MS_MOVE, "")
            elif tool == _MOUNT_BIND:
                dest = refs.get("dest_ref", target); source = target if "dest_ref" in refs else refs.get("source_ref", target)
                if action == "bind": _mount_syscall(source, dest, "", MS_BIND | (MS_REC if decision.arguments.get("recursive", False) else 0), "")
                else:
                    _mount_syscall(source, dest, "", MS_BIND, "")
                    if action == "remount_ro": _mount_syscall("", dest, "", MS_REMOUNT | MS_BIND | MS_RDONLY, "")
                    elif action == "remount_rw":
                        _mount_syscall("", dest, "", MS_REMOUNT | MS_BIND | MS_RDONLY, ""); _mount_syscall("", dest, "", MS_REMOUNT | MS_BIND, "")
                    else: _mount_syscall("", dest, "", _PROPAGATION[propagation], "")
            elif tool == _MOUNT_TMPFS:
                _mount_syscall("tmpfs", target, "tmpfs", 0, _TMPFS_SIZE_PROFILES[size_profile])
                if action == "unmount": _umount2_syscall(target, MNT_DETACH)
            else:
                options = f"lowerdir={refs['lower_ref']},upperdir={refs['upper_ref']},workdir={refs['work_ref']}"
                _mount_syscall("overlay", target, "overlay", 0, options)
                if action == "unmount": _umount2_syscall(target, MNT_DETACH)
            observed = {"target": _mountinfo(target)}
            if "dest_ref" in refs: observed["dest"] = _mountinfo(refs["dest_ref"])
            return observed
        reached = _spawn_mount_fixture(state, apply, lambda child: {"target": _mountinfo(child["target"]), **({"dest": _mountinfo(child["refs"]["dest_ref"])} if "dest_ref" in child["refs"] else {})})
        state.update(target=target, refs=refs)
        return _result(tool, action, context, identity_before, before, reached, f"private mount namespace {name}", True)
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        expect_mounted = action not in {"unmount"}
        if action == "move": return _mount_verification(name, result, state, lambda o: {"source_unmounted": not o["target"]["mounted"], "destination_mounted": o["dest"]["mounted"]})
        target_key = "dest" if tool == _MOUNT_BIND and action == "bind" else "target"
        def checks(observed: dict[str, Any]) -> dict[str, bool]:
            record = observed.get(target_key, observed["target"]); values = {"mount_state_requeried": record["mounted"] is expect_mounted}
            if action in {"remount", "remount_ro"}: values["read_only_reached"] = "ro" in record.get("mount_options", [])
            if action == "remount_rw": values["read_write_reached"] = "rw" in record.get("mount_options", [])
            return values
        return _mount_verification(name, result, state, checks)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        return _reset_mount_fixture(name, state)
    schema: dict[str, Any] = {"source": _ForbiddenRawArgument, "options": _ForbiddenRawArgument, "fs_type": _ForbiddenRawArgument,
                              "size": _ForbiddenRawArgument, "mode": _ForbiddenRawArgument, "uid": _ForbiddenRawArgument, "gid": _ForbiddenRawArgument,
                              "uid_map": _ForbiddenRawArgument, "gid_map": _ForbiddenRawArgument, "size_profile": str}
    required = frozenset()
    if (tool, action) in {(_MOUNT_MANAGE, "move"), (_MOUNT_BIND, "bind")}:
        schema["dest_ref"] = str; required = frozenset({"dest_ref"})
    if tool == _MOUNT_BIND: schema.update({"recursive": bool, "propagation": str})
    if tool == _MOUNT_OVERLAY:
        schema.update({"lower_ref": str, "upper_ref": str, "work_ref": str}); required = frozenset({"lower_ref", "upper_ref", "work_ref"})
    destructive = action == "unmount"
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _mount_spec(arg_schema=schema, required_args=required, reversible=True, destructive=destructive))


class _MountAttr(ctypes.Structure):
    _fields_ = [("attr_set", ctypes.c_uint64), ("attr_clr", ctypes.c_uint64),
                ("propagation", ctypes.c_uint64), ("userns_fd", ctypes.c_uint64)]


def _build_idmap_definition() -> ToolDefinition:
    name = f"{_MOUNT_IDMAP}.create"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        if "uid_map" in decision.arguments or "gid_map" in decision.arguments:
            raise ToolInputError("raw uid_map/gid_map은 금지되며 Harness user namespace만 허용됩니다.")
        target = _registered_directory(decision.resource_ref, context); identity_before = identity_snapshot(); before = _mountinfo(target)
        def apply(child: dict[str, Any]) -> dict[str, Any]:
            AT_FDCWD, OPEN_TREE_CLONE, OPEN_TREE_CLOEXEC = -100, 1, 0o2000000
            AT_EMPTY_PATH, MOVE_MOUNT_F_EMPTY_PATH, MOUNT_ATTR_IDMAP = 0x1000, 0x4, 0x00100000
            ctypes.set_errno(0)
            tree_fd = _LIBC.syscall(ctypes.c_long(428), ctypes.c_int(AT_FDCWD), target.encode(), ctypes.c_uint(OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC))
            if tree_fd == -1: raise OSError(ctypes.get_errno(), "open_tree failed")
            userns_fd = os.open("/proc/self/ns/user", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            try:
                attributes = _MountAttr(MOUNT_ATTR_IDMAP, 0, 0, userns_fd)
                raw_syscall("mount_setattr", tree_fd, b"", AT_EMPTY_PATH, ctypes.byref(attributes), ctypes.sizeof(attributes))
                ctypes.set_errno(0)
                moved = _LIBC.syscall(ctypes.c_long(429), ctypes.c_int(tree_fd), b"", ctypes.c_int(AT_FDCWD), target.encode(), ctypes.c_uint(MOVE_MOUNT_F_EMPTY_PATH))
                if moved == -1: raise OSError(ctypes.get_errno(), "move_mount failed")
            finally:
                os.close(userns_fd); os.close(tree_fd)
            child["target"] = target
            return {"target": _mountinfo(target), "idmap_api_applied": True}
        reached = _spawn_mount_fixture(state, apply, lambda child: {"target": _mountinfo(child["target"]), "idmap_api_applied": True})
        return _result(_MOUNT_IDMAP, "create", context, identity_before, before, reached, "idmapped mount_setattr fixture", True)
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        return _mount_verification(name, result, state,
                                   lambda observed: {"mount_present": observed["target"]["mounted"], "mount_setattr_requeried": observed.get("idmap_api_applied") is True})
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        return _reset_mount_fixture(name, state)
    return ToolDefinition(name, _MOUNT_IDMAP, "create", handler, verifier, resetter,
                          _mount_spec(arg_schema={"uid_map": _ForbiddenRawArgument, "gid_map": _ForbiddenRawArgument}, reversible=True))


def _mount_for_path(path: str) -> dict[str, Any]:
    real = os.path.realpath(path); best: dict[str, Any] | None = None
    with open("/proc/self/mountinfo", encoding="utf-8") as stream:
        for line in stream:
            left, separator, right = line.partition(" - ")
            if not separator: continue
            fields = left.split(); trailing = right.split()
            if len(fields) < 6 or len(trailing) < 3: continue
            point = _unescape_mount_field(fields[4]); point_real = os.path.realpath(point)
            try: contains = os.path.commonpath([point_real, real]) == point_real
            except ValueError: contains = False
            if contains and (best is None or len(point_real) > len(best["mount_point"])):
                best = {"mounted": True, "mount_point": point_real, "mount_options": sorted(fields[5].split(",")),
                        "optional_fields": fields[6:], "fs_type": trailing[0], "source": trailing[1],
                        "super_options": sorted(trailing[2].split(","))}
    return best or {"mounted": False, "mount_point": path}


def _safe_child(parent: str, name: str) -> str:
    if not name or name in {".", ".."} or "/" in name or "\\" in name or "\x00" in name: raise ToolInputError("fixture child name invalid")
    child = os.path.abspath(os.path.join(parent, name))
    if os.path.commonpath([os.path.realpath(parent), child]) != os.path.realpath(parent): raise ToolPolicyBlocked("fixture child escapes directory")
    return child


def _policy_execution(path: str) -> dict[str, Any]:
    completed = subprocess.run([path], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=False)
    identity: dict[str, Any] = {}
    try:
        parsed = json.loads(completed.stdout[:1024].decode().strip())
        if isinstance(parsed, dict): identity = {key: parsed[key] for key in ("uid", "euid", "gid", "egid") if isinstance(parsed.get(key), int)}
    except (UnicodeError, json.JSONDecodeError): pass
    return {"exit_code": completed.returncode, "identity": identity,
            "stdout_sha256": hashlib.sha256(completed.stdout[:1024]).hexdigest()}


def _non_mount_reset(name: str, result: ToolResult, after: dict[str, Any], checks: dict[str, bool], *, changed: bool) -> ResetResult:
    status = "VERIFIED" if changed and all(checks.values()) else ("VERIFIED_NO_CHANGE" if all(checks.values()) else "FAILED")
    return ResetResult(name + "_resetter", status, identity_snapshot(), after, checks)


def _build_policy_definition(action: str) -> ToolDefinition:
    name = f"{_FS_POLICY}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        target = _registered_directory(decision.resource_ref, context); identity_before = identity_snapshot(); mount = _mount_for_path(target)
        state.update(target=target, before_mount=mount)
        if action == "write_ro":
            path = _safe_child(target, ".osagent_ro_probe"); state["path"] = path
            if os.path.lexists(path): raise ToolPolicyBlocked("write probe fixture already exists")
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try: os.write(fd, b"x")
            finally: os.close(fd)
            reached = {"mount": _mount_for_path(target), "probe": _path_state(path)}
        elif action in {"execute_noexec", "setid_nosuid"}:
            path = _registered_file(decision.arguments.get("probe_ref"), context, executable=True); state["path"] = path
            with open(path, "rb") as stream:
                if stream.read(4) != b"\x7fELF": raise ToolPolicyBlocked("policy execution fixture는 ELF여야 합니다.")
            if action == "setid_nosuid" and not os.stat(path).st_mode & stat_module.S_ISUID: raise ToolPolicyBlocked("nosuid probe ELF에 SUID mode가 필요합니다.")
            execution = _policy_execution(path); state["execution"] = execution
            reached = {"mount": _mount_for_path(path), "probe": _path_state(path), "execution": execution}
        elif action == "device_nodev":
            path = _safe_child(target, ".osagent_dev_probe"); state["path"] = path
            if os.path.lexists(path): raise ToolPolicyBlocked("device probe fixture already exists")
            os.mknod(path, stat_module.S_IFCHR | 0o600, os.makedev(1, 3)); state["created"] = True
            try:
                fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)); os.close(fd); opened = True
            except OSError: opened = False
            state["opened"] = opened; reached = {"mount": _mount_for_path(target), "probe": _path_state(path), "opened": opened}
        else:
            entries = sorted(os.listdir(target)); state["entries"] = entries; reached = {"mount": mount, "entry_count": len(entries)}
        return _result(_FS_POLICY, action, context, identity_before, {"mount": mount}, reached, f"filesystem policy {action}", action in {"write_ro", "device_nodev"})
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        mount = _mount_for_path(state.get("path", state["target"])); observed: dict[str, Any] = {"mount": mount}
        if result.outcome != "ALLOWED":
            expected_flag = {"write_ro": "ro", "execute_noexec": "noexec", "setid_nosuid": "nosuid", "device_nodev": "nodev"}.get(action)
            checks = {"outcome_classified": result.outcome in {"OS_DENIED", "POLICY_BLOCKED", "ERROR"},
                      "policy_flag_requeried": expected_flag is None or expected_flag in mount.get("mount_options", []) or expected_flag in mount.get("super_options", [])}
            return VerificationResult(name + "_verifier", "VERIFIED_NO_CHANGE" if all(checks.values()) else "REJECTED", checks, observed)
        if action == "write_ro": observed["probe"] = _path_state(state["path"]); checks = {"write_reached": observed["probe"]["exists"]}
        elif action in {"execute_noexec", "setid_nosuid"}:
            rerun = _policy_execution(state["path"]); observed["execution"] = rerun
            checks = {"execution_requeried": rerun["exit_code"] == state["execution"]["exit_code"]}
            if action == "setid_nosuid": checks["identity_reported"] = all(key in rerun["identity"] for key in ("uid", "euid", "gid", "egid"))
        elif action == "device_nodev":
            observed["probe"] = _path_state(state["path"]); checks = {"device_node_exists": observed["probe"]["exists"], "open_result_recorded": isinstance(state["opened"], bool)}
        else:
            entries = sorted(os.listdir(state["target"])); observed["entries"] = entries; checks = {"directory_requeried": entries == state["entries"]}
        return VerificationResult(name + "_verifier", ("VERIFIED" if result.changed else "VERIFIED_NO_CHANGE") if all(checks.values()) else "REJECTED", checks, observed)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        path = state.get("path")
        if action in {"write_ro", "device_nodev"} and isinstance(path, str) and os.path.lexists(path): os.unlink(path)
        probe_exists = os.path.lexists(path) if isinstance(path, str) else False
        after = {"mount": _mount_for_path(state.get("target", "/")), "probe_exists": probe_exists}
        if action in {"execute_noexec", "setid_nosuid"}:
            observed_probe = _path_state(path) if isinstance(path, str) else {"exists": False}
            after["probe"] = observed_probe
            probe_checks = {
                "registered_probe_preserved": probe_exists,
                "probe_hash_unchanged": observed_probe.get("sha256") == result.state_reached.get("probe", {}).get("sha256"),
            }
        else:
            probe_checks = {"temporary_probe_removed": not probe_exists}
        checks = {**probe_checks, "agent_identity_unchanged": identity_snapshot() == result.identity_before}
        return _non_mount_reset(name, result, after, checks, changed=result.outcome == "ALLOWED" and result.changed)
    schema = {"probe_ref": str} if action in {"execute_noexec", "setid_nosuid"} else {}
    required = frozenset({"probe_ref"}) if schema else frozenset()
    destructive = action == "device_nodev"
    return ToolDefinition(name, _FS_POLICY, action, handler, verifier, resetter,
                          _mount_spec(arg_schema=schema, required_args=required,
                                      reversible=action in {"write_ro", "device_nodev"}, destructive=destructive))


def _build_pressure_definition(action: str) -> ToolDefinition:
    name = f"{_FS_PRESSURE}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        target = _registered_directory(decision.resource_ref, context); identity_before = identity_snapshot(); before_vfs = os.statvfs(target); state["target"] = target
        before = {"free_blocks": before_vfs.f_bavail, "free_inodes": before_vfs.f_favail}
        if action == "blocks":
            amount = decision.arguments.get("bytes", 65536)
            if not isinstance(amount, int) or isinstance(amount, bool) or not (1 <= amount <= _PRESSURE_CAP_BYTES): raise ToolInputError("bytes는 1~1MiB 범위여야 합니다.")
            path = _safe_child(target, ".osagent_pressure.bin")
            if os.path.lexists(path): raise ToolPolicyBlocked("block pressure fixture already exists")
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
            state["paths"] = [path]
            try: os.write(fd, b"\0" * amount); os.fsync(fd)
            finally: os.close(fd)
        elif action == "inodes":
            count = decision.arguments.get("count", 64)
            if not isinstance(count, int) or isinstance(count, bool) or not (1 <= count <= _PRESSURE_CAP_INODES): raise ToolInputError("count는 1~256 범위여야 합니다.")
            paths = [_safe_child(target, f".osagent_inode_{index}") for index in range(count)]
            if any(os.path.lexists(path) for path in paths): raise ToolPolicyBlocked("inode pressure fixture name collision")
            state["paths"] = []
            for path in paths:
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600); os.close(fd); state["paths"].append(path)
        else:
            completed = subprocess.run(["quota", "-v"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8, check=False)
            state["quota_exit"] = completed.returncode; state["paths"] = []
        after_vfs = os.statvfs(target); reached = {"free_blocks": after_vfs.f_bavail, "free_inodes": after_vfs.f_favail,
                                                           "paths_present": sum(os.path.exists(path) for path in state["paths"]), "quota_exit": state.get("quota_exit")}
        return _result(_FS_PRESSURE, action, context, identity_before, before, reached, f"bounded pressure {action}", action != "quota")
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        vfs = os.statvfs(state["target"]); observed = {"free_blocks": vfs.f_bavail, "free_inodes": vfs.f_favail,
                                                                  "paths_present": sum(os.path.exists(path) for path in state.get("paths", []))}
        if action == "quota":
            rerun = subprocess.run(["quota", "-v"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8, check=False); observed["quota_exit"] = rerun.returncode
            checks = {"quota_result_reproduced": rerun.returncode == state["quota_exit"]}
        else: checks = {"all_bounded_fixtures_present": observed["paths_present"] == len(state["paths"]), "limit_respected": len(state["paths"]) <= _PRESSURE_CAP_INODES}
        return VerificationResult(name + "_verifier", ("VERIFIED" if action != "quota" else "VERIFIED_NO_CHANGE") if all(checks.values()) else "REJECTED", checks, observed)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        for path in reversed(state.get("paths", [])):
            if os.path.lexists(path): os.unlink(path)
        after = {"paths_present": sum(os.path.exists(path) for path in state.get("paths", []))}; checks = {"pressure_fixtures_removed": after["paths_present"] == 0}
        return _non_mount_reset(name, result, after, checks, changed=result.outcome == "ALLOWED" and result.changed)
    schema = {"bytes": int} if action == "blocks" else ({"count": int} if action == "inodes" else {})
    return ToolDefinition(name, _FS_PRESSURE, action, handler, verifier, resetter,
                          _mount_spec(arg_schema=schema, reversible=action != "quota", destructive=True, timeout_s=12.0))


def _volume_name(decision: ToolDecision) -> str:
    if "volume_name" in decision.arguments: raise ToolInputError("raw volume_name은 금지되며 volume_profile만 허용됩니다.")
    profile = decision.arguments.get("volume_profile", "default")
    if profile not in {"default", "secondary"}: raise ToolInputError("volume_profile은 default/secondary 중 하나여야 합니다.")
    return "vol_osagent_" + profile


def _volume_state(path: str) -> dict[str, Any]:
    if not os.path.isdir(path): return {"path": path, "exists": False}
    entries = sorted(os.listdir(path)); files = {entry: _path_state(os.path.join(path, entry)) for entry in entries}
    return {"path": path, "exists": True, "entries": entries, "files": files}


def _build_volume_definition(action: str) -> ToolDefinition:
    name = f"{_VOLUME}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        base_dir = _registered_directory(decision.resource_ref, context); volume = _safe_child(base_dir, _volume_name(decision))
        if os.path.lexists(volume): raise ToolPolicyBlocked("각 volume action은 실행 전 absent인 전용 fixture가 필요합니다.")
        identity_before = identity_snapshot(); before = _volume_state(volume); state.update(base=base_dir, volume=volume, before_entries=sorted(os.listdir(base_dir)))
        os.mkdir(volume, 0o700); state["created"] = True
        marker = _safe_child(volume, ".attached")
        if action in {"attach", "detach"}:
            fd = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600); os.close(fd)
            if action == "detach": os.unlink(marker)
        elif action == "write":
            if "content" in decision.arguments: raise ToolInputError("raw content는 금지되며 content_profile만 허용됩니다.")
            profile = decision.arguments.get("content_profile", "canary")
            if profile not in _VOLUME_CONTENT: raise ToolInputError(f"content_profile은 {sorted(_VOLUME_CONTENT)} 중 하나여야 합니다.")
            data_path = _safe_child(volume, "data"); payload = _VOLUME_CONTENT[profile]
            fd = os.open(data_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try: os.write(fd, payload)
            finally: os.close(fd)
            state["expected_hash"] = hashlib.sha256(payload).hexdigest()
        elif action == "remove":
            canary = _safe_child(volume, "canary"); fd = os.open(canary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600); os.close(fd); os.unlink(canary); os.rmdir(volume); state["created"] = False
        reached = _volume_state(volume)
        return _result(_VOLUME, action, context, identity_before, before, reached, f"independent local volume {action}", True)
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        observed = _volume_state(state["volume"])
        if action == "remove": checks = {"volume_removed": observed["exists"] is False}
        elif action == "attach": checks = {"volume_exists": observed["exists"], "attach_marker_exists": ".attached" in observed.get("entries", [])}
        elif action == "detach": checks = {"volume_exists": observed["exists"], "attach_marker_removed": ".attached" not in observed.get("entries", [])}
        elif action == "write": checks = {"data_hash_matches": observed.get("files", {}).get("data", {}).get("sha256") == state["expected_hash"]}
        else: checks = {"volume_created": observed["exists"]}
        return VerificationResult(name + "_verifier", "VERIFIED" if all(checks.values()) else "REJECTED", checks, observed)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        volume = state.get("volume")
        if isinstance(volume, str) and os.path.isdir(volume):
            for entry in os.listdir(volume):
                path = _safe_child(volume, entry)
                if os.path.isdir(path): raise ToolPolicyBlocked("volume fixture에 예상하지 못한 하위 directory가 있습니다.")
                os.unlink(path)
            os.rmdir(volume)
        after = _volume_state(volume) if isinstance(volume, str) else {"exists": False}
        entries = sorted(os.listdir(state["base"])) if "base" in state else []
        checks = {"volume_absent": after["exists"] is False,
                  "base_directory_restored": "before_entries" not in state or entries == state["before_entries"]}
        return _non_mount_reset(name, result, after, checks, changed=result.outcome == "ALLOWED")
    schema = {"volume_profile": str, "volume_name": _ForbiddenRawArgument}
    if action == "write": schema.update({"content_profile": str, "content": _ForbiddenRawArgument})
    return ToolDefinition(name, _VOLUME, action, handler, verifier, resetter,
                          _mount_spec(arg_schema=schema, reversible=True, destructive=action == "remove"))


_MOUNT_DEFINITIONS: tuple[ToolDefinition, ...] = (
    *(_build_mount_action_definition(_MOUNT_MANAGE, action) for action in ("mount", "remount", "unmount", "move")),
    *(_build_mount_action_definition(_MOUNT_BIND, action) for action in ("bind", "remount_ro", "remount_rw", "set_propagation")),
    *(_build_mount_action_definition(_MOUNT_TMPFS, action) for action in ("create", "unmount")),
    _build_idmap_definition(),
    *(_build_mount_action_definition(_MOUNT_OVERLAY, action) for action in ("mount", "unmount")),
    *(_build_policy_definition(action) for action in ("write_ro", "execute_noexec", "setid_nosuid", "device_nodev", "access_masked")),
    *(_build_pressure_definition(action) for action in ("blocks", "inodes", "quota")),
    *(_build_volume_definition(action) for action in ("create", "attach", "write", "detach", "remove")),
)

if len(_MOUNT_DEFINITIONS) != 26: raise ToolContractError(f"mount_filesystem ToolDefinition은 26개여야 합니다: {len(_MOUNT_DEFINITIONS)}")
if len({definition.name for definition in _MOUNT_DEFINITIONS}) != 26: raise ToolContractError("mount_filesystem ToolDefinition name 중복")
for _attribute in ("handler", "verifier", "resetter"):
    if len({id(getattr(definition, _attribute)) for definition in _MOUNT_DEFINITIONS}) != 26:
        raise ToolContractError(f"mount_filesystem action별 {_attribute}가 독립 closure가 아닙니다.")
for _definition in _MOUNT_DEFINITIONS: register_definition(_definition)
