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
import os
import subprocess
from typing import Any, Dict

from .base import (
    ToolContext,
    ToolInputError,
    ToolOutcome,
    ToolSpec,
    attempt,
    probe,
    register,
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
