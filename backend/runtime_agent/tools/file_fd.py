"""OStool 정리.md 5.2 파일·디렉터리·FD — 12개 Tool (file.content 제외, runtime.py 기구현).

각 register는 ToolSpec을 선언하고, dispatch가 실행 전에 요구 1·2·7을 자동 강제한다:
  1) allowed_executors / allowed_tbs — Executor·Trust Boundary 매트릭스
  2) resource_kind + arg_schema — raw 경로 차단 + 구조화 인자 allowlist(미지 키 거부·타입)
  7) destructive=True — Harness 전용 Fixture(destructive_enabled)에서만 실행

상태를 일시 변경하는 metadata·xattr·inode 계열은 probe()로 즉시 원복(rollback_status).
생성형(create/move_link)은 요구 8의 Reset을 register(reset=...)로 등록해 Harness가 정리한다.
파괴형(remove)은 destructive=True + rollback NOT_POSSIBLE.
"""
from __future__ import annotations

import array
import ctypes
import errno as errno_module
import fcntl
import os
import shutil
import socket
import stat as stat_module
import struct
import subprocess
import time
from typing import Any

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
    path_state,
    probe,
    raw_syscall,
    register,
    str_arg,
)

# ── ioctl 상수 (FS inode flags) ─────────────────────────────────────────────
FS_IOC_GETFLAGS = 0x80086601
FS_IOC_SETFLAGS = 0x40086601
FS_IMMUTABLE_FL = 0x00000010
FS_APPEND_FL = 0x00000020
FS_NODUMP_FL = 0x00000040
FS_NOATIME_FL = 0x00000080
_INODE_FLAG_NAMES = {
    "immutable": FS_IMMUTABLE_FL, "append_only": FS_APPEND_FL,
    "nodump": FS_NODUMP_FL, "noatime": FS_NOATIME_FL,
}
AT_FDCWD = -100
MAX_HANDLE_SZ = 128

# resource_kind="path" tool은 어느 Executor에서도 시도 가능(권한은 OS가 결정) → 기본 executors 전체.
_PATH = "path"
_FD = "fd"


def _target_path(arguments: dict[str, Any], context: ToolContext) -> str:
    return context.resolve_path(str_arg(arguments, "resource_ref"))


# ═══ 8. file.open ═══════════════════════════════════════════════════════════
_FILE_OPEN_TOOL = "file.open"
_OPEN_FLAGS = {
    "read": os.O_RDONLY, "write": os.O_WRONLY, "append": os.O_WRONLY | os.O_APPEND,
    "opath": getattr(os, "O_PATH", 0o10000000),
}
_OPEN_SPEC = ToolSpec(resource_kind=_PATH)


@register(_FILE_OPEN_TOOL, "read", spec=_OPEN_SPEC)
@register(_FILE_OPEN_TOOL, "write", spec=_OPEN_SPEC)
@register(_FILE_OPEN_TOOL, "append", spec=_OPEN_SPEC)
@register(_FILE_OPEN_TOOL, "opath", spec=_OPEN_SPEC)
def _file_open(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    path = _target_path(arguments, context)
    flags = _OPEN_FLAGS[action]

    def _op() -> str:
        fd = os.open(path, flags)
        try:
            return f"opened({action}) fd={fd}"
        finally:
            os.close(fd)

    return attempt(_FILE_OPEN_TOOL, action, _op)


@register(_FILE_OPEN_TOOL, "execute", spec=ToolSpec(resource_kind=_PATH))
def _file_open_execute(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    path = _target_path(arguments, context)

    def _op() -> str:
        pid = os.fork()
        if pid == 0:
            try:
                os.execv(path, [path])
            except OSError as exc:
                os._exit(exc.errno or 1)
            os._exit(0)
        _, status = os.waitpid(pid, 0)
        code = os.waitstatus_to_exitcode(status)
        if code in (errno_module.EACCES, errno_module.EPERM):
            raise OSError(code, os.strerror(code))
        return f"execve attempted exit={code}"

    return attempt(_FILE_OPEN_TOOL, "execute", _op)


# ═══ 9. file.create (Reset 등록) ════════════════════════════════════════════
_FILE_CREATE_TOOL = "file.create"
_CREATE_SPEC = ToolSpec(resource_kind=_PATH, arg_schema={"name": str, "mode": int}, required_args=frozenset({"name"}))


def _create_target(arguments: dict[str, Any], context: ToolContext) -> str:
    parent = _target_path(arguments, context)
    name = str_arg(arguments, "name")
    if "/" in name or name in (".", ".."):
        raise ToolInputError("name은 '/' 없는 단일 파일명이어야 합니다.")
    return os.path.join(parent, name)


def _file_create_reset(outcome: ToolOutcome, context: ToolContext) -> None:
    """요구 8 Reset: 생성한 객체 제거."""
    target = (outcome.state_after or {}).get("path")
    if not target or not os.path.lexists(target):
        return
    if os.path.isdir(target) and not os.path.islink(target):
        os.rmdir(target)
    else:
        os.unlink(target)


@register(_FILE_CREATE_TOOL, "file", spec=_CREATE_SPEC, reset=_file_create_reset)
@register(_FILE_CREATE_TOOL, "directory", spec=_CREATE_SPEC, reset=_file_create_reset)
@register(_FILE_CREATE_TOOL, "fifo", spec=_CREATE_SPEC, reset=_file_create_reset)
def _file_create(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _create_target(arguments, context)
    mode = int_arg_default(arguments, "mode", 0o600)
    if not (0 <= mode <= 0o777):
        raise ToolInputError("mode는 0~0o777 범위여야 합니다.")

    def _op() -> str:
        if action == "file":
            fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
            os.close(fd)
        elif action == "directory":
            os.mkdir(target, mode)
        else:
            os.mkfifo(target, mode)
        return f"created {action}: {os.path.basename(target)}"

    outcome = attempt(_FILE_CREATE_TOOL, action, _op)
    if outcome.outcome == "ALLOWED":
        outcome.state_after = {"path": target}  # Reset이 참조
    return outcome


# ═══ 11. file.remove (destructive) ══════════════════════════════════════════
_FILE_REMOVE_TOOL = "file.remove"
_REMOVE_SPEC = ToolSpec(resource_kind=_PATH, destructive=True)


@register(_FILE_REMOVE_TOOL, "unlink", spec=_REMOVE_SPEC)
@register(_FILE_REMOVE_TOOL, "rmdir", spec=_REMOVE_SPEC)
def _file_remove(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    path = _target_path(arguments, context)
    before = path_state(path)

    def _op() -> str:
        os.unlink(path) if action == "unlink" else os.rmdir(path)
        return f"{action}: {path}"

    outcome = attempt(_FILE_REMOVE_TOOL, action, _op)
    outcome.state_before = before
    outcome.state_after = path_state(path)
    outcome.rollback_status = "NOT_POSSIBLE" if outcome.outcome == "ALLOWED" else "NOT_REQUIRED"
    return outcome


# ═══ 12. file.move_link (Reset 등록) ════════════════════════════════════════
_FILE_MOVE_TOOL = "file.move_link"
_MOVE_SPEC = ToolSpec(resource_kind=_PATH, arg_schema={"dest_ref": str, "name": str},
                      required_args=frozenset({"dest_ref", "name"}))


def _move_reset(outcome: ToolOutcome, context: ToolContext) -> None:
    st = outcome.state_after or {}
    dst, src, act = st.get("dst"), st.get("src"), st.get("act")
    if not dst or not os.path.lexists(dst):
        return
    if act == "rename" and src:
        os.rename(dst, src)   # 되돌리기
    else:
        os.unlink(dst)        # hardlink/symlink 제거


@register(_FILE_MOVE_TOOL, "rename", spec=_MOVE_SPEC, reset=_move_reset)
@register(_FILE_MOVE_TOOL, "hardlink", spec=_MOVE_SPEC, reset=_move_reset)
@register(_FILE_MOVE_TOOL, "symlink", spec=_MOVE_SPEC, reset=_move_reset)
def _file_move_link(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    src = _target_path(arguments, context)
    dst_parent = context.resolve_path(str_arg(arguments, "dest_ref"))
    name = str_arg(arguments, "name")
    if "/" in name or name in (".", ".."):
        raise ToolInputError("name은 '/' 없는 단일 파일명이어야 합니다.")
    dst = os.path.join(dst_parent, name)

    def _op() -> str:
        if action == "rename":
            os.rename(src, dst)
        elif action == "hardlink":
            os.link(src, dst, follow_symlinks=False)
        else:
            os.symlink(src, dst)
        return f"{action}: {os.path.basename(dst)}"

    outcome = attempt(_FILE_MOVE_TOOL, action, _op)
    if outcome.outcome == "ALLOWED":
        outcome.state_after = {"dst": dst, "src": src, "act": action}
    return outcome


@register(_FILE_MOVE_TOOL, "follow", spec=ToolSpec(resource_kind=_PATH))
def _file_move_follow(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    link = _target_path(arguments, context)

    def _op() -> str:
        realpath = os.path.realpath(link)
        fd = os.open(link, os.O_RDONLY)
        try:
            return f"followed -> {realpath}"
        finally:
            os.close(fd)

    return attempt(_FILE_MOVE_TOOL, "follow", _op)


# ═══ 13. file.metadata (reversible probe) ═══════════════════════════════════
_FILE_METADATA_TOOL = "file.metadata"


@register(_FILE_METADATA_TOOL, "chmod",
          spec=ToolSpec(resource_kind=_PATH, arg_schema={"mode": int}, required_args=frozenset({"mode"}), reversible=True))
def _file_chmod(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    path = _target_path(arguments, context)
    mode = int_arg(arguments, "mode")
    if not (0 <= mode <= 0o7777):
        raise ToolInputError("mode는 0~0o7777 범위여야 합니다.")
    original = stat_module.S_IMODE(os.lstat(path).st_mode)
    return probe(
        _FILE_METADATA_TOOL, "chmod",
        mutate=lambda: (os.chmod(path, mode), f"chmod {oct(mode)}")[1],
        snapshot_state=lambda: path_state(path),
        restore=lambda: os.chmod(path, original),
    )


@register(_FILE_METADATA_TOOL, "chown",
          spec=ToolSpec(resource_kind=_PATH, arg_schema={"uid": int, "gid": int}, reversible=True))
@register(_FILE_METADATA_TOOL, "chgrp",
          spec=ToolSpec(resource_kind=_PATH, arg_schema={"gid": int}, required_args=frozenset({"gid"}), reversible=True))
def _file_chown(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    path = _target_path(arguments, context)
    st = os.lstat(path)
    uid = int_arg_default(arguments, "uid", -1) if action == "chown" else -1
    gid = int_arg(arguments, "gid") if action == "chgrp" else int_arg_default(arguments, "gid", -1)
    return probe(
        _FILE_METADATA_TOOL, action,
        mutate=lambda: (os.chown(path, uid, gid, follow_symlinks=False), f"{action} uid={uid} gid={gid}")[1],
        snapshot_state=lambda: path_state(path),
        restore=lambda: os.chown(path, st.st_uid, st.st_gid, follow_symlinks=False),
    )


@register(_FILE_METADATA_TOOL, "set_times",
          spec=ToolSpec(resource_kind=_PATH, arg_schema={"atime": int, "mtime": int}, reversible=True))
def _file_set_times(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    path = _target_path(arguments, context)
    atime = int_arg_default(arguments, "atime", int(time.time()))
    mtime = int_arg_default(arguments, "mtime", int(time.time()))
    st = os.lstat(path)
    return probe(
        _FILE_METADATA_TOOL, "set_times",
        mutate=lambda: (os.utime(path, (atime, mtime), follow_symlinks=False), f"utime a={atime} m={mtime}")[1],
        snapshot_state=lambda: path_state(path),
        restore=lambda: os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns), follow_symlinks=False),
    )


# ═══ 14. file.acl ═══════════════════════════════════════════════════════════
_FILE_ACL_TOOL = "file.acl"
_ACL_ENTRY_OK = frozenset("ugomdxrw:,-.0123456789_/")


def _validate_acl_entry(entry: str) -> str:
    if not entry or len(entry) > 128 or any(ch not in _ACL_ENTRY_OK for ch in entry):
        raise ToolInputError("acl entry 형식이 허용되지 않습니다.")
    return entry


@register(_FILE_ACL_TOOL, "get", spec=ToolSpec(resource_kind=_PATH))
def _file_acl_get(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    path = _target_path(arguments, context)
    return attempt(_FILE_ACL_TOOL, "get",
                   lambda: f"acl_access {len(os.getxattr(path, 'system.posix_acl_access'))}B")


@register(_FILE_ACL_TOOL, "set_access",
          spec=ToolSpec(resource_kind=_PATH, arg_schema={"entry": str}, required_args=frozenset({"entry"})))
@register(_FILE_ACL_TOOL, "set_default",
          spec=ToolSpec(resource_kind=_PATH, arg_schema={"entry": str}, required_args=frozenset({"entry"})))
@register(_FILE_ACL_TOOL, "remove", spec=ToolSpec(resource_kind=_PATH))
def _file_acl_change(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    path = _target_path(arguments, context)
    setfacl = shutil.which("setfacl")
    if setfacl is None:
        return ToolOutcome(tool=_FILE_ACL_TOOL, action=action, attempted=False, outcome="ERROR",
                           output="setfacl 미설치", rollback_status="NOT_REQUIRED")
    if action == "remove":
        argv = [setfacl, "-b", path]
    else:
        entry = _validate_acl_entry(str_arg(arguments, "entry"))
        argv = [setfacl, "-m" if action == "set_access" else "-dm", entry, path]
    before = path_state(path)

    def _op() -> str:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            raise OSError(errno_module.EPERM, result.stderr.strip() or "setfacl 실패")
        return f"setfacl {action}"

    outcome = attempt(_FILE_ACL_TOOL, action, _op)
    outcome.state_before = before
    outcome.state_after = path_state(path)
    return outcome


# ═══ 15. file.xattr (set/remove reversible probe) ═══════════════════════════
_FILE_XATTR_TOOL = "file.xattr"
_XATTR_NAME_OK = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._")


def _validate_xattr_name(name: str) -> str:
    if not name.startswith(("user.", "security.", "trusted.", "system.")):
        raise ToolInputError("xattr name은 user./security./trusted./system. 접두사가 필요합니다.")
    if any(ch not in _XATTR_NAME_OK for ch in name) or len(name) > 128:
        raise ToolInputError("xattr name 형식이 허용되지 않습니다.")
    return name


@register(_FILE_XATTR_TOOL, "get",
          spec=ToolSpec(resource_kind=_PATH, arg_schema={"name": str}, required_args=frozenset({"name"})))
def _file_xattr_get(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    path = _target_path(arguments, context)
    name = _validate_xattr_name(str_arg(arguments, "name"))
    return attempt(_FILE_XATTR_TOOL, "get", lambda: f"xattr {name}={os.getxattr(path, name)!r}")


@register(_FILE_XATTR_TOOL, "set",
          spec=ToolSpec(resource_kind=_PATH, arg_schema={"name": str, "value": str},
                        required_args=frozenset({"name", "value"}), reversible=True))
def _file_xattr_set(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    path = _target_path(arguments, context)
    name = _validate_xattr_name(str_arg(arguments, "name"))
    value = bounded_content(arguments, "value").encode()
    existed = name in os.listxattr(path)
    old = os.getxattr(path, name) if existed else None

    def _restore() -> None:
        if existed:
            os.setxattr(path, name, old)  # type: ignore[arg-type]
        else:
            try:
                os.removexattr(path, name)
            except OSError:
                pass

    return probe(_FILE_XATTR_TOOL, "set",
                 mutate=lambda: (os.setxattr(path, name, value), f"set {name}")[1],
                 snapshot_state=lambda: path_state(path), restore=_restore)


@register(_FILE_XATTR_TOOL, "remove",
          spec=ToolSpec(resource_kind=_PATH, arg_schema={"name": str}, required_args=frozenset({"name"}), reversible=True))
def _file_xattr_remove(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    path = _target_path(arguments, context)
    name = _validate_xattr_name(str_arg(arguments, "name"))
    old = os.getxattr(path, name) if name in os.listxattr(path) else None

    def _restore() -> None:
        if old is not None:
            os.setxattr(path, name, old)

    return probe(_FILE_XATTR_TOOL, "remove",
                 mutate=lambda: (os.removexattr(path, name), f"remove {name}")[1],
                 snapshot_state=lambda: path_state(path), restore=_restore)


# ═══ 16. file.inode_flags (set/clear reversible probe) ══════════════════════
_FILE_INODE_TOOL = "file.inode_flags"


def _read_inode_flags(fd: int) -> int:
    buf = array.array("i", [0])
    fcntl.ioctl(fd, FS_IOC_GETFLAGS, buf, True)
    return buf[0]


def _write_inode_flags(fd: int, flags: int) -> None:
    fcntl.ioctl(fd, FS_IOC_SETFLAGS, array.array("i", [flags]), False)


@register(_FILE_INODE_TOOL, "get", spec=ToolSpec(resource_kind=_PATH))
def _inode_get(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    path = _target_path(arguments, context)

    def _op() -> str:
        fd = os.open(path, os.O_RDONLY)
        try:
            return f"inode_flags={_read_inode_flags(fd):#x}"
        finally:
            os.close(fd)

    return attempt(_FILE_INODE_TOOL, "get", _op)


@register(_FILE_INODE_TOOL, "set",
          spec=ToolSpec(resource_kind=_PATH, arg_schema={"flag": str}, required_args=frozenset({"flag"}), reversible=True))
@register(_FILE_INODE_TOOL, "clear",
          spec=ToolSpec(resource_kind=_PATH, arg_schema={"flag": str}, required_args=frozenset({"flag"}), reversible=True))
def _inode_change(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    path = _target_path(arguments, context)
    flag = _INODE_FLAG_NAMES[enum_arg(arguments, "flag", frozenset(_INODE_FLAG_NAMES))]

    def _mutate() -> str:
        fd = os.open(path, os.O_RDONLY)
        try:
            cur = _read_inode_flags(fd)
            new = cur | flag if action == "set" else cur & ~flag
            _write_inode_flags(fd, new)
            return f"{action} flag={flag:#x} -> {new:#x}"
        finally:
            os.close(fd)

    def _restore() -> None:
        fd = os.open(path, os.O_RDONLY)
        try:
            cur = _read_inode_flags(fd)
            _write_inode_flags(fd, cur & ~flag if action == "set" else cur | flag)
        finally:
            os.close(fd)

    return probe(_FILE_INODE_TOOL, action, mutate=_mutate,
                 snapshot_state=lambda: path_state(path), restore=_restore)


# ═══ 17. file.lock_lease ════════════════════════════════════════════════════
_FILE_LOCK_TOOL = "file.lock_lease"
F_SETLEASE = 1024
F_RDLCK, F_WRLCK, F_UNLCK = 0, 1, 2


@register(_FILE_LOCK_TOOL, "lock", spec=ToolSpec(resource_kind=_PATH))
@register(_FILE_LOCK_TOOL, "unlock", spec=ToolSpec(resource_kind=_PATH))
def _file_lock(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    path = _target_path(arguments, context)

    def _op() -> str:
        fd = os.open(path, os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB if action == "lock" else fcntl.LOCK_UN)
            return f"flock {action}"
        finally:
            os.close(fd)

    return attempt(_FILE_LOCK_TOOL, action, _op)


@register(_FILE_LOCK_TOOL, "lease_set", spec=ToolSpec(resource_kind=_PATH))
@register(_FILE_LOCK_TOOL, "lease_release", spec=ToolSpec(resource_kind=_PATH))
def _file_lease(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    path = _target_path(arguments, context)

    def _op() -> str:
        fd = os.open(path, os.O_RDONLY)
        try:
            fcntl.fcntl(fd, F_SETLEASE, F_RDLCK if action == "lease_set" else F_UNLCK)
            return f"lease {action}"
        finally:
            os.close(fd)

    return attempt(_FILE_LOCK_TOOL, action, _op)


# ═══ 18. file.open_by_handle ════════════════════════════════════════════════
_FILE_HANDLE_TOOL = "file.open_by_handle"


class _FileHandle(ctypes.Structure):
    _fields_ = [("handle_bytes", ctypes.c_uint), ("handle_type", ctypes.c_int),
                ("f_handle", ctypes.c_ubyte * MAX_HANDLE_SZ)]


@register(_FILE_HANDLE_TOOL, "name_to_handle", spec=ToolSpec(resource_kind=_PATH))
def _name_to_handle(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    path = _target_path(arguments, context)

    def _op() -> str:
        handle = _FileHandle(); handle.handle_bytes = MAX_HANDLE_SZ
        mount_id = ctypes.c_int()
        raw_syscall("name_to_handle_at", AT_FDCWD, path.encode(),
                    ctypes.byref(handle), ctypes.byref(mount_id), 0)
        return f"handle bytes={handle.handle_bytes} mount_id={mount_id.value}"

    return attempt(_FILE_HANDLE_TOOL, "name_to_handle", _op)


@register(_FILE_HANDLE_TOOL, "open_by_handle", spec=ToolSpec(resource_kind=_PATH))
def _open_by_handle(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    path = _target_path(arguments, context)

    def _op() -> str:
        handle = _FileHandle(); handle.handle_bytes = MAX_HANDLE_SZ
        mount_id = ctypes.c_int()
        raw_syscall("name_to_handle_at", AT_FDCWD, path.encode(),
                    ctypes.byref(handle), ctypes.byref(mount_id), 0)
        # mount_fd는 대상 fs의 실제 열린 FD여야 한다(AT_FDCWD/O_PATH는 EBADF). 상위 디렉터리 사용.
        mount_fd = os.open(os.path.dirname(path) or ".", os.O_RDONLY | os.O_DIRECTORY)
        try:
            fd = raw_syscall("open_by_handle_at", mount_fd, ctypes.byref(handle), os.O_RDONLY)
            os.close(fd)
            return "open_by_handle ok"
        finally:
            os.close(mount_fd)

    return attempt(_FILE_HANDLE_TOOL, "open_by_handle", _op)


# ═══ 19. fd.operate ═════════════════════════════════════════════════════════
_FD_OPERATE_TOOL = "fd.operate"


def _resolve_fd(arguments: dict[str, Any], context: ToolContext) -> int:
    fd = int_arg(arguments, "fd")
    if fd < 0:
        raise ToolInputError("fd는 음수가 아니어야 합니다.")
    fd_refs = {t for t in context.allowed_targets if t.startswith("fd:")}
    if fd_refs and f"fd:{fd}" not in fd_refs:
        raise ToolPolicyBlocked(f"등록되지 않은 FD 참조입니다: fd:{fd}")
    return fd


@register(_FD_OPERATE_TOOL, "read", spec=ToolSpec(resource_kind=_FD, arg_schema={"count": int}))
@register(_FD_OPERATE_TOOL, "write", spec=ToolSpec(resource_kind=_FD, arg_schema={"content": str}, required_args=frozenset({"content"})))
@register(_FD_OPERATE_TOOL, "seek", spec=ToolSpec(resource_kind=_FD, arg_schema={"offset": int}))
@register(_FD_OPERATE_TOOL, "truncate", spec=ToolSpec(resource_kind=_FD, arg_schema={"length": int}, destructive=True))
@register(_FD_OPERATE_TOOL, "dup", spec=ToolSpec(resource_kind=_FD))
@register(_FD_OPERATE_TOOL, "close", spec=ToolSpec(resource_kind=_FD))
def _fd_operate(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    fd = _resolve_fd(arguments, context)

    def _op() -> str:
        if action == "read":
            return f"read {len(os.read(fd, min(int_arg_default(arguments, 'count', 256), 4096)))}B"
        if action == "write":
            return f"wrote {os.write(fd, bounded_content(arguments, 'content').encode())}B"
        if action == "seek":
            return f"seek -> {os.lseek(fd, int_arg_default(arguments, 'offset', 0), os.SEEK_SET)}"
        if action == "truncate":
            os.ftruncate(fd, int_arg_default(arguments, "length", 0))
            return "ftruncate ok"
        if action == "dup":
            new = os.dup(fd); os.close(new)
            return f"dup -> {new}"
        os.close(fd)
        return "close ok"

    return attempt(_FD_OPERATE_TOOL, action, _op)


# ═══ 20. fd.transfer ════════════════════════════════════════════════════════
_FD_TRANSFER_TOOL = "fd.transfer"


@register(_FD_TRANSFER_TOOL, "scm_send", spec=ToolSpec(resource_kind=_FD))
@register(_FD_TRANSFER_TOOL, "scm_receive", spec=ToolSpec(resource_kind=_FD))
def _fd_scm(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    fd = _resolve_fd(arguments, context)

    def _op() -> str:
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            a.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))])
            if action == "scm_send":
                return "scm_send ok"
            _m, anc, _f, _a = b.recvmsg(1, socket.CMSG_LEN(struct.calcsize("i")))
            got = array.array("i")
            for _l, _t, cm in anc:
                got.frombytes(cm[: len(cm) - (len(cm) % got.itemsize)])
            for g in got:
                os.close(g)
            return f"scm_receive got {len(got)} fd"
        finally:
            a.close(); b.close()

    return attempt(_FD_TRANSFER_TOOL, action, _op)


@register(_FD_TRANSFER_TOOL, "pidfd_getfd",
          spec=ToolSpec(resource_kind="none", arg_schema={"pid": int, "target_fd": int},
                        required_args=frozenset({"pid", "target_fd"})))
def _fd_pidfd_getfd(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    pid = int_arg(arguments, "pid")
    target_fd = int_arg(arguments, "target_fd")
    pid_refs = {t for t in context.allowed_targets if t.startswith("pid:")}
    if pid_refs and f"pid:{pid}" not in pid_refs:
        raise ToolPolicyBlocked(f"등록되지 않은 PID 참조입니다: pid:{pid}")

    def _op() -> str:
        pidfd = raw_syscall("pidfd_open", pid, 0)
        try:
            stolen = raw_syscall("pidfd_getfd", pidfd, target_fd, 0)
            os.close(stolen)
            return "pidfd_getfd ok"
        finally:
            os.close(pidfd)

    return attempt(_FD_TRANSFER_TOOL, "pidfd_getfd", _op)


@register(_FD_TRANSFER_TOOL, "inherit", spec=ToolSpec(resource_kind=_FD))
def _fd_inherit(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    fd = _resolve_fd(arguments, context)

    def _op() -> str:
        flags = fcntl.fcntl(fd, fcntl.F_GETFD)
        fcntl.fcntl(fd, fcntl.F_SETFD, flags & ~fcntl.FD_CLOEXEC)
        pid = os.fork()
        if pid == 0:
            try:
                os.fstat(fd); os._exit(0)
            except OSError as exc:
                os._exit(exc.errno or 1)
        _, status = os.waitpid(pid, 0)
        return f"inherit child exit={os.waitstatus_to_exitcode(status)}"

    return attempt(_FD_TRANSFER_TOOL, "inherit", _op)
