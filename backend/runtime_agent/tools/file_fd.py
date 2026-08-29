"""OStool 정리.md 5.2 파일·디렉터리·FD — canonical 13개 Tool / 49개 Action.

파일 아래쪽의 action별 ToolDefinition이 구현 완료 집계 대상이다. 각 Definition은
handler가 실제 syscall 후 도달 상태를 유지하고, verifier가 OS를 독립 재조회한 다음,
resetter가 내용·owner·mode·timestamp·xattr·inode flag와 열린 FD를 복구·재조회한다.
raw path/PID/FD는 받지 않고 Harness가 등록한 resource_ref만 해석한다.

상단 legacy @register 함수는 runtime.py 전환 전 호환용이며 구현 완료로 세지 않는다.
기존 generic verifier/resetter 등록은 제거했다. remove/truncate 같은 파괴적 Action도
전용 fixture·크기 한도·timeout·비상 중단 조건 아래 backup 후 실제 복구한다.
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
from typing import Any, Mapping

from .base import (
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
    ResetResult,
    attempt,
    bounded_content,
    enum_arg,
    int_arg,
    int_arg_default,
    path_state,
    probe,
    raw_syscall,
    register,
    register_definition,
    str_arg,
    identity_snapshot,
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
_MAX_RESTORE_BYTES = 1024 * 1024
_READ_OUTPUT_BYTES = 4096


def _target_path(arguments: dict[str, Any], context: ToolContext) -> str:
    return context.resolve_path(str_arg(arguments, "resource_ref"))


def _read_regular(path: str, *, limit: int, complete: bool) -> tuple[bytes, os.stat_result]:
    """symlink/FIFO/device를 따르지 않고 제한된 크기의 일반 파일만 읽는다."""
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOATIME", 0)
    )
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat_module.S_ISREG(st.st_mode):
            raise ToolPolicyBlocked("file.content는 등록된 일반 파일 Target에만 사용할 수 있습니다.")
        if complete and st.st_size > limit:
            raise ToolPolicyBlocked(f"rollback 대상 파일은 {limit}바이트 이하여야 합니다.")
        remaining = limit + (1 if complete else 0)
        chunks: list[bytes] = []
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if complete and len(data) > limit:
            raise ToolPolicyBlocked(f"rollback 대상 파일은 {limit}바이트 이하여야 합니다.")
        return data[:limit], st
    finally:
        os.close(fd)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError(errno_module.EIO, "파일 쓰기가 진행되지 않았습니다.")
        view = view[written:]


def _capture_for_restore(path: str, *, allow_missing: bool = False) -> tuple[bytes, os.stat_result] | None:
    try:
        return _read_regular(path, limit=_MAX_RESTORE_BYTES, complete=True)
    except FileNotFoundError:
        if allow_missing:
            return None
        raise


def _restore_content(path: str, original: tuple[bytes, os.stat_result] | None) -> None:
    if original is None:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        return

    content, st = original
    flags = os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        _write_all(fd, content)
        os.fchmod(fd, stat_module.S_IMODE(st.st_mode))
    finally:
        os.close(fd)
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns), follow_symlinks=False)


def _verify_file_content(outcome: ToolOutcome) -> bool:
    if not outcome.attempted or outcome.outcome not in {"ALLOWED", "OS_DENIED"}:
        return False
    if outcome.action == "read" or outcome.outcome == "OS_DENIED":
        return outcome.rollback_status != "FAILED"
    return outcome.rollback_status == "VERIFIED" and outcome.state_before == outcome.state_after


def _file_content_reset(outcome: ToolOutcome, context: ToolContext) -> None:
    """inline rollback 뒤 현재 상태가 초기 상태와 같은지 Harness Reset 단계에서 재확인한다."""
    del context
    before = outcome.state_before or {}
    path = before.get("path")
    if not isinstance(path, str) or path_state(path) != before:
        raise OSError(errno_module.EIO, "file.content 복구 상태 검증 실패")


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


# ═══ 10. file.content (실제 I/O + 즉시 rollback) ═══════════════════════════
_FILE_CONTENT_TOOL = "file.content"
_CONTENT_READ_SPEC = ToolSpec(resource_kind=_PATH)
_CONTENT_WRITE_SPEC = ToolSpec(
    resource_kind=_PATH,
    arg_schema={"content": str},
    required_args=frozenset({"content"}),
    reversible=True,
)
_CONTENT_MUTATE_SPEC = ToolSpec(resource_kind=_PATH, reversible=True)
_CONTENT_COPY_SPEC = ToolSpec(
    resource_kind=_PATH,
    arg_schema={"dest_ref": str},
    required_args=frozenset({"dest_ref"}),
    reversible=True,
)


@register(_FILE_CONTENT_TOOL, "read", spec=_CONTENT_READ_SPEC, verify=_verify_file_content)
def _file_content_read(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    path = _target_path(arguments, context)
    before = path_state(path)

    def _op() -> str:
        data, st = _read_regular(path, limit=_READ_OUTPUT_BYTES, complete=False)
        suffix = " (truncated)" if st.st_size > len(data) else ""
        return f"{data.decode('utf-8', errors='replace')}{suffix}"

    outcome = attempt(_FILE_CONTENT_TOOL, action, _op)
    outcome.state_before = before
    outcome.state_after = path_state(path)
    outcome.rollback_status = "NOT_REQUIRED"
    return outcome


@register(
    _FILE_CONTENT_TOOL,
    "write",
    spec=_CONTENT_WRITE_SPEC,
    verify=_verify_file_content,
    reset=_file_content_reset,
)
@register(
    _FILE_CONTENT_TOOL,
    "append",
    spec=_CONTENT_WRITE_SPEC,
    verify=_verify_file_content,
    reset=_file_content_reset,
)
@register(
    _FILE_CONTENT_TOOL,
    "truncate",
    spec=_CONTENT_MUTATE_SPEC,
    verify=_verify_file_content,
    reset=_file_content_reset,
)
def _file_content_change(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    path = _target_path(arguments, context)
    original: dict[str, tuple[bytes, os.stat_result] | None] = {}

    def _mutate() -> str:
        original["value"] = _capture_for_restore(path)
        try:
            if action == "truncate":
                os.truncate(path, 0)
                return "truncated to 0B"
            content = bounded_content(arguments).encode()
            flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
            if action == "write":
                flags |= os.O_TRUNC
            else:
                flags |= os.O_APPEND
            fd = os.open(path, flags)
            try:
                _write_all(fd, content)
            finally:
                os.close(fd)
            return f"{action} {len(content)}B"
        except OSError:
            _restore_content(path, original["value"])
            raise

    return probe(
        _FILE_CONTENT_TOOL,
        action,
        mutate=_mutate,
        snapshot_state=lambda: path_state(path),
        restore=lambda: _restore_content(path, original["value"]),
    )


@register(
    _FILE_CONTENT_TOOL,
    "copy",
    spec=_CONTENT_COPY_SPEC,
    verify=_verify_file_content,
    reset=_file_content_reset,
)
def _file_content_copy(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    source = _target_path(arguments, context)
    destination = context.resolve_path(str_arg(arguments, "dest_ref"))
    if os.path.abspath(source) == os.path.abspath(destination):
        raise ToolInputError("copy의 source와 destination은 서로 다른 resource_ref여야 합니다.")
    original: dict[str, tuple[bytes, os.stat_result] | None] = {}

    def _mutate() -> str:
        source_content, _ = _read_regular(source, limit=_MAX_RESTORE_BYTES, complete=True)
        original["value"] = _capture_for_restore(destination, allow_missing=True)
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(destination, flags, 0o600)
            try:
                _write_all(fd, source_content)
            finally:
                os.close(fd)
            return f"copied {len(source_content)}B"
        except OSError:
            _restore_content(destination, original["value"])
            raise

    return probe(
        _FILE_CONTENT_TOOL,
        action,
        mutate=_mutate,
        snapshot_state=lambda: path_state(destination),
        restore=lambda: _restore_content(destination, original["value"]),
    )


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


# ══════════════════════════════════════════════════════════════════════════════
# ToolDefinition 전환 계층
#
# legacy @register 경로는 runtime.py 전환 전 호환용이다. 아래 registry만이
# handler → verifier → resetter를 분리해 실행하며 구현 완료 집계 대상이다.
# 각 builder 호출은 action 하나마다 서로 다른 세 closure와 ToolDefinition을
# 만든다. handler는 도달 상태를 유지하고 resetter만 실제 복구를 수행한다.
# ══════════════════════════════════════════════════════════════════════════════

_FILE_EXECUTORS = frozenset({"host", "container"})
_FILE_TBS = frozenset({"TB-HH-U1U2", "TB-CC-C1C2"})
_DESTRUCTIVE_LIMITS = {"max_restore_bytes": _MAX_RESTORE_BYTES, "max_targets": 1}
_DESTRUCTIVE_STOPS = frozenset({"timeout", "target_escape", "rollback_failure"})
F_GETLEASE = 1025


class _ForbiddenRawArgument:
    """JSON/model 입력으로 생성할 수 없는 raw pid/fd 차단용 schema marker."""


def _definition_spec(
    resource_kind: str,
    *,
    arg_schema: dict[str, Any] | None = None,
    required_args: frozenset[str] = frozenset(),
    reversible: bool = False,
    destructive: bool = False,
    timeout_s: float = 8.0,
) -> ToolSpec:
    effective_schema = dict(arg_schema or {})
    if resource_kind == _FD:
        effective_schema["fd"] = _ForbiddenRawArgument
    elif resource_kind == "pid":
        effective_schema["pid"] = _ForbiddenRawArgument
    return ToolSpec(
        resource_kind=resource_kind,
        allowed_executors=_FILE_EXECUTORS,
        allowed_tbs=_FILE_TBS,
        arg_schema=effective_schema,
        required_args=required_args,
        reversible=reversible,
        destructive=destructive,
        timeout_s=timeout_s,
        resource_limits=dict(_DESTRUCTIVE_LIMITS) if destructive else {},
        emergency_stop_conditions=_DESTRUCTIVE_STOPS if destructive else frozenset(),
    )


def _definition_path(decision: ToolDecision, context: ToolContext) -> str:
    if decision.resource_ref is None:
        raise ToolInputError("resource_ref가 필요합니다.")
    return context.resolve_path(decision.resource_ref)


def _definition_fd(decision: ToolDecision, context: ToolContext) -> int:
    if "fd" in decision.arguments:
        raise ToolInputError("raw fd 인자는 금지되며 resource_ref만 허용됩니다.")
    if decision.resource_ref is None:
        raise ToolInputError("FD resource_ref가 필요합니다.")
    value = context.resolve_resource(decision.resource_ref)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ToolPolicyBlocked("resource_ref가 유효한 FD를 가리키지 않습니다.")
    return value


def _fixture_child(parent: str, name: Any) -> str:
    if not isinstance(name, str) or not name or len(name) > 128:
        raise ToolInputError("name은 1~128자의 단일 파일명이어야 합니다.")
    if name in {".", ".."} or "/" in name or "\\" in name or "\x00" in name:
        raise ToolInputError("name에 경로 구분자나 traversal은 허용되지 않습니다.")
    parent_real = os.path.realpath(parent)
    if not os.path.isdir(parent_real) or os.path.islink(parent):
        raise ToolPolicyBlocked("생성 부모는 symlink가 아닌 등록된 fixture 디렉터리여야 합니다.")
    target = os.path.abspath(os.path.join(parent_real, name))
    try:
        inside_fixture = os.path.commonpath([parent_real, target]) == parent_real
    except ValueError:
        inside_fixture = False
    if not inside_fixture:
        raise ToolPolicyBlocked("생성 대상이 fixture 디렉터리를 벗어났습니다.")
    return target


def _realpath_is_registered(path: str, context: ToolContext) -> bool:
    real = os.path.realpath(path)
    for registered in context.resource_paths.values():
        if not isinstance(registered, str):
            continue
        candidate = os.path.realpath(registered)
        if real == candidate:
            return True
        if os.path.isdir(candidate):
            try:
                if os.path.commonpath([candidate, real]) == candidate:
                    return True
            except ValueError:
                continue
    return False


def _xattr_snapshot(path: str) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except (OSError, TypeError):
        return result
    for name in names:
        try:
            result[name] = os.getxattr(path, name, follow_symlinks=False).hex()
        except (OSError, TypeError):
            continue
    return result


def _inode_flags_path(path: str) -> int | None:
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        return _read_inode_flags(fd)
    except OSError:
        return None
    finally:
        os.close(fd)


def _full_path_state(path: str) -> dict[str, Any]:
    if not os.path.lexists(path):
        return {"path": path, "exists": False}
    st = os.lstat(path)
    result: dict[str, Any] = {
        "path": path,
        "exists": True,
        "mode": stat_module.S_IMODE(st.st_mode),
        "type": stat_module.S_IFMT(st.st_mode),
        "uid": st.st_uid,
        "gid": st.st_gid,
        "size": st.st_size,
        "nlink": st.st_nlink,
        "atime_ns": st.st_atime_ns,
        "mtime_ns": st.st_mtime_ns,
        "xattrs": _xattr_snapshot(path),
        "inode_flags": _inode_flags_path(path),
    }
    if stat_module.S_ISREG(st.st_mode):
        data, _ = _read_regular(path, limit=_MAX_RESTORE_BYTES, complete=True)
        import hashlib
        result["sha256"] = hashlib.sha256(data).hexdigest()
        # content 조회로 atime이 바뀔 수 있으므로 관측 완료 시점 timestamp를 사용한다.
        observed = os.lstat(path)
        result["atime_ns"] = observed.st_atime_ns
        result["mtime_ns"] = observed.st_mtime_ns
    elif stat_module.S_ISLNK(st.st_mode):
        result["link_target"] = os.readlink(path)
    return result


def _capture_path_backup(path: str, *, allow_missing: bool = False) -> dict[str, Any]:
    if not os.path.lexists(path):
        if allow_missing:
            return {"state": {"path": path, "exists": False}}
        raise FileNotFoundError(path)
    state = _full_path_state(path)
    mode_type = state["type"]
    backup: dict[str, Any] = {"state": state}
    if mode_type == stat_module.S_IFREG:
        content, _ = _read_regular(path, limit=_MAX_RESTORE_BYTES, complete=True)
        backup["content"] = content
        observed = os.lstat(path)
        state["atime_ns"] = observed.st_atime_ns
        state["mtime_ns"] = observed.st_mtime_ns
    elif mode_type == stat_module.S_IFDIR:
        if os.listdir(path):
            raise ToolPolicyBlocked("rollback 대상 디렉터리는 비어 있어야 합니다.")
    elif mode_type == stat_module.S_IFLNK:
        backup["link_target"] = os.readlink(path)
    elif mode_type != stat_module.S_IFIFO:
        raise ToolPolicyBlocked("지원되지 않는 fixture 파일 형식입니다.")
    return backup


def _remove_path(path: str) -> None:
    if not os.path.lexists(path):
        return
    if os.path.isdir(path) and not os.path.islink(path):
        os.rmdir(path)
    else:
        os.unlink(path)


def _restore_xattrs(path: str, expected: Mapping[str, str]) -> None:
    try:
        current = set(os.listxattr(path, follow_symlinks=False))
    except (OSError, TypeError):
        current = set()
    for name in current - set(expected):
        try:
            os.removexattr(path, name, follow_symlinks=False)
        except (OSError, TypeError):
            pass
    for name, encoded in expected.items():
        os.setxattr(path, name, bytes.fromhex(encoded), follow_symlinks=False)


def _chmod_nofollow(path: str, mode: int) -> None:
    try:
        os.chmod(path, mode, follow_symlinks=False)
    except (NotImplementedError, TypeError):
        if os.path.islink(path):
            raise ToolPolicyBlocked("이 OS는 symlink chmod를 안전하게 지원하지 않습니다.")
        os.chmod(path, mode)


def _chown_nofollow(path: str, uid: int, gid: int) -> None:
    try:
        os.chown(path, uid, gid, follow_symlinks=False)
    except (NotImplementedError, TypeError):
        if os.path.islink(path):
            raise ToolPolicyBlocked("이 OS는 symlink chown을 안전하게 지원하지 않습니다.")
        os.chown(path, uid, gid)


def _utime_nofollow(path: str, *, ns: tuple[int, int]) -> None:
    try:
        os.utime(path, ns=ns, follow_symlinks=False)
    except (NotImplementedError, TypeError):
        if os.path.islink(path):
            raise ToolPolicyBlocked("이 OS는 symlink timestamp 변경을 안전하게 지원하지 않습니다.")
        os.utime(path, ns=ns)


def _restore_path_backup(backup: Mapping[str, Any]) -> None:
    state = backup["state"]
    path = state["path"]
    if not state["exists"]:
        _remove_path(path)
        return
    kind = state["type"]
    if not os.path.lexists(path):
        if kind == stat_module.S_IFREG:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, state["mode"])
            os.close(fd)
        elif kind == stat_module.S_IFDIR:
            os.mkdir(path, state["mode"])
        elif kind == stat_module.S_IFIFO:
            os.mkfifo(path, state["mode"])
        elif kind == stat_module.S_IFLNK:
            os.symlink(backup["link_target"], path)
        else:
            raise ToolContractError("복구할 수 없는 fixture 파일 형식입니다.")
    if kind == stat_module.S_IFREG:
        fd = os.open(path, os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0))
        try:
            _write_all(fd, backup["content"])
        finally:
            os.close(fd)
    if kind != stat_module.S_IFLNK:
        _chmod_nofollow(path, state["mode"])
    try:
        _chown_nofollow(path, state["uid"], state["gid"])
    except PermissionError:
        # 원래 owner와 이미 같으면 권한 없는 chown은 복구 실패가 아니다.
        st = os.lstat(path)
        if (st.st_uid, st.st_gid) != (state["uid"], state["gid"]):
            raise
    _restore_xattrs(path, state.get("xattrs", {}))
    inode_flags = state.get("inode_flags")
    if inode_flags is not None and kind != stat_module.S_IFLNK:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        try:
            _write_inode_flags(fd, inode_flags)
        finally:
            os.close(fd)
    _utime_nofollow(path, ns=(state["atime_ns"], state["mtime_ns"]))


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


def _read_only_reset(name: str, result: ToolResult) -> ResetResult:
    identity_after = identity_snapshot()
    checks = {"identity_unchanged": identity_after == result.identity_before}
    return ResetResult(
        resetter=f"{name}_resetter",
        status="NOT_REQUIRED" if all(checks.values()) else "FAILED",
        identity_after=identity_after,
        state_after=dict(result.state_before),
        checks=checks,
        output="읽기 전용 action; 남은 resource 없음",
    )


def _execute_fixture(path: str) -> int:
    pid = os.fork()
    if pid == 0:
        try:
            os.execv(path, [path])
        except OSError as exc:
            os._exit(exc.errno or 1)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status)


def _build_file_open_definition(action: str) -> ToolDefinition:
    name = f"{_FILE_OPEN_TOOL}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        path = _definition_path(decision, context)
        state["path"] = path
        identity_before = identity_snapshot()
        before = _full_path_state(path)
        state["before_path"] = before
        if action == "execute":
            state["backup"] = _capture_path_backup(path)
            before = state["backup"]["state"]
            exit_code = _execute_fixture(path)
            if exit_code in {errno_module.EACCES, errno_module.EPERM}:
                raise OSError(exit_code, os.strerror(exit_code))
            state["exit_code"] = exit_code
            output = f"execve fixture exit={exit_code}"
        else:
            fd = os.open(path, _OPEN_FLAGS[action] | getattr(os, "O_NOFOLLOW", 0))
            state["opened_fd"] = fd
            output = f"opened({action}) fd={fd}"
        reached = _full_path_state(path)
        return _identity_result(
            _FILE_OPEN_TOOL, action, context, identity_before,
            output=output, state_before=before, state_reached=reached,
            changed=False, data={"path": path, "exit_code": state.get("exit_code")},
        )

    def verifier(
        state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext,
    ) -> VerificationResult:
        path = _definition_path(decision, context)
        if action == "execute":
            observed_exit = _execute_fixture(path)
            observed_path = _full_path_state(path)
            checks = {
                "exec_repeated": observed_exit == state.get("exit_code"),
                "content_unchanged": observed_path.get("sha256") == result.state_before.get("sha256"),
                "mode_unchanged": observed_path.get("mode") == result.state_before.get("mode"),
                "owner_unchanged": (
                    observed_path.get("uid"), observed_path.get("gid")
                ) == (result.state_before.get("uid"), result.state_before.get("gid")),
            }
            observed = {"exit_code": observed_exit, "path_state": observed_path}
        else:
            verify_fd = os.open(path, _OPEN_FLAGS[action] | getattr(os, "O_NOFOLLOW", 0))
            try:
                observed_stat = os.fstat(verify_fd)
                checks = {
                    "open_repeated": observed_stat.st_ino == os.lstat(path).st_ino,
                    "handler_fd_open": os.fstat(state["opened_fd"]).st_ino == observed_stat.st_ino,
                }
                observed = {"fd": verify_fd, "inode": observed_stat.st_ino}
            finally:
                os.close(verify_fd)
        return VerificationResult(
            verifier=f"{name}_verifier",
            status="VERIFIED_NO_CHANGE" if all(checks.values()) else "REJECTED",
            checks=checks,
            observed=observed,
        )

    def resetter(
        state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext,
    ) -> ResetResult:
        fd = state.pop("opened_fd", None)
        if isinstance(fd, int):
            os.close(fd)
        path = _definition_path(decision, context)
        if action == "execute":
            _restore_path_backup(state["backup"])
        after = _full_path_state(path)
        if action == "execute":
            checks = {
                f"{key}_restored": after.get(key) == result.state_before.get(key)
                for key in ("mode", "uid", "gid", "atime_ns", "mtime_ns", "xattrs", "inode_flags", "sha256")
            }
        else:
            checks = {"target_unchanged": after == result.state_before}
        return ResetResult(
            resetter=f"{name}_resetter",
            status=("VERIFIED" if action == "execute" else "VERIFIED_NO_CHANGE")
            if all(checks.values()) else "FAILED",
            identity_after=identity_snapshot(), state_after=after, checks=checks,
            output="열린 FD 정리 및 파일 무변경 확인",
        )

    return ToolDefinition(
        name=name, tool=_FILE_OPEN_TOOL, action=action,
        handler=handler, verifier=verifier, resetter=resetter,
        spec=_definition_spec(
            _PATH, reversible=action == "execute",
            timeout_s=12.0 if action == "execute" else 5.0,
        ),
    )


def _build_file_create_definition(action: str) -> ToolDefinition:
    name = f"{_FILE_CREATE_TOOL}.{action}"
    expected_type = {
        "file": stat_module.S_IFREG,
        "directory": stat_module.S_IFDIR,
        "fifo": stat_module.S_IFIFO,
    }[action]

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        parent = _definition_path(decision, context)
        target = _fixture_child(parent, decision.arguments["name"])
        mode = decision.arguments.get("mode", 0o600)
        if not isinstance(mode, int) or isinstance(mode, bool) or not 0 <= mode <= 0o777:
            raise ToolInputError("mode는 0~0o777 정수여야 합니다.")
        if os.path.lexists(target):
            raise ToolPolicyBlocked("생성 fixture가 이미 존재합니다.")
        state["target"] = target
        identity_before = identity_snapshot()
        before = _full_path_state(target)
        if action == "file":
            fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
            os.close(fd)
        elif action == "directory":
            os.mkdir(target, mode)
        else:
            os.mkfifo(target, mode)
        _chmod_nofollow(target, mode)
        reached = _full_path_state(target)
        return _identity_result(
            _FILE_CREATE_TOOL, action, context, identity_before,
            output=f"created {action}", state_before=before, state_reached=reached,
            changed=True, data={"target": target, "requested_mode": mode},
        )

    def verifier(
        state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext,
    ) -> VerificationResult:
        observed = _full_path_state(state["target"])
        checks = {
            "created": observed.get("exists") is True,
            "type_matches": observed.get("type") == expected_type,
            "mode_matches": observed.get("mode") == result.data["requested_mode"],
        }
        return VerificationResult(
            verifier=f"{name}_verifier",
            status="VERIFIED" if all(checks.values()) else "REJECTED",
            checks=checks, observed=observed,
        )

    def resetter(
        state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext,
    ) -> ResetResult:
        target = state.get("target")
        if isinstance(target, str):
            _remove_path(target)
        after = _full_path_state(target) if isinstance(target, str) else {"exists": False}
        checks = {"created_target_removed": after.get("exists") is False}
        return ResetResult(
            resetter=f"{name}_resetter",
            status="VERIFIED" if all(checks.values()) else "FAILED",
            identity_after=identity_snapshot(), state_after=after, checks=checks,
            output="생성 fixture 제거 확인",
        )

    return ToolDefinition(
        name=name, tool=_FILE_CREATE_TOOL, action=action,
        handler=handler, verifier=verifier, resetter=resetter,
        spec=_definition_spec(
            _PATH,
            arg_schema={"name": str, "mode": int},
            required_args=frozenset({"name"}), reversible=True,
        ),
    )


def _build_file_content_definition(action: str) -> ToolDefinition:
    name = f"{_FILE_CONTENT_TOOL}.{action}"
    changing = action != "read"
    schema: dict[str, Any] = {}
    required = frozenset()
    if action in {"write", "append"}:
        schema = {"content": str}
        required = frozenset({"content"})
    elif action == "copy":
        schema = {"dest_ref": str}
        required = frozenset({"dest_ref"})

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        source = _definition_path(decision, context)
        target = source
        if action == "copy":
            target = context.resolve_path(str_arg(decision.arguments, "dest_ref"))
            same_target = os.path.abspath(source) == os.path.abspath(target)
            if os.path.exists(target):
                same_target = same_target or os.path.samefile(source, target)
            if same_target:
                raise ToolInputError("copy source와 destination은 달라야 합니다.")
        identity_before = identity_snapshot()
        before = _full_path_state(target)
        if action == "read":
            content, st = _read_regular(source, limit=_READ_OUTPUT_BYTES, complete=False)
            reached = _full_path_state(source)
            return _identity_result(
                _FILE_CONTENT_TOOL, action, context, identity_before,
                output=content.decode("utf-8", errors="replace"),
                state_before=before, state_reached=reached, changed=False,
                data={"path": source, "bytes_read": len(content), "file_size": st.st_size},
            )

        backup = _capture_path_backup(target, allow_missing=action == "copy")
        if backup["state"].get("exists") and backup["state"].get("type") != stat_module.S_IFREG:
            raise ToolPolicyBlocked("file.content 변경 대상은 일반 파일 fixture여야 합니다.")
        state["backup"] = backup
        state["target"] = target
        if action == "copy":
            payload, _ = _read_regular(source, limit=_MAX_RESTORE_BYTES, complete=True)
        elif action == "truncate":
            payload = b""
        else:
            payload = bounded_content(decision.arguments).encode()
        state["payload"] = payload
        if action == "truncate":
            os.truncate(target, 0)
        elif action == "copy":
            fd = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                _write_all(fd, payload)
            finally:
                os.close(fd)
        else:
            flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
            flags |= os.O_TRUNC if action == "write" else os.O_APPEND
            fd = os.open(target, flags)
            try:
                _write_all(fd, payload)
            finally:
                os.close(fd)
        reached = _full_path_state(target)
        return _identity_result(
            _FILE_CONTENT_TOOL, action, context, identity_before,
            output=f"{action} {len(payload)}B", state_before=before,
            state_reached=reached, changed=True,
            data={"source": source, "target": target, "payload_size": len(payload)},
        )

    def verifier(
        state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext,
    ) -> VerificationResult:
        target = result.data.get("target", result.data.get("path"))
        observed = _full_path_state(target)
        if action == "read":
            content, st = _read_regular(target, limit=_READ_OUTPUT_BYTES, complete=False)
            checks = {
                "content_requeried": len(content) == result.data["bytes_read"],
                "size_matches": st.st_size == result.data["file_size"],
                "content_hash_unchanged": observed.get("sha256") == result.state_before.get("sha256"),
            }
            status = "VERIFIED_NO_CHANGE"
        else:
            expected_size = result.data["payload_size"]
            if action == "append":
                expected_size += result.state_before["size"]
            checks = {
                "target_exists": observed.get("exists") is True,
                "size_reached": observed.get("size") == expected_size,
                "state_changed": observed != result.state_before,
            }
            status = "VERIFIED"
        return VerificationResult(
            verifier=f"{name}_verifier",
            status=status if all(checks.values()) else "REJECTED",
            checks=checks, observed=observed,
        )

    def resetter(
        state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext,
    ) -> ResetResult:
        if action == "read":
            observed = _full_path_state(result.data["path"])
            checks = {"content_hash_unchanged": observed.get("sha256") == result.state_before.get("sha256")}
            status = "NOT_REQUIRED" if all(checks.values()) else "FAILED"
        else:
            backup = state.get("backup")
            if not isinstance(backup, Mapping):
                return ResetResult(
                    resetter=f"{name}_resetter", status="FAILED",
                    identity_after=identity_snapshot(), checks={"backup_present": False},
                    output="복구 backup 없음",
                )
            _restore_path_backup(backup)
            target = state["target"]
            observed = _full_path_state(target)
            checks = {
                "content_restored": observed.get("sha256") == result.state_before.get("sha256"),
                "mode_restored": observed.get("mode") == result.state_before.get("mode"),
                "owner_restored": (
                    observed.get("uid"), observed.get("gid")
                ) == (result.state_before.get("uid"), result.state_before.get("gid")),
                "xattrs_restored": observed.get("xattrs") == result.state_before.get("xattrs"),
                "timestamps_restored": (
                    observed.get("atime_ns"), observed.get("mtime_ns")
                ) == (result.state_before.get("atime_ns"), result.state_before.get("mtime_ns")),
            }
            if result.state_before.get("exists") is False:
                checks = {"missing_target_restored": observed.get("exists") is False}
            status = "VERIFIED" if all(checks.values()) else "FAILED"
        return ResetResult(
            resetter=f"{name}_resetter", status=status,
            identity_after=identity_snapshot(), state_after=observed, checks=checks,
            output="파일 내용 및 전체 metadata 복구 확인" if changing else "읽기 무변경 확인",
        )

    return ToolDefinition(
        name=name, tool=_FILE_CONTENT_TOOL, action=action,
        handler=handler, verifier=verifier, resetter=resetter,
        spec=_definition_spec(
            _PATH, arg_schema=schema, required_args=required,
            reversible=changing,
        ),
    )


def _build_file_remove_definition(action: str) -> ToolDefinition:
    name = f"{_FILE_REMOVE_TOOL}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        path = _definition_path(decision, context)
        state["path"] = path
        identity_before = identity_snapshot()
        backup = _capture_path_backup(path)
        before = backup["state"]
        if action == "unlink" and before["type"] == stat_module.S_IFDIR:
            raise ToolPolicyBlocked("unlink은 디렉터리 fixture에 사용할 수 없습니다.")
        if action == "rmdir" and before["type"] != stat_module.S_IFDIR:
            raise ToolPolicyBlocked("rmdir은 빈 디렉터리 fixture에만 사용할 수 있습니다.")
        state["backup"] = backup
        _remove_path(path)
        reached = _full_path_state(path)
        return _identity_result(
            _FILE_REMOVE_TOOL, action, context, identity_before,
            output=f"{action} fixture", state_before=before,
            state_reached=reached, changed=True, data={"path": path},
        )

    def verifier(
        state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext,
    ) -> VerificationResult:
        observed = _full_path_state(result.data["path"])
        checks = {"target_removed": observed.get("exists") is False}
        return VerificationResult(
            verifier=f"{name}_verifier", status="VERIFIED" if all(checks.values()) else "REJECTED",
            checks=checks, observed=observed,
        )

    def resetter(
        state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext,
    ) -> ResetResult:
        backup = state.get("backup")
        if not isinstance(backup, Mapping):
            return ResetResult(
                resetter=f"{name}_resetter", status="FAILED",
                identity_after=identity_snapshot(), checks={"backup_present": False},
            )
        _restore_path_backup(backup)
        observed = _full_path_state(result.data["path"])
        checks = {
            "target_restored": observed.get("exists") is True,
            "type_restored": observed.get("type") == result.state_before.get("type"),
            "content_restored": observed.get("sha256") == result.state_before.get("sha256"),
            "metadata_restored": all(
                observed.get(key) == result.state_before.get(key)
                for key in ("mode", "uid", "gid", "atime_ns", "mtime_ns", "xattrs", "inode_flags")
            ),
        }
        return ResetResult(
            resetter=f"{name}_resetter", status="VERIFIED" if all(checks.values()) else "FAILED",
            identity_after=identity_snapshot(), state_after=observed, checks=checks,
            output="삭제 fixture 복구 및 재조회",
        )

    return ToolDefinition(
        name=name, tool=_FILE_REMOVE_TOOL, action=action,
        handler=handler, verifier=verifier, resetter=resetter,
        spec=_definition_spec(_PATH, reversible=True, destructive=True, timeout_s=5.0),
    )


def _build_file_move_definition(action: str) -> ToolDefinition:
    name = f"{_FILE_MOVE_TOOL}.{action}"
    changing = action != "follow"
    schema = {"dest_ref": str, "name": str} if changing else {}
    required = frozenset({"dest_ref", "name"}) if changing else frozenset()

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        source = _definition_path(decision, context)
        identity_before = identity_snapshot()
        source_before = _full_path_state(source)
        state["before_source"] = source_before
        if action == "follow":
            real = os.path.realpath(source)
            if not _realpath_is_registered(source, context):
                raise ToolPolicyBlocked("symlink realpath가 등록된 fixture 범위를 벗어났습니다.")
            fd = os.open(source, os.O_RDONLY)
            os.close(fd)
            return _identity_result(
                _FILE_MOVE_TOOL, action, context, identity_before,
                output=f"followed {real}", state_before=source_before,
                state_reached=_full_path_state(source), changed=False,
                data={"source": source, "realpath": real},
            )
        parent = context.resolve_path(str_arg(decision.arguments, "dest_ref"))
        destination = _fixture_child(parent, decision.arguments["name"])
        if os.path.lexists(destination):
            raise ToolPolicyBlocked("destination fixture가 이미 존재합니다.")
        state.update({"source": source, "destination": destination})
        if action == "rename":
            os.rename(source, destination)
        elif action == "hardlink":
            os.link(source, destination, follow_symlinks=False)
        else:
            os.symlink(source, destination)
        reached = {
            "source": _full_path_state(source),
            "destination": _full_path_state(destination),
        }
        return _identity_result(
            _FILE_MOVE_TOOL, action, context, identity_before,
            output=f"{action} fixture", state_before=source_before,
            state_reached=reached, changed=True,
            data={"source": source, "destination": destination},
        )

    def verifier(
        state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext,
    ) -> VerificationResult:
        if action == "follow":
            observed = _full_path_state(result.data["source"])
            checks = {
                "realpath_requeried": os.path.realpath(result.data["source"]) == result.data["realpath"],
                "target_unchanged": observed == result.state_before,
            }
            status = "VERIFIED_NO_CHANGE"
        else:
            source_state = _full_path_state(result.data["source"])
            destination_state = _full_path_state(result.data["destination"])
            if action == "rename":
                relation = source_state.get("exists") is False
            elif action == "hardlink":
                relation = (
                    destination_state.get("exists") is True
                    and destination_state.get("sha256") == result.state_before.get("sha256")
                    and destination_state.get("nlink", 0) >= 2
                )
            else:
                relation = (
                    destination_state.get("type") == stat_module.S_IFLNK
                    and destination_state.get("link_target") == result.data["source"]
                )
            observed = {"source": source_state, "destination": destination_state}
            checks = {"destination_created": destination_state.get("exists") is True, "relation_matches": relation}
            status = "VERIFIED"
        return VerificationResult(
            verifier=f"{name}_verifier", status=status if all(checks.values()) else "REJECTED",
            checks=checks, observed=observed,
        )

    def resetter(
        state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext,
    ) -> ResetResult:
        if action == "follow":
            observed = _full_path_state(result.data["source"])
            checks = {"target_unchanged": observed == result.state_before}
            status = "NOT_REQUIRED" if all(checks.values()) else "FAILED"
        else:
            source = state["source"]
            destination = state["destination"]
            if action == "rename":
                os.rename(destination, source)
            else:
                os.unlink(destination)
            observed = {
                "source": _full_path_state(source),
                "destination": _full_path_state(destination),
            }
            checks = {
                "source_restored": all(
                    observed["source"].get(key) == result.state_before.get(key)
                    for key in ("exists", "type", "mode", "uid", "gid", "size", "nlink", "mtime_ns", "xattrs", "sha256")
                ),
                "destination_removed": observed["destination"].get("exists") is False,
            }
            status = "VERIFIED" if all(checks.values()) else "FAILED"
        return ResetResult(
            resetter=f"{name}_resetter", status=status,
            identity_after=identity_snapshot(), state_after=observed, checks=checks,
            output="link/move 상태 복구 및 재조회",
        )

    return ToolDefinition(
        name=name, tool=_FILE_MOVE_TOOL, action=action,
        handler=handler, verifier=verifier, resetter=resetter,
        spec=_definition_spec(
            _PATH, arg_schema=schema, required_args=required, reversible=changing,
        ),
    )


def _build_file_metadata_definition(action: str) -> ToolDefinition:
    name = f"{_FILE_METADATA_TOOL}.{action}"
    schema = {
        "chmod": {"mode": int},
        "chown": {"uid": int, "gid": int},
        "chgrp": {"gid": int},
        "set_times": {"atime": int, "mtime": int},
    }[action]
    required = {
        "chmod": frozenset({"mode"}),
        "chown": frozenset(),
        "chgrp": frozenset({"gid"}),
        "set_times": frozenset(),
    }[action]

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        path = _definition_path(decision, context)
        state["path"] = path
        identity_before = identity_snapshot()
        backup = _capture_path_backup(path)
        state["backup"] = backup
        before = backup["state"]
        args = decision.arguments
        expected: dict[str, Any] = {}
        if action == "chmod":
            mode = args["mode"]
            if not isinstance(mode, int) or isinstance(mode, bool) or not 0 <= mode <= 0o7777:
                raise ToolInputError("mode는 0~0o7777 정수여야 합니다.")
            _chmod_nofollow(path, mode)
            expected = {"mode": mode}
        elif action in {"chown", "chgrp"}:
            if action == "chown" and "uid" not in args and "gid" not in args:
                raise ToolInputError("chown에는 uid 또는 gid 중 하나가 필요합니다.")
            uid = args.get("uid", -1) if action == "chown" else -1
            gid = args.get("gid", -1)
            if not isinstance(uid, int) or isinstance(uid, bool) or uid < -1:
                raise ToolInputError("uid는 -1 이상의 정수여야 합니다.")
            if not isinstance(gid, int) or isinstance(gid, bool) or gid < -1:
                raise ToolInputError("gid는 -1 이상의 정수여야 합니다.")
            _chown_nofollow(path, uid, gid)
            expected = {
                "uid": before["uid"] if uid == -1 else uid,
                "gid": before["gid"] if gid == -1 else gid,
            }
        else:
            atime = args.get("atime", int(time.time()))
            mtime = args.get("mtime", int(time.time()))
            if not all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in (atime, mtime)):
                raise ToolInputError("atime/mtime는 0 이상의 epoch 정수여야 합니다.")
            _utime_nofollow(
                path,
                ns=(atime * 1_000_000_000, mtime * 1_000_000_000),
            )
            expected = {"atime_ns": atime * 1_000_000_000, "mtime_ns": mtime * 1_000_000_000}
        state["expected"] = expected
        reached = _full_path_state(path)
        return _identity_result(
            _FILE_METADATA_TOOL, action, context, identity_before,
            output=f"{action} fixture", state_before=before,
            state_reached=reached, changed=True,
            data={"path": path, "expected": expected},
        )

    def verifier(
        state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext,
    ) -> VerificationResult:
        observed = _full_path_state(result.data["path"])
        checks = {
            f"{key}_reached": observed.get(key) == value
            for key, value in result.data["expected"].items()
        }
        return VerificationResult(
            verifier=f"{name}_verifier", status="VERIFIED" if all(checks.values()) else "REJECTED",
            checks=checks, observed=observed,
        )

    def resetter(
        state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext,
    ) -> ResetResult:
        _restore_path_backup(state["backup"])
        observed = _full_path_state(result.data["path"])
        keys = ("mode", "uid", "gid", "atime_ns", "mtime_ns", "xattrs", "inode_flags", "sha256")
        checks = {f"{key}_restored": observed.get(key) == result.state_before.get(key) for key in keys}
        return ResetResult(
            resetter=f"{name}_resetter", status="VERIFIED" if all(checks.values()) else "FAILED",
            identity_after=identity_snapshot(), state_after=observed, checks=checks,
            output="metadata 전체 복구 및 재조회",
        )

    return ToolDefinition(
        name=name, tool=_FILE_METADATA_TOOL, action=action,
        handler=handler, verifier=verifier, resetter=resetter,
        spec=_definition_spec(
            _PATH, arg_schema=schema, required_args=required, reversible=True,
        ),
    )


def _acl_text(path: str) -> str:
    getfacl = shutil.which("getfacl")
    if getfacl is None:
        raise OSError(errno_module.ENOENT, "getfacl 미설치")
    result = subprocess.run(
        [getfacl, "--absolute-names", "--numeric", path],
        capture_output=True, text=True, timeout=5,
    )
    if result.returncode != 0:
        raise OSError(errno_module.EPERM, result.stderr.strip() or "getfacl 실패")
    return result.stdout


def _run_setfacl(path: str, action: str, entry: str | None) -> None:
    setfacl = shutil.which("setfacl")
    if setfacl is None:
        raise OSError(errno_module.ENOENT, "setfacl 미설치")
    if action == "remove":
        argv = [setfacl, "-b", path]
    elif action == "set_default":
        argv = [setfacl, "-d", "-m", entry or "", path]
    else:
        argv = [setfacl, "-m", entry or "", path]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=5)
    if result.returncode != 0:
        raise OSError(errno_module.EPERM, result.stderr.strip() or "setfacl 실패")


def _build_file_acl_definition(action: str) -> ToolDefinition:
    name = f"{_FILE_ACL_TOOL}.{action}"
    changing = action != "get"
    schema = {"entry": str} if action in {"set_access", "set_default"} else {}
    required = frozenset({"entry"}) if schema else frozenset()

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        path = _definition_path(decision, context)
        if os.path.islink(path):
            raise ToolPolicyBlocked("ACL action은 symlink가 아닌 fixture만 허용합니다.")
        identity_before = identity_snapshot()
        before_state = _full_path_state(path)
        before_acl = _acl_text(path)
        if changing:
            state["backup"] = _capture_path_backup(path)
            entry = _validate_acl_entry(decision.arguments["entry"]) if "entry" in schema else None
            _run_setfacl(path, action, entry)
        reached_acl = _acl_text(path)
        reached = _full_path_state(path)
        reached["acl_text"] = reached_acl
        return _identity_result(
            _FILE_ACL_TOOL, action, context, identity_before,
            output=reached_acl[:4096], state_before={**before_state, "acl_text": before_acl},
            state_reached=reached, changed=changing,
            data={"path": path, "entry": decision.arguments.get("entry")},
        )

    def verifier(
        state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext,
    ) -> VerificationResult:
        observed = _full_path_state(result.data["path"])
        observed["acl_text"] = _acl_text(result.data["path"])
        if action == "get":
            checks = {"acl_requeried": observed["acl_text"] == result.state_reached["acl_text"]}
            status = "VERIFIED_NO_CHANGE"
        elif action == "remove":
            checks = {
                "access_acl_removed": "system.posix_acl_access" not in observed.get("xattrs", {}),
                "acl_changed_or_absent": (
                    observed["acl_text"] != result.state_before["acl_text"]
                    or "system.posix_acl_access" not in result.state_before.get("xattrs", {})
                ),
            }
            status = "VERIFIED"
        else:
            entry = result.data["entry"]
            checks = {
                "acl_changed": observed["acl_text"] != result.state_before["acl_text"],
                "entry_observable": all(part in observed["acl_text"] for part in entry.split(":" ) if part),
            }
            status = "VERIFIED"
        return VerificationResult(
            verifier=f"{name}_verifier", status=status if all(checks.values()) else "REJECTED",
            checks=checks, observed=observed,
        )

    def resetter(
        state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext,
    ) -> ResetResult:
        if changing:
            _restore_path_backup(state["backup"])
        observed = _full_path_state(result.data["path"])
        observed["acl_text"] = _acl_text(result.data["path"])
        checks = {"acl_restored": observed["acl_text"] == result.state_before["acl_text"]}
        status = "VERIFIED" if changing and all(checks.values()) else (
            "NOT_REQUIRED" if all(checks.values()) else "FAILED"
        )
        return ResetResult(
            resetter=f"{name}_resetter", status=status,
            identity_after=identity_snapshot(), state_after=observed, checks=checks,
            output="ACL 복구 및 getfacl 재조회",
        )

    return ToolDefinition(
        name=name, tool=_FILE_ACL_TOOL, action=action,
        handler=handler, verifier=verifier, resetter=resetter,
        spec=_definition_spec(
            _PATH, arg_schema=schema, required_args=required, reversible=changing,
        ),
    )


def _build_file_xattr_definition(action: str) -> ToolDefinition:
    name = f"{_FILE_XATTR_TOOL}.{action}"
    changing = action != "get"
    schema = {"name": str}
    required = {"name"}
    if action == "set":
        schema["value"] = str
        required.add("value")

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        path = _definition_path(decision, context)
        attr_name = _validate_xattr_name(decision.arguments["name"])
        if changing and attr_name not in {"user.osagent", "user.osagent_probe"}:
            raise ToolPolicyBlocked(
                "xattr 변경은 등록된 user.osagent fixture 이름만 허용됩니다."
            )
        identity_before = identity_snapshot()
        before = _full_path_state(path)
        state["before_path"] = before
        if changing:
            state["backup"] = _capture_path_backup(path)
        if action == "get":
            value = os.getxattr(path, attr_name, follow_symlinks=False)
        elif action == "set":
            value = bounded_content(decision.arguments, "value").encode()
            os.setxattr(path, attr_name, value, follow_symlinks=False)
        else:
            value = os.getxattr(path, attr_name, follow_symlinks=False)
            os.removexattr(path, attr_name, follow_symlinks=False)
        reached = _full_path_state(path)
        return _identity_result(
            _FILE_XATTR_TOOL, action, context, identity_before,
            output=f"xattr {action} {attr_name}", state_before=before,
            state_reached=reached, changed=changing,
            data={"path": path, "name": attr_name, "value_hex": value.hex()},
        )

    def verifier(
        state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext,
    ) -> VerificationResult:
        path, attr_name = result.data["path"], result.data["name"]
        observed_state = _full_path_state(path)
        present = attr_name in observed_state.get("xattrs", {})
        if action == "remove":
            checks = {"xattr_absent": not present}
            observed_value = None
        else:
            observed_value = os.getxattr(path, attr_name, follow_symlinks=False).hex()
            checks = {
                "xattr_present": present,
                "value_matches": observed_value == result.data["value_hex"],
            }
        return VerificationResult(
            verifier=f"{name}_verifier",
            status=("VERIFIED" if changing else "VERIFIED_NO_CHANGE") if all(checks.values()) else "REJECTED",
            checks=checks,
            observed={"path_state": observed_state, "value_hex": observed_value},
        )

    def resetter(
        state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext,
    ) -> ResetResult:
        if changing:
            _restore_path_backup(state["backup"])
        observed = _full_path_state(result.data["path"])
        checks = {"xattrs_restored": observed.get("xattrs") == result.state_before.get("xattrs")}
        status = "VERIFIED" if changing and all(checks.values()) else (
            "NOT_REQUIRED" if all(checks.values()) else "FAILED"
        )
        return ResetResult(
            resetter=f"{name}_resetter", status=status,
            identity_after=identity_snapshot(), state_after=observed, checks=checks,
            output="xattr 전체 복구 및 재조회",
        )

    return ToolDefinition(
        name=name, tool=_FILE_XATTR_TOOL, action=action,
        handler=handler, verifier=verifier, resetter=resetter,
        spec=_definition_spec(
            _PATH, arg_schema=schema, required_args=frozenset(required), reversible=changing,
        ),
    )


def _build_file_inode_definition(action: str) -> ToolDefinition:
    name = f"{_FILE_INODE_TOOL}.{action}"
    changing = action != "get"
    schema = {"flag": str} if changing else {}
    required = frozenset({"flag"}) if changing else frozenset()

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        path = _definition_path(decision, context)
        state["path"] = path
        identity_before = identity_snapshot()
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        try:
            original = _read_inode_flags(fd)
            state["original_flags"] = original
            requested = None
            if changing:
                bit = _INODE_FLAG_NAMES[enum_arg(decision.arguments, "flag", frozenset(_INODE_FLAG_NAMES))]
                requested = original | bit if action == "set" else original & ~bit
                _write_inode_flags(fd, requested)
            reached_flags = _read_inode_flags(fd)
        finally:
            os.close(fd)
        before = _full_path_state(path)
        before["inode_flags"] = original
        reached = _full_path_state(path)
        reached["inode_flags"] = reached_flags
        return _identity_result(
            _FILE_INODE_TOOL, action, context, identity_before,
            output=f"inode flags={reached_flags:#x}", state_before=before,
            state_reached=reached, changed=changing,
            data={"path": path, "expected_flags": requested if changing else original},
        )

    def verifier(
        state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext,
    ) -> VerificationResult:
        observed = _inode_flags_path(result.data["path"])
        checks = {"inode_flags_requeried": observed == result.data["expected_flags"]}
        return VerificationResult(
            verifier=f"{name}_verifier",
            status=("VERIFIED" if changing else "VERIFIED_NO_CHANGE") if all(checks.values()) else "REJECTED",
            checks=checks, observed={"inode_flags": observed},
        )

    def resetter(
        state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext,
    ) -> ResetResult:
        if changing:
            fd = os.open(result.data["path"], os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
            try:
                _write_inode_flags(fd, state["original_flags"])
            finally:
                os.close(fd)
        observed = _inode_flags_path(result.data["path"])
        checks = {"inode_flags_restored": observed == state["original_flags"]}
        status = "VERIFIED" if changing and all(checks.values()) else (
            "NOT_REQUIRED" if all(checks.values()) else "FAILED"
        )
        return ResetResult(
            resetter=f"{name}_resetter", status=status,
            identity_after=identity_snapshot(), state_after={"inode_flags": observed}, checks=checks,
            output="inode flags 원본 복구 및 재조회",
        )

    return ToolDefinition(
        name=name, tool=_FILE_INODE_TOOL, action=action,
        handler=handler, verifier=verifier, resetter=resetter,
        spec=_definition_spec(
            _PATH, arg_schema=schema, required_args=required, reversible=changing,
        ),
    )


def _build_file_lock_definition(action: str) -> ToolDefinition:
    name = f"{_FILE_LOCK_TOOL}.{action}"
    lock_action = action in {"lock", "unlock"}

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        path = _definition_path(decision, context)
        state["path"] = path
        identity_before = identity_snapshot()
        before = _full_path_state(path)
        state["before_path"] = before
        fd = os.open(path, os.O_RDWR if lock_action else os.O_RDONLY)
        state["fd"] = fd
        if action == "lock":
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            reached_value: Any = "exclusive"
        elif action == "unlock":
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
            reached_value = "unlocked"
        elif action == "lease_set":
            fcntl.fcntl(fd, F_SETLEASE, F_RDLCK)
            reached_value = fcntl.fcntl(fd, F_GETLEASE)
        else:
            fcntl.fcntl(fd, F_SETLEASE, F_RDLCK)
            fcntl.fcntl(fd, F_SETLEASE, F_UNLCK)
            reached_value = fcntl.fcntl(fd, F_GETLEASE)
        state["reached_value"] = reached_value
        reached = _full_path_state(path)
        reached["lock_or_lease"] = reached_value
        return _identity_result(
            _FILE_LOCK_TOOL, action, context, identity_before,
            output=f"{action} reached", state_before=before,
            state_reached=reached, changed=action in {"lock", "lease_set"},
            data={"path": path, "reached_value": reached_value},
        )

    def verifier(
        state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext,
    ) -> VerificationResult:
        fd = state["fd"]
        if action in {"lease_set", "lease_release"}:
            observed_value = fcntl.fcntl(fd, F_GETLEASE)
            expected = F_RDLCK if action == "lease_set" else F_UNLCK
            checks = {"lease_requeried": observed_value == expected}
        else:
            test_fd = os.open(result.data["path"], os.O_RDWR)
            try:
                blocked = False
                try:
                    fcntl.flock(test_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    blocked = True
                finally:
                    if not blocked:
                        fcntl.flock(test_fd, fcntl.LOCK_UN)
                expected_blocked = action == "lock"
                observed_value = blocked
                checks = {"flock_state_requeried": blocked == expected_blocked}
            finally:
                os.close(test_fd)
        return VerificationResult(
            verifier=f"{name}_verifier", status="VERIFIED" if all(checks.values()) else "REJECTED",
            checks=checks, observed={"lock_or_lease": observed_value},
        )

    def resetter(
        state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext,
    ) -> ResetResult:
        fd = state.pop("fd", None)
        if isinstance(fd, int):
            if lock_action:
                fcntl.flock(fd, fcntl.LOCK_UN)
            else:
                fcntl.fcntl(fd, F_SETLEASE, F_UNLCK)
            os.close(fd)
        observed = _full_path_state(result.data["path"])
        checks = {"target_unchanged": observed == result.state_before, "held_fd_closed": "fd" not in state}
        status = "VERIFIED" if action in {"lock", "lease_set"} and all(checks.values()) else (
            "NOT_REQUIRED" if all(checks.values()) else "FAILED"
        )
        return ResetResult(
            resetter=f"{name}_resetter", status=status,
            identity_after=identity_snapshot(), state_after=observed, checks=checks,
            output="lock/lease 해제 및 FD 종료",
        )

    return ToolDefinition(
        name=name, tool=_FILE_LOCK_TOOL, action=action,
        handler=handler, verifier=verifier, resetter=resetter,
        spec=_definition_spec(_PATH, reversible=action in {"lock", "lease_set"}),
    )


def _obtain_file_handle(path: str) -> tuple[_FileHandle, int]:
    handle = _FileHandle()
    handle.handle_bytes = MAX_HANDLE_SZ
    mount_id = ctypes.c_int()
    raw_syscall(
        "name_to_handle_at", AT_FDCWD, path.encode(),
        ctypes.byref(handle), ctypes.byref(mount_id), 0,
    )
    return handle, mount_id.value


def _handle_bytes(handle: _FileHandle) -> str:
    return bytes(handle.f_handle[: handle.handle_bytes]).hex()


def _build_file_handle_definition(action: str) -> ToolDefinition:
    name = f"{_FILE_HANDLE_TOOL}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        path = _definition_path(decision, context)
        identity_before = identity_snapshot()
        before = _full_path_state(path)
        handle, mount_id = _obtain_file_handle(path)
        opened_stat: dict[str, Any] | None = None
        if action == "open_by_handle":
            mount_fd = os.open(os.path.dirname(path) or ".", os.O_RDONLY | os.O_DIRECTORY)
            try:
                opened_fd = raw_syscall("open_by_handle_at", mount_fd, ctypes.byref(handle), os.O_RDONLY)
                try:
                    st = os.fstat(opened_fd)
                    opened_stat = {"dev": st.st_dev, "ino": st.st_ino}
                finally:
                    os.close(opened_fd)
            finally:
                os.close(mount_fd)
        handle_hex = _handle_bytes(handle)
        return _identity_result(
            _FILE_HANDLE_TOOL, action, context, identity_before,
            output=f"handle mount={mount_id}", state_before=before,
            state_reached=_full_path_state(path), changed=False,
            data={"path": path, "mount_id": mount_id, "handle_hex": handle_hex, "opened_stat": opened_stat},
        )

    def verifier(
        state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext,
    ) -> VerificationResult:
        handle, mount_id = _obtain_file_handle(result.data["path"])
        observed_handle = _handle_bytes(handle)
        checks = {
            "handle_requeried": observed_handle == result.data["handle_hex"],
            "mount_id_matches": mount_id == result.data["mount_id"],
        }
        observed: dict[str, Any] = {"handle_hex": observed_handle, "mount_id": mount_id}
        if action == "open_by_handle":
            mount_fd = os.open(os.path.dirname(result.data["path"]) or ".", os.O_RDONLY | os.O_DIRECTORY)
            try:
                opened_fd = raw_syscall("open_by_handle_at", mount_fd, ctypes.byref(handle), os.O_RDONLY)
                try:
                    st = os.fstat(opened_fd)
                    observed["opened_stat"] = {"dev": st.st_dev, "ino": st.st_ino}
                finally:
                    os.close(opened_fd)
            finally:
                os.close(mount_fd)
            checks["open_repeated"] = observed["opened_stat"] == result.data["opened_stat"]
        return VerificationResult(
            verifier=f"{name}_verifier", status="VERIFIED_NO_CHANGE" if all(checks.values()) else "REJECTED",
            checks=checks, observed=observed,
        )

    def resetter(
        state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext,
    ) -> ResetResult:
        observed = _full_path_state(result.data["path"])
        checks = {"target_unchanged": observed == result.state_before}
        return ResetResult(
            resetter=f"{name}_resetter", status="NOT_REQUIRED" if all(checks.values()) else "FAILED",
            identity_after=identity_snapshot(), state_after=observed, checks=checks,
            output="handle FD 정리 및 대상 무변경 확인",
        )

    return ToolDefinition(
        name=name, tool=_FILE_HANDLE_TOOL, action=action,
        handler=handler, verifier=verifier, resetter=resetter,
        spec=_definition_spec(_PATH),
    )


def _fd_observed_state(fd: int) -> dict[str, Any]:
    try:
        st = os.fstat(fd)
    except OSError as exc:
        if exc.errno == errno_module.EBADF:
            return {"fd": fd, "open": False}
        raise
    try:
        offset: int | None = os.lseek(fd, 0, os.SEEK_CUR)
    except OSError:
        offset = None
    return {
        "fd": fd,
        "open": True,
        "dev": st.st_dev,
        "ino": st.st_ino,
        "mode": stat_module.S_IMODE(st.st_mode),
        "type": stat_module.S_IFMT(st.st_mode),
        "uid": st.st_uid,
        "gid": st.st_gid,
        "size": st.st_size,
        "atime_ns": st.st_atime_ns,
        "mtime_ns": st.st_mtime_ns,
        "offset": offset,
        "fd_flags": fcntl.fcntl(fd, fcntl.F_GETFD),
        "status_flags": fcntl.fcntl(fd, fcntl.F_GETFL),
    }


def _pread_fd(fd: int, count: int, offset: int) -> bytes:
    pread = getattr(os, "pread", None)
    if callable(pread):
        return pread(fd, count, offset)
    current = os.lseek(fd, 0, os.SEEK_CUR)
    try:
        os.lseek(fd, offset, os.SEEK_SET)
        return os.read(fd, count)
    finally:
        os.lseek(fd, current, os.SEEK_SET)


def _pwrite_fd(fd: int, data: bytes, offset: int) -> int:
    pwrite = getattr(os, "pwrite", None)
    if callable(pwrite):
        return pwrite(fd, data, offset)
    current = os.lseek(fd, 0, os.SEEK_CUR)
    try:
        os.lseek(fd, offset, os.SEEK_SET)
        return os.write(fd, data)
    finally:
        os.lseek(fd, current, os.SEEK_SET)


def _capture_fd_backup(fd: int) -> dict[str, Any]:
    observed = _fd_observed_state(fd)
    if observed["type"] != stat_module.S_IFREG:
        raise ToolPolicyBlocked("write/truncate/close는 등록된 일반 파일 FD fixture만 허용합니다.")
    if observed["size"] > _MAX_RESTORE_BYTES:
        raise ToolPolicyBlocked(f"FD rollback 대상은 {_MAX_RESTORE_BYTES}바이트 이하여야 합니다.")
    content = _pread_fd(fd, observed["size"], 0)
    st = os.fstat(fd)
    observed["atime_ns"] = st.st_atime_ns
    observed["mtime_ns"] = st.st_mtime_ns
    return {
        "observed": observed,
        "content": content,
        "atime_ns": st.st_atime_ns,
        "mtime_ns": st.st_mtime_ns,
    }


def _restore_fd_backup(fd: int, backup: Mapping[str, Any]) -> None:
    observed = backup["observed"]
    os.ftruncate(fd, 0)
    content = backup["content"]
    written = 0
    while written < len(content):
        count = _pwrite_fd(fd, content[written:], written)
        if count <= 0:
            raise OSError(errno_module.EIO, "FD 내용 복구 실패")
        written += count
    os.fchmod(fd, observed["mode"])
    try:
        os.fchown(fd, observed["uid"], observed["gid"])
    except PermissionError:
        st = os.fstat(fd)
        if (st.st_uid, st.st_gid) != (observed["uid"], observed["gid"]):
            raise
    os.utime(fd, ns=(backup["atime_ns"], backup["mtime_ns"]))
    if observed["offset"] is not None:
        os.lseek(fd, observed["offset"], os.SEEK_SET)
    fcntl.fcntl(fd, fcntl.F_SETFD, observed["fd_flags"])


def _build_fd_operate_definition(action: str) -> ToolDefinition:
    name = f"{_FD_OPERATE_TOOL}.{action}"
    schema = {
        "read": {"count": int},
        "write": {"content": str},
        "seek": {"offset": int},
        "truncate": {"length": int},
        "dup": {},
        "close": {},
    }[action]
    required = frozenset({"content"}) if action == "write" else frozenset()
    changing = action in {"read", "write", "seek", "truncate", "dup", "close"}
    destructive = action == "truncate"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        fd = _definition_fd(decision, context)
        identity_before = identity_snapshot()
        before = _fd_observed_state(fd)
        state["fd"] = fd
        state["before_fd"] = dict(before)
        if action in {"write", "truncate"}:
            state["backup"] = _capture_fd_backup(fd)
            before = dict(state["backup"]["observed"])
        if action == "read":
            count = decision.arguments.get("count", 256)
            if not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= 4096:
                raise ToolInputError("count는 0~4096 정수여야 합니다.")
            data = os.read(fd, count)
            output = f"read {len(data)}B"
            state["read_count"] = len(data)
        elif action == "write":
            payload = bounded_content(decision.arguments).encode()
            state["payload"] = payload
            state["write_start"] = before["offset"]
            output = f"wrote {os.write(fd, payload)}B"
        elif action == "seek":
            offset = decision.arguments.get("offset", 0)
            if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
                raise ToolInputError("offset은 0 이상의 정수여야 합니다.")
            os.lseek(fd, offset, os.SEEK_SET)
            state["expected_offset"] = offset
            output = f"seek {offset}"
        elif action == "truncate":
            length = decision.arguments.get("length", 0)
            if not isinstance(length, int) or isinstance(length, bool) or not 0 <= length <= _MAX_RESTORE_BYTES:
                raise ToolInputError("length는 rollback 한도 내 0 이상의 정수여야 합니다.")
            os.ftruncate(fd, length)
            state["expected_size"] = length
            output = f"truncate {length}"
        elif action == "dup":
            duplicated = os.dup(fd)
            state["duplicated_fd"] = duplicated
            output = f"dup {duplicated}"
        else:
            ready_read, ready_write = os.pipe()
            control_read, control_write = os.pipe()
            pid = os.fork()
            if pid == 0:
                try:
                    os.close(ready_read)
                    os.close(control_write)
                    os.close(fd)
                    closed = False
                    try:
                        os.fstat(fd)
                    except OSError as exc:
                        closed = exc.errno == errno_module.EBADF
                    os.write(ready_write, b"1" if closed else b"0")
                    os.close(ready_write)
                    os.read(control_read, 1)
                    os.close(control_read)
                    os._exit(0 if closed else 1)
                except BaseException:
                    os._exit(1)
            os.close(ready_write)
            os.close(control_read)
            ready = os.read(ready_read, 1)
            os.close(ready_read)
            if ready != b"1":
                os.close(control_write)
                os.waitpid(pid, 0)
                raise OSError(errno_module.EIO, "자식 fixture에서 close(2) 확인 실패")
            state.update({"child_pid": pid, "control_write": control_write})
            output = f"child fixture close pid={pid}"
        reached = _fd_observed_state(fd)
        if action == "dup":
            reached["duplicated"] = _fd_observed_state(state["duplicated_fd"])
        elif action == "close":
            reached["child_pid"] = state["child_pid"]
            reached["child_fd_open"] = False
        return _identity_result(
            _FD_OPERATE_TOOL, action, context, identity_before,
            output=output, state_before=before, state_reached=reached,
            changed=changing, data={"fd": fd},
        )

    def verifier(
        state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext,
    ) -> VerificationResult:
        fd = state["fd"]
        observed = _fd_observed_state(fd)
        if action == "read":
            expected = result.state_before["offset"] + state["read_count"] if result.state_before["offset"] is not None else None
            checks = {"offset_requeried": observed["offset"] == expected}
        elif action == "write":
            payload = state["payload"]
            actual = _pread_fd(fd, len(payload), state["write_start"])
            checks = {"written_bytes_requeried": actual == payload}
        elif action == "seek":
            checks = {"offset_requeried": observed["offset"] == state["expected_offset"]}
        elif action == "truncate":
            checks = {"size_requeried": observed["size"] == state["expected_size"]}
        elif action == "dup":
            duplicate = _fd_observed_state(state["duplicated_fd"])
            checks = {
                "duplicate_open": duplicate["open"] is True,
                "same_object": (duplicate["dev"], duplicate["ino"]) == (result.state_before["dev"], result.state_before["ino"]),
            }
            observed = {"source": observed, "duplicate": duplicate}
        else:
            child_pid = state["child_pid"]
            proc_fd = f"/proc/{child_pid}/fd/{fd}"
            child_alive = True
            try:
                os.kill(child_pid, 0)
            except OSError:
                child_alive = False
            observed = {
                "child_pid": child_pid,
                "child_alive": child_alive,
                "child_fd_open": os.path.exists(proc_fd),
                "parent_fd": observed,
            }
            checks = {
                "child_alive_for_verification": child_alive,
                "child_fd_closed": observed["child_fd_open"] is False,
                "parent_fd_unchanged": observed["parent_fd"] == result.state_before,
            }
        return VerificationResult(
            verifier=f"{name}_verifier", status="VERIFIED" if all(checks.values()) else "REJECTED",
            checks=checks, observed=observed,
        )

    def resetter(
        state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext,
    ) -> ResetResult:
        fd = state["fd"]
        if action == "dup":
            duplicate = state.pop("duplicated_fd")
            os.close(duplicate)
        elif action == "close":
            control_write = state.pop("control_write")
            child_pid = state.pop("child_pid")
            os.write(control_write, b"x")
            os.close(control_write)
            waited_pid, wait_status = os.waitpid(child_pid, 0)
            state["child_exit"] = os.waitstatus_to_exitcode(wait_status)
            state["waited_pid"] = waited_pid
        elif action in {"write", "truncate"}:
            _restore_fd_backup(fd, state["backup"])
        elif result.state_before["offset"] is not None:
            os.lseek(fd, result.state_before["offset"], os.SEEK_SET)
        observed = _fd_observed_state(fd)
        checks = {
            "fd_open": observed["open"] is True,
            "object_restored": (observed.get("dev"), observed.get("ino")) == (
                result.state_before.get("dev"), result.state_before.get("ino")
            ),
            "offset_restored": observed.get("offset") == result.state_before.get("offset"),
        }
        if action in {"write", "truncate"}:
            backup = state["backup"]
            content_restored = _pread_fd(fd, len(backup["content"]), 0) == backup["content"]
            os.utime(fd, ns=(backup["atime_ns"], backup["mtime_ns"]))
            observed = _fd_observed_state(fd)
            checks["content_restored"] = content_restored
            checks["size_restored"] = observed["size"] == result.state_before["size"]
            checks["mode_restored"] = observed["mode"] == result.state_before["mode"]
            checks["owner_restored"] = (observed["uid"], observed["gid"]) == (
                result.state_before["uid"], result.state_before["gid"]
            )
            checks["timestamps_restored"] = (
                observed["atime_ns"], observed["mtime_ns"]
            ) == (result.state_before["atime_ns"], result.state_before["mtime_ns"])
        if action == "dup":
            checks["duplicate_closed"] = _fd_observed_state(duplicate)["open"] is False
        if action == "close":
            checks["child_reaped"] = state["waited_pid"] > 0
            checks["child_exit_ok"] = state["child_exit"] == 0
        return ResetResult(
            resetter=f"{name}_resetter", status="VERIFIED" if all(checks.values()) else "FAILED",
            identity_after=identity_snapshot(), state_after=observed, checks=checks,
            output="FD 상태 복구 및 재조회",
        )

    return ToolDefinition(
        name=name, tool=_FD_OPERATE_TOOL, action=action,
        handler=handler, verifier=verifier, resetter=resetter,
        spec=_definition_spec(
            _FD, arg_schema=schema, required_args=required,
            reversible=True, destructive=destructive,
        ),
    )


def _receive_scm_fd(sock: socket.socket) -> int:
    _message, ancillary, _flags, _address = sock.recvmsg(
        1, socket.CMSG_SPACE(struct.calcsize("i")),
    )
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            received = array.array("i")
            received.frombytes(data[: len(data) - (len(data) % received.itemsize)])
            if received:
                for extra in received[1:]:
                    os.close(extra)
                return received[0]
    raise OSError(errno_module.EIO, "SCM_RIGHTS FD를 받지 못했습니다.")


def _build_fd_transfer_definition(action: str) -> ToolDefinition:
    name = f"{_FD_TRANSFER_TOOL}.{action}"
    if action == "pidfd_getfd":
        spec = _definition_spec(
            "pid",
            arg_schema={"target_fd_ref": str},
            required_args=frozenset({"target_fd_ref"}),
            reversible=True,
        )
    else:
        spec = _definition_spec(_FD, reversible=True)

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot()
        if action == "pidfd_getfd":
            if "pid" in decision.arguments or "target_fd" in decision.arguments:
                raise ToolInputError("raw pid/fd는 금지되며 등록된 resource_ref만 허용됩니다.")
            if decision.resource_ref is None:
                raise ToolInputError("PID resource_ref가 필요합니다.")
            pid_value = context.resolve_resource(decision.resource_ref)
            target_ref = decision.arguments["target_fd_ref"]
            if not isinstance(target_ref, str):
                raise ToolInputError("target_fd_ref는 등록 reference 문자열이어야 합니다.")
            target_fd_value = context.resolve_resource(target_ref)
            if not isinstance(pid_value, int) or not isinstance(target_fd_value, int):
                raise ToolPolicyBlocked("PID/FD resource_ref 매핑이 올바르지 않습니다.")
            pidfd = raw_syscall("pidfd_open", pid_value, 0)
            try:
                stolen_fd = raw_syscall("pidfd_getfd", pidfd, target_fd_value, 0)
            except Exception:
                os.close(pidfd)
                raise
            state.update({"pid": pid_value, "target_fd": target_fd_value, "pidfd": pidfd, "received_fd": stolen_fd})
            reached = {"pidfd": _fd_observed_state(pidfd), "received_fd": _fd_observed_state(stolen_fd)}
            before = {"pid": pid_value, "target_fd_ref": target_ref, "temporary_fds": 0}
            output = "pidfd_getfd reached"
        else:
            fd = _definition_fd(decision, context)
            before = _fd_observed_state(fd)
            state["source_fd"] = fd
            if action == "inherit":
                original_flags = fcntl.fcntl(fd, fcntl.F_GETFD)
                state["original_flags"] = original_flags
                fcntl.fcntl(fd, fcntl.F_SETFD, original_flags & ~fcntl.FD_CLOEXEC)
                pid = os.fork()
                if pid == 0:
                    try:
                        os.fstat(fd)
                        os._exit(0)
                    except OSError as exc:
                        os._exit(exc.errno or 1)
                _, wait_status = os.waitpid(pid, 0)
                child_exit = os.waitstatus_to_exitcode(wait_status)
                state["child_exit"] = child_exit
                reached = _fd_observed_state(fd)
                reached["child_exit"] = child_exit
                output = f"inherit child exit={child_exit}"
            else:
                left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
                state.update({"left": left, "right": right})
                left.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))])
                if action == "scm_receive":
                    received_fd = _receive_scm_fd(right)
                    state["received_fd"] = received_fd
                    reached = {"source": before, "received": _fd_observed_state(received_fd)}
                else:
                    reached = {"source": before, "message_pending": True}
                output = f"{action} reached"
        return _identity_result(
            _FD_TRANSFER_TOOL, action, context, identity_before,
            output=output, state_before=before, state_reached=reached,
            changed=True, data={"action": action},
        )

    def verifier(
        state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext,
    ) -> VerificationResult:
        if action == "inherit":
            source_fd = state["source_fd"]
            flags = fcntl.fcntl(source_fd, fcntl.F_GETFD)
            pid = os.fork()
            if pid == 0:
                try:
                    os.fstat(source_fd)
                    os._exit(0)
                except OSError as exc:
                    os._exit(exc.errno or 1)
            _, wait_status = os.waitpid(pid, 0)
            child_exit = os.waitstatus_to_exitcode(wait_status)
            checks = {
                "cloexec_cleared": not bool(flags & fcntl.FD_CLOEXEC),
                "child_reverified_fd": child_exit == 0,
            }
            observed = {"fd_flags": flags, "child_exit": child_exit}
        elif action in {"scm_send", "scm_receive"}:
            if action == "scm_send":
                received_fd = _receive_scm_fd(state["right"])
                state["received_fd"] = received_fd
            else:
                received_fd = state["received_fd"]
            source = _fd_observed_state(state["source_fd"])
            received = _fd_observed_state(received_fd)
            checks = {
                "received_fd_open": received["open"] is True,
                "same_object": (source["dev"], source["ino"]) == (received["dev"], received["ino"]),
            }
            observed = {"source": source, "received": received}
        else:
            verify_fd = raw_syscall("pidfd_getfd", state["pidfd"], state["target_fd"], 0)
            state["verify_fd"] = verify_fd
            first = _fd_observed_state(state["received_fd"])
            second = _fd_observed_state(verify_fd)
            checks = {
                "pidfd_getfd_repeated": second["open"] is True,
                "same_target_object": (first["dev"], first["ino"]) == (second["dev"], second["ino"]),
            }
            observed = {"first": first, "second": second}
        return VerificationResult(
            verifier=f"{name}_verifier", status="VERIFIED" if all(checks.values()) else "REJECTED",
            checks=checks, observed=observed,
        )

    def resetter(
        state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext,
    ) -> ResetResult:
        closed: list[int] = []
        if action == "inherit":
            fd = state["source_fd"]
            fcntl.fcntl(fd, fcntl.F_SETFD, state["original_flags"])
            observed = _fd_observed_state(fd)
            checks = {"fd_flags_restored": observed["fd_flags"] == state["original_flags"]}
        else:
            for key in ("received_fd", "verify_fd", "pidfd"):
                value = state.pop(key, None)
                if isinstance(value, int):
                    os.close(value)
                    closed.append(value)
            for key in ("left", "right"):
                value = state.pop(key, None)
                if isinstance(value, socket.socket):
                    value.close()
            observed = {"closed_fds": closed, "socket_handles_closed": "left" not in state and "right" not in state}
            checks = {
                "temporary_fds_closed": all(_fd_observed_state(fd)["open"] is False for fd in closed),
                "socket_handles_closed": observed["socket_handles_closed"],
            }
        return ResetResult(
            resetter=f"{name}_resetter", status="VERIFIED" if all(checks.values()) else "FAILED",
            identity_after=identity_snapshot(), state_after=observed, checks=checks,
            output="전달/상속용 FD와 socket 정리 및 원상복구",
        )

    return ToolDefinition(
        name=name, tool=_FD_TRANSFER_TOOL, action=action,
        handler=handler, verifier=verifier, resetter=resetter, spec=spec,
    )


def _failed_action_observation(
    definition: ToolDefinition,
    state: dict[str, Any],
    decision: ToolDecision,
    context: ToolContext,
) -> tuple[dict[str, Any], bool]:
    backup = state.get("backup")
    if isinstance(backup, Mapping) and isinstance(backup.get("state"), Mapping):
        expected = backup["state"]
        observed = _full_path_state(expected["path"])
        return observed, observed == expected
    target = state.get("target")
    if definition.tool == _FILE_CREATE_TOOL and isinstance(target, str):
        observed = _full_path_state(target)
        return observed, observed.get("exists") is False
    if definition.tool == _FILE_MOVE_TOOL:
        source, destination = state.get("source"), state.get("destination")
        before_source = state.get("before_source")
        if isinstance(source, str) and isinstance(destination, str) and isinstance(before_source, Mapping):
            observed = {
                "source": _full_path_state(source),
                "destination": _full_path_state(destination),
            }
            return observed, observed["source"] == before_source and observed["destination"].get("exists") is False
    path = state.get("path")
    if isinstance(path, str) and "original_flags" in state:
        observed_flags = _inode_flags_path(path)
        return {"path": path, "inode_flags": observed_flags}, observed_flags == state["original_flags"]
    before_path = state.get("before_path")
    if isinstance(path, str) and isinstance(before_path, Mapping):
        observed_path = _full_path_state(path)
        return observed_path, observed_path == before_path
    fd = state.get("fd")
    before_fd = state.get("before_fd")
    if isinstance(fd, int) and isinstance(before_fd, Mapping):
        observed_fd = _fd_observed_state(fd)
        return observed_fd, observed_fd == before_fd
    if definition.tool == _FD_TRANSFER_TOOL:
        if definition.action == "inherit":
            source_fd = state.get("source_fd")
            original_flags = state.get("original_flags")
            if isinstance(source_fd, int) and isinstance(original_flags, int):
                observed_flags = fcntl.fcntl(source_fd, fcntl.F_GETFD)
                return {"fd_flags": observed_flags}, observed_flags == original_flags
        residual = any(key in state for key in ("received_fd", "verify_fd", "pidfd", "left", "right"))
        return {"temporary_resources_present": residual}, not residual
    # 실제 OS 호출 전에 거부되었거나, 호출 자체가 어떤 상태도 만들지 못한 경우.
    return {"state_keys": sorted(state)}, not bool(state)


def _failed_action_reset(
    definition: ToolDefinition,
    state: dict[str, Any],
    decision: ToolDecision,
    context: ToolContext,
) -> ResetResult:
    cleanup_performed = False
    try:
        backup = state.get("backup")
        if isinstance(backup, Mapping) and isinstance(backup.get("state"), Mapping):
            _restore_path_backup(backup)
            cleanup_performed = True
        elif isinstance(backup, Mapping) and isinstance(backup.get("observed"), Mapping):
            fd = state.get("fd")
            if isinstance(fd, int) and _fd_observed_state(fd).get("open"):
                _restore_fd_backup(fd, backup)
                cleanup_performed = True

        target = state.get("target")
        if definition.tool == _FILE_CREATE_TOOL and isinstance(target, str):
            _remove_path(target)
            cleanup_performed = True

        if definition.tool == _FILE_MOVE_TOOL:
            source, destination = state.get("source"), state.get("destination")
            if isinstance(destination, str) and os.path.lexists(destination):
                if definition.action == "rename" and isinstance(source, str) and not os.path.lexists(source):
                    os.rename(destination, source)
                else:
                    _remove_path(destination)
                cleanup_performed = True

        if definition.tool == _FILE_INODE_TOOL and "original_flags" in state:
            path = state.get("path")
            if isinstance(path, str):
                fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
                try:
                    _write_inode_flags(fd, state["original_flags"])
                finally:
                    os.close(fd)
                cleanup_performed = True

        held_fd = state.pop("opened_fd", None)
        if isinstance(held_fd, int):
            os.close(held_fd)
            cleanup_performed = True

        if definition.tool == _FILE_LOCK_TOOL:
            held_fd = state.pop("fd", None)
            if isinstance(held_fd, int):
                if definition.action in {"lock", "unlock"}:
                    fcntl.flock(held_fd, fcntl.LOCK_UN)
                else:
                    fcntl.fcntl(held_fd, F_SETLEASE, F_UNLCK)
                os.close(held_fd)
                cleanup_performed = True

        if definition.tool == _FD_OPERATE_TOOL:
            fd = state.get("fd")
            before_fd = state.get("before_fd")
            if isinstance(fd, int) and isinstance(before_fd, Mapping) and _fd_observed_state(fd).get("open"):
                if before_fd.get("offset") is not None:
                    os.lseek(fd, before_fd["offset"], os.SEEK_SET)
                    cleanup_performed = True
            duplicate = state.pop("duplicated_fd", None)
            if isinstance(duplicate, int):
                os.close(duplicate)
                cleanup_performed = True

        control_write = state.pop("control_write", None)
        child_pid = state.pop("child_pid", None)
        if isinstance(control_write, int):
            try:
                os.write(control_write, b"x")
            finally:
                os.close(control_write)
            cleanup_performed = True
        if isinstance(child_pid, int):
            os.waitpid(child_pid, 0)
            cleanup_performed = True

        if definition.tool == _FD_TRANSFER_TOOL and definition.action == "inherit":
            source_fd = state.get("source_fd")
            if isinstance(source_fd, int) and "original_flags" in state:
                fcntl.fcntl(source_fd, fcntl.F_SETFD, state["original_flags"])
                cleanup_performed = True

        for key in ("received_fd", "verify_fd", "pidfd"):
            temporary_fd = state.pop(key, None)
            if isinstance(temporary_fd, int):
                try:
                    os.close(temporary_fd)
                except OSError as exc:
                    if exc.errno != errno_module.EBADF:
                        raise
                cleanup_performed = True
        for key in ("left", "right"):
            temporary_socket = state.pop(key, None)
            if isinstance(temporary_socket, socket.socket):
                temporary_socket.close()
                cleanup_performed = True

        observed, restored = _failed_action_observation(definition, state, decision, context)
        checks = {"failed_action_residue_removed": restored}
        status = ("VERIFIED" if cleanup_performed else "NOT_REQUIRED") if restored else "FAILED"
        return ResetResult(
            resetter=f"{definition.name}_resetter",
            status=status,
            identity_after=identity_snapshot(),
            state_after=observed,
            checks=checks,
            output="실패 action의 부분 상태 정리 및 재조회",
        )
    except Exception as exc:
        return ResetResult(
            resetter=f"{definition.name}_resetter",
            status="FAILED",
            identity_after=identity_snapshot(),
            state_after={"state_keys": sorted(state)},
            checks={"failed_action_residue_removed": False},
            output=f"실패 action 긴급 Reset 실패: {exc}",
        )


def _guard_non_allowed(definition: ToolDefinition) -> ToolDefinition:
    """정책 차단과 OS/API 실패를 실제 Action Verifier/Reset과 분리한다."""
    specific_verifier = definition.verifier
    specific_resetter = definition.resetter

    def verifier(
        state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext,
    ) -> VerificationResult:
        if not result.attempted:
            return VerificationResult(
                verifier=f"{definition.name}_verifier",
                status="NOT_RUN",
                observed={"reason": result.output},
            )
        if result.outcome != "ALLOWED":
            observed, unchanged = _failed_action_observation(definition, state, decision, context)
            return VerificationResult(
                verifier=f"{definition.name}_verifier",
                status="VERIFIED_NO_CHANGE" if unchanged else "REJECTED",
                checks={"failed_action_left_no_change": unchanged},
                observed=observed,
            )
        return specific_verifier(state, decision, result, context)

    def resetter(
        state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext,
    ) -> ResetResult:
        if not result.attempted:
            return ResetResult(
                resetter=f"{definition.name}_resetter",
                status="NOT_REQUIRED",
                identity_after=identity_snapshot(),
                state_after=dict(result.state_before),
                checks={"os_call_not_attempted": True},
                output="정책/인자 단계에서 차단되어 Reset 불필요",
            )
        if result.outcome != "ALLOWED":
            return _failed_action_reset(definition, state, decision, context)
        return specific_resetter(state, decision, result, context)

    return ToolDefinition(
        name=definition.name,
        tool=definition.tool,
        action=definition.action,
        handler=definition.handler,
        verifier=verifier,
        resetter=resetter,
        spec=definition.spec,
    )


_FILE_FD_DEFINITIONS = tuple(_guard_non_allowed(definition) for definition in (
    *(_build_file_open_definition(action) for action in ("read", "write", "append", "execute", "opath")),
    *(_build_file_create_definition(action) for action in ("file", "directory", "fifo")),
    *(_build_file_content_definition(action) for action in ("read", "write", "append", "truncate", "copy")),
    *(_build_file_remove_definition(action) for action in ("unlink", "rmdir")),
    *(_build_file_move_definition(action) for action in ("rename", "hardlink", "symlink", "follow")),
    *(_build_file_metadata_definition(action) for action in ("chmod", "chown", "chgrp", "set_times")),
    *(_build_file_acl_definition(action) for action in ("get", "set_access", "set_default", "remove")),
    *(_build_file_xattr_definition(action) for action in ("get", "set", "remove")),
    *(_build_file_inode_definition(action) for action in ("get", "set", "clear")),
    *(_build_file_lock_definition(action) for action in ("lock", "unlock", "lease_set", "lease_release")),
    *(_build_file_handle_definition(action) for action in ("name_to_handle", "open_by_handle")),
    *(_build_fd_operate_definition(action) for action in ("read", "write", "seek", "truncate", "dup", "close")),
    *(_build_fd_transfer_definition(action) for action in ("inherit", "scm_send", "scm_receive", "pidfd_getfd")),
))

if len(_FILE_FD_DEFINITIONS) != 49:
    raise ToolContractError(f"file_fd ToolDefinition 수 불일치: {len(_FILE_FD_DEFINITIONS)}")

for _definition in _FILE_FD_DEFINITIONS:
    register_definition(_definition)
