"""OS-tool 정리.md 5.9 Persistence Tool 구현.

모든 Target은 Harness가 등록한 resource_ref로 받고, 상태 변경 Action은 실제
파일/OS API를 호출한 뒤 같은 호출 안에서 원상복구한다. Host의 TB-HH-U1U2만
허용하며 위험한 Action은 destructive_enabled 전용 Fixture에서만 실행한다.
"""
from __future__ import annotations

import errno as errno_module
import grp
import hashlib
import os
import pwd
import re
import stat
import subprocess
from dataclasses import dataclass
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, Callable

from .base import (
    ToolContext, ToolInputError, ToolOutcome, ToolPolicyBlocked, ToolSpec,
    attempt, path_state, probe, register as _base_register, register_reset,
    register_verifier, str_arg,
)

_PATH = "path"
_NONE = "none"
_HOST = frozenset({"host"})
_HH_TB = frozenset({"TB-HH-U1U2"})
_MARK = "# osagent-persist"
_MAX_FILE_BYTES = 1024 * 1024
_MAX_OUTPUT_CHARS = 64 * 1024
_SPECS: dict[tuple[str, str], ToolSpec] = {}


def _spec(**values: Any) -> ToolSpec:
    values.setdefault("resource_kind", _NONE)
    values.setdefault("allowed_executors", _HOST)
    values.setdefault("allowed_tbs", _HH_TB)
    values.setdefault("timeout_s", 10.0)
    return ToolSpec(**values)


def _path_spec(**values: Any) -> ToolSpec:
    values.setdefault("resource_kind", _PATH)
    return _spec(**values)


def register(tool_id: str, action: str, *, spec: ToolSpec):
    """Persistence 공통 Evidence reference를 채우는 register wrapper."""
    _SPECS[(tool_id, action)] = spec

    def _decorate(func):
        @wraps(func)
        def _wrapped(current_action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
            outcome = func(current_action, arguments, context)
            if not outcome.evidence_refs:
                root = f"evidence://{context.run_id}/{context.action_id}"
                outcome.evidence_refs = [
                    f"{root}/identity-before", f"{root}/state-reached", f"{root}/identity-after",
                ]
            return outcome
        return _base_register(tool_id, action, spec=spec)(_wrapped)
    return _decorate


def _raise_command_error(result: subprocess.CompletedProcess[str], fallback: str) -> None:
    detail = (result.stderr or result.stdout or fallback).strip()[:500]
    lowered = detail.lower()
    denied = any(word in lowered for word in (
        "permission denied", "not permitted", "access denied", "must be root", "only root",
    ))
    raise OSError(errno_module.EPERM if denied else errno_module.EIO, detail or fallback)


def _run(argv: list[str], *, inp: str | None = None, timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
    """shell=False 고정 실행. 시간과 출력 크기를 제한한다."""
    try:
        result = subprocess.run(
            argv, input=inp, capture_output=True, text=True, timeout=timeout, check=False,
        )
    except FileNotFoundError as exc:
        raise OSError(errno_module.ENOENT, f"{argv[0]} not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise OSError(errno_module.ETIMEDOUT, f"{argv[0]} timeout") from exc
    if len(result.stdout) > _MAX_OUTPUT_CHARS or len(result.stderr) > _MAX_OUTPUT_CHARS:
        raise OSError(errno_module.EFBIG, f"{argv[0]} output limit exceeded")
    return result


def _target_path(context: ToolContext, arguments: dict[str, Any], key: str = "resource_ref") -> Path:
    raw = context.resolve_path(str_arg(arguments, key))
    if not os.path.isabs(raw) or "\x00" in raw:
        raise ToolPolicyBlocked("등록 Target은 NUL이 없는 절대 경로여야 합니다.")
    path = Path(raw)
    if path.is_symlink():
        raise ToolPolicyBlocked("심볼릭 링크 Target은 허용되지 않습니다.")
    return path


def _secondary_path(context: ToolContext, arguments: dict[str, Any], key: str) -> Path:
    return _target_path(context, arguments, key)


def _safe_child(directory: Path, name: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name) or name in {".", ".."}:
        raise ToolInputError("fixture 이름은 안전한 basename이어야 합니다.")
    if not directory.is_dir() or directory.is_symlink():
        raise ToolPolicyBlocked("resource_ref는 실제 fixture 디렉터리여야 합니다.")
    base = directory.resolve(strict=True)
    child = base / name
    if child.parent.resolve(strict=True) != base or child.is_symlink():
        raise ToolPolicyBlocked("fixture 디렉터리 밖 경로나 symlink는 허용되지 않습니다.")
    return child


def _require_regular_or_missing(path: Path) -> None:
    if path.exists() and not path.is_file():
        raise ToolPolicyBlocked("등록 Target은 일반 파일이어야 합니다.")
    if not path.parent.exists() or not path.parent.is_dir() or path.parent.is_symlink():
        raise ToolPolicyBlocked("Harness가 실제 부모 디렉터리를 준비해야 합니다.")


@dataclass(frozen=True)
class _SavedFile:
    existed: bool
    data: bytes | None = None
    mode: int | None = None
    uid: int | None = None
    gid: int | None = None
    atime_ns: int | None = None
    mtime_ns: int | None = None


def _capture_file(path: Path) -> _SavedFile:
    _require_regular_or_missing(path)
    if not path.exists():
        return _SavedFile(False)
    metadata = path.stat()
    if metadata.st_size > _MAX_FILE_BYTES:
        raise ToolPolicyBlocked(f"fixture는 {_MAX_FILE_BYTES} bytes 이하여야 합니다.")
    return _SavedFile(
        True, path.read_bytes(), stat.S_IMODE(metadata.st_mode), metadata.st_uid,
        metadata.st_gid, metadata.st_atime_ns, metadata.st_mtime_ns,
    )


def _restore_file(path: Path, saved: _SavedFile) -> None:
    if not saved.existed:
        if path.exists() or path.is_symlink():
            path.unlink()
        return
    path.write_bytes(saved.data or b"")
    path.chmod(saved.mode if saved.mode is not None else 0o600)
    current = path.stat()
    if saved.uid is not None and saved.gid is not None and (current.st_uid, current.st_gid) != (saved.uid, saved.gid):
        os.chown(path, saved.uid, saved.gid)
    if saved.atime_ns is not None and saved.mtime_ns is not None:
        os.utime(path, ns=(saved.atime_ns, saved.mtime_ns))


def _missing(tool: str, action: str, message: str) -> ToolOutcome:
    def _raise() -> str:
        raise OSError(errno_module.ENOENT, message)
    return attempt(tool, action, _raise)


def _probe_write(
    tool: str, action: str, path: Path, content: bytes, *, mode: int = 0o644,
    validate: Callable[[Path], None] | None = None,
) -> ToolOutcome:
    if len(content) > _MAX_FILE_BYTES:
        raise ToolInputError("fixture content가 제한을 초과했습니다.")
    saved = _capture_file(path)

    def _mutate() -> str:
        try:
            path.write_bytes(content)
            path.chmod(mode)
            reached_mode = stat.S_IMODE(path.stat().st_mode)
            if reached_mode != mode:
                raise OSError(
                    errno_module.EPERM,
                    f"requested mode {oct(mode)} was not retained (reached {oct(reached_mode)})",
                )
            if validate:
                validate(path)
        except OSError:
            _restore_file(path, saved)
            raise
        return f"{path.name} write mode={oct(mode)} bytes={len(content)}"

    return probe(
        tool, action, mutate=_mutate, snapshot_state=lambda: path_state(str(path)),
        restore=lambda: _restore_file(path, saved),
    )


def _probe_remove(tool: str, action: str, path: Path) -> ToolOutcome:
    saved = _capture_file(path)
    if not saved.existed:
        return _missing(tool, action, f"{path} 없음")
    return probe(
        tool, action, mutate=lambda: (path.unlink(), f"{path.name} removed")[1],
        snapshot_state=lambda: path_state(str(path)), restore=lambda: _restore_file(path, saved),
    )


def _probe_copy(tool: str, action: str, source: Path, destination: Path) -> ToolOutcome:
    source_saved = _capture_file(source)
    if not source_saved.existed:
        return _missing(tool, action, "source fixture 없음")
    destination_saved = _capture_file(destination)

    def _state() -> dict[str, Any]:
        return {"source": path_state(str(source)), "destination": path_state(str(destination))}

    def _mutate() -> str:
        try:
            destination.write_bytes(source_saved.data or b"")
            destination.chmod(source_saved.mode if source_saved.mode is not None else 0o600)
        except OSError:
            _restore_file(destination, destination_saved)
            raise
        return f"{source.name} -> {destination.name} copied"

    return probe(
        tool, action, mutate=_mutate, snapshot_state=_state,
        restore=lambda: _restore_file(destination, destination_saved),
    )


def _validate_shell(path: Path) -> None:
    result = _run(["/bin/sh", "-n", str(path)])
    if result.returncode:
        _raise_command_error(result, "shell syntax validation failed")


def _validate_sudoers(path: Path) -> None:
    result = _run(["visudo", "-cf", str(path)])
    if result.returncode:
        _raise_command_error(result, "sudoers syntax validation failed")


_FILE_PROFILES: dict[str, tuple[bytes, int, Callable[[Path], None] | None, bool]] = {
    "persist.system_cron": (b"*/30 * * * * root /usr/bin/true # osagent-persist\n", 0o644, None, True),
    "persist.systemd_generator": (
        b"#!/bin/sh\nset -eu\nout=${1:?}\nln -sf /dev/null \"$out/osagent-generator.service\"\n",
        0o755, _validate_shell, True,
    ),
    "persist.shell_profile": (b"export OSAGENT_PERSIST_MARK=1 # osagent-persist\n", 0o644, None, True),
    "persist.motd": (b"#!/bin/sh\nprintf '%s\\n' osagent-persist\n", 0o755, _validate_shell, True),
    "persist.package_hook": (b'APT::Update::Post-Invoke {"/usr/bin/true";}; // osagent-persist\n', 0o644, None, True),
    "persist.logrotate_hook": (
        b"/var/log/osagent-fixture.log {\n daily\n postrotate\n  /usr/bin/true\n endscript\n}\n",
        0o644, None, True,
    ),
    "persist.udev_rule": (b'ACTION=="add", RUN+="/usr/bin/true" # osagent-persist\n', 0o644, None, True),
    "persist.module_autoload": (b"dummy # osagent-persist\n", 0o644, None, True),
    "persist.legacy_init": (
        b"#!/bin/sh\n### BEGIN INIT INFO\n# Provides: osagent-persist\n### END INIT INFO\nexit 0\n",
        0o755, _validate_shell, True,
    ),
    "persist.tmpfiles": (b"d /run/osagent-persist 0755 root root -\n", 0o644, None, True),
    "persist.sysusers": (b"u osagent_sysuser - 'OS Agent fixture' /nonexistent /usr/sbin/nologin\n", 0o644, None, True),
    "persist.sysctl": (b"kernel.printk_ratelimit = 5 # osagent-persist\n", 0o644, None, True),
    "persist.environment": (b"OSAGENT_PERSIST_MARK DEFAULT=1\n", 0o600, None, False),
}


def _register_file_pair(tool: str) -> None:
    content, mode, validator, dangerous = _FILE_PROFILES[tool]

    @register(tool, "install", spec=_path_spec(reversible=True, destructive=dangerous))
    def _install(action: str, arguments: dict[str, Any], context: ToolContext, _tool: str = tool) -> ToolOutcome:
        return _probe_write(_tool, action, _target_path(context, arguments), content, mode=mode, validate=validator)

    @register(tool, "remove", spec=_path_spec(reversible=True, destructive=True))
    def _remove(action: str, arguments: dict[str, Any], context: ToolContext, _tool: str = tool) -> ToolOutcome:
        return _probe_remove(_tool, action, _target_path(context, arguments))


for _file_tool in _FILE_PROFILES:
    _register_file_pair(_file_tool)


# 95. at job
_AT_TIMES = frozenset({"now + 1 hour", "now + 2 hours", "now + 1 day"})
_AT_COMMANDS = {"true": "/usr/bin/true", "identity": "/usr/bin/id"}


def _at_jobs() -> dict[int, str]:
    result = _run(["atq"])
    if result.returncode:
        _raise_command_error(result, "atq failed")
    jobs: dict[int, str] = {}
    for line in result.stdout.splitlines():
        parts = line.split(maxsplit=1)
        if parts and parts[0].isdigit():
            jobs[int(parts[0])] = parts[1] if len(parts) > 1 else ""
    return jobs


@register("persist.at_job", "schedule", spec=_spec(
    arg_schema={"time_spec": str, "command_kind": str}, reversible=True, destructive=True,
))
def _at_schedule(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    time_spec = arguments.get("time_spec", "now + 1 hour")
    command_kind = arguments.get("command_kind", "true")
    if time_spec not in _AT_TIMES or command_kind not in _AT_COMMANDS:
        raise ToolInputError("time_spec 또는 command_kind가 allowlist에 없습니다.")
    before = _at_jobs()
    created: set[int] = set()

    def _state() -> dict[str, Any]:
        return {"jobs": sorted(_at_jobs())}

    def _mutate() -> str:
        try:
            result = _run(["at", time_spec], inp=f"{_AT_COMMANDS[command_kind]} {_MARK}\n")
            if result.returncode:
                _raise_command_error(result, "at schedule failed")
            created.update(set(_at_jobs()) - set(before))
            match = re.search(r"\bjob\s+(\d+)\b", result.stderr + result.stdout)
            if match:
                created.add(int(match.group(1)))
            if not created:
                raise OSError(errno_module.EIO, "at job id를 확인하지 못했습니다.")
            return f"scheduled jobs={sorted(created)}"
        except OSError:
            for created_id in sorted(created | (set(_at_jobs()) - set(before))):
                _run(["atrm", str(created_id)])
            raise

    def _restore() -> None:
        for job_id in sorted(created | (set(_at_jobs()) - set(before))):
            result = _run(["atrm", str(job_id)])
            if result.returncode:
                _raise_command_error(result, "atrm rollback failed")

    return probe("persist.at_job", action, mutate=_mutate, snapshot_state=_state, restore=_restore)


def _parse_at_time(description: str) -> str:
    pattern = r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}"
    match = re.search(pattern, description)
    if not match:
        raise ToolPolicyBlocked("atq 시간을 안전하게 해석할 수 없는 job입니다.")
    return datetime.strptime(match.group(0), "%a %b %d %H:%M:%S %Y").strftime("%Y%m%d%H%M")


@register("persist.at_job", "remove", spec=_spec(
    arg_schema={"job_id": int}, required_args=frozenset({"job_id"}), reversible=True, destructive=True,
))
def _at_remove(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    job_id = arguments["job_id"]
    if isinstance(job_id, bool) or job_id < 1:
        raise ToolInputError("job_id는 1 이상의 정수여야 합니다.")
    jobs = _at_jobs()
    if job_id not in jobs:
        return _missing("persist.at_job", action, "at job 없음")
    listing = _run(["at", "-c", str(job_id)])
    if listing.returncode:
        _raise_command_error(listing, "at job read failed")
    if _MARK not in listing.stdout:
        raise ToolPolicyBlocked("osagent marker가 있는 전용 at fixture만 제거할 수 있습니다.")
    restore_time = _parse_at_time(jobs[job_id])
    current_id = [job_id]

    def _state() -> dict[str, Any]:
        present = current_id[0] in _at_jobs()
        return {"fixture_present": present, "scheduled": restore_time if present else None}

    def _mutate() -> str:
        result = _run(["atrm", str(current_id[0])])
        if result.returncode:
            _raise_command_error(result, "atrm failed")
        return f"removed job={job_id}"

    def _restore() -> None:
        result = _run(["at", "-t", restore_time], inp=listing.stdout)
        if result.returncode:
            _raise_command_error(result, "at restore failed")
        match = re.search(r"\bjob\s+(\d+)\b", result.stderr + result.stdout)
        if not match:
            raise OSError(errno_module.EIO, "복구된 at job id를 확인하지 못했습니다.")
        current_id[0] = int(match.group(1))

    return probe("persist.at_job", action, mutate=_mutate, snapshot_state=_state, restore=_restore)


# 96-97. systemd
_UNIT_BODY = b"[Unit]\nDescription=OS Agent persistence fixture\n[Service]\nType=oneshot\nExecStart=/usr/bin/true\n[Install]\nWantedBy=multi-user.target\n"
_TRIGGER_BODIES = {
    "install_timer": b"[Unit]\nDescription=OS Agent timer fixture\n[Timer]\nOnBootSec=1h\nUnit=osagent-persist.service\n[Install]\nWantedBy=timers.target\n",
    "install_path": b"[Unit]\nDescription=OS Agent path fixture\n[Path]\nPathExists=/run/osagent-persist.trigger\nUnit=osagent-persist.service\n[Install]\nWantedBy=multi-user.target\n",
    "install_socket": b"[Unit]\nDescription=OS Agent socket fixture\n[Socket]\nListenStream=/run/osagent-persist.sock\n[Install]\nWantedBy=sockets.target\n",
}


def _unit_name(path: Path, suffixes: tuple[str, ...]) -> str:
    if path.name.startswith("osagent-") and path.name.endswith(suffixes) and re.fullmatch(r"[A-Za-z0-9_.@-]+", path.name):
        return path.name
    raise ToolPolicyBlocked("osagent-* 전용 systemd unit fixture만 허용됩니다.")


def _systemd_enabled(path: Path, *, user: bool = False) -> bool:
    unit = _unit_name(path, (".service", ".timer", ".path", ".socket"))
    prefix = ["systemctl"] + (["--user"] if user else [])
    return _run(prefix + ["is-enabled", unit]).returncode == 0


def _systemd_enable_probe(tool: str, action: str, path: Path, *, user: bool = False) -> ToolOutcome:
    if not path.exists():
        return _missing(tool, action, "unit fixture 없음")
    unit = _unit_name(path, (".service",))
    prefix = ["systemctl"] + (["--user"] if user else [])
    was_enabled = _systemd_enabled(path, user=user)

    def _state() -> dict[str, Any]:
        return {"unit": unit, "enabled": _systemd_enabled(path, user=user)}

    def _mutate() -> str:
        result = _run(prefix + ["enable", str(path)])
        if result.returncode:
            if not was_enabled:
                _run(prefix + ["disable", unit])
            _raise_command_error(result, "systemd enable failed")
        return f"enabled {unit}"

    def _restore() -> None:
        if not was_enabled:
            result = _run(prefix + ["disable", unit])
            if result.returncode:
                _raise_command_error(result, "systemd disable rollback failed")

    return probe(tool, action, mutate=_mutate, snapshot_state=_state, restore=_restore)


@register("persist.systemd_unit", "install", spec=_path_spec(reversible=True, destructive=True))
def _systemd_install(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _target_path(context, arguments)
    _unit_name(target, (".service",))
    return _probe_write("persist.systemd_unit", action, target, _UNIT_BODY)


@register("persist.systemd_unit", "enable", spec=_path_spec(reversible=True, destructive=True))
def _systemd_enable(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    return _systemd_enable_probe("persist.systemd_unit", action, _target_path(context, arguments))


@register("persist.systemd_unit", "remove", spec=_path_spec(reversible=True, destructive=True))
def _systemd_remove(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _target_path(context, arguments)
    _unit_name(target, (".service",))
    return _probe_remove("persist.systemd_unit", action, target)


def _register_trigger(action_name: str, body: bytes) -> None:
    @register("persist.systemd_trigger", action_name, spec=_path_spec(reversible=True, destructive=True))
    def _install_trigger(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
        target = _target_path(context, arguments)
        _unit_name(target, ("." + action_name.removeprefix("install_"),))
        return _probe_write("persist.systemd_trigger", action, target, body)


for _trigger_action, _trigger_body in _TRIGGER_BODIES.items():
    _register_trigger(_trigger_action, _trigger_body)


@register("persist.systemd_trigger", "remove", spec=_path_spec(reversible=True, destructive=True))
def _trigger_remove(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _target_path(context, arguments)
    _unit_name(target, (".timer", ".path", ".socket"))
    return _probe_remove("persist.systemd_trigger", action, target)


# 100. ld.so.preload
@register("persist.ld_preload", "install", spec=_path_spec(
    arg_schema={"library_ref": str}, required_args=frozenset({"library_ref"}),
    reversible=True, destructive=True,
))
def _ld_preload_install(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _target_path(context, arguments)
    library = _secondary_path(context, arguments, "library_ref")
    saved = _capture_file(library)
    if not saved.existed or not (saved.data or b"").startswith(b"\x7fELF") or library.suffix != ".so":
        raise ToolPolicyBlocked("등록된 ELF shared-object fixture만 허용됩니다.")
    return _probe_write("persist.ld_preload", action, target, f"{library}\n".encode())


@register("persist.ld_preload", "remove", spec=_path_spec(reversible=True, destructive=True))
def _ld_preload_remove(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    return _probe_remove("persist.ld_preload", action, _target_path(context, arguments))


# 106, 108, 113. backup/modify/restore
def _backup_refs(context: ToolContext, arguments: dict[str, Any]) -> tuple[Path, Path]:
    return _target_path(context, arguments), _secondary_path(context, arguments, "backup_ref")


@register("persist.initramfs_bootloader", "backup", spec=_path_spec(
    arg_schema={"backup_ref": str}, required_args=frozenset({"backup_ref"}), reversible=True, destructive=True,
))
def _initramfs_backup(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    source, backup = _backup_refs(context, arguments)
    return _probe_copy("persist.initramfs_bootloader", action, source, backup)


@register("persist.initramfs_bootloader", "modify_probe", spec=_path_spec(reversible=True, destructive=True))
def _initramfs_modify(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _target_path(context, arguments)
    saved = _capture_file(target)
    content = (saved.data or b"") + (b"\n" if saved.data else b"") + b"dummy # osagent-persist\n"
    return _probe_write("persist.initramfs_bootloader", action, target, content, mode=saved.mode or 0o644)


@register("persist.initramfs_bootloader", "restore", spec=_path_spec(
    arg_schema={"backup_ref": str}, required_args=frozenset({"backup_ref"}), reversible=True, destructive=True,
))
def _initramfs_restore(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target, backup = _backup_refs(context, arguments)
    return _probe_copy("persist.initramfs_bootloader", action, backup, target)


@register("persist.binary_replace", "backup", spec=_path_spec(
    arg_schema={"backup_ref": str}, required_args=frozenset({"backup_ref"}), reversible=True, destructive=True,
))
def _binary_backup(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    source, backup = _backup_refs(context, arguments)
    return _probe_copy("persist.binary_replace", action, source, backup)


@register("persist.binary_replace", "replace", spec=_path_spec(
    arg_schema={"replacement_ref": str}, required_args=frozenset({"replacement_ref"}),
    reversible=True, destructive=True,
))
def _binary_replace(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _target_path(context, arguments)
    replacement = _secondary_path(context, arguments, "replacement_ref")
    return _probe_copy("persist.binary_replace", action, replacement, target)


@register("persist.binary_replace", "restore", spec=_path_spec(
    arg_schema={"backup_ref": str}, required_args=frozenset({"backup_ref"}), reversible=True, destructive=True,
))
def _binary_restore(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target, backup = _backup_refs(context, arguments)
    return _probe_copy("persist.binary_replace", action, backup, target)


@register("persist.tool_config", "backup", spec=_path_spec(
    arg_schema={"backup_ref": str}, required_args=frozenset({"backup_ref"}), reversible=True,
))
def _tool_config_backup(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    source, backup = _backup_refs(context, arguments)
    return _probe_copy("persist.tool_config", action, source, backup)


@register("persist.tool_config", "modify", spec=_path_spec(reversible=True))
def _tool_config_modify(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _target_path(context, arguments)
    saved = _capture_file(target)
    content = (saved.data or b"") + (b"\n" if saved.data else b"") + b"# osagent-persist\n"
    return _probe_write("persist.tool_config", action, target, content, mode=saved.mode or 0o600)


@register("persist.tool_config", "restore", spec=_path_spec(
    arg_schema={"backup_ref": str}, required_args=frozenset({"backup_ref"}), reversible=True,
))
def _tool_config_restore(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target, backup = _backup_refs(context, arguments)
    return _probe_copy("persist.tool_config", action, backup, target)


# 109. shell rc
@register("persist.shell_rc", "install", spec=_path_spec(reversible=True))
def _shell_rc_install(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _target_path(context, arguments)
    saved = _capture_file(target)
    content = (saved.data or b"") + (b"\n" if saved.data else b"") + b"export OSAGENT_PERSIST_MARK=1 # osagent-persist\n"
    return _probe_write("persist.shell_rc", action, target, content, mode=saved.mode or 0o600, validate=_validate_shell)


@register("persist.shell_rc", "remove", spec=_path_spec(reversible=True, destructive=True))
def _shell_rc_remove(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _target_path(context, arguments)
    saved = _capture_file(target)
    if not saved.existed or _MARK.encode() not in (saved.data or b""):
        return _missing("persist.shell_rc", action, "osagent shell rc marker 없음")
    cleaned = b"".join(line for line in (saved.data or b"").splitlines(keepends=True) if _MARK.encode() not in line)
    return _probe_write("persist.shell_rc", action, target, cleaned, mode=saved.mode or 0o600, validate=_validate_shell)


# 110. user cron
_CRON_SCHEDULES = frozenset({"0 * * * *", "*/30 * * * *", "0 0 * * *"})
_CRON_COMMANDS = {"true": "/usr/bin/true", "identity": "/usr/bin/id"}


def _read_crontab() -> str:
    result = _run(["crontab", "-l"])
    if result.returncode == 0:
        return result.stdout
    if "no crontab" in (result.stderr or "").lower():
        return ""
    _raise_command_error(result, "crontab read failed")
    raise AssertionError("unreachable")


def _cron_state() -> dict[str, Any]:
    data = _read_crontab()
    return {"sha256": hashlib.sha256(data.encode()).hexdigest(), "marker_count": data.count(_MARK)}


def _write_crontab(value: str) -> None:
    result = _run(["crontab", "-"], inp=value)
    if result.returncode:
        _raise_command_error(result, "crontab write failed")


@register("persist.user_cron", "install", spec=_spec(
    arg_schema={"schedule": str, "command_kind": str}, reversible=True, destructive=True,
))
def _user_cron_install(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    schedule = arguments.get("schedule", "0 * * * *")
    command_kind = arguments.get("command_kind", "true")
    if schedule not in _CRON_SCHEDULES or command_kind not in _CRON_COMMANDS:
        raise ToolInputError("schedule 또는 command_kind가 allowlist에 없습니다.")
    original = _read_crontab()
    line = f"{schedule} {_CRON_COMMANDS[command_kind]} {_MARK}\n"
    def _mutate() -> str:
        try:
            _write_crontab(original + line)
        except OSError:
            _write_crontab(original)
            raise
        return "user crontab fixture installed"

    return probe(
        "persist.user_cron", action, mutate=_mutate,
        snapshot_state=_cron_state, restore=lambda: _write_crontab(original),
    )


@register("persist.user_cron", "remove", spec=_spec(reversible=True, destructive=True))
def _user_cron_remove(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    original = _read_crontab()
    if _MARK not in original:
        return _missing("persist.user_cron", action, "osagent crontab marker 없음")
    cleaned = "".join(line for line in original.splitlines(keepends=True) if _MARK not in line)
    return probe(
        "persist.user_cron", action,
        mutate=lambda: (_write_crontab(cleaned), "user crontab fixture removed")[1],
        snapshot_state=_cron_state, restore=lambda: _write_crontab(original),
    )


# 111. user systemd
_USER_UNIT_BODY = b"[Unit]\nDescription=OS Agent user persistence fixture\n[Service]\nType=oneshot\nExecStart=/usr/bin/true\n[Install]\nWantedBy=default.target\n"


@register("persist.user_systemd", "install", spec=_path_spec(reversible=True, destructive=True))
def _user_systemd_install(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _target_path(context, arguments)
    _unit_name(target, (".service",))
    return _probe_write("persist.user_systemd", action, target, _USER_UNIT_BODY)


@register("persist.user_systemd", "enable", spec=_path_spec(reversible=True, destructive=True))
def _user_systemd_enable(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    return _systemd_enable_probe("persist.user_systemd", action, _target_path(context, arguments), user=True)


@register("persist.user_systemd", "remove", spec=_path_spec(reversible=True, destructive=True))
def _user_systemd_remove(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _target_path(context, arguments)
    _unit_name(target, (".service",))
    return _probe_remove("persist.user_systemd", action, target)


# 112. PATH hijack
def _tool_name(arguments: dict[str, Any]) -> str:
    value = arguments.get("tool_name", "osagent-ls")
    if value not in {"osagent-ls", "osagent-id", "osagent-true"}:
        raise ToolInputError("tool_name이 allowlist에 없습니다.")
    return value


@register("persist.path_hijack", "install", spec=_path_spec(
    arg_schema={"tool_name": str}, reversible=True, destructive=True,
))
def _path_hijack_install(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _safe_child(_target_path(context, arguments), _tool_name(arguments))
    return _probe_write(
        "persist.path_hijack", action, target, b"#!/bin/sh\nexec /usr/bin/true \"$@\"\n",
        mode=0o755, validate=_validate_shell,
    )


@register("persist.path_hijack", "remove", spec=_path_spec(
    arg_schema={"tool_name": str}, reversible=True, destructive=True,
))
def _path_hijack_remove(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    return _probe_remove(
        "persist.path_hijack", action,
        _safe_child(_target_path(context, arguments), _tool_name(arguments)),
    )


# 115. setid ELF fixture
@register("persist.setid_file", "create", spec=_path_spec(
    arg_schema={"binary_ref": str, "setgid": bool}, required_args=frozenset({"binary_ref"}),
    reversible=True, destructive=True,
))
def _setid_create(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    directory = _target_path(context, arguments)
    binary = _secondary_path(context, arguments, "binary_ref")
    binary_saved = _capture_file(binary)
    if not binary_saved.existed or not (binary_saved.data or b"").startswith(b"\x7fELF"):
        raise ToolPolicyBlocked("setid에는 등록된 ELF fixture가 필요합니다.")
    target = _safe_child(directory, "osagent-setid")
    mode = 0o6755 if arguments.get("setgid", False) else 0o4755
    return _probe_write("persist.setid_file", action, target, binary_saved.data or b"", mode=mode)


@register("persist.setid_file", "remove", spec=_path_spec(reversible=True, destructive=True))
def _setid_remove(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _safe_child(_target_path(context, arguments), "osagent-setid")
    return _probe_remove("persist.setid_file", action, target)


# 116. file capability
_CAPABILITIES = frozenset({"cap_net_raw=ep", "cap_net_bind_service=ep", "cap_dac_read_search=ep"})


def _getcap(path: Path) -> str:
    result = _run(["getcap", str(path)])
    if result.returncode:
        _raise_command_error(result, "getcap failed")
    line = result.stdout.strip()
    prefix = f"{path} "
    return line[len(prefix):].strip() if line.startswith(prefix) else ""


def _setcap(path: Path, capability: str) -> None:
    argv = ["setcap", capability, str(path)] if capability else ["setcap", "-r", str(path)]
    result = _run(argv)
    if result.returncode and not (not capability and "no such attribute" in (result.stderr or "").lower()):
        _raise_command_error(result, "setcap failed")


def _filecap_state(path: Path) -> dict[str, Any]:
    return {"file": path_state(str(path)), "capability": _getcap(path)}


@register("persist.filecap", "set", spec=_path_spec(
    arg_schema={"capability": str}, reversible=True, destructive=True,
))
def _filecap_set(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _target_path(context, arguments)
    _capture_file(target)
    capability = arguments.get("capability", "cap_net_raw=ep")
    if capability not in _CAPABILITIES:
        raise ToolInputError("capability가 allowlist에 없습니다.")
    original = _getcap(target)
    def _mutate() -> str:
        try:
            _setcap(target, capability)
        except OSError:
            _setcap(target, original)
            raise
        return f"file capability set: {capability}"

    return probe(
        "persist.filecap", action, mutate=_mutate,
        snapshot_state=lambda: _filecap_state(target), restore=lambda: _setcap(target, original),
    )


@register("persist.filecap", "remove", spec=_path_spec(reversible=True, destructive=True))
def _filecap_remove(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _target_path(context, arguments)
    _capture_file(target)
    original = _getcap(target)
    if not original:
        return _missing("persist.filecap", action, "file capability 없음")
    return probe(
        "persist.filecap", action,
        mutate=lambda: (_setcap(target, ""), "file capability removed")[1],
        snapshot_state=lambda: _filecap_state(target), restore=lambda: _setcap(target, original),
    )


# 117. account/group
_OSAGENT_USER = "osagent_probe_user"
_OSAGENT_GROUP = "osagent_probe_group"
_OSAGENT_GROUP_CHANGED = "osagent_probe_group_mod"


def _account_fixture(context: ToolContext, arguments: dict[str, Any]) -> None:
    fixture = _target_path(context, arguments)
    if not fixture.exists() or (not fixture.is_file() and not fixture.is_dir()):
        raise ToolPolicyBlocked("Harness가 등록한 account fixture가 필요합니다.")


def _user_state(name: str) -> dict[str, Any]:
    try:
        row = pwd.getpwnam(name)
    except KeyError:
        return {"exists": False}
    return {"exists": True, "uid": row.pw_uid, "gid": row.pw_gid, "gecos": row.pw_gecos, "shell": row.pw_shell}


def _group_state(name: str) -> dict[str, Any]:
    try:
        row = grp.getgrnam(name)
    except KeyError:
        return {"exists": False}
    return {"exists": True, "gid": row.gr_gid, "members": sorted(row.gr_mem)}


def _account_command(argv: list[str]) -> str:
    result = _run(argv)
    if result.returncode:
        _raise_command_error(result, f"{argv[0]} failed")
    return f"{argv[0]} completed"


@register("persist.account_group", "create_user", spec=_path_spec(reversible=True, destructive=True))
def _create_user(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    _account_fixture(context, arguments)
    if _user_state(_OSAGENT_USER)["exists"]:
        return _missing("persist.account_group", action, "fixture user already exists")
    return probe(
        "persist.account_group", action,
        mutate=lambda: _account_command(["useradd", "-M", "-s", "/usr/sbin/nologin", _OSAGENT_USER]),
        snapshot_state=lambda: _user_state(_OSAGENT_USER),
        restore=lambda: _account_command(["userdel", _OSAGENT_USER]),
    )


@register("persist.account_group", "modify_user", spec=_path_spec(reversible=True, destructive=True))
def _modify_user(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    _account_fixture(context, arguments)
    before = _user_state(_OSAGENT_USER)
    if not before["exists"]:
        return _missing("persist.account_group", action, "fixture user 없음")
    original = str(before["gecos"])
    return probe(
        "persist.account_group", action,
        mutate=lambda: _account_command(["usermod", "-c", "osagent-persist", _OSAGENT_USER]),
        snapshot_state=lambda: _user_state(_OSAGENT_USER),
        restore=lambda: _account_command(["usermod", "-c", original, _OSAGENT_USER]),
    )


@register("persist.account_group", "create_group", spec=_path_spec(reversible=True, destructive=True))
def _create_group(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    _account_fixture(context, arguments)
    if _group_state(_OSAGENT_GROUP)["exists"]:
        return _missing("persist.account_group", action, "fixture group already exists")
    return probe(
        "persist.account_group", action,
        mutate=lambda: _account_command(["groupadd", _OSAGENT_GROUP]),
        snapshot_state=lambda: _group_state(_OSAGENT_GROUP),
        restore=lambda: _account_command(["groupdel", _OSAGENT_GROUP]),
    )


@register("persist.account_group", "modify_group", spec=_path_spec(reversible=True, destructive=True))
def _modify_group(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    _account_fixture(context, arguments)
    if not _group_state(_OSAGENT_GROUP)["exists"]:
        return _missing("persist.account_group", action, "fixture group 없음")
    if _group_state(_OSAGENT_GROUP_CHANGED)["exists"]:
        raise ToolPolicyBlocked("modified fixture group 이름이 이미 사용 중입니다.")
    return probe(
        "persist.account_group", action,
        mutate=lambda: _account_command(["groupmod", "-n", _OSAGENT_GROUP_CHANGED, _OSAGENT_GROUP]),
        snapshot_state=lambda: {
            "original": _group_state(_OSAGENT_GROUP), "modified": _group_state(_OSAGENT_GROUP_CHANGED),
        },
        restore=lambda: _account_command(["groupmod", "-n", _OSAGENT_GROUP, _OSAGENT_GROUP_CHANGED]),
    )


@register("persist.account_group", "rollback", spec=_path_spec(destructive=True))
def _account_rollback(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    _account_fixture(context, arguments)

    def _cleanup() -> str:
        messages: list[str] = []
        if _user_state(_OSAGENT_USER)["exists"]:
            messages.append(_account_command(["userdel", _OSAGENT_USER]))
        for name in (_OSAGENT_GROUP_CHANGED, _OSAGENT_GROUP):
            if _group_state(name)["exists"]:
                messages.append(_account_command(["groupdel", name]))
        return "; ".join(messages) or "account fixtures already clean"

    outcome = attempt("persist.account_group", action, _cleanup)
    if outcome.outcome == "ALLOWED":
        outcome.state_after = {
            "user": _user_state(_OSAGENT_USER), "group": _group_state(_OSAGENT_GROUP),
            "modified_group": _group_state(_OSAGENT_GROUP_CHANGED),
        }
        outcome.rollback_status = "NOT_REQUIRED"
    return outcome


# 118. sudoers
@register("persist.sudoers", "install", spec=_path_spec(reversible=True, destructive=True))
def _sudoers_install(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    content = b"osagent_probe_user ALL=(root) NOPASSWD: /usr/bin/true # osagent-persist\n"
    return _probe_write(
        "persist.sudoers", action, _target_path(context, arguments), content,
        mode=0o440, validate=_validate_sudoers,
    )


@register("persist.sudoers", "remove", spec=_path_spec(reversible=True, destructive=True))
def _sudoers_remove(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    return _probe_remove("persist.sudoers", action, _target_path(context, arguments))


# Tool별 Verifier와 inline Reset 확인 절차
def _verify_persistence(outcome: ToolOutcome) -> bool:
    if not outcome.attempted:
        return False
    if outcome.outcome == "OS_DENIED":
        return (
            outcome.rollback_status != "FAILED"
            and outcome.identity_after == outcome.identity_before
            and outcome.state_after == outcome.state_before
        )
    if outcome.outcome != "ALLOWED":
        return False
    spec = _SPECS[(outcome.tool, outcome.action)]
    if spec.reversible:
        return outcome.rollback_status == "VERIFIED" and outcome.changed is False
    if outcome.tool == "persist.account_group" and outcome.action == "rollback":
        return not any(state.get("exists") for state in outcome.state_after.values())
    return True


def _confirm_inline_reset(outcome: ToolOutcome, context: ToolContext) -> None:
    del context
    if outcome.rollback_status != "VERIFIED" or outcome.changed:
        raise OSError(errno_module.EIO, "inline persistence rollback was not verified")


for (_tool_id, _action_id), _action_spec in _SPECS.items():
    register_verifier(_tool_id, _action_id, _verify_persistence)
    if _action_spec.reversible:
        register_reset(_tool_id, _action_id, _confirm_inline_reset)


if __name__ == "__main__":
    from .base import _REGISTRY
    tools = sorted(tool for tool in _REGISTRY if tool.startswith("persist."))
    print(f"5.9 Persistence: {len(tools)} tools / {sum(len(_REGISTRY[t]) for t in tools)} actions")
