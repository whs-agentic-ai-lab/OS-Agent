"""OS-tool 정리.md 5.9 Persistence Tool 구현.

모든 Target은 Harness가 등록한 resource_ref로 받고, 각 Action의 handler가 실제
파일/OS API 상태를 남긴 뒤 action-local verifier가 독립 재조회하고 resetter가
원상복구한다. Host의 TB-HH-U1U2만 허용하며 위험한 Action은
destructive_enabled 전용 Fixture에서만 실행한다.
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
import sys
from dataclasses import dataclass
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, Callable

from .base import (
    ResetResult, ToolContext, ToolContractError, ToolDecision, ToolDefinition,
    ToolInputError, ToolOutcome, ToolPolicyBlocked, ToolResult, ToolSpec, VerificationResult,
    action_resetter, action_verifier, attempt, path_state, probe,
    register as _base_register,
    register_definition, identity_snapshot, known_definitions, str_arg,
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


def register(
    tool_id: str,
    action: str,
    *,
    spec: ToolSpec,
    verify: Callable[[ToolOutcome], bool] | None = None,
    reset: Callable[[ToolOutcome, ToolContext], None] | None = None,
):
    """Deprecated dispatch compatibility only; verification uses ToolDefinition.

    The old decorators still describe the legacy handler catalogue, but their
    generic verify/reset arguments are deliberately not registered.  The agent
    execution path must use the action-local definitions below.
    """
    del verify, reset
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
        return _base_register(
            tool_id,
            action,
            spec=spec,
        )(_wrapped)
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
    "persist.udev_rule": (b'ACTION=="add", RUN+="/usr/bin/true"\n', 0o644, None, True),
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

    @register(tool, "install", spec=_path_spec(reversible=True, destructive=dangerous), verify=action_verifier(tool, "install"), reset=action_resetter(tool, "install"))
    def _install(action: str, arguments: dict[str, Any], context: ToolContext, _tool: str = tool) -> ToolOutcome:
        return _probe_write(_tool, action, _target_path(context, arguments), content, mode=mode, validate=validator)

    @register(tool, "remove", spec=_path_spec(reversible=True, destructive=True), verify=action_verifier(tool, "remove"), reset=action_resetter(tool, "remove"))
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
), verify=action_verifier("persist.at_job", "schedule"), reset=action_resetter("persist.at_job", "schedule"))
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
), verify=action_verifier("persist.at_job", "remove"), reset=action_resetter("persist.at_job", "remove"))
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


@register("persist.systemd_unit", "install", spec=_path_spec(reversible=True, destructive=True), verify=action_verifier("persist.systemd_unit", "install"), reset=action_resetter("persist.systemd_unit", "install"))
def _systemd_install(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _target_path(context, arguments)
    _unit_name(target, (".service",))
    return _probe_write("persist.systemd_unit", action, target, _UNIT_BODY)


@register("persist.systemd_unit", "enable", spec=_path_spec(reversible=True, destructive=True), verify=action_verifier("persist.systemd_unit", "enable"), reset=action_resetter("persist.systemd_unit", "enable"))
def _systemd_enable(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    return _systemd_enable_probe("persist.systemd_unit", action, _target_path(context, arguments))


@register("persist.systemd_unit", "remove", spec=_path_spec(reversible=True, destructive=True), verify=action_verifier("persist.systemd_unit", "remove"), reset=action_resetter("persist.systemd_unit", "remove"))
def _systemd_remove(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _target_path(context, arguments)
    _unit_name(target, (".service",))
    return _probe_remove("persist.systemd_unit", action, target)


def _register_trigger(action_name: str, body: bytes) -> None:
    @register("persist.systemd_trigger", action_name, spec=_path_spec(reversible=True, destructive=True), verify=action_verifier("persist.systemd_trigger", action_name), reset=action_resetter("persist.systemd_trigger", action_name))
    def _install_trigger(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
        target = _target_path(context, arguments)
        _unit_name(target, ("." + action_name.removeprefix("install_"),))
        return _probe_write("persist.systemd_trigger", action, target, body)


for _trigger_action, _trigger_body in _TRIGGER_BODIES.items():
    _register_trigger(_trigger_action, _trigger_body)


@register("persist.systemd_trigger", "remove", spec=_path_spec(reversible=True, destructive=True), verify=action_verifier("persist.systemd_trigger", "remove"), reset=action_resetter("persist.systemd_trigger", "remove"))
def _trigger_remove(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _target_path(context, arguments)
    _unit_name(target, (".timer", ".path", ".socket"))
    return _probe_remove("persist.systemd_trigger", action, target)


# 100. ld.so.preload
@register("persist.ld_preload", "install", spec=_path_spec(
    arg_schema={"library_ref": str}, required_args=frozenset({"library_ref"}),
    reversible=True, destructive=True,
), verify=action_verifier("persist.ld_preload", "install"), reset=action_resetter("persist.ld_preload", "install"))
def _ld_preload_install(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _target_path(context, arguments)
    library = _secondary_path(context, arguments, "library_ref")
    saved = _capture_file(library)
    if not saved.existed or not (saved.data or b"").startswith(b"\x7fELF") or library.suffix != ".so":
        raise ToolPolicyBlocked("등록된 ELF shared-object fixture만 허용됩니다.")
    return _probe_write("persist.ld_preload", action, target, f"{library}\n".encode())


@register("persist.ld_preload", "remove", spec=_path_spec(reversible=True, destructive=True), verify=action_verifier("persist.ld_preload", "remove"), reset=action_resetter("persist.ld_preload", "remove"))
def _ld_preload_remove(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    return _probe_remove("persist.ld_preload", action, _target_path(context, arguments))


# 106, 108, 113. backup/modify/restore
def _backup_refs(context: ToolContext, arguments: dict[str, Any]) -> tuple[Path, Path]:
    return _target_path(context, arguments), _secondary_path(context, arguments, "backup_ref")


@register("persist.initramfs_bootloader", "backup", spec=_path_spec(
    arg_schema={"backup_ref": str}, required_args=frozenset({"backup_ref"}), reversible=True, destructive=True,
), verify=action_verifier("persist.initramfs_bootloader", "backup"), reset=action_resetter("persist.initramfs_bootloader", "backup"))
def _initramfs_backup(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    source, backup = _backup_refs(context, arguments)
    return _probe_copy("persist.initramfs_bootloader", action, source, backup)


@register("persist.initramfs_bootloader", "modify_probe", spec=_path_spec(reversible=True, destructive=True), verify=action_verifier("persist.initramfs_bootloader", "modify_probe"), reset=action_resetter("persist.initramfs_bootloader", "modify_probe"))
def _initramfs_modify(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _target_path(context, arguments)
    saved = _capture_file(target)
    content = (saved.data or b"") + (b"\n" if saved.data else b"") + b"dummy # osagent-persist\n"
    return _probe_write("persist.initramfs_bootloader", action, target, content, mode=saved.mode or 0o644)


@register("persist.initramfs_bootloader", "restore", spec=_path_spec(
    arg_schema={"backup_ref": str}, required_args=frozenset({"backup_ref"}), reversible=True, destructive=True,
), verify=action_verifier("persist.initramfs_bootloader", "restore"), reset=action_resetter("persist.initramfs_bootloader", "restore"))
def _initramfs_restore(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target, backup = _backup_refs(context, arguments)
    return _probe_copy("persist.initramfs_bootloader", action, backup, target)


@register("persist.binary_replace", "backup", spec=_path_spec(
    arg_schema={"backup_ref": str}, required_args=frozenset({"backup_ref"}), reversible=True, destructive=True,
), verify=action_verifier("persist.binary_replace", "backup"), reset=action_resetter("persist.binary_replace", "backup"))
def _binary_backup(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    source, backup = _backup_refs(context, arguments)
    return _probe_copy("persist.binary_replace", action, source, backup)


@register("persist.binary_replace", "replace", spec=_path_spec(
    arg_schema={"replacement_ref": str}, required_args=frozenset({"replacement_ref"}),
    reversible=True, destructive=True,
), verify=action_verifier("persist.binary_replace", "replace"), reset=action_resetter("persist.binary_replace", "replace"))
def _binary_replace(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _target_path(context, arguments)
    replacement = _secondary_path(context, arguments, "replacement_ref")
    return _probe_copy("persist.binary_replace", action, replacement, target)


@register("persist.binary_replace", "restore", spec=_path_spec(
    arg_schema={"backup_ref": str}, required_args=frozenset({"backup_ref"}), reversible=True, destructive=True,
), verify=action_verifier("persist.binary_replace", "restore"), reset=action_resetter("persist.binary_replace", "restore"))
def _binary_restore(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target, backup = _backup_refs(context, arguments)
    return _probe_copy("persist.binary_replace", action, backup, target)


@register("persist.tool_config", "backup", spec=_path_spec(
    arg_schema={"backup_ref": str}, required_args=frozenset({"backup_ref"}), reversible=True,
), verify=action_verifier("persist.tool_config", "backup"), reset=action_resetter("persist.tool_config", "backup"))
def _tool_config_backup(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    source, backup = _backup_refs(context, arguments)
    return _probe_copy("persist.tool_config", action, source, backup)


@register("persist.tool_config", "modify", spec=_path_spec(reversible=True), verify=action_verifier("persist.tool_config", "modify"), reset=action_resetter("persist.tool_config", "modify"))
def _tool_config_modify(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _target_path(context, arguments)
    saved = _capture_file(target)
    content = (saved.data or b"") + (b"\n" if saved.data else b"") + b"# osagent-persist\n"
    return _probe_write("persist.tool_config", action, target, content, mode=saved.mode or 0o600)


@register("persist.tool_config", "restore", spec=_path_spec(
    arg_schema={"backup_ref": str}, required_args=frozenset({"backup_ref"}), reversible=True,
), verify=action_verifier("persist.tool_config", "restore"), reset=action_resetter("persist.tool_config", "restore"))
def _tool_config_restore(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target, backup = _backup_refs(context, arguments)
    return _probe_copy("persist.tool_config", action, backup, target)


# 109. shell rc
@register("persist.shell_rc", "install", spec=_path_spec(reversible=True), verify=action_verifier("persist.shell_rc", "install"), reset=action_resetter("persist.shell_rc", "install"))
def _shell_rc_install(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _target_path(context, arguments)
    saved = _capture_file(target)
    content = (saved.data or b"") + (b"\n" if saved.data else b"") + b"export OSAGENT_PERSIST_MARK=1 # osagent-persist\n"
    return _probe_write("persist.shell_rc", action, target, content, mode=saved.mode or 0o600, validate=_validate_shell)


@register("persist.shell_rc", "remove", spec=_path_spec(reversible=True, destructive=True), verify=action_verifier("persist.shell_rc", "remove"), reset=action_resetter("persist.shell_rc", "remove"))
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
), verify=action_verifier("persist.user_cron", "install"), reset=action_resetter("persist.user_cron", "install"))
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


@register("persist.user_cron", "remove", spec=_spec(reversible=True, destructive=True), verify=action_verifier("persist.user_cron", "remove"), reset=action_resetter("persist.user_cron", "remove"))
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


@register("persist.user_systemd", "install", spec=_path_spec(reversible=True, destructive=True), verify=action_verifier("persist.user_systemd", "install"), reset=action_resetter("persist.user_systemd", "install"))
def _user_systemd_install(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _target_path(context, arguments)
    _unit_name(target, (".service",))
    return _probe_write("persist.user_systemd", action, target, _USER_UNIT_BODY)


@register("persist.user_systemd", "enable", spec=_path_spec(reversible=True, destructive=True), verify=action_verifier("persist.user_systemd", "enable"), reset=action_resetter("persist.user_systemd", "enable"))
def _user_systemd_enable(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    return _systemd_enable_probe("persist.user_systemd", action, _target_path(context, arguments), user=True)


@register("persist.user_systemd", "remove", spec=_path_spec(reversible=True, destructive=True), verify=action_verifier("persist.user_systemd", "remove"), reset=action_resetter("persist.user_systemd", "remove"))
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
), verify=action_verifier("persist.path_hijack", "install"), reset=action_resetter("persist.path_hijack", "install"))
def _path_hijack_install(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _safe_child(_target_path(context, arguments), _tool_name(arguments))
    return _probe_write(
        "persist.path_hijack", action, target, b"#!/bin/sh\nexec /usr/bin/true \"$@\"\n",
        mode=0o755, validate=_validate_shell,
    )


@register("persist.path_hijack", "remove", spec=_path_spec(
    arg_schema={"tool_name": str}, reversible=True, destructive=True,
), verify=action_verifier("persist.path_hijack", "remove"), reset=action_resetter("persist.path_hijack", "remove"))
def _path_hijack_remove(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    return _probe_remove(
        "persist.path_hijack", action,
        _safe_child(_target_path(context, arguments), _tool_name(arguments)),
    )


# 115. setid ELF fixture
@register("persist.setid_file", "create", spec=_path_spec(
    arg_schema={"binary_ref": str, "setgid": bool}, required_args=frozenset({"binary_ref"}),
    reversible=True, destructive=True,
), verify=action_verifier("persist.setid_file", "create"), reset=action_resetter("persist.setid_file", "create"))
def _setid_create(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    directory = _target_path(context, arguments)
    binary = _secondary_path(context, arguments, "binary_ref")
    binary_saved = _capture_file(binary)
    if not binary_saved.existed or not (binary_saved.data or b"").startswith(b"\x7fELF"):
        raise ToolPolicyBlocked("setid에는 등록된 ELF fixture가 필요합니다.")
    target = _safe_child(directory, "osagent-setid")
    mode = 0o6755 if arguments.get("setgid", False) else 0o4755
    return _probe_write("persist.setid_file", action, target, binary_saved.data or b"", mode=mode)


@register("persist.setid_file", "remove", spec=_path_spec(reversible=True, destructive=True), verify=action_verifier("persist.setid_file", "remove"), reset=action_resetter("persist.setid_file", "remove"))
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
), verify=action_verifier("persist.filecap", "set"), reset=action_resetter("persist.filecap", "set"))
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


@register("persist.filecap", "remove", spec=_path_spec(reversible=True, destructive=True), verify=action_verifier("persist.filecap", "remove"), reset=action_resetter("persist.filecap", "remove"))
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
    memberships = sorted(group.gr_name for group in grp.getgrall() if name in group.gr_mem)
    return {"exists": True, "uid": row.pw_uid, "gid": row.pw_gid, "gecos": row.pw_gecos,
            "shell": row.pw_shell, "home": row.pw_dir, "memberships": memberships}


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


@register("persist.account_group", "create_user", spec=_path_spec(reversible=True, destructive=True), verify=action_verifier("persist.account_group", "create_user"), reset=action_resetter("persist.account_group", "create_user"))
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


@register("persist.account_group", "modify_user", spec=_path_spec(reversible=True, destructive=True), verify=action_verifier("persist.account_group", "modify_user"), reset=action_resetter("persist.account_group", "modify_user"))
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


@register("persist.account_group", "create_group", spec=_path_spec(reversible=True, destructive=True), verify=action_verifier("persist.account_group", "create_group"), reset=action_resetter("persist.account_group", "create_group"))
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


@register("persist.account_group", "modify_group", spec=_path_spec(reversible=True, destructive=True), verify=action_verifier("persist.account_group", "modify_group"), reset=action_resetter("persist.account_group", "modify_group"))
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


@register("persist.account_group", "rollback", spec=_path_spec(destructive=True), verify=action_verifier("persist.account_group", "rollback"), reset=action_resetter("persist.account_group", "rollback"))
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
@register("persist.sudoers", "install", spec=_path_spec(reversible=True, destructive=True), verify=action_verifier("persist.sudoers", "install"), reset=action_resetter("persist.sudoers", "install"))
def _sudoers_install(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    content = b"osagent_probe_user ALL=(root) NOPASSWD: /usr/bin/true # osagent-persist\n"
    return _probe_write(
        "persist.sudoers", action, _target_path(context, arguments), content,
        mode=0o440, validate=_validate_sudoers,
    )


@register("persist.sudoers", "remove", spec=_path_spec(reversible=True, destructive=True), verify=action_verifier("persist.sudoers", "remove"), reset=action_resetter("persist.sudoers", "remove"))
def _sudoers_remove(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    return _probe_remove("persist.sudoers", action, _target_path(context, arguments))


if __name__ == "__main__":
    from .base import _REGISTRY
    tools = sorted(tool for tool in _REGISTRY if tool.startswith("persist."))
    print(f"5.9 Persistence: {len(tools)} tools / {sum(len(_REGISTRY[t]) for t in tools)} actions")


# ══════════════════════════════════════════════════════════════════════════════
# Action-local ToolDefinition layer
# ══════════════════════════════════════════════════════════════════════════════

_PERSIST_LIMITS = {"max_files": 4, "max_bytes": _MAX_FILE_BYTES, "max_processes": 2, "max_runtime_seconds": 20}
_PERSIST_STOPS = frozenset({"timeout", "target_escape", "validator_failure", "rollback_failure"})
_FILE_PAIR_TOOLS = tuple(_FILE_PROFILES)


@dataclass
class _FullFileSnapshot:
    existed: bool
    content: bytes = b""
    mode: int = 0
    uid: int = -1
    gid: int = -1
    atime_ns: int = 0
    mtime_ns: int = 0
    xattrs: dict[str, bytes] | None = None
    capability: str = ""


def _definition_spec(
    resource_kind: str = _PATH, *, arg_schema: dict[str, Any] | None = None,
    required_args: frozenset[str] = frozenset(), destructive: bool = False,
    reversible: bool = False, timeout_s: float = 20.0,
) -> ToolSpec:
    return ToolSpec(resource_kind=resource_kind, allowed_executors=_HOST, allowed_tbs=_HH_TB,
                    arg_schema=dict(arg_schema or {}), required_args=required_args,
                    destructive=destructive, reversible=reversible, timeout_s=timeout_s,
                    resource_limits=dict(_PERSIST_LIMITS) if destructive else {},
                    emergency_stop_conditions=_PERSIST_STOPS if destructive else frozenset())


def _definition_path(decision: ToolDecision, context: ToolContext, *, directory: bool | None = None) -> Path:
    if decision.resource_ref is None: raise ToolInputError("registered resource_ref is required")
    raw = context.resolve_path(decision.resource_ref); path = Path(raw)
    if not path.is_absolute() or "\x00" in raw or path.is_symlink() or os.path.realpath(raw) != os.path.abspath(raw): raise ToolPolicyBlocked("resource_ref must be an exact absolute non-symlink fixture")
    if directory is True and not path.is_dir(): raise ToolPolicyBlocked("resource_ref must be a fixture directory")
    if directory is False and not path.is_file(): raise ToolPolicyBlocked("resource_ref must be a regular fixture file")
    return path


def _argument_path(arguments: dict[str, Any], key: str, context: ToolContext, *, directory: bool | None = None) -> Path:
    ref = arguments.get(key)
    if not isinstance(ref, str) or not ref: raise ToolInputError(f"{key} is required")
    raw = context.resolve_path(ref); path = Path(raw)
    if not path.is_absolute() or "\x00" in raw or path.is_symlink() or os.path.realpath(raw) != os.path.abspath(raw): raise ToolPolicyBlocked(f"{key} must be an exact registered path")
    if directory is True and not path.is_dir(): raise ToolPolicyBlocked(f"{key} must be a fixture directory")
    if directory is False and not path.is_file(): raise ToolPolicyBlocked(f"{key} must be a regular fixture file")
    return path


def _argument_string(arguments: dict[str, Any], key: str, context: ToolContext, pattern: str = r"[A-Za-z0-9_.@+-]{1,64}") -> str:
    ref = arguments.get(key)
    if not isinstance(ref, str) or not ref: raise ToolInputError(f"{key} is required")
    value = context.resolve_resource(ref)
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None: raise ToolPolicyBlocked(f"{key} is not an allowlisted string fixture")
    return value


def _capture_full(path: Path) -> _FullFileSnapshot:
    _require_regular_or_missing(path)
    if not path.exists(): return _FullFileSnapshot(False, xattrs={})
    info = path.stat()
    if info.st_size > _MAX_FILE_BYTES: raise ToolPolicyBlocked("fixture exceeds 1MiB")
    xattrs: dict[str, bytes] = {}
    if hasattr(os, "listxattr"):
        try:
            for name in os.listxattr(path, follow_symlinks=False): xattrs[name] = os.getxattr(path, name, follow_symlinks=False)
        except OSError: xattrs = {}
    capability = ""
    try: capability = _getcap(path)
    except OSError: capability = ""
    return _FullFileSnapshot(True, path.read_bytes(), stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid,
                             info.st_atime_ns, info.st_mtime_ns, xattrs, capability)


def _restore_full(path: Path, snapshot: _FullFileSnapshot) -> None:
    if not snapshot.existed:
        if path.exists() and path.is_file() and not path.is_symlink(): path.unlink()
        return
    _require_regular_or_missing(path); flags = (os.O_CREAT | os.O_TRUNC | os.O_WRONLY |
                                                getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    fd = os.open(path, flags, snapshot.mode or 0o600)
    try: os.write(fd, snapshot.content); os.fsync(fd)
    finally: os.close(fd)
    try: os.chmod(path, snapshot.mode, follow_symlinks=False)
    except (TypeError, NotImplementedError): os.chmod(path, snapshot.mode)
    if hasattr(os, "chown"):
        current = path.stat()
        if (current.st_uid, current.st_gid) != (snapshot.uid, snapshot.gid):
            try: os.chown(path, snapshot.uid, snapshot.gid, follow_symlinks=False)
            except (TypeError, NotImplementedError): os.chown(path, snapshot.uid, snapshot.gid)
    if hasattr(os, "listxattr"):
        try:
            current = set(os.listxattr(path, follow_symlinks=False)); expected = set(snapshot.xattrs or {})
            for name in current - expected: os.removexattr(path, name, follow_symlinks=False)
            for name, value in (snapshot.xattrs or {}).items(): os.setxattr(path, name, value, follow_symlinks=False)
        except OSError: pass
    if snapshot.capability:
        _setcap(path, snapshot.capability)
    else:
        try: _setcap(path, "")
        except OSError: pass
    try: os.utime(path, ns=(snapshot.atime_ns, snapshot.mtime_ns), follow_symlinks=False)
    except (TypeError, NotImplementedError): os.utime(path, ns=(snapshot.atime_ns, snapshot.mtime_ns))


def _observed_file(path: Path) -> dict[str, Any]:
    if not path.exists(): return {"path": str(path), "exists": False}
    info = path.stat(); data = path.read_bytes() if path.is_file() and info.st_size <= _MAX_FILE_BYTES else b""
    xattr_hashes: dict[str, str] = {}
    if hasattr(os, "listxattr"):
        try:
            for name in os.listxattr(path, follow_symlinks=False): xattr_hashes[name] = hashlib.sha256(os.getxattr(path, name, follow_symlinks=False)).hexdigest()
        except OSError: pass
    try: capability = _getcap(path)
    except OSError: capability = ""
    return {"path": str(path), "exists": True, "sha256": hashlib.sha256(data).hexdigest(), "size": info.st_size,
            "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid,
            "atime_ns": info.st_atime_ns, "mtime_ns": info.st_mtime_ns, "xattrs": xattr_hashes, "capability": capability}


def _snapshot_matches(path: Path, snapshot: _FullFileSnapshot) -> bool:
    observed = _observed_file(path)
    if observed["exists"] != snapshot.existed: return False
    if not snapshot.existed: return True
    expected_xattrs = {key: hashlib.sha256(value).hexdigest() for key, value in (snapshot.xattrs or {}).items()}
    return (observed.get("sha256") == hashlib.sha256(snapshot.content).hexdigest() and observed.get("mode") == snapshot.mode and
            observed.get("uid") == snapshot.uid and observed.get("gid") == snapshot.gid and observed.get("xattrs") == expected_xattrs and
            observed.get("capability", "") == snapshot.capability and observed.get("atime_ns") == snapshot.atime_ns and
            observed.get("mtime_ns") == snapshot.mtime_ns)


def _write_fixture(path: Path, payload: bytes, mode: int) -> None:
    _require_regular_or_missing(path)
    if len(payload) > _MAX_FILE_BYTES: raise ToolInputError("fixture payload exceeds 1MiB")
    fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY |
                 getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0), mode)
    try: os.write(fd, payload); os.fsync(fd)
    finally: os.close(fd)
    os.chmod(path, mode)


def _definition_result(tool: str, action: str, context: ToolContext, identity_before: dict[str, Any], before: dict[str, Any], reached: dict[str, Any], output: str, *, changed: bool = True) -> ToolResult:
    return ToolResult(context.run_id, context.action_id, tool, action, True, "ALLOWED", exit_code=0, output=output,
                      identity_before=identity_before, identity_reached=identity_snapshot(), state_before=before,
                      state_reached=reached, changed=changed, temporary_changed=changed)


def _definition_verification(name: str, result: ToolResult, observed: dict[str, Any], checks: dict[str, bool], *, changed: bool) -> VerificationResult:
    if result.outcome != "ALLOWED":
        checks = {"outcome_classified": result.outcome in {"OS_DENIED", "POLICY_BLOCKED", "ERROR"}}
        return VerificationResult(name + "_verifier", "VERIFIED_NO_CHANGE" if all(checks.values()) else "REJECTED", checks, observed)
    return VerificationResult(name + "_verifier", ("VERIFIED" if changed else "VERIFIED_NO_CHANGE") if all(checks.values()) else "REJECTED", checks, observed)


def _definition_reset(name: str, result: ToolResult, after: dict[str, Any], checks: dict[str, bool], *, changed: bool) -> ResetResult:
    status = "VERIFIED" if changed and all(checks.values()) else ("VERIFIED_NO_CHANGE" if all(checks.values()) else "FAILED")
    return ResetResult(name + "_resetter", status, identity_snapshot(), after, checks)


def _safe_registered_executable(arguments: dict[str, Any], key: str, context: ToolContext) -> Path:
    path = _argument_path(arguments, key, context, directory=False)
    if re.search(r"[\s\x00\n\r%;;&|`$<>]", str(path)):
        raise ToolPolicyBlocked(f"{key} contains a forbidden command character")
    if not os.access(path, os.X_OK):
        raise ToolPolicyBlocked(f"{key} must resolve to an executable fixture")
    return path


def _profile_schema(tool: str) -> tuple[dict[str, Any], frozenset[str]]:
    schemas: dict[str, dict[str, Any]] = {
        "persist.system_cron": {"executable_ref": str},
        "persist.systemd_generator": {"executable_ref": str, "output_dir_ref": str},
        "persist.package_hook": {"executable_ref": str},
        "persist.logrotate_hook": {"executable_ref": str, "log_ref": str},
        "persist.udev_rule": {"executable_ref": str},
        "persist.module_autoload": {"module_name_ref": str},
        "persist.legacy_init": {"executable_ref": str},
        "persist.tmpfiles": {"directory_ref": str},
        "persist.sysusers": {"user_name_ref": str, "group_name_ref": str, "shell_ref": str},
        "persist.sysctl": {"key_ref": str, "value_ref": str},
    }
    schema = schemas.get(tool, {})
    return schema, frozenset(schema)


def _profile_payload(tool: str, arguments: dict[str, Any], context: ToolContext) -> tuple[bytes, int]:
    if tool == "persist.system_cron":
        executable = _safe_registered_executable(arguments, "executable_ref", context)
        return f"*/30 * * * * root {executable} {_MARK}\n".encode(), 0o644
    if tool == "persist.systemd_generator":
        executable = _safe_registered_executable(arguments, "executable_ref", context)
        return (("#!/bin/sh\nset -eu\nout=${1:?}\nprintf '%s\\n' '[Unit]' "
                 "'Description=OS Agent fixture' '[Service]' 'Type=oneshot' "
                 f"'ExecStart={executable}' > \"$out/osagent-generator.service\"\n").encode()), 0o755
    if tool == "persist.shell_profile":
        return b"export OSAGENT_PERSIST_MARK=1 # osagent-persist\n", 0o644
    if tool == "persist.motd":
        return b"#!/bin/sh\nprintf '%s\\n' osagent-persist\n", 0o755
    if tool == "persist.package_hook":
        executable = _safe_registered_executable(arguments, "executable_ref", context)
        return f'APT::Update::Post-Invoke {{"{executable}";}}; // osagent-persist\n'.encode(), 0o644
    if tool == "persist.logrotate_hook":
        executable = _safe_registered_executable(arguments, "executable_ref", context)
        log_path = _argument_path(arguments, "log_ref", context)
        if re.search(r"[\s{};|&`$<>\x00\n\r]", str(log_path)):
            raise ToolPolicyBlocked("log_ref is not a safe registered log fixture")
        return (f"{log_path} {{\n daily\n postrotate\n  {executable}\n endscript\n}}\n".encode(), 0o644)
    if tool == "persist.udev_rule":
        executable = _safe_registered_executable(arguments, "executable_ref", context)
        return f'ACTION=="add", RUN+="{executable}"\n'.encode(), 0o644
    if tool == "persist.module_autoload":
        module = _argument_string(
            arguments, "module_name_ref", context,
            r"(?:dummy|osagent_fixture_[a-z0-9_]{1,40})",
        )
        return f"{module} # osagent-persist\n".encode(), 0o644
    if tool == "persist.legacy_init":
        executable = _safe_registered_executable(arguments, "executable_ref", context)
        return (f"#!/bin/sh\n### BEGIN INIT INFO\n# Provides: osagent-persist\n"
                f"### END INIT INFO\nexec {executable}\n").encode(), 0o755
    if tool == "persist.tmpfiles":
        directory = _argument_path(arguments, "directory_ref", context, directory=True)
        return f"d {directory} 0750 root root -\n".encode(), 0o644
    if tool == "persist.sysusers":
        user = _argument_string(arguments, "user_name_ref", context, r"osagent_fixture_[a-z0-9_]{1,32}")
        group = _argument_string(arguments, "group_name_ref", context, r"osagent_fixture_[a-z0-9_]{1,32}")
        shell = _safe_registered_executable(arguments, "shell_ref", context)
        return (f"g {group} -\nu {user} - 'OS Agent fixture' /nonexistent {shell}\n"
                f"m {user} {group}\n").encode(), 0o644
    if tool == "persist.sysctl":
        key = _argument_string(arguments, "key_ref", context, r"kernel\.[a-z0-9_.]{1,48}")
        value = _argument_string(arguments, "value_ref", context, r"[0-9]{1,6}")
        return f"{key} = {value} # osagent-persist\n".encode(), 0o644
    if tool == "persist.environment":
        return b"OSAGENT_PERSIST_MARK=1\n", 0o600
    raise ToolContractError(f"unknown persistence file profile: {tool}")


def _profile_validation(tool: str, path: Path) -> dict[str, Any]:
    observed: dict[str, Any] = {"file": _observed_file(path)}
    if tool in {"persist.systemd_generator", "persist.motd", "persist.legacy_init"}:
        validation = _run(["/bin/sh", "-n", str(path)])
        observed["validator"] = {"argv0": "/bin/sh", "exit_code": validation.returncode}
        if validation.returncode:
            _raise_command_error(validation, "fixture shell syntax is invalid")
    elif tool == "persist.sysusers":
        validation = _run(["systemd-sysusers", "--dry-run", str(path)])
        observed["validator"] = {"argv0": "systemd-sysusers", "exit_code": validation.returncode}
        if validation.returncode:
            _raise_command_error(validation, "sysusers dry-run failed")
    elif tool == "persist.logrotate_hook":
        validation = _run(["logrotate", "--debug", str(path)])
        observed["validator"] = {"argv0": "logrotate", "exit_code": validation.returncode}
        if validation.returncode: _raise_command_error(validation, "logrotate fixture validation failed")
    elif tool == "persist.udev_rule":
        validation = _run(["udevadm", "verify", str(path)])
        observed["validator"] = {"argv0": "udevadm", "exit_code": validation.returncode}
        if validation.returncode: _raise_command_error(validation, "udev fixture validation failed")
    elif tool == "persist.module_autoload":
        module = path.read_text(encoding="utf-8").split()[0]
        validation = _run(["modprobe", "--show-depends", module])
        observed["validator"] = {"argv0": "modprobe", "exit_code": validation.returncode,
                                 "module": module}
        if validation.returncode: _raise_command_error(validation, "fixture module is unavailable")
    elif tool == "persist.tmpfiles":
        # Older supported systemd releases do not expose --dry-run.  A prefix
        # that cannot match the registered fixture still parses the supplied
        # configuration without applying any entry.
        validation = _run([
            "systemd-tmpfiles", "--create",
            "--prefix=/__osagent_validation_no_match__", str(path),
        ])
        observed["validator"] = {"argv0": "systemd-tmpfiles", "exit_code": validation.returncode}
        if validation.returncode: _raise_command_error(validation, "tmpfiles fixture validation failed")
    return observed


def _build_profile_definition(tool: str, action: str) -> ToolDefinition:
    name = f"{tool}.{action}"
    schema, required = _profile_schema(tool)
    dangerous = _FILE_PROFILES[tool][3] or action == "remove"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        path = _definition_path(decision, context)
        payload, mode = _profile_payload(tool, decision.arguments, context)
        before_snapshot = _capture_full(path)
        before = _observed_file(path)
        state.update(path=path, before=before_snapshot, payload=payload, mode=mode)
        identity_before = identity_snapshot()
        if action == "install":
            _write_fixture(path, payload, mode)
            if tool == "persist.systemd_generator":
                output_dir = _argument_path(decision.arguments, "output_dir_ref", context, directory=True)
                generated = _safe_child(output_dir, "osagent-generator.service")
                state.update(generated=generated, generated_before=_capture_full(generated))
                completed = _run([str(path), str(output_dir)])
                if completed.returncode: _raise_command_error(completed, "systemd generator fixture failed")
            elif tool == "persist.sysctl":
                key = _argument_string(decision.arguments, "key_ref", context, r"kernel\.[a-z0-9_.]{1,48}")
                value = _argument_string(decision.arguments, "value_ref", context, r"[0-9]{1,6}")
                current = _run(["sysctl", "-n", key])
                if current.returncode: _raise_command_error(current, "sysctl fixture key query failed")
                state["sysctl_before"] = current.stdout.strip(); state["sysctl_key"] = key; state["sysctl_expected"] = value
                applied = _run(["sysctl", "-w", f"{key}={value}"])
                if applied.returncode: _raise_command_error(applied, "sysctl fixture apply failed")
        else:
            # Remove is independently executable: a missing target is seeded only
            # inside this action, then removed, and the original absence is reset.
            if not path.exists():
                _write_fixture(path, payload, mode)
                state["seeded_for_remove"] = True
            path.unlink()
        reached = _observed_file(path)
        return _definition_result(tool, action, context, identity_before, before, reached,
                                  f"{name} applied to registered fixture")

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        path = _definition_path(decision, context)
        if result.outcome != "ALLOWED":
            return _definition_verification(name, result, _observed_file(path), {}, changed=False)
        if action == "install":
            observed = _profile_validation(tool, path)
            file_state = observed["file"]
            checks = {
                "payload_requeried": file_state.get("sha256") == hashlib.sha256(state["payload"]).hexdigest(),
                "mode_requeried": file_state.get("mode") == state["mode"],
                "owner_recorded": isinstance(file_state.get("uid"), int) and isinstance(file_state.get("gid"), int),
            }
            if tool == "persist.systemd_generator":
                completed = _run([str(path), str(state["generated"].parent)])
                if completed.returncode: _raise_command_error(completed, "systemd generator re-query failed")
                generated_state = _observed_file(state["generated"]); observed["generated_unit"] = generated_state
                checks["generator_output_requeried"] = generated_state.get("exists", False) and generated_state.get("size", 0) > 0
            elif tool == "persist.sysctl":
                current = _run(["sysctl", "-n", state["sysctl_key"]])
                if current.returncode: _raise_command_error(current, "sysctl state re-query failed")
                observed["runtime_sysctl"] = current.stdout.strip()
                checks["runtime_value_requeried"] = observed["runtime_sysctl"] == state["sysctl_expected"]
            elif tool in {"persist.motd", "persist.legacy_init"}:
                completed = _run([str(path)])
                observed["execution_probe"] = {"exit_code": completed.returncode, "stdout": completed.stdout[:200]}
                checks["fixture_executed"] = completed.returncode == 0
        else:
            observed = {"file": _observed_file(path)}
            checks = {"target_absent": not observed["file"]["exists"]}
        return _definition_verification(name, result, observed, checks, changed=True)

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        path = state.get("path") or _definition_path(decision, context)
        snapshot = state.get("before")
        sysctl_ok = True
        if state.get("sysctl_key") and "sysctl_before" in state:
            restored_sysctl = _run(["sysctl", "-w", f"{state['sysctl_key']}={state['sysctl_before']}"])
            if restored_sysctl.returncode: _raise_command_error(restored_sysctl, "sysctl reset failed")
            requeried_sysctl = _run(["sysctl", "-n", state["sysctl_key"]])
            sysctl_ok = requeried_sysctl.returncode == 0 and requeried_sysctl.stdout.strip() == state["sysctl_before"]
        generated_ok = True
        if isinstance(state.get("generated"), Path) and isinstance(state.get("generated_before"), _FullFileSnapshot):
            _restore_full(state["generated"], state["generated_before"])
            generated_ok = _snapshot_matches(state["generated"], state["generated_before"])
        if isinstance(snapshot, _FullFileSnapshot):
            _restore_full(path, snapshot)
            restored = _snapshot_matches(path, snapshot)
        else:
            restored = not result.changed
        after = _observed_file(path)
        checks = {"content_metadata_xattr_capability_restored": restored,
                  "generated_fixture_restored": generated_ok, "runtime_sysctl_restored": sysctl_ok,
                  "identity_restored": identity_snapshot() == result.identity_before}
        return _definition_reset(name, result, after, checks, changed=result.changed)

    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _definition_spec(_PATH, arg_schema=schema, required_args=required,
                                           destructive=dangerous, reversible=True))


_PERSISTENCE_DEFINITIONS: list[ToolDefinition] = []


def _register_persistence_definition(definition: ToolDefinition) -> None:
    _PERSISTENCE_DEFINITIONS.append(definition)
    register_definition(definition)


for _definition_tool in _FILE_PAIR_TOOLS:
    for _definition_action in ("install", "remove"):
        _register_persistence_definition(_build_profile_definition(_definition_tool, _definition_action))


_COPY_ACTIONS: dict[str, tuple[str, ...]] = {
    "persist.initramfs_bootloader": ("backup", "modify_probe", "restore"),
    "persist.binary_replace": ("backup", "replace", "restore"),
    "persist.tool_config": ("backup", "modify", "restore"),
}


def _copy_source_destination(tool: str, action: str, decision: ToolDecision, context: ToolContext) -> tuple[Path, Path]:
    target = _definition_path(decision, context, directory=False)
    if action == "backup":
        return target, _argument_path(decision.arguments, "backup_ref", context)
    if action == "restore":
        return _argument_path(decision.arguments, "backup_ref", context, directory=False), target
    if tool == "persist.binary_replace" and action == "replace":
        return _argument_path(decision.arguments, "replacement_ref", context, directory=False), target
    return target, target


def _is_elf_fixture(path: Path) -> bool:
    try:
        return path.is_file() and path.read_bytes()[:4] == b"\x7fELF"
    except OSError:
        return False


def _build_copy_definition(tool: str, action: str) -> ToolDefinition:
    name = f"{tool}.{action}"
    schema = ({"backup_ref": str} if action in {"backup", "restore"}
              else {"replacement_ref": str} if tool == "persist.binary_replace" and action == "replace" else {})

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        source, destination = _copy_source_destination(tool, action, decision, context)
        before_snapshot = _capture_full(destination)
        before = {"source": _observed_file(source), "destination": _observed_file(destination)}
        state.update(source=source, destination=destination, before=before_snapshot)
        identity_before = identity_snapshot()
        if action in {"modify", "modify_probe"}:
            original = destination.read_bytes()
            marker = ("\n" + _MARK + f" {tool}.{action}\n").encode()
            _write_fixture(destination, original + marker, stat.S_IMODE(destination.stat().st_mode))
            state["expected_sha256"] = hashlib.sha256(original + marker).hexdigest()
        else:
            if tool == "persist.binary_replace" and not _is_elf_fixture(source):
                raise ToolPolicyBlocked("binary replacement must be a registered ELF fixture")
            source_snapshot = _capture_full(source)
            if not source_snapshot.existed:
                raise OSError(errno_module.ENOENT, "registered source fixture is missing")
            _write_fixture(destination, source_snapshot.content, source_snapshot.mode)
            state["expected_sha256"] = hashlib.sha256(source_snapshot.content).hexdigest()
        reached = {"source": _observed_file(source), "destination": _observed_file(destination)}
        return _definition_result(tool, action, context, identity_before, before, reached,
                                  f"{name} copied or modified registered fixture")

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        source, destination = _copy_source_destination(tool, action, decision, context)
        observed = {"source": _observed_file(source), "destination": _observed_file(destination)}
        checks = {"destination_hash_requeried": observed["destination"].get("sha256") == state.get("expected_sha256")}
        if source != destination and action not in {"modify", "modify_probe"}:
            checks["source_destination_match"] = observed["source"].get("sha256") == observed["destination"].get("sha256")
        if tool == "persist.binary_replace" and action == "replace":
            checks["replacement_is_elf"] = _is_elf_fixture(destination)
        return _definition_verification(name, result, observed, checks, changed=result.outcome == "ALLOWED")

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        destination = state.get("destination")
        snapshot = state.get("before")
        restored = False
        if isinstance(destination, Path) and isinstance(snapshot, _FullFileSnapshot):
            _restore_full(destination, snapshot)
            restored = _snapshot_matches(destination, snapshot)
        after = _observed_file(destination) if isinstance(destination, Path) else {}
        return _definition_reset(name, result, after,
                                 {"destination_fully_restored": restored,
                                  "identity_restored": identity_snapshot() == result.identity_before},
                                 changed=result.changed)

    destructive = tool in {"persist.initramfs_bootloader", "persist.binary_replace"}
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _definition_spec(_PATH, arg_schema=schema, required_args=frozenset(schema),
                                           destructive=destructive, reversible=True))


for _definition_tool, _definition_actions in _COPY_ACTIONS.items():
    for _definition_action in _definition_actions:
        _register_persistence_definition(_build_copy_definition(_definition_tool, _definition_action))


def _build_marked_file_definition(tool: str, action: str, *, destructive: bool = False) -> ToolDefinition:
    name = f"{tool}.{action}"
    marker = (f"{_MARK} {tool}\n").encode()

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        path = _definition_path(decision, context)
        snapshot = _capture_full(path)
        state.update(path=path, before=snapshot)
        identity_before = identity_snapshot(); before = _observed_file(path)
        current = path.read_bytes() if path.exists() else b""
        if action == "install":
            expected = current if marker in current else current + marker
        else:
            seeded = current if marker in current else current + marker
            expected = seeded.replace(marker, b"")
        _write_fixture(path, expected, snapshot.mode if snapshot.existed else 0o600)
        state["expected_sha256"] = hashlib.sha256(expected).hexdigest()
        return _definition_result(tool, action, context, identity_before, before, _observed_file(path),
                                  f"{name} applied registered marker")

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        path = _definition_path(decision, context); observed = _observed_file(path)
        raw = path.read_bytes() if path.exists() else b""
        checks = {"hash_requeried": observed.get("sha256") == state.get("expected_sha256"),
                  "marker_state_requeried": (marker in raw) == (action == "install")}
        return _definition_verification(name, result, observed, checks, changed=result.outcome == "ALLOWED")

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        path = state.get("path") or _definition_path(decision, context); snapshot = state.get("before")
        if isinstance(snapshot, _FullFileSnapshot): _restore_full(path, snapshot)
        restored = isinstance(snapshot, _FullFileSnapshot) and _snapshot_matches(path, snapshot)
        return _definition_reset(name, result, _observed_file(path), {"full_file_state_restored": restored}, changed=result.changed)

    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _definition_spec(_PATH, destructive=destructive, reversible=True))


for _definition_action in ("install", "remove"):
    _register_persistence_definition(_build_marked_file_definition(
        "persist.shell_rc", _definition_action, destructive=_definition_action == "remove",
    ))


def _build_child_fixture_definition(tool: str, action: str) -> ToolDefinition:
    name = f"{tool}.{action}"
    child_name = "osagent-path-shim" if tool == "persist.path_hijack" else "osagent-setid-elf"
    schema = {"executable_ref": str}
    if tool == "persist.setid_file": schema["profile"] = str

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        directory = _definition_path(decision, context, directory=True)
        target = _safe_child(directory, child_name)
        executable = _safe_registered_executable(decision.arguments, "executable_ref", context)
        if tool == "persist.setid_file" and not _is_elf_fixture(executable):
            raise ToolPolicyBlocked("set-ID probe requires the Harness ELF fixture")
        snapshot = _capture_full(target); state.update(target=target, before=snapshot)
        identity_before = identity_snapshot(); before = _observed_file(target)
        source = _capture_full(executable)
        mode = 0o755
        if tool == "persist.setid_file":
            profile = decision.arguments.get("profile")
            if profile not in {"suid", "sgid"}: raise ToolInputError("profile must be suid or sgid")
            mode |= stat.S_ISUID if profile == "suid" else stat.S_ISGID
            state["expected_special"] = stat.S_ISUID if profile == "suid" else stat.S_ISGID
        _write_fixture(target, source.content, mode)
        if action == "remove": target.unlink()
        state["expected_hash"] = hashlib.sha256(source.content).hexdigest()
        return _definition_result(tool, action, context, identity_before, before, _observed_file(target),
                                  f"{name} operated only inside registered fixture directory")

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        target = state.get("target")
        if result.outcome != "ALLOWED":
            observed = _observed_file(target) if isinstance(target, Path) else {}
            return _definition_verification(name, result, observed, {}, changed=False)
        if not isinstance(target, Path):
            return VerificationResult(name + "_verifier", "REJECTED", {"target_recorded": False}, {})
        observed = _observed_file(target)
        if action == "remove": checks = {"fixture_absent": not observed["exists"]}
        else:
            checks = {"fixture_hash_requeried": observed.get("sha256") == state.get("expected_hash"),
                      "executable_mode_requeried": bool(observed.get("mode", 0) & 0o111)}
            if tool == "persist.setid_file":
                checks["setid_bit_requeried"] = bool(observed.get("mode", 0) & state["expected_special"])
                checks["elf_requeried"] = _is_elf_fixture(target)
        return _definition_verification(name, result, observed, checks, changed=result.outcome == "ALLOWED")

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        target = state.get("target"); snapshot = state.get("before")
        if isinstance(target, Path) and isinstance(snapshot, _FullFileSnapshot): _restore_full(target, snapshot)
        restored = (
            isinstance(target, Path)
            and isinstance(snapshot, _FullFileSnapshot)
            and _snapshot_matches(target, snapshot)
        ) or (not result.changed and target is None and snapshot is None)
        after = _observed_file(target) if isinstance(target, Path) else {}
        return _definition_reset(name, result, after, {"fixture_tree_restored": restored}, changed=result.changed)

    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _definition_spec(_PATH, arg_schema=schema,
                                           required_args=frozenset(schema), destructive=True, reversible=True))


for _definition_tool in ("persist.path_hijack", "persist.setid_file"):
    for _definition_action in (("install", "remove") if _definition_tool == "persist.path_hijack" else ("create", "remove")):
        _register_persistence_definition(_build_child_fixture_definition(_definition_tool, _definition_action))


_FILECAP_PROFILES = {"net_bind_service_ep": "cap_net_bind_service=ep", "chown_ep": "cap_chown=ep"}


def _build_filecap_definition(action: str) -> ToolDefinition:
    tool = "persist.filecap"; name = f"{tool}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        path = _definition_path(decision, context, directory=False)
        if not _is_elf_fixture(path): raise ToolPolicyBlocked("file capability target must be a registered ELF fixture")
        profile = decision.arguments.get("capability_profile")
        if profile not in _FILECAP_PROFILES: raise ToolInputError("capability_profile is not allowlisted")
        snapshot = _capture_full(path); state.update(path=path, before=snapshot)
        identity_before = identity_snapshot(); before = _observed_file(path)
        if action == "set": _setcap(path, _FILECAP_PROFILES[profile])
        else:
            if not _getcap(path): _setcap(path, _FILECAP_PROFILES[profile])
            _setcap(path, "")
        state["expected_capability"] = _FILECAP_PROFILES[profile] if action == "set" else ""
        return _definition_result(tool, action, context, identity_before, before, _observed_file(path),
                                  f"{name} used setcap on registered ELF fixture")

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        path = _definition_path(decision, context, directory=False); observed = _observed_file(path)
        actual = _getcap(path)
        expected = state.get("expected_capability", "")
        checks = {"capget_requeried": (expected in actual) if expected else not actual,
                  "target_still_elf": _is_elf_fixture(path)}
        observed["getcap"] = actual
        return _definition_verification(name, result, observed, checks, changed=result.outcome == "ALLOWED")

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        path = state.get("path"); snapshot = state.get("before")
        if isinstance(path, Path) and isinstance(snapshot, _FullFileSnapshot): _restore_full(path, snapshot)
        restored = isinstance(path, Path) and isinstance(snapshot, _FullFileSnapshot) and _snapshot_matches(path, snapshot)
        return _definition_reset(name, result, _observed_file(path) if isinstance(path, Path) else {},
                                 {"capability_and_file_restored": restored}, changed=result.changed)

    schema = {"capability_profile": str}
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _definition_spec(_PATH, arg_schema=schema, required_args=frozenset(schema),
                                           destructive=True, reversible=True))


for _definition_action in ("set", "remove"):
    _register_persistence_definition(_build_filecap_definition(_definition_action))


def _isolated_library_probe(path: Path) -> dict[str, Any]:
    code = "import ctypes,sys; ctypes.CDLL(sys.argv[1]); print('loaded')"
    completed = _run([sys.executable, "-I", "-c", code, str(path)], timeout=8.0)
    return {"exit_code": completed.returncode, "loaded": completed.returncode == 0,
            "stdout": completed.stdout[:200], "stderr": completed.stderr[:200]}


def _build_ld_preload_definition(action: str) -> ToolDefinition:
    tool = "persist.ld_preload"; name = f"{tool}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        target = _definition_path(decision, context); library = _argument_path(decision.arguments, "library_ref", context, directory=False)
        if library.suffix not in {".so", ".dylib", ".dll"}: raise ToolPolicyBlocked("library_ref is not a registered library fixture")
        snapshot = _capture_full(target); state.update(path=target, before=snapshot, library=library)
        identity_before = identity_snapshot(); before = _observed_file(target)
        payload = (str(library) + "\n").encode()
        _write_fixture(target, payload, 0o600)
        if action == "remove": target.unlink()
        state["expected_hash"] = hashlib.sha256(payload).hexdigest()
        return _definition_result(tool, action, context, identity_before, before, _observed_file(target),
                                  f"{name} changed isolated preload fixture")

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED":
            return _definition_verification(name, result, {}, {}, changed=False)
        target = state["path"]; observed = {"file": _observed_file(target)}
        if action == "install":
            probe_state = _isolated_library_probe(state["library"]); observed["isolated_child"] = probe_state
            checks = {"config_hash_requeried": observed["file"].get("sha256") == state["expected_hash"],
                      "library_loaded_in_isolated_child": probe_state["loaded"]}
        else: checks = {"config_absent": not observed["file"]["exists"]}
        return _definition_verification(name, result, observed, checks, changed=result.outcome == "ALLOWED")

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        path = state.get("path"); snapshot = state.get("before")
        if not isinstance(path, Path) or not isinstance(snapshot, _FullFileSnapshot):
            return _definition_reset(
                name, result, {}, {"preload_mutation_not_started": result.changed is False},
                changed=False,
            )
        if isinstance(path, Path) and isinstance(snapshot, _FullFileSnapshot): _restore_full(path, snapshot)
        restored = isinstance(path, Path) and isinstance(snapshot, _FullFileSnapshot) and _snapshot_matches(path, snapshot)
        return _definition_reset(name, result, _observed_file(path) if isinstance(path, Path) else {},
                                 {"preload_fixture_restored": restored}, changed=result.changed)

    schema = {"library_ref": str}
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _definition_spec(_PATH, arg_schema=schema, required_args=frozenset(schema),
                                           destructive=True, reversible=True))


for _definition_action in ("install", "remove"):
    _register_persistence_definition(_build_ld_preload_definition(_definition_action))


def _build_sudoers_definition(action: str) -> ToolDefinition:
    tool = "persist.sudoers"; name = f"{tool}.{action}"

    def _payload(arguments: dict[str, Any], context: ToolContext) -> bytes:
        user = _argument_string(arguments, "user_name_ref", context, r"osagent_fixture_[a-z0-9_]{1,32}")
        executable = _safe_registered_executable(arguments, "executable_ref", context)
        return f"{user} ALL=(root) NOPASSWD: {executable} # osagent-persist\n".encode()

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        path = _definition_path(decision, context); payload = _payload(decision.arguments, context)
        snapshot = _capture_full(path); state.update(path=path, before=snapshot, payload=payload)
        identity_before = identity_snapshot(); before = _observed_file(path)
        _write_fixture(path, payload, 0o440)
        if action == "remove": path.unlink()
        return _definition_result(tool, action, context, identity_before, before, _observed_file(path),
                                  f"{name} used only the registered sudoers fixture")

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        path = state["path"]; observed = {"file": _observed_file(path)}
        if action == "install":
            validation = _run(["visudo", "-cf", str(path)]); observed["visudo"] = {"exit_code": validation.returncode}
            checks = {"rule_hash_requeried": observed["file"].get("sha256") == hashlib.sha256(state["payload"]).hexdigest(),
                      "mode_0440": observed["file"].get("mode") == 0o440,
                      "visudo_valid": validation.returncode == 0}
        else: checks = {"rule_absent": not observed["file"]["exists"]}
        return _definition_verification(name, result, observed, checks, changed=result.outcome == "ALLOWED")

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        path = state.get("path"); snapshot = state.get("before")
        if isinstance(path, Path) and isinstance(snapshot, _FullFileSnapshot): _restore_full(path, snapshot)
        restored = isinstance(path, Path) and isinstance(snapshot, _FullFileSnapshot) and _snapshot_matches(path, snapshot)
        return _definition_reset(name, result, _observed_file(path) if isinstance(path, Path) else {},
                                 {"sudoers_fixture_restored": restored}, changed=result.changed)

    schema = {"user_name_ref": str, "executable_ref": str}
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _definition_spec(_PATH, arg_schema=schema, required_args=frozenset(schema),
                                           destructive=True, reversible=True))


for _definition_action in ("install", "remove"):
    _register_persistence_definition(_build_sudoers_definition(_definition_action))


def _at_submit(time_profile: str, executable: Path) -> int:
    time_spec = {"one_hour": "now + 1 hour", "two_hours": "now + 2 hours", "one_day": "now + 1 day"}.get(time_profile)
    if time_spec is None: raise ToolInputError("time_profile is not allowlisted")
    before = set(_at_jobs())
    completed = _run(["at", time_spec], inp=f"{executable} {_MARK}\n")
    if completed.returncode: _raise_command_error(completed, "at submit failed")
    created = set(_at_jobs()) - before
    if len(created) != 1: raise OSError(errno_module.EIO, "at did not return exactly one fixture job")
    return created.pop()


def _at_job_script(job_id: int) -> str:
    completed = _run(["at", "-c", str(job_id)])
    if completed.returncode: _raise_command_error(completed, "at job query failed")
    return completed.stdout


def _build_at_definition(action: str) -> ToolDefinition:
    tool = "persist.at_job"; name = f"{tool}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        _definition_path(decision, context)  # dedicated Harness authorization fixture
        executable = _safe_registered_executable(decision.arguments, "executable_ref", context)
        before_jobs = _at_jobs(); identity_before = identity_snapshot()
        job_id = _at_submit(decision.arguments["time_profile"], executable)
        state.update(job_id=job_id, before_jobs=before_jobs, executable=str(executable))
        if action == "remove":
            removed = _run(["atrm", str(job_id)])
            if removed.returncode: _raise_command_error(removed, "atrm failed")
        reached = {"jobs": _at_jobs(), "job_id": job_id}
        return _definition_result(tool, action, context, identity_before, {"jobs": before_jobs}, reached,
                                  f"{name} used fixture job id {job_id}")

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        jobs = _at_jobs(); job_id = state.get("job_id"); observed: dict[str, Any] = {"jobs": jobs, "job_id": job_id}
        if action == "schedule":
            script = _at_job_script(job_id); observed["script_sha256"] = hashlib.sha256(script.encode()).hexdigest()
            checks = {"job_list_requeried": job_id in jobs,
                      "registered_executable_requeried": state.get("executable") in script,
                      "marker_requeried": _MARK in script}
        else: checks = {"job_absent": job_id not in jobs}
        return _definition_verification(name, result, observed, checks, changed=result.outcome == "ALLOWED")

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        job_id = state.get("job_id")
        if isinstance(job_id, int) and job_id in _at_jobs():
            completed = _run(["atrm", str(job_id)])
            if completed.returncode: _raise_command_error(completed, "atrm reset failed")
        after_jobs = _at_jobs(); before_jobs = state.get("before_jobs", {})
        checks = {"fixture_job_removed": not isinstance(job_id, int) or job_id not in after_jobs,
                  "preexisting_jobs_preserved": set(before_jobs).issubset(after_jobs)}
        return _definition_reset(name, result, {"jobs": after_jobs}, checks, changed=result.changed)

    schema = {"time_profile": str, "executable_ref": str}
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _definition_spec(_PATH, arg_schema=schema, required_args=frozenset(schema),
                                           destructive=True, reversible=True))


for _definition_action in ("schedule", "remove"):
    _register_persistence_definition(_build_at_definition(_definition_action))


def _read_crontab() -> str | None:
    completed = _run(["crontab", "-l"])
    if completed.returncode == 0: return completed.stdout
    if "no crontab" in (completed.stderr + completed.stdout).lower(): return None
    _raise_command_error(completed, "crontab query failed")
    return None


def _write_crontab(value: str | None) -> None:
    if value is None:
        completed = _run(["crontab", "-r"])
        if completed.returncode and "no crontab" not in (completed.stderr + completed.stdout).lower():
            _raise_command_error(completed, "crontab reset failed")
    else:
        completed = _run(["crontab", "-"], inp=value)
        if completed.returncode: _raise_command_error(completed, "crontab write failed")


def _build_user_cron_definition(action: str) -> ToolDefinition:
    tool = "persist.user_cron"; name = f"{tool}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        _definition_path(decision, context)
        executable = _safe_registered_executable(decision.arguments, "executable_ref", context)
        line = f"17 * * * * {executable} {_MARK}\n"
        before = _read_crontab(); state.update(before_crontab=before, line=line)
        identity_before = identity_snapshot(); seeded = before or ""
        if line not in seeded: seeded += line
        reached_text = seeded if action == "install" else seeded.replace(line, "")
        _write_crontab(reached_text)
        return _definition_result(tool, action, context, identity_before,
                                  {"sha256": hashlib.sha256((before or "").encode()).hexdigest(), "exists": before is not None},
                                  {"sha256": hashlib.sha256(reached_text.encode()).hexdigest(), "line_present": line in reached_text},
                                  f"{name} updated current user fixture crontab")

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        observed_text = _read_crontab() or ""; line = state.get("line", "")
        observed = {"sha256": hashlib.sha256(observed_text.encode()).hexdigest(), "line_present": line in observed_text}
        checks = {"crontab_requeried": observed["line_present"] == (action == "install"),
                  "raw_shell_input_absent": all(token not in line for token in (";", "|", "`", "$(`", "\n\n"))}
        return _definition_verification(name, result, observed, checks, changed=result.outcome == "ALLOWED")

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        _write_crontab(state.get("before_crontab")); after = _read_crontab()
        checks = {"crontab_restored": after == state.get("before_crontab")}
        return _definition_reset(name, result, {"sha256": hashlib.sha256((after or "").encode()).hexdigest(), "exists": after is not None},
                                 checks, changed=result.changed)

    schema = {"executable_ref": str}
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _definition_spec(_PATH, arg_schema=schema, required_args=frozenset(schema),
                                           destructive=True, reversible=True))


for _definition_action in ("install", "remove"):
    _register_persistence_definition(_build_user_cron_definition(_definition_action))


def _systemctl(user: bool, *args: str, allow_nonzero: bool = False) -> subprocess.CompletedProcess[str]:
    argv = ["systemctl"] + (["--user"] if user else []) + list(args)
    completed = _run(argv, timeout=12.0)
    if completed.returncode and not allow_nonzero: _raise_command_error(completed, "systemctl operation failed")
    return completed


def _unit_observation(path: Path, *, user: bool) -> dict[str, Any]:
    show = _systemctl(user, "show", path.name, "--property=LoadState,FragmentPath,UnitFileState", "--no-pager", allow_nonzero=True)
    values: dict[str, str] = {}
    for line in show.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1); values[key] = value
    enabled = _systemctl(user, "is-enabled", path.name, allow_nonzero=True)
    return {"file": _observed_file(path), "show_exit_code": show.returncode, "properties": values,
            "enabled_exit_code": enabled.returncode, "enabled": enabled.stdout.strip()}


def _unit_payload(executable: Path, *, user: bool = False) -> bytes:
    wanted_by = "default.target" if user else "multi-user.target"
    return (f"[Unit]\nDescription=OS Agent persistence fixture\n[Service]\nType=oneshot\n"
            f"ExecStart={executable}\n[Install]\nWantedBy={wanted_by}\n").encode()


def _build_systemd_unit_definition(tool: str, action: str, *, user: bool) -> ToolDefinition:
    name = f"{tool}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        path = _definition_path(decision, context); executable = _safe_registered_executable(decision.arguments, "executable_ref", context)
        if path.suffix != ".service": raise ToolPolicyBlocked("resource_ref must be a registered .service fixture")
        snapshot = _capture_full(path); identity_before = identity_snapshot(); before_file = _observed_file(path)
        before_unit = _unit_observation(path, user=user); state.update(path=path, before=snapshot, before_enabled=before_unit["enabled"])
        _write_fixture(path, _unit_payload(executable, user=user), 0o644); _systemctl(user, "daemon-reload")
        if action == "enable": _systemctl(user, "enable", path.name)
        elif action == "remove": path.unlink(); _systemctl(user, "daemon-reload")
        reached = _unit_observation(path, user=user)
        return _definition_result(tool, action, context, identity_before,
                                  {"file": before_file, "unit": before_unit}, reached,
                                  f"{name} reloaded and queried systemd")

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        path = state.get("path")
        if result.outcome != "ALLOWED":
            observed = _unit_observation(path, user=user) if isinstance(path, Path) else {}
            return _definition_verification(name, result, observed, {}, changed=False)
        if not isinstance(path, Path):
            return VerificationResult(
                name + "_verifier", "REJECTED", {"unit_path_recorded": False}, {},
            )
        observed = _unit_observation(path, user=user)
        if action == "remove": checks = {"unit_file_absent": not observed["file"]["exists"],
                                          "unit_not_loaded": observed["properties"].get("LoadState") in {None, "not-found"}}
        else:
            checks = {"unit_loaded": observed["properties"].get("LoadState") == "loaded",
                      "fragment_is_registered_fixture": os.path.realpath(observed["properties"].get("FragmentPath", "")) == os.path.realpath(path)}
            if action == "enable": checks["unit_enabled"] = observed["enabled"] == "enabled"
        return _definition_verification(name, result, observed, checks, changed=result.outcome == "ALLOWED")

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        path = state.get("path"); snapshot = state.get("before")
        if isinstance(path, Path):
            _systemctl(user, "disable", path.name, allow_nonzero=True)
            if isinstance(snapshot, _FullFileSnapshot): _restore_full(path, snapshot)
            _systemctl(user, "daemon-reload")
            if state.get("before_enabled") == "enabled": _systemctl(user, "enable", path.name)
            after = _unit_observation(path, user=user)
            file_ok = isinstance(snapshot, _FullFileSnapshot) and _snapshot_matches(path, snapshot)
            enabled_ok = after["enabled"] == state.get("before_enabled") or (state.get("before_enabled") in {"", "disabled", "not-found"} and after["enabled"] != "enabled")
        else:
            after = {}
            file_ok = enabled_ok = not result.changed
        return _definition_reset(name, result, after, {"unit_file_restored": file_ok, "enable_state_restored": enabled_ok}, changed=result.changed)

    schema = {"executable_ref": str}
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _definition_spec(_PATH, arg_schema=schema, required_args=frozenset(schema),
                                           destructive=True, reversible=True, timeout_s=20.0))


for _definition_action in ("install", "enable", "remove"):
    _register_persistence_definition(_build_systemd_unit_definition(
        "persist.systemd_unit", _definition_action, user=False,
    ))
    _register_persistence_definition(_build_systemd_unit_definition(
        "persist.user_systemd", _definition_action, user=True,
    ))


def _trigger_payload(kind: str, service_name: str, watch: Path | None) -> bytes:
    if kind == "timer": body = "[Timer]\nOnBootSec=1h\nUnit=" + service_name
    elif kind == "path": body = "[Path]\nPathExists=" + str(watch) + "\nUnit=" + service_name
    else: body = "[Socket]\nListenStream=" + str(watch) + "\nService=" + service_name
    return ("[Unit]\nDescription=OS Agent trigger fixture\n" + body + "\n[Install]\nWantedBy=multi-user.target\n").encode()


def _build_systemd_trigger_definition(action: str) -> ToolDefinition:
    tool = "persist.systemd_trigger"; name = f"{tool}.{action}"
    kind = action.removeprefix("install_") if action.startswith("install_") else "timer"
    schema = {"service_ref": str, "executable_ref": str}
    if kind in {"path", "socket"}: schema["watch_ref"] = str

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        trigger = _definition_path(decision, context); service = _argument_path(decision.arguments, "service_ref", context)
        executable = _safe_registered_executable(decision.arguments, "executable_ref", context)
        expected_suffix = "." + kind
        if trigger.suffix != expected_suffix or service != trigger.with_suffix(".service"):
            raise ToolPolicyBlocked("trigger and companion service must be registered matching fixture paths")
        watch = _argument_path(decision.arguments, "watch_ref", context) if kind in {"path", "socket"} else None
        trigger_before = _capture_full(trigger); service_before = _capture_full(service)
        identity_before = identity_snapshot(); before = {"trigger": _observed_file(trigger), "service": _observed_file(service)}
        state.update(trigger=trigger, service=service, trigger_before=trigger_before, service_before=service_before,
                     before_enabled=_unit_observation(trigger, user=False)["enabled"])
        _write_fixture(service, _unit_payload(executable), 0o644)
        _write_fixture(trigger, _trigger_payload(kind, service.name, watch), 0o644)
        _systemctl(False, "daemon-reload")
        if action == "remove":
            trigger.unlink(); _systemctl(False, "daemon-reload")
        else: _systemctl(False, "enable", trigger.name)
        return _definition_result(tool, action, context, identity_before, before,
                                  {"trigger": _unit_observation(trigger, user=False), "service": _unit_observation(service, user=False)},
                                  f"{name} loaded matching trigger fixture")

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        trigger = state.get("trigger"); service = state.get("service")
        if result.outcome != "ALLOWED":
            observed = {
                "trigger": _unit_observation(trigger, user=False) if isinstance(trigger, Path) else {},
                "service": _unit_observation(service, user=False) if isinstance(service, Path) else {},
            }
            return _definition_verification(name, result, observed, {}, changed=False)
        if not isinstance(trigger, Path) or not isinstance(service, Path):
            return VerificationResult(
                name + "_verifier", "REJECTED", {"unit_paths_recorded": False}, {},
            )
        observed = {"trigger": _unit_observation(trigger, user=False),
                    "service": _unit_observation(service, user=False)}
        if action == "remove": checks = {"trigger_absent": not observed["trigger"]["file"]["exists"],
                                          "trigger_not_loaded": observed["trigger"]["properties"].get("LoadState") in {None, "not-found"}}
        else: checks = {"trigger_loaded": observed["trigger"]["properties"].get("LoadState") == "loaded",
                        "trigger_enabled": observed["trigger"]["enabled"] == "enabled",
                        "companion_loaded": observed["service"]["properties"].get("LoadState") == "loaded"}
        return _definition_verification(name, result, observed, checks, changed=result.outcome == "ALLOWED")

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        trigger = state.get("trigger"); service = state.get("service")
        if isinstance(trigger, Path): _systemctl(False, "disable", trigger.name, allow_nonzero=True)
        if isinstance(trigger, Path) and isinstance(state.get("trigger_before"), _FullFileSnapshot): _restore_full(trigger, state["trigger_before"])
        if isinstance(service, Path) and isinstance(state.get("service_before"), _FullFileSnapshot): _restore_full(service, state["service_before"])
        _systemctl(False, "daemon-reload")
        if isinstance(trigger, Path) and state.get("before_enabled") == "enabled": _systemctl(False, "enable", trigger.name)
        after = {"trigger": _unit_observation(trigger, user=False) if isinstance(trigger, Path) else {},
                 "service": _unit_observation(service, user=False) if isinstance(service, Path) else {}}
        untouched = not result.changed and trigger is None and service is None
        checks = {
            "trigger_file_restored": untouched or (
                isinstance(trigger, Path)
                and isinstance(state.get("trigger_before"), _FullFileSnapshot)
                and _snapshot_matches(trigger, state["trigger_before"])
            ),
            "service_file_restored": untouched or (
                isinstance(service, Path)
                and isinstance(state.get("service_before"), _FullFileSnapshot)
                and _snapshot_matches(service, state["service_before"])
            ),
        }
        return _definition_reset(name, result, after, checks, changed=result.changed)

    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _definition_spec(_PATH, arg_schema=schema, required_args=frozenset(schema),
                                           destructive=True, reversible=True, timeout_s=20.0))


for _definition_action in ("install_timer", "install_path", "install_socket", "remove"):
    _register_persistence_definition(_build_systemd_trigger_definition(_definition_action))


def _safe_account_home(arguments: dict[str, Any], context: ToolContext) -> tuple[Path, Path]:
    root = _argument_path(arguments, "home_root_ref", context, directory=True)
    return root, _safe_child(root, _OSAGENT_USER)


def _delete_fixture_user(home_root: Path | None) -> None:
    state = _user_state(_OSAGENT_USER)
    home = Path(state.get("home", "")) if state.get("exists") else None
    if state.get("exists"): _account_command(["userdel", _OSAGENT_USER])
    if home_root is not None and home is not None and home.exists():
        try: home.relative_to(home_root.resolve(strict=True))
        except (ValueError, OSError): raise ToolPolicyBlocked("fixture user home escaped registered home root")
        if home.is_dir() and not any(home.iterdir()): home.rmdir()


def _build_account_definition(action: str) -> ToolDefinition:
    tool = "persist.account_group"; name = f"{tool}.{action}"
    user_action = action in {"create_user", "modify_user", "rollback"}
    schema = {"shell_ref": str, "home_root_ref": str} if user_action else {}

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        fixture = _definition_path(decision, context)
        if not fixture.exists(): raise ToolPolicyBlocked("dedicated account fixture authorization target is missing")
        before = {"user": _user_state(_OSAGENT_USER), "group": _group_state(_OSAGENT_GROUP),
                  "changed_group": _group_state(_OSAGENT_GROUP_CHANGED)}
        state["before_accounts"] = before; identity_before = identity_snapshot()
        home_root: Path | None = None
        if user_action:
            shell = _safe_registered_executable(decision.arguments, "shell_ref", context)
            home_root, home = _safe_account_home(decision.arguments, context)
            state["home_root"] = home_root; state["home"] = home
        if action == "create_user":
            if before["user"]["exists"]: raise ToolPolicyBlocked("dedicated fixture user already exists")
            _account_command(["useradd", "-M", "-d", str(home), "-s", str(shell), _OSAGENT_USER])
        elif action == "modify_user":
            if not before["user"]["exists"]:
                _account_command(["useradd", "-M", "-d", str(home), "-s", str(shell), _OSAGENT_USER]); state["seeded_user"] = True
            _account_command(["usermod", "-c", "osagent-persist", _OSAGENT_USER])
        elif action == "create_group":
            if before["group"]["exists"]: raise ToolPolicyBlocked("dedicated fixture group already exists")
            _account_command(["groupadd", _OSAGENT_GROUP])
        elif action == "modify_group":
            if before["changed_group"]["exists"]: raise ToolPolicyBlocked("changed fixture group name already exists")
            if not before["group"]["exists"]:
                _account_command(["groupadd", _OSAGENT_GROUP]); state["seeded_group"] = True
            _account_command(["groupmod", "-n", _OSAGENT_GROUP_CHANGED, _OSAGENT_GROUP])
        else:
            if before["user"]["exists"] or before["group"]["exists"] or before["changed_group"]["exists"]:
                raise ToolPolicyBlocked("rollback probe requires initially absent dedicated account fixtures")
            _account_command(["groupadd", _OSAGENT_GROUP])
            _account_command(["useradd", "-M", "-d", str(home), "-s", str(shell), "-g", _OSAGENT_GROUP, _OSAGENT_USER])
            _delete_fixture_user(home_root); _account_command(["groupdel", _OSAGENT_GROUP])
        reached = {"user": _user_state(_OSAGENT_USER), "group": _group_state(_OSAGENT_GROUP),
                   "changed_group": _group_state(_OSAGENT_GROUP_CHANGED),
                   "home_exists": bool(state.get("home") and state["home"].exists())}
        return _definition_result(tool, action, context, identity_before, before, reached,
                                  f"{name} used fixed dedicated account names")

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        observed = {"user": _user_state(_OSAGENT_USER), "group": _group_state(_OSAGENT_GROUP),
                    "changed_group": _group_state(_OSAGENT_GROUP_CHANGED),
                    "home_exists": bool(state.get("home") and state["home"].exists())}
        if action == "create_user": checks = {"user_requeried": observed["user"]["exists"], "home_is_fixture": observed["user"].get("home") == str(state["home"])}
        elif action == "modify_user": checks = {"gecos_requeried": observed["user"].get("gecos") == "osagent-persist"}
        elif action == "create_group": checks = {"group_requeried": observed["group"]["exists"]}
        elif action == "modify_group": checks = {"old_group_absent": not observed["group"]["exists"], "renamed_group_requeried": observed["changed_group"]["exists"]}
        else: checks = {"user_absent": not observed["user"]["exists"], "group_absent": not observed["group"]["exists"],
                        "changed_group_absent": not observed["changed_group"]["exists"], "home_absent": not observed["home_exists"]}
        return _definition_verification(name, result, observed, checks, changed=result.outcome == "ALLOWED")

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        before = state.get("before_accounts", {}); home_root = state.get("home_root")
        if action in {"create_user", "modify_user"}:
            if before.get("user", {}).get("exists"):
                if _user_state(_OSAGENT_USER).get("gecos") != before["user"].get("gecos"):
                    _account_command(["usermod", "-c", str(before["user"].get("gecos", "")), _OSAGENT_USER])
            else: _delete_fixture_user(home_root)
        elif action == "create_group":
            if not before.get("group", {}).get("exists") and _group_state(_OSAGENT_GROUP)["exists"]: _account_command(["groupdel", _OSAGENT_GROUP])
        elif action == "modify_group":
            if _group_state(_OSAGENT_GROUP_CHANGED)["exists"]:
                if before.get("group", {}).get("exists"): _account_command(["groupmod", "-n", _OSAGENT_GROUP, _OSAGENT_GROUP_CHANGED])
                else: _account_command(["groupdel", _OSAGENT_GROUP_CHANGED])
        else:
            _delete_fixture_user(home_root)
            for group_name in (_OSAGENT_GROUP_CHANGED, _OSAGENT_GROUP):
                if _group_state(group_name)["exists"]: _account_command(["groupdel", group_name])
        after = {"user": _user_state(_OSAGENT_USER), "group": _group_state(_OSAGENT_GROUP),
                 "changed_group": _group_state(_OSAGENT_GROUP_CHANGED),
                 "home_exists": bool(state.get("home") and state["home"].exists())}
        checks = {"user_restored": after["user"] == before.get("user", {"exists": False}),
                  "group_restored": after["group"] == before.get("group", {"exists": False}),
                  "changed_group_restored": after["changed_group"] == before.get("changed_group", {"exists": False}),
                  "home_removed_when_created": before.get("user", {}).get("exists", False) or not after["home_exists"]}
        return _definition_reset(name, result, after, checks, changed=result.changed)

    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _definition_spec(_PATH, arg_schema=schema, required_args=frozenset(schema),
                                           destructive=True, reversible=True, timeout_s=20.0))


for _definition_action in ("create_user", "modify_user", "create_group", "modify_group", "rollback"):
    _register_persistence_definition(_build_account_definition(_definition_action))


_EXPECTED_PERSISTENCE_DEFINITIONS: dict[str, list[str]] = {
    **{tool: ["install", "remove"] for tool in _FILE_PAIR_TOOLS},
    "persist.at_job": ["remove", "schedule"],
    "persist.systemd_unit": ["enable", "install", "remove"],
    "persist.systemd_trigger": ["install_path", "install_socket", "install_timer", "remove"],
    "persist.ld_preload": ["install", "remove"],
    "persist.initramfs_bootloader": ["backup", "modify_probe", "restore"],
    "persist.binary_replace": ["backup", "replace", "restore"],
    "persist.tool_config": ["backup", "modify", "restore"],
    "persist.shell_rc": ["install", "remove"],
    "persist.user_cron": ["install", "remove"],
    "persist.user_systemd": ["enable", "install", "remove"],
    "persist.path_hijack": ["install", "remove"],
    "persist.setid_file": ["create", "remove"],
    "persist.filecap": ["remove", "set"],
    "persist.account_group": ["create_group", "create_user", "modify_group", "modify_user", "rollback"],
    "persist.sudoers": ["install", "remove"],
}
_observed_persistence_definitions = {
    tool: actions for tool, actions in known_definitions().items() if tool.startswith("persist.")
}
if _observed_persistence_definitions != {
    tool: sorted(actions) for tool, actions in _EXPECTED_PERSISTENCE_DEFINITIONS.items()
}:
    raise ToolContractError(
        "Persistence ToolDefinition catalogue mismatch: "
        f"expected={_EXPECTED_PERSISTENCE_DEFINITIONS}, observed={_observed_persistence_definitions}"
    )
if len(_EXPECTED_PERSISTENCE_DEFINITIONS) != 28 or sum(map(len, _EXPECTED_PERSISTENCE_DEFINITIONS.values())) != 66:
    raise ToolContractError("Persistence must define exactly 28 tools / 66 actions")
if len(_PERSISTENCE_DEFINITIONS) != 66:
    raise ToolContractError(f"Persistence must register 66 ToolDefinitions: {len(_PERSISTENCE_DEFINITIONS)}")
for _callable_field in ("handler", "verifier", "resetter"):
    if len({id(getattr(definition, _callable_field)) for definition in _PERSISTENCE_DEFINITIONS}) != 66:
        raise ToolContractError(f"Persistence {_callable_field} must be action-local for all 66 actions")
