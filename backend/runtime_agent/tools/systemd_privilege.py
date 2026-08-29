"""OStool 정리.md 5.7 systemd·로컬 권한 위임 — canonical 9개 Tool.

| # | Tool | action |
|---|------|--------|
| 69 | systemd.unit_lifecycle | create, start, stop, restart, reload, remove |
| 70 | systemd.unit_enablement | enable, disable, mask, unmask |
| 71 | systemd.trigger_unit | create_timer, create_path, create_socket, trigger, remove |
| 72 | systemd.transient_run | service, scope |
| 73 | systemd.unit_property | get, set_runtime |
| 74 | systemd.manager_reload | daemon_reload, reexec_probe |
| 75 | systemd.user_linger | enable, disable |
| 76 | systemd.scope_run | run |
| 77 | systemd.hostname_change | get, set_probe |

모두 host executor + TB-HH-U1U2 전용. systemctl/systemd-run/hostnamectl가 없거나
권한이 없으면 OS_DENIED/ERROR로 관측된다. Tool은 성공/실패를 판정하지 않는다.
생성형(unit/timer 파일)은 probe로 원복하거나 reset으로 정리한다.
"""
from __future__ import annotations

import errno as errno_module
import hashlib
import json
import os
import stat as stat_module
import subprocess
import time
from pathlib import Path
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
    probe,
    register,
    register_definition,
    identity_snapshot,
    str_arg,
)

_NONE = "none"
_PATH = "path"
_HOST = frozenset({"host"})
_HH_TB = frozenset({"TB-HH-U1U2"})


def _spec(**kw: Any) -> ToolSpec:
    kw.setdefault("resource_kind", _NONE)
    kw.setdefault("allowed_executors", _HOST)
    kw.setdefault("allowed_tbs", _HH_TB)
    return ToolSpec(**kw)


def _run(argv: list[str], timeout: int = 10) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise OSError(errno_module.ENOENT, f"{argv[0]} command not found")


def _run_checked(argv: list[str], ok_msg: str, timeout: int = 10) -> str:
    r = _run(argv, timeout)
    if r.returncode != 0:
        # 권한 거부는 OS_DENIED로 보이도록 EPERM 매핑
        err = (r.stderr or r.stdout or "failed").strip()[:200]
        code = errno_module.EPERM if ("permission" in err.lower() or "denied" in err.lower() or "access" in err.lower()) else 1
        raise OSError(code, err)
    return ok_msg


def _safe_unit_name(name: str, allowed_suffixes: tuple[str, ...] = (".service", ".timer", ".path", ".socket", ".scope")) -> str:
    if "/" in name or ".." in name:
        raise ToolInputError("unit_name에 '/'나 '..'는 허용되지 않습니다.")
    return name


def _legacy_fixture_directory(arguments: Dict[str, Any], context: ToolContext) -> Path:
    ref = arguments.get("resource_ref")
    if not isinstance(ref, str) or not ref: raise ToolInputError("registered fixture directory resource_ref is required")
    path = context.resolve_path(ref)
    if not os.path.isdir(path) or os.path.islink(path) or os.path.realpath(path) != os.path.abspath(path):
        raise ToolPolicyBlocked("resource_ref must be an exact systemd fixture directory")
    return Path(path)


# ══════════════════════════════════════════════════════════════════════════════
# 69. systemd.unit_lifecycle
# ══════════════════════════════════════════════════════════════════════════════
_LIFECYCLE = "systemd.unit_lifecycle"


def _unit_file_reset(outcome: ToolOutcome, context: ToolContext) -> None:
    made = (outcome.state_after or {}).get("unit_file")
    if made and os.path.exists(made):
        try:
            os.unlink(made)
            _run(["systemctl", "daemon-reload"])
        except OSError:
            pass


@register(_LIFECYCLE, "create", spec=_spec(
    resource_kind=_PATH,
    arg_schema={"unit_name": str, "exec_start": str, "description": str, "unit_type": str},
    required_args=frozenset({"unit_name", "exec_start"}), reversible=True), reset=_unit_file_reset)
def _lifecycle_create(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    unit = _safe_unit_name(str_arg(arguments, "unit_name"))
    exec_start = str_arg(arguments, "exec_start")
    description = arguments.get("description", "osagent unit")
    unit_type = arguments.get("unit_type", "simple")
    unit_path = _legacy_fixture_directory(arguments, context) / (unit if unit.endswith(".service") else f"{unit}.service")

    def _mutate() -> str:
        unit_path.write_text(
            f"[Unit]\nDescription={description}\n\n[Service]\nType={unit_type}\nExecStart={exec_start}\n\n[Install]\nWantedBy=multi-user.target\n"
        )
        _run(["systemctl", "daemon-reload"])
        return f"unit {unit_path.name} 작성"

    def _restore() -> None:
        if unit_path.exists():
            unit_path.unlink()
            _run(["systemctl", "daemon-reload"])

    outcome = probe(_LIFECYCLE, "create", mutate=_mutate,
                    snapshot_state=lambda: {"exists": unit_path.exists()}, restore=_restore)
    if outcome.outcome == "ALLOWED":
        outcome.state_after = {**(outcome.state_after or {}), "unit_file": str(unit_path)}
    return outcome


@register(_LIFECYCLE, "start", spec=_spec(arg_schema={"unit_name": str}, required_args=frozenset({"unit_name"})))
@register(_LIFECYCLE, "stop", spec=_spec(arg_schema={"unit_name": str}, required_args=frozenset({"unit_name"})))
@register(_LIFECYCLE, "restart", spec=_spec(arg_schema={"unit_name": str}, required_args=frozenset({"unit_name"})))
@register(_LIFECYCLE, "reload", spec=_spec(arg_schema={"unit_name": str}, required_args=frozenset({"unit_name"})))
def _lifecycle_action(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    unit = _safe_unit_name(str_arg(arguments, "unit_name"))
    return attempt(_LIFECYCLE, action, lambda: _run_checked(["systemctl", action, unit], f"systemctl {action} {unit}"))


@register(_LIFECYCLE, "remove", spec=_spec(resource_kind=_PATH, arg_schema={"unit_name": str}, required_args=frozenset({"unit_name"}), destructive=True))
def _lifecycle_remove(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    unit = _safe_unit_name(str_arg(arguments, "unit_name"))
    unit_path = _legacy_fixture_directory(arguments, context) / (unit if "." in unit else f"{unit}.service")

    def _op() -> str:
        _run(["systemctl", "stop", unit])
        if unit_path.exists():
            unit_path.unlink()
            _run(["systemctl", "daemon-reload"])
            return f"unit {unit_path.name} 제거"
        raise OSError(errno_module.ENOENT, "unit file not found")

    return attempt(_LIFECYCLE, "remove", _op)


# ══════════════════════════════════════════════════════════════════════════════
# 70. systemd.unit_enablement
# ══════════════════════════════════════════════════════════════════════════════
_ENABLEMENT = "systemd.unit_enablement"


@register(_ENABLEMENT, "enable", spec=_spec(arg_schema={"unit_name": str}, required_args=frozenset({"unit_name"})))
@register(_ENABLEMENT, "disable", spec=_spec(arg_schema={"unit_name": str}, required_args=frozenset({"unit_name"})))
@register(_ENABLEMENT, "mask", spec=_spec(arg_schema={"unit_name": str}, required_args=frozenset({"unit_name"})))
@register(_ENABLEMENT, "unmask", spec=_spec(arg_schema={"unit_name": str}, required_args=frozenset({"unit_name"})))
def _enablement(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    unit = _safe_unit_name(str_arg(arguments, "unit_name"))
    return attempt(_ENABLEMENT, action, lambda: _run_checked(["systemctl", action, unit], f"systemctl {action} {unit}"))


# ══════════════════════════════════════════════════════════════════════════════
# 71. systemd.trigger_unit — timer/path/socket 생성·실행
# ══════════════════════════════════════════════════════════════════════════════
_TRIGGER = "systemd.trigger_unit"
_TRIGGER_KINDS = {"create_timer": ("timer", "[Timer]\nOnActiveSec=1h\n"),
                  "create_path": ("path", "[Path]\nPathExists=/tmp/osagent\n"),
                  "create_socket": ("socket", "[Socket]\nListenStream=/run/osagent.sock\n")}


def _trigger_reset(outcome: ToolOutcome, context: ToolContext) -> None:
    made = (outcome.state_after or {}).get("unit_file")
    if made and os.path.exists(made):
        try:
            os.unlink(made)
            _run(["systemctl", "daemon-reload"])
        except OSError:
            pass


@register(_TRIGGER, "create_timer", spec=_spec(resource_kind=_PATH, arg_schema={"unit_name": str}, required_args=frozenset({"unit_name"}), reversible=True), reset=_trigger_reset)
@register(_TRIGGER, "create_path", spec=_spec(resource_kind=_PATH, arg_schema={"unit_name": str}, required_args=frozenset({"unit_name"}), reversible=True), reset=_trigger_reset)
@register(_TRIGGER, "create_socket", spec=_spec(resource_kind=_PATH, arg_schema={"unit_name": str}, required_args=frozenset({"unit_name"}), reversible=True), reset=_trigger_reset)
def _trigger_create(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    unit = _safe_unit_name(str_arg(arguments, "unit_name"))
    suffix, body = _TRIGGER_KINDS[action]
    unit_path = _legacy_fixture_directory(arguments, context) / (unit if unit.endswith(f".{suffix}") else f"{unit}.{suffix}")

    def _mutate() -> str:
        unit_path.write_text(f"[Unit]\nDescription=osagent {suffix}\n\n{body}\n[Install]\nWantedBy=multi-user.target\n")
        _run(["systemctl", "daemon-reload"])
        return f"{suffix} unit {unit_path.name} 작성"

    def _restore() -> None:
        if unit_path.exists():
            unit_path.unlink()
            _run(["systemctl", "daemon-reload"])

    outcome = probe(_TRIGGER, action, mutate=_mutate, snapshot_state=lambda: {"exists": unit_path.exists()}, restore=_restore)
    if outcome.outcome == "ALLOWED":
        outcome.state_after = {**(outcome.state_after or {}), "unit_file": str(unit_path)}
    return outcome


@register(_TRIGGER, "trigger", spec=_spec(arg_schema={"unit_name": str}, required_args=frozenset({"unit_name"})))
def _trigger_start(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    unit = _safe_unit_name(str_arg(arguments, "unit_name"))
    return attempt(_TRIGGER, "trigger", lambda: _run_checked(["systemctl", "start", unit], f"triggered {unit}"))


@register(_TRIGGER, "remove", spec=_spec(resource_kind=_PATH, arg_schema={"unit_name": str}, required_args=frozenset({"unit_name"}), destructive=True))
def _trigger_remove(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    unit = _safe_unit_name(str_arg(arguments, "unit_name"))

    def _op() -> str:
        removed = []
        for suffix in ("timer", "path", "socket"):
            p = _legacy_fixture_directory(arguments, context) / (unit if unit.endswith(f".{suffix}") else f"{unit}.{suffix}")
            if p.exists():
                p.unlink()
                removed.append(p.name)
        if not removed:
            raise OSError(errno_module.ENOENT, "trigger unit not found")
        _run(["systemctl", "daemon-reload"])
        return f"removed {removed}"

    return attempt(_TRIGGER, "remove", _op)


# ══════════════════════════════════════════════════════════════════════════════
# 72. systemd.transient_run — systemd-run --scope / transient service
# ══════════════════════════════════════════════════════════════════════════════
_TRANSIENT = "systemd.transient_run"


@register(_TRANSIENT, "service", spec=_spec(arg_schema={"exec_cmd": str}, required_args=frozenset({"exec_cmd"})))
@register(_TRANSIENT, "scope", spec=_spec(arg_schema={"exec_cmd": str}, required_args=frozenset({"exec_cmd"})))
def _transient_run(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    exec_cmd = str_arg(arguments, "exec_cmd")
    if exec_cmd not in ("true", "id", "echo"):
        raise ToolInputError("exec_cmd는 무해한 확인 명령(true/id/echo)만 허용됩니다.")
    flag = "--scope" if action == "scope" else "--unit=osagent-transient"

    def _op() -> str:
        return _run_checked(["systemd-run", flag, "--collect", exec_cmd], f"systemd-run {action} {exec_cmd}")

    return attempt(_TRANSIENT, action, _op)


# ══════════════════════════════════════════════════════════════════════════════
# 73. systemd.unit_property — get / set_runtime
# ══════════════════════════════════════════════════════════════════════════════
_PROPERTY = "systemd.unit_property"


@register(_PROPERTY, "get", spec=_spec(arg_schema={"unit_name": str, "property": str}, required_args=frozenset({"unit_name"})))
def _property_get(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    unit = _safe_unit_name(str_arg(arguments, "unit_name"))
    prop = arguments.get("property", "MainPID")

    def _op() -> str:
        r = _run(["systemctl", "show", unit, "-p", prop, "--no-page"])
        return f"{unit}.{prop}: {r.stdout.strip()[:120]}"

    return attempt(_PROPERTY, "get", _op)


@register(_PROPERTY, "set_runtime", spec=_spec(
    arg_schema={"unit_name": str, "property": str, "value": str},
    required_args=frozenset({"unit_name", "property", "value"})))
def _property_set(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    unit = _safe_unit_name(str_arg(arguments, "unit_name"))
    prop = str_arg(arguments, "property")
    value = str_arg(arguments, "value")

    def _op() -> str:
        return _run_checked(["systemctl", "set-property", "--runtime", unit, f"{prop}={value}"],
                            f"set-property {unit} {prop}={value}")

    return attempt(_PROPERTY, "set_runtime", _op)


# ══════════════════════════════════════════════════════════════════════════════
# 74. systemd.manager_reload — daemon_reload / reexec_probe
# ══════════════════════════════════════════════════════════════════════════════
_MANAGER = "systemd.manager_reload"


@register(_MANAGER, "daemon_reload", spec=_spec())
def _manager_reload(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    return attempt(_MANAGER, "daemon_reload", lambda: _run_checked(["systemctl", "daemon-reload"], "daemon-reload"))


@register(_MANAGER, "reexec_probe", spec=_spec(destructive=True))
def _manager_reexec(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    # daemon-reexec은 PID1 재실행이라 종료성 위험 → destructive. 권한 관측만.
    return attempt(_MANAGER, "reexec_probe", lambda: _run_checked(["systemctl", "daemon-reexec"], "daemon-reexec 도달"))


# ══════════════════════════════════════════════════════════════════════════════
# 75. systemd.user_linger — enable / disable
# ══════════════════════════════════════════════════════════════════════════════
_LINGER = "systemd.user_linger"


@register(_LINGER, "enable", spec=_spec(arg_schema={"user": str}, required_args=frozenset({"user"})))
@register(_LINGER, "disable", spec=_spec(arg_schema={"user": str}, required_args=frozenset({"user"})))
def _linger(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    user = str_arg(arguments, "user")
    if "/" in user or ".." in user:
        raise ToolInputError("user 이름이 올바르지 않습니다.")
    flag = "enable-linger" if action == "enable" else "disable-linger"
    return attempt(_LINGER, action, lambda: _run_checked(["loginctl", flag, user], f"loginctl {flag} {user}"))


# ══════════════════════════════════════════════════════════════════════════════
# 76. systemd.scope_run — 지정 cgroup property로 process 실행
# ══════════════════════════════════════════════════════════════════════════════
_SCOPE = "systemd.scope_run"


@register(_SCOPE, "run", spec=_spec(arg_schema={"exec_cmd": str, "cpu_quota": str, "memory_max": str},
                                    required_args=frozenset({"exec_cmd"})))
def _scope_run(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    exec_cmd = str_arg(arguments, "exec_cmd")
    if exec_cmd not in ("true", "id", "echo"):
        raise ToolInputError("exec_cmd는 무해한 확인 명령(true/id/echo)만 허용됩니다.")
    argv = ["systemd-run", "--scope", "--collect"]
    if "cpu_quota" in arguments:
        argv += ["-p", f"CPUQuota={arguments['cpu_quota']}"]
    if "memory_max" in arguments:
        argv += ["-p", f"MemoryMax={arguments['memory_max']}"]
    argv.append(exec_cmd)
    return attempt(_SCOPE, "run", lambda: _run_checked(argv, f"scope run {exec_cmd}"))


# ══════════════════════════════════════════════════════════════════════════════
# 77. systemd.hostname_change — get / set_probe
# ══════════════════════════════════════════════════════════════════════════════
_HOSTNAME = "systemd.hostname_change"


@register(_HOSTNAME, "get", spec=_spec())
def _hostname_get(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    def _op() -> str:
        r = _run(["hostnamectl", "status", "--no-pager"])
        if r.returncode != 0:
            return f"hostname={os.uname().nodename}"
        return r.stdout.strip()[:160]

    return attempt(_HOSTNAME, "get", _op)


@register(_HOSTNAME, "set_probe", spec=_spec(arg_schema={"hostname": str}, required_args=frozenset({"hostname"}), reversible=True))
def _hostname_set_probe(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    new_name = str_arg(arguments, "hostname")
    if "/" in new_name or len(new_name) > 64:
        raise ToolInputError("hostname이 올바르지 않습니다.")
    original = os.uname().nodename

    def _mutate() -> str:
        return _run_checked(["hostnamectl", "set-hostname", new_name], f"hostname -> {new_name}")

    def _restore() -> None:
        _run(["hostnamectl", "set-hostname", original])

    return probe(_HOSTNAME, "set_probe", mutate=_mutate,
                 snapshot_state=lambda: {"hostname": os.uname().nodename}, restore=_restore)


if __name__ == "__main__":
    print("5.7 systemd·권한 위임 (canonical 9)")
    for t in (_LIFECYCLE, _ENABLEMENT, _TRIGGER, _TRANSIENT, _PROPERTY, _MANAGER, _LINGER, _SCOPE, _HOSTNAME):
        print("  -", t)


# ══════════════════════════════════════════════════════════════════════════════
# Action-local ToolDefinition layer
# ══════════════════════════════════════════════════════════════════════════════

_SYSTEMD_LIMITS = {"max_units": 2, "max_runtime_seconds": 15, "max_file_bytes": 16 * 1024}
_SYSTEMD_STOPS = frozenset({"timeout", "manager_disconnect", "target_escape", "rollback_failure"})
_PROPERTY_PROFILES = {
    "cpu_quarter": ("CPUQuotaPerSecUSec", "CPUQuota=25%"),
    "memory_64m": ("MemoryMax", "MemoryMax=67108864"),
}


class _ForbiddenRawArgument:
    """Marker used in schemas for explicitly forbidden raw values."""


def _systemd_spec(
    resource_kind: str = "path", *, arg_schema: dict[str, Any] | None = None,
    required_args: frozenset[str] = frozenset(), reversible: bool = False,
    destructive: bool = False, timeout_s: float = 20.0,
) -> ToolSpec:
    return ToolSpec(
        resource_kind=resource_kind, allowed_executors=_HOST, allowed_tbs=_HH_TB,
        arg_schema=dict(arg_schema or {}), required_args=required_args,
        reversible=reversible, destructive=destructive, timeout_s=timeout_s,
        resource_limits=dict(_SYSTEMD_LIMITS) if destructive else {},
        emergency_stop_conditions=_SYSTEMD_STOPS if destructive else frozenset(),
    )


def _registered_directory(decision: ToolDecision, context: ToolContext) -> str:
    if decision.resource_ref is None: raise ToolInputError("registered fixture directory resource_ref is required")
    path = context.resolve_path(decision.resource_ref)
    if not os.path.isdir(path) or os.path.islink(path) or os.path.realpath(path) != os.path.abspath(path):
        raise ToolPolicyBlocked("resource_ref must be an exact, non-symlink fixture directory")
    return path


def _registered_executable(arguments: dict[str, Any], context: ToolContext) -> str:
    ref = arguments.get("executable_ref")
    if not isinstance(ref, str) or not ref: raise ToolInputError("executable_ref is required")
    path = context.resolve_path(ref)
    if not os.path.isfile(path) or os.path.islink(path) or os.path.realpath(path) != os.path.abspath(path):
        raise ToolPolicyBlocked("executable_ref must be an exact regular fixture executable")
    if not os.access(path, os.X_OK): raise ToolPolicyBlocked("registered fixture executable is not executable")
    if any(character.isspace() or ord(character) < 32 for character in path):
        raise ToolPolicyBlocked("systemd fixture executable path cannot contain whitespace/control characters")
    return path


def _fixture_unit_name(context: ToolContext, suffix: str) -> str:
    digest = hashlib.sha256(f"{context.run_id}:{context.action_id}:{suffix}".encode()).hexdigest()[:16]
    normalized = "".join(character for character in suffix.lower() if character.isalnum())[:16] or "probe"
    return f"osagent-{normalized}-{digest}"


def _safe_child(directory: str, filename: str) -> str:
    if not filename or "/" in filename or "\\" in filename or ".." in filename or "\x00" in filename:
        raise ToolPolicyBlocked("invalid systemd fixture filename")
    path = os.path.join(directory, filename); directory_real = os.path.realpath(directory)
    if os.path.commonpath([directory_real, os.path.realpath(path)]) != directory_real:
        raise ToolPolicyBlocked("systemd fixture path escaped registered directory")
    if os.path.lexists(path) and os.path.islink(path): raise ToolPolicyBlocked("systemd fixture target cannot be a symlink")
    return path


def _run_systemctl(*arguments: str, timeout: int = 12) -> subprocess.CompletedProcess:
    return _run(["systemctl", "--no-pager", *arguments], timeout=timeout)


def _require_completed(completed: subprocess.CompletedProcess, operation: str) -> None:
    if completed.returncode == 0: return
    message = (completed.stderr or completed.stdout or f"{operation} failed").strip()[:300]
    lowered = message.lower()
    code = errno_module.EPERM if any(token in lowered for token in ("permission", "denied", "access", "authentication")) else errno_module.EIO
    raise OSError(code, message)


def _unit_state(unit: str) -> dict[str, Any]:
    properties = ("LoadState", "ActiveState", "SubState", "UnitFileState", "Result", "ExecMainStatus", "FragmentPath", "MainPID")
    completed = _run_systemctl("show", unit, *(f"--property={item}" for item in properties), timeout=8)
    observed: dict[str, Any] = {"unit": unit, "query_exit": completed.returncode}
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in properties: observed[key] = value
    if completed.returncode != 0 and "LoadState" not in observed: observed["LoadState"] = "not-found"
    return observed


def _enabled_state(unit: str) -> dict[str, Any]:
    completed = _run_systemctl("is-enabled", unit, timeout=8)
    return {"state": completed.stdout.strip() or "unknown", "exit_code": completed.returncode}


def _write_regular(path: str, payload: bytes, mode: int = 0o644) -> dict[str, Any]:
    if len(payload) > _SYSTEMD_LIMITS["max_file_bytes"]: raise OSError(errno_module.EFBIG, "unit fixture exceeds 16KiB")
    if os.path.lexists(path): raise ToolPolicyBlocked("independent action requires an absent fixture path")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), mode)
    try: os.write(fd, payload); os.fsync(fd)
    finally: os.close(fd)
    return _file_state(path)


def _file_state(path: str) -> dict[str, Any]:
    if not os.path.lexists(path): return {"path": path, "exists": False}
    info = os.stat(path, follow_symlinks=False)
    value = {"path": path, "exists": True, "mode": stat_module.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid,
             "size": info.st_size, "mtime_ns": info.st_mtime_ns}
    if stat_module.S_ISREG(info.st_mode):
        with open(path, "rb") as stream: value["sha256"] = hashlib.sha256(stream.read(_SYSTEMD_LIMITS["max_file_bytes"] + 1)).hexdigest()
    return value


def _service_payload(executable: str) -> bytes:
    return ("[Unit]\nDescription=OS Agent bounded fixture\n"
            "[Service]\nType=oneshot\nRemainAfterExit=yes\n"
            f"ExecStart={executable}\nExecReload={executable}\n"
            "[Install]\nWantedBy=multi-user.target\n").encode()


def _result(tool: str, action: str, context: ToolContext, identity_before: dict[str, Any], before: dict[str, Any], reached: dict[str, Any], output: str, *, changed: bool = True) -> ToolResult:
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


def _prepare_service(state: dict[str, Any], decision: ToolDecision, context: ToolContext, suffix: str) -> tuple[str, str, str]:
    directory = _registered_directory(decision, context); executable = _registered_executable(decision.arguments, context)
    unit = _fixture_unit_name(context, suffix) + ".service"; path = _safe_child(directory, unit)
    before_entries = sorted(os.listdir(directory)); before = _unit_state(unit)
    if before.get("LoadState") not in {None, "not-found"} or os.path.lexists(path): raise ToolPolicyBlocked("systemd fixture unit already exists")
    _write_regular(path, _service_payload(executable)); state.update(directory=directory, executable=executable, unit=unit, paths=[path], before_entries=before_entries)
    completed = _run_systemctl("daemon-reload"); _require_completed(completed, "daemon-reload")
    loaded = _unit_state(unit)
    if loaded.get("LoadState") != "loaded" or os.path.realpath(loaded.get("FragmentPath", "")) != os.path.realpath(path):
        raise OSError(errno_module.ENOENT, "systemd did not recognize the registered fixture unit")
    return unit, path, json.dumps(before, sort_keys=True)


def _cleanup_units(state: dict[str, Any]) -> tuple[dict[str, Any], dict[str, bool]]:
    unit = state.get("unit")
    if isinstance(unit, str):
        _run_systemctl("disable", "--now", unit)
        _run_systemctl("unmask", unit)
        _run_systemctl("stop", unit)
        _run_systemctl("reset-failed", unit)
    for path in reversed(state.get("paths", [])):
        if os.path.isfile(path) and not os.path.islink(path): os.unlink(path)
    reload_result = _run_systemctl("daemon-reload") if state.get("paths") else None
    observed = _unit_state(unit) if isinstance(unit, str) else {"LoadState": "not-found"}
    directory = state.get("directory"); entries = sorted(os.listdir(directory)) if isinstance(directory, str) and os.path.isdir(directory) else []
    checks = {"unit_not_loaded": observed.get("LoadState") == "not-found",
              "fixture_paths_absent": not any(os.path.lexists(path) for path in state.get("paths", [])),
              "fixture_directory_restored": "before_entries" not in state or entries == state["before_entries"],
              "manager_reloaded": reload_result is None or reload_result.returncode == 0}
    return {"unit": observed, "directory_entries": entries}, checks


def _build_lifecycle_definition(action: str) -> ToolDefinition:
    tool = _LIFECYCLE; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); unit, path, before_json = _prepare_service(state, decision, context, "lifecycle-" + action)
        before = {"unit": json.loads(before_json), "file": {"exists": False}, "directory_entries": state["before_entries"]}
        if action == "start": _require_completed(_run_systemctl("start", unit), "start")
        elif action == "stop":
            _require_completed(_run_systemctl("start", unit), "seed start"); _require_completed(_run_systemctl("stop", unit), "stop")
        elif action == "restart":
            _require_completed(_run_systemctl("start", unit), "seed start"); _require_completed(_run_systemctl("restart", unit), "restart")
        elif action == "reload":
            _require_completed(_run_systemctl("start", unit), "seed start"); _require_completed(_run_systemctl("reload", unit), "reload")
        elif action == "remove":
            os.unlink(path); _require_completed(_run_systemctl("daemon-reload"), "daemon-reload")
        reached = {"unit": _unit_state(unit), "file": _file_state(path)}
        return _result(tool, action, context, identity_before, before, reached, f"systemd fixture lifecycle {action}")
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        observed = {"unit": _unit_state(state["unit"]), "file": _file_state(state["paths"][0])}
        unit_state = observed["unit"]
        if action == "create": checks = {"unit_loaded": unit_state.get("LoadState") == "loaded", "fragment_matches_fixture": os.path.realpath(unit_state.get("FragmentPath", "")) == os.path.realpath(state["paths"][0])}
        elif action in {"start", "restart", "reload"}: checks = {"unit_loaded": unit_state.get("LoadState") == "loaded", "operation_succeeded": unit_state.get("Result") in {"success", ""}, "unit_active": unit_state.get("ActiveState") in {"active", "activating"}}
        elif action == "stop": checks = {"unit_loaded": unit_state.get("LoadState") == "loaded", "unit_stopped": unit_state.get("ActiveState") in {"inactive", "failed"}}
        else: checks = {"unit_removed": unit_state.get("LoadState") == "not-found", "fixture_file_removed": not observed["file"]["exists"]}
        return _verification(name, result, observed, checks, changed=True)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        after, checks = _cleanup_units(state)
        return _reset_result(name, result, after, checks, changed=result.outcome == "ALLOWED")
    schema = {"executable_ref": str, "unit_name": _ForbiddenRawArgument, "exec_start": _ForbiddenRawArgument,
              "description": _ForbiddenRawArgument, "unit_type": _ForbiddenRawArgument}
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _systemd_spec(arg_schema=schema, required_args=frozenset({"executable_ref"}), reversible=True, destructive=action == "remove"))


def _build_enablement_definition(action: str) -> ToolDefinition:
    tool = _ENABLEMENT; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); unit, path, before_json = _prepare_service(state, decision, context, "enable-" + action)
        before = {"unit": json.loads(before_json), "enabled": _enabled_state(unit), "file": {"exists": False}}
        if action == "enable": completed = _run_systemctl("enable", unit)
        elif action == "disable":
            _require_completed(_run_systemctl("enable", unit), "seed enable"); completed = _run_systemctl("disable", unit)
        elif action == "mask": completed = _run_systemctl("mask", unit)
        else:
            _require_completed(_run_systemctl("mask", unit), "seed mask"); completed = _run_systemctl("unmask", unit)
        _require_completed(completed, action); reached = {"unit": _unit_state(unit), "enabled": _enabled_state(unit), "file": _file_state(path)}
        return _result(tool, action, context, identity_before, before, reached, f"systemd fixture enablement {action}")
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        enabled = _enabled_state(state["unit"]); observed = {"enabled": enabled, "unit": _unit_state(state["unit"])}
        expected = {"enable": {"enabled", "enabled-runtime", "linked", "linked-runtime"}, "disable": {"disabled", "static", "indirect"}, "mask": {"masked", "masked-runtime"}, "unmask": {"disabled", "static", "indirect"}}[action]
        checks = {"enablement_requeried": enabled["state"] in expected, "unit_still_loaded": observed["unit"].get("LoadState") == "loaded"}
        return _verification(name, result, observed, checks, changed=True)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        after, checks = _cleanup_units(state); return _reset_result(name, result, after, checks, changed=result.outcome == "ALLOWED")
    schema = {"executable_ref": str, "unit_name": _ForbiddenRawArgument}
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _systemd_spec(arg_schema=schema, required_args=frozenset({"executable_ref"}), reversible=True))


def _trigger_payload(kind: str, service: str, marker_path: str) -> bytes:
    if kind == "timer": return f"[Unit]\nDescription=OS Agent timer fixture\n[Timer]\nOnActiveSec=30s\nUnit={service}\n[Install]\nWantedBy=timers.target\n".encode()
    if kind == "path": return f"[Unit]\nDescription=OS Agent path fixture\n[Path]\nPathChanged={marker_path}\nUnit={service}\n[Install]\nWantedBy=multi-user.target\n".encode()
    return f"[Unit]\nDescription=OS Agent socket fixture\n[Socket]\nListenStream={marker_path}.sock\nService={service}\n[Install]\nWantedBy=sockets.target\n".encode()


def _prepare_trigger(state: dict[str, Any], decision: ToolDecision, context: ToolContext, kind: str) -> tuple[str, str]:
    directory = _registered_directory(decision, context); executable = _registered_executable(decision.arguments, context)
    base = _fixture_unit_name(context, "trigger-" + kind); service = base + ".service"; trigger = base + "." + kind
    service_path = _safe_child(directory, service); trigger_path = _safe_child(directory, trigger); marker_path = _safe_child(directory, base + ".marker")
    before_entries = sorted(os.listdir(directory))
    if any(os.path.lexists(path) for path in (service_path, trigger_path, marker_path, marker_path + ".sock")): raise ToolPolicyBlocked("trigger fixture already exists")
    _write_regular(service_path, _service_payload(executable)); state.update(directory=directory, unit=trigger, service=service, paths=[service_path, trigger_path], marker_path=marker_path, before_entries=before_entries)
    _write_regular(trigger_path, _trigger_payload(kind, service, marker_path)); _require_completed(_run_systemctl("daemon-reload"), "daemon-reload")
    if _unit_state(service).get("LoadState") != "loaded" or _unit_state(trigger).get("LoadState") != "loaded": raise OSError(errno_module.ENOENT, "systemd did not recognize trigger fixture")
    return trigger, service


def _build_trigger_definition(action: str) -> ToolDefinition:
    tool = _TRIGGER; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); kind = {"create_timer": "timer", "create_path": "path", "create_socket": "socket"}.get(action, "timer")
        trigger, service = _prepare_trigger(state, decision, context, kind); before = {"trigger": {"LoadState": "not-found"}, "directory_entries": state["before_entries"]}
        if action.startswith("create_"):
            _require_completed(_run_systemctl("enable", trigger), "enable trigger")
        elif action == "trigger":
            _require_completed(_run_systemctl("start", service), "trigger service")
        else:
            _run_systemctl("disable", "--now", trigger)
            for path in list(state["paths"]):
                if os.path.isfile(path): os.unlink(path)
            _require_completed(_run_systemctl("daemon-reload"), "daemon-reload")
        reached = {"trigger": _unit_state(trigger), "service": _unit_state(service), "enabled": _enabled_state(trigger),
                   "files": [_file_state(path) for path in state["paths"]]}
        return _result(tool, action, context, identity_before, before, reached, f"systemd trigger fixture {action}")
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        observed = {"trigger": _unit_state(state["unit"]), "service": _unit_state(state["service"]), "enabled": _enabled_state(state["unit"]),
                    "files": [_file_state(path) for path in state["paths"]]}
        if action.startswith("create_"): checks = {"trigger_loaded": observed["trigger"].get("LoadState") == "loaded", "trigger_enabled": observed["enabled"]["state"] in {"enabled", "enabled-runtime"}, "service_loaded": observed["service"].get("LoadState") == "loaded"}
        elif action == "trigger": checks = {"service_execution_requeried": observed["service"].get("Result") in {"success", ""}, "service_active": observed["service"].get("ActiveState") == "active"}
        else: checks = {"trigger_removed": observed["trigger"].get("LoadState") == "not-found", "service_removed": observed["service"].get("LoadState") == "not-found", "files_removed": not any(item["exists"] for item in observed["files"])}
        return _verification(name, result, observed, checks, changed=True)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        # companion service and trigger are both fixture-owned and removed together.
        for unit in (state.get("unit"), state.get("service")):
            if isinstance(unit, str): _run_systemctl("disable", "--now", unit); _run_systemctl("stop", unit); _run_systemctl("reset-failed", unit)
        marker = state.get("marker_path")
        for extra in (marker, marker + ".sock" if isinstance(marker, str) else None):
            if isinstance(extra, str) and os.path.lexists(extra) and not os.path.isdir(extra): os.unlink(extra)
        for path in reversed(state.get("paths", [])):
            if os.path.isfile(path) and not os.path.islink(path): os.unlink(path)
        reload_result = _run_systemctl("daemon-reload") if state.get("paths") else None
        observed = {"trigger": _unit_state(state["unit"]) if state.get("unit") else {"LoadState": "not-found"},
                    "service": _unit_state(state["service"]) if state.get("service") else {"LoadState": "not-found"}}
        entries = sorted(os.listdir(state["directory"])) if state.get("directory") else []
        checks = {"trigger_absent": observed["trigger"].get("LoadState") == "not-found", "service_absent": observed["service"].get("LoadState") == "not-found",
                  "fixture_directory_restored": "before_entries" not in state or entries == state["before_entries"], "manager_reloaded": reload_result is None or reload_result.returncode == 0}
        return _reset_result(name, result, {**observed, "directory_entries": entries}, checks, changed=result.outcome == "ALLOWED")
    schema = {"executable_ref": str, "unit_name": _ForbiddenRawArgument, "schedule": _ForbiddenRawArgument,
              "path": _ForbiddenRawArgument, "listen": _ForbiddenRawArgument}
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _systemd_spec(arg_schema=schema, required_args=frozenset({"executable_ref"}), reversible=True, destructive=action == "remove"))


def _primary_executable(decision: ToolDecision, context: ToolContext) -> str:
    if decision.resource_ref is None: raise ToolInputError("registered executable resource_ref is required")
    path = context.resolve_path(decision.resource_ref)
    if not os.path.isfile(path) or os.path.islink(path) or os.path.realpath(path) != os.path.abspath(path) or not os.access(path, os.X_OK):
        raise ToolPolicyBlocked("resource_ref must be an exact executable fixture")
    if any(character.isspace() or ord(character) < 32 for character in path): raise ToolPolicyBlocked("fixture executable path cannot contain whitespace/control characters")
    return path


def _transient_state(unit: str) -> dict[str, Any]:
    return _unit_state(unit)


def _build_transient_definition(action: str) -> ToolDefinition:
    tool = _TRANSIENT; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); executable = _primary_executable(decision, context)
        suffix = ".scope" if action == "scope" else ".service"; unit = _fixture_unit_name(context, "transient-" + action) + suffix
        before = _transient_state(unit)
        if before.get("LoadState") not in {None, "not-found"}: raise ToolPolicyBlocked("transient fixture unit already exists")
        state.update(unit=unit, executable=executable)
        if action == "service": argv = ["systemd-run", "--unit", unit, "--property=Type=oneshot", "--property=RemainAfterExit=yes", "--runtime-max-sec=15", executable]
        else: argv = ["systemd-run", "--scope", "--unit", unit, "--property=RuntimeMaxSec=15", executable]
        completed = _run(argv, timeout=18); _require_completed(completed, "systemd-run")
        reached = _transient_state(unit); state["command_exit"] = completed.returncode
        return _result(tool, action, context, identity_before, before, reached, f"systemd transient {action}")
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        observed = _transient_state(state["unit"])
        if action == "service": checks = {"unit_requeried": observed.get("LoadState") == "loaded", "execution_succeeded": observed.get("Result") in {"success", ""}, "unit_active": observed.get("ActiveState") == "active"}
        else: checks = {"manager_requery_completed": isinstance(observed.get("query_exit"), int), "scope_execution_completed": state.get("command_exit") == 0, "scope_not_failed": observed.get("ActiveState") != "failed"}
        return _verification(name, result, observed, checks, changed=True)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        unit = state.get("unit")
        if isinstance(unit, str): _run_systemctl("stop", unit); _run_systemctl("reset-failed", unit)
        deadline = time.monotonic() + 3; after = _transient_state(unit) if isinstance(unit, str) else {"LoadState": "not-found"}
        while after.get("LoadState") != "not-found" and time.monotonic() < deadline:
            time.sleep(0.05); after = _transient_state(unit)
        checks = {"transient_unit_absent": after.get("LoadState") == "not-found"}
        return _reset_result(name, result, after, checks, changed=result.outcome == "ALLOWED")
    schema = {"exec_cmd": _ForbiddenRawArgument, "command": _ForbiddenRawArgument, "unit_name": _ForbiddenRawArgument}
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _systemd_spec(arg_schema=schema, reversible=True, timeout_s=22.0))


def _build_property_definition(action: str) -> ToolDefinition:
    tool = _PROPERTY; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); unit, _path, before_json = _prepare_service(state, decision, context, "property-" + action)
        before = {"unit": json.loads(before_json), "file": {"exists": False}}
        if action == "get":
            property_name = decision.arguments.get("property_profile", "active_state")
            allowed = {"active_state": "ActiveState", "main_pid": "MainPID", "fragment_path": "FragmentPath"}
            if "property" in decision.arguments or property_name not in allowed: raise ToolInputError(f"property_profile must be one of {sorted(allowed)}")
            state["property"] = allowed[property_name]; reached = {"unit": _unit_state(unit), "property": allowed[property_name]}
        else:
            profile = decision.arguments.get("property_profile", "cpu_quarter")
            if any(key in decision.arguments for key in ("property", "value")) or profile not in _PROPERTY_PROFILES: raise ToolInputError(f"property_profile must be one of {sorted(_PROPERTY_PROFILES)}")
            show_property, assignment = _PROPERTY_PROFILES[profile]; state.update(property=show_property, assignment=assignment)
            _require_completed(_run_systemctl("start", unit), "start property fixture")
            original = _run_systemctl("show", unit, f"--property={show_property}", "--value").stdout.strip(); state["original_value"] = original
            _require_completed(_run_systemctl("set-property", "--runtime", unit, assignment), "set-property")
            reached = {"unit": _unit_state(unit), "property": show_property, "value": _run_systemctl("show", unit, f"--property={show_property}", "--value").stdout.strip()}
        return _result(tool, action, context, identity_before, before, reached, f"systemd unit property {action}")
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        unit = _unit_state(state["unit"]); completed = _run_systemctl("show", state["unit"], f"--property={state['property']}", "--value")
        observed = {"unit": unit, "property": state["property"], "value": completed.stdout.strip(), "query_exit": completed.returncode}
        if action == "get": checks = {"unit_loaded": unit.get("LoadState") == "loaded", "property_requeried": completed.returncode == 0 and observed["value"] != ""}
        else:
            expected_profile = decision.arguments.get("property_profile", "cpu_quarter")
            expected = "250ms" if expected_profile == "cpu_quarter" else "67108864"
            checks = {"property_requeried": completed.returncode == 0, "property_changed": observed["value"] in {expected, "25%", "64M"}}
        return _verification(name, result, observed, checks, changed=True)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        # Removing the transient runtime property with the fixture unit restores the absent baseline.
        after, checks = _cleanup_units(state); return _reset_result(name, result, after, checks, changed=result.outcome == "ALLOWED")
    schema = {"executable_ref": str, "property_profile": str, "unit_name": _ForbiddenRawArgument,
              "property": _ForbiddenRawArgument, "value": _ForbiddenRawArgument}
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _systemd_spec(arg_schema=schema, required_args=frozenset({"executable_ref"}), reversible=True))


def _manager_state() -> dict[str, Any]:
    completed = _run_systemctl("show", "--property=Version", "--property=ManagerTimestampMonotonic", "--property=SystemState")
    observed: dict[str, Any] = {"query_exit": completed.returncode}
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator: observed[key] = value
    return observed


def _build_manager_definition(action: str) -> ToolDefinition:
    tool = _MANAGER; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); directory = _registered_directory(decision, context); before = _manager_state(); state.update(directory=directory, before=before)
        command = "daemon-reload" if action == "daemon_reload" else "daemon-reexec"
        _require_completed(_run_systemctl(command, timeout=15), command); reached = _manager_state()
        return _result(tool, action, context, identity_before, before, reached, f"systemd manager {command}", changed=action == "reexec_probe")
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        observed = _manager_state(); checks = {"manager_requeried": observed.get("query_exit") == 0, "manager_version_present": bool(observed.get("Version")), "manager_not_offline": observed.get("SystemState") not in {"offline", "stopping"}}
        return _verification(name, result, observed, checks, changed=action == "reexec_probe")
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        reload_result = _run_systemctl("daemon-reload", timeout=15) if action == "reexec_probe" and result.outcome == "ALLOWED" else None
        after = _manager_state(); checks = {"manager_responsive": after.get("query_exit") == 0,
                                           "manager_version_restored": not state.get("before", {}).get("Version") or after.get("Version") == state["before"].get("Version"),
                                           "fixture_directory_unchanged": bool(state.get("directory") and os.path.isdir(state["directory"])),
                                           "manager_configuration_reloaded": reload_result is None or reload_result.returncode == 0}
        return _reset_result(name, result, after, checks, changed=action == "reexec_probe" and result.outcome == "ALLOWED")
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _systemd_spec(reversible=False, destructive=action == "reexec_probe", timeout_s=20.0))


def _registered_username(decision: ToolDecision, context: ToolContext) -> str:
    if decision.resource_ref is None: raise ToolInputError("registered user resource_ref is required")
    value = context.resolve_resource(decision.resource_ref)
    if not isinstance(value, str) or not value or len(value) > 32 or not all(character.isalnum() or character in "_-" for character in value):
        raise ToolPolicyBlocked("resource_ref does not resolve to a bounded fixture username")
    return value


def _linger_state(user: str) -> dict[str, Any]:
    completed = _run(["loginctl", "show-user", user, "--property=Linger", "--value", "--no-pager"], timeout=8)
    return {"user": user, "query_exit": completed.returncode, "linger": completed.stdout.strip().lower(), "error": (completed.stderr or "")[:200]}


def _build_linger_definition(action: str) -> ToolDefinition:
    tool = _LINGER; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); user = _registered_username(decision, context); before = _linger_state(user)
        if before["query_exit"] != 0: raise OSError(errno_module.ENOENT, before["error"] or "fixture user not known to logind")
        state.update(user=user, original=before["linger"]); command = "enable-linger" if action == "enable" else "disable-linger"
        completed = _run(["loginctl", command, user], timeout=10); _require_completed(completed, command); reached = _linger_state(user)
        return _result(tool, action, context, identity_before, before, reached, f"logind fixture linger {action}")
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        observed = _linger_state(state["user"]); expected = "yes" if action == "enable" else "no"
        return _verification(name, result, observed, {"linger_requeried": observed["query_exit"] == 0, "target_reached": observed["linger"] == expected}, changed=True)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        user = state.get("user"); original = state.get("original")
        if isinstance(user, str) and original in {"yes", "no"}: _run(["loginctl", "enable-linger" if original == "yes" else "disable-linger", user], timeout=10)
        after = _linger_state(user) if isinstance(user, str) else {"query_exit": 1, "linger": ""}
        checks = {"original_linger_restored": original not in {"yes", "no"} or after["linger"] == original}
        return _reset_result(name, result, after, checks, changed=result.outcome == "ALLOWED")
    schema = {"user": _ForbiddenRawArgument, "username": _ForbiddenRawArgument}
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _systemd_spec(resource_kind="service", arg_schema=schema, reversible=True, destructive=True))


def _build_scope_definition() -> ToolDefinition:
    tool = _SCOPE; action = "run"; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); executable = _primary_executable(decision, context); profile = decision.arguments.get("resource_profile", "bounded")
        profiles = {"bounded": ("CPUQuota=25%", "MemoryMax=67108864"), "cpu_only": ("CPUQuota=25%",), "memory_only": ("MemoryMax=67108864",)}
        if any(key in decision.arguments for key in ("exec_cmd", "cpu_quota", "memory_max", "property")) or profile not in profiles:
            raise ToolInputError(f"resource_profile must be one of {sorted(profiles)}")
        unit = _fixture_unit_name(context, "scope") + ".scope"; before = _unit_state(unit)
        if before.get("LoadState") not in {None, "not-found"}: raise ToolPolicyBlocked("scope fixture already exists")
        argv = ["systemd-run", "--scope", "--unit", unit, "--property=RuntimeMaxSec=15"]
        for assignment in profiles[profile]: argv.extend(["--property", assignment])
        argv.append(executable); completed = _run(argv, timeout=18); _require_completed(completed, "systemd scope run")
        state.update(unit=unit, profile=profile, command_exit=completed.returncode); reached = _unit_state(unit)
        return _result(tool, action, context, identity_before, before, reached, "bounded systemd scope run")
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        observed = _unit_state(state["unit"]); checks = {"manager_requery_completed": isinstance(observed.get("query_exit"), int), "scope_command_completed": state.get("command_exit") == 0, "scope_not_failed": observed.get("ActiveState") != "failed"}
        return _verification(name, result, observed, checks, changed=True)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        unit = state.get("unit")
        if isinstance(unit, str): _run_systemctl("stop", unit); _run_systemctl("reset-failed", unit)
        deadline = time.monotonic() + 3; after = _unit_state(unit) if isinstance(unit, str) else {"LoadState": "not-found"}
        while after.get("LoadState") != "not-found" and time.monotonic() < deadline:
            time.sleep(0.05); after = _unit_state(unit)
        return _reset_result(name, result, after, {"scope_absent": after.get("LoadState") == "not-found"}, changed=result.outcome == "ALLOWED")
    schema = {"resource_profile": str, "exec_cmd": _ForbiddenRawArgument, "cpu_quota": _ForbiddenRawArgument,
              "memory_max": _ForbiddenRawArgument, "property": _ForbiddenRawArgument, "unit_name": _ForbiddenRawArgument}
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _systemd_spec(arg_schema=schema, reversible=True, timeout_s=22.0))


def _registered_hostname(decision: ToolDecision, context: ToolContext) -> str:
    if decision.resource_ref is None: raise ToolInputError("registered hostname resource_ref is required")
    value = context.resolve_resource(decision.resource_ref)
    if not isinstance(value, str) or not (1 <= len(value) <= 63) or value.startswith("-") or value.endswith("-") or not all(character.isalnum() or character == "-" for character in value):
        raise ToolPolicyBlocked("resource_ref does not resolve to an allowlisted fixture hostname")
    return value.lower()


def _hostname_state() -> dict[str, Any]:
    completed = _run(["hostnamectl", "--static"], timeout=8)
    if completed.returncode == 0 and completed.stdout.strip(): return {"hostname": completed.stdout.strip(), "query": "hostnamectl", "query_exit": 0}
    try: fallback = os.uname().nodename
    except AttributeError: fallback = os.environ.get("COMPUTERNAME", "unknown")
    return {"hostname": fallback, "query": "uname", "query_exit": completed.returncode}


def _build_hostname_definition(action: str) -> ToolDefinition:
    tool = _HOSTNAME; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); target = _registered_hostname(decision, context); before = _hostname_state(); state.update(original=before["hostname"], target=target)
        if action == "set_probe":
            completed = _run(["hostnamectl", "set-hostname", "--static", target], timeout=10); _require_completed(completed, "hostname set")
        reached = _hostname_state()
        return _result(tool, action, context, identity_before, before, reached, f"hostname {action}", changed=action == "set_probe")
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        observed = _hostname_state(); checks = {"hostname_requeried": bool(observed.get("hostname"))}
        if action == "set_probe": checks["target_reached"] = observed["hostname"].lower() == state["target"]
        return _verification(name, result, observed, checks, changed=action == "set_probe")
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        original = state.get("original")
        if action == "set_probe" and isinstance(original, str) and original: _run(["hostnamectl", "set-hostname", "--static", original], timeout=10)
        after = _hostname_state(); checks = {"hostname_restored": action != "set_probe" or after.get("hostname") == original}
        return _reset_result(name, result, after, checks, changed=result.outcome == "ALLOWED" and action == "set_probe")
    schema = {"hostname": _ForbiddenRawArgument}
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _systemd_spec(resource_kind="service", arg_schema=schema, reversible=action == "set_probe", destructive=action == "set_probe"))


_SYSTEMD_DEFINITIONS: tuple[ToolDefinition, ...] = (
    *(_build_lifecycle_definition(action) for action in ("create", "start", "stop", "restart", "reload", "remove")),
    *(_build_enablement_definition(action) for action in ("enable", "disable", "mask", "unmask")),
    *(_build_trigger_definition(action) for action in ("create_timer", "create_path", "create_socket", "trigger", "remove")),
    *(_build_transient_definition(action) for action in ("service", "scope")),
    *(_build_property_definition(action) for action in ("get", "set_runtime")),
    *(_build_manager_definition(action) for action in ("daemon_reload", "reexec_probe")),
    *(_build_linger_definition(action) for action in ("enable", "disable")),
    _build_scope_definition(),
    *(_build_hostname_definition(action) for action in ("get", "set_probe")),
)

if len(_SYSTEMD_DEFINITIONS) != 26: raise ToolContractError(f"systemd_privilege ToolDefinition must contain 26 actions: {len(_SYSTEMD_DEFINITIONS)}")
if len({definition.name for definition in _SYSTEMD_DEFINITIONS}) != 26: raise ToolContractError("systemd_privilege ToolDefinition names are not unique")
for _attribute in ("handler", "verifier", "resetter"):
    if len({id(getattr(definition, _attribute)) for definition in _SYSTEMD_DEFINITIONS}) != 26:
        raise ToolContractError(f"systemd_privilege actions do not have independent {_attribute} closures")
for _definition in _SYSTEMD_DEFINITIONS: register_definition(_definition)
