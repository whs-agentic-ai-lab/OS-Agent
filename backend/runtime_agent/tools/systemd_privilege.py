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
import os
import subprocess
from pathlib import Path
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
)

_NONE = "none"
_HOST = frozenset({"host"})
_HH_TB = frozenset({"TB-HH-U1U2"})
_SYSTEM_DIR = Path("/etc/systemd/system")


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
    arg_schema={"unit_name": str, "exec_start": str, "description": str, "unit_type": str},
    required_args=frozenset({"unit_name", "exec_start"}), reversible=True), reset=_unit_file_reset)
def _lifecycle_create(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    unit = _safe_unit_name(str_arg(arguments, "unit_name"))
    exec_start = str_arg(arguments, "exec_start")
    description = arguments.get("description", "osagent unit")
    unit_type = arguments.get("unit_type", "simple")
    unit_path = _SYSTEM_DIR / (unit if unit.endswith(".service") else f"{unit}.service")

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


@register(_LIFECYCLE, "remove", spec=_spec(arg_schema={"unit_name": str}, required_args=frozenset({"unit_name"}), destructive=True))
def _lifecycle_remove(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    unit = _safe_unit_name(str_arg(arguments, "unit_name"))
    unit_path = _SYSTEM_DIR / (unit if "." in unit else f"{unit}.service")

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


@register(_TRIGGER, "create_timer", spec=_spec(arg_schema={"unit_name": str}, required_args=frozenset({"unit_name"}), reversible=True), reset=_trigger_reset)
@register(_TRIGGER, "create_path", spec=_spec(arg_schema={"unit_name": str}, required_args=frozenset({"unit_name"}), reversible=True), reset=_trigger_reset)
@register(_TRIGGER, "create_socket", spec=_spec(arg_schema={"unit_name": str}, required_args=frozenset({"unit_name"}), reversible=True), reset=_trigger_reset)
def _trigger_create(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    unit = _safe_unit_name(str_arg(arguments, "unit_name"))
    suffix, body = _TRIGGER_KINDS[action]
    unit_path = _SYSTEM_DIR / (unit if unit.endswith(f".{suffix}") else f"{unit}.{suffix}")

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


@register(_TRIGGER, "remove", spec=_spec(arg_schema={"unit_name": str}, required_args=frozenset({"unit_name"}), destructive=True))
def _trigger_remove(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    unit = _safe_unit_name(str_arg(arguments, "unit_name"))

    def _op() -> str:
        removed = []
        for suffix in ("timer", "path", "socket"):
            p = _SYSTEM_DIR / (unit if unit.endswith(f".{suffix}") else f"{unit}.{suffix}")
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
