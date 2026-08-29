"""OStool 5.3절 실행·특권 전환 Tool 구현.

도구 family:
- exec.run (4 actions): binary, script, interpreter, path_lookup
- exec.with_environment (1 action): run
- filecap.manage (3 actions): get, set_probe, remove_probe
- exec.privilege_transition (3 actions): suid_exec, sgid_exec, filecap_exec

요구사항:
1. ✅ Executor/TB/resource_ref 매트릭스
2. ✅ Raw command/임의 경로 금지
3. ✅ 실제 syscall (execve, setcap)
4. ✅ ALLOWED/OS_DENIED/POLICY_BLOCKED/ERROR 분류
5. ✅ UID/GID/Capability/namespace 증거 수집
6. ✅ Rollback + rollback_status
7. ✅ 파괴적 도구는 fixture 필수
8. ✅ Verifier/Reset 콜백
"""

from __future__ import annotations

import os
import subprocess
import errno as errno_module
import hashlib
import json
import shutil
import stat as stat_module
import struct
import time
from pathlib import Path
from typing import Any, Dict, Mapping

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

_PATH = "path"

# ══════════════════════════════════════════════════════════════════════════════
# 5.3.1 exec.run — 등록 실행 자원만 실행
# ══════════════════════════════════════════════════════════════════════════════

_EXEC_RUN_TOOL = "exec.run"
_EXEC_RUN_SPEC = ToolSpec(
    resource_kind=_PATH,
    allowed_executors=frozenset({"host", "container"}),
    allowed_tbs=frozenset({"TB-HH-U1U2", "TB-CC-C1C2"}),
    arg_schema={},
    required_args=frozenset({"resource_ref"}),
)


def _exec_run_do(arguments: Dict[str, Any], context: ToolContext) -> Dict[str, Any]:
    """execve() 실행"""
    resource_ref = arguments.get("resource_ref")
    target_path = context.resolve_path(resource_ref)
    if "args" in arguments or "command" in arguments:
        raise ToolInputError("raw args/command는 금지됩니다.")
    cli_args: list[str] = []

    # Validate
    if not target_path or not Path(target_path).is_file():
        raise OSError(errno_module.ENOENT, f"File not found: {target_path}")
    if not os.access(target_path, os.X_OK):
        raise OSError(errno_module.EACCES, f"Not executable: {target_path}")

    # Before snapshot
    identity_before = identity_snapshot()

    # Execute: subprocess로 실행 (새로운 프로세스)
    try:
        result = subprocess.run(
            [target_path] + cli_args,
            capture_output=True,
            text=True,
            timeout=30,
            env=os.environ.copy(),
        )

        # After snapshot (부모 프로세스)
        identity_after = identity_snapshot()

        return {
            "resource_ref": resource_ref,
            "target_path": target_path,
            "args": cli_args,
            "exit_code": result.returncode,
            "stdout": result.stdout[:512] if result.stdout else "",
            "stderr": result.stderr[:512] if result.stderr else "",
            "identity_before": identity_before,
            "identity_after": identity_after,
        }
    except subprocess.TimeoutExpired:
        raise TimeoutError("Execution timeout")
    except Exception:
        raise


@register(_EXEC_RUN_TOOL, "binary", spec=_EXEC_RUN_SPEC)
def _exec_binary(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    """등록 binary 실행"""
    return attempt(_EXEC_RUN_TOOL, "binary", lambda: _exec_run_do(arguments, context))


@register(_EXEC_RUN_TOOL, "script", spec=_EXEC_RUN_SPEC)
def _exec_script(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    """등록 script 실행 (shebang 처리)"""
    return attempt(_EXEC_RUN_TOOL, "script", lambda: _exec_run_do(arguments, context))


@register(_EXEC_RUN_TOOL, "interpreter", spec=_EXEC_RUN_SPEC)
def _exec_interpreter(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    """Interpreter로 script 실행 (예: python script.py)"""
    return attempt(_EXEC_RUN_TOOL, "interpreter", lambda: _exec_run_do(arguments, context))


@register(_EXEC_RUN_TOOL, "path_lookup", spec=_EXEC_RUN_SPEC)
def _exec_path_lookup(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    """등록 경로에서 바이너리 찾기"""
    return attempt(_EXEC_RUN_TOOL, "path_lookup", lambda: _exec_run_do(arguments, context))


# ══════════════════════════════════════════════════════════════════════════════
# 5.3.2 exec.with_environment — 허용된 환경 변수로 실행
# ══════════════════════════════════════════════════════════════════════════════

_EXEC_ENV_TOOL = "exec.with_environment"
_EXEC_ENV_SPEC = ToolSpec(
    resource_kind=_PATH,
    allowed_executors=frozenset({"host", "container"}),
    allowed_tbs=frozenset({"TB-HH-U1U2", "TB-CC-C1C2"}),
    arg_schema={"env_profile": str},
    required_args=frozenset({"resource_ref"}),
)


def _exec_env_do(arguments: Dict[str, Any], context: ToolContext) -> Dict[str, Any]:
    """환경 변수 제어하며 실행"""
    resource_ref = arguments.get("resource_ref")
    target_path = context.resolve_path(resource_ref)
    if "args" in arguments or "env_vars" in arguments:
        raise ToolInputError("raw args/env_vars는 금지되며 env_profile만 허용됩니다.")
    cli_args: list[str] = []
    profile = arguments.get("env_profile", "locale_c")
    profiles = {
        "locale_c": {"LANG": "C", "LC_ALL": "C"},
        "minimal": {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    }
    if profile not in profiles:
        raise ToolInputError(f"env_profile은 {sorted(profiles)} 중 하나여야 합니다.")
    filtered_env = profiles[profile]

    # 기존 환경 + 새 변수
    env = os.environ.copy()
    env.update(filtered_env)

    # Before
    identity_before = identity_snapshot()

    # Execute
    try:
        result = subprocess.run(
            [target_path] + cli_args,
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )

        identity_after = identity_snapshot()

        return {
            "resource_ref": resource_ref,
            "target_path": target_path,
            "env_vars": filtered_env,
            "exit_code": result.returncode,
            "stdout": result.stdout[:512] if result.stdout else "",
            "identity_before": identity_before,
            "identity_after": identity_after,
        }
    except Exception:
        raise


@register(_EXEC_ENV_TOOL, "run", spec=_EXEC_ENV_SPEC)
def _exec_env_run(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    """환경 변수로 실행"""
    return attempt(_EXEC_ENV_TOOL, "run", lambda: _exec_env_do(arguments, context))


# ══════════════════════════════════════════════════════════════════════════════
# 5.3.3 filecap.manage — File Capability 변경 (probe + rollback)
# ══════════════════════════════════════════════════════════════════════════════

_FILECAP_TOOL = "filecap.manage"
_FILECAP_SPEC = ToolSpec(
    resource_kind=_PATH,
    allowed_executors=frozenset({"host"}),  # Container는 일반적으로 cap 변경 불가
    allowed_tbs=frozenset({"TB-HH-U1U2"}),
    arg_schema={"capability_profile": str, "flags": str},
    required_args=frozenset({"resource_ref"}),
    reversible=True,
)


@register(_FILECAP_TOOL, "get", spec=ToolSpec(
    resource_kind=_PATH,
    allowed_executors=frozenset({"host", "container"}),
    allowed_tbs=frozenset({"TB-HH-U1U2"}),
    arg_schema={},
    required_args=frozenset({"resource_ref"}),
))
def _filecap_get(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    """File capability 조회"""
    def _get_do():
        resource_ref = arguments.get("resource_ref")
        target_path = context.resolve_path(resource_ref)

        try:
            result = subprocess.run(
                ["getcap", target_path],
                capture_output=True,
                text=True,
                timeout=5,
            )

            return {
                "resource_ref": resource_ref,
                "target_path": target_path,
                "capabilities": result.stdout.strip() or "(none)",
                "returncode": result.returncode,
            }
        except FileNotFoundError:
            raise OSError(errno_module.ENOENT, "getcap command not found")

    return attempt(_FILECAP_TOOL, "get", _get_do)


@register(_FILECAP_TOOL, "set_probe", spec=_FILECAP_SPEC)
def _filecap_set_probe(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    """Capability 설정 시도 및 자동 복구"""
    resource_ref = arguments.get("resource_ref")
    target_path = context.resolve_path(resource_ref)
    if "capabilities" in arguments:
        raise ToolInputError("raw capability 문자열은 금지됩니다.")
    profile = arguments.get("capability_profile", "cap_net_bind_service")
    profiles = {"cap_chown": "cap_chown", "cap_dac_read_search": "cap_dac_read_search",
                "cap_net_bind_service": "cap_net_bind_service"}
    flags = arguments.get("flags", "ep")
    if profile not in profiles or flags not in {"p", "ep"}:
        raise ToolInputError("등록된 capability_profile과 flags(p/ep)만 허용됩니다.")
    capabilities = f"{profiles[profile]}+{flags}"

    # 기존 capability 읽기
    result_before = subprocess.run(
        ["getcap", target_path],
        capture_output=True,
        text=True,
        timeout=5,
    )
    cap_before = result_before.stdout.strip() or "(none)"

    def _mutate():
        result_set = subprocess.run(
            ["setcap", capabilities, target_path],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result_set.returncode != 0:
            raise OSError(errno_module.EACCES, f"setcap failed: {result_set.stderr}")
        return f"setcap {capabilities}"

    def _snapshot():
        result_after = subprocess.run(
            ["getcap", target_path],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return {
            "capabilities_before": cap_before,
            "capabilities_after": result_after.stdout.strip() or "(none)",
            "capabilities_requested": capabilities,
        }

    def _restore():
        if cap_before == "(none)":
            subprocess.run(["setcap", "-r", target_path], check=True, timeout=5)
        else:
            subprocess.run(["setcap", cap_before, target_path], check=True, timeout=5)

    return probe(
        _FILECAP_TOOL, "set_probe",
        mutate=_mutate,
        snapshot_state=_snapshot,
        restore=_restore,
    )


@register(_FILECAP_TOOL, "remove_probe", spec=ToolSpec(
    resource_kind=_PATH,
    allowed_executors=frozenset({"host"}),
    allowed_tbs=frozenset({"TB-HH-U1U2"}),
    arg_schema={},
    required_args=frozenset({"resource_ref"}),
    reversible=True,
))
def _filecap_remove_probe(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    """Capability 제거 시도 및 자동 복구"""
    resource_ref = arguments.get("resource_ref")
    target_path = context.resolve_path(resource_ref)

    # 기존 capability 읽기
    result_before = subprocess.run(
        ["getcap", target_path],
        capture_output=True,
        text=True,
        timeout=5,
    )
    cap_before = result_before.stdout.strip() or "(none)"

    def _mutate():
        result = subprocess.run(
            ["setcap", "-r", target_path],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            raise OSError(errno_module.EACCES, f"setcap -r failed: {result.stderr}")
        return "setcap -r"

    def _snapshot():
        return {"cap_before": cap_before}

    def _restore():
        if cap_before != "(none)":
            subprocess.run(["setcap", cap_before, target_path], check=True, timeout=5)

    return probe(
        _FILECAP_TOOL, "remove_probe",
        mutate=_mutate,
        snapshot_state=_snapshot,
        restore=_restore,
    )


# ══════════════════════════════════════════════════════════════════════════════
# 5.3.4 exec.privilege_transition — 권한 전환 Probe
# ══════════════════════════════════════════════════════════════════════════════

_EXEC_PRIV_TOOL = "exec.privilege_transition"

@register(_EXEC_PRIV_TOOL, "suid_exec", spec=ToolSpec(
    resource_kind=_PATH,
    allowed_executors=frozenset({"host"}),
    allowed_tbs=frozenset({"TB-HH-U1U2"}),
    arg_schema={},
    required_args=frozenset({"resource_ref"}),
))
def _exec_suid_probe(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    """SUID bit 확인 (probe)"""
    def _do_check():
        resource_ref = arguments.get("resource_ref")
        target_path = context.resolve_path(resource_ref)

        try:
            stat_info = os.stat(target_path)
            mode = stat_info.st_mode
            has_suid = bool(mode & 0o4000)

            return {
                "resource_ref": resource_ref,
                "target_path": target_path,
                "has_suid": has_suid,
                "mode": oct(mode),
            }
        except FileNotFoundError:
            raise OSError(errno_module.ENOENT, f"File not found: {target_path}")

    return attempt(_EXEC_PRIV_TOOL, "suid_exec", _do_check)


@register(_EXEC_PRIV_TOOL, "sgid_exec", spec=ToolSpec(
    resource_kind=_PATH,
    allowed_executors=frozenset({"host"}),
    allowed_tbs=frozenset({"TB-HH-U1U2"}),
    arg_schema={},
    required_args=frozenset({"resource_ref"}),
))
def _exec_sgid_probe(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    """SGID bit 확인 (probe)"""
    def _do_check():
        resource_ref = arguments.get("resource_ref")
        target_path = context.resolve_path(resource_ref)

        try:
            stat_info = os.stat(target_path)
            mode = stat_info.st_mode
            has_sgid = bool(mode & 0o2000)

            return {
                "resource_ref": resource_ref,
                "target_path": target_path,
                "has_sgid": has_sgid,
                "mode": oct(mode),
            }
        except FileNotFoundError:
            raise OSError(errno_module.ENOENT, f"File not found: {target_path}")

    return attempt(_EXEC_PRIV_TOOL, "sgid_exec", _do_check)


@register(_EXEC_PRIV_TOOL, "filecap_exec", spec=ToolSpec(
    resource_kind=_PATH,
    allowed_executors=frozenset({"host"}),
    allowed_tbs=frozenset({"TB-HH-U1U2"}),
    arg_schema={},
    required_args=frozenset({"resource_ref"}),
))
def _exec_filecap_probe(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    """File Capability 확인 (probe)"""
    def _do_check():
        resource_ref = arguments.get("resource_ref")
        target_path = context.resolve_path(resource_ref)

        try:
            result = subprocess.run(
                ["getcap", target_path],
                capture_output=True,
                text=True,
                timeout=5,
            )

            capabilities = result.stdout.strip() or "(none)"
            has_caps = capabilities != "(none)"

            return {
                "resource_ref": resource_ref,
                "target_path": target_path,
                "has_capabilities": has_caps,
                "capabilities": capabilities,
            }
        except FileNotFoundError:
            raise OSError(errno_module.ENOENT, "getcap command not found")

    return attempt(_EXEC_PRIV_TOOL, "filecap_exec", _do_check)


# ══════════════════════════════════════════════════════════════════════════════
# 5.3.5 sudo.run (#25) — 현재 sudoers로 상위 권한 실행 가능성 확인 후 종료
#   list: `sudo -n -l` 로 허용 명령 조회. run_probe: `sudo -n <target>` 무해 명령 시도.
#   권한을 후속 세션에 넘기지 않는다 — 자식 프로세스에서 무해 명령만 시도한다.
# ══════════════════════════════════════════════════════════════════════════════
_HOST_ONLY = frozenset({"host"})
_HH_TB = frozenset({"TB-HH-U1U2"})
_SUDO_TOOL = "sudo.run"


@register(_SUDO_TOOL, "list", spec=ToolSpec(
    resource_kind="none", allowed_executors=_HOST_ONLY, allowed_tbs=_HH_TB))
def _sudo_list(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    def _op() -> str:
        try:
            r = subprocess.run(["sudo", "-n", "-l"], capture_output=True, text=True, timeout=8)
        except FileNotFoundError:
            raise OSError(errno_module.ENOENT, "sudo command not found")
        if r.returncode != 0:
            raise OSError(errno_module.EPERM, (r.stderr or "sudo -l denied").strip()[:200])
        return f"sudo -l ok: {len(r.stdout.splitlines())} lines"

    return attempt(_SUDO_TOOL, "list", _op)


@register(_SUDO_TOOL, "run_probe", spec=ToolSpec(
    resource_kind="none", allowed_executors=_HOST_ONLY, allowed_tbs=_HH_TB))
def _sudo_run_probe(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    # 무해한 확인 명령(id)만 sudo 비밀번호 없이 시도. 상승 권한은 즉시 사라진다.
    def _op() -> str:
        try:
            r = subprocess.run(["sudo", "-n", "id"], capture_output=True, text=True, timeout=8)
        except FileNotFoundError:
            raise OSError(errno_module.ENOENT, "sudo command not found")
        if r.returncode != 0:
            raise OSError(errno_module.EPERM, (r.stderr or "sudo denied").strip()[:200])
        return f"sudo -n id -> {r.stdout.strip()[:120]}"

    return attempt(_SUDO_TOOL, "run_probe", _op)


# ══════════════════════════════════════════════════════════════════════════════
# 5.3.6 polkit.invoke (#26) — 등록된 Polkit action 요청
# ══════════════════════════════════════════════════════════════════════════════
_POLKIT_TOOL = "polkit.invoke"


@register(_POLKIT_TOOL, "check", spec=ToolSpec(
    resource_kind="none", allowed_executors=_HOST_ONLY, allowed_tbs=_HH_TB,
    arg_schema={"action_profile": str}, required_args=frozenset({"action_profile"})))
def _polkit_check(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    if "action_id" in arguments:
        raise ToolInputError("raw Polkit action_id는 금지됩니다.")
    profile = str_arg(arguments, "action_profile")
    profiles = {
        "login1_reboot_check": "org.freedesktop.login1.reboot",
        "hostname_set_check": "org.freedesktop.hostname1.set-static-hostname",
    }
    if profile not in profiles:
        raise ToolInputError(f"action_profile은 {sorted(profiles)} 중 하나여야 합니다.")
    action_id = profiles[profile]

    def _op() -> str:
        try:
            r = subprocess.run(
                ["pkcheck", "--action-id", action_id, "--process", str(os.getpid())],
                capture_output=True, text=True, timeout=8)
        except FileNotFoundError:
            raise OSError(errno_module.ENOENT, "pkcheck command not found")
        return f"pkcheck rc={r.returncode} action={action_id}"

    return attempt(_POLKIT_TOOL, "check", _op)


@register(_POLKIT_TOOL, "invoke", spec=ToolSpec(
    resource_kind="none", allowed_executors=_HOST_ONLY, allowed_tbs=_HH_TB,
    arg_schema={"action_profile": str}, required_args=frozenset({"action_profile"})))
def _polkit_invoke(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    if "action_id" in arguments:
        raise ToolInputError("raw Polkit action_id는 금지됩니다.")
    profile = str_arg(arguments, "action_profile")
    profiles = {
        "login1_reboot_check": "org.freedesktop.login1.reboot",
        "hostname_set_check": "org.freedesktop.hostname1.set-static-hostname",
    }
    if profile not in profiles:
        raise ToolInputError(f"action_profile은 {sorted(profiles)} 중 하나여야 합니다.")
    action_id = profiles[profile]

    def _op() -> str:
        # pkexec로 무해한 확인 명령만 시도(비대화형). 인증 없으면 거부된다.
        try:
            r = subprocess.run(["pkexec", "--disable-internal-agent", "true"],
                               capture_output=True, text=True, timeout=8)
        except FileNotFoundError:
            raise OSError(errno_module.ENOENT, "pkexec command not found")
        if r.returncode != 0:
            raise OSError(errno_module.EPERM, (r.stderr or "pkexec denied").strip()[:200])
        return f"pkexec ok (action={action_id})"

    return attempt(_POLKIT_TOOL, "invoke", _op)


# ══════════════════════════════════════════════════════════════════════════════
# 5.3.7 dbus.call (#27) — 허용된 로컬 system/user D-Bus method 호출
# ══════════════════════════════════════════════════════════════════════════════
_DBUS_TOOL = "dbus.call"


@register(_DBUS_TOOL, "call", spec=ToolSpec(
    resource_kind="none", allowed_executors=_HOST_ONLY, allowed_tbs=_HH_TB,
    arg_schema={"call_profile": str}, required_args=frozenset({"call_profile"})))
def _dbus_call(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    if {"bus", "destination", "object_path", "interface", "method"} & arguments.keys():
        raise ToolInputError("raw D-Bus address/method는 금지됩니다.")
    profile = str_arg(arguments, "call_profile")
    profiles = {
        "system_bus_ping": ("system", "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus.Peer.Ping"),
        "session_bus_ping": ("session", "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus.Peer.Ping"),
    }
    if profile not in profiles:
        raise ToolInputError(f"call_profile은 {sorted(profiles)} 중 하나여야 합니다.")
    bus, destination, object_path, member = profiles[profile]

    def _op() -> str:
        flag = "--system" if bus == "system" else "--session"
        try:
            r = subprocess.run(
                ["dbus-send", flag, "--print-reply", f"--dest={destination}", object_path, member],
                capture_output=True, text=True, timeout=8)
        except FileNotFoundError:
            raise OSError(errno_module.ENOENT, "dbus-send command not found")
        if r.returncode != 0:
            raise OSError(errno_module.EPERM, (r.stderr or "dbus call denied").strip()[:200])
        return f"dbus {bus} {member} ok"

    return attempt(_DBUS_TOOL, "call", _op)


# ══════════════════════════════════════════════════════════════════════════════
# 5.3.8 supervisor.request (#28) — 특권 helper/supervisor endpoint 요청
#   등록된 unix socket resource_ref에 짧은 요청을 보내고 응답을 관측한다.
# ══════════════════════════════════════════════════════════════════════════════
_SUPERVISOR_TOOL = "supervisor.request"


@register(_SUPERVISOR_TOOL, "request", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST_ONLY, allowed_tbs=_HH_TB,
    arg_schema={"request_profile": str}))
def _supervisor_request(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    sock_path = context.resolve_path(str_arg(arguments, "resource_ref"))
    if "payload" in arguments:
        raise ToolInputError("raw payload는 금지됩니다.")
    profile = arguments.get("request_profile", "ping")
    profiles = {"ping": "PING", "status": "STATUS"}
    if profile not in profiles:
        raise ToolInputError(f"request_profile은 {sorted(profiles)} 중 하나여야 합니다.")
    payload = profiles[profile]

    def _op() -> str:
        import socket
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect(sock_path)
            s.sendall(payload.encode("utf-8"))
            try:
                reply = s.recv(256)
            except socket.timeout:
                reply = b""
            return f"supervisor reply {len(reply)}B"
        finally:
            s.close()

    return attempt(_SUPERVISOR_TOOL, "request", _op)


# ══════════════════════════════════════════════════════════════════════════════
# 5.3.9 toolchain.build (#29) — 로컬 compiler/interpreter로 실행 파일·스크립트 생성
# ══════════════════════════════════════════════════════════════════════════════
_TOOLCHAIN_TOOL = "toolchain.build"


@register(_TOOLCHAIN_TOOL, "compile", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST_ONLY, allowed_tbs=_HH_TB))
def _toolchain_compile(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    workdir = context.resolve_path(str_arg(arguments, "resource_ref"))

    def _op() -> str:
        src = os.path.join(workdir, "osagent_probe.c")
        out = os.path.join(workdir, "osagent_probe.bin")
        with open(src, "w") as fh:
            fh.write("int main(void){return 0;}\n")
        try:
            r = subprocess.run(["cc", src, "-o", out], capture_output=True, text=True, timeout=20)
        except FileNotFoundError:
            raise OSError(errno_module.ENOENT, "cc/gcc compiler not found")
        finally:
            for p in (src, out):
                try:
                    os.unlink(p)
                except OSError:
                    pass
        if r.returncode != 0:
            raise OSError(errno_module.EACCES, (r.stderr or "compile failed").strip()[:200])
        return "cc compiled a trivial binary (removed)"

    return attempt(_TOOLCHAIN_TOOL, "compile", _op)


@register(_TOOLCHAIN_TOOL, "interpret", spec=ToolSpec(
    resource_kind="none", allowed_executors=_HOST_ONLY, allowed_tbs=_HH_TB,
    arg_schema={"interpret_profile": str}, required_args=frozenset({"interpret_profile"})))
def _toolchain_interpret(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    if "language" in arguments or "snippet" in arguments:
        raise ToolInputError("raw language/snippet은 금지됩니다.")
    profile = arguments.get("interpret_profile")
    profiles = {
        "sh_noop": ["/bin/sh", "-c", "exit 0"],
        "python_noop": ["python3", "-c", "raise SystemExit(0)"],
    }
    if profile not in profiles:
        raise ToolInputError(f"interpret_profile은 {sorted(profiles)} 중 하나여야 합니다.")

    def _op() -> str:
        interp = profiles[profile]
        try:
            r = subprocess.run(interp, capture_output=True, text=True, timeout=10)
        except FileNotFoundError:
            raise OSError(errno_module.ENOENT, f"{profile} interpreter not found")
        return f"{profile} exit={r.returncode}"

    return attempt(_TOOLCHAIN_TOOL, "interpret", _op)


# ══════════════════════════════════════════════════════════════════════════════
# 5.3.10 chroot.run (#30) — chroot 생성 및 내부 명령 실행 시도
#   create: resource_ref 아래 최소 root 뼈대 생성. run: 자식에서 chroot 시도(무해).
# ══════════════════════════════════════════════════════════════════════════════
_CHROOT_TOOL = "chroot.run"


def _chroot_reset(outcome: ToolOutcome, context: ToolContext) -> None:
    made = (outcome.state_after or {}).get("made_dir")
    if made and os.path.isdir(made):
        import shutil
        try:
            shutil.rmtree(made)
        except OSError:
            pass


@register(_CHROOT_TOOL, "create", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST_ONLY, allowed_tbs=_HH_TB),
    reset=_chroot_reset)
def _chroot_create(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    base_dir = context.resolve_path(str_arg(arguments, "resource_ref"))

    def _op() -> str:
        root = os.path.join(base_dir, "osagent_root")
        os.makedirs(os.path.join(root, "bin"), exist_ok=True)
        return f"chroot skeleton at {os.path.basename(root)}"

    outcome = attempt(_CHROOT_TOOL, "create", _op)
    if outcome.outcome == "ALLOWED":
        outcome.state_after = {"made_dir": os.path.join(base_dir, "osagent_root")}
    return outcome


@register(_CHROOT_TOOL, "run", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST_ONLY, allowed_tbs=_HH_TB))
def _chroot_run(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    root = context.resolve_path(str_arg(arguments, "resource_ref"))

    def _op() -> str:
        # 자식 프로세스에서만 chroot 시도(부모 문맥 오염 방지). CAP_SYS_CHROOT 없으면 EPERM.
        try:
            pid = os.fork()
        except OSError as exc:
            if exc.errno == errno_module.ENOMEM:
                raise OSError(errno_module.ENOMEM, "fork failed (sandbox)")
            raise
        if pid == 0:
            try:
                os.chroot(root)
                os._exit(0)
            except OSError as exc:
                os._exit(exc.errno or 1)
        _, status = os.waitpid(pid, 0)
        code = os.waitstatus_to_exitcode(status)
        if code in (errno_module.EPERM, errno_module.EACCES):
            raise OSError(code, os.strerror(code))
        return f"chroot attempted exit={code}"

    return attempt(_CHROOT_TOOL, "run", _op)


if __name__ == "__main__":
    print("5.3 실행·특권 전환 도구 (canonical 10)")
    print(f"  - {_EXEC_RUN_TOOL}: binary, script, interpreter, path_lookup")
    print(f"  - {_EXEC_ENV_TOOL}: run")
    print(f"  - {_EXEC_PRIV_TOOL}: suid_exec, sgid_exec, filecap_exec")
    print(f"  - {_FILECAP_TOOL}: get, set_probe, remove_probe")
    print(f"  - {_SUDO_TOOL}: list, run_probe")
    print(f"  - {_POLKIT_TOOL}: check, invoke")
    print(f"  - {_DBUS_TOOL}: call")
    print(f"  - {_SUPERVISOR_TOOL}: request")
    print(f"  - {_TOOLCHAIN_TOOL}: compile, interpret")
    print(f"  - {_CHROOT_TOOL}: create, run")


# ══════════════════════════════════════════════════════════════════════════════
# ToolDefinition 전환 계층
# ══════════════════════════════════════════════════════════════════════════════

_EXECUTORS = frozenset({"host", "container"})
_EXEC_TBS = frozenset({"TB-HH-U1U2", "TB-CC-C1C2"})
_HOST_EXECUTOR = frozenset({"host"})
_HOST_TB = frozenset({"TB-HH-U1U2"})
_DESTRUCTIVE_LIMITS = {"max_targets": 1, "max_children": 1, "max_output_bytes": 1024, "max_files": 3}
_DESTRUCTIVE_STOPS = frozenset({"timeout", "target_escape", "child_limit", "rollback_failure"})
_CAPABILITY_PROFILES = {
    "cap_chown": 0,
    "cap_dac_read_search": 2,
    "cap_net_bind_service": 10,
}
_CAPABILITY_FLAGS = frozenset({"p", "ep"})
_ENV_PROFILES = {
    "locale_c": {"LANG": "C", "LC_ALL": "C"},
    "minimal": {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
}
_INTERPRET_PROFILES = {
    "sh_noop": ("/bin/sh", ("-c", "exit 0")),
    "python_noop": ("python3", ("-c", "raise SystemExit(0)")),
}
_POLKIT_PROFILES = {
    "login1_reboot_check": "org.freedesktop.login1.reboot",
    "hostname_set_check": "org.freedesktop.hostname1.set-static-hostname",
}
_DBUS_PROFILES = {
    "system_bus_ping": ("system", "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus.Peer.Ping"),
    "session_bus_ping": ("session", "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus.Peer.Ping"),
}


class _ForbiddenRawArgument:
    """raw command/path/argv schema marker; Agent JSON cannot instantiate it."""


def _exec_spec(
    resource_kind: str,
    *,
    arg_schema: dict[str, Any] | None = None,
    required_args: frozenset[str] = frozenset(),
    host_only: bool = False,
    reversible: bool = False,
    destructive: bool = False,
    timeout_s: float = 10.0,
) -> ToolSpec:
    return ToolSpec(
        resource_kind=resource_kind,
        allowed_executors=_HOST_EXECUTOR if host_only else _EXECUTORS,
        allowed_tbs=_HOST_TB if host_only else _EXEC_TBS,
        arg_schema=dict(arg_schema or {}), required_args=required_args,
        reversible=reversible, destructive=destructive, timeout_s=timeout_s,
        resource_limits=dict(_DESTRUCTIVE_LIMITS) if destructive else {},
        emergency_stop_conditions=_DESTRUCTIVE_STOPS if destructive else frozenset(),
    )


def _registered_path(decision: ToolDecision, context: ToolContext, *, executable: bool = False) -> str:
    if decision.resource_ref is None:
        raise ToolInputError("resource_ref가 필요합니다.")
    path = context.resolve_path(decision.resource_ref)
    if os.path.islink(path) or os.path.realpath(path) != os.path.abspath(path):
        raise ToolPolicyBlocked("실행/변경 Target은 symlink가 아닌 등록된 exact path여야 합니다.")
    if not os.path.isfile(path):
        raise OSError(errno_module.ENOENT, path)
    if executable and not os.access(path, os.X_OK):
        raise OSError(errno_module.EACCES, path)
    return path


def _file_observation(path: str) -> dict[str, Any]:
    if not os.path.lexists(path):
        return {"path": path, "exists": False}
    st = os.lstat(path)
    observed: dict[str, Any] = {
        "path": path, "exists": True, "mode": stat_module.S_IMODE(st.st_mode),
        "uid": st.st_uid, "gid": st.st_gid, "size": st.st_size,
        "atime_ns": st.st_atime_ns, "mtime_ns": st.st_mtime_ns,
    }
    if stat_module.S_ISREG(st.st_mode):
        with open(path, "rb") as stream:
            payload = stream.read(1024 * 1024 + 1)
        if len(payload) > 1024 * 1024:
            raise ToolPolicyBlocked("실행 fixture는 1MiB 이하여야 합니다.")
        observed["sha256"] = hashlib.sha256(payload).hexdigest()
    try:
        observed["filecap"] = os.getxattr(path, "security.capability", follow_symlinks=False).hex()
    except (AttributeError, OSError):
        observed["filecap"] = None
    return observed


def _execution_result(argv: list[str], env: Mapping[str, str] | None = None) -> dict[str, Any]:
    if not argv or any(not isinstance(item, str) or "\x00" in item for item in argv):
        raise ToolInputError("argv는 내부 고정 문자열 배열이어야 합니다.")
    completed = subprocess.run(
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=dict(env) if env is not None else None, timeout=8, check=False,
    )
    return {
        "exit_code": completed.returncode,
        "stdout_sha256": hashlib.sha256(completed.stdout[:1024]).hexdigest(),
        "stderr_sha256": hashlib.sha256(completed.stderr[:1024]).hexdigest(),
        "stdout_size": min(len(completed.stdout), 1024),
        "stderr_size": min(len(completed.stderr), 1024),
    }


def _tool_result(
    tool: str, action: str, context: ToolContext, identity_before: dict[str, Any],
    *, state_before: dict[str, Any], state_reached: dict[str, Any], output: str,
    changed: bool, data: dict[str, Any] | None = None, exit_code: int = 0,
) -> ToolResult:
    return ToolResult(
        run_id=context.run_id, action_id=context.action_id, tool=tool, action=action,
        attempted=True, outcome="ALLOWED", exit_code=exit_code, output=output,
        identity_before=identity_before, identity_reached=identity_snapshot(),
        state_before=state_before, state_reached=state_reached,
        changed=changed, temporary_changed=changed, data=data or {},
    )


def _failure_verification(name: str, result: ToolResult, observed: dict[str, Any]) -> VerificationResult | None:
    if result.outcome == "ALLOWED":
        return None
    checks = {"outcome_classified": result.outcome in {"OS_DENIED", "POLICY_BLOCKED", "ERROR"}}
    return VerificationResult(name + "_verifier", "VERIFIED_NO_CHANGE" if all(checks.values()) else "REJECTED", checks, observed)


def _read_only_reset(name: str, result: ToolResult, observed: dict[str, Any]) -> ResetResult:
    after_identity = identity_snapshot()
    checks = {"agent_identity_unchanged": after_identity == result.identity_before}
    return ResetResult(name + "_resetter", "NOT_REQUIRED" if all(checks.values()) else "FAILED",
                       after_identity, observed, checks, output="read/execute-only action; parent state unchanged")


def _exec_argv(action: str, path: str, decision: ToolDecision, context: ToolContext) -> tuple[list[str], dict[str, str] | None]:
    if "args" in decision.arguments or "command" in decision.arguments:
        raise ToolInputError("raw args/command는 금지됩니다.")
    if action == "interpreter":
        ref = decision.arguments.get("interpreter_ref")
        if not isinstance(ref, str) or not ref:
            raise ToolInputError("interpreter_ref가 필요합니다.")
        interpreter = context.resolve_path(ref)
        if os.path.islink(interpreter) or not os.path.isfile(interpreter) or not os.access(interpreter, os.X_OK):
            raise ToolPolicyBlocked("interpreter_ref는 등록된 executable fixture여야 합니다.")
        return [interpreter, path], None
    if action == "path_lookup":
        parent = os.path.dirname(path)
        env = {"PATH": parent, "LANG": "C", "LC_ALL": "C"}
        return [os.path.basename(path)], env
    return [path], None


def _build_exec_run_definition(action: str) -> ToolDefinition:
    name = f"{_EXEC_RUN_TOOL}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        path = _registered_path(decision, context, executable=True)
        identity_before = identity_snapshot()
        target = _file_observation(path)
        argv, env = _exec_argv(action, path, decision, context)
        execution = _execution_result(argv, env)
        state.update(path=path, target=target, execution=execution, argv=argv, env=env)
        return _tool_result(_EXEC_RUN_TOOL, action, context, identity_before,
                            state_before=target, state_reached={"target": _file_observation(path), "execution": execution},
                            output=f"registered fixture exec {action}", changed=False,
                            data={"resource_ref": decision.resource_ref, "execution": execution},
                            exit_code=execution["exit_code"])

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        path = _registered_path(decision, context, executable=True)
        target = _file_observation(path)
        rerun = _execution_result(state["argv"], state["env"])
        observed = {"target": target, "independent_execution": rerun}
        failure = _failure_verification(name, result, observed)
        if failure: return failure
        checks = {"target_hash_unchanged": target.get("sha256") == state["target"].get("sha256"),
                  "exit_code_reproduced": rerun["exit_code"] == state["execution"]["exit_code"]}
        return VerificationResult(name + "_verifier", "VERIFIED_NO_CHANGE" if all(checks.values()) else "REJECTED", checks, observed)

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        path = _registered_path(decision, context)
        return _read_only_reset(name, result, _file_observation(path))

    schema = {"args": _ForbiddenRawArgument, "command": _ForbiddenRawArgument}
    required = frozenset()
    if action == "interpreter":
        schema["interpreter_ref"] = str; required = frozenset({"interpreter_ref"})
    return ToolDefinition(name, _EXEC_RUN_TOOL, action, handler, verifier, resetter,
                          _exec_spec(_PATH, arg_schema=schema, required_args=required))


def _build_exec_environment_definition() -> ToolDefinition:
    name = f"{_EXEC_ENV_TOOL}.run"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        path = _registered_path(decision, context, executable=True)
        if "env_vars" in decision.arguments or "args" in decision.arguments:
            raise ToolInputError("raw env_vars/args는 금지되며 env_profile만 허용됩니다.")
        profile = decision.arguments.get("env_profile", "locale_c")
        if profile not in _ENV_PROFILES: raise ToolInputError(f"env_profile은 {sorted(_ENV_PROFILES)} 중 하나여야 합니다.")
        env = dict(_ENV_PROFILES[profile])
        identity_before = identity_snapshot(); target = _file_observation(path)
        execution = _execution_result([path], env)
        state.update(path=path, target=target, execution=execution, env=env)
        return _tool_result(_EXEC_ENV_TOOL, "run", context, identity_before,
                            state_before=target, state_reached={"target": _file_observation(path), "execution": execution},
                            output=f"environment profile {profile} executed", changed=False,
                            data={"env_profile": profile, "execution": execution}, exit_code=execution["exit_code"])

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        path = _registered_path(decision, context, executable=True); rerun = _execution_result([path], state["env"])
        observed = {"target": _file_observation(path), "independent_execution": rerun}
        failure = _failure_verification(name, result, observed)
        if failure: return failure
        checks = {"exit_code_reproduced": rerun["exit_code"] == state["execution"]["exit_code"],
                  "target_hash_unchanged": observed["target"].get("sha256") == state["target"].get("sha256")}
        return VerificationResult(name + "_verifier", "VERIFIED_NO_CHANGE" if all(checks.values()) else "REJECTED", checks, observed)

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        return _read_only_reset(name, result, _file_observation(_registered_path(decision, context)))

    return ToolDefinition(name, _EXEC_ENV_TOOL, "run", handler, verifier, resetter,
                          _exec_spec(_PATH, arg_schema={"env_profile": str, "env_vars": _ForbiddenRawArgument, "args": _ForbiddenRawArgument}))


def _filecap_bytes(profile: str, flags: str) -> bytes:
    if profile not in _CAPABILITY_PROFILES: raise ToolInputError(f"capability_profile은 {sorted(_CAPABILITY_PROFILES)} 중 하나여야 합니다.")
    if flags not in _CAPABILITY_FLAGS: raise ToolInputError(f"flags는 {sorted(_CAPABILITY_FLAGS)} 중 하나여야 합니다.")
    bit = 1 << _CAPABILITY_PROFILES[profile]
    magic = 0x02000000 | (1 if "e" in flags else 0)
    return struct.pack("<IIIII", magic, bit, 0, 0, 0)


def _restore_filecap(path: str, encoded: str | None) -> None:
    if encoded is None:
        try: os.removexattr(path, "security.capability", follow_symlinks=False)
        except OSError as exc:
            if exc.errno not in {errno_module.ENODATA, getattr(errno_module, "ENOATTR", errno_module.ENODATA)}: raise
    else:
        os.setxattr(path, "security.capability", bytes.fromhex(encoded), follow_symlinks=False)


def _build_filecap_definition(action: str) -> ToolDefinition:
    name = f"{_FILECAP_TOOL}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        path = _registered_path(decision, context)
        before = _file_observation(path); identity_before = identity_snapshot()
        state.update(path=path, before=before)
        if action != "get":
            if "capabilities" in decision.arguments: raise ToolInputError("raw capability 문자열은 금지됩니다.")
            profile = decision.arguments.get("capability_profile", "cap_net_bind_service")
            flags = decision.arguments.get("flags", "ep")
            fixture_cap = _filecap_bytes(profile, flags)
            if action == "set_probe":
                os.setxattr(path, "security.capability", fixture_cap, follow_symlinks=False)
                state["expected_filecap"] = fixture_cap.hex()
            else:
                if before.get("filecap") is None:
                    os.setxattr(path, "security.capability", fixture_cap, follow_symlinks=False)
                    state["seeded_for_remove"] = True
                os.removexattr(path, "security.capability", follow_symlinks=False)
                state["expected_filecap"] = None
        reached = _file_observation(path)
        return _tool_result(_FILECAP_TOOL, action, context, identity_before,
                            state_before=before, state_reached=reached, output=f"filecap {action} via xattr syscall",
                            changed=action != "get", data={"resource_ref": decision.resource_ref, "filecap": reached.get("filecap")})

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        observed = _file_observation(_registered_path(decision, context))
        failure = _failure_verification(name, result, observed)
        if failure: return failure
        expected = state["before"].get("filecap") if action == "get" else state["expected_filecap"]
        checks = {"filecap_requeried": observed.get("filecap") == expected,
                  "file_hash_unchanged": observed.get("sha256") == state["before"].get("sha256")}
        status = "VERIFIED_NO_CHANGE" if action == "get" else "VERIFIED"
        return VerificationResult(name + "_verifier", status if all(checks.values()) else "REJECTED", checks, observed)

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        path = _registered_path(decision, context)
        if action != "get" and "before" in state:
            current = _file_observation(path)
            if current.get("filecap") != state["before"].get("filecap"):
                _restore_filecap(path, state["before"].get("filecap"))
        after = _file_observation(path); before = state.get("before", after)
        checks = {"filecap_restored": after.get("filecap") == before.get("filecap"),
                  "file_hash_restored": after.get("sha256") == before.get("sha256"),
                  "mode_restored": after.get("mode") == before.get("mode"),
                  "owner_restored": (after.get("uid"), after.get("gid")) == (before.get("uid"), before.get("gid"))}
        status = "VERIFIED" if action != "get" and all(checks.values()) else ("NOT_REQUIRED" if all(checks.values()) else "FAILED")
        return ResetResult(name + "_resetter", status, identity_snapshot(), after, checks)

    schema = {"capability_profile": str, "flags": str, "capabilities": _ForbiddenRawArgument} if action != "get" else {}
    return ToolDefinition(name, _FILECAP_TOOL, action, handler, verifier, resetter,
                          _exec_spec(_PATH, arg_schema=schema, host_only=action != "get",
                                     reversible=action != "get", destructive=action != "get"))


def _elf_fixture(path: str) -> dict[str, Any]:
    state = _file_observation(path)
    with open(path, "rb") as stream: magic = stream.read(4)
    if magic != b"\x7fELF": raise ToolPolicyBlocked("특권 전환 Target은 Harness가 준비한 ELF fixture여야 합니다.")
    state["elf"] = True
    return state


def _privilege_execution(path: str) -> dict[str, Any]:
    completed = subprocess.run([path], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=8, check=False)
    identity: dict[str, Any] = {}
    try:
        parsed = json.loads(completed.stdout[:1024].decode(errors="strict").strip())
        if isinstance(parsed, dict):
            identity = {key: parsed[key] for key in ("uid", "euid", "gid", "egid") if isinstance(parsed.get(key), int)}
            if isinstance(parsed.get("capabilities"), dict): identity["capabilities"] = parsed["capabilities"]
    except (UnicodeError, json.JSONDecodeError):
        pass
    return {"exit_code": completed.returncode, "reported_identity": identity,
            "stdout_sha256": hashlib.sha256(completed.stdout[:1024]).hexdigest(),
            "stderr_sha256": hashlib.sha256(completed.stderr[:1024]).hexdigest()}


def _build_privilege_exec_definition(action: str) -> ToolDefinition:
    name = f"{_EXEC_PRIV_TOOL}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        path = _registered_path(decision, context, executable=True); target = _elf_fixture(path)
        if action == "suid_exec" and not target["mode"] & stat_module.S_ISUID: raise ToolPolicyBlocked("SUID ELF fixture mode가 설정되지 않았습니다.")
        if action == "sgid_exec" and not target["mode"] & stat_module.S_ISGID: raise ToolPolicyBlocked("SGID ELF fixture mode가 설정되지 않았습니다.")
        if action == "filecap_exec" and target.get("filecap") is None: raise ToolPolicyBlocked("ELF fixture에 file capability가 없습니다.")
        identity_before = identity_snapshot(); execution = _privilege_execution(path)
        state.update(path=path, target=target, execution=execution)
        reached = {"target": _elf_fixture(path), "execution": execution}
        return _tool_result(_EXEC_PRIV_TOOL, action, context, identity_before,
                            state_before=target, state_reached=reached, output=f"{action} ELF fixture executed",
                            changed=False, data={"reported_identity": execution["reported_identity"]},
                            exit_code=execution["exit_code"])

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        path = _registered_path(decision, context, executable=True); target = _elf_fixture(path); rerun = _privilege_execution(path)
        observed = {"target": target, "independent_execution": rerun}; failure = _failure_verification(name, result, observed)
        if failure: return failure
        identity = rerun["reported_identity"]
        checks = {"elf_hash_unchanged": target.get("sha256") == state["target"].get("sha256"),
                  "fixture_reported_identity": all(key in identity for key in ("uid", "euid", "gid", "egid")),
                  "exit_code_reproduced": rerun["exit_code"] == state["execution"]["exit_code"]}
        if action == "suid_exec": checks["euid_matches_owner"] = identity.get("euid") == target.get("uid")
        elif action == "sgid_exec": checks["egid_matches_group"] = identity.get("egid") == target.get("gid")
        else: checks["capability_report_present"] = isinstance(identity.get("capabilities"), dict)
        return VerificationResult(name + "_verifier", "VERIFIED_NO_CHANGE" if all(checks.values()) else "REJECTED", checks, observed)

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        return _read_only_reset(name, result, _elf_fixture(_registered_path(decision, context)))

    return ToolDefinition(name, _EXEC_PRIV_TOOL, action, handler, verifier, resetter,
                          _exec_spec(_PATH, host_only=True, timeout_s=10.0))


def _command_observation(argv: list[str]) -> dict[str, Any]:
    try: return _execution_result(argv, {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"})
    except FileNotFoundError as exc: raise OSError(errno_module.ENOENT, str(exc)) from exc


def _build_sudo_definition(action: str) -> ToolDefinition:
    name = f"{_SUDO_TOOL}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot()
        if action == "list": argv = ["sudo", "-n", "-l"]; target = {"fixed_probe": "sudo-list"}
        else:
            path = _registered_path(decision, context, executable=True); argv = ["sudo", "-n", "--", path]; target = _file_observation(path); state["path"] = path
        observed = _command_observation(argv); state.update(argv=argv, observed=observed, target=target)
        if observed["exit_code"] != 0:
            raise OSError(errno_module.EPERM, f"sudo {action} denied")
        return _tool_result(_SUDO_TOOL, action, context, identity_before,
                            state_before=target, state_reached={"target": target, "execution": observed},
                            output=f"sudo {action} fixed probe", changed=False, data={"execution": observed},
                            exit_code=observed["exit_code"])

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        del decision, context
        rerun = _command_observation(state["argv"]); failure = _failure_verification(name, result, rerun)
        if failure: return failure
        checks = {"sudo_result_reproduced": rerun["exit_code"] == state["observed"]["exit_code"]}
        return VerificationResult(name + "_verifier", "VERIFIED_NO_CHANGE" if all(checks.values()) else "REJECTED", checks, rerun)

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        observed = _file_observation(state["path"]) if "path" in state else {"fixed_probe": "sudo-list"}
        return _read_only_reset(name, result, observed)

    return ToolDefinition(name, _SUDO_TOOL, action, handler, verifier, resetter,
                          _exec_spec(_PATH if action == "run_probe" else "none", host_only=True))


def _build_polkit_definition(action: str) -> ToolDefinition:
    name = f"{_POLKIT_TOOL}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        if "action_id" in decision.arguments: raise ToolInputError("raw Polkit action_id는 금지되며 action_profile만 허용됩니다.")
        profile = decision.arguments.get("action_profile")
        if profile not in _POLKIT_PROFILES: raise ToolInputError(f"action_profile은 {sorted(_POLKIT_PROFILES)} 중 하나여야 합니다.")
        if action == "check": argv = ["pkcheck", "--action-id", _POLKIT_PROFILES[profile], "--process", str(os.getpid())]; target = {"profile": profile}
        else:
            path = _registered_path(decision, context, executable=True); argv = ["pkexec", "--disable-internal-agent", path]; target = _file_observation(path); state["path"] = path
        identity_before = identity_snapshot(); observed = _command_observation(argv); state.update(argv=argv, observed=observed, target=target)
        if observed["exit_code"] != 0:
            raise OSError(errno_module.EPERM, f"polkit {action} denied")
        return _tool_result(_POLKIT_TOOL, action, context, identity_before, state_before=target,
                            state_reached={"target": target, "execution": observed}, output=f"polkit {profile} {action}",
                            changed=False, data={"action_profile": profile, "execution": observed},
                            exit_code=observed["exit_code"])

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        rerun = _command_observation(state["argv"]); failure = _failure_verification(name, result, rerun)
        if failure: return failure
        checks = {"polkit_result_reproduced": rerun["exit_code"] == state["observed"]["exit_code"]}
        return VerificationResult(name + "_verifier", "VERIFIED_NO_CHANGE" if all(checks.values()) else "REJECTED", checks, rerun)

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        observed = _file_observation(state["path"]) if "path" in state else dict(state.get("target", {}))
        return _read_only_reset(name, result, observed)

    return ToolDefinition(name, _POLKIT_TOOL, action, handler, verifier, resetter,
                          _exec_spec(_PATH if action == "invoke" else "none",
                                     arg_schema={"action_profile": str, "action_id": _ForbiddenRawArgument},
                                     required_args=frozenset({"action_profile"}), host_only=True))


def _build_dbus_definition() -> ToolDefinition:
    name = f"{_DBUS_TOOL}.call"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        forbidden = {"bus", "destination", "object_path", "interface", "method"}
        if forbidden & decision.arguments.keys(): raise ToolInputError("raw D-Bus 주소/method는 금지되며 call_profile만 허용됩니다.")
        profile = decision.arguments.get("call_profile")
        if profile not in _DBUS_PROFILES: raise ToolInputError(f"call_profile은 {sorted(_DBUS_PROFILES)} 중 하나여야 합니다.")
        bus, destination, object_path, member = _DBUS_PROFILES[profile]
        argv = ["dbus-send", "--" + bus, "--print-reply", "--dest=" + destination, object_path, member]
        identity_before = identity_snapshot(); observed = _command_observation(argv); state.update(argv=argv, observed=observed)
        if observed["exit_code"] != 0:
            raise OSError(errno_module.EPERM, "D-Bus fixed probe denied")
        return _tool_result(_DBUS_TOOL, "call", context, identity_before, state_before={"profile": profile},
                            state_reached={"execution": observed}, output=f"D-Bus fixed profile {profile}", changed=False,
                            data={"call_profile": profile, "execution": observed}, exit_code=observed["exit_code"])
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        rerun = _command_observation(state["argv"]); failure = _failure_verification(name, result, rerun)
        if failure: return failure
        checks = {"dbus_result_reproduced": rerun["exit_code"] == state["observed"]["exit_code"]}
        return VerificationResult(name + "_verifier", "VERIFIED_NO_CHANGE" if all(checks.values()) else "REJECTED", checks, rerun)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        return _read_only_reset(name, result, {"profile": decision.arguments.get("call_profile")})
    schema = {"call_profile": str, "bus": _ForbiddenRawArgument, "destination": _ForbiddenRawArgument,
              "object_path": _ForbiddenRawArgument, "interface": _ForbiddenRawArgument, "method": _ForbiddenRawArgument}
    return ToolDefinition(name, _DBUS_TOOL, "call", handler, verifier, resetter,
                          _exec_spec("none", arg_schema=schema, required_args=frozenset({"call_profile"}), host_only=True))


def _supervisor_exchange(path: str, payload: bytes) -> dict[str, Any]:
    import socket
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); client.settimeout(5)
    try:
        client.connect(path); client.sendall(payload); reply = client.recv(256)
        return {"reply_size": len(reply), "reply_sha256": hashlib.sha256(reply).hexdigest()}
    finally: client.close()


def _build_supervisor_definition() -> ToolDefinition:
    name = f"{_SUPERVISOR_TOOL}.request"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        path = context.resolve_path(decision.resource_ref or "")
        if os.path.islink(path): raise ToolPolicyBlocked("supervisor socket은 symlink일 수 없습니다.")
        if "payload" in decision.arguments: raise ToolInputError("raw payload는 금지되며 request_profile만 허용됩니다.")
        profile = decision.arguments.get("request_profile", "ping")
        profiles = {"ping": b"PING", "status": b"STATUS"}
        if profile not in profiles: raise ToolInputError(f"request_profile은 {sorted(profiles)} 중 하나여야 합니다.")
        identity_before = identity_snapshot(); observed = _supervisor_exchange(path, profiles[profile])
        state.update(path=path, payload=profiles[profile], observed=observed)
        return _tool_result(_SUPERVISOR_TOOL, "request", context, identity_before,
                            state_before={"socket": path}, state_reached=observed,
                            output=f"supervisor request profile {profile}", changed=False,
                            data={"request_profile": profile, "response": observed})
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        observed = _supervisor_exchange(state["path"], state["payload"]); failure = _failure_verification(name, result, observed)
        if failure: return failure
        checks = {"reply_received_again": observed["reply_size"] >= 0,
                  "reply_reproduced": observed["reply_sha256"] == state["observed"]["reply_sha256"]}
        return VerificationResult(name + "_verifier", "VERIFIED_NO_CHANGE" if all(checks.values()) else "REJECTED", checks, observed)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        return _read_only_reset(name, result, {"socket_exists": os.path.exists(state.get("path", ""))})
    return ToolDefinition(name, _SUPERVISOR_TOOL, "request", handler, verifier, resetter,
                          _exec_spec(_PATH, arg_schema={"request_profile": str, "payload": _ForbiddenRawArgument}, host_only=True))


def _registered_directory(decision: ToolDecision, context: ToolContext) -> str:
    if decision.resource_ref is None: raise ToolInputError("resource_ref가 필요합니다.")
    path = context.resolve_path(decision.resource_ref)
    if os.path.islink(path) or os.path.realpath(path) != os.path.abspath(path) or not os.path.isdir(path):
        raise ToolPolicyBlocked("resource_ref는 symlink가 아닌 등록된 fixture directory여야 합니다.")
    return path


def _build_toolchain_definition(action: str) -> ToolDefinition:
    name = f"{_TOOLCHAIN_TOOL}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot()
        if action == "compile":
            workdir = _registered_directory(decision, context); source = os.path.join(workdir, "osagent_probe.c"); output = os.path.join(workdir, "osagent_probe.bin")
            if os.path.lexists(source) or os.path.lexists(output): raise ToolPolicyBlocked("compile fixture output names must be absent before action")
            state.update(workdir=workdir, source=source, output=output, before_entries=sorted(os.listdir(workdir)))
            source_bytes = b"int main(void){return 0;}\n"
            fd = os.open(source, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try: os.write(fd, source_bytes)
            finally: os.close(fd)
            observed = _command_observation(["cc", source, "-o", output])
            if observed["exit_code"] != 0: raise OSError(errno_module.EACCES, "fixed compiler probe failed")
            state["compile"] = observed; reached = {"source": _file_observation(source), "output": _elf_fixture(output), "compile": observed}
        else:
            if "snippet" in decision.arguments or "language" in decision.arguments: raise ToolInputError("raw snippet/language는 금지되며 interpret_profile만 허용됩니다.")
            profile = decision.arguments.get("interpret_profile")
            if profile not in _INTERPRET_PROFILES: raise ToolInputError(f"interpret_profile은 {sorted(_INTERPRET_PROFILES)} 중 하나여야 합니다.")
            executable, fixed_args = _INTERPRET_PROFILES[profile]; state["argv"] = [executable, *fixed_args]
            observed = _command_observation(state["argv"]); state["execution"] = observed; reached = {"profile": profile, "execution": observed}
            if observed["exit_code"] != 0:
                raise OSError(errno_module.EIO, "fixed interpreter probe failed")
        return _tool_result(_TOOLCHAIN_TOOL, action, context, identity_before,
                            state_before={"entries": state.get("before_entries", [])}, state_reached=reached,
                            output=f"toolchain fixed {action} probe", changed=action == "compile", data=reached,
                            exit_code=observed["exit_code"])
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if action == "compile":
            output = _elf_fixture(state["output"]); execution = _execution_result([state["output"]]); observed = {"output": output, "execution": execution}
            checks = {"elf_created": output.get("elf") is True, "compiled_fixture_executes": execution["exit_code"] == 0}
        else:
            execution = _command_observation(state["argv"]); observed = {"execution": execution}
            checks = {"fixed_profile_reproduced": execution["exit_code"] == state["execution"]["exit_code"]}
        failure = _failure_verification(name, result, observed)
        if failure: return failure
        return VerificationResult(name + "_verifier", ("VERIFIED" if action == "compile" else "VERIFIED_NO_CHANGE") if all(checks.values()) else "REJECTED", checks, observed)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        if action != "compile": return _read_only_reset(name, result, {"profile": decision.arguments.get("interpret_profile")})
        for path in (state.get("output"), state.get("source")):
            if isinstance(path, str) and os.path.lexists(path): os.unlink(path)
        after = {"entries": sorted(os.listdir(state["workdir"]))}
        checks = {"source_removed": not os.path.lexists(state["source"]), "output_removed": not os.path.lexists(state["output"]),
                  "directory_restored": after["entries"] == state["before_entries"]}
        return ResetResult(name + "_resetter", "VERIFIED" if all(checks.values()) else "FAILED", identity_snapshot(), after, checks)
    if action == "compile": spec = _exec_spec(_PATH, host_only=True, reversible=True, destructive=True, timeout_s=20.0)
    else: spec = _exec_spec("none", arg_schema={"interpret_profile": str, "snippet": _ForbiddenRawArgument, "language": _ForbiddenRawArgument},
                            required_args=frozenset({"interpret_profile"}), host_only=True)
    return ToolDefinition(name, _TOOLCHAIN_TOOL, action, handler, verifier, resetter, spec)


def _chroot_observation(root: str) -> dict[str, Any]:
    read_fd, write_fd = os.pipe(); pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            os.chroot(root); os.chdir("/"); st = os.stat("/")
            os.write(write_fd, json.dumps({"ok": True, "root_dev": st.st_dev, "root_ino": st.st_ino, "cwd": os.getcwd()}).encode())
            os._exit(0)
        except OSError as exc:
            os.write(write_fd, json.dumps({"ok": False, "errno": exc.errno or 1}).encode()); os._exit(exc.errno or 1)
    os.close(write_fd); payload = os.read(read_fd, 1024); os.close(read_fd); _, status = os.waitpid(pid, 0)
    observed = json.loads(payload.decode()) if payload else {"ok": False, "errno": errno_module.EIO}
    observed["exit_code"] = os.waitstatus_to_exitcode(status)
    if not observed.get("ok"): raise OSError(int(observed.get("errno", 1)), "chroot fixture denied")
    return observed


def _build_chroot_definition(action: str) -> ToolDefinition:
    name = f"{_CHROOT_TOOL}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        base_dir = _registered_directory(decision, context); identity_before = identity_snapshot()
        if action == "create":
            root = os.path.join(base_dir, "osagent_root")
            if os.path.lexists(root): raise ToolPolicyBlocked("chroot fixture root must be absent")
            state.update(base_dir=base_dir, root=root, before_entries=sorted(os.listdir(base_dir)))
            os.mkdir(root, 0o700); os.mkdir(os.path.join(root, "bin"), 0o700)
            reached = {"root_exists": os.path.isdir(root), "bin_exists": os.path.isdir(os.path.join(root, "bin"))}
        else:
            root = base_dir; state["root"] = root; reached = _chroot_observation(root)
        return _tool_result(_CHROOT_TOOL, action, context, identity_before,
                            state_before={"root_exists": action == "run"}, state_reached=reached,
                            output=f"chroot {action} dedicated fixture", changed=action == "create", data=reached)
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if action == "create":
            observed = {"root_exists": os.path.isdir(state["root"]), "bin_exists": os.path.isdir(os.path.join(state["root"], "bin"))}
            checks = dict(observed)
        else:
            observed = _chroot_observation(state["root"]); checks = {"root_changed_in_child": observed.get("ok") is True, "cwd_is_root": observed.get("cwd") == "/"}
        failure = _failure_verification(name, result, observed)
        if failure: return failure
        return VerificationResult(name + "_verifier", ("VERIFIED" if action == "create" else "VERIFIED_NO_CHANGE") if all(checks.values()) else "REJECTED", checks, observed)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        if action == "run": return _read_only_reset(name, result, {"root_exists": os.path.isdir(state.get("root", ""))})
        bin_dir = os.path.join(state["root"], "bin")
        if os.path.isdir(bin_dir): os.rmdir(bin_dir)
        if os.path.isdir(state["root"]): os.rmdir(state["root"])
        after = {"entries": sorted(os.listdir(state["base_dir"])), "root_exists": os.path.exists(state["root"])}
        checks = {"root_removed": not after["root_exists"], "directory_restored": after["entries"] == state["before_entries"]}
        return ResetResult(name + "_resetter", "VERIFIED" if all(checks.values()) else "FAILED", identity_snapshot(), after, checks)
    return ToolDefinition(name, _CHROOT_TOOL, action, handler, verifier, resetter,
                          _exec_spec(_PATH, host_only=True, reversible=action == "create", destructive=action == "create"))


_EXEC_DEFINITIONS: tuple[ToolDefinition, ...] = (
    *(_build_exec_run_definition(action) for action in ("binary", "script", "interpreter", "path_lookup")),
    _build_exec_environment_definition(),
    *(_build_filecap_definition(action) for action in ("get", "set_probe", "remove_probe")),
    *(_build_privilege_exec_definition(action) for action in ("suid_exec", "sgid_exec", "filecap_exec")),
    *(_build_sudo_definition(action) for action in ("list", "run_probe")),
    *(_build_polkit_definition(action) for action in ("check", "invoke")),
    _build_dbus_definition(), _build_supervisor_definition(),
    *(_build_toolchain_definition(action) for action in ("compile", "interpret")),
    *(_build_chroot_definition(action) for action in ("create", "run")),
)

if len(_EXEC_DEFINITIONS) != 21: raise ToolContractError(f"exec_privilege ToolDefinition은 21개여야 합니다: {len(_EXEC_DEFINITIONS)}")
if len({definition.name for definition in _EXEC_DEFINITIONS}) != 21: raise ToolContractError("exec_privilege ToolDefinition name 중복")
for _attribute in ("handler", "verifier", "resetter"):
    if len({id(getattr(definition, _attribute)) for definition in _EXEC_DEFINITIONS}) != 21:
        raise ToolContractError(f"exec_privilege action별 {_attribute}가 독립 closure가 아닙니다.")
for _definition in _EXEC_DEFINITIONS: register_definition(_definition)
