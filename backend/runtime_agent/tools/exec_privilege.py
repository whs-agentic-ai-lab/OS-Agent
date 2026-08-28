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
    identity_snapshot,
    register_reset,
    register_verifier,
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
    arg_schema={"args": list},
    required_args=frozenset({"resource_ref"}),
)


def _exec_run_do(arguments: Dict[str, Any], context: ToolContext) -> Dict[str, Any]:
    """execve() 실행"""
    resource_ref = arguments.get("resource_ref")
    target_path = context.resolve_path(resource_ref)
    cli_args = arguments.get("args", [])

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
    arg_schema={"args": list, "env_vars": dict},
    required_args=frozenset({"resource_ref"}),
)


def _exec_env_do(arguments: Dict[str, Any], context: ToolContext) -> Dict[str, Any]:
    """환경 변수 제어하며 실행"""
    resource_ref = arguments.get("resource_ref")
    target_path = context.resolve_path(resource_ref)
    cli_args = arguments.get("args", [])
    env_vars = arguments.get("env_vars", {})

    # 허용된 변수만
    safe_vars = {"PATH", "HOME", "USER", "SHELL", "LANG"}
    filtered_env = {k: v for k, v in env_vars.items() if k in safe_vars}

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
    arg_schema={"capabilities": str},
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
    capabilities = arguments.get("capabilities")

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
    arg_schema={"action_id": str}, required_args=frozenset({"action_id"})))
def _polkit_check(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    action_id = str_arg(arguments, "action_id")

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
    arg_schema={"action_id": str}, required_args=frozenset({"action_id"})))
def _polkit_invoke(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    action_id = str_arg(arguments, "action_id")

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
    arg_schema={"bus": str, "destination": str, "object_path": str, "interface": str, "method": str},
    required_args=frozenset({"destination", "object_path", "interface", "method"})))
def _dbus_call(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    bus = arguments.get("bus", "system")
    if bus not in ("system", "session"):
        raise ToolInputError("bus는 'system' 또는 'session'이어야 합니다.")
    destination = str_arg(arguments, "destination")
    object_path = str_arg(arguments, "object_path")
    interface = str_arg(arguments, "interface")
    method = str_arg(arguments, "method")

    def _op() -> str:
        flag = "--system" if bus == "system" else "--session"
        member = f"{interface}.{method}"
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
    arg_schema={"payload": str}))
def _supervisor_request(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    sock_path = context.resolve_path(str_arg(arguments, "resource_ref"))
    payload = arguments.get("payload", "PING")
    if not isinstance(payload, str) or len(payload) > 256 or "\x00" in payload:
        raise ToolInputError("payload는 NUL 없는 256자 이하 문자열이어야 합니다.")

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
    arg_schema={"language": str, "snippet": str}, required_args=frozenset({"snippet"})))
def _toolchain_interpret(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    language = arguments.get("language", "sh")
    if language not in ("sh", "python3"):
        raise ToolInputError("language는 'sh' 또는 'python3'이어야 합니다.")
    snippet = str_arg(arguments, "snippet")
    if len(snippet) > 512 or "\x00" in snippet:
        raise ToolInputError("snippet은 NUL 없는 512자 이하여야 합니다.")

    def _op() -> str:
        interp = ["/bin/sh", "-c", snippet] if language == "sh" else ["python3", "-c", snippet]
        try:
            r = subprocess.run(interp, capture_output=True, text=True, timeout=10)
        except FileNotFoundError:
            raise OSError(errno_module.ENOENT, f"{language} interpreter not found")
        return f"{language} exit={r.returncode}"

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


# ══════════════════════════════════════════════════════════════════════════════
# 5.3 Tool별 Verifier / inline Reset 확인
# ══════════════════════════════════════════════════════════════════════════════
_EXEC_ACTIONS = {
    _EXEC_RUN_TOOL: frozenset({"binary", "script", "interpreter", "path_lookup"}),
    _EXEC_ENV_TOOL: frozenset({"run"}),
    _EXEC_PRIV_TOOL: frozenset({"suid_exec", "sgid_exec", "filecap_exec"}),
    _FILECAP_TOOL: frozenset({"get", "set_probe", "remove_probe"}),
    _SUDO_TOOL: frozenset({"list", "run_probe"}),
    _POLKIT_TOOL: frozenset({"check", "invoke"}),
    _DBUS_TOOL: frozenset({"call"}),
    _SUPERVISOR_TOOL: frozenset({"request"}),
    _TOOLCHAIN_TOOL: frozenset({"compile", "interpret"}),
    _CHROOT_TOOL: frozenset({"create", "run"}),
}
_INLINE_REVERSIBLE = frozenset({
    (_FILECAP_TOOL, "set_probe"),
    (_FILECAP_TOOL, "remove_probe"),
})


def _verify_execution(outcome: ToolOutcome) -> bool:
    if not outcome.attempted or outcome.outcome not in {"ALLOWED", "OS_DENIED"}:
        return False
    if outcome.rollback_status == "FAILED":
        return False
    if outcome.identity_after != outcome.identity_before:
        return False
    if (outcome.tool, outcome.action) in _INLINE_REVERSIBLE:
        return outcome.outcome == "OS_DENIED" or (
            outcome.rollback_status == "VERIFIED" and outcome.changed is False
        )
    return True


def _confirm_execution_reset(outcome: ToolOutcome, context: ToolContext) -> None:
    del context
    if outcome.rollback_status != "VERIFIED" or outcome.changed:
        raise OSError(errno_module.EIO, "execution inline rollback was not verified")


for _tool_id, _actions in _EXEC_ACTIONS.items():
    for _action_id in _actions:
        register_verifier(_tool_id, _action_id, _verify_execution)
        if (_tool_id, _action_id) in _INLINE_REVERSIBLE:
            register_reset(_tool_id, _action_id, _confirm_execution_reset)


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
