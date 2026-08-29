"""OS-tool 정리.md 5.1 신분·Capability — 7개 Tool / 23개 Action.

| # | Tool | 비고 |
|---|------|------|
| 1 | privilege.identity_probe | UID/EUID/FSUID/GID/EGID/FSGID·보조 그룹 |
| 2 | privilege.capability_probe | P/E/I/A/B capability 추가·제거·clear |
| 3 | privilege.securebits_probe | securebit 설정·잠금 |
| 4 | privilege.no_new_privs_probe | no_new_privs 활성화 |
| 5 | keyring.manage | Key 추가·조회·수정·연결·해제·폐기·권한 변경 |
| 6 | session.manage | setsid, setpgid |
| 7 | umask.set | 현재 공격 문맥 umask 변경 |

이 파일의 모든 함수는 "성공 판정"을 하지 않는다. OS가 실제로 반환한 값을
`attempt()`(base.py)에 그대로 넘기고, ALLOWED/OS_DENIED/ERROR 중 무엇으로
분류할지는 attempt()가 errno만 보고 기계적으로 정한다.
"""
from __future__ import annotations

import ctypes
import errno as errno_module
import hashlib
import json
import os
import signal
import sys
import time
from typing import Any, Callable

from . import base
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
    prctl,
    raw_syscall,
    register,
    register_definition,
    identity_snapshot,
)


# ---------------------------------------------------------------------------
# 입력 검증 헬퍼 — Action별 필수 인자와 형식만 본다. OS 호출은 하지 않는다.
# ---------------------------------------------------------------------------


def _require(arguments: dict[str, Any], *keys: str) -> None:
    missing = [key for key in keys if key not in arguments]
    if missing:
        raise ToolInputError(f"필수 인자가 없습니다: {', '.join(missing)}")


def _int_arg(arguments: dict[str, Any], key: str) -> int:
    _require(arguments, key)
    value = arguments[key]
    if not isinstance(value, int) or isinstance(value, bool):
        raise ToolInputError(f"{key}는 정수여야 합니다.")
    return value


def _int_arg_default(arguments: dict[str, Any], key: str, default: int) -> int:
    if key not in arguments:
        return default
    return _int_arg(arguments, key)


def _list_int_arg(arguments: dict[str, Any], key: str) -> list[int]:
    _require(arguments, key)
    value = arguments[key]
    if not isinstance(value, list) or not all(
        isinstance(item, int) and not isinstance(item, bool) for item in value
    ):
        raise ToolInputError(f"{key}는 정수 배열이어야 합니다.")
    return value


def _str_arg(arguments: dict[str, Any], key: str) -> str:
    _require(arguments, key)
    value = arguments[key]
    if not isinstance(value, str) or not value:
        raise ToolInputError(f"{key}는 비어 있지 않은 문자열이어야 합니다.")
    return value


# ---------------------------------------------------------------------------
# 1. privilege.identity_probe
# ---------------------------------------------------------------------------

_IDENTITY_TOOL = "privilege.identity_probe"


@register(_IDENTITY_TOOL, "setuid")
def _setuid(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    uid = _int_arg(arguments, "uid")
    return attempt(_IDENTITY_TOOL, action, lambda: (os.setuid(uid), f"uid -> {uid}")[1])


@register(_IDENTITY_TOOL, "seteuid")
def _seteuid(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    euid = _int_arg(arguments, "euid")
    return attempt(_IDENTITY_TOOL, action, lambda: (os.seteuid(euid), f"euid -> {euid}")[1])


@register(_IDENTITY_TOOL, "setgid")
def _setgid(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    gid = _int_arg(arguments, "gid")
    return attempt(_IDENTITY_TOOL, action, lambda: (os.setgid(gid), f"gid -> {gid}")[1])


@register(_IDENTITY_TOOL, "setegid")
def _setegid(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    egid = _int_arg(arguments, "egid")
    return attempt(_IDENTITY_TOOL, action, lambda: (os.setegid(egid), f"egid -> {egid}")[1])


@register(_IDENTITY_TOOL, "setgroups")
def _setgroups(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    groups = _list_int_arg(arguments, "groups")

    def _op() -> str:
        os.setgroups(groups)
        return f"groups -> {groups}"

    return attempt(_IDENTITY_TOOL, action, _op)


@register(_IDENTITY_TOOL, "setfsuid")
def _setfsuid(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    # setfsuid(2)는 errno로 실패를 알리지 않고 항상 "이전 fsuid"를 반환한다.
    # 그래서 반환값이 요청값과 다르면 OS가 조용히 거부한 것으로 판단한다.
    fsuid = _int_arg(arguments, "fsuid")

    def _op() -> str:
        previous = base.libc.setfsuid(ctypes.c_uint(fsuid))
        applied = base.libc.setfsuid(ctypes.c_uint(0xFFFFFFFF))  # -1: 조회만, 변경 없음
        if applied != fsuid:
            raise OSError(1, f"setfsuid가 반영되지 않았습니다(이전={previous}, 적용={applied})")
        return f"fsuid: {previous} -> {applied}"

    return attempt(_IDENTITY_TOOL, action, _op)


@register(_IDENTITY_TOOL, "setfsgid")
def _setfsgid(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    fsgid = _int_arg(arguments, "fsgid")

    def _op() -> str:
        previous = base.libc.setfsgid(ctypes.c_uint(fsgid))
        applied = base.libc.setfsgid(ctypes.c_uint(0xFFFFFFFF))
        if applied != fsgid:
            raise OSError(1, f"setfsgid가 반영되지 않았습니다(이전={previous}, 적용={applied})")
        return f"fsgid: {previous} -> {applied}"

    return attempt(_IDENTITY_TOOL, action, _op)


# ---------------------------------------------------------------------------
# 2. privilege.capability_probe
# ---------------------------------------------------------------------------

_CAP_TOOL = "privilege.capability_probe"
_CAP_SETS = frozenset({"effective", "permitted", "inheritable", "ambient", "bounding"})


def _capability_arg(arguments: dict[str, Any]) -> int:
    capability = _int_arg(arguments, "capability")
    if not 0 <= capability <= 31:
        raise ToolInputError("capability는 현재 구현 범위인 0~31이어야 합니다.")
    return capability


def _cap_set_name(arguments: dict[str, Any], *, default: str = "effective") -> str:
    name = arguments.get("set_name", default)
    if name not in _CAP_SETS:
        raise ToolInputError(f"set_name은 {sorted(_CAP_SETS)} 중 하나여야 합니다.")
    return name


def _change_epi(set_name: str, capability: int, *, add: bool) -> None:
    effective, permitted, inheritable = base.capget_raw()
    values = {"effective": effective, "permitted": permitted, "inheritable": inheritable}
    bit = 1 << capability
    values[set_name] = values[set_name] | bit if add else values[set_name] & ~bit
    base.capset_raw(values["effective"], values["permitted"], values["inheritable"])


@register(_CAP_TOOL, "add")
def _cap_add(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    capability = _capability_arg(arguments)
    set_name = _cap_set_name(arguments)

    def _op() -> str:
        if set_name in {"effective", "permitted", "inheritable"}:
            _change_epi(set_name, capability, add=True)
        elif set_name == "ambient":
            prctl(base.PR_CAP_AMBIENT, base.PR_CAP_AMBIENT_RAISE, capability, 0, 0)
        else:
            raise OSError(1, "Linux bounding capability set에는 capability를 다시 추가할 수 없습니다.")
        return f"{set_name} capability {capability} add"

    return attempt(_CAP_TOOL, action, _op)


@register(_CAP_TOOL, "drop")
def _cap_drop(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    capability = _capability_arg(arguments)
    set_name = _cap_set_name(arguments)

    def _op() -> str:
        if set_name in {"effective", "permitted", "inheritable"}:
            _change_epi(set_name, capability, add=False)
        elif set_name == "ambient":
            prctl(base.PR_CAP_AMBIENT, base.PR_CAP_AMBIENT_LOWER, capability, 0, 0)
        else:
            prctl(base.PR_CAPBSET_DROP, capability, 0, 0, 0)
        return f"{set_name} capability {capability} drop"

    return attempt(_CAP_TOOL, action, _op)


@register(_CAP_TOOL, "clear")
def _cap_clear(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    set_name = _cap_set_name(arguments)

    def _op() -> str:
        if set_name in {"effective", "permitted", "inheritable"}:
            effective, permitted, inheritable = base.capget_raw()
            values = {"effective": effective, "permitted": permitted, "inheritable": inheritable}
            values[set_name] = 0
            base.capset_raw(values["effective"], values["permitted"], values["inheritable"])
        elif set_name == "ambient":
            prctl(base.PR_CAP_AMBIENT, base.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
        else:
            raise OSError(1, "Linux bounding capability set은 일괄 clear할 수 없습니다.")
        return f"{set_name} capability clear"

    return attempt(_CAP_TOOL, action, _op)


# ---------------------------------------------------------------------------
# 3. privilege.securebits_probe
# ---------------------------------------------------------------------------

_SECUREBITS_TOOL = "privilege.securebits_probe"


@register(_SECUREBITS_TOOL, "set")
def _securebits_set(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    bits = _int_arg(arguments, "bits")

    def _op() -> str:
        prctl(base.PR_SET_SECUREBITS, bits, 0, 0, 0)
        return f"securebits -> {bin(bits)}"

    return attempt(_SECUREBITS_TOOL, action, _op)


@register(_SECUREBITS_TOOL, "lock")
def _securebits_lock(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    bits = _int_arg(arguments, "bits")
    if bits < 0 or bits > 0x55:
        raise ToolInputError("bits는 securebit 값 비트 범위(0x00~0x55)여야 합니다.")
    locked = bits | (bits << 1)

    def _op() -> str:
        prctl(base.PR_SET_SECUREBITS, locked, 0, 0, 0)
        return f"securebits lock -> {bin(locked)}"

    return attempt(_SECUREBITS_TOOL, action, _op)


# ---------------------------------------------------------------------------
# 4. privilege.no_new_privs_probe
# ---------------------------------------------------------------------------

_NNP_TOOL = "privilege.no_new_privs_probe"


@register(_NNP_TOOL, "enable")
def _no_new_privs_enable(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    # 커널 문서: 한 번 켜면 같은 프로세스(및 자식)에서 되돌릴 수 없다.
    # 이 함수를 호출하는 쪽(runtime_agent)은 반드시 별도 프로세스/자식에서
    # 실행해 호출 프로세스 자체의 상태를 되돌릴 수 없게 만들지 않아야 한다.
    def _op() -> str:
        prctl(base.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        return "no_new_privs=1 (이 프로세스에서는 되돌릴 수 없음)"

    return attempt(_NNP_TOOL, action, _op)


# ---------------------------------------------------------------------------
# 5. keyring.manage
# ---------------------------------------------------------------------------

_KEYRING_TOOL = "keyring.manage"

_KEYCTL_UPDATE = 2
_KEYCTL_REVOKE = 3
_KEYCTL_SETPERM = 5
_KEYCTL_LINK = 8
_KEYCTL_UNLINK = 9
_KEYCTL_READ = 11

_KEYRING_TARGETS = {
    "thread": -1,  # KEY_SPEC_THREAD_KEYRING
    "process": -2,  # KEY_SPEC_PROCESS_KEYRING
    "session": -3,  # KEY_SPEC_SESSION_KEYRING
}


def _resolve_keyring(name: str) -> int:
    if name not in _KEYRING_TARGETS:
        raise ToolInputError(
            f"허용되지 않은 keyring 대상입니다: {name} (허용: {sorted(_KEYRING_TARGETS)})"
        )
    return _KEYRING_TARGETS[name]


@register(_KEYRING_TOOL, "add")
def _keyring_add(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    description = _str_arg(arguments, "description")
    payload = _str_arg(arguments, "payload")
    keyring = _resolve_keyring(_str_arg(arguments, "keyring"))
    key_type = arguments.get("key_type", "user")
    if not isinstance(key_type, str) or not key_type:
        raise ToolInputError("key_type은 비어 있지 않은 문자열이어야 합니다.")

    def _op() -> str:
        payload_bytes = payload.encode("utf-8")
        key_id = raw_syscall(
            "add_key",
            key_type.encode("utf-8"),
            description.encode("utf-8"),
            payload_bytes,
            len(payload_bytes),
            keyring,
        )
        return f"key_id={key_id}"

    return attempt(_KEYRING_TOOL, action, _op)


@register(_KEYRING_TOOL, "read")
def _keyring_read(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    key_id = _int_arg(arguments, "key_id")

    def _op() -> str:
        buf_size = 4096
        buf = ctypes.create_string_buffer(buf_size)
        written = raw_syscall("keyctl", _KEYCTL_READ, key_id, buf, buf_size)
        return buf.raw[: max(written, 0)].decode("utf-8", errors="replace")

    return attempt(_KEYRING_TOOL, action, _op)


@register(_KEYRING_TOOL, "update")
def _keyring_update(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    key_id = _int_arg(arguments, "key_id")
    payload = _str_arg(arguments, "payload")

    def _op() -> str:
        payload_bytes = payload.encode("utf-8")
        raw_syscall("keyctl", _KEYCTL_UPDATE, key_id, payload_bytes, len(payload_bytes))
        return f"key_id={key_id} 페이로드 갱신"

    return attempt(_KEYRING_TOOL, action, _op)


@register(_KEYRING_TOOL, "link")
def _keyring_link(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    key_id = _int_arg(arguments, "key_id")
    keyring = _resolve_keyring(_str_arg(arguments, "keyring"))

    def _op() -> str:
        raw_syscall("keyctl", _KEYCTL_LINK, key_id, keyring)
        return f"key_id={key_id} -> keyring={keyring}"

    return attempt(_KEYRING_TOOL, action, _op)


@register(_KEYRING_TOOL, "unlink")
def _keyring_unlink(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    key_id = _int_arg(arguments, "key_id")
    keyring = _resolve_keyring(_str_arg(arguments, "keyring"))

    def _op() -> str:
        raw_syscall("keyctl", _KEYCTL_UNLINK, key_id, keyring)
        return f"key_id={key_id} unlink from keyring={keyring}"

    return attempt(_KEYRING_TOOL, action, _op)


@register(_KEYRING_TOOL, "revoke")
def _keyring_revoke(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    key_id = _int_arg(arguments, "key_id")

    def _op() -> str:
        raw_syscall("keyctl", _KEYCTL_REVOKE, key_id)
        return f"key_id={key_id} revoked"

    return attempt(_KEYRING_TOOL, action, _op)


@register(_KEYRING_TOOL, "set_permission")
def _keyring_set_permission(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    key_id = _int_arg(arguments, "key_id")
    permissions = _int_arg(arguments, "permissions")

    def _op() -> str:
        raw_syscall("keyctl", _KEYCTL_SETPERM, key_id, ctypes.c_uint32(permissions))
        return f"key_id={key_id} permissions={oct(permissions)}"

    return attempt(_KEYRING_TOOL, action, _op)


# ---------------------------------------------------------------------------
# 6. session.manage
# ---------------------------------------------------------------------------

_SESSION_TOOL = "session.manage"


@register(_SESSION_TOOL, "setsid")
def _setsid(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    return attempt(_SESSION_TOOL, action, lambda: f"new sid={os.setsid()}")


@register(_SESSION_TOOL, "setpgid")
def _setpgid(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    pid = _int_arg_default(arguments, "pid", 0)
    pgid = _int_arg_default(arguments, "pgid", 0)
    if pid != 0:
        # 자기 자신(0)이 아닌 다른 PID를 대상으로 하면 등록된 Target인지 확인한다.
        context.resolve_target(str(pid))

    def _op() -> str:
        os.setpgid(pid, pgid)
        return f"pid={pid} pgid={pgid}"

    return attempt(_SESSION_TOOL, action, _op)


# ---------------------------------------------------------------------------
# 7. umask.set
# ---------------------------------------------------------------------------

_UMASK_TOOL = "umask.set"


@register(_UMASK_TOOL, "set")
def _umask_set(action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    mask = _int_arg(arguments, "mask")
    if not (0 <= mask <= 0o777):
        raise ToolInputError("mask는 0 ~ 0o777 범위의 8진수 값이어야 합니다.")

    def _op() -> str:
        previous = os.umask(mask)
        return f"umask {oct(previous)} -> {oct(mask)}"

    return attempt(_UMASK_TOOL, action, _op)


# ══════════════════════════════════════════════════════════════════════════════
# ToolDefinition 전환 계층
#
# 신분·Capability family는 성공한 setuid/securebits/no_new_privs/setsid 등을
# Agent 프로세스 안에서 되돌릴 수 없다. 따라서 action마다 전용 child fixture를
# 만들고, handler가 child에서 syscall을 실행한 뒤 살려 둔다. verifier는 같은
# child에 별도 observe 명령을 보내 실제 syscall 상태를 재조회하고, resetter는
# child를 종료·wait하여 실행 전의 "fixture 없음" 상태를 복구한다.
# ══════════════════════════════════════════════════════════════════════════════

_IDENTITY_EXECUTORS = frozenset({"host", "container"})
_IDENTITY_TBS = frozenset({"TB-HH-U1U2", "TB-CC-C1C2"})
_FIXTURE_LIMITS = {"max_children": 1, "max_keys": 2, "max_payload_bytes": 256}
_FIXTURE_STOPS = frozenset({"timeout", "child_exit", "rollback_failure"})
_ALLOWED_CAPABILITIES = frozenset(range(32))
_ALLOWED_UMASKS = frozenset({0o022, 0o027, 0o077})
_SECUREBIT_PROFILES = {
    "noroot": 1 << 0,
    "no_setuid_fixup": 1 << 2,
    "keep_caps": 1 << 4,
    "no_cap_ambient_raise": 1 << 6,
}


class _ForbiddenRawArgument:
    """Agent JSON이 직접 제공할 수 없는 uid/gid/key id/pid marker."""


def _identity_spec(
    *,
    arg_schema: dict[str, Any] | None = None,
    required_args: frozenset[str] = frozenset(),
    destructive: bool = False,
    timeout_s: float = 6.0,
) -> ToolSpec:
    return ToolSpec(
        resource_kind="self",
        allowed_executors=_IDENTITY_EXECUTORS,
        allowed_tbs=_IDENTITY_TBS,
        arg_schema=dict(arg_schema or {}),
        required_args=required_args,
        reversible=True,
        destructive=destructive,
        timeout_s=timeout_s,
        resource_limits=dict(_FIXTURE_LIMITS) if destructive else {},
        emergency_stop_conditions=_FIXTURE_STOPS if destructive else frozenset(),
    )


def _write_json_line(stream: Any, payload: dict[str, Any]) -> None:
    stream.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    stream.flush()


def _read_json_line(stream: Any) -> dict[str, Any]:
    line = stream.readline()
    if not line:
        raise OSError(errno_module.EPIPE, "fixture child response pipe closed")
    value = json.loads(line)
    if not isinstance(value, dict):
        raise OSError(errno_module.EPROTO, "fixture child response is not an object")
    return value


def _spawn_state_fixture(
    state: dict[str, Any],
    apply: Callable[[dict[str, Any]], dict[str, Any]],
    observe: Callable[[dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    command_r, command_w = os.pipe()
    response_r, response_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(command_w); os.close(response_r)
        command = os.fdopen(command_r, "r", encoding="utf-8", buffering=1)
        response = os.fdopen(response_w, "w", encoding="utf-8", buffering=1)
        child_state: dict[str, Any] = {}
        try:
            try:
                reached = apply(child_state)
                _write_json_line(response, {"ok": True, "observed": reached})
            except OSError as exc:
                _write_json_line(response, {"ok": False, "errno": exc.errno or 1, "error": str(exc)})
            except Exception as exc:
                _write_json_line(response, {"ok": False, "errno": 1, "error": str(exc)})
            for line in command:
                operation = line.strip()
                if operation == "observe":
                    try:
                        _write_json_line(response, {"ok": True, "observed": observe(child_state)})
                    except OSError as exc:
                        _write_json_line(response, {"ok": False, "errno": exc.errno or 1, "error": str(exc)})
                elif operation == "exit":
                    _write_json_line(response, {"ok": True, "exiting": True})
                    os._exit(0)
                else:
                    _write_json_line(response, {"ok": False, "errno": errno_module.EINVAL, "error": "unknown command"})
        finally:
            os._exit(1)
    os.close(command_r); os.close(response_w)
    command = os.fdopen(command_w, "w", encoding="utf-8", buffering=1)
    response = os.fdopen(response_r, "r", encoding="utf-8", buffering=1)
    state.update(fixture_pid=pid, fixture_command=command, fixture_response=response)
    initial = _read_json_line(response)
    if not initial.get("ok"):
        raise OSError(int(initial.get("errno", 1)), str(initial.get("error", "fixture apply failed")))
    observed = initial.get("observed")
    if not isinstance(observed, dict):
        raise OSError(errno_module.EPROTO, "fixture apply response has no observation")
    return observed


def _observe_state_fixture(state: dict[str, Any]) -> dict[str, Any]:
    command = state.get("fixture_command")
    response = state.get("fixture_response")
    if command is None or response is None:
        raise OSError(errno_module.ESRCH, "fixture child was not created")
    command.write("observe\n"); command.flush()
    message = _read_json_line(response)
    if not message.get("ok"):
        raise OSError(int(message.get("errno", 1)), str(message.get("error", "fixture observe failed")))
    observed = message.get("observed")
    if not isinstance(observed, dict):
        raise OSError(errno_module.EPROTO, "fixture observe response has no observation")
    return observed


def _fixture_proc_state(pid: int) -> dict[str, Any]:
    path = f"/proc/{pid}/status"
    observed: dict[str, Any] = {"pid": pid, "exists": os.path.exists(path)}
    if observed["exists"]:
        with open(path, encoding="utf-8") as stream:
            for line in stream:
                key, _, value = line.partition(":")
                if key in {"Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs"}:
                    observed[key] = value.strip()
    return observed


def _reset_state_fixture(name: str, state: dict[str, Any]) -> ResetResult:
    pid = state.get("fixture_pid")
    command = state.pop("fixture_command", None)
    response = state.pop("fixture_response", None)
    acknowledged = False
    if command is not None:
        try:
            command.write("exit\n"); command.flush()
            if response is not None:
                acknowledged = bool(_read_json_line(response).get("exiting"))
        except (BrokenPipeError, OSError):
            pass
        finally:
            command.close()
    if response is not None:
        response.close()
    reaped = False
    if isinstance(pid, int):
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            try:
                waited, _ = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                reaped = True
                break
            if waited == pid:
                reaped = True
                break
            time.sleep(0.01)
        if not reaped:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            reaped = True
    after = _fixture_proc_state(pid) if isinstance(pid, int) else {"exists": False}
    checks = {"child_reaped": reaped, "fixture_absent": after.get("exists") is False,
              "exit_acknowledged_or_forced": acknowledged or reaped}
    return ResetResult(
        resetter=f"{name}_resetter",
        status="VERIFIED" if all(checks.values()) else "FAILED",
        identity_after=identity_snapshot(),
        state_after=after,
        checks=checks,
        output="dedicated identity fixture child 종료·wait 완료",
    )


def _fixture_result(
    tool: str,
    action: str,
    context: ToolContext,
    identity_before: dict[str, Any],
    reached: dict[str, Any],
    pid: int,
) -> ToolResult:
    return ToolResult(
        run_id=context.run_id, action_id=context.action_id, tool=tool, action=action,
        attempted=True, outcome="ALLOWED", exit_code=0,
        output=f"dedicated fixture pid={pid} reached {action}",
        identity_before=identity_before, identity_reached=identity_snapshot(),
        state_before={"fixture_exists": False}, state_reached=reached,
        changed=True, temporary_changed=True, data={"fixture_pid": pid},
    )


def _fixture_verification(
    name: str,
    result: ToolResult,
    state: dict[str, Any],
    expected: Callable[[dict[str, Any]], dict[str, bool]],
) -> VerificationResult:
    if result.outcome != "ALLOWED":
        proc = _fixture_proc_state(state.get("fixture_pid", -1))
        checks = {"outcome_classified": result.outcome in {"OS_DENIED", "POLICY_BLOCKED", "ERROR"}}
        return VerificationResult(name + "_verifier", "VERIFIED_NO_CHANGE" if all(checks.values()) else "REJECTED", checks, proc)
    child_observed = _observe_state_fixture(state)
    proc_observed = _fixture_proc_state(state["fixture_pid"])
    checks = expected(child_observed)
    checks["fixture_alive"] = proc_observed.get("exists") is True
    return VerificationResult(
        verifier=name + "_verifier",
        status="VERIFIED" if all(checks.values()) else "REJECTED",
        checks=checks,
        observed={"child_requery": child_observed, "proc_requery": proc_observed},
    )


def _resolved_identity_value(decision: ToolDecision, context: ToolContext, argument: str) -> int:
    raw_name = argument.removesuffix("_ref")
    if raw_name in decision.arguments:
        raise ToolInputError(f"raw {raw_name}는 금지되며 {argument}만 허용됩니다.")
    ref = decision.arguments.get(argument)
    if not isinstance(ref, str) or not ref:
        raise ToolInputError(f"{argument}가 필요합니다.")
    value = context.resolve_resource(ref)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ToolPolicyBlocked(f"{argument}가 Harness의 uid/gid 정수 fixture를 가리키지 않습니다.")
    return value


def _child_identity_observation() -> dict[str, Any]:
    snapshot = identity_snapshot()
    snapshot["fsuid"] = int(base.libc.setfsuid(ctypes.c_uint(0xFFFFFFFF)))
    snapshot["fsgid"] = int(base.libc.setfsgid(ctypes.c_uint(0xFFFFFFFF)))
    return snapshot


def _build_identity_definition(action: str) -> ToolDefinition:
    name = f"{_IDENTITY_TOOL}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot()
        if action == "setgroups":
            if "groups" in decision.arguments:
                raise ToolInputError("raw groups는 금지되며 group_refs만 허용됩니다.")
            refs = decision.arguments.get("group_refs")
            if not isinstance(refs, list) or not refs or len(refs) > 16 or not all(isinstance(item, str) and item for item in refs):
                raise ToolInputError("group_refs는 1~16개의 등록된 group reference 배열이어야 합니다.")
            values = [context.resolve_resource(ref) for ref in refs]
            if not all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in values):
                raise ToolPolicyBlocked("group_refs 중 Harness GID fixture가 아닌 값이 있습니다.")
            requested: Any = sorted(set(values))
        else:
            ref_arg = {
                "setuid": "uid_ref", "seteuid": "euid_ref", "setgid": "gid_ref",
                "setegid": "egid_ref", "setfsuid": "fsuid_ref", "setfsgid": "fsgid_ref",
            }[action]
            requested = _resolved_identity_value(decision, context, ref_arg)

        def apply(child_state: dict[str, Any]) -> dict[str, Any]:
            child_state["requested"] = requested
            if action == "setuid": os.setuid(requested)
            elif action == "seteuid": os.seteuid(requested)
            elif action == "setgid": os.setgid(requested)
            elif action == "setegid": os.setegid(requested)
            elif action == "setgroups": os.setgroups(requested)
            elif action == "setfsuid":
                base.libc.setfsuid(ctypes.c_uint(requested))
            else:
                base.libc.setfsgid(ctypes.c_uint(requested))
            return _child_identity_observation()

        reached = _spawn_state_fixture(state, apply, lambda _state: _child_identity_observation())
        state["requested"] = requested
        return _fixture_result(_IDENTITY_TOOL, action, context, identity_before, reached, state["fixture_pid"])

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        del decision, context
        requested = state.get("requested")
        field = {
            "setuid": "uid", "seteuid": "euid", "setgid": "gid", "setegid": "egid",
            "setgroups": "groups", "setfsuid": "fsuid", "setfsgid": "fsgid",
        }[action]
        return _fixture_verification(
            name, result, state,
            lambda observed: {f"{field}_matches": sorted(observed.get(field, [])) == requested
                              if action == "setgroups" else observed.get(field) == requested},
        )

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        del decision, result, context
        return _reset_state_fixture(name, state)

    if action == "setgroups":
        schema = {"group_refs": list, "groups": _ForbiddenRawArgument}
        required = frozenset({"group_refs"})
    else:
        raw_arg = {"setuid": "uid", "seteuid": "euid", "setgid": "gid", "setegid": "egid", "setfsuid": "fsuid", "setfsgid": "fsgid"}[action]
        ref_arg = raw_arg + "_ref"
        schema = {ref_arg: str, raw_arg: _ForbiddenRawArgument}
        required = frozenset({ref_arg})
    return ToolDefinition(name, _IDENTITY_TOOL, action, handler, verifier, resetter,
                          _identity_spec(arg_schema=schema, required_args=required))


def _capability_observation() -> dict[str, Any]:
    effective, permitted, inheritable = base.capget_raw()
    ambient = 0
    bounding = 0
    for capability in _ALLOWED_CAPABILITIES:
        if prctl(base.PR_CAP_AMBIENT, base.PR_CAP_AMBIENT_IS_SET, capability, 0, 0):
            ambient |= 1 << capability
        if prctl(base.PR_CAPBSET_READ, capability, 0, 0, 0):
            bounding |= 1 << capability
    return {"effective": effective, "permitted": permitted, "inheritable": inheritable,
            "ambient": ambient, "bounding": bounding}


def _build_capability_definition(action: str) -> ToolDefinition:
    name = f"{_CAP_TOOL}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot()
        set_name = decision.arguments.get("set_name", "effective")
        if set_name not in _CAP_SETS:
            raise ToolInputError(f"set_name은 {sorted(_CAP_SETS)} 중 하나여야 합니다.")
        capability = decision.arguments.get("capability")
        if action != "clear" and (not isinstance(capability, int) or isinstance(capability, bool) or capability not in _ALLOWED_CAPABILITIES):
            raise ToolInputError("capability는 allowlist 0~31 중 하나여야 합니다.")
        if action == "clear" and set_name == "bounding":
            raise ToolPolicyBlocked("bounding set 일괄 clear는 복구 불가능하므로 제공하지 않습니다.")
        if action == "add" and set_name == "bounding":
            raise ToolPolicyBlocked("Linux bounding set에는 capability를 추가할 수 없습니다.")

        def apply(child_state: dict[str, Any]) -> dict[str, Any]:
            before = _capability_observation()
            child_state["before"] = before
            if set_name in {"effective", "permitted", "inheritable"}:
                effective, permitted, inheritable = base.capget_raw()
                values = {"effective": effective, "permitted": permitted, "inheritable": inheritable}
                if action == "clear": values[set_name] = 0
                elif action == "add": values[set_name] |= 1 << capability
                else: values[set_name] &= ~(1 << capability)
                base.capset_raw(values["effective"], values["permitted"], values["inheritable"])
            elif set_name == "ambient":
                operation = {"add": base.PR_CAP_AMBIENT_RAISE, "drop": base.PR_CAP_AMBIENT_LOWER,
                             "clear": base.PR_CAP_AMBIENT_CLEAR_ALL}[action]
                prctl(base.PR_CAP_AMBIENT, operation, 0 if action == "clear" else capability, 0, 0)
            elif action == "drop":
                prctl(base.PR_CAPBSET_DROP, capability, 0, 0, 0)
            child_state["set_name"] = set_name
            child_state["capability"] = capability
            return _capability_observation()

        reached = _spawn_state_fixture(state, apply, lambda _state: _capability_observation())
        state.update(set_name=set_name, capability=capability)
        return _fixture_result(_CAP_TOOL, action, context, identity_before, reached, state["fixture_pid"])

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        del decision, context
        set_name = state.get("set_name")
        capability = state.get("capability")
        def expected(observed: dict[str, Any]) -> dict[str, bool]:
            value = int(observed.get(set_name, 0))
            if action == "clear": reached = value == 0
            elif action == "add": reached = bool(value & (1 << capability))
            else: reached = not bool(value & (1 << capability))
            return {f"{set_name}_{action}_requeried": reached}
        return _fixture_verification(name, result, state, expected)

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        del decision, result, context
        return _reset_state_fixture(name, state)

    schema = {"set_name": str}
    required = frozenset()
    if action != "clear":
        schema["capability"] = int
        required = frozenset({"capability"})
    return ToolDefinition(name, _CAP_TOOL, action, handler, verifier, resetter,
                          _identity_spec(arg_schema=schema, required_args=required,
                                         destructive=_capability_action_is_destructive(action)))


def _capability_action_is_destructive(action: str) -> bool:
    """Drop/clear는 child fixture 내부에서만 파괴적이다; Harness gate를 요구한다."""
    return action in {"drop", "clear"}


def _build_securebits_definition(action: str) -> ToolDefinition:
    name = f"{_SECUREBITS_TOOL}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot()
        if "bits" in decision.arguments:
            raise ToolInputError("raw securebits 값은 금지되며 profile enum만 허용됩니다.")
        profile = decision.arguments.get("profile")
        if profile not in _SECUREBIT_PROFILES:
            raise ToolInputError(f"profile은 {sorted(_SECUREBIT_PROFILES)} 중 하나여야 합니다.")
        bits = _SECUREBIT_PROFILES[profile]
        requested = bits | (bits << 1) if action == "lock" else bits

        def apply(child_state: dict[str, Any]) -> dict[str, Any]:
            child_state["before"] = prctl(base.PR_GET_SECUREBITS, 0, 0, 0, 0)
            prctl(base.PR_SET_SECUREBITS, requested, 0, 0, 0)
            return {"securebits": prctl(base.PR_GET_SECUREBITS, 0, 0, 0, 0)}

        reached = _spawn_state_fixture(state, apply, lambda _state: {"securebits": prctl(base.PR_GET_SECUREBITS, 0, 0, 0, 0)})
        state["requested"] = requested
        return _fixture_result(_SECUREBITS_TOOL, action, context, identity_before, reached, state["fixture_pid"])

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        del decision, context
        return _fixture_verification(name, result, state,
                                     lambda observed: {"securebits_match": observed.get("securebits") == state.get("requested")})

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        del decision, result, context
        return _reset_state_fixture(name, state)

    return ToolDefinition(name, _SECUREBITS_TOOL, action, handler, verifier, resetter,
                          _identity_spec(arg_schema={"profile": str, "bits": _ForbiddenRawArgument},
                                         required_args=frozenset({"profile"}), destructive=action == "lock"))


def _build_nnp_definition() -> ToolDefinition:
    name = f"{_NNP_TOOL}.enable"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        del decision
        identity_before = identity_snapshot()
        def apply(child_state: dict[str, Any]) -> dict[str, Any]:
            child_state["before"] = prctl(base.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
            prctl(base.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
            return {"no_new_privs": prctl(base.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)}
        reached = _spawn_state_fixture(state, apply,
                                       lambda _state: {"no_new_privs": prctl(base.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)})
        return _fixture_result(_NNP_TOOL, "enable", context, identity_before, reached, state["fixture_pid"])

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        del decision, context
        return _fixture_verification(name, result, state,
                                     lambda observed: {"no_new_privs_enabled": observed.get("no_new_privs") == 1})

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        del decision, result, context
        return _reset_state_fixture(name, state)

    return ToolDefinition(name, _NNP_TOOL, "enable", handler, verifier, resetter,
                          _identity_spec(destructive=True))


_KEYCTL_JOIN_SESSION_KEYRING = 1
_KEYCTL_DESCRIBE = 6
_KEY_PERMISSION_PROFILES = {
    "possessor_view": 0x01000000,
    "possessor_all": 0x3F000000,
}


def _bounded_key_payload(arguments: dict[str, Any], *, default: str = "osagent-canary") -> bytes:
    value = arguments.get("payload", default)
    if not isinstance(value, str) or not value or "\x00" in value or len(value.encode()) > 256:
        raise ToolInputError("payload는 NUL 없는 1~256 byte 문자열이어야 합니다.")
    return value.encode()


def _keyctl_read_bytes(serial: int, *, limit: int = 4096) -> bytes:
    size = raw_syscall("keyctl", _KEYCTL_READ, serial, 0, 0)
    if size < 0 or size > limit:
        raise OSError(errno_module.EFBIG, f"key payload/list가 {limit} bytes를 초과합니다.")
    buffer = ctypes.create_string_buffer(max(size, 1))
    written = raw_syscall("keyctl", _KEYCTL_READ, serial, buffer, size)
    return bytes(buffer.raw[:written])


def _keyctl_describe(serial: int) -> str:
    buffer = ctypes.create_string_buffer(512)
    written = raw_syscall("keyctl", _KEYCTL_DESCRIBE, serial, buffer, len(buffer))
    return buffer.raw[:max(0, written - 1)].decode(errors="replace")


def _keyring_members(serial: int) -> list[int]:
    payload = _keyctl_read_bytes(serial)
    width = ctypes.sizeof(ctypes.c_int32)
    return [int.from_bytes(payload[index:index + width], sys.byteorder, signed=True)
            for index in range(0, len(payload) - (len(payload) % width), width)]


def _key_observation(child_state: dict[str, Any]) -> dict[str, Any]:
    action = child_state["action"]
    key_id = child_state["key_id"]
    session_id = child_state["session_id"]
    observed: dict[str, Any] = {"key_id": key_id, "session_id": session_id, "action": action}
    if action in {"link", "unlink"}:
        members = _keyring_members(session_id)
        observed.update(members=members, linked=key_id in members)
    elif action == "revoke":
        try:
            _keyctl_read_bytes(key_id)
            observed.update(readable=True, read_errno=None)
        except OSError as exc:
            observed.update(readable=False, read_errno=errno_module.errorcode.get(exc.errno or 0, str(exc.errno)))
    elif action == "set_permission":
        description = _keyctl_describe(key_id)
        fields = description.split(";", 4)
        observed.update(description=description, permissions=int(fields[3], 16) if len(fields) >= 4 else -1)
    else:
        payload = _keyctl_read_bytes(key_id)
        observed.update(payload_sha256=hashlib.sha256(payload).hexdigest(), payload_size=len(payload))
    return observed


def _build_keyring_definition(action: str) -> ToolDefinition:
    name = f"{_KEYRING_TOOL}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot()
        if "key_id" in decision.arguments:
            raise ToolInputError("raw key_id는 금지되며 action 내부 private key fixture만 허용됩니다.")
        payload = _bounded_key_payload(decision.arguments)
        updated = _bounded_key_payload({"payload": decision.arguments.get("updated_payload", "osagent-updated")})
        permission_profile = decision.arguments.get("permission_profile", "possessor_all")
        if permission_profile not in _KEY_PERMISSION_PROFILES:
            raise ToolInputError(f"permission_profile은 {sorted(_KEY_PERMISSION_PROFILES)} 중 하나여야 합니다.")

        def apply(child_state: dict[str, Any]) -> dict[str, Any]:
            session_name = f"osagent-{os.getpid()}-{context.action_id}"[:64]
            session_id = raw_syscall("keyctl", _KEYCTL_JOIN_SESSION_KEYRING, session_name.encode())
            target = -1 if action == "link" else session_id
            key_id = raw_syscall("add_key", b"user", b"osagent-fixture", payload, len(payload), target)
            child_state.update(action=action, session_id=session_id, key_id=key_id,
                               original_payload=payload, expected_payload=payload)
            if action == "update":
                raw_syscall("keyctl", _KEYCTL_UPDATE, key_id, updated, len(updated))
                child_state["expected_payload"] = updated
            elif action == "link":
                raw_syscall("keyctl", _KEYCTL_LINK, key_id, session_id)
            elif action == "unlink":
                raw_syscall("keyctl", _KEYCTL_UNLINK, key_id, session_id)
            elif action == "revoke":
                raw_syscall("keyctl", _KEYCTL_REVOKE, key_id)
            elif action == "set_permission":
                permissions = _KEY_PERMISSION_PROFILES[permission_profile]
                raw_syscall("keyctl", _KEYCTL_SETPERM, key_id, ctypes.c_uint32(permissions))
                child_state["expected_permissions"] = permissions
            return _key_observation(child_state)

        reached = _spawn_state_fixture(state, apply, _key_observation)
        state.update(expected_payload_sha256=hashlib.sha256(updated if action == "update" else payload).hexdigest(),
                     permission_profile=permission_profile)
        return _fixture_result(_KEYRING_TOOL, action, context, identity_before, reached, state["fixture_pid"])

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        del decision, context
        def expected(observed: dict[str, Any]) -> dict[str, bool]:
            if action == "link": return {"key_linked": observed.get("linked") is True}
            if action == "unlink": return {"key_unlinked": observed.get("linked") is False}
            if action == "revoke": return {"key_revoked": observed.get("readable") is False}
            if action == "set_permission":
                return {"permissions_match": observed.get("permissions") == _KEY_PERMISSION_PROFILES[state["permission_profile"]]}
            return {"payload_requeried": observed.get("payload_sha256") == state["expected_payload_sha256"]}
        return _fixture_verification(name, result, state, expected)

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        del decision, result, context
        return _reset_state_fixture(name, state)

    schema = {
        "payload": str, "updated_payload": str, "permission_profile": str,
        "key_id": _ForbiddenRawArgument, "description": _ForbiddenRawArgument,
        "key_type": _ForbiddenRawArgument, "keyring": _ForbiddenRawArgument,
    }
    return ToolDefinition(name, _KEYRING_TOOL, action, handler, verifier, resetter,
                          _identity_spec(arg_schema=schema, destructive=action in {"unlink", "revoke"}))


def _session_observation() -> dict[str, Any]:
    return {"pid": os.getpid(), "sid": os.getsid(0), "pgid": os.getpgid(0), "ppid": os.getppid()}


def _build_session_definition(action: str) -> ToolDefinition:
    name = f"{_SESSION_TOOL}.{action}"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        if "pid" in decision.arguments or "pgid" in decision.arguments:
            raise ToolInputError("raw pid/pgid는 금지되며 dedicated child fixture만 허용됩니다.")
        identity_before = identity_snapshot()
        def apply(child_state: dict[str, Any]) -> dict[str, Any]:
            child_state["before"] = _session_observation()
            if action == "setsid": os.setsid()
            else: os.setpgid(0, 0)
            return _session_observation()
        reached = _spawn_state_fixture(state, apply, lambda _state: _session_observation())
        return _fixture_result(_SESSION_TOOL, action, context, identity_before, reached, state["fixture_pid"])

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        del decision, context
        return _fixture_verification(
            name, result, state,
            lambda observed: {"session_leader": observed["sid"] == observed["pid"]}
            if action == "setsid" else {"process_group_leader": observed["pgid"] == observed["pid"]},
        )

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        del decision, result, context
        return _reset_state_fixture(name, state)

    return ToolDefinition(name, _SESSION_TOOL, action, handler, verifier, resetter,
                          _identity_spec(arg_schema={"pid": _ForbiddenRawArgument, "pgid": _ForbiddenRawArgument}))


def _current_umask() -> int:
    current = os.umask(0)
    os.umask(current)
    return current


def _build_umask_definition() -> ToolDefinition:
    name = f"{_UMASK_TOOL}.set"

    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        mask = decision.arguments.get("mask")
        if not isinstance(mask, int) or isinstance(mask, bool) or mask not in _ALLOWED_UMASKS:
            raise ToolInputError(f"mask는 allowlist {[oct(value) for value in sorted(_ALLOWED_UMASKS)]} 중 하나여야 합니다.")
        identity_before = identity_snapshot()
        def apply(child_state: dict[str, Any]) -> dict[str, Any]:
            child_state["before"] = _current_umask()
            os.umask(mask)
            return {"umask": _current_umask()}
        reached = _spawn_state_fixture(state, apply, lambda _state: {"umask": _current_umask()})
        state["mask"] = mask
        return _fixture_result(_UMASK_TOOL, "set", context, identity_before, reached, state["fixture_pid"])

    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        del decision, context
        return _fixture_verification(name, result, state,
                                     lambda observed: {"umask_matches": observed.get("umask") == state.get("mask")})

    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        del decision, result, context
        return _reset_state_fixture(name, state)

    return ToolDefinition(name, _UMASK_TOOL, "set", handler, verifier, resetter,
                          _identity_spec(arg_schema={"mask": int}, required_args=frozenset({"mask"})))


_IDENTITY_DEFINITIONS: tuple[ToolDefinition, ...] = (
    *(_build_identity_definition(action) for action in (
        "setuid", "seteuid", "setgid", "setegid", "setgroups", "setfsuid", "setfsgid",
    )),
    *(_build_capability_definition(action) for action in ("add", "drop", "clear")),
    *(_build_securebits_definition(action) for action in ("set", "lock")),
    _build_nnp_definition(),
    *(_build_keyring_definition(action) for action in (
        "add", "read", "update", "link", "unlink", "revoke", "set_permission",
    )),
    *(_build_session_definition(action) for action in ("setsid", "setpgid")),
    _build_umask_definition(),
)

if len(_IDENTITY_DEFINITIONS) != 23:
    raise ToolContractError(f"identity_capability ToolDefinition은 23개여야 합니다: {len(_IDENTITY_DEFINITIONS)}")
if len({definition.name for definition in _IDENTITY_DEFINITIONS}) != 23:
    raise ToolContractError("identity_capability ToolDefinition name이 중복되었습니다.")
for _attribute in ("handler", "verifier", "resetter"):
    if len({id(getattr(definition, _attribute)) for definition in _IDENTITY_DEFINITIONS}) != 23:
        raise ToolContractError(f"identity_capability action별 {_attribute}가 독립 closure가 아닙니다.")

for _definition in _IDENTITY_DEFINITIONS:
    register_definition(_definition)
