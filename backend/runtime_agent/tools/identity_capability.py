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
import os
from typing import Any

from . import base
from .base import (
    ToolContext,
    ToolInputError,
    ToolOutcome,
    attempt,
    prctl,
    raw_syscall,
    register,
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
