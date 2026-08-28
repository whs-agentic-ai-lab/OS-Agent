"""OStool 5절 Agent Attack Tool의 공통 계약.

각 Tool 모듈(identity_capability.py 등)은 이 파일의 ToolOutcome / ToolContext /
register / attempt / dispatch만 사용해 Action 함수를 만든다.

핵심 원칙 (OStool 정리.md 3.1·7·9절):
  - Tool은 절대 스스로 "성공/실패"를 판정하지 않는다. OS·커널이 반환한
    attempted 여부, errno, exit_code, 변경 전후 상태를 있는 그대로 담아
    반환할 뿐이다. 최종 PASS/FAIL 판정은 Control Backend의 독립 Verifier가
    Collector 원본 증거로 내린다.
  - Tool 자체가 특별한 권한을 부여해서는 안 된다. 여기 있는 모든 함수는
    현재 프로세스의 실제 UID/GID/Capability로 실제 syscall을 시도한다.
  - 임의 문자열 대신 구조화된 action + 인자만 받는다. 인자 형식이 틀리면
    OS 호출 전에 ToolInputError로 거부(POLICY_BLOCKED)한다.
  - 모든 Target은 등록된 Target reference로만 해석한다(ToolContext.resolve_target).
"""
from __future__ import annotations

import ctypes
import ctypes.util
import errno as errno_module
import os
import platform
import signal
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator


@contextmanager
def _time_limit(seconds: float) -> Iterator[None]:
    """요구 7: 파괴적/오래 걸리는 syscall에 soft timeout. 메인 스레드에서만 SIGALRM을 건다.

    비-메인 스레드(테스트 러너 등)에서는 signal을 설치할 수 없어 timeout을 생략한다 —
    그 경우 자원 한도·비상 중단은 상위 Harness/컨테이너 제한에 위임한다.
    """
    if seconds <= 0 or threading.current_thread() is not threading.main_thread():
        yield
        return

    def _raise(signum: int, frame: Any) -> None:  # noqa: ANN401
        raise TimeoutError

    previous = signal.signal(signal.SIGALRM, _raise)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


# ---------------------------------------------------------------------------
# 예외 — OStool 3.1의 POLICY_BLOCKED과 실제 OS 실패를 구분한다.
# ---------------------------------------------------------------------------


class ToolInputError(ValueError):
    """Action별 필수 인자·형식 검사 실패. OS 호출 이전에 거부한다."""


class ToolPolicyBlocked(Exception):
    """실험 범위를 벗어난 Target이나 금지된 인자. Executor가 호출 자체를 막는다."""


# ---------------------------------------------------------------------------
# 반환 계약 — OStool 9절 공통 Tool 반환값 JSON과 1:1 대응한다.
# run_id / action_id / executor_mode / trust_boundary_id / source / target은
# Tool이 채우지 않는다. Executor(runtime_agent)가 ToolContext를 보고 감싸서 채운다.
# ---------------------------------------------------------------------------

Outcome = str  # "ALLOWED" | "OS_DENIED" | "ERROR" | "POLICY_BLOCKED"


@dataclass
class ToolOutcome:
    tool: str
    action: str
    attempted: bool
    outcome: Outcome
    errno: str | None = None
    exit_code: int | None = None
    changed: bool = False
    identity_before: dict[str, Any] = field(default_factory=dict)
    identity_after: dict[str, Any] = field(default_factory=dict)
    output: str = ""
    # Collector 연동 전까지는 항상 빈 목록이다. evidence.feedback이 붙으면
    # Executor가 run_id/action_id로 상관분석한 참조를 채워 넣는다.
    evidence_refs: list[str] = field(default_factory=list)
    # ── OStool 정리.md 9절 공통 반환값 확장 (5.2~5.10 Probe/Rollback 계약) ──
    # 권한 상승·상태 변경 Probe는 격리 문맥에서 도달한 상태(identity_reached /
    # state_reached)로 "가능성"을 증명하고, rollback 후 초기 상태 복구를
    # identity_after / state_after 와 rollback_status 로 증명한다. Tool은
    # 성공을 "판정"하지 않는다 — 도달·복구 사실만 있는 그대로 담는다.
    identity_reached: dict[str, Any] = field(default_factory=dict)
    state_before: dict[str, Any] = field(default_factory=dict)
    state_reached: dict[str, Any] = field(default_factory=dict)
    state_after: dict[str, Any] = field(default_factory=dict)
    escalation_possible: bool = False   # 격리 문맥에서 상위 상태 도달을 관측했는가
    temporary_changed: bool = False     # Probe 동안 일시적으로 상태가 바뀌었는가
    # "VERIFIED" | "FAILED" | "NOT_REQUIRED" | "NOT_POSSIBLE" | None
    rollback_status: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "action": self.action,
            "attempted": self.attempted,
            "outcome": self.outcome,
            "errno": self.errno,
            "exit_code": self.exit_code,
            "changed": self.changed,
            "escalation_possible": self.escalation_possible,
            "temporary_changed": self.temporary_changed,
            "identity_before": self.identity_before,
            "identity_reached": self.identity_reached,
            "identity_after": self.identity_after,
            "state_before": self.state_before,
            "state_reached": self.state_reached,
            "state_after": self.state_after,
            "rollback_status": self.rollback_status,
            "output": self.output,
            "evidence_refs": self.evidence_refs,
        }


@dataclass
class ToolContext:
    """Executor가 채워서 넘기는 공통 문맥. Tool 함수는 이 값을 읽기만 한다."""

    run_id: str
    action_id: str
    executor_mode: str  # "host" | "container"
    trust_boundary_id: str
    source: str
    target: str
    # 이번 Run에서 Harness가 등록한 Target reference 전체 집합.
    # 비어 있으면(테스트 등) 검사를 생략한다 — 운영 경로에서는 항상 채워서 넘긴다.
    allowed_targets: frozenset[str] = field(default_factory=frozenset)
    # 등록된 resource_ref -> 실제 경로/PID/Container/service 매핑. Executor(Harness)가
    # Run 시작 시 채운다. Agent는 raw 경로를 직접 넘기지 못하고 이 매핑만 참조한다(5.11).
    resource_paths: dict[str, str] = field(default_factory=dict)
    # 파괴적·종료성 Tool(destructive)은 Harness가 전용 Fixture·제한 Target을 준비하고
    # 이 플래그를 True로 켰을 때에만 실행된다. 기본 False → 파괴적 Tool은 POLICY_BLOCKED.
    destructive_enabled: bool = False

    def resolve_target(self, resource_ref: str) -> str:
        """OStool 5.11: 모든 경로·PID·Container·service는 등록된 Target reference로 해석한다."""
        if self.allowed_targets and resource_ref not in self.allowed_targets:
            raise ToolPolicyBlocked(f"등록되지 않은 Target reference입니다: {resource_ref}")
        return resource_ref

    def resolve_path(self, resource_ref: str) -> str:
        """등록된 resource_ref를 Executor가 매핑한 실제 경로로 변환한다.

        allowed_targets가 있으면 멤버십을 먼저 검사하고, resource_paths에 매핑이
        없으면 POLICY_BLOCKED로 거부한다(임의 절대 경로 접근 차단).
        """
        self.resolve_target(resource_ref)
        path = self.resource_paths.get(resource_ref)
        if path is None:
            raise ToolPolicyBlocked(f"resource_ref에 매핑된 경로가 없습니다: {resource_ref}")
        return path


ToolFunc = Callable[[str, dict[str, Any], ToolContext], ToolOutcome]

# ---------------------------------------------------------------------------
# ToolSpec — 선언적 Tool 거버넌스 (OStool 정리.md 요구 1·2·7).
#   dispatch()가 handler 호출 전에 이 선언을 자동 강제한다:
#     1) 허용 Executor(host/container) · Trust Boundary
#     2) 구조화 인자 스키마 allowlist(미지의 키 거부·타입 검사·필수 인자)
#     7) 파괴적 Tool은 Harness가 전용 Fixture를 준비(destructive_enabled)했을 때만
#   → 개별 handler가 같은 검증을 반복하지 않고, 위반은 전부 POLICY_BLOCKED로 정규화.
# ---------------------------------------------------------------------------

# resource_kind별 표준 인자(스키마에 자동 포함되어 handler가 매번 선언하지 않아도 됨)
_STANDARD_ARGS: dict[str, frozenset[str]] = {
    "path": frozenset({"resource_ref"}),
    "container": frozenset({"resource_ref"}),
    "service": frozenset({"resource_ref"}),
    "pid": frozenset({"pid"}),
    "fd": frozenset({"fd"}),
    "self": frozenset(),
    "none": frozenset(),
}
_REQUIRED_STANDARD: dict[str, str] = {
    "path": "resource_ref", "container": "resource_ref", "service": "resource_ref",
    "pid": "pid", "fd": "fd",
}


@dataclass(frozen=True)
class ToolSpec:
    resource_kind: str = "none"                                  # path|container|service|pid|fd|self|none
    allowed_executors: frozenset[str] = frozenset({"host", "container"})
    allowed_tbs: frozenset[str] = frozenset()                    # 비어 있으면 모든 TB 허용
    arg_schema: dict[str, Any] = field(default_factory=dict)     # key -> type | (type, ...) (표준 인자 제외)
    required_args: frozenset[str] = frozenset()
    destructive: bool = False                                    # 되돌릴 수 없는 파괴·종료성
    reversible: bool = False                                     # probe로 즉시 원복
    timeout_s: float = 10.0

    def allowed_keys(self) -> frozenset[str]:
        return _STANDARD_ARGS.get(self.resource_kind, frozenset()) | frozenset(self.arg_schema)


_REGISTRY: dict[str, dict[str, ToolFunc]] = {}
_SPECS: dict[tuple[str, str], ToolSpec] = {}
_VERIFIERS: dict[tuple[str, str], Callable[[ToolOutcome], bool]] = {}
_RESETS: dict[tuple[str, str], Callable[[ToolOutcome, ToolContext], None]] = {}


def register(
    tool_id: str,
    action: str,
    *,
    spec: "ToolSpec | None" = None,
    verify: "Callable[[ToolOutcome], bool] | None" = None,
    reset: "Callable[[ToolOutcome, ToolContext], None] | None" = None,
) -> Callable[[ToolFunc], ToolFunc]:
    """Tool ID + Action을 레지스트리에 등록한다.

    spec을 주면 dispatch가 Executor/TB/인자 스키마/파괴성을 자동 강제한다(신규 5.2~5.10).
    spec 없이 등록하면 legacy 경로(5.1 identity_capability)로, 강제 없이 그대로 실행한다.
    """

    def _wrap(func: ToolFunc) -> ToolFunc:
        _REGISTRY.setdefault(tool_id, {})[action] = func
        if spec is not None:
            _SPECS[(tool_id, action)] = spec
        if verify is not None:
            _VERIFIERS[(tool_id, action)] = verify
        if reset is not None:
            _RESETS[(tool_id, action)] = reset
        return func

    return _wrap


def register_verifier(tool_id: str, action: str, func: Callable[[ToolOutcome], bool]) -> None:
    _VERIFIERS[(tool_id, action)] = func


def register_reset(tool_id: str, action: str, func: Callable[[ToolOutcome, ToolContext], None]) -> None:
    _RESETS[(tool_id, action)] = func


def _blocked(tool_id: str, action: str, message: str) -> ToolOutcome:
    return ToolOutcome(
        tool=tool_id, action=action, attempted=False, outcome="POLICY_BLOCKED", output=message,
    )


def _enforce_spec(tool_id: str, action: str, spec: ToolSpec, arguments: dict[str, Any], context: ToolContext) -> None:
    """요구 1·2·7 강제. 위반 시 ToolPolicyBlocked를 던진다."""
    # 2) raw command·임의 경로 인자 차단
    reject_raw_arguments(arguments)
    # 1) 허용 Executor
    if context.executor_mode not in spec.allowed_executors:
        raise ToolPolicyBlocked(
            f"{tool_id}.{action}는 {sorted(spec.allowed_executors)} Executor에서만 허용됩니다(현재 {context.executor_mode})."
        )
    # 1) 허용 Trust Boundary
    if spec.allowed_tbs and context.trust_boundary_id not in spec.allowed_tbs:
        raise ToolPolicyBlocked(
            f"{tool_id}.{action}는 {sorted(spec.allowed_tbs)} TB에서만 허용됩니다(현재 {context.trust_boundary_id})."
        )
    # 2) 구조화 인자 allowlist — 미지의 키 거부
    allowed = spec.allowed_keys()
    unknown = set(arguments) - allowed
    if unknown:
        raise ToolInputError(f"허용되지 않은 인자입니다: {sorted(unknown)} (허용: {sorted(allowed)})")
    # 2) resource_kind의 표준 인자(resource_ref/fd/pid)는 필수
    std_required = _REQUIRED_STANDARD.get(spec.resource_kind)
    required = spec.required_args | ({std_required} if std_required else set())
    missing = required - set(arguments)
    if missing:
        raise ToolInputError(f"필수 인자가 없습니다: {sorted(missing)}")
    # 2) 타입 검사(선언된 것만)
    for key, expected in spec.arg_schema.items():
        if key in arguments and not isinstance(arguments[key], expected):
            names = expected.__name__ if isinstance(expected, type) else "/".join(t.__name__ for t in expected)
            raise ToolInputError(f"{key}는 {names} 타입이어야 합니다.")
    # 7) 파괴적·종료성 Tool은 전용 Fixture(destructive_enabled)에서만
    if spec.destructive and not context.destructive_enabled:
        raise ToolPolicyBlocked(
            f"{tool_id}.{action}는 파괴적/종료성 Tool입니다. Harness 전용 Fixture(destructive_enabled)에서만 실행됩니다."
        )


def dispatch(tool_id: str, action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    """레지스트리에서 Tool을 찾아 spec을 강제한 뒤 실행한다. 등록 밖·위반은 POLICY_BLOCKED로 정규화한다."""
    actions = _REGISTRY.get(tool_id)
    if actions is None or action not in actions:
        return _blocked(tool_id, action, f"등록되지 않은 Tool/Action입니다: {tool_id}.{action}")
    func = actions[action]
    args = dict(arguments)
    spec = _SPECS.get((tool_id, action))
    try:
        if spec is not None:
            _enforce_spec(tool_id, action, spec, args, context)
            with _time_limit(spec.timeout_s):
                return func(action, args, context)
        return func(action, args, context)
    except ToolPolicyBlocked as exc:
        return _blocked(tool_id, action, str(exc))
    except ToolInputError as exc:
        return _blocked(tool_id, action, str(exc))
    except TimeoutError:
        return ToolOutcome(
            tool=tool_id, action=action, attempted=True, outcome="ERROR",
            errno="ETIMEDOUT", exit_code=110, output=f"{tool_id}.{action} timeout({spec.timeout_s if spec else '?'}s)",
        )


def verify(tool_id: str, action: str, outcome: ToolOutcome) -> bool:
    """요구 8: Tool별 Verifier. 등록된 게 있으면 그것을, 없으면 기본 판정을 쓴다.

    기본 판정: 실제 시도됐고(rollback_status가 FAILED가 아니며) probe면 복구가 검증됐는가.
    최종 TB 판정은 여전히 Collector 원본 증거 기반 외부 Verifier의 몫이다(3.1/7절).
    """
    fn = _VERIFIERS.get((tool_id, action))
    if fn is not None:
        return fn(outcome)
    if not outcome.attempted:
        return False
    if outcome.rollback_status == "FAILED":
        return False
    return outcome.outcome in {"ALLOWED", "OS_DENIED"}


def reset(tool_id: str, action: str, outcome: ToolOutcome, context: ToolContext) -> str:
    """요구 8: Tool별 Reset 절차. probe 계열은 이미 inline 복구되어 NOT_REQUIRED.

    비-probe 상태 변경(file.create/move_link 등)은 등록된 reset으로 생성물을 정리한다.
    반환: "DONE" | "NOT_REQUIRED" | "FAILED".
    """
    fn = _RESETS.get((tool_id, action))
    if fn is None:
        return "NOT_REQUIRED"
    if outcome.outcome != "ALLOWED":
        return "NOT_REQUIRED"
    try:
        fn(outcome, context)
        return "DONE"
    except OSError:
        return "FAILED"


def known_tools() -> dict[str, list[str]]:
    return {tool_id: sorted(actions) for tool_id, actions in _REGISTRY.items()}


# ---------------------------------------------------------------------------
# 공통 실행 래퍼 — before/after identity 스냅샷과 OSError→outcome 매핑을
# 129개 Tool 전체가 반복하지 않도록 한 곳에 모은다.
# ---------------------------------------------------------------------------

_DENIED_ERRNOS = {errno_module.EPERM, errno_module.EACCES, errno_module.EROFS}


def outcome_from_oserror(exc: OSError) -> tuple[Outcome, str | None, int]:
    code = exc.errno
    name = errno_module.errorcode.get(code, str(code)) if code is not None else None
    if code in _DENIED_ERRNOS:
        return "OS_DENIED", name, code or 1
    return "ERROR", name, code or 1


def attempt(tool: str, action: str, operation: Callable[[], str | None]) -> ToolOutcome:
    """OS 호출 한 번을 시도하고 결과를 그대로 담는다. 성공/실패를 "판단"하지 않는다."""
    before = identity_snapshot()
    try:
        message = operation()
    except OSError as exc:
        outcome, errno_name, exit_code = outcome_from_oserror(exc)
        return ToolOutcome(
            tool=tool,
            action=action,
            attempted=True,
            outcome=outcome,
            errno=errno_name,
            exit_code=exit_code,
            changed=False,
            identity_before=before,
            identity_after=identity_snapshot(),
        )
    after = identity_snapshot()
    return ToolOutcome(
        tool=tool,
        action=action,
        attempted=True,
        outcome="ALLOWED",
        exit_code=0,
        changed=before != after,
        identity_before=before,
        identity_after=after,
        output=message or "",
    )


# ---------------------------------------------------------------------------
# probe() — 상태 변경/권한 상승 Probe의 트랜잭션 래퍼 (OStool 정리.md 4.2·9절).
#
#   초기 Snapshot → 격리·일시 변경 → 도달 상태 관측 → Rollback → 복구 검증
#
# reversible 상태 변경(파일 chmod, umask, 일시적 setuid 등)을 "가능성"만 확인하고
# 즉시 원복하는 Action에 쓴다. attempt()와 달리 resource state(파일 메타데이터·해시
# 등)도 스냅샷하고, restore 후 초기 상태로 돌아왔는지 검증해 rollback_status를 채운다.
# 성공/실패를 판정하지 않는다 — 도달과 복구 "사실"만 담는다.
# ---------------------------------------------------------------------------


def probe(
    tool: str,
    action: str,
    *,
    mutate: Callable[[], str | None],
    snapshot_state: Callable[[], dict[str, Any]] | None = None,
    restore: Callable[[], None] | None = None,
) -> ToolOutcome:
    """일시 변경을 시도하고 즉시 원복하는 Probe. rollback_status까지 채워 반환한다.

    Args:
        mutate: 실제 상태 변경 syscall. 실패 시 OSError를 던지면 OS_DENIED/ERROR로 분류.
        snapshot_state: 자원 상태(파일 메타·해시 등) 스냅샷. None이면 process identity만 본다.
        restore: 원복 함수. None이면 rollback 불필요(NOT_REQUIRED)로 본다.
    """
    id_before = identity_snapshot()
    st_before = snapshot_state() if snapshot_state else {}
    try:
        message = mutate()
    except OSError as exc:
        outcome, errno_name, exit_code = outcome_from_oserror(exc)
        return ToolOutcome(
            tool=tool,
            action=action,
            attempted=True,
            outcome=outcome,
            errno=errno_name,
            exit_code=exit_code,
            changed=False,
            temporary_changed=False,
            escalation_possible=False,
            identity_before=id_before,
            identity_reached=id_before,
            identity_after=identity_snapshot(),
            state_before=st_before,
            state_reached=st_before,
            state_after=snapshot_state() if snapshot_state else {},
            rollback_status="NOT_REQUIRED",
        )

    id_reached = identity_snapshot()
    st_reached = snapshot_state() if snapshot_state else {}
    temp_changed = (id_reached != id_before) or (st_reached != st_before)

    rollback_status: str | None
    if restore is None:
        rollback_status = "NOT_REQUIRED"
    else:
        try:
            restore()
        except OSError:
            rollback_status = "FAILED"

    id_after = identity_snapshot()
    st_after = snapshot_state() if snapshot_state else {}
    if restore is not None:
        restored = (id_after == id_before) and (st_after == st_before)
        rollback_status = "VERIFIED" if restored else "FAILED"

    return ToolOutcome(
        tool=tool,
        action=action,
        attempted=True,
        outcome="ALLOWED",
        exit_code=0,
        changed=(id_after != id_before) or (st_after != st_before),
        temporary_changed=temp_changed,
        escalation_possible=temp_changed,
        identity_before=id_before,
        identity_reached=id_reached,
        identity_after=id_after,
        state_before=st_before,
        state_reached=st_reached,
        state_after=st_after,
        rollback_status=rollback_status,
        output=message or "",
    )


# ---------------------------------------------------------------------------
# 공통 입력 검증 & 파일 상태 스냅샷 헬퍼 — 5.2~5.10 모든 모듈이 공유한다.
# 임의 문자열 명령·절대 경로를 직접 받지 않고 구조화된 인자만 받는다(5.11).
# ---------------------------------------------------------------------------

_FORBIDDEN_ARG_KEYS = frozenset({"command", "shell", "path", "absolute_path", "cmd", "argv"})


def reject_raw_arguments(arguments: dict[str, Any]) -> None:
    """raw command·임의 경로 인자를 거부한다(OStool 5.11 공통 제약)."""
    hit = _FORBIDDEN_ARG_KEYS.intersection(arguments)
    if hit:
        raise ToolInputError(f"raw command·임의 경로 인자는 허용되지 않습니다: {sorted(hit)}")


def require(arguments: dict[str, Any], *keys: str) -> None:
    missing = [key for key in keys if key not in arguments]
    if missing:
        raise ToolInputError(f"필수 인자가 없습니다: {', '.join(missing)}")


def int_arg(arguments: dict[str, Any], key: str) -> int:
    require(arguments, key)
    value = arguments[key]
    if not isinstance(value, int) or isinstance(value, bool):
        raise ToolInputError(f"{key}는 정수여야 합니다.")
    return value


def int_arg_default(arguments: dict[str, Any], key: str, default: int) -> int:
    if key not in arguments:
        return default
    return int_arg(arguments, key)


def str_arg(arguments: dict[str, Any], key: str) -> str:
    require(arguments, key)
    value = arguments[key]
    if not isinstance(value, str) or not value:
        raise ToolInputError(f"{key}는 비어 있지 않은 문자열이어야 합니다.")
    return value


def enum_arg(arguments: dict[str, Any], key: str, allowed: frozenset[str], default: str | None = None) -> str:
    if key not in arguments:
        if default is not None:
            return default
        raise ToolInputError(f"필수 인자가 없습니다: {key}")
    value = arguments[key]
    if value not in allowed:
        raise ToolInputError(f"{key}는 {sorted(allowed)} 중 하나여야 합니다.")
    return value


def bounded_content(arguments: dict[str, Any], key: str = "content", *, max_len: int = 128) -> str:
    """카나리 쓰기 등에 쓰는 NUL 없는 짧은 문자열. runtime.py의 MAX_CONTENT 규칙과 동일."""
    value = str_arg(arguments, key)
    if len(value) > max_len or "\x00" in value:
        raise ToolInputError(f"{key}는 NUL 없는 1~{max_len}자 문자열이어야 합니다.")
    return value


def path_state(path: str) -> dict[str, Any]:
    """파일·디렉터리의 존재·소유권·모드·크기·내용해시 스냅샷 (rollback 검증·evidence용)."""
    import hashlib as _hashlib
    import stat as _stat

    try:
        st = os.lstat(path)
    except OSError:
        return {"path": path, "exists": False}
    info: dict[str, Any] = {
        "path": path,
        "exists": True,
        "uid": st.st_uid,
        "gid": st.st_gid,
        "mode": _stat.S_IMODE(st.st_mode),
        "type": _stat.S_IFMT(st.st_mode),
        "size": st.st_size,
        "nlink": st.st_nlink,
        "mtime_ns": st.st_mtime_ns,
    }
    if _stat.S_ISREG(st.st_mode):
        try:
            h = _hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
            info["sha256"] = h.hexdigest()
        except OSError:
            info["sha256"] = None
    return info


# ---------------------------------------------------------------------------
# libc / raw syscall — Python os 모듈에 없는 identity·prctl·capability·keyring
# 계열 호출에 쓴다. glibc가 심볼을 직접 노출하지 않는 syscall(capget/capset,
# add_key, keyctl)은 libc.syscall(2)을 통해 번호로 직접 호출한다.
# ---------------------------------------------------------------------------

_libc_name = ctypes.util.find_library("c") or "libc.so.6"
libc = ctypes.CDLL(_libc_name, use_errno=True)

PR_SET_SECUREBITS = 28
PR_GET_SECUREBITS = 27
PR_SET_NO_NEW_PRIVS = 38
PR_GET_NO_NEW_PRIVS = 39
PR_CAPBSET_DROP = 24
PR_CAPBSET_READ = 23
PR_CAP_AMBIENT = 47
PR_CAP_AMBIENT_IS_SET = 1
PR_CAP_AMBIENT_RAISE = 2
PR_CAP_AMBIENT_LOWER = 3
PR_CAP_AMBIENT_CLEAR_ALL = 4

# x86_64/aarch64 Linux syscall 번호. 다른 아키텍처에서 이 표에 없는 이름을
# 부르면 ENOSYS로 명확하게 실패한다(조용히 잘못된 번호를 부르지 않는다).
_SYSCALL_NUMBERS: dict[str, dict[str, int]] = {
    "x86_64": {
        "capget": 125, "capset": 126, "add_key": 248, "keyctl": 250,
        "name_to_handle_at": 303, "open_by_handle_at": 304,
        "pidfd_open": 434, "pidfd_getfd": 438, "pidfd_send_signal": 424,
        "process_vm_readv": 310, "process_vm_writev": 311,
        "setns": 308, "unshare": 272, "mount_setattr": 442,
        "perf_event_open": 298, "bpf": 321, "seccomp": 317,
        "init_module": 175, "finit_module": 313, "delete_module": 176,
        "kexec_load": 246, "reboot": 169, "fsopen": 430, "move_mount": 429,
    },
    "aarch64": {
        "capget": 90, "capset": 91, "add_key": 217, "keyctl": 219,
        "name_to_handle_at": 264, "open_by_handle_at": 265,
        "pidfd_open": 434, "pidfd_getfd": 438, "pidfd_send_signal": 424,
        "process_vm_readv": 270, "process_vm_writev": 271,
        "setns": 268, "unshare": 97, "mount_setattr": 442,
        "perf_event_open": 241, "bpf": 280, "seccomp": 277,
        "init_module": 105, "finit_module": 273, "delete_module": 106,
        "kexec_load": 104, "reboot": 142, "fsopen": 430, "move_mount": 429,
    },
}

_LINUX_CAPABILITY_VERSION_3 = 0x20080522


class _CapUserHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _CapUserData(ctypes.Structure):
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]


def _syscall_number(name: str) -> int:
    machine = platform.machine()
    table = _SYSCALL_NUMBERS.get(machine)
    if table is None or name not in table:
        raise OSError(errno_module.ENOSYS, f"{machine} 아키텍처의 {name} syscall 번호를 등록하지 않았습니다.")
    return table[name]


def raw_syscall(name: str, *args: Any) -> int:
    """libc.syscall(2)로 번호를 직접 지정해 호출한다. 실패 시 OSError(errno)."""
    number = _syscall_number(name)
    result = libc.syscall(ctypes.c_long(number), *args)
    if result == -1:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return result


def prctl(*args: int) -> int:
    """prctl(2) 래퍼. 실패 시 OSError(errno)를 던진다."""
    padded = (list(args) + [0, 0, 0, 0, 0])[:5]
    result = libc.prctl(*[ctypes.c_ulong(v) for v in padded])
    if result == -1:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return result


def capget_raw() -> tuple[int, int, int]:
    """현재 스레드의 Permitted/Effective/Inheritable capability(하위 32bit)를 읽는다."""
    header = _CapUserHeader(_LINUX_CAPABILITY_VERSION_3, 0)
    data = (_CapUserData * 2)()
    raw_syscall("capget", ctypes.byref(header), ctypes.byref(data))
    return data[0].effective, data[0].permitted, data[0].inheritable


def capset_raw(effective: int, permitted: int, inheritable: int) -> None:
    """capset(2)로 하위 32bit E/P/I capability set을 직접 설정한다.

    32번 이상(capability 32~63)은 이 구현에서 다루지 않는다 — 필요해지면
    _CapUserData 두 번째 원소(data[1])를 채우고 version은 그대로 v3를 쓰면 된다.
    """
    header = _CapUserHeader(_LINUX_CAPABILITY_VERSION_3, 0)
    data = (_CapUserData * 2)()
    data[0].effective = effective & 0xFFFFFFFF
    data[0].permitted = permitted & 0xFFFFFFFF
    data[0].inheritable = inheritable & 0xFFFFFFFF
    raw_syscall("capset", ctypes.byref(header), ctypes.byref(data))


def _proc_self_ids() -> dict[str, list[int]]:
    """/proc/self/status의 real/effective/saved/fs UID·GID 4개 값을 읽는다."""
    result: dict[str, list[int]] = {}
    try:
        with open("/proc/self/status", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("Uid:") or line.startswith("Gid:"):
                    key = "uid" if line.startswith("Uid:") else "gid"
                    result[key] = [int(part) for part in line.split()[1:5]]
    except OSError:
        pass
    return result


def _peek_umask() -> int:
    """os.umask()는 이전 값을 반환하는 부작용으로만 조회할 수 있어 즉시 원복한다."""
    current = os.umask(0)
    os.umask(current)
    return current


_NS_KINDS = ("mnt", "pid", "ipc", "uts", "user", "cgroup", "time")


def ns_snapshot(pid: str | int = "self") -> dict[str, str | None]:
    """요구 5: namespace 소속 스냅샷. /proc/<pid>/ns/*의 inode를 읽어 격리 탈출·전환을 증명한다.

    network namespace는 실험 범위에서 제외한다(스펙 5.6). 값은 'mnt:[4026531840]' 형태.
    """
    out: dict[str, str | None] = {}
    for kind in _NS_KINDS:
        try:
            out[kind] = os.readlink(f"/proc/{pid}/ns/{kind}")
        except OSError:
            out[kind] = None
    return out


def identity_snapshot() -> dict[str, Any]:
    """OStool 9절 identity_before/after에 넣는 최소 신분 스냅샷 (uid/gid/cap/namespace)."""
    try:
        effective, permitted, inheritable = capget_raw()
        capabilities: dict[str, int] | None = {
            "effective": effective,
            "permitted": permitted,
            "inheritable": inheritable,
        }
    except OSError:
        capabilities = None
    ids = _proc_self_ids()
    return {
        "uid": os.getuid(),
        "euid": os.geteuid(),
        "gid": os.getgid(),
        "egid": os.getegid(),
        "uid_real_effective_saved_fs": ids.get("uid"),
        "gid_real_effective_saved_fs": ids.get("gid"),
        "groups": sorted(os.getgroups()),
        "pid": os.getpid(),
        "pgid": os.getpgid(0),
        "sid": os.getsid(0),
        "umask": _peek_umask(),
        "capabilities": capabilities,
        "namespaces": ns_snapshot("self"),
    }
