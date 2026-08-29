"""OStool 5절 Agent Attack Tool의 공통 계약.

신규 action은 이 파일의 ToolDefinition / ToolResult / VerificationResult /
ResetResult 계약을 사용한다. legacy register/attempt/probe/dispatch는 family별
전환이 끝날 때까지만 호환용으로 유지하며 구현 완료 수에 포함하지 않는다.

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


class ToolContractError(RuntimeError):
    """ToolDefinition 또는 action 반환 계약이 올바르지 않다."""


class ToolRollbackFailed(RuntimeError):
    """resetter가 실행 전 상태 복구를 검증하지 못해 Run을 중단해야 한다."""


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
class RunGuard:
    """rollback 실패 후 같은 Run의 후속 action 실행을 차단하는 공유 상태."""

    aborted: bool = False
    reason: str | None = None

    def abort(self, reason: str) -> None:
        self.aborted = True
        self.reason = reason


EvidenceWriter = Callable[[str, str, str, dict[str, Any]], str]
AbortHandler = Callable[[str, str], None]


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
    resource_paths: dict[str, str | int] = field(default_factory=dict)
    # 파괴적·종료성 Tool(destructive)은 Harness가 전용 Fixture·제한 Target을 준비하고
    # 이 플래그를 True로 켰을 때에만 실행된다. 기본 False → 파괴적 Tool은 POLICY_BLOCKED.
    destructive_enabled: bool = False
    # 같은 Run의 모든 action context가 동일한 guard를 공유해야 한다. reset 실패 시
    # aborted=True가 되어 다음 ToolDefinition 실행이 정책 단계에서 차단된다.
    run_guard: RunGuard = field(default_factory=RunGuard, repr=False)
    # Collector/Evidence Store 연결은 Harness가 주입한다. base.py는 Evidence를
    # 만들어내거나 성공을 꾸미지 않고 run_id/action_id와 payload만 전달한다.
    evidence_writer: EvidenceWriter | None = field(default=None, repr=False)
    # rollback 실패 시 Harness Reset을 요청하는 callback. 실제 Reset 구현은
    # 신뢰 영역인 Harness 책임이며 Agent Tool이 직접 환경을 재구성하지 않는다.
    abort_handler: AbortHandler | None = field(default=None, repr=False)

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
        if not isinstance(path, str):
            raise ToolPolicyBlocked(f"resource_ref가 경로를 가리키지 않습니다: {resource_ref}")
        return path

    def resolve_resource(self, resource_ref: str) -> str | int:
        """path/PID/FD/container/service 공통 Target reference 해석."""
        self.resolve_target(resource_ref)
        resource = self.resource_paths.get(resource_ref)
        if resource is None:
            raise ToolPolicyBlocked(f"resource_ref 매핑이 없습니다: {resource_ref}")
        return resource

    def ensure_run_active(self) -> None:
        if self.run_guard.aborted:
            raise ToolPolicyBlocked(
                f"rollback 실패로 Run이 중단되었습니다: {self.run_guard.reason or 'unknown'}"
            )

    def record_evidence(self, kind: str, payload: dict[str, Any]) -> str:
        """동일 run_id/action_id로 Collector Evidence를 저장하고 참조를 받는다."""
        if self.evidence_writer is None:
            raise ToolContractError("ToolDefinition 실행에는 evidence_writer가 필요합니다.")
        reference = self.evidence_writer(self.run_id, self.action_id, kind, payload)
        if not isinstance(reference, str) or not reference:
            raise ToolContractError("evidence_writer가 유효한 Evidence reference를 반환하지 않았습니다.")
        return reference

    def abort_for_rollback(self, reason: str) -> None:
        self.run_guard.abort(reason)
        if self.abort_handler is not None:
            try:
                self.abort_handler(self.run_id, reason)
            except Exception:
                # RunGuard는 이미 중단 상태다. callback 오류 때문에 복구 결과
                # 반환까지 잃지 않고 상위 Harness가 상태를 확인하게 한다.
                pass


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
    # pid/fd 직접 값은 legacy family가 전환될 때까지만 허용한다. 새
    # ToolDefinition 실행 경로는 아래 execute_definition에서 resource_ref를
    # 강제하고 resolve_resource()로 실제 값을 얻는다.
    "pid": frozenset({"resource_ref", "pid"}),
    "fd": frozenset({"resource_ref", "fd"}),
    "self": frozenset(),
    "none": frozenset(),
}
_REQUIRED_STANDARD: dict[str, str] = {
    "path": "resource_ref", "container": "resource_ref", "service": "resource_ref",
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
    resource_limits: dict[str, int] = field(default_factory=dict)
    emergency_stop_conditions: frozenset[str] = frozenset()

    def allowed_keys(self) -> frozenset[str]:
        return _STANDARD_ARGS.get(self.resource_kind, frozenset()) | frozenset(self.arg_schema)


# ---------------------------------------------------------------------------
# 새 action 수직 계약. family 파일은 action 하나마다 ToolDefinition 하나를
# 만들고 그 안에 handler/verifier/resetter를 함께 둔다. legacy @register
# 레지스트리는 family별 전환이 끝날 때까지만 호환용으로 유지한다.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolDecision:
    tool: str
    action: str
    resource_ref: str | None
    arguments: dict[str, Any]


@dataclass
class ToolResult:
    """handler가 반환하는 OS/API 시도 사실과 실행 전·도달 상태."""

    run_id: str
    action_id: str
    tool: str
    action: str
    attempted: bool
    outcome: Outcome
    errno: str | None = None
    exit_code: int | None = None
    output: str = ""
    identity_before: dict[str, Any] = field(default_factory=dict)
    identity_reached: dict[str, Any] = field(default_factory=dict)
    identity_after: dict[str, Any] = field(default_factory=dict)
    state_before: dict[str, Any] = field(default_factory=dict)
    state_reached: dict[str, Any] = field(default_factory=dict)
    state_after: dict[str, Any] = field(default_factory=dict)
    changed: bool = False
    temporary_changed: bool = False
    escalation_possible: bool = False
    rollback_status: str | None = None
    evidence_refs: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "action_id": self.action_id,
            "tool": self.tool,
            "action": self.action,
            "attempted": self.attempted,
            "outcome": self.outcome,
            "errno": self.errno,
            "exit_code": self.exit_code,
            "output": self.output,
            "identity_before": self.identity_before,
            "identity_reached": self.identity_reached,
            "identity_after": self.identity_after,
            "state_before": self.state_before,
            "state_reached": self.state_reached,
            "state_after": self.state_after,
            "changed": self.changed,
            "temporary_changed": self.temporary_changed,
            "escalation_possible": self.escalation_possible,
            "rollback_status": self.rollback_status,
            "evidence_refs": list(self.evidence_refs),
            "data": dict(self.data),
        }


@dataclass
class VerificationResult:
    """Verifier가 실제 OS/API를 독립 재조회한 결과."""

    verifier: str
    status: str  # VERIFIED | VERIFIED_NO_CHANGE | REJECTED | NOT_RUN
    checks: dict[str, bool] = field(default_factory=dict)
    observed: dict[str, Any] = field(default_factory=dict)
    evidence_refs: list[str] = field(default_factory=list)

    @property
    def accepted(self) -> bool:
        return self.status in {"VERIFIED", "VERIFIED_NO_CHANGE"}


@dataclass
class ResetResult:
    """resetter가 실제 복구 후 상태를 다시 조회한 결과."""

    resetter: str
    status: str  # VERIFIED | VERIFIED_NO_CHANGE | NOT_REQUIRED | FAILED
    identity_after: dict[str, Any] = field(default_factory=dict)
    state_after: dict[str, Any] = field(default_factory=dict)
    checks: dict[str, bool] = field(default_factory=dict)
    evidence_refs: list[str] = field(default_factory=list)
    output: str = ""

    @property
    def restored(self) -> bool:
        return self.status in {"VERIFIED", "VERIFIED_NO_CHANGE", "NOT_REQUIRED"}


DefinitionState = dict[str, Any]
DefinitionHandler = Callable[[DefinitionState, ToolDecision, ToolContext], ToolResult]
DefinitionVerifier = Callable[
    [DefinitionState, ToolDecision, ToolResult, ToolContext], VerificationResult
]
DefinitionResetter = Callable[
    [DefinitionState, ToolDecision, ToolResult, ToolContext], ResetResult
]


@dataclass(frozen=True)
class ToolDefinition:
    """action 하나에 필요한 실행·독립 검증·복구 계약 전체."""

    name: str
    tool: str
    action: str
    handler: DefinitionHandler
    verifier: DefinitionVerifier
    resetter: DefinitionResetter
    spec: ToolSpec


@dataclass
class ToolExecution:
    """handler → verifier → resetter 실행의 전체 결과."""

    definition: str
    result: ToolResult
    verification: VerificationResult
    reset: ResetResult

    @property
    def rollback_verified(self) -> bool:
        return self.reset.restored

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.result.to_dict(),
            "verification": {
                "verifier": self.verification.verifier,
                "status": self.verification.status,
                "checks": dict(self.verification.checks),
                "observed": dict(self.verification.observed),
                "evidence_refs": list(self.verification.evidence_refs),
            },
            "reset": {
                "resetter": self.reset.resetter,
                "status": self.reset.status,
                "checks": dict(self.reset.checks),
                "identity_after": self.reset.identity_after,
                "state_after": self.reset.state_after,
                "evidence_refs": list(self.reset.evidence_refs),
                "output": self.reset.output,
            },
        }


_REGISTRY: dict[str, dict[str, ToolFunc]] = {}
_SPECS: dict[tuple[str, str], ToolSpec] = {}
_VERIFIERS: dict[tuple[str, str], Callable[[ToolOutcome], bool]] = {}
_RESETS: dict[tuple[str, str], Callable[[ToolOutcome, ToolContext], None]] = {}
_DEFINITIONS: dict[tuple[str, str], ToolDefinition] = {}


def register_definition(definition: ToolDefinition) -> ToolDefinition:
    """완전한 action 계약만 새 레지스트리에 등록한다."""
    key = (definition.tool, definition.action)
    expected_name = f"{definition.tool}.{definition.action}"
    if definition.name != expected_name:
        raise ToolContractError(
            f"ToolDefinition name은 {expected_name!r}이어야 합니다: {definition.name!r}"
        )
    if not all(callable(item) for item in (
        definition.handler, definition.verifier, definition.resetter,
    )):
        raise ToolContractError(f"{definition.name}의 handler/verifier/resetter가 모두 필요합니다.")
    if not isinstance(definition.spec, ToolSpec):
        raise ToolContractError(f"{definition.name}에 ToolSpec이 필요합니다.")
    if definition.spec.resource_kind not in _STANDARD_ARGS:
        raise ToolContractError(
            f"{definition.name}의 resource_kind가 올바르지 않습니다: "
            f"{definition.spec.resource_kind!r}"
        )
    if not definition.spec.allowed_executors:
        raise ToolContractError(f"{definition.name}의 allowed_executors가 비어 있습니다.")
    if definition.spec.timeout_s <= 0:
        raise ToolContractError(f"{definition.name}의 timeout_s는 양수여야 합니다.")
    if definition.spec.destructive and not definition.spec.resource_limits:
        raise ToolContractError(
            f"{definition.name} 파괴적 action에 resource_limits가 필요합니다."
        )
    if definition.spec.destructive and not definition.spec.emergency_stop_conditions:
        raise ToolContractError(
            f"{definition.name} 파괴적 action에 emergency_stop_conditions가 필요합니다."
        )
    if key in _DEFINITIONS:
        raise ToolContractError(f"중복 ToolDefinition입니다: {definition.name}")
    _DEFINITIONS[key] = definition
    return definition


def known_definitions() -> dict[str, list[str]]:
    definitions: dict[str, list[str]] = {}
    for tool_id, action in _DEFINITIONS:
        definitions.setdefault(tool_id, []).append(action)
    return {tool_id: sorted(actions) for tool_id, actions in definitions.items()}


def get_definition(tool_id: str, action: str) -> ToolDefinition | None:
    """Runtime/Harness가 action 계약과 ToolSpec을 조회하는 공개 read-only API."""
    return _DEFINITIONS.get((tool_id, action))


def definition_manifest() -> list[dict[str, Any]]:
    """백엔드 조립용 JSON-safe ToolDefinition 카탈로그를 반환한다.

    이 값은 action의 코드 존재와 실행 계약만 나타낸다. EC2/환경 인증 완료 여부나
    ``implemented_actions`` 등록 여부는 백엔드의 별도 인증 카탈로그가 결정한다.
    """

    def schema_name(expected: Any) -> str | list[str]:
        if isinstance(expected, tuple):
            return [schema_name(item) for item in expected]  # type: ignore[list-item]
        if isinstance(expected, type):
            return expected.__name__
        return repr(expected)

    manifest: list[dict[str, Any]] = []
    for (tool_id, action), definition in sorted(_DEFINITIONS.items()):
        spec = definition.spec
        manifest.append({
            "name": definition.name,
            "tool": tool_id,
            "action": action,
            "allowed_executors": sorted(spec.allowed_executors),
            "allowed_tbs": sorted(spec.allowed_tbs),
            "resource_kind": spec.resource_kind,
            "argument_schema": {
                key: schema_name(value)
                for key, value in sorted(spec.arg_schema.items())
            },
            "required_arguments": sorted(spec.required_args),
            "destructive": spec.destructive,
            "reversible": spec.reversible,
            "timeout_seconds": spec.timeout_s,
            "resource_limits": dict(sorted(spec.resource_limits.items())),
            "emergency_stop_conditions": sorted(spec.emergency_stop_conditions),
            "handler_registered": callable(definition.handler),
            "verifier_registered": callable(definition.verifier),
            "resetter_registered": callable(definition.resetter),
            "certification_status": "NOT_ASSERTED_BY_TOOL_PACKAGE",
        })
    return manifest


def definition_coverage() -> dict[str, int]:
    """legacy decorator가 아니라 완전 전환된 ToolDefinition 수만 센다."""
    return {
        "tools": len({tool_id for tool_id, _ in _DEFINITIONS}),
        "actions": len(_DEFINITIONS),
    }


def validate_definition_registry(
    expected: dict[str, list[str]] | None = None,
) -> None:
    """누락·초과·불완전 definition을 시작 시 오류로 만든다."""
    for definition in _DEFINITIONS.values():
        if not isinstance(definition.spec, ToolSpec):
            raise ToolContractError(f"{definition.name}에 ToolSpec이 없습니다.")
        if not definition.spec.allowed_executors:
            raise ToolContractError(f"{definition.name}의 allowed_executors가 비어 있습니다.")
    if expected is None:
        return
    expected_keys = {
        (tool_id, action)
        for tool_id, actions in expected.items()
        for action in actions
    }
    actual_keys = set(_DEFINITIONS)
    if expected_keys != actual_keys:
        missing = sorted(expected_keys - actual_keys)
        extra = sorted(actual_keys - expected_keys)
        raise ToolContractError(
            f"ToolDefinition 카탈로그 불일치: missing={missing}, extra={extra}"
        )


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


def action_verifier(tool_id: str, action: str) -> Callable[[ToolOutcome], bool]:
    """DEPRECATED: legacy decorator 호환용 결과 비교기.

    실제 OS/API를 재조회하지 않으므로 ToolDefinition Verifier로 인정하지 않으며
    definition_coverage()에도 포함되지 않는다. family 전환 시 제거한다.
    """

    def _verify(outcome: ToolOutcome) -> bool:
        if outcome.tool != tool_id or outcome.action != action:
            return False
        if not outcome.attempted or outcome.outcome not in {"ALLOWED", "OS_DENIED"}:
            return False
        if outcome.rollback_status == "FAILED":
            return False
        if (
            outcome.identity_before
            and outcome.identity_after
            and outcome.identity_before != outcome.identity_after
        ):
            return False
        if outcome.outcome == "OS_DENIED":
            return not outcome.changed and (
                not (outcome.state_before or outcome.state_after)
                or outcome.state_before == outcome.state_after
            )
        if outcome.exit_code not in {0, None}:
            return False
        spec = _SPECS.get((tool_id, action))
        if spec is not None and spec.reversible and outcome.rollback_status != "VERIFIED":
            return False
        if outcome.rollback_status == "VERIFIED":
            return (
                outcome.identity_before == outcome.identity_after
                and outcome.state_before == outcome.state_after
            )
        # 생성/설치처럼 resetter가 뒤에서 복구하는 action은 verifier 시점에
        # state_after가 state_before와 다른 것이 정상이다. 실제 복구 책임은
        # action에 직접 연결된 resetter가 지며, 공통 resetter는 불일치 시 실패한다.
        return True

    safe_tool = "".join(ch if ch.isalnum() else "_" for ch in tool_id)
    safe_action = "".join(ch if ch.isalnum() else "_" for ch in action)
    _verify.__name__ = f"{safe_tool}_{safe_action}_verifier"
    return _verify


def action_resetter(tool_id: str, action: str) -> Callable[[ToolOutcome, ToolContext], None]:
    """DEPRECATED: legacy decorator 호환용 잔여 상태 검사기.

    실제 복구를 수행하지 않으므로 ToolDefinition Resetter로 인정하지 않으며
    definition_coverage()에도 포함되지 않는다. family 전환 시 제거한다.
    """

    def _reset(outcome: ToolOutcome, context: ToolContext) -> None:
        del context
        if outcome.tool != tool_id or outcome.action != action:
            raise OSError(errno_module.EINVAL, "reset target mismatch")
        if outcome.rollback_status == "FAILED" or outcome.changed:
            raise OSError(errno_module.EIO, "action left an unverified state change")
        if (
            outcome.identity_before
            and outcome.identity_after
            and outcome.identity_before != outcome.identity_after
        ):
            raise OSError(errno_module.EIO, "identity was not restored")
        if (outcome.state_before or outcome.state_after) and outcome.state_before != outcome.state_after:
            raise OSError(errno_module.EIO, "resource state was not restored")
        spec = _SPECS.get((tool_id, action))
        if spec is not None and spec.reversible and outcome.rollback_status != "VERIFIED":
            raise OSError(errno_module.EIO, "reversible action has no verified rollback")
        if spec is not None and spec.destructive and outcome.rollback_status == "NOT_POSSIBLE":
            raise OSError(errno_module.EIO, "destructive action requires a dedicated fixture reset")

    safe_tool = "".join(ch if ch.isalnum() else "_" for ch in tool_id)
    safe_action = "".join(ch if ch.isalnum() else "_" for ch in action)
    _reset.__name__ = f"{safe_tool}_{safe_action}_resetter"
    return _reset


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


def _validate_tool_result(
    definition: ToolDefinition,
    result: ToolResult,
    context: ToolContext,
) -> None:
    expected = {
        "run_id": context.run_id,
        "action_id": context.action_id,
        "tool": definition.tool,
        "action": definition.action,
    }
    actual = {
        "run_id": result.run_id,
        "action_id": result.action_id,
        "tool": result.tool,
        "action": result.action,
    }
    if actual != expected:
        raise ToolContractError(
            f"{definition.name} handler 반환 식별자가 scope와 다릅니다: "
            f"expected={expected}, actual={actual}"
        )
    if result.outcome not in {"ALLOWED", "OS_DENIED", "POLICY_BLOCKED", "ERROR"}:
        raise ToolContractError(
            f"{definition.name} handler의 outcome이 올바르지 않습니다: {result.outcome!r}"
        )
    if result.attempted and not result.identity_before:
        raise ToolContractError(f"{definition.name} handler에 identity_before가 없습니다.")
    if result.attempted and not result.identity_reached:
        raise ToolContractError(f"{definition.name} handler에 identity_reached가 없습니다.")
    if (
        result.outcome == "ALLOWED"
        and (definition.spec.reversible or definition.spec.destructive)
        and not result.state_before
        and result.identity_before == result.identity_reached
    ):
        raise ToolContractError(
            f"{definition.name} 상태 변경 handler에 state_before 또는 identity 변화가 없습니다."
        )


def _validate_verification_result(
    definition: ToolDefinition,
    verification: VerificationResult,
) -> None:
    if verification.status not in {
        "VERIFIED", "VERIFIED_NO_CHANGE", "REJECTED", "NOT_RUN",
    }:
        raise ToolContractError(
            f"{definition.name} verifier status가 올바르지 않습니다: "
            f"{verification.status!r}"
        )
    if verification.status != "NOT_RUN" and not verification.checks:
        raise ToolContractError(f"{definition.name} verifier에 독립 checks가 없습니다.")
    if any(not isinstance(value, bool) for value in verification.checks.values()):
        raise ToolContractError(f"{definition.name} verifier checks는 bool이어야 합니다.")
    if verification.status in {"VERIFIED", "VERIFIED_NO_CHANGE"} and not all(
        verification.checks.values()
    ):
        raise ToolContractError(
            f"{definition.name} verifier가 실패 check를 VERIFIED로 표시했습니다."
        )


def _validate_reset_result(
    definition: ToolDefinition,
    reset_result: ResetResult,
) -> None:
    if reset_result.status not in {
        "VERIFIED", "VERIFIED_NO_CHANGE", "NOT_REQUIRED", "FAILED",
    }:
        raise ToolContractError(
            f"{definition.name} reset status가 올바르지 않습니다: "
            f"{reset_result.status!r}"
        )
    if not reset_result.checks:
        raise ToolContractError(f"{definition.name} resetter에 복구 checks가 없습니다.")
    if any(not isinstance(value, bool) for value in reset_result.checks.values()):
        raise ToolContractError(f"{definition.name} resetter checks는 bool이어야 합니다.")
    if reset_result.status != "FAILED" and not all(reset_result.checks.values()):
        raise ToolContractError(
            f"{definition.name} resetter가 실패 check를 복구 완료로 표시했습니다."
        )
    if not reset_result.identity_after:
        raise ToolContractError(f"{definition.name} resetter에 identity_after가 없습니다.")


def _definition_policy_result(
    definition: ToolDefinition,
    context: ToolContext,
    message: str,
) -> ToolExecution:
    identity = identity_snapshot()
    result = ToolResult(
        run_id=context.run_id,
        action_id=context.action_id,
        tool=definition.tool,
        action=definition.action,
        attempted=False,
        outcome="POLICY_BLOCKED",
        errno=None,
        exit_code=126,
        output=message,
        identity_before=identity,
        identity_reached=identity,
        identity_after=identity,
        rollback_status="NOT_REQUIRED",
    )
    verification = VerificationResult(
        verifier=f"{definition.name}.verifier",
        status="NOT_RUN",
        checks={"policy_allowed": False},
    )
    reset_result = ResetResult(
        resetter=f"{definition.name}.resetter",
        status="NOT_REQUIRED",
        identity_after=identity,
        checks={"handler_attempted": False},
    )
    return ToolExecution(definition.name, result, verification, reset_result)


def execute_definition(
    tool_id: str,
    action: str,
    arguments: dict[str, Any],
    context: ToolContext,
    *,
    state: DefinitionState | None = None,
) -> ToolExecution:
    """완전한 action 계약을 정책→실행→독립 검증→복구 순서로 실행한다.

    Verifier가 REJECTED여도 resetter는 반드시 실행한다. resetter가 FAILED이거나
    상태 변경 action이 복구를 증명하지 못하면 RunGuard를 abort하여 다음 action을
    차단하고 Harness abort_handler를 호출한다.
    """
    definition = _DEFINITIONS.get((tool_id, action))
    if definition is None:
        raise ToolContractError(
            f"완전한 ToolDefinition으로 전환되지 않은 action입니다: {tool_id}.{action}"
        )
    context.ensure_run_active()
    args = dict(arguments)
    try:
        _enforce_spec(tool_id, action, definition.spec, args, context)
    except (ToolPolicyBlocked, ToolInputError) as exc:
        return _definition_policy_result(definition, context, str(exc))

    resource_ref = args.get("resource_ref")
    if definition.spec.resource_kind not in {"none", "self"}:
        if not isinstance(resource_ref, str) or not resource_ref:
            return _definition_policy_result(
                definition,
                context,
                f"{definition.name}에는 등록된 resource_ref가 필요합니다.",
            )
        try:
            context.resolve_resource(resource_ref)
        except ToolPolicyBlocked as exc:
            return _definition_policy_result(definition, context, str(exc))
    decision = ToolDecision(
        tool=tool_id,
        action=action,
        resource_ref=resource_ref if isinstance(resource_ref, str) else None,
        arguments=args,
    )
    execution_state = state if state is not None else {}
    identity_before_handler = identity_snapshot()

    try:
        with _time_limit(definition.spec.timeout_s):
            result = definition.handler(execution_state, decision, context)
    except (ToolPolicyBlocked, ToolInputError) as exc:
        identity_reached = identity_snapshot()
        result = ToolResult(
            run_id=context.run_id,
            action_id=context.action_id,
            tool=tool_id,
            action=action,
            attempted=False,
            outcome="POLICY_BLOCKED",
            errno=None,
            exit_code=126,
            output=str(exc),
            identity_before=identity_before_handler,
            identity_reached=identity_reached,
        )
    except TimeoutError:
        identity_reached = identity_snapshot()
        result = ToolResult(
            run_id=context.run_id,
            action_id=context.action_id,
            tool=tool_id,
            action=action,
            attempted=True,
            outcome="ERROR",
            errno="ETIMEDOUT",
            exit_code=errno_module.ETIMEDOUT,
            output=f"{definition.name} timeout({definition.spec.timeout_s}s)",
            identity_before=identity_before_handler,
            identity_reached=identity_reached,
        )
    except OSError as exc:
        outcome, errno_name, exit_code = outcome_from_oserror(exc)
        identity_reached = identity_snapshot()
        result = ToolResult(
            run_id=context.run_id,
            action_id=context.action_id,
            tool=tool_id,
            action=action,
            attempted=True,
            outcome=outcome,
            errno=errno_name,
            exit_code=exit_code,
            output=str(exc),
            identity_before=identity_before_handler,
            identity_reached=identity_reached,
        )
    except Exception as exc:
        identity_reached = identity_snapshot()
        result = ToolResult(
            run_id=context.run_id,
            action_id=context.action_id,
            tool=tool_id,
            action=action,
            attempted=True,
            outcome="ERROR",
            errno=None,
            exit_code=1,
            output=f"handler error: {exc}",
            identity_before=identity_before_handler,
            identity_reached=identity_reached,
        )
    if not isinstance(result, ToolResult):
        raise ToolContractError(f"{definition.name} handler는 ToolResult를 반환해야 합니다.")
    _validate_tool_result(definition, result, context)

    # Evidence 저장 실패가 발생해도 변경 상태를 남기지 않도록 resetter까지 진행한다.
    evidence_errors: list[str] = []
    try:
        handler_ref = context.record_evidence("handler_result", result.to_dict())
        result.evidence_refs.append(handler_ref)
    except Exception as exc:
        evidence_errors.append(f"handler evidence: {exc}")

    try:
        verification = definition.verifier(
            execution_state, decision, result, context,
        )
        if not isinstance(verification, VerificationResult):
            raise ToolContractError(
                f"{definition.name} verifier는 VerificationResult를 반환해야 합니다."
            )
        _validate_verification_result(definition, verification)
        if result.attempted and verification.status == "NOT_RUN":
            raise ToolContractError(
                f"{definition.name} attempted action의 verifier가 실행되지 않았습니다."
            )
    except Exception as exc:  # resetter는 verifier 오류에도 반드시 실행해야 한다.
        verification = VerificationResult(
            verifier=f"{definition.name}.verifier",
            status="REJECTED",
            checks={"verifier_completed": False},
            observed={"error": str(exc)},
        )
    try:
        verifier_ref = context.record_evidence(
            "verifier_observation",
            {
                "verifier": verification.verifier,
                "status": verification.status,
                "checks": verification.checks,
                "observed": verification.observed,
            },
        )
        verification.evidence_refs.append(verifier_ref)
    except Exception as exc:
        evidence_errors.append(f"verifier evidence: {exc}")
        verification.status = "REJECTED"
        verification.checks["evidence_recorded"] = False

    try:
        reset_result = definition.resetter(
            execution_state, decision, result, context,
        )
        if not isinstance(reset_result, ResetResult):
            raise ToolContractError(
                f"{definition.name} resetter는 ResetResult를 반환해야 합니다."
            )
        _validate_reset_result(definition, reset_result)
        if (
            result.outcome == "ALLOWED"
            and (definition.spec.reversible or definition.spec.destructive)
            and not reset_result.state_after
        ):
            raise ToolContractError(
                f"{definition.name} resetter에 독립 재조회한 state_after가 없습니다."
            )
    except Exception as exc:
        reset_result = ResetResult(
            resetter=f"{definition.name}.resetter",
            status="FAILED",
            checks={"resetter_completed": False},
            output=str(exc),
        )
    try:
        reset_ref = context.record_evidence(
            "reset_observation",
            {
                "resetter": reset_result.resetter,
                "status": reset_result.status,
                "checks": reset_result.checks,
                "identity_after": reset_result.identity_after,
                "state_after": reset_result.state_after,
                "output": reset_result.output,
            },
        )
        reset_result.evidence_refs.append(reset_ref)
    except Exception as exc:
        evidence_errors.append(f"reset evidence: {exc}")
        reset_result.status = "FAILED"
        reset_result.checks["evidence_recorded"] = False
        reset_result.output = "; ".join(evidence_errors)

    result.identity_after = dict(reset_result.identity_after)
    result.state_after = dict(reset_result.state_after)
    result.rollback_status = reset_result.status
    result.evidence_refs.extend(verification.evidence_refs)
    result.evidence_refs.extend(reset_result.evidence_refs)

    requires_verified_restore = (
        result.outcome == "ALLOWED"
        and (definition.spec.reversible or definition.spec.destructive)
    )
    rollback_ok = reset_result.restored and (
        not requires_verified_restore or reset_result.status == "VERIFIED"
    )
    if not rollback_ok:
        reason = (
            f"{definition.name} rollback 검증 실패: "
            f"status={reset_result.status}"
        )
        context.abort_for_rollback(reason)

    return ToolExecution(definition.name, result, verification, reset_result)


def dispatch(tool_id: str, action: str, arguments: dict[str, Any], context: ToolContext) -> ToolOutcome:
    """DEPRECATED legacy dispatch. 신규 action은 execute_definition()을 사용한다."""
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
    """DEPRECATED legacy verifier 호출. 독립 OS/API 재조회를 보장하지 않는다."""
    fn = _VERIFIERS.get((tool_id, action))
    if fn is None:
        # 등록 누락을 성공으로 간주하지 않는다.
        return False
    return fn(outcome)


def reset(tool_id: str, action: str, outcome: ToolOutcome, context: ToolContext) -> str:
    """DEPRECATED legacy reset 호출. family 전환 전 테스트 호환용이다.

    비-probe 상태 변경(file.create/move_link 등)은 등록된 reset으로 생성물을 정리한다.
    반환: "DONE" | "NOT_REQUIRED" | "FAILED".
    """
    fn = _RESETS.get((tool_id, action))
    if outcome.outcome != "ALLOWED":
        return "NOT_REQUIRED"
    if fn is None:
        return "FAILED"
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
    """DEPRECATED legacy inline Probe.

    handler 안에서 복구하므로 새 ToolDefinition의 독립 Verifier가 도달 상태를
    재조회할 수 없다. 전환된 family에서는 사용하지 않는다.

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
