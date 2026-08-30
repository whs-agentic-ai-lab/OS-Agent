"""OStool Agent action 계약의 public execution surface.

각 family import가 action-local ``ToolDefinition``을 등록한다. 신규 Agent 호출은
``execute_tool_action``을 사용하며, 이 모듈은 import 완료 시 MD 카탈로그 수와
handler/verifier/resetter definition coverage를 fail-closed 방식으로 검사한다.
``dispatch/verify/reset``은 기존 호출자 마이그레이션을 위한 deprecated API다.
"""
from .base import (
    ResetResult,
    RunGuard,
    ToolContext,
    ToolContractError,
    ToolDefinition,
    ToolExecution,
    ToolInputError,
    ToolOutcome,
    ToolPolicyBlocked,
    ToolResult,
    ToolSpec,
    VerificationResult,
    definition_coverage,
    definition_manifest,
    dispatch,
    execute_definition,
    get_definition,
    identity_snapshot,
    known_definitions,
    known_tools,
    ns_snapshot,
    reset,
    validate_definition_registry,
    verify,
)
from . import identity_capability  # noqa: F401  (5.1 — 7개 Tool 등록)
from . import file_fd  # noqa: F401  (5.2 — 파일·FD 13개 Tool 등록)
from . import exec_privilege  # noqa: F401  (5.3 — 실행·특권 10개 Tool 등록)
from . import mount_filesystem  # noqa: F401  (5.4 — 마운트·파일시스템 8개 Tool 등록)
from . import process_ipc  # noqa: F401  (5.5 — 프로세스·IPC 14개 Tool 등록)
from . import namespace_kernel  # noqa: F401  (5.6 — Namespace·Kernel 16개 Tool 등록)
from . import container_docker  # noqa: F401  (5.8 — Docker·containerd·OCI 16개 Tool 등록)
from . import systemd_privilege  # noqa: F401  (5.7 — systemd·권한 위임 9개 Tool 등록)
from . import audit_evidence  # noqa: F401  (5.10 — Audit·로그·증거 8개 Tool 등록)
from . import persistence  # noqa: F401  (5.9 — Persistence 28개 Tool 등록)


_EXPECTED_DEFINITION_COVERAGE = {"tools": 129, "actions": 383}
_EXPECTED_DEFINITION_ONLY_ACTIONS = {
    ("evidence.feedback", "stream"),
    ("evidence.feedback", "query"),
    ("evidence.feedback", "correlate"),
}


def _action_keys(catalogue: dict[str, list[str]]) -> set[tuple[str, str]]:
    return {
        (tool, action)
        for tool, actions in catalogue.items()
        for action in actions
    }


_DEFINITION_CATALOGUE = known_definitions()
_LEGACY_CATALOGUE = known_tools()
_DEFINITION_KEYS = _action_keys(_DEFINITION_CATALOGUE)
_LEGACY_KEYS = _action_keys(_LEGACY_CATALOGUE)
_MISSING_DEFINITIONS = _LEGACY_KEYS - _DEFINITION_KEYS
_DEFINITION_ONLY_ACTIONS = _DEFINITION_KEYS - _LEGACY_KEYS

validate_definition_registry(_DEFINITION_CATALOGUE)
if definition_coverage() != _EXPECTED_DEFINITION_COVERAGE:
    raise ToolContractError(
        "Agent ToolDefinition coverage mismatch: "
        f"expected={_EXPECTED_DEFINITION_COVERAGE}, observed={definition_coverage()}"
    )
if _MISSING_DEFINITIONS:
    raise ToolContractError(
        f"legacy catalogue actions without ToolDefinition: {sorted(_MISSING_DEFINITIONS)}"
    )
if _DEFINITION_ONLY_ACTIONS != _EXPECTED_DEFINITION_ONLY_ACTIONS:
    raise ToolContractError(
        "definition-only catalogue mismatch: "
        f"expected={sorted(_EXPECTED_DEFINITION_ONLY_ACTIONS)}, "
        f"observed={sorted(_DEFINITION_ONLY_ACTIONS)}"
    )


# Agent가 호출해야 하는 유일한 신규 action 실행 경로. ToolExecution을 그대로
# 반환하므로 verifier/resetter 결과와 Evidence reference가 소실되지 않는다.
execute_tool_action = execute_definition


__all__ = [
    "ResetResult",
    "RunGuard",
    "ToolContext",
    "ToolContractError",
    "ToolDefinition",
    "ToolExecution",
    "ToolInputError",
    "ToolOutcome",
    "ToolPolicyBlocked",
    "ToolResult",
    "ToolSpec",
    "VerificationResult",
    "definition_coverage",
    "definition_manifest",
    "execute_definition",
    "execute_tool_action",
    "get_definition",
    "known_definitions",
    "validate_definition_registry",
    # Deprecated compatibility API.
    "dispatch",
    "verify",
    "reset",
    "identity_snapshot",
    "ns_snapshot",
    "known_tools",
]
