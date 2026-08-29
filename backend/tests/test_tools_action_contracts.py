"""모든 OS Tool action이 handler/verifier/resetter 계약을 갖는지 검사한다."""
from __future__ import annotations

from dataclasses import replace
import sys

import pytest

if sys.platform != "linux":
    pytest.skip("runtime_agent.tools 계약 테스트는 Linux syscall 환경에서만 실행합니다.", allow_module_level=True)

from runtime_agent.tools import (
    ToolContext,
    ToolContractError,
    definition_coverage,
    execute_tool_action,
    get_definition,
    known_definitions,
)
from runtime_agent.tools import base


def _evidence_writer(run_id: str, action_id: str, kind: str, payload: dict) -> str:
    del run_id, action_id, payload
    return f"evidence:{kind}"


def _context(
    resource_paths: dict[str, str] | None = None,
    *,
    with_evidence: bool = True,
) -> ToolContext:
    paths = resource_paths or {}
    return ToolContext(
        run_id="contract-run",
        action_id="contract-action",
        executor_mode="host",
        trust_boundary_id="TB-HH-U1U2",
        source="u1",
        target="u2",
        allowed_targets=frozenset(paths),
        resource_paths=paths,
        evidence_writer=_evidence_writer if with_evidence else None,
    )


def test_all_383_actions_have_handler_verifier_and_resetter() -> None:
    tools = known_definitions()
    keys = {
        (tool, action)
        for tool, actions in tools.items()
        for action in actions
    }

    assert definition_coverage() == {"tools": 129, "actions": 383}
    assert len(tools) == 129
    assert len(keys) == 383
    assert keys == set(base._DEFINITIONS)

    for tool, action in keys:
        definition = get_definition(tool, action)
        assert definition is not None
        assert definition.name == f"{tool}.{action}"
        assert callable(definition.handler)
        assert callable(definition.verifier)
        assert callable(definition.resetter)


def test_definition_catalogue_is_authoritative_over_legacy_dispatch() -> None:
    """호환용 @register 누락이 신규 ToolDefinition 계약 누락으로 보이면 안 된다."""
    definition_keys = set(base._DEFINITIONS)
    legacy_keys = {
        (tool, action)
        for tool, actions in base._REGISTRY.items()
        for action in actions
    }
    assert legacy_keys <= definition_keys


def test_missing_contract_never_defaults_to_success() -> None:
    with pytest.raises(ToolContractError, match="완전한 ToolDefinition"):
        execute_tool_action("not.registered", "missing", {}, _context())


def test_read_action_contract_accepts_stable_observation(tmp_path) -> None:
    target = tmp_path / "target-canary"
    target.write_text("canary", encoding="utf-8")

    execution = execute_tool_action(
        "file.open",
        "read",
        {"resource_ref": "target-canary"},
        _context({"target-canary": str(target)}),
    )

    assert execution.result.outcome == "ALLOWED"
    assert execution.verification.status == "VERIFIED_NO_CHANGE"
    assert execution.reset.status == "VERIFIED_NO_CHANGE"
    assert execution.result.rollback_status == "VERIFIED_NO_CHANGE"


def test_agent_chain_can_defer_registered_resetter(monkeypatch, tmp_path) -> None:
    target = tmp_path / "target-canary"
    target.write_text("canary", encoding="utf-8")
    definition = get_definition("file.open", "read")
    assert definition is not None

    def fail_if_called(*args, **kwargs):
        del args, kwargs
        raise AssertionError("Agent chain must not call the individual resetter")

    monkeypatch.setitem(
        base._DEFINITIONS,
        ("file.open", "read"),
        replace(definition, resetter=fail_if_called),
    )
    execution = execute_tool_action(
        "file.open",
        "read",
        {"resource_ref": "target-canary"},
        _context({"target-canary": str(target)}),
        reset_after=False,
    )

    assert execution.result.outcome == "ALLOWED"
    assert execution.reset.status == "NOT_REQUIRED"
    assert execution.reset.checks == {"deferred_to_harness_reset": True}
    assert "Harness 환경 전체 초기화" in execution.reset.output
    assert target.read_text(encoding="utf-8") == "canary"


def test_missing_evidence_is_rejected_by_action_contract(tmp_path) -> None:
    target = tmp_path / "target-canary"
    target.write_text("canary", encoding="utf-8")
    context = _context({"target-canary": str(target)}, with_evidence=False)

    execution = execute_tool_action(
        "file.open",
        "read",
        {"resource_ref": "target-canary"},
        context,
    )

    assert execution.result.outcome == "ALLOWED"
    assert execution.verification.status == "REJECTED"
    assert execution.reset.status == "FAILED"
    assert context.run_guard.aborted is True
