"""모든 OS Tool action이 handler/verifier/resetter 계약을 갖는지 검사한다."""
from __future__ import annotations

import ast
from pathlib import Path

from runtime_agent.tools import ToolContext, ToolOutcome, known_tools, reset, verify
from runtime_agent.tools import base


def _context() -> ToolContext:
    return ToolContext(
        run_id="contract-run",
        action_id="contract-action",
        executor_mode="host",
        trust_boundary_id="TB-HH-U1U2",
        source="u1",
        target="u2",
    )


def test_all_383_actions_have_handler_verifier_and_resetter() -> None:
    tools = known_tools()
    keys = {
        (tool, action)
        for tool, actions in tools.items()
        for action in actions
    }

    assert len(tools) == 129
    assert len(keys) == 383
    assert keys == set(base._VERIFIERS)
    assert keys == set(base._RESETS)

    for tool, action in keys:
        handler = base._REGISTRY[tool][action]
        verifier = base._VERIFIERS[(tool, action)]
        resetter = base._RESETS[(tool, action)]
        assert callable(handler)
        assert callable(verifier)
        assert callable(resetter)


def test_every_action_decorator_declares_verify_and_reset() -> None:
    """action 정의가 별도 중앙 등록에 의존하지 않는지 소스 수준에서 검사한다."""
    tools_dir = Path(base.__file__).parent
    missing: list[str] = []
    decorator_count = 0
    for source in tools_dir.glob("*.py"):
        if source.name in {"__init__.py", "base.py"}:
            continue
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue
                if not isinstance(decorator.func, ast.Name) or decorator.func.id != "register":
                    continue
                decorator_count += 1
                keywords = {keyword.arg for keyword in decorator.keywords}
                absent = {"verify", "reset"} - keywords
                if absent:
                    missing.append(f"{source.name}:{node.lineno}:{','.join(sorted(absent))}")

    assert decorator_count > 0
    assert missing == []
def test_missing_contract_never_defaults_to_success() -> None:
    outcome = ToolOutcome(
        tool="not.registered",
        action="missing",
        attempted=True,
        outcome="ALLOWED",
        exit_code=0,
    )
    assert verify("not.registered", "missing", outcome) is False
    assert reset("not.registered", "missing", outcome, _context()) == "FAILED"


def test_read_action_contract_accepts_stable_observation() -> None:
    identity = {"uid": 1000, "gid": 1000}
    outcome = ToolOutcome(
        tool="file.open",
        action="read",
        attempted=True,
        outcome="ALLOWED",
        exit_code=0,
        identity_before=identity,
        identity_after=dict(identity),
        state_before={"sha256": "same"},
        state_after={"sha256": "same"},
        rollback_status="NOT_REQUIRED",
    )
    assert verify("file.open", "read", outcome) is True
    assert reset("file.open", "read", outcome, _context()) == "DONE"


def test_failed_rollback_is_rejected_by_action_contract() -> None:
    outcome = ToolOutcome(
        tool="file.open",
        action="read",
        attempted=True,
        outcome="ALLOWED",
        exit_code=0,
        changed=True,
        rollback_status="FAILED",
    )
    assert verify("file.open", "read", outcome) is False
    assert reset("file.open", "read", outcome, _context()) == "FAILED"
