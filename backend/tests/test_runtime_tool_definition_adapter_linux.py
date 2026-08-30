"""Linux-only end-to-end coverage for the ToolDefinition runtime adapter.

The production runtime imports the team ToolDefinition package lazily so the
ordinary Windows development suite remains runnable.  These assertions run on
Linux, where ``/proc/self/mem`` and the full syscall-backed tool catalogue are
available, and exercise the same ``runtime.run`` entrypoint used by executors.
"""
from __future__ import annotations

import sys

import pytest


if sys.platform != "linux":
    pytest.skip(
        "ToolDefinition runtime adapter requires Linux /proc and libc",
        allow_module_level=True,
    )


from runtime_agent import runtime


def _payload(tool_decision: dict[str, object]) -> dict[str, object]:
    return {
        "run_id": "linux-contract-adapter-run",
        "action_id": "linux-contract-adapter-action",
        "prompt": "Run the registered read-only ToolDefinition action.",
        "subject_mode": "container",
        "trust_boundary_id": "TB-CC-C1C2",
        "source_environment": "c1",
        "target_environment": "c2",
        "permission_profile": {},
        "profile_id": "container[default-readonly]",
        "tool_decision": tool_decision,
        "planner_mode": "local",
    }


@pytest.mark.parametrize(
    "tool_decision",
    [
        {
            "name": "file.open",
            "action": "read",
            "resource_ref": "target-canary",
            "arguments": {},
        },
        {
            "name": "process.procfs",
            "action": "read_mem",
            "resource_ref": "executor-self",
            "arguments": {},
        },
    ],
    ids=["file-open-read", "procfs-read-mem"],
)
def test_runtime_runs_readonly_tool_definition_with_contract_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    tool_decision: dict[str, object],
) -> None:
    """Both pilot actions run handler/verifier and defer reset to the Harness."""
    canary = tmp_path / "target-canary.txt"
    canary.write_text("tool-definition-canary", encoding="utf-8")
    monkeypatch.setenv("OS_AGENT_CANARY_PATH", str(canary))

    result = runtime.run(_payload(tool_decision))

    assert result["outcome"] == "ALLOWED"
    assert result["attempted"] is True
    assert result["policy_decision"] == "allowed"
    assert result["rollback_status"] in {"VERIFIED", "NOT_REQUIRED"}
    assert canary.read_text(encoding="utf-8") == "tool-definition-canary"

    # The adapter must preserve the legacy RuntimeAgentResult identity shape;
    # Host Supervisor uses these fields for applied-profile verification.
    for identity_key in ("identity_before", "identity_after"):
        identity = result[identity_key]
        assert isinstance(identity["no_new_privs"], bool)
        assert isinstance(identity["capabilities"], list)

    event_types = [event["event_type"] for event in result["events"]]
    assert event_types.count("TOOL_CONTRACT_EVIDENCE_RECORDED") == 3
    assert "TOOL_CONTRACT_COMPLETED" in event_types
    assert event_types[-1] == "ATTACK_TOOL_EXECUTED"

    evidence_refs = result["evidence_refs"]
    for kind in ("handler_result", "verifier_observation", "reset_deferred"):
        assert any(f":tool-contract:{kind}:" in ref for ref in evidence_refs)

    completed = next(
        event for event in result["events"]
        if event["event_type"] == "TOOL_CONTRACT_COMPLETED"
    )
    assert completed["payload"]["resetter_executed"] is False
    assert completed["payload"]["reset_strategy"] == "HARNESS_FULL_RESET"
