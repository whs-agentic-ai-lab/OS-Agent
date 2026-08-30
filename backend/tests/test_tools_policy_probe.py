"""Filesystem policy probe reset contracts."""
from __future__ import annotations

import sys
import shutil

import pytest

if sys.platform != "linux":
    pytest.skip("filesystem policy probes require Linux", allow_module_level=True)

from runtime_agent.tools import ToolContext, execute_tool_action


def test_execute_noexec_preserves_registered_probe(tmp_path) -> None:
    probe = tmp_path / "probe"
    shutil.copy2("/usr/bin/true", probe)
    probe.chmod(0o700)
    context = ToolContext(
        run_id="policy-run", action_id="execute-noexec", executor_mode="host",
        trust_boundary_id="TB-HH-U1U2", source="u1", target="u2",
        allowed_targets=frozenset({"mount", "probe"}),
        resource_paths={"mount": str(tmp_path), "probe": str(probe)},
        evidence_writer=lambda run_id, action_id, kind, payload: f"evidence:{kind}",
    )
    execution = execute_tool_action(
        "filesystem.policy_probe", "execute_noexec",
        {"resource_ref": "mount", "probe_ref": "probe"}, context,
    )
    assert execution.result.outcome == "ALLOWED"
    assert execution.verification.status == "VERIFIED_NO_CHANGE"
    assert execution.reset.status == "VERIFIED_NO_CHANGE"
    assert execution.reset.checks["registered_probe_preserved"] is True
