"""Audit and journal record verifier source contracts."""
from __future__ import annotations

import os
from types import SimpleNamespace

from runtime_agent.tools import ToolContext, audit_evidence, execute_tool_action


def test_audit_user_record_requeries_bounded_audit_log(tmp_path, monkeypatch) -> None:
    marker = "osagent-audit-probe run=run-1 action=record-1"
    audit_log = tmp_path / "audit.log"
    audit_log.write_text(f"unrelated\ntype=USER msg='{marker}'\n", encoding="utf-8")
    monkeypatch.setattr(audit_evidence, "_AUDIT_LOG", str(audit_log))

    observed = audit_evidence._record_query("audit.user_record", marker)

    assert observed["matches"] == 1
    assert observed["source"] == str(audit_log)
    assert len(observed["sample_hashes"]) == 1


def test_journal_record_keeps_journal_query(monkeypatch) -> None:
    expected = {"marker": "m", "matches": 1, "sample_hashes": ["hash"]}
    monkeypatch.setattr(audit_evidence, "_journal_query", lambda marker: expected)

    assert audit_evidence._record_query("journal.manage", "m") == expected


def test_file_state_requery_does_not_mutate_atime(tmp_path) -> None:
    fixture = tmp_path / "audit-fixture"
    fixture.write_bytes(b"fixture")
    os.utime(fixture, ns=(1_000_000_000, 2_000_000_000))

    first = audit_evidence._file_state(fixture)
    second = audit_evidence._file_state(fixture)

    assert first["atime_ns"] == 1_000_000_000
    assert second["atime_ns"] == first["atime_ns"]


def test_audit_log_append_fixture_restores_exact_state(tmp_path) -> None:
    fixture = tmp_path / "audit-fixture"
    fixture.write_bytes(b"before")
    context = ToolContext(
        run_id="audit-run", action_id="audit-append", executor_mode="host",
        trust_boundary_id="TB-HH-U1U2", source="u1", target="u2",
        allowed_targets=frozenset({"fixture"}),
        resource_paths={"fixture": str(fixture)}, destructive_enabled=True,
        evidence_writer=lambda run_id, action_id, kind, payload: f"evidence:{kind}",
    )

    execution = execute_tool_action(
        "audit.log_manage", "append_probe", {"resource_ref": "fixture"}, context,
    )

    assert execution.verification.status == "VERIFIED"
    assert execution.reset.status == "VERIFIED"
    assert fixture.read_bytes() == b"before"


def test_audit_rule_change_leaves_requested_rule_then_restores(tmp_path, monkeypatch) -> None:
    target = tmp_path / "watch"
    target.write_text("fixture", encoding="utf-8")
    rules: list[str] = []

    monkeypatch.setattr(audit_evidence, "_audit_rules", lambda: tuple(rules))

    def mutate_rule(add: bool, path, permission: str, key: str) -> None:
        rule = f"-w {path} -p {permission} -k {key}"
        if add:
            rules.append(rule)
        elif rule in rules:
            rules.remove(rule)

    monkeypatch.setattr(audit_evidence, "_audit_rule_command", mutate_rule)
    context = ToolContext(
        run_id="audit-run", action_id="audit-change", executor_mode="host",
        trust_boundary_id="TB-HH-U1U2", source="u1", target="u2",
        allowed_targets=frozenset({"watch"}), resource_paths={"watch": str(target)},
        evidence_writer=lambda run_id, action_id, kind, payload: f"evidence:{kind}",
    )

    execution = execute_tool_action(
        "audit.rule_manage", "change",
        {"resource_ref": "watch", "permissions_profile": "read", "key_profile": "primary"},
        context,
    )

    assert execution.result.outcome == "ALLOWED"
    assert execution.verification.status == "VERIFIED"
    assert execution.reset.status == "VERIFIED"
    assert rules == []


def test_queue_pressure_preserves_append_only_evidence_without_aborting_guard(
    tmp_path, monkeypatch,
) -> None:
    fixture = tmp_path / "queue-fixture"
    fixture.write_text("authorization marker", encoding="utf-8")
    status = {"enabled": 1, "backlog_limit": 8192, "lost": 0}
    monkeypatch.setattr(audit_evidence, "_audit_status", lambda: dict(status))
    monkeypatch.setattr(
        audit_evidence, "_journal_query",
        lambda marker: {"marker": marker, "matches": 10, "sample_hashes": ["hash"]},
    )
    monkeypatch.setattr(
        audit_evidence, "_run",
        lambda argv, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    context = ToolContext(
        run_id="audit-run", action_id="audit-queue", executor_mode="host",
        trust_boundary_id="TB-HH-U1U2", source="u1", target="u2",
        allowed_targets=frozenset({"fixture"}),
        resource_paths={"fixture": str(fixture)}, destructive_enabled=True,
        evidence_writer=lambda run_id, action_id, kind, payload: f"evidence:{kind}",
    )

    execution = execute_tool_action(
        "audit.queue_pressure", "fill_queue",
        {"resource_ref": "fixture", "count_profile": "small"}, context,
    )

    assert execution.result.changed is False
    assert execution.result.temporary_changed is False
    assert execution.verification.status == "VERIFIED_NO_CHANGE"
    assert execution.reset.status == "VERIFIED_NO_CHANGE"
    assert context.run_guard is not None
    assert context.run_guard.aborted is False
