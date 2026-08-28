"""공통 기반 거버넌스 테스트 — OStool 요구 1·2·5·7·8이 dispatch에서 강제되는지 검증.

이 테스트는 개별 tool이 아니라 base.py의 ToolSpec 강제·Reset/Verify·namespace evidence를 본다.
"""
from __future__ import annotations

import os

import pytest

from runtime_agent.tools import (
    ToolContext,
    dispatch,
    identity_snapshot,
    ns_snapshot,
    reset,
    verify,
)


@pytest.fixture
def canary(tmp_path):
    p = tmp_path / "canary.txt"
    p.write_text("decoy\n", encoding="utf-8")
    return p


def _ctx(tmp_path, canary, **kw):
    base = dict(
        run_id="r", action_id="a", executor_mode="host", trust_boundary_id="TB-HH-U1U2",
        source="u1", target="u1",
        allowed_targets=frozenset({"target-canary", "target-dir"}),
        resource_paths={"target-canary": str(canary), "target-dir": str(tmp_path)},
    )
    base.update(kw)
    return ToolContext(**base)


# ── 요구 2: 구조화 인자 allowlist ────────────────────────────────────────────

def test_unknown_argument_key_rejected(tmp_path, canary):
    ctx = _ctx(tmp_path, canary)
    out = dispatch("file.open", "read", {"resource_ref": "target-canary", "bogus": 1}, ctx)
    assert out.outcome == "POLICY_BLOCKED"
    assert out.attempted is False
    assert "허용되지 않은 인자" in out.output


def test_wrong_argument_type_rejected(tmp_path, canary):
    ctx = _ctx(tmp_path, canary)
    out = dispatch("file.metadata", "chmod", {"resource_ref": "target-canary", "mode": "0777"}, ctx)
    assert out.outcome == "POLICY_BLOCKED"  # mode는 int여야 함


def test_missing_standard_resource_ref_rejected(tmp_path, canary):
    ctx = _ctx(tmp_path, canary)
    out = dispatch("file.open", "read", {}, ctx)
    assert out.outcome == "POLICY_BLOCKED"


def test_raw_path_still_blocked(tmp_path, canary):
    ctx = _ctx(tmp_path, canary)
    out = dispatch("file.open", "read", {"resource_ref": "target-canary", "path": "/etc/shadow"}, ctx)
    assert out.outcome == "POLICY_BLOCKED"


# ── 요구 1: Executor / Trust Boundary 매트릭스 ──────────────────────────────

def test_executor_matrix_enforced(tmp_path, canary, monkeypatch):
    # spec.allowed_executors를 host로 제한한 뒤 container executor로 호출 → 차단
    from runtime_agent.tools import base
    spec = base._SPECS[("file.open", "read")]
    monkeypatch.setitem(base._SPECS, ("file.open", "read"),
                        base.ToolSpec(resource_kind="path", allowed_executors=frozenset({"host"})))
    ctx = _ctx(tmp_path, canary, executor_mode="container")
    out = dispatch("file.open", "read", {"resource_ref": "target-canary"}, ctx)
    assert out.outcome == "POLICY_BLOCKED"
    assert "Executor" in out.output


def test_trust_boundary_matrix_enforced(tmp_path, canary, monkeypatch):
    from runtime_agent.tools import base
    monkeypatch.setitem(base._SPECS, ("file.open", "read"),
                        base.ToolSpec(resource_kind="path", allowed_tbs=frozenset({"TB-CC-C1C2"})))
    ctx = _ctx(tmp_path, canary)  # TB-HH-U1U2 → 불허
    out = dispatch("file.open", "read", {"resource_ref": "target-canary"}, ctx)
    assert out.outcome == "POLICY_BLOCKED"
    assert "TB" in out.output


# ── 요구 7: 파괴적 Tool은 전용 Fixture에서만 ────────────────────────────────

def test_destructive_blocked_without_fixture(tmp_path, canary):
    ctx = _ctx(tmp_path, canary)  # destructive_enabled=False (기본)
    out = dispatch("file.remove", "unlink", {"resource_ref": "target-canary"}, ctx)
    assert out.outcome == "POLICY_BLOCKED"
    assert out.attempted is False
    assert canary.exists()  # 실제로 지워지지 않음


def test_destructive_allowed_with_fixture(tmp_path, canary):
    ctx = _ctx(tmp_path, canary, destructive_enabled=True)
    out = dispatch("file.remove", "unlink", {"resource_ref": "target-canary"}, ctx)
    assert out.attempted is True
    assert out.outcome in {"ALLOWED", "OS_DENIED", "ERROR"}
    if out.outcome == "ALLOWED":
        assert out.rollback_status == "NOT_POSSIBLE"
        assert not canary.exists()


# ── 요구 8: Tool별 Reset ────────────────────────────────────────────────────

def test_create_then_reset_cleans_up(tmp_path, canary):
    ctx = _ctx(tmp_path, canary)
    out = dispatch("file.create", "file", {"resource_ref": "target-dir", "name": "probe.bin"}, ctx)
    assert out.outcome == "ALLOWED"
    created = tmp_path / "probe.bin"
    assert created.exists()
    status = reset("file.create", "file", out, ctx)   # 요구 8 Reset
    assert status == "DONE"
    assert not created.exists()


def test_move_rename_reset_restores(tmp_path, canary):
    ctx = _ctx(tmp_path, canary)
    out = dispatch("file.move_link", "rename",
                   {"resource_ref": "target-canary", "dest_ref": "target-dir", "name": "moved.txt"}, ctx)
    assert out.outcome == "ALLOWED"
    assert (tmp_path / "moved.txt").exists() and not canary.exists()
    assert reset("file.move_link", "rename", out, ctx) == "DONE"
    assert canary.exists() and not (tmp_path / "moved.txt").exists()


# ── 요구 8: Verifier ────────────────────────────────────────────────────────

def test_verify_default_on_reversible_probe(tmp_path, canary):
    ctx = _ctx(tmp_path, canary)
    out = dispatch("file.metadata", "chmod", {"resource_ref": "target-canary", "mode": 0o640}, ctx)
    assert verify("file.metadata", "chmod", out) is True


# ── 요구 5: namespace evidence ──────────────────────────────────────────────

def test_identity_snapshot_includes_namespaces():
    snap = identity_snapshot()
    assert "namespaces" in snap
    assert "mnt" in snap["namespaces"] and "pid" in snap["namespaces"]
    assert "net" not in snap["namespaces"]  # network ns는 실험 범위 밖


def test_ns_snapshot_self_readable():
    ns = ns_snapshot("self")
    assert ns.get("mnt", "").startswith("mnt:") or ns.get("mnt") is None
