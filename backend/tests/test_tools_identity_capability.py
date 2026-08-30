"""OStool 5.1 신분·Capability Tool 단위 테스트.

이 테스트는 Tool의 계약(입력 검증 · POLICY_BLOCKED 정규화 · OSError→outcome
매핑 · Target 해석)만 검증한다. 실제로 ALLOWED가 나왔을 때 커널 상태가
"올바르게" 바뀌었는지는 여기서 판정하지 않는다 — 그건 Verifier와 실제
Harness Run의 몫이다(OStool 3.1/7절).

그래서 테스트는 두 종류의 입력만 쓴다.
  1) 현재 값과 동일한 값으로 "변경"을 시도하는 안전한 no-op
  2) 비-root에서 반드시 EPERM으로 실패해 아무 것도 바꾸지 않는 값

프로세스에 되돌릴 수 없는 부작용을 남기는 성공 경로(no_new_privs 활성화,
capability bounding set 제거의 성공 케이스 등)는 이 단위 테스트에서
실제로 실행하지 않는다 — 실행하면 이 테스트 프로세스 자체가 이후 테스트에
영향을 주는 상태로 남기 때문이다.
"""
from __future__ import annotations

import errno as errno_module
import os
import sys

import pytest

if sys.platform != "linux":
    pytest.skip("runtime_agent.tools 계약 테스트는 Linux syscall 환경에서만 실행합니다.", allow_module_level=True)

from runtime_agent.tools import ToolContext, dispatch, execute_tool_action, known_tools


@pytest.fixture
def context() -> ToolContext:
    return ToolContext(
        run_id="test-run",
        action_id="test-action",
        executor_mode="host",
        trust_boundary_id="TB-HH-U1U2",
        source="u1",
        target="u1",
    )


def test_all_5_1_tools_registered():
    tools = known_tools()
    assert set(tools) >= {
        "privilege.identity_probe",
        "privilege.capability_probe",
        "privilege.securebits_probe",
        "privilege.no_new_privs_probe",
        "keyring.manage",
        "session.manage",
        "umask.set",
    }
    assert set(tools["privilege.identity_probe"]) == {
        "setuid",
        "seteuid",
        "setfsuid",
        "setgid",
        "setegid",
        "setfsgid",
        "setgroups",
    }
    assert set(tools["privilege.capability_probe"]) == {"add", "drop", "clear"}
    assert set(tools["privilege.securebits_probe"]) == {"set", "lock"}
    assert set(tools["privilege.no_new_privs_probe"]) == {"enable"}
    assert set(tools["keyring.manage"]) == {
        "add",
        "read",
        "update",
        "link",
        "unlink",
        "revoke",
        "set_permission",
    }
    assert set(tools["session.manage"]) == {"setsid", "setpgid"}
    assert set(tools["umask.set"]) == {"set"}
    assert sum(len(tools[tool]) for tool in {
        "privilege.identity_probe", "privilege.capability_probe",
        "privilege.securebits_probe", "privilege.no_new_privs_probe",
        "keyring.manage", "session.manage", "umask.set",
    }) == 23


def test_unknown_tool_is_policy_blocked(context):
    outcome = dispatch("no.such.tool", "noop", {}, context)
    assert outcome.attempted is False
    assert outcome.outcome == "POLICY_BLOCKED"


def test_unknown_action_is_policy_blocked(context):
    outcome = dispatch("umask.set", "no_such_action", {}, context)
    assert outcome.outcome == "POLICY_BLOCKED"
    assert outcome.attempted is False


def test_umask_set_roundtrip(context):
    previous = os.umask(0o022)
    os.umask(previous)
    try:
        outcome = dispatch("umask.set", "set", {"mask": 0o027}, context)
        assert outcome.attempted is True
        assert outcome.outcome == "ALLOWED"
        assert outcome.identity_after["umask"] == 0o027
    finally:
        os.umask(previous)


def test_umask_set_rejects_out_of_range(context):
    outcome = dispatch("umask.set", "set", {"mask": 0o1000}, context)
    assert outcome.outcome == "POLICY_BLOCKED"
    assert outcome.attempted is False


def test_identity_setuid_noop_is_allowed(context):
    current_uid = os.getuid()
    outcome = dispatch("privilege.identity_probe", "setuid", {"uid": current_uid}, context)
    assert outcome.attempted is True
    assert outcome.outcome == "ALLOWED"
    assert outcome.changed is False
    assert outcome.identity_before["uid"] == current_uid
    assert outcome.identity_after["uid"] == current_uid


@pytest.mark.skipif(os.getuid() == 0, reason="root에서는 실제로 uid가 바뀌어 테스트 프로세스에 부작용을 남긴다")
def test_identity_setuid_denied_without_privilege(context):
    # 실패 errno는 커널/컨테이너 런타임에 따라 EPERM 말고도 달라질 수 있다
    # (예: gVisor 계열 sandbox는 지원하지 않는 uid에 EINVAL을 돌려주기도 한다).
    # 그래서 "무엇으로 실패했는지"가 아니라 "성공하지 않았고 아무 것도 안 바뀌었는지"만 본다 —
    # 이 판단 자체가 바로 OStool이 outcome을 4종으로 나눠 그대로 기록하게 만든 이유다.
    other_uid = 1 if os.getuid() != 1 else 2
    outcome = dispatch("privilege.identity_probe", "setuid", {"uid": other_uid}, context)
    assert outcome.attempted is True
    assert outcome.outcome in {"OS_DENIED", "ERROR"}
    assert outcome.outcome != "ALLOWED"
    assert outcome.changed is False
    assert os.getuid() != other_uid  # 실제로는 바뀌지 않았음을 재확인


def test_identity_setuid_missing_argument(context):
    outcome = dispatch("privilege.identity_probe", "setuid", {}, context)
    assert outcome.outcome == "POLICY_BLOCKED"
    assert outcome.attempted is False


def test_identity_setgroups_type_check(context):
    outcome = dispatch(
        "privilege.identity_probe", "setgroups", {"groups": ["not-an-int"]}, context
    )
    assert outcome.outcome == "POLICY_BLOCKED"


def test_securebits_lock_requires_bits(context):
    outcome = dispatch("privilege.securebits_probe", "lock", {}, context)
    assert outcome.attempted is False
    assert outcome.outcome == "POLICY_BLOCKED"


def test_securebits_policy_block_before_child_is_verified_no_change(context):
    context.evidence_writer = lambda run_id, action_id, kind, payload: f"evidence:{kind}"

    execution = execute_tool_action(
        "privilege.securebits_probe", "set", {"profile": "not-allowlisted"}, context,
    )

    assert execution.result.outcome == "POLICY_BLOCKED"
    assert execution.reset.status == "VERIFIED_NO_CHANGE"
    assert context.run_guard.aborted is False


def test_capability_add_returns_structured_outcome(context, monkeypatch):
    # capability 값은 임의로 넣는다 — 대개 permitted set에 없어 EPERM으로
    # 안전하게 실패한다. 성공/실패 여부는 환경에 따라 달라질 수 있으므로
    # 결과가 계약된 형태로 오는지만 검증한다.
    from runtime_agent.tools import identity_capability

    def _denied_prctl(*args):
        raise OSError(errno_module.EPERM, "test denial")

    monkeypatch.setattr(identity_capability, "prctl", _denied_prctl)
    outcome = dispatch(
        "privilege.capability_probe", "add",
        {"capability": 2, "set_name": "ambient"}, context,
    )
    assert outcome.attempted is True
    assert outcome.outcome in {"ALLOWED", "OS_DENIED", "ERROR"}


def test_capability_add_missing_argument_is_policy_blocked(context):
    outcome = dispatch("privilege.capability_probe", "add", {"set_name": "effective"}, context)
    assert outcome.outcome == "POLICY_BLOCKED"


def test_keyring_add_returns_structured_outcome(context):
    outcome = dispatch(
        "keyring.manage",
        "add",
        {"description": "os-agent-test", "payload": "probe", "keyring": "process"},
        context,
    )
    assert outcome.attempted is True
    assert outcome.outcome in {"ALLOWED", "OS_DENIED", "ERROR"}


def test_keyring_unknown_keyring_target_is_policy_blocked(context):
    outcome = dispatch(
        "keyring.manage",
        "add",
        {"description": "d", "payload": "p", "keyring": "not-a-real-keyring"},
        context,
    )
    assert outcome.outcome == "POLICY_BLOCKED"


def test_session_setpgid_self_is_resilient(context):
    current_pgid = os.getpgid(0)
    outcome = dispatch("session.manage", "setpgid", {"pid": 0, "pgid": current_pgid}, context)
    assert outcome.attempted is True
    assert outcome.outcome in {"ALLOWED", "OS_DENIED"}


def test_session_setpgid_blocks_unregistered_pid():
    ctx = ToolContext(
        run_id="test-run",
        action_id="test-action",
        executor_mode="host",
        trust_boundary_id="TB-HH-U1U2",
        source="u1",
        target="u1",
        allowed_targets=frozenset({"9999"}),
    )
    outcome = dispatch("session.manage", "setpgid", {"pid": 1, "pgid": 1}, ctx)
    assert outcome.outcome == "POLICY_BLOCKED"
    assert outcome.attempted is False
