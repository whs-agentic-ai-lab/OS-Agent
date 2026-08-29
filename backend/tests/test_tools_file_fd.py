"""OStool 5.2 파일·디렉터리·FD Tool 단위 테스트.

identity_capability 테스트와 같은 계약만 검증한다.
  1) 안전한 no-op / 실제로 되는 동작 → ALLOWED (부작용은 tmp fixture 안에서만)
  2) 권한 없이 반드시 실패하는 동작 → OS_DENIED/ERROR
  3) 등록 밖 resource_ref / 잘못된 인자 → POLICY_BLOCKED
  4) reversible probe는 rollback_status == "VERIFIED" 이고 changed == False
실제 커널 상태의 "올바름"은 Verifier와 EC2 통합 테스트의 몫이다(3.1/7절).
"""
from __future__ import annotations

import os
import stat as stat_module
import sys

import pytest

if sys.platform != "linux":
    pytest.skip("runtime_agent.tools 계약 테스트는 Linux syscall 환경에서만 실행합니다.", allow_module_level=True)

from runtime_agent.tools import (
    ToolContext,
    dispatch,
    execute_tool_action,
    known_tools,
    reset,
    verify,
)


@pytest.fixture
def canary(tmp_path):
    p = tmp_path / "canary.txt"
    p.write_text("decoy-marker\n", encoding="utf-8")
    return p


@pytest.fixture
def context(tmp_path, canary):
    return ToolContext(
        run_id="test-run",
        action_id="test-action",
        executor_mode="host",
        trust_boundary_id="TB-HH-U1U2",
        source="u1",
        target="u1",
        allowed_targets=frozenset({"target-canary", "target-dir"}),
        resource_paths={"target-canary": str(canary), "target-dir": str(tmp_path)},
    )


# ── 등록 확인 ────────────────────────────────────────────────────────────────


def test_all_5_2_tools_registered():
    tools = known_tools()
    expected = {
        "file.open": {"read", "write", "append", "execute", "opath"},
        "file.create": {"file", "directory", "fifo"},
        "file.content": {"read", "write", "append", "truncate", "copy"},
        "file.remove": {"unlink", "rmdir"},
        "file.move_link": {"rename", "hardlink", "symlink", "follow"},
        "file.metadata": {"chmod", "chown", "chgrp", "set_times"},
        "file.acl": {"get", "set_access", "set_default", "remove"},
        "file.xattr": {"get", "set", "remove"},
        "file.inode_flags": {"get", "set", "clear"},
        "file.lock_lease": {"lock", "unlock", "lease_set", "lease_release"},
        "file.open_by_handle": {"name_to_handle", "open_by_handle"},
        "fd.operate": {"read", "write", "seek", "truncate", "dup", "close"},
        "fd.transfer": {"inherit", "scm_send", "scm_receive", "pidfd_getfd"},
    }
    assert len(expected) == 13
    assert sum(len(actions) for actions in expected.values()) == 49
    for tool_id, actions in expected.items():
        assert tool_id in tools, f"{tool_id} 미등록"
        assert set(tools[tool_id]) == actions, f"{tool_id} action 불일치"


# ── POLICY_BLOCKED ──────────────────────────────────────────────────────────


def test_unregistered_resource_ref_is_policy_blocked(context):
    outcome = dispatch("file.open", "read", {"resource_ref": "not-registered"}, context)
    assert outcome.outcome == "POLICY_BLOCKED"
    assert outcome.attempted is False


def test_raw_path_argument_is_policy_blocked(context):
    outcome = dispatch("file.open", "read", {"resource_ref": "target-canary", "path": "/etc/shadow"}, context)
    assert outcome.outcome == "POLICY_BLOCKED"
    assert outcome.attempted is False


def test_missing_resource_ref_is_policy_blocked(context):
    outcome = dispatch("file.open", "read", {}, context)
    assert outcome.outcome == "POLICY_BLOCKED"


def test_create_rejects_path_traversal_name(context):
    outcome = dispatch("file.create", "file", {"resource_ref": "target-dir", "name": "../escape"}, context)
    assert outcome.outcome == "POLICY_BLOCKED"


# ── ALLOWED (실제 동작, fixture 안) ─────────────────────────────────────────


def test_file_open_read_allowed(context):
    outcome = dispatch("file.open", "read", {"resource_ref": "target-canary"}, context)
    assert outcome.attempted is True
    assert outcome.outcome == "ALLOWED"


def test_file_create_and_registered(context, tmp_path):
    outcome = dispatch("file.create", "file", {"resource_ref": "target-dir", "name": "probe.bin"}, context)
    assert outcome.outcome == "ALLOWED"
    assert (tmp_path / "probe.bin").exists()


@pytest.mark.parametrize("executor_mode", ["host", "container"])
def test_file_content_read_allowed(context, executor_mode):
    context.executor_mode = executor_mode
    outcome = dispatch("file.content", "read", {"resource_ref": "target-canary"}, context)
    assert outcome.outcome == "ALLOWED"
    assert "decoy-marker" in outcome.output
    assert outcome.rollback_status == "NOT_REQUIRED"
    assert verify("file.content", "read", outcome) is True


@pytest.mark.parametrize(
    ("action", "arguments", "reached_size"),
    [
        ("write", {"content": "changed"}, len("changed")),
        ("append", {"content": "changed"}, len("decoy-marker\nchanged")),
        ("truncate", {}, 0),
    ],
)
def test_file_content_changes_are_rolled_back(context, canary, action, arguments, reached_size):
    before = canary.read_bytes()
    outcome = dispatch(
        "file.content",
        action,
        {"resource_ref": "target-canary", **arguments},
        context,
    )
    assert outcome.outcome == "ALLOWED"
    assert outcome.rollback_status == "VERIFIED"
    assert outcome.state_reached["size"] == reached_size
    assert outcome.state_before == outcome.state_after
    assert canary.read_bytes() == before
    assert verify("file.content", action, outcome) is True
    assert reset("file.content", action, outcome, context) == "DONE"


def test_file_content_copy_is_rolled_back(context, canary, tmp_path):
    destination = tmp_path / "destination.txt"
    destination.write_text("original", encoding="utf-8")
    copy_context = ToolContext(
        run_id=context.run_id,
        action_id=context.action_id,
        executor_mode=context.executor_mode,
        trust_boundary_id=context.trust_boundary_id,
        source=context.source,
        target=context.target,
        allowed_targets=frozenset({"target-canary", "target-copy"}),
        resource_paths={"target-canary": str(canary), "target-copy": str(destination)},
    )
    outcome = dispatch(
        "file.content",
        "copy",
        {"resource_ref": "target-canary", "dest_ref": "target-copy"},
        copy_context,
    )
    assert outcome.outcome == "ALLOWED"
    assert outcome.rollback_status == "VERIFIED"
    assert outcome.state_reached["size"] == len(canary.read_bytes())
    assert destination.read_text(encoding="utf-8") == "original"
    assert verify("file.content", "copy", outcome) is True
    assert reset("file.content", "copy", outcome, copy_context) == "DONE"


def test_file_content_rejects_missing_or_oversized_content(context):
    missing = dispatch("file.content", "write", {"resource_ref": "target-canary"}, context)
    oversized = dispatch(
        "file.content",
        "append",
        {"resource_ref": "target-canary", "content": "x" * 129},
        context,
    )
    assert missing.outcome == "POLICY_BLOCKED"
    assert oversized.outcome == "POLICY_BLOCKED"


def test_fd_operate_read_allowed(context, canary):
    fd = os.open(str(canary), os.O_RDONLY)
    try:
        outcome = dispatch("fd.operate", "read", {"fd": fd, "count": 16}, context)
        assert outcome.outcome == "ALLOWED"
        assert "read" in outcome.output
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def test_fd_scm_roundtrip_allowed(context, canary):
    fd = os.open(str(canary), os.O_RDONLY)
    try:
        outcome = dispatch("fd.transfer", "scm_receive", {"fd": fd}, context)
        assert outcome.outcome == "ALLOWED"
    finally:
        os.close(fd)


# ── reversible probe: rollback 검증 ─────────────────────────────────────────


def test_file_chmod_probe_rolls_back(context, canary):
    original = stat_module.S_IMODE(os.stat(canary).st_mode)
    outcome = dispatch("file.metadata", "chmod", {"resource_ref": "target-canary", "mode": 0o777}, context)
    assert outcome.attempted is True
    if outcome.outcome == "ALLOWED":
        # 일시적으로 0o777에 도달했더라도 원복돼야 한다.
        assert outcome.rollback_status == "VERIFIED"
        assert outcome.changed is False
        assert stat_module.S_IMODE(os.stat(canary).st_mode) == original
        assert outcome.state_reached.get("mode") == 0o777
        assert outcome.escalation_possible is True


def test_file_xattr_set_probe_rolls_back(context, canary):
    before = set(os.listxattr(str(canary)))
    outcome = dispatch(
        "file.xattr", "set",
        {"resource_ref": "target-canary", "name": "user.osagent", "value": "probe"},
        context,
    )
    assert outcome.attempted is True
    if outcome.outcome == "ALLOWED":
        assert outcome.rollback_status == "VERIFIED"
        assert set(os.listxattr(str(canary))) == before  # 원복됨


def test_definition_lease_release_tolerates_already_unlocked_reset(context) -> None:
    context.evidence_writer = (
        lambda run_id, action_id, kind, payload: f"evidence:{kind}"
    )
    execution = execute_tool_action(
        "file.lock_lease", "lease_release",
        {"resource_ref": "target-canary"}, context,
    )
    assert execution.result.outcome == "ALLOWED"
    assert execution.verification.status == "VERIFIED"
    assert execution.reset.status == "NOT_REQUIRED"


def test_metadata_chmod_missing_mode_is_policy_blocked(context):
    outcome = dispatch("file.metadata", "chmod", {"resource_ref": "target-canary"}, context)
    assert outcome.outcome == "POLICY_BLOCKED"


# ── deny / structured outcome (권한 의존이라 형태만 검증) ────────────────────


def test_inode_set_immutable_returns_structured_outcome(context):
    # immutable 설정은 보통 CAP_LINUX_IMMUTABLE이 없어 OS_DENIED로 실패한다.
    outcome = dispatch(
        "file.inode_flags", "set",
        {"resource_ref": "target-canary", "flag": "immutable"},
        context,
    )
    assert outcome.attempted is True
    assert outcome.outcome in {"ALLOWED", "OS_DENIED", "ERROR"}
    if outcome.outcome == "ALLOWED":
        assert outcome.rollback_status == "VERIFIED"


def test_inode_flag_ioctl_uses_linux_long_sized_buffer(monkeypatch):
    from runtime_agent.tools import file_fd

    widths: list[int] = []
    requests: list[int] = []

    def fake_ioctl(fd, request, buffer, mutate=False):
        del fd, mutate
        requests.append(request)
        widths.append(buffer.itemsize)
        buffer[0] = 64
        return 0

    monkeypatch.setattr(file_fd.fcntl, "ioctl", fake_ioctl)

    assert file_fd._read_inode_flags(3) == 64
    file_fd._write_inode_flags(3, 64)
    assert widths == [8, 8]
    assert requests == [0x80086601, 0x40086602]


def test_pidfd_getfd_returns_structured_outcome(context):
    outcome = dispatch(
        "fd.transfer", "pidfd_getfd",
        {"pid": os.getpid(), "target_fd": 0},
        context,
    )
    assert outcome.attempted is True
    assert outcome.outcome in {"ALLOWED", "OS_DENIED", "ERROR"}


def test_common_return_fields_present(context):
    outcome = dispatch("file.open", "read", {"resource_ref": "target-canary"}, context)
    d = outcome.to_dict()
    for key in (
        "tool", "action", "attempted", "outcome", "errno", "exit_code",
        "identity_before", "identity_reached", "identity_after",
        "rollback_status", "evidence_refs",
    ):
        assert key in d, f"공통 반환 필드 누락: {key}"
