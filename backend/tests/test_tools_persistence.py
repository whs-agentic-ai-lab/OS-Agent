"""OS-tool 5.9 Persistence 등록·정책·실행·rollback 테스트."""
from __future__ import annotations

import os
import stat
import sys

import pytest

if sys.platform != "linux":
    pytest.skip("runtime_agent.tools 계약 테스트는 Linux syscall 환경에서만 실행합니다.", allow_module_level=True)

from runtime_agent.tools import ToolContext, dispatch, execute_tool_action, known_tools


EXPECTED = {
    "persist.system_cron": {"install", "remove"},
    "persist.at_job": {"schedule", "remove"},
    "persist.systemd_unit": {"install", "enable", "remove"},
    "persist.systemd_trigger": {"install_timer", "install_path", "install_socket", "remove"},
    "persist.systemd_generator": {"install", "remove"},
    "persist.shell_profile": {"install", "remove"},
    "persist.ld_preload": {"install", "remove"},
    "persist.motd": {"install", "remove"},
    "persist.package_hook": {"install", "remove"},
    "persist.logrotate_hook": {"install", "remove"},
    "persist.udev_rule": {"install", "remove"},
    "persist.module_autoload": {"install", "remove"},
    "persist.initramfs_bootloader": {"backup", "modify_probe", "restore"},
    "persist.legacy_init": {"install", "remove"},
    "persist.binary_replace": {"backup", "replace", "restore"},
    "persist.shell_rc": {"install", "remove"},
    "persist.user_cron": {"install", "remove"},
    "persist.user_systemd": {"install", "enable", "remove"},
    "persist.path_hijack": {"install", "remove"},
    "persist.tool_config": {"backup", "modify", "restore"},
    "persist.environment": {"install", "remove"},
    "persist.setid_file": {"create", "remove"},
    "persist.filecap": {"set", "remove"},
    "persist.account_group": {"create_user", "modify_user", "create_group", "modify_group", "rollback"},
    "persist.sudoers": {"install", "remove"},
    "persist.tmpfiles": {"install", "remove"},
    "persist.sysusers": {"install", "remove"},
    "persist.sysctl": {"install", "remove"},
}


@pytest.fixture
def context(tmp_path):
    replacement = tmp_path / "replacement.bin"
    replacement.write_bytes(b"replacement\n")
    elf = tmp_path / "fixture-elf"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 60)
    account = tmp_path / "account.fixture"
    account.touch()
    paths = {
        "target-dir": str(tmp_path),
        "target-file": str(tmp_path / "target.conf"),
        "backup-file": str(tmp_path / "backup.conf"),
        "replacement-file": str(replacement),
        "elf-file": str(elf),
        "account-fixture": str(account),
        "system-cron": str(tmp_path / "osagent-cron"),
        "motd-script": str(tmp_path / "99-osagent"),
        "systemd-service": str(tmp_path / "osagent-persist.service"),
        "shell-rc": str(tmp_path / ".bashrc"),
    }
    return ToolContext(
        run_id="test-run", action_id="test-action", executor_mode="host",
        trust_boundary_id="TB-HH-U1U2", source="u1", target="u2",
        allowed_targets=frozenset(paths), resource_paths=paths,
    )


def test_all_persistence_tools_and_actions_registered():
    tools = known_tools()
    assert len(EXPECTED) == 28
    assert sum(map(len, EXPECTED.values())) == 66
    for tool_id, actions in EXPECTED.items():
        assert set(tools[tool_id]) == actions


@pytest.mark.parametrize(
    ("tool_id", "action"),
    [(tool_id, action) for tool_id, actions in EXPECTED.items() for action in actions],
)
def test_every_persistence_action_is_blocked_in_container(context, tool_id, action):
    context.executor_mode = "container"
    outcome = dispatch(tool_id, action, {}, context)
    assert outcome.outcome == "POLICY_BLOCKED"
    assert outcome.attempted is False


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"executor_mode": "container"}, "Executor"),
        ({"trust_boundary_id": "TB-CC-C1C2"}, "TB"),
    ],
)
def test_executor_and_trust_boundary_matrix(context, change, message):
    for key, value in change.items():
        setattr(context, key, value)
    outcome = dispatch(
        "persist.path_hijack", "install",
        {"resource_ref": "target-dir", "tool_name": "osagent-ls"}, context,
    )
    assert outcome.outcome == "POLICY_BLOCKED"
    assert outcome.attempted is False
    assert message in outcome.output


def test_raw_path_and_unknown_argument_are_rejected(context):
    outcome = dispatch(
        "persist.path_hijack", "install",
        {"resource_ref": "target-dir", "tool_name": "osagent-ls", "path": "/tmp/escape"}, context,
    )
    assert outcome.outcome == "POLICY_BLOCKED"


def test_destructive_action_requires_fixture_gate(context):
    outcome = dispatch(
        "persist.account_group", "create_user", {"resource_ref": "account-fixture"}, context,
    )
    assert outcome.outcome == "POLICY_BLOCKED"
    assert outcome.attempted is False


def test_path_hijack_probe_rolls_back(context, tmp_path):
    context.destructive_enabled = True
    outcome = dispatch(
        "persist.path_hijack", "install",
        {"resource_ref": "target-dir", "tool_name": "osagent-ls"}, context,
    )
    assert outcome.outcome == "ALLOWED"
    assert outcome.rollback_status == "VERIFIED"
    assert outcome.temporary_changed is True and outcome.changed is False
    assert not (tmp_path / "osagent-ls").exists()
    assert len(outcome.evidence_refs) == 3


def test_path_hijack_rejects_traversal(context):
    context.destructive_enabled = True
    outcome = dispatch(
        "persist.path_hijack", "install",
        {"resource_ref": "target-dir", "tool_name": "../escape"}, context,
    )
    assert outcome.outcome == "POLICY_BLOCKED"


def test_required_and_allowlisted_arguments(context):
    assert dispatch("persist.at_job", "remove", {}, context).outcome == "POLICY_BLOCKED"
    context.destructive_enabled = True
    with open(context.resource_paths["target-file"], "wb") as stream:
        stream.write(b"fixture")
    outcome = dispatch(
        "persist.filecap", "set",
        {"resource_ref": "target-file", "capability": "cap_net_raw+ep;id"}, context,
    )
    assert outcome.outcome == "POLICY_BLOCKED"
    assert dispatch("persist.system_cron", "install", {}, context).outcome == "POLICY_BLOCKED"


def test_system_cron_writes_real_rule_then_rolls_back(context):
    context.destructive_enabled = True
    outcome = dispatch("persist.system_cron", "install", {"resource_ref": "system-cron"}, context)
    assert outcome.outcome == "ALLOWED"
    assert outcome.state_reached["exists"] is True
    assert outcome.state_reached["mode"] == 0o644
    assert outcome.rollback_status == "VERIFIED"
    assert not os.path.exists(context.resource_paths["system-cron"])


def test_executable_script_mode_is_observed(context):
    context.destructive_enabled = True
    outcome = dispatch("persist.motd", "install", {"resource_ref": "motd-script"}, context)
    assert outcome.outcome == "ALLOWED"
    assert stat.S_IMODE(outcome.state_reached["mode"]) == 0o755
    assert outcome.rollback_status == "VERIFIED"


def test_remove_restores_content_mode_and_timestamp(context):
    context.destructive_enabled = True
    target = context.resource_paths["target-file"]
    with open(target, "wb") as stream:
        stream.write(b"original")
    os.chmod(target, 0o640)
    os.utime(target, ns=(1_000_000_000, 2_000_000_000))
    before = os.stat(target)
    outcome = dispatch("persist.environment", "remove", {"resource_ref": "target-file"}, context)
    after = os.stat(target)
    assert outcome.outcome == "ALLOWED" and outcome.rollback_status == "VERIFIED"
    with open(target, "rb") as stream:
        assert stream.read() == b"original"
    assert stat.S_IMODE(after.st_mode) == 0o640
    assert after.st_mtime_ns == before.st_mtime_ns


def test_binary_replace_uses_registered_replacement_and_restores(context):
    context.destructive_enabled = True
    target = context.resource_paths["target-file"]
    with open(target, "wb") as stream:
        stream.write(b"original")
    outcome = dispatch(
        "persist.binary_replace", "replace",
        {"resource_ref": "target-file", "replacement_ref": "replacement-file"}, context,
    )
    assert outcome.outcome == "ALLOWED"
    assert outcome.state_reached["destination"]["sha256"] != outcome.state_before["destination"]["sha256"]
    with open(target, "rb") as stream:
        assert stream.read() == b"original"
    assert outcome.rollback_status == "VERIFIED"


def test_setid_uses_registered_elf_and_rolls_back(context, tmp_path):
    context.destructive_enabled = True
    outcome = dispatch(
        "persist.setid_file", "create",
        {"resource_ref": "target-dir", "binary_ref": "elf-file", "setgid": False}, context,
    )
    assert outcome.outcome in {"ALLOWED", "OS_DENIED"}
    if outcome.outcome == "ALLOWED":
        assert outcome.state_reached["mode"] == 0o4755
        assert outcome.rollback_status == "VERIFIED"
    assert not (tmp_path / "osagent-setid").exists()


def test_symlink_target_is_rejected(context, tmp_path):
    real = tmp_path / "real.conf"
    real.write_text("safe", encoding="utf-8")
    link = tmp_path / "link.conf"
    link.symlink_to(real)
    context.resource_paths["target-file"] = str(link)
    outcome = dispatch("persist.tool_config", "modify", {"resource_ref": "target-file"}, context)
    assert outcome.outcome == "POLICY_BLOCKED"
    assert real.read_text(encoding="utf-8") == "safe"


def test_definition_verifier_and_reset(context):
    context.destructive_enabled = True
    replacement = context.resource_paths["replacement-file"]
    assert isinstance(replacement, str)
    os.chmod(replacement, 0o755)
    context.evidence_writer = (
        lambda run_id, action_id, kind, payload: f"evidence://{run_id}/{action_id}/{kind}"
    )
    execution = execute_tool_action(
        "persist.path_hijack", "install",
        {"resource_ref": "target-dir", "executable_ref": "replacement-file"}, context,
    )
    assert execution.result.outcome == "ALLOWED"
    assert execution.verification.status == "VERIFIED"
    assert execution.reset.status == "VERIFIED"
    assert execution.rollback_verified is True


def test_path_hijack_policy_block_has_verified_no_change(context):
    context.destructive_enabled = True
    replacement = context.resource_paths["replacement-file"]
    assert isinstance(replacement, str)
    os.chmod(replacement, 0o755)
    context.evidence_writer = (
        lambda run_id, action_id, kind, payload: f"evidence://{run_id}/{action_id}/{kind}"
    )

    execution = execute_tool_action(
        "persist.path_hijack", "install",
        {"resource_ref": "target-file", "executable_ref": "replacement-file"}, context,
    )

    assert execution.result.outcome == "POLICY_BLOCKED"
    assert execution.verification.status == "VERIFIED_NO_CHANGE"
    assert execution.reset.status == "VERIFIED_NO_CHANGE"


def test_common_result_fields_present(context):
    context.destructive_enabled = True
    outcome = dispatch(
        "persist.path_hijack", "install",
        {"resource_ref": "target-dir", "tool_name": "osagent-id"}, context,
    )
    body = outcome.to_dict()
    for key in (
        "tool", "action", "attempted", "outcome", "errno", "exit_code",
        "identity_before", "identity_reached", "identity_after", "state_before",
        "state_reached", "state_after", "rollback_status", "evidence_refs",
    ):
        assert key in body
