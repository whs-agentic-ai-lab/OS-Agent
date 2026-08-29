"""Checkpoint and result-classification tests for the live validator."""
from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

if sys.platform != "linux":
    pytest.skip("Tool validation runner requires Linux", allow_module_level=True)

from runtime_agent.tool_validation import build_inventory
from runtime_agent.tool_validation_runner import (
    CheckpointEvidenceReader,
    EvidenceStore,
    Fixture,
    TERMINAL_FAILURES,
    _acknowledge_external_resets,
    _classify,
    _default_arguments,
    _default_resource_ref,
    _write_reports,
    _tree_hash,
)


def test_failures_only_excludes_environment_limitations() -> None:
    assert TERMINAL_FAILURES == {
        "FAIL_HANDLER", "FAIL_VERIFIER", "FAIL_RESETTER", "TIMEOUT",
    }
    assert "UNSUPPORTED_ENV" not in TERMINAL_FAILURES
    assert "INCONCLUSIVE" not in TERMINAL_FAILURES


def test_every_action_has_a_safe_structured_default_plan() -> None:
    inventory = build_inventory()
    for action in inventory["actions"]:
        arguments = _default_arguments(action)
        assert not (set(arguments) - ({"resource_ref"} | set(action["argument_schema"])))
        for required in action["required_arguments"]:
            assert required in arguments


def test_runtime_specific_resources_use_exact_host_endpoints() -> None:
    actions = {item["name"]: item for item in build_inventory()["actions"]}

    assert _default_resource_ref(actions["containerd.task_manage.create"]) == "fixture-containerd-socket"
    assert _default_resource_ref(actions["cgroup.manage.create"]) == "fixture-cgroup"
    assert _default_resource_ref(actions["cdi.device_inject.inject"]) == "fixture-directory"
    assert _default_resource_ref(actions["oci.runtime_run.create"]) == "fixture-oci-bundle"
    assert _default_resource_ref(actions["docker.compose_local.config"]) == "fixture-directory"
    assert _default_resource_ref(actions["systemd.unit_lifecycle.create"]) == "fixture-systemd-runtime"
    assert _default_resource_ref(actions["device.manage.rule_probe"]) == "fixture-cgroup-controllers"
    assert _default_resource_ref(actions["device.manage.mknod"]) == "fixture-directory"
    assert _default_resource_ref(actions["device.manage.write"]) == "fixture-backup"
    assert _default_resource_ref(actions["file.remove.rmdir"]) == "fixture-directory"
    assert _default_resource_ref(actions["filesystem.policy_probe.device_nodev"]) == "fixture-directory"
    assert _default_resource_ref(actions["filesystem.resource_pressure.blocks"]) == "fixture-directory"
    assert _default_resource_ref(actions["filesystem.resource_pressure.inodes"]) == "fixture-directory"
    assert _default_resource_ref(actions["filesystem.resource_pressure.quota"]) == "fixture-directory"
    assert _default_resource_ref(actions["mount.manage.unmount"]) == "fixture-directory"
    assert _default_resource_ref(actions["mount.overlay.unmount"]) == "fixture-directory"
    assert _default_resource_ref(actions["oci.hook_run.run"]) == "fixture-oci-hook-bundle"
    assert _default_resource_ref(actions["kernel.module.load_probe"]) == "fixture-module-file"
    assert _default_resource_ref(actions["kernel.module.unload_probe"]) == "fixture-module-name"
    assert _default_resource_ref(actions["bpf.manage.pin"]) == "fixture-directory"
    assert _default_resource_ref(actions["bpf.manage.remove"]) == "fixture-directory"
    assert _default_resource_ref(actions["chroot.run.create"]) == "fixture-directory"
    assert _default_resource_ref(actions["persist.path_hijack.install"]) == "fixture-directory"
    assert _default_resource_ref(actions["persist.path_hijack.remove"]) == "fixture-directory"
    assert _default_resource_ref(actions["persist.setid_file.create"]) == "fixture-directory"
    assert _default_resource_ref(actions["persist.setid_file.remove"]) == "fixture-directory"
    assert _default_resource_ref(actions["persist.systemd_trigger.install_path"]) == "fixture-systemd-trigger"
    assert _default_resource_ref(actions["persist.systemd_unit.enable"]) == "fixture-systemd-unit"
    assert _default_resource_ref(actions["persist.user_systemd.enable"]) == "fixture-user-systemd-unit"
    assert _default_resource_ref(actions["power.manage.reboot_probe"]) == "fixture-power-reboot"
    assert _default_resource_ref(actions["power.manage.kexec_probe"]) == "fixture-power-kexec"
    assert _default_resource_ref(actions["power.manage.wake_alarm_probe"]) == "fixture-power-wake-alarm"
    assert _default_resource_ref(actions["power.manage.suspend_probe"]) == "fixture-power-suspend"
    assert _default_resource_ref(actions["process.accounting.start"]) == "fixture-accounting"
    assert _default_resource_ref(actions["rawio.access.write"]) == "fixture-backup"
    assert _default_resource_ref(actions["systemd.user_linger.enable"]) == "fixture-linger-user"
    assert _default_resource_ref(actions["toolchain.build.compile"]) == "fixture-directory"
    assert _default_resource_ref(actions["namespace.manage.enter"]) == "fixture-namespace-mnt"
    assert _default_arguments(actions["privilege.securebits_probe.set"])["profile"] == "noroot"
    assert _default_arguments(actions["file.acl.set_access"])["entry"] == "u::rw"
    assert _default_arguments(actions["file.xattr.get"])["name"] == "user.osagent"
    assert _default_arguments(actions["file.inode_flags.set"])["flag"] == "nodump"
    assert _default_arguments(actions["file.xattr.set"])["name"] == "user.osagent"
    assert _default_arguments(actions["file.xattr.remove"])["name"] == "user.osagent"
    assert _default_arguments(actions["file.content.copy"])["dest_ref"] == "fixture-backup"
    assert _default_arguments(actions["docker.log_manage.delete_probe"])["log_root_ref"] == "fixture-docker-log-root"
    assert _default_arguments(actions["persist.account_group.create_user"])["shell_ref"] == "fixture-shell"
    assert _default_arguments(actions["kernel.module.load_probe"])["module_name_ref"] == "fixture-module-name"
    assert _default_arguments(actions["kernel.module.unload_probe"])["module_file_ref"] == "fixture-module-file"
    assert _default_arguments(actions["audit.queue_pressure.fill_queue"])["count_profile"] == "small"
    assert _default_arguments(actions["persist.at_job.schedule"])["time_profile"] == "one_hour"
    assert _default_arguments(actions["persist.filecap.set"])["capability_profile"] == "chown_ep"
    assert _default_arguments(actions["persist.legacy_init.install"])["executable_ref"] == "fixture-executable"
    assert _default_arguments(actions["persist.legacy_init.remove"])["executable_ref"] == "fixture-executable"
    assert _default_arguments(actions["persist.sysctl.install"])["key_ref"] == "fixture-sysctl-key"
    assert _default_arguments(actions["persist.sysctl.install"])["value_ref"] == "fixture-sysctl-value"
    assert _default_arguments(actions["persist.systemd_trigger.install_path"])["service_ref"] == "fixture-systemd-trigger-service"
    assert _default_arguments(actions["persist.systemd_trigger.install_path"])["watch_ref"] == "fixture-systemd-trigger-watch"
    assert _default_arguments(actions["persist.systemd_unit.enable"])["executable_ref"] == "fixture-executable"
    assert _default_arguments(actions["persist.user_systemd.enable"])["executable_ref"] == "fixture-executable"


def test_fixture_hash_is_stable_and_sensitive(tmp_path) -> None:
    fixture = Fixture.create(tmp_path / "fixture")
    try:
        assert fixture.resource_paths["fixture-executable"] == "/usr/bin/true"
        assert __import__("os").path.realpath("/usr/bin/true") == "/usr/bin/true"
        before = _tree_hash(fixture.root)
        assert before == _tree_hash(fixture.root)
        (fixture.root / "canary").write_text("changed", encoding="utf-8")
        assert before != _tree_hash(fixture.root)
    finally:
        fixture.close()


def test_systemd_trigger_fixture_uses_matching_runtime_units(tmp_path) -> None:
    fixture = Fixture.create(
        tmp_path / "fixture", "persist.systemd_trigger.install_path",
    )
    try:
        path_type = __import__("pathlib").Path
        trigger = path_type(fixture.resource_paths["fixture-systemd-trigger"])
        service = path_type(fixture.resource_paths["fixture-systemd-trigger-service"])
        assert trigger.parent == path_type("/run/systemd/system")
        assert trigger.suffix == ".path"
        assert service == trigger.with_suffix(".service")
    finally:
        fixture.close()


def test_runtime_image_contains_compiled_identity_reporter() -> None:
    reporter = __import__("pathlib").Path(__file__).parents[1] / "runtime_agent" / "fixtures" / "identity-reporter"
    if not reporter.exists():
        pytest.skip("compiled fixture exists in the built runtime image")
    assert reporter.read_bytes().startswith(b"\x7fELF")


def test_checkpoint_evidence_reader_is_scoped_and_read_only(tmp_path) -> None:
    evidence = tmp_path / "evidence" / "action-a"
    evidence.mkdir(parents=True)
    (evidence / "001-handler.json").write_text(
        '{"run_id":"run-a","action_id":"action-a","kind":"handler"}',
        encoding="utf-8",
    )
    reader = CheckpointEvidenceReader(tmp_path)
    response = reader.read(
        operation="query", run_id="run-a", action_id="action-a",
        source="before_after_state", limit=10,
    )
    assert len(response["records"]) == 1
    assert reader.verify_read_only(response["read_token"]) is True
    assert reader.close(response["read_token"]) == {
        "closed": True, "collector_mutated": False,
    }


def test_unsupported_kernel_result_is_not_a_handler_failure() -> None:
    execution = SimpleNamespace(
        result=SimpleNamespace(
            errno="ENOTSUP", outcome="ERROR", output="kernel feature unsupported",
        ),
        reset=SimpleNamespace(restored=True, output=""),
        verification=SimpleNamespace(accepted=True, observed={}),
    )

    assert _classify(execution, False) == (
        "UNSUPPORTED_ENV", "kernel feature unsupported",
    )


def test_external_reset_acknowledgement_requires_independent_verification(
    monkeypatch, tmp_path,
) -> None:
    checkpoint = {
        "run_id": "run-a",
        "results": {
            "audit.lock.enable_probe": {
                "status": "FAIL_RESETTER",
                "execution": {"verification": {"status": "VERIFIED"}},
            },
        },
    }
    monkeypatch.setattr(
        "runtime_agent.tool_validation_runner._external_reset_observation",
        lambda name: {"verified": True, "method": "same-instance-reboot"},
    )

    count = _acknowledge_external_resets(
        checkpoint,
        ["audit.lock.enable_probe"],
        {"audit.lock.enable_probe": {"code_hash": "sha256:current"}},
        EvidenceStore(tmp_path),
    )

    record = checkpoint["results"]["audit.lock.enable_probe"]
    assert count == 1
    assert record["status"] == "PASS"
    assert record["external_reset"]["evidence_ref"].endswith(
        "external_reset_observation.json"
    )


def test_irreversible_journal_reset_is_acknowledged_as_inconclusive(
    monkeypatch, tmp_path,
) -> None:
    name = "journal.manage.rotate_probe"
    checkpoint = {
        "run_id": "run-a",
        "results": {
            name: {
                "status": "FAIL_RESETTER",
                "execution": {"verification": {"status": "VERIFIED"}},
            },
        },
    }
    monkeypatch.setattr(
        "runtime_agent.tool_validation_runner._external_reset_observation",
        lambda action_name: {
            "verified": True,
            "reset_restored": False,
            "reason": "journal maintenance is not exactly reversible",
        },
    )

    count = _acknowledge_external_resets(
        checkpoint, [name], {name: {"code_hash": "sha256:current"}},
        EvidenceStore(tmp_path),
    )

    assert count == 1
    assert checkpoint["results"][name]["status"] == "INCONCLUSIVE"
    assert "not exactly reversible" in checkpoint["results"][name]["reason"]


def test_report_reconstructs_global_checkpoint_coverage(tmp_path) -> None:
    inventory = build_inventory()
    first, second = inventory["actions"][:2]
    checkpoint = {
        "run_id": "run-report",
        "results": {
            first["name"]: {"status": "PASS", "reason": "verified"},
            second["name"]: {"status": "INCONCLUSIVE", "reason": "exact reset unproven"},
        },
    }

    report = _write_reports(tmp_path, checkpoint, inventory, selected=2, aborted=False)

    assert report["executed"] == 2
    assert report["untested_count"] == inventory["summary"]["actions"] - 2
    assert report["counts"] == {"INCONCLUSIVE": 1, "PASS": 1}
    assert report["outcome"] == "INCOMPLETE"
    assert (tmp_path / "report.json").is_file()
    markdown = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "129 Tools / 383 Actions" in markdown
    assert first["name"] in markdown
