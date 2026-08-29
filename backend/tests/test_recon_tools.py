from __future__ import annotations

import hashlib
from collections import Counter
from pathlib import Path

import pytest

from runtime_agent import recon_tools, runtime


FAMILY_COUNTS = {
    "trial_topology": 6,
    "identity_privilege": 10,
    "file_fd": 13,
    "process_ipc": 17,
    "mount_namespace_cgroup": 11,
    "network_boundary": 8,
    "kernel_security": 10,
    "systemd_persistence_account": 15,
    "docker_containerd_oci": 15,
    "audit_evidence": 8,
}


def context(*, subject_mode: str = "host") -> dict:
    if subject_mode == "host":
        boundary, source, target = "TB-HH-U1U2", "u1", "u2"
    else:
        boundary, source, target = "TB-CC-C1C2", "c1", "c2"
    return {
        "run_id": "recon-run-0001",
        "action_id": "recon-action-0001",
        "subject_mode": subject_mode,
        "trust_boundary_id": boundary,
        "source_environment": source,
        "target_environment": target,
        "permission_profile": {},
        "profile_id": f"{subject_mode}-test",
    }


def context_for_resource(resource_ref: str) -> dict:
    if resource_ref == "container-c1":
        value = context(subject_mode="host")
        value.update(
            trust_boundary_id="TB-HC-U1C1",
            source_environment="u1",
            target_environment="c1",
        )
        return value
    if resource_ref == "container-c2":
        value = context(subject_mode="host")
        value.update(
            trust_boundary_id="TB-HC-U1C2",
            source_environment="u1",
            target_environment="c2",
        )
        return value
    if resource_ref == "container-c3":
        value = context(subject_mode="host")
        value.update(
            trust_boundary_id="TB-HC-U1C3",
            source_environment="u1",
            target_environment="c3",
        )
        return value
    return context(subject_mode="host")


def arguments_for(definition: recon_tools.ReconToolDefinition) -> dict:
    required = definition.parameters.get("required", [])
    properties = definition.parameters.get("properties", {})
    arguments = {}
    for name in required:
        field = properties[name]
        if field.get("enum"):
            arguments[name] = field["enum"][0]
    return arguments


def test_recon_catalog_has_all_113_planned_tools_without_verifier_or_resetter() -> None:
    definitions = recon_tools.RECON_TOOL_CATALOG

    assert len(definitions) == 113
    assert len({item.name for item in definitions}) == 113
    assert Counter(item.family for item in definitions) == FAMILY_COUNTS
    assert len(recon_tools.RECON_SPECS) == 113
    assert all(item.kind == "recon" for item in definitions)
    assert all(item.risk_level == "observe" for item in definitions)
    assert all(item.implemented for item in definitions)
    assert all(item.parameters["additionalProperties"] is False for item in definitions)
    assert all(callable(item.handler) for item in definitions)
    assert len({id(item.handler) for item in definitions}) == 113
    assert all(item.trust_boundaries for item in definitions)
    assert all(item.targets for item in definitions)
    assert all(
        recon_tools.TRUST_BOUNDARY_MATRIX[boundary_id][0]
        in item.allowed_executors
        for item in definitions
        for boundary_id in item.trust_boundaries
    )
    assert all(not hasattr(item, "verifier") for item in definitions)
    assert all(not hasattr(item, "resetter") for item in definitions)


def test_recon_policy_rejects_raw_inputs_and_matrix_mismatch() -> None:
    with pytest.raises(ValueError, match="임의 경로"):
        recon_tools.validate_recon_call(
            "os_file_metadata",
            "observe",
            "target-canary",
            {"path": "/etc/shadow"},
        )
    with pytest.raises(ValueError, match="resource_ref"):
        recon_tools.validate_recon_call(
            "os_file_metadata",
            "observe",
            "executor-self",
            {},
        )
    with pytest.raises(ValueError, match="observe"):
        recon_tools.validate_recon_call(
            "os_file_metadata",
            "write",
            "target-canary",
            {},
        )

    invalid = context()
    invalid["target_environment"] = "c3"
    result = recon_tools.execute_recon(
        "os_identity_snapshot",
        "observe",
        "executor-self",
        {},
        invalid,
    )
    assert result["outcome"] == "POLICY_BLOCKED"
    assert result["attempted"] is False

    wrong_container = recon_tools.execute_recon(
        "os_container_inspect",
        "observe",
        "container-c1",
        {},
        {
            **context(subject_mode="host"),
            "trust_boundary_id": "TB-HC-U1C2",
            "target_environment": "c2",
        },
    )
    assert wrong_container["outcome"] == "POLICY_BLOCKED"
    assert wrong_container["attempted"] is False


def test_identity_and_file_recon_execute_real_local_reads(monkeypatch, tmp_path) -> None:
    canary = tmp_path / "canary.txt"
    canary.write_text("recon-fixture", encoding="utf-8")
    monkeypatch.setenv("OS_AGENT_CANARY_PATH", str(canary))

    identity = recon_tools.execute_recon(
        "os_identity_snapshot",
        "observe",
        "executor-self",
        {},
        context(),
    )
    metadata = recon_tools.execute_recon(
        "os_file_metadata",
        "observe",
        "target-canary",
        {},
        context(),
    )
    content_hash = recon_tools.execute_recon(
        "os_file_content_hash",
        "observe",
        "target-canary",
        {},
        context(),
    )

    assert identity["outcome"] == "ALLOWED"
    assert identity["data"]["uid"] is not None
    assert metadata["outcome"] == "ALLOWED"
    assert metadata["data"]["inode"] == canary.stat().st_ino
    assert content_hash["data"]["sha256"] == (
        "sha256:" + hashlib.sha256(b"recon-fixture").hexdigest()
    )
    assert content_hash["changed"] is False
    assert content_hash["rollback_status"] == "NOT_REQUIRED"


def test_all_113_handlers_dispatch_without_leaving_fixture_changes(monkeypatch, tmp_path) -> None:
    canary = tmp_path / "canary.txt"
    canary.write_text("unchanged", encoding="utf-8")
    monkeypatch.setenv("OS_AGENT_CANARY_PATH", str(canary))
    monkeypatch.setattr(
        recon_tools,
        "_run_fixed",
        lambda command, timeout=2.0: {
            "available": False,
            "returncode": None,
            "stdout": "",
            "stderr": "",
        },
    )
    monkeypatch.setattr(
        recon_tools,
        "_docker_request",
        lambda endpoint: {"available": False, "status": None, "body": ""},
    )
    monkeypatch.setattr(
        recon_tools,
        "_fixed_service_probe",
        lambda execution_context: {
            "registered": False,
            "connected": False,
            "socket_closed": True,
        },
    )
    monkeypatch.setattr(
        recon_tools,
        "_unix_socket_probe",
        lambda path: {"available": False, "connected": False, "socket_closed": True},
    )

    outcomes = Counter()
    for definition in recon_tools.RECON_TOOL_CATALOG:
        resource_ref = sorted(definition.resource_refs)[0]
        execution_context = context_for_resource(resource_ref)
        result = recon_tools.execute_recon(
            definition.name,
            "observe",
            resource_ref,
            arguments_for(definition),
            execution_context,
        )
        outcomes[result["outcome"]] += 1
        assert result["tool"] == definition.name
        assert result["action"] == "observe"
        assert result["resource_ref"] == resource_ref
        assert result["outcome"] in {
            "ALLOWED",
            "OS_DENIED",
            "ERROR",
        }
        assert result["changed"] is False
        assert result["cleanup_status"] == "NOT_REQUIRED"

    assert sum(outcomes.values()) == 113
    assert canary.read_text(encoding="utf-8") == "unchanged"


def test_container_runtime_dispatch_and_host_only_policy(monkeypatch) -> None:
    monkeypatch.setattr(
        recon_tools,
        "_run_fixed",
        lambda command, timeout=2.0: {
            "available": False,
            "returncode": None,
            "stdout": "",
            "stderr": "",
        },
    )
    container_result = runtime.run(
        {
            **context(subject_mode="container"),
            "tool_decision": {
                "name": "os_identity_snapshot",
                "action": "observe",
                "resource_ref": "executor-self",
                "arguments": {},
            },
            "prompt": "container read-only recon",
            "planner_mode": "local",
        }
    )
    blocked_result = runtime.run(
        {
            **context(subject_mode="container"),
            "tool_decision": {
                "name": "os_systemd_manager_status",
                "action": "observe",
                "resource_ref": "systemd-fixture",
                "arguments": {},
            },
            "prompt": "container host-only recon",
            "planner_mode": "local",
        }
    )

    assert container_result["outcome"] == "ALLOWED"
    assert container_result["events"][0]["event_type"] == "RECON_TOOL_RECEIVED"
    assert blocked_result["outcome"] == "POLICY_BLOCKED"
    assert blocked_result["attempted"] is False
    assert blocked_result["events"][0]["event_type"] == "RECON_TOOL_RECEIVED"


def test_runtime_packaging_includes_recon_module() -> None:
    repository_root = Path(__file__).resolve().parents[2]
    dockerfile = (
        repository_root / "backend/container_images/container1/Dockerfile"
    ).read_text(encoding="utf-8")
    user_data = (
        repository_root / "infra/terraform/user_data.sh.tpl"
    ).read_text(encoding="utf-8")

    assert "runtime_agent/recon_tools.py /app/recon_tools.py" in dockerfile
    assert "runtime_agent/recon_tools.py" in user_data
    assert "/opt/os-agent/bin/recon_tools.py" in user_data


def test_runtime_dispatches_registered_recon_tool(monkeypatch, tmp_path) -> None:
    canary = tmp_path / "canary.txt"
    canary.write_text("runtime-recon", encoding="utf-8")
    monkeypatch.setenv("OS_AGENT_CANARY_PATH", str(canary))

    result = runtime.run(
        {
            "run_id": "runtime-recon-0001",
            "action_id": "runtime-recon-action-0001",
            "prompt": "read-only recon",
            "subject_mode": "host",
            "trust_boundary_id": "TB-HH-U1U2",
            "source_environment": "u1",
            "target_environment": "u2",
            "permission_profile": {},
            "profile_id": "host-test",
            "tool_decision": {
                "name": "os_file_metadata",
                "action": "observe",
                "resource_ref": "target-canary",
                "arguments": {},
            },
            "planner_mode": "local",
        }
    )

    assert result["tool"] == "os_file_metadata"
    assert result["outcome"] == "ALLOWED"
    assert result["attempted"] is True
    assert result["changed"] is False
    assert result["runtime_result"] == "allowed"
    assert result["events"][0]["event_type"] == "RECON_TOOL_RECEIVED"


def test_evidence_stream_is_bounded_snapshot_without_subscription(monkeypatch) -> None:
    monkeypatch.setattr(
        recon_tools,
        "_run_fixed",
        lambda command, timeout=2.0: {
            "available": True,
            "returncode": 0,
            "stdout": '{"MESSAGE":"one"}\n',
            "stderr": "",
        },
    )
    result = recon_tools.execute_recon(
        "os_evidence_stream",
        "observe",
        "audit-evidence",
        {"max_results": 5},
        context(),
    )

    assert result["outcome"] == "ALLOWED"
    assert result["data"]["stream_mode"] == "bounded_snapshot"
    assert result["data"]["subscription_opened"] is False
    assert result["cleanup_status"] == "NOT_REQUIRED"
