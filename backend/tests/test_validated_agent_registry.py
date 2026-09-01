from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.attack_tools import (
    ATTACK_TOOL_CATALOG,
    IMPLEMENTED_ATTACK_TOOLS,
    attack_exposure_counts,
    validate_attack_tool_call,
)
from app.catalog import TRUST_BOUNDARIES
from app.harness.os_adapters import (
    ALLOWED_RUNTIME_ACTIONS,
    ALLOWED_RUNTIME_TOOLS,
)
from app.model_gateway import (
    ATTACK_FUNCTION_NAME,
    RECON_FUNCTION_NAME,
    ModelGateway,
    tool_schemas_for_boundary,
)
from runtime_agent import runtime
from runtime_agent.recon_tools import RECON_TOOL_CATALOG
from runtime_agent.validated_actions import (
    CANONICAL_TOOLS_SOURCE_SHA256,
    NON_PASS_ACTIONS,
    tools_source_sha256,
    validated_action_names,
    validation_provenance,
)
from runtime_agent.validated_tool_registry import (
    VALIDATED_ACTION_REGISTRY,
    candidate_arguments,
    runtime_resource_paths,
)


def _payload(decision: dict, *, action_id: str = "targeted-action") -> dict:
    return {
        "run_id": "targeted-run",
        "action_id": action_id,
        "prompt": "targeted test",
        "subject_mode": "container",
        "trust_boundary_id": "TB-CC-C1C2",
        "source_environment": "c1",
        "target_environment": "c2",
        "permission_profile": {},
        "profile_id": "targeted-profile",
        "tool_decision": decision,
        "planner_mode": "local",
    }


def test_canonical_hash_ignores_checkout_line_endings(tmp_path: Path) -> None:
    lf = tmp_path / "lf"
    crlf = tmp_path / "crlf"
    lf.mkdir()
    crlf.mkdir()
    (lf / "a.py").write_bytes(b"x = 1\ny = 2\n")
    (crlf / "a.py").write_bytes(b"x = 1\r\ny = 2\r\n")

    assert tools_source_sha256(lf) == tools_source_sha256(crlf)


def test_canonical_hash_changes_for_content_and_file_membership(tmp_path: Path) -> None:
    root = tmp_path / "tools"
    root.mkdir()
    first = root / "a.py"
    first.write_text("x = 1\n", encoding="utf-8")
    baseline = tools_source_sha256(root)
    first.write_text("x = 2\n", encoding="utf-8")
    changed = tools_source_sha256(root)
    extra = root / "b.py"
    extra.write_text("y = 1\n", encoding="utf-8")
    added = tools_source_sha256(root)
    extra.unlink()

    assert baseline != changed
    assert changed != added
    assert tools_source_sha256(root) == changed


def test_provenance_and_inventory_are_verified() -> None:
    provenance = validation_provenance()
    counts = attack_exposure_counts()

    assert provenance["source_verified"] is True
    assert provenance["canonical_tools_source_sha256"] == CANONICAL_TOOLS_SOURCE_SHA256
    assert provenance["current_tools_source_sha256"] == CANONICAL_TOOLS_SOURCE_SHA256
    assert (provenance["inventory_tools"], provenance["inventory_actions"]) == (129, 383)
    assert provenance["validated_action_count"] == 378
    assert counts == {
        "inventory_tools": 129,
        "inventory_actions": 383,
        "agent_tools": 129,
        "agent_actions": 378,
    }
    assert len(ATTACK_TOOL_CATALOG) == 129
    assert len(IMPLEMENTED_ATTACK_TOOLS) == 129


def test_manifest_mismatch_fails_closed(tmp_path: Path) -> None:
    source = Path(__file__).parents[2] / "validation" / "tool-manifest.json"
    payload = json.loads(source.read_text(encoding="utf-8"))
    payload["tools"][0]["actions"][0]["name"] = "tampered.action"
    stale = tmp_path / "tool-manifest.json"
    stale.write_text(json.dumps(payload), encoding="utf-8")

    assert validated_action_names(manifest_path=stale) == frozenset()
    assert validation_provenance(stale)["source_verified"] is False


def test_agent_surfaces_expose_378_attack_and_113_recon_only() -> None:
    schemas = tool_schemas_for_boundary(TRUST_BOUNDARIES[0])
    by_name = {item["function"]["name"]: item["function"] for item in schemas}

    assert len(by_name[ATTACK_FUNCTION_NAME]["x-validated-actions"]) == 378
    assert len(by_name[RECON_FUNCTION_NAME]["x-recon-tools"]) == 113
    assert len(RECON_TOOL_CATALOG) == 113
    assert not NON_PASS_ACTIONS.intersection(VALIDATED_ACTION_REGISTRY)


def test_docker_control_uses_disposable_registered_fixture() -> None:
    registration = VALIDATED_ACTION_REGISTRY["docker.container_create.create"]

    assert registration.resource_kind == "docker_socket"
    assert registration.resource_refs == frozenset({"docker-engine-socket"})
    assert candidate_arguments(registration) == {
        "image_ref": "docker-fixture-image"
    }
    resources = runtime_resource_paths()
    assert resources["docker-engine-socket"] == "/run/docker.sock"
    assert resources["docker-fixture-image"]


@pytest.mark.skipif(
    not Path("/run/docker.sock").exists(),
    reason="Docker control fixture requires a mounted engine socket",
)
def test_docker_control_fixture_is_verified_and_removed(monkeypatch) -> None:
    monkeypatch.setenv("OS_AGENT_DOCKER_SOCKET_PATH", "/run/docker.sock")
    monkeypatch.setenv("OS_AGENT_DOCKER_FIXTURE_IMAGE", "python:3.10-slim")

    result = runtime.run(_payload({
        "name": "docker.container_create",
        "action": "create",
        "resource_ref": "docker-engine-socket",
        "arguments": {"image_ref": "docker-fixture-image"},
    }))

    assert result["outcome"] == "ALLOWED"
    assert result["changed"] is True
    assert result["temporary_changed"] is True
    assert result["rollback_status"] == "VERIFIED"
    assert any(
        event["event_type"] == "TOOL_CONTRACT_COMPLETED"
        and event["payload"]["verification_status"] == "VERIFIED"
        and event["payload"]["rollback_status"] == "VERIFIED"
        for event in result["events"]
    )


def test_registry_rejects_unknown_action_resource_and_raw_command() -> None:
    with pytest.raises(ValueError, match="validated Agent registry"):
        validate_attack_tool_call("file.open", "unknown", "target-canary", {})
    with pytest.raises(ValueError, match="resource_ref"):
        validate_attack_tool_call("file.open", "read", "unregistered", {})
    with pytest.raises(ValueError, match="Raw command"):
        validate_attack_tool_call(
            "file.open", "read", "target-canary", {"command": "id"}
        )
    with pytest.raises(RuntimeError, match="Raw command"):
        ModelGateway._validate_decision(
            ATTACK_FUNCTION_NAME,
            {
                "tool_id": "file.open",
                "action": "read",
                "resource_ref": "target-canary",
                "arguments": {"command": "id"},
            },
        )


def test_pm_harness_uses_nonempty_validated_allowlist() -> None:
    assert ALLOWED_RUNTIME_TOOLS
    assert len(ALLOWED_RUNTIME_ACTIONS) == 378
    assert ALLOWED_RUNTIME_ACTIONS == frozenset(VALIDATED_ACTION_REGISTRY)
    assert not NON_PASS_ACTIONS.intersection(ALLOWED_RUNTIME_ACTIONS)


def test_representative_attack_dispatches_to_tooldefinition_handler(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    canary = tmp_path / "canary"
    canary.write_text("registry", encoding="utf-8")
    monkeypatch.setenv("OS_AGENT_CANARY_PATH", str(canary))

    result = runtime.run(_payload({
        "name": "file.open",
        "action": "read",
        "resource_ref": "target-canary",
        "arguments": {},
    }))

    assert result["outcome"] == "ALLOWED"
    assert result["attempted"] is True
    assert any(event["event_type"] == "TOOL_CONTRACT_COMPLETED" for event in result["events"])


def test_representative_recon_dispatches_to_existing_handler() -> None:
    result = runtime.run(_payload({
        "name": "os_identity_snapshot",
        "action": "observe",
        "resource_ref": "executor-self",
        "arguments": {},
    }, action_id="targeted-recon"))

    assert result["outcome"] == "ALLOWED"
    assert result["attempted"] is True
    assert "capabilities" in result["identity_before"]
    assert "capability_sets" in result["identity_before"]
    assert "docker_socket" in result["identity_before"]
    assert "apparmor_profile" in result["identity_before"]
    assert "system_path_mounts" in result["identity_before"]
    assert result["runtime_agent"].endswith("-executor-v6")
    assert any(event["event_type"] == "RECON_TOOL_EXECUTED" for event in result["events"])
