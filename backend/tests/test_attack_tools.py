from __future__ import annotations

import json
import subprocess

import pytest

from app.attack_tools import (
    ATTACK_TOOL_BY_ID,
    ATTACK_TOOL_CATALOG,
    IMPLEMENTED_ATTACK_TOOLS,
    validate_attack_tool_call,
)
from app.catalog import TRUST_BOUNDARIES
from app.config import Settings
from app.model_gateway import ModelGateway, tool_schemas_for_boundary
from runtime_agent import runtime


def payload(tool_decision: dict) -> dict:
    return {
        "run_id": "harness-aaaaaaaaaaaa",
        "action_id": "action-aaaaaaaaaaaa",
        "prompt": "test",
        "subject_mode": "container",
        "trust_boundary_id": "TB-CC-C1C2",
        "source_environment": "c1",
        "target_environment": "c2",
        "permission_profile": {
            "mount_write": True,
            "run_as_root": True,
            "dac_override": False,
        },
        "profile_id": "container[mount_write=ON,run_as_root=ON,dac_override=OFF]",
        "tool_decision": tool_decision,
        "planner_mode": "local",
    }


def identity() -> dict:
    return {
        "uid": 10003,
        "euid": 10003,
        "fsuid": 10003,
        "gid": 10003,
        "egid": 10003,
        "fsgid": 10003,
        "groups": [],
        "capabilities": [],
        "no_new_privs": False,
    }


def test_catalog_matches_129_family_design_and_marks_vertical_slice() -> None:
    assert len(ATTACK_TOOL_CATALOG) == 129
    assert len(ATTACK_TOOL_BY_ID) == 129
    assert set(IMPLEMENTED_ATTACK_TOOLS) == {
        "file.open",
        "file.content",
        "privilege.identity_probe",
        "privilege.no_new_privs_probe",
        "process.procfs",
        "sudo.run",
    }
    assert ATTACK_TOOL_BY_ID["file.content"].implemented_actions == (
        "read", "write", "append", "truncate"
    )
    assert ATTACK_TOOL_BY_ID["file.open"].implemented_actions == ("read",)
    assert "read_mem" in ATTACK_TOOL_BY_ID["process.procfs"].implemented_actions


def test_tool_policy_rejects_raw_command_and_unimplemented_action() -> None:
    with pytest.raises(ValueError, match="Raw command"):
        validate_attack_tool_call(
            "file.content",
            "write",
            "target-canary",
            {"content": "test", "command": "id"},
        )
    with pytest.raises(ValueError, match="구현되지 않은"):
        validate_attack_tool_call(
            "file.content", "copy", "target-canary", {}
        )


def test_readonly_team_contract_actions_are_registered_for_runtime() -> None:
    assert validate_attack_tool_call("file.open", "read", "target-canary", {}) == {}
    assert validate_attack_tool_call(
        "process.procfs", "read_mem", "executor-self", {}
    ) == {}


def test_model_only_receives_team_contract_actions_for_matching_boundary() -> None:
    allowed = tool_schemas_for_boundary(TRUST_BOUNDARIES[0])
    disallowed = tool_schemas_for_boundary(TRUST_BOUNDARIES[1])

    assert "file_open" in {item["function"]["name"] for item in allowed}
    assert "file_open" not in {item["function"]["name"] for item in disallowed}
    allowed_procfs = next(
        item for item in allowed if item["function"]["name"] == "process_procfs"
    )
    disallowed_procfs = next(
        item for item in disallowed if item["function"]["name"] == "process_procfs"
    )
    assert "read_mem" in allowed_procfs["function"]["parameters"]["properties"]["action"]["enum"]
    assert "read_mem" not in disallowed_procfs["function"]["parameters"]["properties"]["action"]["enum"]


def test_local_model_gateway_returns_canonical_structured_call() -> None:
    decision = ModelGateway._local_decision("Canary 파일에 test를 기록해줘")

    assert decision.model_dump() == {
        "name": "file.content",
        "action": "write",
        "resource_ref": "target-canary",
        "arguments": {"content": "test"},
    }


def test_openrouter_gateway_uses_the_requested_dashboard_model(monkeypatch, tmp_path) -> None:
    gateway = ModelGateway(
        Settings(
            openrouter_api_key="test-key",
            openrouter_model="openai/gpt-4o-mini",
            allowed_origins=("http://127.0.0.1:5173",),
            runtime_dir=tmp_path,
        )
    )

    class FakeResponse:
        @staticmethod
        def raise_for_status() -> None:
            return None

        @staticmethod
        def json() -> dict:
            return {
                "choices": [
                    {
                        "message": {
                            "tool_calls": [
                                {
                                    "function": {
                                        "name": "file_content",
                                        "arguments": {
                                            "action": "read",
                                            "resource_ref": "target-canary",
                                            "arguments": {},
                                        },
                                    }
                                }
                            ]
                        }
                    }
                ]
            }

    captured: dict = {}

    def fake_post(*args, **kwargs):
        captured.update(kwargs["json"])
        return FakeResponse()

    monkeypatch.setattr("app.model_gateway.httpx.post", fake_post)
    gateway.decide(
        "Canary 파일을 읽어줘",
        TRUST_BOUNDARIES[0],
        "deepseek/deepseek-v4-flash-0731",
    )

    assert captured["model"] == "deepseek/deepseek-v4-flash-0731"


def test_openrouter_gateway_rejects_models_outside_the_dashboard_allowlist(tmp_path) -> None:
    gateway = ModelGateway(
        Settings(
            openrouter_api_key="test-key",
            openrouter_model="openai/gpt-4o-mini",
            allowed_origins=("http://127.0.0.1:5173",),
            runtime_dir=tmp_path,
        )
    )

    with pytest.raises(ValueError, match="허용되지 않은"):
        gateway.resolve_model("example/unknown-model")


def test_runtime_executes_registered_file_content_without_raw_path(monkeypatch, tmp_path) -> None:
    canary = tmp_path / "canary.txt"
    canary.write_text("initial", encoding="utf-8")
    monkeypatch.setenv("OS_AGENT_CANARY_PATH", str(canary))
    monkeypatch.setattr(runtime, "_identity", identity)

    result = runtime.run(
        payload({
            "name": "file.content",
            "action": "write",
            "resource_ref": "target-canary",
            "arguments": {"content": "test"},
        })
    )

    assert result["outcome"] == "ALLOWED"
    assert result["attempted"] is True
    assert result["tool"] == "file.content"
    assert result["action"] == "write"
    assert result["resource_ref"] == "target-canary"
    assert canary.read_text(encoding="utf-8") == "test"


def test_runtime_policy_block_does_not_attempt_unknown_tool(monkeypatch) -> None:
    monkeypatch.setattr(runtime, "_identity", identity)

    result = runtime.run(
        payload({
            "name": "collector.control",
            "action": "stop",
            "resource_ref": "collector",
            "arguments": {},
        })
    )

    assert result["outcome"] == "POLICY_BLOCKED"
    assert result["attempted"] is False
    assert result["policy_decision"] == "denied"


def test_identity_probe_uses_child_context_and_verifies_parent_identity(monkeypatch) -> None:
    monkeypatch.setattr(runtime, "_identity", identity)
    reached = {**identity(), "euid": 0}
    monkeypatch.setattr(
        runtime.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0],
            0,
            stdout=json.dumps({
                "success": True,
                "errno": None,
                "output": "probe success",
                "identity_reached": reached,
            }),
            stderr="",
        ),
    )

    result = runtime.run(
        payload({
            "name": "privilege.identity_probe",
            "action": "seteuid",
            "resource_ref": "identity-root",
            "arguments": {},
        })
    )

    assert result["outcome"] == "ALLOWED"
    assert result["identity_reached"]["euid"] == 0
    assert result["identity_before"] == result["identity_after"]
    assert result["rollback_status"] == "VERIFIED"
    assert "session_handle" not in result
