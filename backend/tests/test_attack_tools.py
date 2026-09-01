from __future__ import annotations

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
from app.model_gateway import ATTACK_FUNCTION_NAME, RECON_FUNCTION_NAME
from runtime_agent import runtime
from runtime_agent import validated_actions


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


def test_catalog_matches_129_383_design_and_connects_live_pass_registry() -> None:
    assert len(ATTACK_TOOL_CATALOG) == 129
    assert len(ATTACK_TOOL_BY_ID) == 129
    assert len(IMPLEMENTED_ATTACK_TOOLS) == 129
    assert sum(
        len(definition.implemented_actions)
        for definition in IMPLEMENTED_ATTACK_TOOLS.values()
    ) == 378
    assert set(ATTACK_TOOL_BY_ID["file.content"].implemented_actions) == {
        "read", "write", "append", "truncate", "copy",
    }
    assert set(ATTACK_TOOL_BY_ID["file.open"].implemented_actions) == {
        "read", "write", "append", "execute", "opath",
    }
    assert "read_mem" in ATTACK_TOOL_BY_ID["process.procfs"].implemented_actions


def test_agent_exposure_is_a_subset_of_live_pass_actions() -> None:
    passed = validated_actions.validated_action_names()
    exposed = {
        f"{definition.id}.{action}"
        for definition in IMPLEMENTED_ATTACK_TOOLS.values()
        for action in definition.implemented_actions
    }

    assert len(passed) == 378
    assert exposed
    assert exposed <= passed
    assert not (exposed & validated_actions.NON_PASS_ACTIONS)
    assert validated_actions.validation_provenance()["source_verified"] is True


def test_validation_provenance_fails_closed_on_source_drift(monkeypatch) -> None:
    monkeypatch.setattr(
        validated_actions,
        "tools_source_sha256",
        lambda: "sha256:stale",
    )

    assert validated_actions.validated_action_names() == frozenset()


def test_tool_policy_rejects_raw_command_and_non_pass_action() -> None:
    with pytest.raises(ValueError, match="Raw command"):
        validate_attack_tool_call(
            "file.content",
            "write",
            "target-canary",
            {"content": "test", "command": "id"},
        )
    with pytest.raises(ValueError, match="validated Agent registry"):
        validate_attack_tool_call(
            "memory.lock", "hugepage", "executor-self", {}
        )


def test_readonly_team_contract_actions_are_registered_for_runtime() -> None:
    assert validate_attack_tool_call("file.open", "read", "target-canary", {}) == {}
    assert validate_attack_tool_call(
        "process.procfs", "read_mem", "executor-self", {}
    ) == {}


def test_model_only_receives_team_contract_actions_for_matching_boundary() -> None:
    allowed = tool_schemas_for_boundary(TRUST_BOUNDARIES[0])
    disallowed = tool_schemas_for_boundary(TRUST_BOUNDARIES[1])

    assert {item["function"]["name"] for item in allowed} == {
        ATTACK_FUNCTION_NAME, RECON_FUNCTION_NAME,
    }
    assert {item["function"]["name"] for item in disallowed} == {
        ATTACK_FUNCTION_NAME, RECON_FUNCTION_NAME,
    }
    attack = next(
        item for item in allowed if item["function"]["name"] == ATTACK_FUNCTION_NAME
    )
    recon = next(
        item for item in allowed if item["function"]["name"] == RECON_FUNCTION_NAME
    )
    assert len(attack["function"]["x-validated-actions"]) == 378
    assert len(recon["function"]["x-recon-tools"]) == 113


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
                                            "name": ATTACK_FUNCTION_NAME,
                                            "arguments": {
                                                "tool_id": "file.content",
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

    with pytest.raises(ValueError, match="허용되지 않은"):
        gateway.resolve_model(None)


def test_openrouter_hard_timeout_is_independent_from_httpx(monkeypatch, tmp_path) -> None:
    import time

    gateway = ModelGateway(
        Settings(
            openrouter_api_key="test-key",
            openrouter_model="openai/gpt-5-mini",
            allowed_origins=("http://127.0.0.1:5173",),
            runtime_dir=tmp_path,
            openrouter_hard_timeout_seconds=0.02,
        )
    )

    def blocked_post(**_kwargs):
        time.sleep(0.2)
        raise AssertionError("late transport result must not reach the orchestrator")

    monkeypatch.setattr("app.model_gateway.httpx.post", blocked_post)
    started = time.monotonic()
    result = gateway.next_action("{}", TRUST_BOUNDARIES[0])

    assert time.monotonic() - started < 0.15
    assert result.kind == "finish"


def test_model_decision_rejects_schema_bypass_arguments() -> None:
    with pytest.raises(RuntimeError, match="outside the ToolDefinition schema"):
        ModelGateway._validate_decision(
            ATTACK_FUNCTION_NAME,
            {
                "tool_id": "file.content",
                "action": "read",
                "resource_ref": "target-canary",
                "arguments": {"content": "ignored", "reason": "model note"},
            },
        )


def test_model_decision_never_canonicalizes_raw_command_fields() -> None:
    with pytest.raises(RuntimeError, match="Raw command"):
        ModelGateway._validate_decision(
            ATTACK_FUNCTION_NAME,
            {
                "tool_id": "process.procfs",
                "action": "read_cmdline",
                "resource_ref": "executor-self",
                "arguments": {"command": "id"},
            },
        )


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


def test_identity_probe_requires_registered_structured_identity_reference() -> None:
    with pytest.raises(ValueError, match="Required structured"):
        validate_attack_tool_call(
            "privilege.identity_probe", "seteuid", "executor-self", {}
        )
    assert validate_attack_tool_call(
        "privilege.identity_probe",
        "seteuid",
        "executor-self",
        {"euid_ref": "identity-root"},
    ) == {"euid_ref": "identity-root"}
