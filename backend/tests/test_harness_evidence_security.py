"""Harness and collector Evidence must share the same security boundaries."""

from copy import deepcopy
import json

import pytest

from app.harness.evidence import redact
from app.harness.models import ToolExecution


@pytest.mark.parametrize("argument", [
    "66697273742d686578",
    '"two word fragment"',
    "'single quoted fragment'",
    r'"escaped \" quote fragment"',
    '"truncated fragment' + "\\",
])
def test_harness_masks_indexed_audit_fragments_and_preserves_numeric_metadata(argument):
    prefix = "type=EXECVE msg=audit(1788051601.123:42): argc=3 uid=1000 a2_len=8192 "
    source = {"nested": [{"output": prefix + "a2[107]=" + argument}]}
    original = deepcopy(source)
    result, count = redact(source)
    assert result["nested"][0]["output"] == prefix + "a2[107]=[REDACTED]"
    assert isinstance(count, int) and count > 0
    assert source == original


@pytest.mark.parametrize("key", ["pass\x00word", "to\x00ken", "pass\\u0000word", "pass\\\\u0000word"])
def test_harness_masks_nul_obfuscated_sensitive_keys_without_renaming_keys(key):
    source = {"nested": [{key: "synthetic-nul-key-credential", "benign\x00key": 41,
                          "benign\\u0000key": 42}]}
    result, count = redact(source)
    assert result["nested"][0][key] == "[REDACTED]"
    assert result["nested"][0]["benign\x00key"] == 41
    assert result["nested"][0]["benign\\u0000key"] == 42
    assert count > 0
    assert source["nested"][0][key] == "synthetic-nul-key-credential"


def test_harness_raw_json_and_cli_arrays_use_shared_masking_contract():
    raw = json.dumps({"pass\x00word": "synthetic-json-credential", "value": 17})
    source = {"message": raw, "command": ["curl", "--api-key", "synthetic-cli-credential"]}
    result, count = redact(source)
    assert json.loads(result["message"]) == {"pass\x00word": "[REDACTED]", "value": 17}
    assert result["command"] == ["curl", "--api-key", "[REDACTED]"]
    assert count >= 2
    assert "synthetic-json-credential" not in json.dumps(result)
    assert "synthetic-cli-credential" not in json.dumps(result)


def test_harness_specific_patterns_and_existing_count_contract_are_preserved():
    source = {"api_key": "top-secret", "text": "Bearer another-secret-token"}
    assert redact(source) == ({"api_key": "[REDACTED]", "text": "[REDACTED]"}, 2)
    specific, count = redact({"credential": "private-credential", "private_key": "private-key",
                              "temporary": "ASIA0123456789ABCDEF", "publishable": "pk-0123456789ABCDEF"})
    assert set(specific.values()) == {"[REDACTED]"}
    assert count == 4


def test_harness_security_pass_preserves_execution_and_verification_contract_fields():
    execution = ToolExecution(
        success=True,
        output="type=EXECVE msg=audit(1788051601.123:42): a2[0]=66697273742d686578",
        evidence={
            "runtime_result": {"run_id": "harness-test", "action_id": "action-test",
                               "outcome": "ALLOWED", "changed": True,
                               "before_sha256": "abc", "after_sha256": "def"},
            "reset_required": True,
            "evidence_refs": ["action:action-test:runtime"],
            "verification": {"status": "VERIFIED", "checks": {"matches": True}},
        },
    )
    original = execution.model_dump(mode="json")
    sanitized, count = redact(original)
    reconstructed = ToolExecution.model_validate(sanitized)
    assert reconstructed.success is True
    assert reconstructed.evidence == execution.evidence
    assert reconstructed.output.endswith("a2[0]=[REDACTED]")
    assert count > 0
    assert execution.model_dump(mode="json") == original


def test_harness_does_not_mask_syscall_registers_or_nonsecret_json_values():
    source = {"output": "type=SYSCALL syscall=59 a0=7ffd1234 a1=0 a2=3 uid=1000",
              "values": [False, None, 17, {"status": "ok"}]}
    assert redact(source) == (source, 0)


def test_harness_json_formatting_does_not_count_as_secret_redaction():
    source = {"message": '{"value": 17, "enabled": true}'}
    result, count = redact(source)
    assert json.loads(result["message"]) == json.loads(source["message"])
    assert count == 0
