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


def test_harness_preserves_semantic_booleans_and_counts_masked_values_once():
    source = {"credential_changed": True, "credentials_verified": False,
              "private_key_present": True, "api_token_present": False,
              "checks": {"authorization_applied": True, "secret_matches": False},
              "credential": "sensitive-credential"}
    original = deepcopy(source)
    expected = {**source, "credential": "[REDACTED]"}
    assert redact(source) == (expected, 1)
    assert source == original
    assert redact(expected) == (expected, 0)


def test_harness_mixed_audit_and_json_records_count_only_sensitive_arguments():
    syscall = "type=SYSCALL syscall=59 a0=7ffd1234 a1=0 a2=3 uid=1000"
    source = {
        "output": 'type=EXECVE a0="curl" a2_len=42 a2[0]="secret fragment"\n' + syscall,
        "message": json.dumps({"type": "EXECVE", "argc": 1, "a0": "secret"}),
    }
    sanitized, count = redact(source)
    assert count == 3
    assert sanitized["output"].splitlines()[1] == syscall
    assert json.loads(sanitized["message"])["a0"] == "[REDACTED]"
    assert redact(sanitized) == (sanitized, 0)


@pytest.mark.parametrize("prefix,credential", [
    ("--authorization ", "Bearer SYNTHETIC_HARNESS_AUTH_SECRET"),
    ("--authorization=", "Basic SYNTHETIC_HARNESS_AUTH_SECRET"),
    ("--proxy-authorization=", "Bearer SYNTHETIC_HARNESS_AUTH_SECRET"),
    ("--authorization ", '"Bearer SYNTHETIC_HARNESS_AUTH_SECRET"'),
    ("--proxy-authorization ", "Basic SYNTHETIC_HARNESS_AUTH_SECRET"),
])
def test_harness_cli_authorization_consumes_both_scheme_and_secret(prefix, credential):
    suffix = " --retry 3 status=ok"
    command = "curl " + prefix + credential + suffix
    safe_command = "curl " + prefix + "[REDACTED]" + suffix
    source = {"command": command,
              "message": json.dumps({"command": command, "exit_code": 0}),
              "checks": {"success": True}}
    original = deepcopy(source)

    result, count = redact(source)

    assert result["command"] == safe_command
    assert json.loads(result["message"]) == {"command": safe_command, "exit_code": 0}
    assert result["checks"] == {"success": True}
    assert "SYNTHETIC_HARNESS_AUTH_SECRET" not in json.dumps(result)
    assert count == 2
    assert redact(result) == (result, 0)
    assert source == original


@pytest.mark.parametrize("key", [
    "authorization_header", "api_key_value", "access_key_id", "secret_value",
    "password_hash", "token_payload", "credential_blob", "private_key_pem",
    "prefixCREDENTIALsuffix",
])
def test_harness_retains_legacy_sensitive_key_substring_coverage(key):
    source = {"nested": [{key: "SYNTHETIC_SUFFIX_KEY_SECRET", "safe_label": "visible"}]}
    original = deepcopy(source)
    expected = {"nested": [{key: "[REDACTED]", "safe_label": "visible"}]}

    assert redact(source) == (expected, 1)
    assert redact(expected) == (expected, 0)
    assert source == original


@pytest.mark.parametrize("key,boolean", [
    ("credential_changed", True), ("credentials_verified", False),
    ("private_key_present", True), ("api_token_present", False),
    ("authorization_applied", True), ("secret_matches", False),
    ("handler_token_is_read_only", True), ("credentials_requeried", False),
])
def test_harness_preserves_boolean_checks_but_masks_strings_under_the_same_key(key, boolean):
    source = {"checks": {key: boolean}, "diagnostic": {key: "SYNTHETIC_CHECK_NAME_SECRET"}}
    original = deepcopy(source)
    expected = {"checks": {key: boolean}, "diagnostic": {key: "[REDACTED]"}}

    assert redact(source) == (expected, 1)
    assert redact(expected) == (expected, 0)
    assert source == original


@pytest.mark.parametrize("value", [None, "false", 0, 1, 17, ["SYNTHETIC_LIST_CREDENTIAL"],
                                   {"first": "SYNTHETIC_FIRST_CREDENTIAL", "second": "SYNTHETIC_SECOND_CREDENTIAL"}])
def test_harness_suffix_credentials_mask_nonboolean_values_as_one_field(value):
    source = {"credential_blob": value, "success": False}
    original = deepcopy(source)
    expected = {"credential_blob": "[REDACTED]", "success": False}

    assert redact(source) == (expected, 1)
    assert redact(expected) == (expected, 0)
    assert source == original


@pytest.mark.parametrize("key", ["cred\x00ential_blob", "private\\u0000_key_pem", "sec\\\\x00ret_value"])
def test_harness_nul_suffix_keys_are_masked_in_nested_values_and_json_strings(key):
    source = {"nested": [{key: "SYNTHETIC_NUL_SUFFIX_SECRET", "safe": 41}],
              "message": json.dumps({key: "SYNTHETIC_JSON_SUFFIX_SECRET", "safe": 42})}
    original = deepcopy(source)

    result, count = redact(source)

    assert result["nested"] == [{key: "[REDACTED]", "safe": 41}]
    assert json.loads(result["message"]) == {key: "[REDACTED]", "safe": 42}
    assert count == 2
    assert redact(result) == (result, 0)
    assert "SYNTHETIC_NUL_SUFFIX_SECRET" not in json.dumps(result)
    assert "SYNTHETIC_JSON_SUFFIX_SECRET" not in json.dumps(result)
    assert source == original


def test_harness_json_suffix_credentials_and_semantic_flags_preserve_count_meaning():
    source = {"nested": [{"private_key_pem": "SYNTHETIC_PRIVATE_PEM", "safe": "visible"}],
              "message": json.dumps({"credential_blob": "SYNTHETIC_JSON_CREDENTIAL",
                                     "checks": {"handler_token_is_read_only": True}, "attempt": 3}),
              "already": {"secret_value": "[REDACTED]"}}
    original = deepcopy(source)

    result, count = redact(source)

    assert result["nested"] == [{"private_key_pem": "[REDACTED]", "safe": "visible"}]
    assert json.loads(result["message"]) == {"credential_blob": "[REDACTED]",
                                             "checks": {"handler_token_is_read_only": True}, "attempt": 3}
    assert result["already"] == {"secret_value": "[REDACTED]"}
    assert count == 2  # Existing markers and JSON formatting are not new masking.
    assert redact(result) == (result, 0)
    assert source == original


def test_harness_exact_sensitive_key_booleans_are_still_redacted():
    keys = ["password", "token", "env", "credential", "private_key", "access_key", "authorization"]
    source = {key: index % 2 == 0 for index, key in enumerate(keys)}
    source["success"] = True
    expected = {key: "[REDACTED]" for key in keys}
    expected["success"] = True

    assert redact(source) == (expected, len(keys))
    assert redact(expected) == (expected, 0)
