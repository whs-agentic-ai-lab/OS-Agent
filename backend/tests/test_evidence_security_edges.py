"""Regression coverage for encoded/split audit data and JSONB safety boundaries."""

import copy
import json

import pytest

from app.evidence_security import REDACTED, redact, redact_artifact, redact_text, redact_with_count, validate_json_value


@pytest.mark.parametrize("argument", [
    "766563746f722d666978747572652d736563726574",
    "unquoted-argument-fragment",
    '"quoted two word fragment"',
    "'single quoted fragment'",
    r'"escaped \" quote fragment"',
    r"'escaped \' quote fragment'",
    '"truncated two word fragment',
    '"truncated fragment with dangling escape' + "\\",
    '"fragment with\x00control"',
    '"fragment with escaped' + "\\\n" + 'newline"',
])
def test_indexed_execve_argument_is_masked_without_losing_length_metadata(argument):
    prefix = "type=EXECVE msg=audit(1788051601.123:42): argc=3 uid=1000 a2_len=8192 "
    record = prefix + "a2[107]=" + argument
    expected = prefix + "a2[107]=" + REDACTED
    assert redact_text(record) == expected
    assert redact_artifact(record.encode(), "processes.txt").decode() == expected


def test_all_execve_fragments_are_masked_in_nested_json_strings_without_mutation():
    record = (
        "type=EXECVE msg=audit(1788051601.123:42): argc=3 "
        'a0="curl" a1="--token" a2_len=36 '
        "a2[0]=66697273742d686578 a2[1]=7365636f6e642d686578"
    )
    source = {"nested": [record, json.dumps({"message": record})]}
    original = copy.deepcopy(source)
    result = redact(source)
    assert source == original
    assert "66697273742d686578" not in json.dumps(result)
    assert "7365636f6e642d686578" not in json.dumps(result)
    assert "a2_len=36" in result["nested"][0]
    assert json.loads(result["nested"][1])["message"] == result["nested"][0]


def test_structured_execve_masks_only_argument_fields():
    source = {"type": "EXECVE", "argc": 3, "uid": 1000, "a2_len": 8192,
              "a2[0]": "736563726574", "a2[1]": "second fragment", "a0": "curl"}
    result = redact(source)
    assert result == {**source, "a2[0]": REDACTED, "a2[1]": REDACTED, "a0": REDACTED}
    assert source["a2[0]"] == "736563726574"


def test_syscall_argument_registers_are_not_execve_strings():
    record = "type=SYSCALL msg=audit(1788051601.123:42): syscall=59 a0=7ffd1234 a1=0 a2=3 uid=1000"
    assert redact_text(record) == record
    fields = {"type": "SYSCALL", "syscall": 59, "a0": "7ffd1234", "a1": 0, "a2": 3}
    assert redact(fields) == fields
    assert redact_text("ordinary a2=42 a2_len=8192") == "ordinary a2=42 a2_len=8192"


@pytest.mark.parametrize("prefix", ["", "Aug 31 10:00:00 fixture audit: "])
def test_mixed_audit_records_mask_execve_only_and_are_idempotent(prefix):
    execve = prefix + 'type=EXECVE msg=audit(1788051601.123:42): a0="curl" a2_len=42 a2[0]="private fragment"'
    syscall = prefix + "type=SYSCALL msg=audit(1788051601.123:42): syscall=59 a0=7ffd1234 a1=0 a2=3 uid=1000"
    sanitized = redact_text(execve + "\n" + syscall)
    assert sanitized == (
        prefix + "type=EXECVE msg=audit(1788051601.123:42): a0=[REDACTED] a2_len=42 a2[0]=[REDACTED]\n"
        + syscall
    )
    assert redact_text(sanitized) == sanitized


def test_structured_audit_context_covers_nested_fields_but_not_nested_syscalls():
    source = {"type": "EXECVE", "fields": {"a2[1]": "secret fragment", "a2_len": 42},
              "related": {"type": "SYSCALL", "a0": "7ffd1234", "a1": 0}}
    assert redact(source) == {
        **source, "fields": {"a2[1]": REDACTED, "a2_len": 42},
    }


def test_nul_obfuscated_sensitive_keys_are_masked_before_any_encoding():
    source = {"pass\x00word": "nul-key-credential", "nested": [{"to\x00ken": "nested-credential"}],
              "benign\x00name": 42, "benign\\u0000name": 43}
    result = redact(source)
    assert result["pass\x00word"] == REDACTED
    assert result["nested"][0]["to\x00ken"] == REDACTED
    assert result["benign\x00name"] == 42
    assert result["benign\\u0000name"] == 43
    assert source["pass\x00word"] == "nul-key-credential"


@pytest.mark.parametrize("key", ["pass\\u0000word", "pass\\\\u0000word", "to\\u0000ken"])
def test_escaped_nul_sensitive_keys_cannot_bypass_repeated_redaction(key):
    assert redact({key: "encoded-nul-key-credential"}) == {key: REDACTED}


@pytest.mark.parametrize("value", [{"bad\x00key": "safe"}, {"nested": [{"bad\x00key": "safe"}]},
                                   {"safe": "bad\x00value"}])
def test_api_jsonb_boundary_still_rejects_actual_nul(value):
    with pytest.raises(ValueError, match="Unsupported JSON string"):
        validate_json_value(value, reject_nul=True)


@pytest.mark.parametrize("prefix,credential", [
    ("--authorization ", "Bearer SYNTHETIC_AUTH_SECRET"),
    ("--authorization=", "Bearer SYNTHETIC_AUTH_SECRET"),
    ("--authorization ", "Basic SYNTHETIC_AUTH_SECRET"),
    ("--authorization=", "Basic SYNTHETIC_AUTH_SECRET"),
    ("--proxy-authorization\t", "bEaReR SYNTHETIC_AUTH_SECRET"),
    ("--proxy-authorization=", "Basic SYNTHETIC_AUTH_SECRET"),
    ("--authorization ", '"Bearer SYNTHETIC_AUTH_SECRET"'),
    ("--proxy-authorization=", "'Basic SYNTHETIC_AUTH_SECRET'"),
])
def test_cli_authorization_masks_the_entire_scheme_and_credential(prefix, credential):
    suffix = " --retry 3 status=ok"
    source = "curl " + prefix + credential + suffix
    expected = "curl " + prefix + REDACTED + suffix

    assert redact_text(source) == expected
    assert redact(source) == expected
    assert redact_with_count(source) == (expected, 1)
    assert redact_artifact(source.encode(), "processes.txt").decode() == expected
    assert redact_with_count(expected) == (expected, 0)


@pytest.mark.parametrize("prefix,credential", [
    ("Authorization: ", "Bearer SYNTHETIC_HEADER_SECRET"),
    ("Proxy-Authorization: ", "Basic SYNTHETIC_HEADER_SECRET"),
    ('"Authorization": ', '"Bearer SYNTHETIC_HEADER_SECRET"'),
    ("authorization=", "'Basic SYNTHETIC_HEADER_SECRET'"),
])
def test_authorization_headers_keep_unrelated_suffix_and_count_once(prefix, credential):
    suffix = " status=ok request_id=17"
    source = prefix + credential + suffix
    expected = prefix + REDACTED + suffix

    assert redact_with_count(source) == (expected, 1)
    assert redact_text(source) == expected
    assert redact_with_count(expected) == (expected, 0)


@pytest.mark.parametrize("scheme", ["Bearer", "Basic"])
def test_nested_json_cli_authorization_has_no_leak_or_double_count(scheme):
    command = f"curl --authorization {scheme} SYNTHETIC_NESTED_AUTH_SECRET --retry 3"
    safe_command = "curl --authorization [REDACTED] --retry 3"
    source = {"plain": command, "nested": [{"message": json.dumps({"command": command, "status": "ok"})}],
              "checks": {"success": True}, "attempt": 2}
    original = copy.deepcopy(source)

    result, count = redact_with_count(source)

    assert result["plain"] == safe_command
    assert json.loads(result["nested"][0]["message"]) == {"command": safe_command, "status": "ok"}
    assert result["checks"] == {"success": True}
    assert result["attempt"] == 2
    assert "SYNTHETIC_NESTED_AUTH_SECRET" not in json.dumps(result)
    assert count == 2  # Two credential occurrences, not formatting or regex passes.
    assert redact(source) == result
    assert redact_with_count(result) == (result, 0)
    assert json.loads(redact_artifact(json.dumps(source).encode(), "manifest.json")) == result
    assert source == original


@pytest.mark.parametrize("key,value", [("authorization", True), ("api_token", False), ("environment", True)])
def test_common_sensitive_key_booleans_keep_the_existing_masking_contract(key, value):
    source = {key: value, "success": True}
    expected = {key: REDACTED, "success": True}

    assert redact_with_count(source) == (expected, 1)
    assert redact(source) == expected
    assert redact_with_count(expected) == (expected, 0)
