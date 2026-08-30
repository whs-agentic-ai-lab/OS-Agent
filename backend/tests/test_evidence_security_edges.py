"""Regression coverage for encoded/split audit data and JSONB safety boundaries."""

import copy
import json

import pytest

from app.evidence_security import REDACTED, redact, redact_artifact, redact_text, validate_json_value


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
