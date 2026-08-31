"""Small, shared redaction rules for the existing Evidence producers and API.

These functions never mutate a caller's result/verifier objects. They do not read
files, consult credentials, or change the execution of an experiment.
"""

import json
import math
import re
from typing import Any


REDACTED = "[REDACTED]"
ARTIFACT_FILENAMES = frozenset({
    "timestamp_utc.txt", "boot_id.txt", "journal_cursor.txt", "audit_status.txt",
    "processes.txt", "listeners.txt", "identity.txt", "target_processes.txt",
    "container_inspect.json", "container_processes.txt", "container_diff.txt",
    "files.sha256", "files.metadata", "diff-from-before.txt", "manifest.json",
    "artifact-sha256.txt",
})

_KEY = (
    r"(?:(?:set[-_]?)?cookie|[a-z0-9_-]{0,96}authorization|[a-z0-9_-]{0,96}(?:password|passwd|pwd)|"
    r"[a-z0-9_-]{0,96}api[-_]?key|[a-z0-9_-]{0,96}token|[a-z0-9_-]{0,96}secret(?:[-_]?key)?|"
    r"supabase[-_]?(?:service[-_]?role[-_]?key|secret[-_]?key)|"
    r"aws[-_]?(?:access[-_]?key[-_]?id|secret[-_]?access[-_]?key|session[-_]?token))"
)
_SENSITIVE_KEY = re.compile(r"^(?:" + _KEY + r"|env|environment)$", re.IGNORECASE)
_HARNESS_SENSITIVE_KEY = re.compile(
    r"^[a-z0-9_-]{0,96}(?:credentials?|private[-_]?key|access[-_]?key)$",
    re.IGNORECASE,
)
_NUL_IN_KEY = re.compile(r"\x00|\\+(?:u0000|x00)", re.IGNORECASE)
_AUTH = re.compile(r"\b(Bearer|Basic)\s+[^\s\"'<>;,]+", re.IGNORECASE)
_ASSIGNMENT = re.compile(
    r"(?P<prefix>(?<![a-z0-9_-])[\"']?" + _KEY
    + r"[\"']?\s*(?:=|:)\s*)"
    + r"(?:\"(?:\\.|[^\"\\])*(?:\"|$)|'(?:\\.|[^'\\])*(?:'|$)|"
    + r"(?:Bearer|Basic)\s+[^\s\"'<>;,]+|[^\s,;&]+)",
    re.IGNORECASE,
)
_CLI = re.compile(
    r"(?P<prefix>--" + _KEY + r"(?:=|\s+))"
    + r"(?:\"(?:\\.|[^\"\\])*(?:\"|$)|'(?:\\.|[^'\\])*(?:'|$)|[^\s]+)",
    re.IGNORECASE,
)
_CLI_FLAG = re.compile(r"^--" + _KEY + r"$", re.IGNORECASE)
_CLI_QUOTED_ARGV = re.compile(
    r"(?P<prefix>[\"']--" + _KEY + r"[\"']\s*,\s*)"
    + r"(?:\"(?:\\.|[^\"\\])*(?:\"|$)|'(?:\\.|[^'\\])*(?:'|$))",
    re.IGNORECASE,
)
_PROVIDER_TOKEN = re.compile(
    r"\b(?:sk-(?:proj-|or-v1-)?[A-Za-z0-9_-]{12,}|"
    r"sb_secret_[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,}|"
    r"github_pat_[A-Za-z0-9_]{12,}|AKIA[A-Z0-9]{16}|"
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b"
)
_HARNESS_PROVIDER_TOKEN = re.compile(r"\b(?:ASIA[A-Z0-9]{16}|pk-[A-Za-z0-9_-]{16,})\b")
_URL_CREDENTIALS = re.compile(r"(https?://)[^\s/@:]+:[^\s/@]+@", re.IGNORECASE)
_COOKIE_HEADER = re.compile(r"(?P<prefix>\b(?:set-cookie|cookie)\s*[:=]\s*)[^\r\n]+", re.IGNORECASE)
# Restrict aN masking to the matching audit record. A capture can contain both
# EXECVE strings and SYSCALL numeric registers, including on adjacent lines.
_AUDIT_EXEC_RECORD = re.compile(
    r"\btype=(?:EXECVE|PROCTITLE)\b[\s\S]*?"
    r"(?=^[^\r\n]*\btype=[A-Z][A-Z0-9_]*\b|\Z)",
    re.MULTILINE,
)
_AUDIT_ARGUMENT_KEY = re.compile(r"^(?:proctitle|a[0-9]+(?:\[[0-9]+\])?)$")
# Audit fragments may contain escaped quotes/newlines, or end in an incomplete
# quoted value. Consume the entire fragment, including a dangling backslash.
_AUDIT_VALUE = r'''(?:"(?:\\[\s\S]|[^"\\])*(?:"|\\?$)|'(?:\\[\s\S]|[^'\\])*(?:'|\\?$)|[^\s]+)'''
_AUDIT_ARGUMENT = re.compile(
    r"\b(?P<key>proctitle|a[0-9]+(?:\[[0-9]+\])?)=" + _AUDIT_VALUE,
)
_AUDIT_PROCTITLE = re.compile(r"\bproctitle=" + _AUDIT_VALUE)
_LONE_SURROGATE = re.compile(r"[\ud800-\udfff]")


def _reject_constant(_value: str) -> None:
    raise ValueError("Non-finite JSON number")


def parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("Non-finite JSON number")
    return parsed


def validate_json_value(value: Any, *, reject_nul: bool = False) -> None:
    """Reject values that cannot reach UTF-8 JSON/JSONB, without echoing them."""
    if isinstance(value, str):
        if _LONE_SURROGATE.search(value) or (reject_nul and "\x00" in value):
            raise ValueError("Unsupported JSON string")
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Non-finite JSON number")
    elif isinstance(value, dict):
        for key, item in value.items():
            validate_json_value(key, reject_nul=reject_nul)
            validate_json_value(item, reject_nul=reject_nul)
    elif isinstance(value, (list, tuple)):
        for item in value:
            validate_json_value(item, reject_nul=reject_nul)


def _redact_text(text: str, *, harness_compat: bool) -> tuple[str, int]:
    # A Docker message may itself contain JSON. Preserve that string's structure
    # while applying the same nested-key rules used for an ordinary payload.
    if text.lstrip().startswith(("{", "[")):
        try:
            value = json.loads(text, parse_constant=_reject_constant, parse_float=parse_finite_float)
            validate_json_value(value)
        except (ValueError, RecursionError):
            pass
        else:
            if isinstance(value, (dict, list)):
                sanitized, count = _redact_value(value, harness_compat=harness_compat)
                return json.dumps(sanitized, ensure_ascii=False, separators=(",", ":")), count

    count = 0

    def replace(pattern: re.Pattern[str], replacement: Any, source: str) -> str:
        def substitute(match: re.Match[str]) -> str:
            nonlocal count
            sanitized = replacement(match)
            if sanitized != match.group(0):
                count += 1
            return sanitized

        return pattern.sub(substitute, source)

    # Mask audit values before generic CLI patterns can interpret a quoted
    # argument flag and accidentally consume a following audit field.
    text = _AUDIT_EXEC_RECORD.sub(
        lambda record: replace(
            _AUDIT_ARGUMENT,
            lambda match: match.group("key") + "=" + REDACTED,
            record.group(0),
        ),
        text,
    )
    text = replace(_AUDIT_PROCTITLE, lambda _match: "proctitle=" + REDACTED, text)
    text = replace(_COOKIE_HEADER, lambda match: match.group("prefix") + REDACTED, text)
    text = replace(_URL_CREDENTIALS, lambda match: match.group(1) + REDACTED + "@", text)
    # Invalid/truncated JSON and Python repr messages can still contain a
    # literal argv pair. Do not require a successful JSON parse to redact it.
    text = replace(_CLI_QUOTED_ARGV, lambda match: match.group("prefix") + '"' + REDACTED + '"', text)
    text = replace(_CLI, lambda match: match.group("prefix") + REDACTED, text)
    text = replace(_ASSIGNMENT, lambda match: match.group("prefix") + REDACTED, text)
    text = replace(
        _AUTH,
        lambda match: REDACTED if harness_compat and match.group(1).lower() == "bearer"
        else match.group(1) + " " + REDACTED,
        text,
    )
    text = replace(_PROVIDER_TOKEN, lambda _match: REDACTED, text)
    if harness_compat:
        text = replace(_HARNESS_PROVIDER_TOKEN, lambda _match: REDACTED, text)
    return text, count


def _redact_value(
    value: Any, *, harness_compat: bool, audit_arguments: bool = False,
) -> tuple[Any, int]:
    if isinstance(value, dict):
        record_type = value.get("type", value.get("record_type", value.get("audit_type")))
        if isinstance(record_type, str):
            audit_arguments = record_type.upper() in {"EXECVE", "PROCTITLE"}
        result = {}
        count = 0
        for key, item in value.items():
            # Normalize only for classification: stored keys, including benign
            # NUL-containing keys, must not be renamed by the redaction pass.
            normalized_key = _NUL_IN_KEY.sub("", str(key))
            sensitive = (
                _SENSITIVE_KEY.fullmatch(normalized_key)
                or normalized_key == "proctitle"
                or (audit_arguments and _AUDIT_ARGUMENT_KEY.fullmatch(normalized_key))
                or (harness_compat and _HARNESS_SENSITIVE_KEY.fullmatch(normalized_key))
            )
            if sensitive:
                result[key] = REDACTED
                count += int(item != REDACTED)
            else:
                result[key], child_count = _redact_value(
                    item, harness_compat=harness_compat, audit_arguments=audit_arguments,
                )
                count += child_count
        return result, count
    if isinstance(value, (list, tuple)):
        result = []
        count = 0
        previous_secret_flag = False
        for item in value:
            if previous_secret_flag:
                sanitized, child_count = REDACTED, int(item != REDACTED)
            else:
                sanitized, child_count = _redact_value(
                    item, harness_compat=harness_compat, audit_arguments=audit_arguments,
                )
            result.append(sanitized)
            count += child_count
            previous_secret_flag = isinstance(item, str) and bool(
                _CLI_FLAG.fullmatch(_NUL_IN_KEY.sub("", item))
            )
        return result, count
    if isinstance(value, str):
        return _redact_text(value, harness_compat=harness_compat)
    return value, 0


def redact_with_count(value: Any, *, harness_compat: bool = False) -> tuple[Any, int]:
    """Mask independent values and count replacements, not JSON formatting.

    Harness compatibility preserves its additional credential patterns and
    whole-Bearer replacement while sharing the collector's recursive rules.
    """
    return _redact_value(value, harness_compat=harness_compat)


def redact_text(text: str) -> str:
    """Mask representative credentials in raw messages, errors and command lines."""
    return _redact_text(text, harness_compat=False)[0]


def redact(value: Any) -> Any:
    """Return an independent JSON-like value with nested credentials masked."""
    return redact_with_count(value)[0]


def redact_artifact(data: bytes, filename: str) -> bytes:
    """Sanitize an existing allowlisted UTF-8 capture file, without any file I/O."""
    if filename not in ARTIFACT_FILENAMES:
        raise ValueError("Unsupported Evidence artifact")
    text = data.decode("utf-8", errors="strict")
    if filename.endswith(".json"):
        value = json.loads(text, parse_constant=_reject_constant, parse_float=parse_finite_float)
        validate_json_value(value)
        if not isinstance(value, dict) and not (filename == "container_inspect.json" and isinstance(value, list)):
            raise ValueError("Artifact JSON must be an object")
        return (
            json.dumps(redact(value), ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        ).encode("utf-8")
    return redact_text(text).encode("utf-8")
