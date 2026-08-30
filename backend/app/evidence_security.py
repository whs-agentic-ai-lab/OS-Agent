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
_AUTH = re.compile(r"\b(Bearer|Basic)\s+[^\s\"'<>;,]+", re.IGNORECASE)
_ASSIGNMENT = re.compile(
    r"(?P<prefix>(?<![a-z0-9_-])[\"']?" + _KEY
    + r"[\"']?\s*(?:=|:)\s*)"
    + r"(?:\"(?:\\.|[^\"\\])*(?:\"|$)|'(?:\\.|[^'\\])*(?:'|$)|[^\s,;&]+)",
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
_URL_CREDENTIALS = re.compile(r"(https?://)[^\s/@:]+:[^\s/@]+@", re.IGNORECASE)
_COOKIE_HEADER = re.compile(r"(?P<prefix>\b(?:set-cookie|cookie)\s*[:=]\s*)[^\r\n]+", re.IGNORECASE)
_AUDIT_EXEC = re.compile(r"\btype=(?:EXECVE|PROCTITLE)\b")
_AUDIT_ARGUMENT = re.compile(r"\b(?P<key>proctitle|a[0-9]+)=(?:\"[^\"]*\"|'[^']*'|[^\s]+)")
_AUDIT_PROCTITLE = re.compile(r"\bproctitle=(?:\"[^\"]*\"|'[^']*'|[^\s]+)")
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


def redact_text(text: str) -> str:
    """Mask representative credentials in raw messages, errors and command lines."""
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
                return json.dumps(redact(value), ensure_ascii=False, separators=(",", ":"))
    text = _COOKIE_HEADER.sub(lambda match: match.group("prefix") + REDACTED, text)
    text = _AUTH.sub(lambda match: match.group(1) + " " + REDACTED, text)
    text = _URL_CREDENTIALS.sub(lambda match: match.group(1) + REDACTED + "@", text)
    # Invalid/truncated JSON and Python repr messages can still contain a
    # literal argv pair. Do not require a successful JSON parse to redact it.
    text = _CLI_QUOTED_ARGV.sub(lambda match: match.group("prefix") + '"' + REDACTED + '"', text)
    text = _CLI.sub(lambda match: match.group("prefix") + REDACTED, text)
    text = _ASSIGNMENT.sub(lambda match: match.group("prefix") + REDACTED, text)
    # EXECVE arguments can be quoted, split across aN fields or hex encoded.
    # Omit these argument values instead of pretending encoded text is safe;
    # retain the audit record identity, operation, uid and other metadata.
    if _AUDIT_EXEC.search(text):
        text = _AUDIT_ARGUMENT.sub(lambda match: match.group("key") + "=" + REDACTED, text)
    text = _AUDIT_PROCTITLE.sub("proctitle=" + REDACTED, text)
    return _PROVIDER_TOKEN.sub(REDACTED, text)


def redact(value: Any) -> Any:
    """Return an independent JSON-like value with nested credentials masked."""
    if isinstance(value, dict):
        return {
            key: REDACTED if _SENSITIVE_KEY.fullmatch(str(key)) or key == "proctitle" else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        result = []
        previous_secret_flag = False
        for item in value:
            result.append(REDACTED if previous_secret_flag else redact(item))
            previous_secret_flag = isinstance(item, str) and bool(_CLI_FLAG.fullmatch(item))
        return result
    if isinstance(value, str):
        return redact_text(value)
    return value


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
