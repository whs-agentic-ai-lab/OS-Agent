"""Best-effort records for the existing control-backend Docker log stream.

This module never dispatches a tool, verifies it, retries it, or changes the
objects it receives. Vector performs the common Evidence normalization.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import sys
from threading import Lock
from typing import Any, TYPE_CHECKING
from uuid import uuid4

from .evidence_security import redact

if TYPE_CHECKING:
    from .schemas import RuntimeAgentResult
    from .verifiers import VerificationResult


# Leave room for the Docker relay's JSON string escaping and metadata inside
# Vector's existing 262144-byte max_line_bytes limit.
MAX_EMITTED_BYTES = 64 * 1024
_OUTPUT_LOCK = Lock()
_CONTEXT_FIELDS = (
    "run_id", "action_id", "executor_mode", "trust_boundary_id",
    "source_environment", "target_environment", "tool", "action", "resource_ref",
)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _bounded_line(event: dict[str, Any]) -> str:
    line = _json(event)
    original_bytes = len(line.encode("utf-8"))
    if original_bytes + 1 <= MAX_EMITTED_BYTES:
        return line

    # Reduce only the copied, already-redacted log representation. Never alter
    # the actual output or verification checks used by the experiment.
    payload = event["payload"]
    truncation: dict[str, Any] = {
        "code": "event_truncated",
        "original_bytes": original_bytes,
        "truncated_fields": [],
    }
    payload["collection_error"] = truncation
    candidates: list[tuple[int, str, dict[str, Any], str]] = []
    for section in ("tool_result", "verifier_result", "error"):
        value = payload.get(section)
        if isinstance(value, dict):
            for key, field in value.items():
                candidates.append((
                    len(_json(field).encode("utf-8")),
                    f"payload.{section}.{key}", value, key,
                ))
    # IDs normally are short. An invalid oversized producer value must not
    # bypass the bound or become a fabricated/truncated execution identifier.
    for key in _CONTEXT_FIELDS:
        candidates.append((len(_json(event[key]).encode("utf-8")), key, event, key))

    for original_size, path, owner, key in sorted(candidates, key=lambda item: item[0], reverse=True):
        if len(_json(event).encode("utf-8")) + 1 <= MAX_EMITTED_BYTES:
            break
        value = owner[key]
        owner[key] = (
            value[:2048]
            if isinstance(value, str) and len(value) > 2048 and owner is not event
            else None
        )
        truncation["truncated_fields"].append({"field": path, "original_bytes": original_size})
    line = _json(event)
    if len(line.encode("utf-8")) + 1 > MAX_EMITTED_BYTES:
        raise ValueError("Evidence log exceeds the fixed line budget")
    return line


def emit_execution_evidence(
    event_type: str,
    *,
    result: RuntimeAgentResult | None = None,
    verification: VerificationResult | None = None,
    run_id: str | None = None,
    action_id: str | None = None,
    error: Exception | None = None,
    source: str = "control-backend",
) -> None:
    """Emit an existing result, containing all logging failures locally.

    Successful tool attempts and successful verification are deliberately
    different records. Missing IDs stay null; no OS event correlation is
    inferred. The returned result's IDs remain visible even if validation of
    that runtime response subsequently fails.
    """
    try:
        raw_result = (
            result.model_dump(mode="json", exclude={"applied_profile_state", "events"})
            if result is not None else {}
        )
        payload: dict[str, Any] = {}
        if event_type == "TOOL_RESULT":
            payload["tool_result"] = raw_result
        if verification is not None:
            payload["verifier_result"] = {
                "verifier": verification.verifier,
                "status": verification.status,
                "checks": verification.checks,
            }
        if error is not None:
            payload["error"] = {
                "code": "executor_failed",
                "type": type(error).__name__,
                "message": str(error),
            }
        event = {
            "evidence_kind": "executor",
            "event_id": "executor-" + uuid4().hex,
            "occurred_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "source": source,
            "event_type": event_type,
            **{key: raw_result.get(key) for key in _CONTEXT_FIELDS},
            "step_id": None,
            "tool_call_id": None,
            "payload": payload,
        }
        if result is None:
            event["run_id"] = run_id
            event["action_id"] = action_id
        with _OUTPUT_LOCK:
            # Keep the JSON and its newline in one nonempty stream write,
            # including when unrelated application loggers share stdout.
            print(_bounded_line(redact(event)) + "\n", end="", flush=True)
    except Exception:
        # Do not expose exceptions, raw payloads, or secrets from a failed
        # formatter/redactor. stderr is already collected by the Docker relay.
        # A failed output channel cannot be fixed by replaying the experiment.
        try:
            with _OUTPUT_LOCK:
                print(_json({
                    "evidence_kind": "executor",
                    "source": "control-backend",
                    "event_type": "EXECUTOR_ERROR",
                    "run_id": None,
                    "action_id": None,
                    "step_id": None,
                    "tool_call_id": None,
                    "payload": {"collection_error": {"code": "emission_failed"}},
                }) + "\n", end="", file=sys.stderr, flush=True)
        except Exception:
            pass
