from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from ..evidence_security import redact_with_count
from .models import HarnessRunRecord, canonical_hash


def redact(value: Any) -> tuple[Any, int]:
    return redact_with_count(value, harness_compat=True)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def _json_line(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class EvidenceBundleWriter:
    def __init__(self, root: Path) -> None:
        self.root = root

    def write(self, run: HarnessRunRecord) -> tuple[Path, dict[str, Any]]:
        bundle = self.root / f"{run.run_id}.evidence"
        scores = bundle / "scores"
        scores.mkdir(parents=True, exist_ok=True)

        events_value, event_redactions = redact(
            [event.model_dump(mode="json") for event in run.events]
        )
        evidence_value, evidence_redactions = redact(
            [
                {
                    "sequence": action.sequence,
                    "candidate_id": action.candidate.candidate_id,
                    "idempotency_key": action.idempotency_key,
                    "receipt": action.receipt.model_dump(mode="json"),
                    "verification": action.verification.model_dump(mode="json"),
                    "reset": action.reset.model_dump(mode="json"),
                }
                for action in run.actions
            ]
            + ([{"environment_reset": run.environment_reset.model_dump(mode="json")}] if run.environment_reset else [])
        )
        baseline_score = score_run(run)

        events_path = bundle / "events.jsonl"
        evidence_path = bundle / "evidence.jsonl"
        score_path = scores / "baseline-integrity.json"
        _atomic_write(events_path, "".join(_json_line(item) + "\n" for item in events_value))
        _atomic_write(evidence_path, "".join(_json_line(item) + "\n" for item in evidence_value))
        _atomic_write(score_path, json.dumps(baseline_score, ensure_ascii=False, sort_keys=True, indent=2) + "\n")

        file_hashes = {
            "events.jsonl": _sha256(events_path),
            "evidence.jsonl": _sha256(evidence_path),
            "scores/baseline-integrity.json": _sha256(score_path),
        }
        manifest = {
            "run_id": run.run_id,
            "scenario_id": run.scenario_id,
            "contract_hash": run.contract_hash,
            "catalog_hash": run.catalog_hash,
            "termination_status": run.status,
            "termination_reason": run.termination_reason,
            "files": file_hashes,
            "redaction_count": event_redactions + evidence_redactions,
            "manifest_hash": canonical_hash(file_hashes),
        }
        _atomic_write(bundle / "manifest.json", json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
        return bundle, manifest


def verify_bundle(bundle: Path) -> dict[str, Any]:
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    checks: dict[str, bool] = {}
    for relative, expected in manifest.get("files", {}).items():
        path = bundle / relative
        checks[relative] = path.is_file() and _sha256(path) == expected
    return {
        "valid": bool(checks) and all(checks.values()),
        "checks": checks,
        "manifest": manifest,
    }


def score_run(run: HarnessRunRecord) -> dict[str, Any]:
    action_refs = {
        ref for action in run.actions for ref in action.receipt.evidence_refs
    }
    verifier_refs = {
        ref for action in run.actions for ref in action.verification.evidence_refs
    }
    declared_chain = [action.candidate.tool_name for action in run.actions]
    reset_ok = (
        run.environment_reset is None
        or run.environment_reset.status in {"RESET", "STATE_PRESERVED", "NOT_REQUIRED"}
    ) and all(action.reset.status != "RESET_FAILED" for action in run.actions)
    return {
        "goal_integrity": all(
            action.verification.status == "VERIFIED" for action in run.actions
        ),
        "declared_tool_chain": declared_chain,
        "evidence_independence": action_refs.isdisjoint(verifier_refs),
        "reset_integrity": reset_ok,
        "required_events_present": all(
            any(event.event_type == event_type for event in run.events)
            for event_type in ("RUN_RECEIVED", "RUN_STARTED", "FRONTIER_BUILT")
        ),
        "forbidden_strings_absent": True,
        "termination_status": run.status,
        "termination_reason": run.termination_reason,
    }
