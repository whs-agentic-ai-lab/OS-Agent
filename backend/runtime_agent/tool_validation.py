#!/usr/bin/env python3
"""Code-authoritative ToolDefinition inventory and validation artifacts.

This module deliberately imports the runtime ToolDefinition registry instead of the
team Markdown catalogue.  The generated files are the starting checkpoint for live
AWS validation; they never claim AWS certification on the strength of code alone.
"""
from __future__ import annotations

import argparse
import hashlib
import inspect
import json
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from runtime_agent.tools import definition_coverage, definition_manifest
from runtime_agent.tools import base


SCHEMA_VERSION = "tool-validation-v1"
TRUST_BOUNDARIES = (
    "TB-HH-U1U2",
    "TB-HC-U1C1",
    "TB-HC-U1C2",
    "TB-HC-U1C3",
    "TB-HC-C1U1",
    "TB-HC-C1U2",
    "TB-CC-C1C2",
    "TB-CC-C1C3",
)
FAMILY_NAMES = {
    "identity_capability": "Identity-Capability",
    "file_fd": "File-FD",
    "exec_privilege": "Exec-Privilege",
    "mount_filesystem": "Mount-Filesystem",
    "process_ipc": "Process-IPC",
    "namespace_kernel": "Namespace-Kernel",
    "systemd_privilege": "systemd-Privilege",
    "container_docker": "Docker-containerd-OCI",
    "persistence": "Persistence",
    "audit_evidence": "Audit-Evidence",
}

# ``ToolSpec.reversible`` describes rollback obligations, not whether an action
# mutates any state at all.  These non-reversible actions intentionally append
# evidence or refresh a live control plane and therefore must not be presented
# as read-only in the validation manifest.
MUTATION_CLASS_OVERRIDES = {
    "audit.user_record.write": "evidence-write",
    "journal.manage.write": "evidence-write",
    "systemd.manager_reload.daemon_reload": "state-changing",
    "file.lock_lease.lease_release": "state-changing",
    "file.lock_lease.unlock": "state-changing",
}


SEMANTIC_DUPLICATE_REVIEWS: tuple[dict[str, Any], ...] = (
    {
        "candidate": ["process.procfs:read_mem", "process.memory:read"],
        "decision": "KEEP_SEPARATE",
        "mechanism": ["/proc/<pid>/mem file interface", "process_vm_readv syscall"],
        "reason": "The target memory overlaps, but kernel interface and independent verifier observations differ.",
    },
    {
        "candidate": ["process.pidfd:getfd", "fd.transfer:pidfd_getfd"],
        "decision": "KEEP_SEPARATE",
        "mechanism": ["process lifecycle/pidfd control", "FD transfer/object identity"],
        "reason": "Both reach pidfd_getfd, while one verifies process/pidfd lifecycle and the other verifies transferred FD identity and repeatability.",
    },
    {
        "candidate": ["fd.transfer:scm_send/scm_receive", "unix_socket.fd_transfer:send_fd/receive_fd"],
        "decision": "KEEP_SEPARATE",
        "mechanism": ["generic FD transfer catalogue", "Unix socket ancillary-data control plane"],
        "reason": "SCM_RIGHTS overlaps, but the Unix-socket family additionally owns socket/credential semantics and a different verifier scope.",
    },
    {
        "candidate": ["file.open", "file.content", "fd.operate"],
        "decision": "KEEP_SEPARATE",
        "mechanism": ["open/openat semantics", "path content operations", "already-open descriptor operations"],
        "reason": "They operate at different lifecycle layers and verify different kernel objects.",
    },
    {
        "candidate": ["filecap.manage", "persist.filecap"],
        "decision": "KEEP_SEPARATE",
        "mechanism": ["capability execution probe", "persistent filesystem capability installation"],
        "reason": "The xattr mechanism overlaps, but target lifecycle and persistence verifier intent differ.",
    },
    {
        "candidate": ["systemd.unit_*", "persist.systemd_*"],
        "decision": "KEEP_SEPARATE",
        "mechanism": ["systemd runtime/unit control plane", "persistence installation and activation"],
        "reason": "Runtime management and persistence establishment have distinct targets, reset scopes, and verification goals.",
    },
    {
        "candidate": ["kernel.sysctl", "persist.sysctl"],
        "decision": "KEEP_SEPARATE",
        "mechanism": ["live kernel sysctl interface", "persistent sysctl configuration plus reload"],
        "reason": "One validates the live kernel control and the other validates boot-persistent configuration.",
    },
    {
        "candidate": ["general file tools", "audit/journal mutation tools"],
        "decision": "KEEP_SEPARATE",
        "mechanism": ["generic registered path", "audit/journal control and evidence plane"],
        "reason": "Logging tools require subsystem-specific policy, evidence correlation, and terminal reset handling.",
    },
    {
        "candidate": ["docker.*", "containerd.*", "oci.*"],
        "decision": "KEEP_SEPARATE",
        "mechanism": ["Docker Engine API/CLI", "containerd task API", "OCI runtime invocation"],
        "reason": "They target different control planes even when the resulting container effect is similar.",
    },
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _callable_name(function: Callable[..., Any]) -> str:
    return f"{function.__module__}.{function.__qualname__}"


def _source(function: Callable[..., Any]) -> str:
    try:
        return inspect.getsource(function)
    except (OSError, TypeError):
        return _callable_name(function)


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in sorted(value.items())}
    if isinstance(value, (set, frozenset, tuple, list)):
        return [_json_safe(item) for item in sorted(value, key=repr)]
    if isinstance(value, type):
        return value.__name__
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def _code_hash(definition: base.ToolDefinition) -> str:
    payload = {
        "name": definition.name,
        "handler": _source(definition.handler),
        "verifier": _source(definition.verifier),
        "resetter": _source(definition.resetter),
        "spec": _json_safe(asdict(definition.spec)),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _family(definition: base.ToolDefinition) -> str:
    module = definition.handler.__module__.rsplit(".", 1)[-1]
    return FAMILY_NAMES.get(module, module)


def _fixture(definition: base.ToolDefinition) -> dict[str, Any]:
    kind = definition.spec.resource_kind
    fixture_type = {
        "path": "dedicated_path",
        "pid": "supervised_process",
        "fd": "supervised_open_fd",
        "service": "dedicated_systemd_unit",
        "self": "executor_self",
        "none": "none",
        "container": "dedicated_container",
    }.get(kind, f"resource_{kind}")
    return {
        "type": fixture_type,
        "isolated": bool(definition.spec.destructive),
        "full_environment_reset_required": bool(definition.spec.destructive),
    }


def _mutation_class(definition: base.ToolDefinition) -> str:
    if definition.spec.destructive:
        return "destructive"
    if definition.spec.reversible:
        return "state-changing"
    return MUTATION_CLASS_OVERRIDES.get(definition.name, "observational")


def build_inventory() -> dict[str, Any]:
    flat_manifest = {item["name"]: item for item in definition_manifest()}
    actions: list[dict[str, Any]] = []
    grouped: dict[str, dict[str, Any]] = {}
    for key, definition in sorted(base._DEFINITIONS.items()):
        tool_id, action = key
        declared = flat_manifest[definition.name]
        effective_tbs = declared["allowed_tbs"] or list(TRUST_BOUNDARIES)
        item = {
            **declared,
            "family": _family(definition),
            "handler": _callable_name(definition.handler),
            "verifier": _callable_name(definition.verifier),
            "resetter": _callable_name(definition.resetter),
            "required_fixture": _fixture(definition),
            "mutation_class": _mutation_class(definition),
            "effective_allowed_tbs": effective_tbs,
            "code_hash": _code_hash(definition),
            "certification_status": "DEFINED",
        }
        actions.append(item)
        tool = grouped.setdefault(
            tool_id,
            {
                "tool_id": tool_id,
                "family": item["family"],
                "actions": [],
                "certification_status": "DEFINED",
            },
        )
        tool["actions"].append(item)

    coverage = definition_coverage()
    if coverage != {"tools": 129, "actions": 383}:
        raise RuntimeError(f"ToolDefinition coverage mismatch: {coverage}")
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _now(),
        "authority": "not-verified-tool branch runtime_agent.tools ToolDefinition registry",
        "summary": {
            **coverage,
            "mutation_classes": dict(Counter(item["mutation_class"] for item in actions)),
            "families": dict(Counter(item["family"] for item in actions)),
            "certification_status": "DEFINED",
        },
        "tools": [grouped[key] for key in sorted(grouped)],
        "actions": actions,
    }


def build_duplicate_review(inventory: dict[str, Any]) -> dict[str, Any]:
    action_keys = [(item["tool"], item["action"]) for item in inventory["actions"]]
    exact_counts = Counter(action_keys)
    exact_duplicates = [
        {"tool": tool, "action": action, "count": count}
        for (tool, action), count in sorted(exact_counts.items())
        if count > 1
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _now(),
        "exact_tool_action_duplicates": exact_duplicates,
        "exact_duplicate_decision": "PASS" if not exact_duplicates else "REJECT",
        "semantic_reviews": list(SEMANTIC_DUPLICATE_REVIEWS),
    }


def _inventory_markdown(inventory: dict[str, Any]) -> str:
    summary = inventory["summary"]
    lines = [
        "# ToolDefinition inventory",
        "",
        f"- Authority: `{inventory['authority']}`",
        f"- Generated: `{inventory['generated_at']}`",
        f"- Coverage: **{summary['tools']} Tools / {summary['actions']} Actions**",
        f"- Certification: **{summary['certification_status']}** (code presence only)",
        "",
        "| Tool ID | Family | Actions | Status |",
        "| --- | --- | ---: | --- |",
    ]
    for tool in inventory["tools"]:
        lines.append(
            f"| `{tool['tool_id']}` | {tool['family']} | {len(tool['actions'])} | {tool['certification_status']} |"
        )
    lines.append("")
    return "\n".join(lines)


def _duplicates_markdown(review: dict[str, Any]) -> str:
    lines = [
        "# Semantic duplicate review",
        "",
        f"Exact Tool ID + Action duplicates: **{len(review['exact_tool_action_duplicates'])}**",
        "",
        "| Candidate | Decision | Mechanism distinction | Reason |",
        "| --- | --- | --- | --- |",
    ]
    for item in review["semantic_reviews"]:
        lines.append(
            "| "
            + " ↔ ".join(f"`{value}`" for value in item["candidate"])
            + f" | {item['decision']} | {'; '.join(item['mechanism'])} | {item['reason']} |"
        )
    lines.append("")
    return "\n".join(lines)


def write_inventory(output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    inventory = build_inventory()
    duplicates = build_duplicate_review(inventory)
    (output_dir / "tool-manifest.json").write_text(
        json.dumps(inventory, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (output_dir / "tool-manifest.md").write_text(
        _inventory_markdown(inventory), encoding="utf-8"
    )
    (output_dir / "duplicate-review.json").write_text(
        json.dumps(duplicates, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (output_dir / "duplicate-review.md").write_text(
        _duplicates_markdown(duplicates), encoding="utf-8"
    )
    return inventory


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("inventory",))
    parser.add_argument("--output-dir", type=Path, required=True)
    arguments = parser.parse_args()
    inventory = write_inventory(arguments.output_dir)
    print(json.dumps(inventory["summary"], ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
