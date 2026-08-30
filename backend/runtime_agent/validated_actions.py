"""Fail-closed exposure for actions proven by the existing EC2 validation run.

The legacy validation digest hashed checkout bytes. That made an otherwise
identical Git tree fail verification when Git materialised CRLF on Windows.
The canonical digest below hashes normalized Git-style text and relative POSIX
paths, while the manifest inventory is independently checked before exposure.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Any


VALIDATION_RUN_ID = "tool-validation-3bc32759b2a2"
VALIDATION_IMAGE = (
    "078716600800.dkr.ecr.us-east-1.amazonaws.com/"
    "os-agent-test-hanbin-074709-0009-runtime:tool-validation-6c72a31-r45"
)
VALIDATION_IMAGE_DIGEST = (
    "sha256:de40c307b18defb084caa7baee3f34ca6c327adbcc8df7f229bab9369162d0c6"
)
VALIDATION_COUNTS = {"PASS": 378, "UNSUPPORTED_ENV": 3, "INCONCLUSIVE": 2}

# Historical raw-checkout digest recorded by the five-hour validation run.
LEGACY_TOOLS_SOURCE_SHA256 = (
    "sha256:42c76ab03421f7ff79b9e992bbc2b59e9ea2f290882b0c0b87c77d6b5eb14246"
)
# Compatibility name retained for older readers of this module.
EXPECTED_TOOLS_SOURCE_SHA256 = LEGACY_TOOLS_SOURCE_SHA256

# origin/not-verified-tool and origin/main have identical Tool source trees.
CANONICAL_TOOLS_SOURCE_SHA256 = (
    "sha256:70b4e9e62ce442f539e04675c02fc2c6bf5c9401eab478b4e510fa7ffd8f170f"
)
VALIDATION_MANIFEST_INVENTORY_SHA256 = (
    "sha256:e9ca963cb31a3b0bbaf67d3fa56716428058f8ccc9ba1e3dc7fc1496b51ee22d"
)
VALIDATION_ACTION_NAMES_SHA256 = (
    "sha256:401fd7468888192238905ce5d9949416b1de6d737fca38ad2910f1ddbf4ead53"
)
VALIDATION_BRANCH_COMMIT_SHA = "07358c1f45579e6acb79961061d9c9fb67f33a99"
MIGRATION_MAIN_COMMIT_SHA = "fab08a414f372674238693665b5ae5b68b4fc260"

NON_PASS_ACTIONS = frozenset({
    "journal.manage.rotate_probe",
    "journal.manage.vacuum_probe",
    "memory.lock.hugepage",
    "namespace.handle.bind_mount",
    "power.manage.suspend_probe",
})

_MANIFEST_ACTION_FIELDS = (
    "name", "tool", "action", "resource_kind", "argument_schema",
    "required_arguments", "allowed_executors", "allowed_tbs", "code_hash",
)


def _normalized_source_bytes(path: Path) -> bytes:
    """Return Git-style text bytes independent of checkout line endings."""
    return path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def tools_source_sha256(tools_dir: Path | None = None) -> str:
    """Hash every Tool Python source with deterministic relative paths/order."""
    root = tools_dir or Path(__file__).with_name("tools")
    digest = hashlib.sha256()
    paths = sorted(
        (path for path in root.rglob("*.py") if path.is_file()),
        key=lambda item: item.relative_to(root).as_posix(),
    )
    for path in paths:
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(_normalized_source_bytes(path))
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest()


def _default_manifest_path() -> Path | None:
    candidate = Path(__file__).parents[2] / "validation" / "tool-manifest.json"
    if candidate.is_file():
        return candidate
    packaged = Path(__file__).with_name("validated-manifest-fingerprint.json")
    return packaged if packaged.is_file() else None


def _manifest_actions(payload: dict[str, Any]) -> list[dict[str, Any]]:
    tools = payload.get("tools")
    if not isinstance(tools, list):
        raise ValueError("validation manifest tools must be an array")
    actions: list[dict[str, Any]] = []
    for tool in tools:
        if not isinstance(tool, dict) or not isinstance(tool.get("actions"), list):
            raise ValueError("validation manifest tool entry is malformed")
        for action in tool["actions"]:
            if not isinstance(action, dict):
                raise ValueError("validation manifest action entry is malformed")
            actions.append(action)
    return actions


def manifest_inventory_sha256(manifest_path: Path) -> str:
    """Hash validated action contracts while excluding mutable report metadata."""
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    contracts = [
        {key: action.get(key) for key in _MANIFEST_ACTION_FIELDS}
        for action in _manifest_actions(payload)
    ]
    canonical = json.dumps(
        sorted(contracts, key=lambda item: str(item["name"])),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _action_names_sha256(names: frozenset[str] | set[str]) -> str:
    canonical = json.dumps(sorted(names), separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _manifest_catalogue(
    manifest_path: Path | None = None,
) -> tuple[dict[str, list[str]], frozenset[str]]:
    selected = manifest_path if manifest_path is not None else _default_manifest_path()
    if selected is None:
        raise ValueError("validated action manifest is unavailable")
    payload = json.loads(selected.read_text(encoding="utf-8"))
    if payload.get("schema_version") == "validated-manifest-fingerprint-v1":
        raise ValueError("fingerprint manifest does not contain action contracts")
    catalogue: dict[str, list[str]] = {}
    for contract in _manifest_actions(payload):
        tool = contract.get("tool")
        action = contract.get("action")
        if not isinstance(tool, str) or not isinstance(action, str):
            raise ValueError("validation manifest action identity is malformed")
        catalogue.setdefault(tool, []).append(action)
    catalogue = {
        tool: sorted(actions) for tool, actions in sorted(catalogue.items())
    }
    names = frozenset(
        f"{tool}.{action}" for tool, actions in catalogue.items() for action in actions
    )
    return catalogue, names


def _catalogue_action_names() -> tuple[dict[str, list[str]], frozenset[str]]:
    # The ToolDefinition modules intentionally use Linux-only APIs (libc, fcntl,
    # resource, pwd/grp).  The Windows control backend needs only their validated
    # contracts; the actual handlers are imported later by the Linux executor.
    if sys.platform != "linux":
        return _manifest_catalogue()
    from runtime_agent.tools import known_definitions
    catalogue = known_definitions()
    names = frozenset(
        f"{tool}.{action}" for tool, actions in catalogue.items() for action in actions
    )
    return catalogue, names


def _manifest_verification(
    names: frozenset[str], manifest_path: Path | None,
) -> tuple[bool, str | None, str | None]:
    """Verify both the embedded fingerprint and repository manifest when present."""
    names_hash = _action_names_sha256(names)
    if names_hash != VALIDATION_ACTION_NAMES_SHA256:
        return False, None, names_hash
    selected = manifest_path if manifest_path is not None else _default_manifest_path()
    if selected is None:
        return False, None, names_hash
    try:
        payload = json.loads(selected.read_text(encoding="utf-8"))
        if payload.get("schema_version") == "validated-manifest-fingerprint-v1":
            inventory_hash = payload.get("manifest_inventory_sha256")
            verified = (
                inventory_hash == VALIDATION_MANIFEST_INVENTORY_SHA256
                and payload.get("action_names_sha256") == names_hash
                and payload.get("tools") == 129
                and payload.get("actions") == 383
            )
            return verified, str(inventory_hash), names_hash
        inventory_hash = manifest_inventory_sha256(selected)
        manifest_names = frozenset(
            str(action.get("name")) for action in _manifest_actions(payload)
        )
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return False, None, names_hash
    verified = (
        inventory_hash == VALIDATION_MANIFEST_INVENTORY_SHA256
        and manifest_names == names
    )
    return verified, inventory_hash, names_hash


def validated_action_contracts(
    *, verify_source: bool = True, manifest_path: Path | None = None,
) -> tuple[dict[str, Any], ...]:
    """Return verified live-PASS contracts for metadata-only control planes.

    This avoids importing Linux syscall handlers on Windows.  Source, inventory,
    and action-name fingerprints are still checked before any contract is exposed.
    """
    if verify_source and tools_source_sha256() != CANONICAL_TOOLS_SOURCE_SHA256:
        return ()
    selected = manifest_path if manifest_path is not None else _default_manifest_path()
    if selected is None:
        return ()
    try:
        payload = json.loads(selected.read_text(encoding="utf-8"))
        if payload.get("schema_version") == "validated-manifest-fingerprint-v1":
            return ()
        actions = _manifest_actions(payload)
        catalogue, names = _manifest_catalogue(selected)
        manifest_verified, _, _ = _manifest_verification(names, selected)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return ()
    if (
        not manifest_verified
        or len(catalogue) != 129
        or len(names) != 383
        or not NON_PASS_ACTIONS <= names
    ):
        return ()
    passed = names - NON_PASS_ACTIONS
    if len(passed) != VALIDATION_COUNTS["PASS"]:
        return ()
    by_name = {str(action.get("name")): action for action in actions}
    if set(by_name) != names:
        return ()
    return tuple(dict(by_name[name]) for name in sorted(passed))


def validated_action_names(
    *, verify_source: bool = True, manifest_path: Path | None = None,
) -> frozenset[str]:
    """Return the historical live-PASS set, or nothing on provenance drift."""
    if verify_source and tools_source_sha256() != CANONICAL_TOOLS_SOURCE_SHA256:
        return frozenset()
    try:
        catalogue, names = _catalogue_action_names()
    except (ImportError, OSError, RuntimeError, ValueError):
        return frozenset()
    manifest_verified, _, _ = _manifest_verification(names, manifest_path)
    if not manifest_verified:
        return frozenset()
    if len(catalogue) != 129 or len(names) != 383 or not NON_PASS_ACTIONS <= names:
        return frozenset()
    passed = names - NON_PASS_ACTIONS
    return passed if len(passed) == VALIDATION_COUNTS["PASS"] else frozenset()


def validation_provenance(manifest_path: Path | None = None) -> dict[str, object]:
    current_hash = tools_source_sha256()
    try:
        catalogue, names = _catalogue_action_names()
        manifest_verified, manifest_hash, names_hash = _manifest_verification(
            names, manifest_path
        )
    except (ImportError, OSError, RuntimeError, ValueError):
        catalogue, names = {}, frozenset()
        manifest_verified, manifest_hash, names_hash = False, None, None
    source_verified = current_hash == CANONICAL_TOOLS_SOURCE_SHA256
    exposed = validated_action_names(manifest_path=manifest_path)
    return {
        "run_id": VALIDATION_RUN_ID,
        "image": VALIDATION_IMAGE,
        "image_digest": VALIDATION_IMAGE_DIGEST,
        "counts": dict(VALIDATION_COUNTS),
        "legacy_tools_source_sha256": LEGACY_TOOLS_SOURCE_SHA256,
        "canonical_tools_source_sha256": CANONICAL_TOOLS_SOURCE_SHA256,
        "current_tools_source_sha256": current_hash,
        "manifest_inventory_sha256": manifest_hash,
        "expected_manifest_inventory_sha256": VALIDATION_MANIFEST_INVENTORY_SHA256,
        "action_names_sha256": names_hash,
        "source_verified": source_verified and manifest_verified,
        "manifest_verified": manifest_verified,
        "validation_branch_commit_sha": VALIDATION_BRANCH_COMMIT_SHA,
        "migration_main_commit_sha": MIGRATION_MAIN_COMMIT_SHA,
        "inventory_tools": len(catalogue),
        "inventory_actions": len(names),
        "validated_action_count": len(exposed),
        "excluded_actions": sorted(NON_PASS_ACTIONS),
        "migration_reason": (
            "legacy digest depended on checkout CRLF/LF; canonical digest uses "
            "normalized Git text, POSIX relative paths, and deterministic sorting"
        ),
    }
