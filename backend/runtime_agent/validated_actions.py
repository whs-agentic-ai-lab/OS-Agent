"""Fail-closed Agent exposure for actions proven by the live EC2 validation run."""
from __future__ import annotations

import hashlib
from pathlib import Path


VALIDATION_RUN_ID = "tool-validation-3bc32759b2a2"
VALIDATION_IMAGE = (
    "078716600800.dkr.ecr.us-east-1.amazonaws.com/"
    "os-agent-test-hanbin-074709-0009-runtime:tool-validation-6c72a31-r45"
)
VALIDATION_IMAGE_DIGEST = (
    "sha256:de40c307b18defb084caa7baee3f34ca6c327adbcc8df7f229bab9369162d0c6"
)
VALIDATION_COUNTS = {
    "PASS": 378,
    "UNSUPPORTED_ENV": 3,
    "INCONCLUSIVE": 2,
}
EXPECTED_TOOLS_SOURCE_SHA256 = (
    "sha256:42c76ab03421f7ff79b9e992bbc2b59e9ea2f290882b0c0b87c77d6b5eb14246"
)

NON_PASS_ACTIONS = frozenset({
    "journal.manage.rotate_probe",
    "journal.manage.vacuum_probe",
    "memory.lock.hugepage",
    "namespace.handle.bind_mount",
    "power.manage.suspend_probe",
})


def tools_source_sha256(tools_dir: Path | None = None) -> str:
    root = tools_dir or Path(__file__).with_name("tools")
    digest = hashlib.sha256()
    for path in sorted(root.glob("*.py"), key=lambda item: item.name):
        digest.update(path.name.encode("utf-8") + b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest()


def validated_action_names(*, verify_source: bool = True) -> frozenset[str]:
    """Return the live-PASS set, or nothing when validation provenance is stale."""
    if verify_source and tools_source_sha256() != EXPECTED_TOOLS_SOURCE_SHA256:
        return frozenset()

    from runtime_agent.tools import known_definitions

    catalogue = known_definitions()
    names = frozenset(
        f"{tool}.{action}"
        for tool, actions in catalogue.items()
        for action in actions
    )
    if len(catalogue) != 129 or len(names) != 383:
        return frozenset()
    if not NON_PASS_ACTIONS <= names:
        return frozenset()
    passed = names - NON_PASS_ACTIONS
    return passed if len(passed) == VALIDATION_COUNTS["PASS"] else frozenset()


def validation_provenance() -> dict[str, object]:
    current_hash = tools_source_sha256()
    exposed = validated_action_names()
    return {
        "run_id": VALIDATION_RUN_ID,
        "image": VALIDATION_IMAGE,
        "image_digest": VALIDATION_IMAGE_DIGEST,
        "counts": dict(VALIDATION_COUNTS),
        "expected_tools_source_sha256": EXPECTED_TOOLS_SOURCE_SHA256,
        "current_tools_source_sha256": current_hash,
        "source_verified": current_hash == EXPECTED_TOOLS_SOURCE_SHA256,
        "validated_action_count": len(exposed),
        "excluded_actions": sorted(NON_PASS_ACTIONS),
    }
