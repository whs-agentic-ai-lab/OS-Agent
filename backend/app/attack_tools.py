"""Automatic Agent catalog over the validated ToolDefinition registry."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from runtime_agent.validated_actions import NON_PASS_ACTIONS
from runtime_agent.validated_tool_registry import (
    VALIDATED_ACTION_REGISTRY,
    registry_by_tool,
    validate_registered_attack_call,
)


@dataclass(frozen=True)
class AttackToolDefinition:
    id: str
    family: str
    actions: tuple[str, ...]
    description: str
    implemented_actions: tuple[str, ...] = ()

    @property
    def implemented(self) -> bool:
        return bool(self.implemented_actions)


def _definition_catalogue() -> dict[str, list[str]]:
    if not VALIDATED_ACTION_REGISTRY:
        return {}
    catalogue: dict[str, set[str]] = {}
    for registration in VALIDATED_ACTION_REGISTRY.values():
        catalogue.setdefault(registration.tool_id, set()).add(registration.action)
    for name in NON_PASS_ACTIONS:
        tool_id, action = name.rsplit(".", 1)
        catalogue.setdefault(tool_id, set()).add(action)
    return {
        tool_id: sorted(actions) for tool_id, actions in sorted(catalogue.items())
    }


VALIDATED_ACTION_NAMES = frozenset(VALIDATED_ACTION_REGISTRY)
_CATALOGUE = _definition_catalogue()
_REGISTRY_BY_TOOL = registry_by_tool()

ATTACK_TOOL_CATALOG = tuple(
    AttackToolDefinition(
        id=tool_id,
        family=tool_id.split(".", 1)[0],
        actions=tuple(sorted(actions)),
        description="Validated ToolDefinition-backed OS action family.",
        implemented_actions=tuple(
            item.action for item in _REGISTRY_BY_TOOL.get(tool_id, ())
        ),
    )
    for tool_id, actions in sorted(_CATALOGUE.items())
)
ATTACK_TOOL_BY_ID = {definition.id: definition for definition in ATTACK_TOOL_CATALOG}

# "implemented" now means connected through the generic ToolDefinition adapter,
# not a separately handwritten Runtime switch branch.
IMPLEMENTED_ATTACK_TOOLS = {
    definition.id: definition
    for definition in ATTACK_TOOL_CATALOG
    if definition.implemented
}

RESOURCE_REFS: dict[str, frozenset[str]] = {
    tool_id: frozenset(
        resource_ref
        for registration in registrations
        for resource_ref in registration.resource_refs
    )
    for tool_id, registrations in _REGISTRY_BY_TOOL.items()
}


def validate_attack_tool_call(
    tool_id: str,
    action: str,
    resource_ref: str,
    arguments: Any,
    *,
    require_implemented: bool = True,
) -> dict[str, Any]:
    """Validate a generic Agent envelope against the live-PASS registry."""
    del require_implemented  # Non-PASS actions are never exposed in either mode.
    return validate_registered_attack_call(
        tool_id, action, resource_ref, arguments
    )


def attack_exposure_counts() -> dict[str, int]:
    return {
        "inventory_tools": len(ATTACK_TOOL_CATALOG),
        "inventory_actions": sum(len(item.actions) for item in ATTACK_TOOL_CATALOG),
        "agent_tools": len(IMPLEMENTED_ATTACK_TOOLS),
        "agent_actions": len(VALIDATED_ACTION_REGISTRY),
    }
