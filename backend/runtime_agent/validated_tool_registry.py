"""Automatic Agent adapter registry for the historical live-PASS actions.

ToolDefinition remains the execution authority.  This module only builds the
Agent-facing allowlist and validates structured calls before runtime dispatch;
it never replaces or edits a Tool handler.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

from runtime_agent.validated_actions import NON_PASS_ACTIONS, validated_action_names


FORBIDDEN_ARGUMENT_NAMES = frozenset({
    "command", "shell", "path", "absolute_path", "raw_command",
})

_RESOURCE_REFS_BY_KIND: dict[str, frozenset[str]] = {
    "none": frozenset({"executor-self"}),
    "self": frozenset({"executor-self"}),
    "path": frozenset({"target-canary"}),
    "pid": frozenset({"executor-self"}),
    "fd": frozenset({"executor-self"}),
    "service": frozenset({"target-service"}),
    "container": frozenset({"target-container"}),
}
_REGISTERED_REFERENCE_NAMES = frozenset({
    "target-canary", "executor-self", "identity-root",
    "target-service", "target-container",
})


@dataclass(frozen=True)
class ValidatedActionRegistration:
    name: str
    tool_id: str
    action: str
    resource_kind: str
    resource_refs: frozenset[str]
    argument_schema: dict[str, Any]
    required_arguments: frozenset[str]
    allowed_executors: frozenset[str]
    allowed_tbs: frozenset[str]
    destructive: bool
    reversible: bool


def _build_registry() -> dict[str, ValidatedActionRegistration]:
    passed = validated_action_names()
    if not passed:
        return {}
    try:
        from runtime_agent.tools import get_definition, known_definitions
        catalogue = known_definitions()
    except (ImportError, RuntimeError, ValueError):
        return {}
    registrations: dict[str, ValidatedActionRegistration] = {}
    for tool_id, actions in sorted(catalogue.items()):
        for action in sorted(actions):
            name = f"{tool_id}.{action}"
            if name not in passed:
                continue
            definition = get_definition(tool_id, action)
            spec = definition.spec
            resource_refs = _RESOURCE_REFS_BY_KIND.get(spec.resource_kind)
            if resource_refs is None:
                return {}
            registrations[name] = ValidatedActionRegistration(
                name=name,
                tool_id=tool_id,
                action=action,
                resource_kind=spec.resource_kind,
                resource_refs=resource_refs,
                argument_schema=dict(spec.arg_schema),
                required_arguments=frozenset(spec.required_args),
                allowed_executors=frozenset(spec.allowed_executors),
                allowed_tbs=frozenset(spec.allowed_tbs),
                destructive=spec.destructive,
                reversible=spec.reversible,
            )
    if len(registrations) != 378 or NON_PASS_ACTIONS.intersection(registrations):
        return {}
    return registrations


VALIDATED_ACTION_REGISTRY = _build_registry()


def registry_by_tool() -> dict[str, tuple[ValidatedActionRegistration, ...]]:
    grouped: dict[str, list[ValidatedActionRegistration]] = {}
    for registration in VALIDATED_ACTION_REGISTRY.values():
        grouped.setdefault(registration.tool_id, []).append(registration)
    return {
        tool_id: tuple(sorted(items, key=lambda item: item.action))
        for tool_id, items in sorted(grouped.items())
    }


def registered_resource_refs() -> frozenset[str]:
    primary = frozenset(
        resource_ref
        for registration in VALIDATED_ACTION_REGISTRY.values()
        for resource_ref in registration.resource_refs
    )
    return primary | _REGISTERED_REFERENCE_NAMES


def _looks_like_absolute_path(value: str) -> bool:
    return (
        PurePosixPath(value).is_absolute()
        or PureWindowsPath(value).is_absolute()
        or re.match(r"^[A-Za-z]:[\\/]", value) is not None
    )


def _reject_unsafe_value(name: str, value: Any) -> None:
    if name in FORBIDDEN_ARGUMENT_NAMES:
        raise ValueError("Raw command, shell, or arbitrary path arguments are forbidden.")
    if isinstance(value, str) and _looks_like_absolute_path(value):
        raise ValueError("Arbitrary absolute paths are forbidden.")
    if isinstance(value, dict):
        for child_name, child_value in value.items():
            if not isinstance(child_name, str):
                raise ValueError("Argument object keys must be strings.")
            _reject_unsafe_value(child_name, child_value)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_unsafe_value(name, item)


def _matches_type(value: Any, expected: Any) -> bool:
    if isinstance(expected, tuple):
        return any(_matches_type(value, item) for item in expected)
    if expected is int:
        return isinstance(value, int) and not isinstance(value, bool)
    if expected is float:
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if isinstance(expected, type):
        return isinstance(value, expected)
    return True


def validate_registered_attack_call(
    tool_id: str,
    action: str,
    resource_ref: str,
    arguments: Any,
    *,
    executor: str | None = None,
    trust_boundary_id: str | None = None,
) -> dict[str, Any]:
    """Validate one Agent call against the live-PASS ToolDefinition registry."""
    registration = VALIDATED_ACTION_REGISTRY.get(f"{tool_id}.{action}")
    if registration is None:
        raise ValueError("Action is not present in the validated Agent registry.")
    if resource_ref not in registration.resource_refs:
        raise ValueError("resource_ref is not registered for this action.")
    if executor is not None and executor not in registration.allowed_executors:
        raise ValueError("Action is not allowed on this executor.")
    if (
        trust_boundary_id is not None
        and registration.allowed_tbs
        and trust_boundary_id not in registration.allowed_tbs
    ):
        raise ValueError("Action is not allowed on this trust boundary.")
    if not isinstance(arguments, dict):
        raise ValueError("Attack Tool arguments must be a JSON object.")
    for name, value in arguments.items():
        if not isinstance(name, str):
            raise ValueError("Argument object keys must be strings.")
        _reject_unsafe_value(name, value)
        if name.endswith("_ref") and value not in _REGISTERED_REFERENCE_NAMES:
            raise ValueError("Argument references an unregistered resource_ref.")
        if name.endswith("_refs") and (
            not isinstance(value, list)
            or any(item not in _REGISTERED_REFERENCE_NAMES for item in value)
        ):
            raise ValueError("Argument references an unregistered resource_ref.")
    allowed = set(registration.argument_schema) - FORBIDDEN_ARGUMENT_NAMES
    unexpected = set(arguments) - allowed
    if unexpected:
        raise ValueError("Arguments contain fields outside the ToolDefinition schema.")
    required = registration.required_arguments - FORBIDDEN_ARGUMENT_NAMES
    missing = required - set(arguments)
    if missing:
        raise ValueError("Required structured ToolDefinition arguments are missing.")
    for name, value in arguments.items():
        if not _matches_type(value, registration.argument_schema.get(name)):
            raise ValueError(f"Argument has the wrong type: {name}")
    return dict(arguments)


def runtime_arguments(
    registration: ValidatedActionRegistration,
    resource_ref: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    """Adapt the generic Agent envelope to the existing ToolDefinition input."""
    adapted = dict(arguments)
    if registration.resource_kind not in {"none", "self"}:
        adapted["resource_ref"] = resource_ref
    return adapted


def candidate_arguments(
    registration: ValidatedActionRegistration,
) -> dict[str, Any]:
    """Build a bounded structured candidate without commands or raw paths.

    These values let the orchestrator expose every validated action without a
    handwritten 378-entry candidate table. Handlers remain authoritative and
    may policy-block a value that is not meaningful for the active fixture.
    """
    values: dict[str, Any] = {}
    for name in sorted(registration.required_arguments - FORBIDDEN_ARGUMENT_NAMES):
        expected = registration.argument_schema.get(name)
        candidate_type = expected[0] if isinstance(expected, tuple) and expected else expected
        if name.endswith("_ref"):
            if any(token in name for token in ("uid", "gid", "user", "group")):
                values[name] = "identity-root"
            elif "service" in name:
                values[name] = "target-service"
            elif "container" in name or "image" in name:
                values[name] = "target-container"
            else:
                values[name] = "target-canary"
        elif name.endswith("_refs"):
            values[name] = ["identity-root"]
        elif candidate_type is bool:
            values[name] = False
        elif candidate_type is int:
            values[name] = 1
        elif candidate_type is float:
            values[name] = 1.0
        elif candidate_type in {list, tuple}:
            values[name] = []
        elif candidate_type is dict:
            values[name] = {}
        else:
            values[name] = "default"
    return values


def runtime_resource_paths() -> dict[str, str | int]:
    """Resolve only backend-owned logical references; never use Agent paths."""
    canary = os.environ.get("OS_AGENT_CANARY_PATH", "/target/canary.txt")
    fixed: dict[str, str | int] = {
        "target-canary": canary,
        "executor-self": os.getpid(),
        "identity-root": 0,
        "target-service": "os-agent-validation.service",
        "target-container": "os-agent-validation",
    }
    return fixed


def registry_counts() -> dict[str, int]:
    return {
        "tools": len({item.tool_id for item in VALIDATED_ACTION_REGISTRY.values()}),
        "actions": len(VALIDATED_ACTION_REGISTRY),
        "excluded": len(NON_PASS_ACTIONS),
    }
