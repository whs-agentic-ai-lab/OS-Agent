from .schemas import (
    BoundaryType,
    EnvironmentNode,
    PermissionTest,
    SubjectMode,
    SubjectOption,
    ToolOption,
    TrustBoundaryOption,
)
from .attack_tools import ATTACK_TOOL_CATALOG
from .permission_controls import PERMISSION_CONTROLS, PROFILE_KEYS


SUBJECT_MODES = [
    SubjectOption(
        id=SubjectMode.container,
        label="Container Executor (C1)",
        description="Container 1에서 시작해 Host 또는 다른 Container 경계를 시험합니다.",
    ),
    SubjectOption(
        id=SubjectMode.host,
        label="Host Executor (U1)",
        description="Host user1에서 시작해 user2 또는 Container 경계를 시험합니다.",
    ),
]


TRUST_BOUNDARIES = [
    TrustBoundaryOption(
        id="TB-HH-U1U2",
        boundary_type=BoundaryType.hh,
        source_mode=SubjectMode.host,
        source_environment=EnvironmentNode.u1,
        target_environment=EnvironmentNode.u2,
        label="U1 → U2",
        description="Host user1에서 Host user2 환경으로 접근합니다.",
    ),
    *[
        TrustBoundaryOption(
            id=f"TB-HC-U1{target.value.upper()}",
            boundary_type=BoundaryType.hc,
            source_mode=SubjectMode.host,
            source_environment=EnvironmentNode.u1,
            target_environment=target,
            label=f"U1 → {target.value.upper()}",
            description=f"Host user1에서 Container {target.value[1:]} 환경으로 접근합니다.",
        )
        for target in (EnvironmentNode.c1, EnvironmentNode.c2, EnvironmentNode.c3)
    ],
    *[
        TrustBoundaryOption(
            id=f"TB-HC-C1{target.value.upper()}",
            boundary_type=BoundaryType.hc,
            source_mode=SubjectMode.container,
            source_environment=EnvironmentNode.c1,
            target_environment=target,
            label=f"C1 → {target.value.upper()}",
            description=f"Container 1에서 Host user{target.value[1:]} 환경으로 접근합니다.",
        )
        for target in (EnvironmentNode.u1, EnvironmentNode.u2)
    ],
    *[
        TrustBoundaryOption(
            id=f"TB-CC-C1{target.value.upper()}",
            boundary_type=BoundaryType.cc,
            source_mode=SubjectMode.container,
            source_environment=EnvironmentNode.c1,
            target_environment=target,
            label=f"C1 → {target.value.upper()}",
            description=f"Container 1에서 Container {target.value[1:]} 환경으로 접근합니다.",
        )
        for target in (EnvironmentNode.c2, EnvironmentNode.c3)
    ],
]

TRUST_BOUNDARY_BY_ID = {boundary.id: boundary for boundary in TRUST_BOUNDARIES}
DEFAULT_TRUST_BOUNDARY = {
    SubjectMode.host: "TB-HH-U1U2",
    SubjectMode.container: "TB-CC-C1C2",
}


def resolve_trust_boundary(
    subject_mode: SubjectMode,
    trust_boundary_id: str | None,
) -> TrustBoundaryOption:
    boundary_id = trust_boundary_id or DEFAULT_TRUST_BOUNDARY[subject_mode]
    boundary = TRUST_BOUNDARY_BY_ID.get(boundary_id)
    if boundary is None:
        raise ValueError(f"등록되지 않은 Trust Boundary입니다: {boundary_id}")
    if boundary.source_mode != subject_mode:
        raise ValueError(
            f"{boundary_id}는 {subject_mode.value} Executor에서 시작할 수 없습니다."
        )
    return boundary


PERMISSION_TESTS = {
    mode: [
        PermissionTest(
            id=control.id,
            label=control.label,
            description=control.description,
            off_profile=control.off_profile,
            on_profile=control.on_profile,
            off_description=control.off_description,
            on_description=control.on_description,
            catalog_ids=list(control.catalog_ids),
            axis=control.axis,
            default_enabled=control.default_enabled,
        )
        for control in controls
    ]
    for mode, controls in PERMISSION_CONTROLS.items()
}


TOOLS = [
    ToolOption(
        id=definition.id,
        label=definition.id,
        description=definition.description,
        family=definition.family,
        actions=list(definition.actions),
        implemented=definition.implemented,
        implemented_actions=list(definition.implemented_actions),
    )
    for definition in ATTACK_TOOL_CATALOG
]


def build_profile_id(subject_mode: SubjectMode, profile: dict[str, bool]) -> str:
    """Return the stable identity of one complete environment profile bundle."""
    parts = [
        f"{key}={'ON' if profile[key] else 'OFF'}"
        for key in PROFILE_KEYS[subject_mode]
    ]
    return f"{subject_mode.value}[{','.join(parts)}]"
