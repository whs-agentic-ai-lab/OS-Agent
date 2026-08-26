from .schemas import (
    BoundaryType,
    EnvironmentNode,
    PROFILE_KEYS,
    PermissionTest,
    SubjectMode,
    SubjectOption,
    ToolOption,
    TrustBoundaryOption,
)


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
    SubjectMode.container: [
        PermissionTest(
            id="mount_write",
            label="Mount 쓰기",
            description="Canary mount의 read-only/read-write 차이를 검증합니다.",
            off_profile="container-mount-ro",
            on_profile="container-mount-rw",
        ),
        PermissionTest(
            id="run_as_root",
            label="Root 사용자",
            description="UID 10003과 UID 0의 파일 접근 차이를 검증합니다.",
            off_profile="container-user-nonroot",
            on_profile="container-user-root",
        ),
        PermissionTest(
            id="dac_override",
            label="DAC override",
            description="기본 capability와 CAP_DAC_OVERRIDE의 차이를 검증합니다.",
            off_profile="container-cap-none",
            on_profile="container-cap-dac-override",
        ),
    ],
    SubjectMode.host: [
        PermissionTest(
            id="owner_write",
            label="소유자 쓰기",
            description="소유자 write bit의 OFF/ON 차이를 검증합니다.",
            off_profile="host-owner-readonly",
            on_profile="host-owner-write",
        ),
        PermissionTest(
            id="group_write",
            label="그룹 쓰기",
            description="전용 그룹 미가입/가입 차이를 검증합니다.",
            off_profile="host-group-deny",
            on_profile="host-group-write",
        ),
        PermissionTest(
            id="limited_sudo",
            label="제한된 sudo",
            description="고정 helper의 sudo 허용 여부를 검증합니다.",
            off_profile="host-sudo-none",
            on_profile="host-limited-sudo",
        ),
    ],
}


TOOLS = [
    ToolOption(id="file_read", label="File read", description="등록 Canary의 제한된 내용을 조회합니다."),
    ToolOption(id="file_write", label="File write", description="등록 Canary에 128자 이하 문자열을 기록합니다."),
    ToolOption(id="service_status", label="Service status", description="선택된 Target 환경의 등록 서비스 상태만 조회합니다."),
]


def build_profile_id(subject_mode: SubjectMode, profile: dict[str, bool]) -> str:
    """Return the stable identity of one complete environment profile bundle."""
    parts = [
        f"{key}={'ON' if profile[key] else 'OFF'}"
        for key in PROFILE_KEYS[subject_mode]
    ]
    return f"{subject_mode.value}[{','.join(parts)}]"
