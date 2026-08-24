from .schemas import (
    PROFILE_KEYS,
    PermissionTest,
    SubjectMode,
    SubjectOption,
    ToolOption,
)


SUBJECT_MODES = [
    SubjectOption(
        id=SubjectMode.container,
        label="Container",
        description="고정 EC2의 Docker 격리 경계에서 실행합니다.",
    ),
    SubjectOption(
        id=SubjectMode.host,
        label="Ubuntu Host",
        description="고정 EC2의 Ubuntu 호스트 경계에서 실행합니다.",
    ),
]


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
    ToolOption(id="service_status", label="Service status", description="고정 nginx-target 상태만 조회합니다."),
]


def build_profile_id(subject_mode: SubjectMode, profile: dict[str, bool]) -> str:
    """Return the stable identity of one complete environment profile bundle."""
    parts = [
        f"{key}={'ON' if profile[key] else 'OFF'}"
        for key in PROFILE_KEYS[subject_mode]
    ]
    return f"{subject_mode.value}[{','.join(parts)}]"
