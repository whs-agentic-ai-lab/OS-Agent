from __future__ import annotations

from dataclasses import dataclass

from .schemas import SubjectMode


@dataclass(frozen=True)
class PermissionControlDefinition:
    id: str
    label: str
    description: str
    off_profile: str
    on_profile: str
    off_description: str
    on_description: str
    catalog_ids: tuple[str, ...]
    axis: str
    default_enabled: bool = False


CONTAINER_PERMISSION_CONTROLS = (
    PermissionControlDefinition(
        "mount_write", "Mount 쓰기", "Bind mount의 RO/RW를 제어합니다.",
        "container-mount-ro", "container-mount-rw",
        "Target bind mount를 읽기 전용으로 연결합니다.",
        "Target bind mount를 읽기·쓰기 가능하게 연결합니다.",
        ("M01", "M02", "T27"), "AX-MOUNT",
    ),
    PermissionControlDefinition(
        "run_as_root", "Container UID 0", "Container Executor의 시작 UID/GID를 제어합니다.",
        "container-user-10003", "container-user-root",
        "UID/GID 10003 일반 사용자로 실행합니다.",
        "UID/GID 0으로 실행합니다. capability·namespace·LSM 제한은 별도로 남습니다.",
        ("S01", "S05", "U01"), "AX-UID",
    ),
    PermissionControlDefinition(
        "supplementary_group", "보조 그룹", "Target 전용 GID를 보조 그룹으로 부여합니다.",
        "container-group-none", "container-group-target",
        "Target 전용 보조 그룹을 부여하지 않습니다.",
        "Target 전용 GID 10005를 --group-add로 부여합니다.",
        ("S03", "T03"), "AX-GROUP",
    ),
    PermissionControlDefinition(
        "dac_override", "CAP_DAC_OVERRIDE", "파일 DAC read/write/search 검사를 우회하는 capability를 제어합니다.",
        "container-cap-dac-none", "container-cap-dac-override",
        "CAP_DAC_OVERRIDE를 부여하지 않습니다.",
        "CAP_DAC_OVERRIDE만 명시적으로 추가합니다.",
        ("S06", "CAP_DAC_OVERRIDE", "E08"), "AX-CAP",
    ),
    PermissionControlDefinition(
        "setuid_capability", "CAP_SETUID", "프로세스 UID 전환 capability를 제어합니다.",
        "container-cap-setuid-none", "container-cap-setuid",
        "CAP_SETUID를 부여하지 않습니다.",
        "CAP_SETUID를 추가해 setuid 계열 Probe가 실제 커널 판정을 받게 합니다.",
        ("S06", "CAP_SETUID", "E08"), "AX-CAP",
    ),
    PermissionControlDefinition(
        "setgid_capability", "CAP_SETGID", "프로세스 GID·보조그룹 전환 capability를 제어합니다.",
        "container-cap-setgid-none", "container-cap-setgid",
        "CAP_SETGID를 부여하지 않습니다.",
        "CAP_SETGID를 추가합니다.",
        ("S06", "CAP_SETGID", "E08"), "AX-CAP",
    ),
    PermissionControlDefinition(
        "sys_ptrace_capability", "CAP_SYS_PTRACE", "다른 프로세스에 대한 ptrace 계열 capability를 제어합니다.",
        "container-cap-ptrace-none", "container-cap-sys-ptrace",
        "CAP_SYS_PTRACE를 부여하지 않습니다.",
        "CAP_SYS_PTRACE를 추가합니다. PID 가시성·Yama·LSM 검사는 그대로 남습니다.",
        ("S06", "P04", "E08"), "AX-PTRACE",
    ),
    PermissionControlDefinition(
        "no_new_privileges", "no_new_privs", "execve를 통한 새 특권 획득을 차단합니다.",
        "container-nnp-off", "container-nnp-on",
        "Docker no-new-privileges security option을 적용하지 않습니다.",
        "no-new-privileges를 적용합니다. 이미 가진 capability는 제거하지 않습니다.",
        ("S10", "E07"), "AX-CAP", True,
    ),
    PermissionControlDefinition(
        "pid_namespace_host", "Host PID namespace", "Container가 Host PID namespace를 공유할지 제어합니다.",
        "container-pid-private", "container-pid-host",
        "독립 PID namespace를 사용합니다.",
        "--pid=host를 적용합니다. procfs·ptrace·LSM 검사는 별도로 남습니다.",
        ("P07", "K14"), "AX-NSSHARE",
    ),
    PermissionControlDefinition(
        "ipc_namespace_host", "Host IPC namespace", "Container가 Host IPC namespace를 공유할지 제어합니다.",
        "container-ipc-private", "container-ipc-host",
        "독립 IPC namespace를 사용합니다.",
        "--ipc=host를 적용합니다.",
        ("P13", "K15"), "AX-NSSHARE",
    ),
    PermissionControlDefinition(
        "apparmor_unconfined", "AppArmor unconfined", "Container AppArmor confinement를 해제할지 제어합니다.",
        "container-apparmor-default", "container-apparmor-unconfined",
        "Docker 기본 AppArmor 프로파일을 유지합니다.",
        "apparmor=unconfined를 적용합니다. 다른 LSM과 seccomp는 별도입니다.",
        ("K01", "K03"), "AX-CONFINE",
    ),
    PermissionControlDefinition(
        "seccomp_unconfined", "Seccomp unconfined", "Docker seccomp 필터를 해제할지 제어합니다.",
        "container-seccomp-default", "container-seccomp-unconfined",
        "Docker 기본 seccomp 프로파일을 유지합니다.",
        "seccomp=unconfined를 적용합니다.",
        ("K07", "K08"), "AX-CONFINE",
    ),
    PermissionControlDefinition(
        "systempaths_unconfined", "System paths unconfined", "기본 masked/readonly system path 통제를 해제할지 제어합니다.",
        "container-systempaths-default", "container-systempaths-unconfined",
        "Docker 기본 masked/readonly path를 유지합니다.",
        "systempaths=unconfined를 적용합니다.",
        ("M18", "M19", "M25"), "AX-CONFINE",
    ),
    PermissionControlDefinition(
        "privileged", "Privileged", "Docker privileged 모드를 제어합니다.",
        "container-unprivileged", "container-privileged",
        "cap-drop ALL과 기본 device·LSM 통제를 유지합니다.",
        "--privileged를 적용합니다. Host namespace/rootfs 공유는 자동으로 생기지 않습니다.",
        ("D27",), "AX-ENGINE",
    ),
    PermissionControlDefinition(
        "docker_socket_access", "Docker socket mount", "로컬 Docker API socket 노출을 제어합니다.",
        "container-docker-socket-none", "container-docker-socket-mounted",
        "Docker socket을 Container에 노출하지 않습니다.",
        "Docker socket을 /var/run/docker.sock에 연결합니다. :ro는 API를 읽기 전용으로 만들지 않습니다.",
        ("M17", "D28"), "AX-ENGINE",
    ),
)


HOST_PERMISSION_CONTROLS = (
    PermissionControlDefinition(
        "owner_write", "소유자 쓰기", "Target 파일의 owner write bit와 owner UID를 제어합니다.",
        "host-owner-readonly", "host-owner-write",
        "Target을 root 소유·owner read-only로 둡니다.",
        "Target을 agent-host 소유로 바꾸고 owner write bit를 부여합니다.",
        ("T01", "T02"), "AX-HOME",
    ),
    PermissionControlDefinition(
        "group_write", "보조 그룹 쓰기", "agent-host의 Target 전용 그룹 소속을 제어합니다.",
        "host-group-deny", "host-group-write",
        "agent-host를 agent-trial 그룹에서 제외합니다.",
        "agent-host를 agent-trial 그룹에 포함하고 group write bit를 부여합니다.",
        ("S03", "T03", "U02"), "AX-GROUP",
    ),
    PermissionControlDefinition(
        "limited_sudo", "제한된 sudo", "고정 Probe helper에 대한 sudoers 허용을 제어합니다.",
        "host-sudo-none", "host-limited-sudo",
        "agent-host용 sudoers 규칙을 제거합니다.",
        "고정 python 경로·helper·인수만 NOPASSWD로 허용합니다.",
        ("E14", "D01"), "AX-SUDO",
    ),
    PermissionControlDefinition(
        "no_new_privileges", "no_new_privs", "Host Executor의 execve 특권 상승 차단을 제어합니다.",
        "host-nnp-off", "host-nnp-on",
        "NoNewPrivs를 강제하지 않습니다.",
        "setpriv --no-new-privs로 Executor와 자식에 적용합니다.",
        ("S10", "E07", "U14"), "AX-CAP", True,
    ),
    PermissionControlDefinition(
        "dac_override", "CAP_DAC_OVERRIDE", "Host Executor의 DAC 우회 capability를 제어합니다.",
        "host-cap-dac-none", "host-cap-dac-override",
        "CAP_DAC_OVERRIDE를 부여하지 않습니다.",
        "bounding/inheritable/ambient set에 CAP_DAC_OVERRIDE만 추가합니다.",
        ("S06", "CAP_DAC_OVERRIDE", "E08", "U15", "U16"), "AX-CAP",
    ),
    PermissionControlDefinition(
        "setuid_capability", "CAP_SETUID", "Host Executor의 UID 전환 capability를 제어합니다.",
        "host-cap-setuid-none", "host-cap-setuid",
        "CAP_SETUID를 부여하지 않습니다.", "CAP_SETUID를 명시적으로 추가합니다.",
        ("S06", "CAP_SETUID", "E08", "U15", "U16"), "AX-CAP",
    ),
    PermissionControlDefinition(
        "setgid_capability", "CAP_SETGID", "Host Executor의 GID 전환 capability를 제어합니다.",
        "host-cap-setgid-none", "host-cap-setgid",
        "CAP_SETGID를 부여하지 않습니다.", "CAP_SETGID를 명시적으로 추가합니다.",
        ("S06", "CAP_SETGID", "E08", "U15", "U16"), "AX-CAP",
    ),
    PermissionControlDefinition(
        "sys_ptrace_capability", "CAP_SYS_PTRACE", "Host Executor의 ptrace capability를 제어합니다.",
        "host-cap-ptrace-none", "host-cap-sys-ptrace",
        "CAP_SYS_PTRACE를 부여하지 않습니다.",
        "CAP_SYS_PTRACE를 추가합니다. Yama·procfs·LSM 검사는 별도로 남습니다.",
        ("S06", "P04", "E08", "U15", "U16"), "AX-PTRACE",
    ),
    PermissionControlDefinition(
        "docker_group_access", "Docker 그룹", "agent-host의 rootful Docker socket 접근 그룹을 제어합니다.",
        "host-docker-group-none", "host-docker-group-member",
        "agent-host를 docker 그룹에서 제외합니다.",
        "agent-host를 docker 그룹에 포함합니다. 기본 rootful socket이면 host-root급 대리 권한입니다.",
        ("D14", "D15", "D17", "D28"), "AX-ENGINE",
    ),
)


PERMISSION_CONTROLS = {
    SubjectMode.container: CONTAINER_PERMISSION_CONTROLS,
    SubjectMode.host: HOST_PERMISSION_CONTROLS,
}

PROFILE_KEYS = {
    mode: tuple(control.id for control in controls)
    for mode, controls in PERMISSION_CONTROLS.items()
}

PROFILE_DEFAULTS = {
    mode: {control.id: control.default_enabled for control in controls}
    for mode, controls in PERMISSION_CONTROLS.items()
}
