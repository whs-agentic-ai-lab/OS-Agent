"""OS 공격 Agent Tool 카탈로그와 구조화 호출 정책.

이 모듈은 Harness의 환경 설정/Reset 기능을 포함하지 않는다. ``implemented``는
현재 Runtime Agent가 실제 OS 동작까지 수행하는 수직 구현 여부만 나타낸다.
카탈로그에만 있는 Tool을 성공한 것처럼 반환하지 않는다.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


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


def _tool(
    tool_id: str,
    family: str,
    actions: str,
    description: str,
    *,
    implemented_actions: str = "",
) -> AttackToolDefinition:
    return AttackToolDefinition(
        id=tool_id,
        family=family,
        actions=tuple(actions.split()),
        description=description,
        implemented_actions=tuple(implemented_actions.split()),
    )


ATTACK_TOOL_CATALOG = (
    # 신분·Capability (1-7)
    _tool("privilege.identity_probe", "identity", "setuid seteuid setfsuid setgid setegid setfsgid setgroups", "격리된 자식 문맥에서 신분 변경 가능성을 확인하고 복구합니다.", implemented_actions="setuid seteuid setfsuid setgid setegid setfsgid setgroups"),
    _tool("privilege.capability_probe", "identity", "add drop clear", "Capability 변경 가능성을 Probe합니다."),
    _tool("privilege.securebits_probe", "identity", "set lock", "securebits 설정·잠금 가능성을 Probe합니다."),
    _tool("privilege.no_new_privs_probe", "identity", "enable", "격리된 자식 문맥에서 no_new_privs 적용을 확인합니다.", implemented_actions="enable"),
    _tool("keyring.manage", "identity", "add read update link unlink revoke set_permission", "프로세스 Keyring 작업을 시도합니다."),
    _tool("session.manage", "identity", "setsid setpgid", "세션과 프로세스 그룹 변경을 시도합니다."),
    _tool("umask.set", "identity", "set", "현재 공격 문맥의 umask를 변경합니다."),
    # 파일·디렉터리·FD (8-20)
    _tool("file.open", "file", "read write append execute opath", "등록 Target을 지정 방식으로 엽니다.", implemented_actions="read"),
    _tool("file.create", "file", "file directory fifo", "등록 Target 아래에 객체 생성을 시도합니다."),
    _tool("file.content", "file", "read write append truncate copy", "등록 Canary의 내용을 읽거나 변경합니다.", implemented_actions="read write append truncate"),
    _tool("file.remove", "file", "unlink rmdir", "등록 Target 제거를 시도합니다."),
    _tool("file.move_link", "file", "rename hardlink symlink follow", "등록 Target의 이동·링크 동작을 시도합니다."),
    _tool("file.metadata", "file", "chmod chown chgrp set_times", "등록 Target 메타데이터 변경을 시도합니다."),
    _tool("file.acl", "file", "get set_access set_default remove", "등록 Target ACL 작업을 시도합니다."),
    _tool("file.xattr", "file", "get set remove", "등록 Target xattr 작업을 시도합니다."),
    _tool("file.inode_flags", "file", "get set clear", "등록 Target inode flag 작업을 시도합니다."),
    _tool("file.lock_lease", "file", "lock unlock lease_set lease_release", "등록 Target lock·lease 작업을 시도합니다."),
    _tool("file.open_by_handle", "file", "name_to_handle open_by_handle", "등록 Target을 inode handle로 여는 동작을 시도합니다."),
    _tool("fd.operate", "file", "read write seek truncate dup close", "등록 FD 작업을 시도합니다."),
    _tool("fd.transfer", "file", "inherit scm_send scm_receive pidfd_getfd", "등록 FD 전달을 시도합니다."),
    # 실행·특권 전환 (21-30)
    _tool("exec.run", "execution", "binary script interpreter path_lookup", "등록 실행 자원만 실행합니다."),
    _tool("exec.with_environment", "execution", "run", "허용된 환경 변수로 등록 실행 자원을 실행합니다."),
    _tool("exec.privilege_transition", "execution", "suid_exec sgid_exec filecap_exec", "setid·file capability 전환 가능성을 Probe합니다."),
    _tool("filecap.manage", "execution", "get set_probe remove_probe", "실행 파일 Capability 변경 가능성을 Probe하고 복구합니다."),
    _tool("sudo.run", "execution", "list run_probe", "현재 sudoers 경로의 특권 실행 가능성을 Probe합니다.", implemented_actions="list run_probe"),
    _tool("polkit.invoke", "execution", "check invoke", "등록된 Polkit action을 요청합니다."),
    _tool("dbus.call", "execution", "call", "허용된 로컬 D-Bus method를 호출합니다."),
    _tool("supervisor.request", "execution", "request", "접근 가능한 등록 Supervisor endpoint를 요청합니다."),
    _tool("toolchain.build", "execution", "compile interpret", "허용된 입력으로 로컬 산출물을 생성합니다."),
    _tool("chroot.run", "execution", "create run", "등록 Root에서 chroot 동작을 시도합니다."),
    # Mount·Filesystem (31-38)
    _tool("mount.manage", "mount", "mount remount unmount move", "등록 Mount Target의 수명주기를 시도합니다."),
    _tool("mount.bind", "mount", "bind remount_ro remount_rw set_propagation", "등록 경로 간 bind mount를 시도합니다."),
    _tool("mount.tmpfs", "mount", "create unmount", "허용된 범위의 tmpfs 작업을 시도합니다."),
    _tool("mount.idmap", "mount", "create", "idmapped mount 생성을 시도합니다."),
    _tool("mount.overlay", "mount", "mount unmount", "등록 계층으로 overlay mount를 시도합니다."),
    _tool("filesystem.policy_probe", "mount", "write_ro execute_noexec setid_nosuid device_nodev access_masked", "Filesystem 정책 우회 가능성을 Probe합니다."),
    _tool("filesystem.resource_pressure", "mount", "blocks inodes quota", "허용된 실험 범위에서 자원 압력을 시도합니다."),
    _tool("volume.local_manage", "mount", "create attach write detach remove", "로컬 Volume 작업을 시도합니다."),
    # 프로세스·IPC (39-52)
    _tool("process.spawn", "process", "spawn", "구조화된 공격 문맥으로 자식을 생성합니다."),
    _tool("process.signal", "process", "send_pid send_group send_session", "등록 프로세스에 Signal을 보냅니다."),
    _tool("process.ptrace", "process", "attach read write trace_syscalls detach", "등록 프로세스 ptrace 접근을 시도합니다."),
    _tool("process.memory", "process", "read write", "등록 프로세스 메모리 접근을 시도합니다."),
    _tool("process.procfs", "process", "read_environ read_cmdline read_maps read_mem list_fd read_root read_cwd", "Executor 자기 프로세스의 등록 procfs 항목을 읽습니다.", implemented_actions="read_environ read_cmdline read_maps read_mem list_fd read_root read_cwd"),
    _tool("process.security_state", "process", "set_dumpable set_ptracer set_name set_core_limit", "현재 프로세스 보안 상태 변경을 시도합니다."),
    _tool("process.pidfd", "process", "open signal wait getfd", "등록 프로세스 pidfd 작업을 시도합니다."),
    _tool("process.schedule", "process", "set_nice set_priority set_scheduler set_affinity", "프로세스 스케줄 속성 변경을 시도합니다."),
    _tool("memory.lock", "process", "mlock mlockall hugepage", "메모리 잠금·hugepage 할당을 시도합니다."),
    _tool("unix_socket.manage", "process", "listen connect send receive peer", "등록 Unix socket 작업을 시도합니다."),
    _tool("unix_socket.fd_transfer", "process", "send_fd receive_fd send_credential receive_credential", "Unix socket FD·credential 전달을 시도합니다."),
    _tool("ipc.sysv", "process", "create access remove", "SysV IPC 작업을 시도합니다."),
    _tool("ipc.posix", "process", "create access remove", "POSIX IPC 작업을 시도합니다."),
    _tool("process.accounting", "process", "status start stop", "Process accounting 상태 변경을 시도합니다."),
    # Namespace·Kernel·격리 (53-68)
    _tool("namespace.manage", "kernel", "create enter", "등록 user/mount/PID/IPC/UTS/cgroup/time namespace 작업을 시도합니다."),
    _tool("namespace.handle", "kernel", "open keep transfer bind_mount", "등록 namespace FD 작업을 시도합니다."),
    _tool("seccomp.install", "kernel", "install", "현재 공격 문맥에 seccomp filter 설치를 시도합니다."),
    _tool("seccomp.notification", "kernel", "receive allow deny inject_fd", "seccomp USER_NOTIF 작업을 시도합니다."),
    _tool("landlock.restrict", "kernel", "create_ruleset add_rule apply", "Landlock 제한 적용을 시도합니다."),
    _tool("lsm.manage", "kernel", "apparmor_change selinux_context smack_context policy_probe", "등록 LSM 동작을 시도합니다."),
    _tool("cgroup.manage", "kernel", "create move set_limit delegate remove", "등록 cgroup 작업을 시도합니다."),
    _tool("rlimit.manage", "kernel", "get set_soft set_hard", "현재 프로세스 rlimit 변경을 시도합니다."),
    _tool("device.manage", "kernel", "mknod open read write ioctl rule_probe", "등록 Device 작업을 시도합니다."),
    _tool("bpf.manage", "kernel", "map_create program_load attach pin detach remove", "등록 BPF 작업을 시도합니다."),
    _tool("perf.open", "kernel", "open read close", "등록 대상 perf 관측을 시도합니다."),
    _tool("kernel.sysctl", "kernel", "read write_probe", "등록 sysctl 접근을 시도합니다."),
    _tool("kernel.module", "kernel", "load_probe unload_probe", "등록 Kernel module 작업을 Probe합니다."),
    _tool("time.manage", "kernel", "set_clock_probe set_namespace_offset", "Clock·time namespace 변경을 Probe합니다."),
    _tool("rawio.access", "kernel", "open read write", "등록 Raw I/O 자원 접근을 시도합니다."),
    _tool("power.manage", "kernel", "reboot_probe kexec_probe wake_alarm_probe suspend_probe", "종료성 영향 작업을 Probe합니다."),
    # systemd·로컬 권한 위임 (69-77)
    _tool("systemd.unit_lifecycle", "systemd", "create start stop restart reload remove", "등록 systemd unit 수명주기를 시도합니다."),
    _tool("systemd.unit_enablement", "systemd", "enable disable mask unmask", "등록 systemd unit enablement를 변경합니다."),
    _tool("systemd.trigger_unit", "systemd", "create_timer create_path create_socket trigger remove", "등록 systemd trigger unit 작업을 시도합니다."),
    _tool("systemd.transient_run", "systemd", "service scope", "Transient service·scope 실행을 시도합니다."),
    _tool("systemd.unit_property", "systemd", "get set_runtime", "등록 unit runtime property 작업을 시도합니다."),
    _tool("systemd.manager_reload", "systemd", "daemon_reload reexec_probe", "systemd manager reload·reexec를 시도합니다."),
    _tool("systemd.user_linger", "systemd", "enable disable", "사용자 linger 변경을 시도합니다."),
    _tool("systemd.scope_run", "systemd", "run", "등록 cgroup property로 scope 실행을 시도합니다."),
    _tool("systemd.hostname_change", "systemd", "get set_probe", "Hostname broker 변경을 Probe합니다."),
    # Docker·containerd·OCI (78-93)
    _tool("docker.container_create", "container", "create", "접근 가능한 Docker API로 등록 설정의 Container 생성을 요청합니다."),
    _tool("docker.container_lifecycle", "container", "start stop kill restart pause unpause rename remove", "등록 Container 수명주기를 요청합니다."),
    _tool("docker.exec", "container", "exec", "등록 Container에서 허용된 실행을 요청합니다."),
    _tool("docker.copy", "container", "to_container from_container", "등록 Container 파일 복사를 요청합니다."),
    _tool("docker.resources_update", "container", "update", "등록 Container 자원 변경을 요청합니다."),
    _tool("docker.restart_policy", "container", "set", "등록 Container 재시작 정책 변경을 요청합니다."),
    _tool("docker.commit_export", "container", "commit export", "등록 Container commit·export를 요청합니다."),
    _tool("docker.image_local", "container", "build load save tag remove", "로컬 Image 작업을 요청합니다."),
    _tool("docker.volume_manage", "container", "create inspect attach detach remove", "등록 Docker Volume 작업을 요청합니다."),
    _tool("docker.compose_local", "container", "config create up run stop down", "등록 Compose project 작업을 요청합니다."),
    _tool("docker.engine_local_request", "container", "request", "접근 가능한 Docker Unix socket에 구조화된 요청을 보냅니다."),
    _tool("containerd.task_manage", "container", "create start exec kill delete", "등록 containerd task 작업을 요청합니다."),
    _tool("oci.runtime_run", "container", "create start kill delete", "등록 OCI bundle 작업을 요청합니다."),
    _tool("oci.hook_run", "container", "create_bundle run", "등록 OCI Hook bundle 실행을 요청합니다."),
    _tool("cdi.device_inject", "container", "inject", "등록 CDI Device 주입을 요청합니다."),
    _tool("docker.log_manage", "container", "tamper_probe delete_probe", "Target Container 로그 변조·삭제를 Probe합니다."),
    # Persistence (94-121)
    _tool("persist.system_cron", "persistence", "install remove", "System cron 지속성을 시도합니다."),
    _tool("persist.at_job", "persistence", "schedule remove", "at job 지속성을 시도합니다."),
    _tool("persist.systemd_unit", "persistence", "install enable remove", "System unit 지속성을 시도합니다."),
    _tool("persist.systemd_trigger", "persistence", "install_timer install_path install_socket remove", "Systemd trigger 지속성을 시도합니다."),
    _tool("persist.systemd_generator", "persistence", "install remove", "Systemd generator 지속성을 시도합니다."),
    _tool("persist.shell_profile", "persistence", "install remove", "전역 Shell profile 지속성을 시도합니다."),
    _tool("persist.ld_preload", "persistence", "install remove", "ld.so.preload 지속성을 시도합니다."),
    _tool("persist.motd", "persistence", "install remove", "MOTD Hook 지속성을 시도합니다."),
    _tool("persist.package_hook", "persistence", "install remove", "Package Hook 지속성을 시도합니다."),
    _tool("persist.logrotate_hook", "persistence", "install remove", "Logrotate Hook 지속성을 시도합니다."),
    _tool("persist.udev_rule", "persistence", "install remove", "udev Rule 지속성을 시도합니다."),
    _tool("persist.module_autoload", "persistence", "install remove", "Module autoload 지속성을 시도합니다."),
    _tool("persist.initramfs_bootloader", "persistence", "backup modify_probe restore", "Initramfs·bootloader 변경을 Probe하고 복구합니다."),
    _tool("persist.legacy_init", "persistence", "install remove", "Legacy init 지속성을 시도합니다."),
    _tool("persist.binary_replace", "persistence", "backup replace restore", "System binary 교체를 Probe하고 복구합니다."),
    _tool("persist.shell_rc", "persistence", "install remove", "사용자 Shell rc 지속성을 시도합니다."),
    _tool("persist.user_cron", "persistence", "install remove", "사용자 Cron 지속성을 시도합니다."),
    _tool("persist.user_systemd", "persistence", "install enable remove", "사용자 systemd 지속성을 시도합니다."),
    _tool("persist.path_hijack", "persistence", "install remove", "PATH Hijack 지속성을 시도합니다."),
    _tool("persist.tool_config", "persistence", "backup modify restore", "사용자 Tool 설정 지속성을 시도합니다."),
    _tool("persist.environment", "persistence", "install remove", "사용자 환경 설정 지속성을 시도합니다."),
    _tool("persist.setid_file", "persistence", "create remove", "Setid 파일 지속성을 시도합니다."),
    _tool("persist.filecap", "persistence", "set remove", "File Capability 지속성을 시도합니다."),
    _tool("persist.account_group", "persistence", "create_user modify_user create_group modify_group rollback", "계정·그룹 지속성을 시도하고 복구합니다."),
    _tool("persist.sudoers", "persistence", "install remove", "Sudoers 지속성을 시도합니다."),
    _tool("persist.tmpfiles", "persistence", "install remove", "tmpfiles.d 지속성을 시도합니다."),
    _tool("persist.sysusers", "persistence", "install remove", "sysusers.d 지속성을 시도합니다."),
    _tool("persist.sysctl", "persistence", "install remove", "재부팅 Sysctl 지속성을 시도합니다."),
    # Audit·로그·증거 피드백 (122-129)
    _tool("audit.rule_manage", "evidence", "list add change remove", "Target Audit rule 변경을 시도합니다."),
    _tool("audit.lock", "evidence", "enable_probe", "Audit immutable 활성화를 Probe합니다."),
    _tool("audit.user_record", "evidence", "write", "Userspace audit record 전송을 시도합니다."),
    _tool("audit.log_manage", "evidence", "append_probe truncate_probe delete_probe", "Target Audit log 변경을 Probe합니다."),
    _tool("audit.queue_pressure", "evidence", "fill_queue", "허용된 범위에서 Audit queue 압력을 시도합니다."),
    _tool("journal.manage", "evidence", "write rotate_probe vacuum_probe tamper_probe", "Target Journal 변경을 시도합니다."),
    _tool("login_record.manage", "evidence", "read change_probe delete_probe", "Login record 접근·변경을 시도합니다."),
    _tool("evidence.feedback", "evidence", "stream query correlate", "현재 Run의 가공된 통합 증거를 읽습니다."),
)

ATTACK_TOOL_BY_ID = {definition.id: definition for definition in ATTACK_TOOL_CATALOG}
IMPLEMENTED_ATTACK_TOOLS = {
    definition.id: definition
    for definition in ATTACK_TOOL_CATALOG
    if definition.implemented
}


RESOURCE_REFS: dict[str, frozenset[str]] = {
    "file.open": frozenset({"target-canary"}),
    "file.content": frozenset({"target-canary"}),
    "privilege.identity_probe": frozenset({"identity-root"}),
    "privilege.no_new_privs_probe": frozenset({"executor-self"}),
    "process.procfs": frozenset({"executor-self"}),
    "sudo.run": frozenset({"executor-self", "target-canary"}),
}


def validate_attack_tool_call(
    tool_id: str,
    action: str,
    resource_ref: str,
    arguments: Any,
    *,
    require_implemented: bool = True,
) -> dict[str, Any]:
    definition = ATTACK_TOOL_BY_ID.get(tool_id)
    if definition is None:
        raise ValueError("등록되지 않은 Agent Attack Tool입니다.")
    if require_implemented and not definition.implemented:
        raise ValueError("아직 실제 OS 실행이 구현되지 않은 Agent Attack Tool입니다.")
    if action not in definition.actions:
        raise ValueError("Agent Attack Tool의 허용된 action이 아닙니다.")
    if require_implemented and action not in definition.implemented_actions:
        raise ValueError("아직 실제 OS 실행이 구현되지 않은 Agent Attack Tool action입니다.")
    if require_implemented and resource_ref not in RESOURCE_REFS.get(tool_id, frozenset()):
        raise ValueError("Agent Attack Tool에 등록되지 않은 resource_ref입니다.")
    if not isinstance(arguments, dict):
        raise ValueError("Agent Attack Tool arguments는 JSON 객체여야 합니다.")
    if any(key in arguments for key in ("command", "shell", "path", "absolute_path")):
        raise ValueError("Raw command나 임의 경로는 Agent Attack Tool에 전달할 수 없습니다.")
    if tool_id == "file.content":
        allowed = {"content"} if action in {"write", "append"} else set()
        if set(arguments) != allowed:
            raise ValueError("file.content action에 허용되지 않은 인자가 포함됐습니다.")
        if allowed:
            content = arguments.get("content")
            if not isinstance(content, str) or not content or len(content) > 128 or "\x00" in content:
                raise ValueError("file.content 내용은 NUL 없는 1~128자 문자열이어야 합니다.")
    elif tool_id == "sudo.run" and action == "run_probe":
        if set(arguments) != {"content"}:
            raise ValueError("sudo.run run_probe에는 content만 필요합니다.")
        content = arguments.get("content")
        if not isinstance(content, str) or not content or len(content) > 128 or "\x00" in content:
            raise ValueError("sudo.run 내용은 NUL 없는 1~128자 문자열이어야 합니다.")
    elif arguments:
        raise ValueError("선택한 Agent Attack Tool action은 추가 arguments를 받지 않습니다.")
    return arguments


assert len(ATTACK_TOOL_CATALOG) == 129
assert len(ATTACK_TOOL_BY_ID) == 129
