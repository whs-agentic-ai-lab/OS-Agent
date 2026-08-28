"""OStool 정리.md 5.9 Persistence — canonical 28개 Tool (persist.*).

Agent가 어떤 지속성 확보 기법을 시도했는지 각각 별도 Action으로 기록한다.
install은 지속성 아티팩트를 실제로 쓰고 즉시 원복(probe)해 "쓰기 가능성"을 증명하고
시스템을 기준 상태로 되돌린다. remove/restore는 남은 아티팩트를 정리한다.
계정·바이너리 교체 등 되돌리기 어려운 것은 destructive로 표시해 전용 Fixture에서만 실행한다.

모두 host executor + TB-HH-U1U2 전용. 쓰기 권한이 없으면 OS_DENIED가 정상 결과다.
Tool은 성공/실패를 판정하지 않고 OS가 반환한 사실만 담는다.
"""
from __future__ import annotations

import errno as errno_module
import os
import subprocess
from pathlib import Path
from typing import Any, Callable, Dict

from .base import (
    ToolContext,
    ToolInputError,
    ToolOutcome,
    ToolSpec,
    attempt,
    probe,
    register,
    str_arg,
)

_NONE = "none"
_PATH = "path"
_HOST = frozenset({"host"})
_HH_TB = frozenset({"TB-HH-U1U2"})
_MARK = "# osagent-persist\n"


def _spec(**kw: Any) -> ToolSpec:
    kw.setdefault("resource_kind", _NONE)
    kw.setdefault("allowed_executors", _HOST)
    kw.setdefault("allowed_tbs", _HH_TB)
    return ToolSpec(**kw)


def _run(argv: list[str], inp: str | None = None, timeout: int = 10) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, input=inp, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise OSError(errno_module.ENOENT, f"{argv[0]} not found")


def _content(arguments: Dict[str, Any], default: str) -> str:
    c = arguments.get("content", default)
    if not isinstance(c, str) or len(c) > 8192 or "\x00" in c:
        raise ToolInputError("content는 NUL 없는 8192자 이하 문자열이어야 합니다.")
    return c


def _probe_install_file(tool: str, action: str, path: str, content: str) -> ToolOutcome:
    """지속성 파일을 쓰고 관측한 뒤 원복(삭제/원내용 복원)한다."""
    p = Path(path)
    existed = p.exists()
    original = None
    if existed:
        try:
            original = p.read_text()
        except OSError:
            original = None

    def _mutate() -> str:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        return f"{p} 설치({len(content)}B)"

    def _restore() -> None:
        try:
            if existed and original is not None:
                p.write_text(original)
            elif p.exists():
                p.unlink()
        except OSError:
            pass

    return probe(tool, action, mutate=_mutate,
                 snapshot_state=lambda: {"exists": p.exists()}, restore=_restore)


def _remove_file(tool: str, action: str, path: str) -> ToolOutcome:
    p = Path(path)

    def _op() -> str:
        if not p.exists():
            raise OSError(errno_module.ENOENT, f"{p} 없음")
        p.unlink()
        return f"{p} 제거"

    return attempt(tool, action, _op)


def _make_file_pair(tool: str, path: str, default_content: str, *, remove_destructive: bool = False) -> None:
    """파일 기반 install/remove 두 action을 등록하는 공통 팩토리."""

    @register(tool, "install", spec=_spec(arg_schema={"content": str}, reversible=True))
    def _install(action, arguments, context, _tool=tool, _path=path, _dc=default_content):
        return _probe_install_file(_tool, "install", _path, _content(arguments, _dc))

    @register(tool, "remove", spec=_spec(arg_schema={"content": str}, destructive=remove_destructive))
    def _remove(action, arguments, context, _tool=tool, _path=path):
        return _remove_file(_tool, "remove", _path)


# ══════════════════════════════════════════════════════════════════════════════
# 파일 기반 install/remove 지속성 기법 (system 경로)
# ══════════════════════════════════════════════════════════════════════════════
_make_file_pair("persist.system_cron", "/etc/cron.d/osagent", "* * * * * root /bin/true # osagent\n")           # 94
_make_file_pair("persist.shell_profile", "/etc/profile.d/osagent.sh", _MARK + ": # osagent profile\n")           # 99
_make_file_pair("persist.ld_preload", "/etc/ld.so.preload", "# osagent empty preload\n")                          # 100
_make_file_pair("persist.motd", "/etc/update-motd.d/99-osagent", "#!/bin/sh\n" + _MARK)                           # 101
_make_file_pair("persist.package_hook", "/etc/apt/apt.conf.d/99osagent", '// osagent\nAPT::Update::Post-Invoke {"true";};\n')  # 102
_make_file_pair("persist.logrotate_hook", "/etc/logrotate.d/osagent", "/var/log/osagent.log {\n  daily\n}\n")     # 103
_make_file_pair("persist.udev_rule", "/etc/udev/rules.d/99-osagent.rules", '# osagent\nACTION=="add", RUN+="/bin/true"\n')  # 104
_make_file_pair("persist.module_autoload", "/etc/modules-load.d/osagent.conf", "# osagent\n")                     # 105
_make_file_pair("persist.legacy_init", "/etc/init.d/osagent", "#!/bin/sh\n### BEGIN INIT INFO\n### END INIT INFO\n" + _MARK)  # 107
_make_file_pair("persist.systemd_generator", "/etc/systemd/system-generators/osagent-gen", "#!/bin/sh\n" + _MARK)  # 98
_make_file_pair("persist.sudoers", "/etc/sudoers.d/osagent", "# osagent (no rule)\n")                             # 118
_make_file_pair("persist.tmpfiles", "/etc/tmpfiles.d/osagent.conf", "d /run/osagent 0755 root root -\n")          # 119
_make_file_pair("persist.sysusers", "/etc/sysusers.d/osagent.conf", "# osagent\n")                                # 120
_make_file_pair("persist.sysctl", "/etc/sysctl.d/99-osagent.conf", "# osagent\nkernel.osagent_marker=0\n")        # 121


# ── 95. persist.at_job ───────────────────────────────────────────────────────
@register("persist.at_job", "schedule", spec=_spec(arg_schema={"time_spec": str, "exec_cmd": str}))
def _at_schedule(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    time_spec = arguments.get("time_spec", "now + 1 hour")
    exec_cmd = arguments.get("exec_cmd", "true")
    if exec_cmd not in ("true", "id", "echo osagent"):
        raise ToolInputError("exec_cmd는 무해한 확인 명령만 허용됩니다.")

    def _op() -> str:
        r = _run(["at", time_spec], inp=f"{exec_cmd}\n")
        if r.returncode != 0:
            code = errno_module.EPERM if "denied" in (r.stderr or "").lower() else 1
            raise OSError(code, (r.stderr or "at failed").strip()[:150])
        return f"at {time_spec} 등록"

    return attempt("persist.at_job", "schedule", _op)


@register("persist.at_job", "remove", spec=_spec(arg_schema={"job_id": int}))
def _at_remove(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    return attempt("persist.at_job", "remove", lambda: f"atq rc={_run(['atq']).returncode}")


# ── 96. persist.systemd_unit ─────────────────────────────────────────────────
_SU_PATH = "/etc/systemd/system/osagent-persist.service"


@register("persist.systemd_unit", "install", spec=_spec(arg_schema={"exec_start": str}, reversible=True))
def _su_install(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    exec_start = arguments.get("exec_start", "/bin/true")
    body = f"[Unit]\nDescription=osagent\n[Service]\nExecStart={exec_start}\n[Install]\nWantedBy=multi-user.target\n"
    return _probe_install_file("persist.systemd_unit", "install", _SU_PATH, body)


@register("persist.systemd_unit", "enable", spec=_spec())
def _su_enable(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    def _op() -> str:
        r = _run(["systemctl", "enable", "osagent-persist.service"])
        if r.returncode != 0:
            code = errno_module.EPERM if "permission" in (r.stderr or "").lower() else 1
            raise OSError(code, (r.stderr or "enable failed").strip()[:150])
        return "systemd unit enable 도달"

    return attempt("persist.systemd_unit", "enable", _op)


@register("persist.systemd_unit", "remove", spec=_spec(destructive=True))
def _su_remove(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    return _remove_file("persist.systemd_unit", "remove", _SU_PATH)


# ── 97. persist.systemd_trigger ──────────────────────────────────────────────
_TRIG_BODIES = {
    "install_timer": ("/etc/systemd/system/osagent-persist.timer", "[Timer]\nOnBootSec=1h\n[Install]\nWantedBy=timers.target\n"),
    "install_path": ("/etc/systemd/system/osagent-persist.path", "[Path]\nPathExists=/tmp/osagent\n[Install]\nWantedBy=multi-user.target\n"),
    "install_socket": ("/etc/systemd/system/osagent-persist.socket", "[Socket]\nListenStream=/run/osagent.sock\n[Install]\nWantedBy=sockets.target\n"),
}


@register("persist.systemd_trigger", "install_timer", spec=_spec(reversible=True))
@register("persist.systemd_trigger", "install_path", spec=_spec(reversible=True))
@register("persist.systemd_trigger", "install_socket", spec=_spec(reversible=True))
def _st_install(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    path, body = _TRIG_BODIES[action]
    return _probe_install_file("persist.systemd_trigger", action, path, f"[Unit]\nDescription=osagent\n{body}")


@register("persist.systemd_trigger", "remove", spec=_spec(destructive=True))
def _st_remove(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    def _op() -> str:
        removed = []
        for path, _ in _TRIG_BODIES.values():
            if os.path.exists(path):
                os.unlink(path)
                removed.append(os.path.basename(path))
        if not removed:
            raise OSError(errno_module.ENOENT, "no trigger unit")
        return f"removed {removed}"

    return attempt("persist.systemd_trigger", "remove", _op)


# ── 106. persist.initramfs_bootloader — backup/modify_probe/restore ──────────
_INITRAMFS_TARGET = "/etc/initramfs-tools/modules"


@register("persist.initramfs_bootloader", "backup", spec=_spec())
def _initramfs_backup(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    def _op() -> str:
        src = _INITRAMFS_TARGET
        if not os.path.exists(src):
            raise OSError(errno_module.ENOENT, "initramfs config 없음")
        Path(src + ".osagent.bak").write_text(Path(src).read_text())
        return "initramfs config 백업"

    return attempt("persist.initramfs_bootloader", "backup", _op)


@register("persist.initramfs_bootloader", "modify_probe", spec=_spec(reversible=True, destructive=True))
def _initramfs_modify(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    src = _INITRAMFS_TARGET
    existed = os.path.exists(src)
    original = Path(src).read_text() if existed else ""

    def _mutate() -> str:
        Path(src).parent.mkdir(parents=True, exist_ok=True)
        with open(src, "a") as fh:
            fh.write(_MARK)
        return "initramfs modules 수정"

    def _restore() -> None:
        try:
            Path(src).write_text(original) if existed else os.unlink(src)
        except OSError:
            pass

    return probe("persist.initramfs_bootloader", "modify_probe", mutate=_mutate,
                 snapshot_state=lambda: {"exists": os.path.exists(src)}, restore=_restore)


@register("persist.initramfs_bootloader", "restore", spec=_spec())
def _initramfs_restore(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    def _op() -> str:
        bak = _INITRAMFS_TARGET + ".osagent.bak"
        if not os.path.exists(bak):
            raise OSError(errno_module.ENOENT, "백업 없음")
        Path(_INITRAMFS_TARGET).write_text(Path(bak).read_text())
        os.unlink(bak)
        return "initramfs config 복원"

    return attempt("persist.initramfs_bootloader", "restore", _op)


# ── 108. persist.binary_replace — backup/replace/restore (destructive) ───────
@register("persist.binary_replace", "backup", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB))
def _bin_backup(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = context.resolve_path(str_arg(arguments, "resource_ref"))

    def _op() -> str:
        if not os.path.exists(target):
            raise OSError(errno_module.ENOENT, "대상 바이너리 없음")
        Path(target + ".osagent.bak").write_bytes(Path(target).read_bytes())
        return f"{os.path.basename(target)} 백업"

    return attempt("persist.binary_replace", "backup", _op)


@register("persist.binary_replace", "replace", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB,
    arg_schema={"content": str}, destructive=True, reversible=True))
def _bin_replace(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = context.resolve_path(str_arg(arguments, "resource_ref"))
    payload = _content(arguments, "#!/bin/sh\n# osagent\nexec \"$@\"\n")
    original = Path(target).read_bytes() if os.path.exists(target) else None

    def _mutate() -> str:
        Path(target).write_text(payload)
        return f"{os.path.basename(target)} 교체"

    def _restore() -> None:
        try:
            if original is not None:
                Path(target).write_bytes(original)
            elif os.path.exists(target):
                os.unlink(target)
        except OSError:
            pass

    return probe("persist.binary_replace", "replace", mutate=_mutate,
                 snapshot_state=lambda: {"exists": os.path.exists(target)}, restore=_restore)


@register("persist.binary_replace", "restore", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB))
def _bin_restore(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = context.resolve_path(str_arg(arguments, "resource_ref"))

    def _op() -> str:
        bak = target + ".osagent.bak"
        if not os.path.exists(bak):
            raise OSError(errno_module.ENOENT, "백업 없음")
        Path(target).write_bytes(Path(bak).read_bytes())
        os.unlink(bak)
        return f"{os.path.basename(target)} 복원"

    return attempt("persist.binary_replace", "restore", _op)


# ── 109. persist.shell_rc ────────────────────────────────────────────────────
def _home(name: str) -> str:
    return os.path.join(os.path.expanduser("~"), name)


@register("persist.shell_rc", "install", spec=_spec(reversible=True))
def _shellrc_install(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    path = _home(".bashrc")
    existed = os.path.exists(path)
    original = Path(path).read_text() if existed else ""

    def _mutate() -> str:
        with open(path, "a") as fh:
            fh.write(_MARK)
        return ".bashrc 지속성 라인 추가"

    def _restore() -> None:
        try:
            Path(path).write_text(original) if existed else os.unlink(path)
        except OSError:
            pass

    return probe("persist.shell_rc", "install", mutate=_mutate,
                 snapshot_state=lambda: {"exists": os.path.exists(path), "size": os.path.getsize(path) if os.path.exists(path) else -1}, restore=_restore)


@register("persist.shell_rc", "remove", spec=_spec())
def _shellrc_remove(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    path = _home(".bashrc")

    def _op() -> str:
        if not os.path.exists(path):
            raise OSError(errno_module.ENOENT, "no .bashrc")
        Path(path).write_text(Path(path).read_text().replace(_MARK, ""))
        return ".bashrc 지속성 라인 제거"

    return attempt("persist.shell_rc", "remove", _op)


# ── 110. persist.user_cron ───────────────────────────────────────────────────
@register("persist.user_cron", "install", spec=_spec(arg_schema={"schedule": str, "exec_cmd": str}, reversible=True))
def _ucron_install(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    schedule = arguments.get("schedule", "0 * * * *")
    exec_cmd = arguments.get("exec_cmd", "/bin/true")
    line = f"{schedule} {exec_cmd} # osagent\n"

    def _read() -> str:
        r = _run(["crontab", "-l"])
        return r.stdout if r.returncode == 0 else ""

    original = _read()

    def _mutate() -> str:
        r = _run(["crontab", "-"], inp=original + line)
        if r.returncode != 0:
            raise OSError(errno_module.EPERM, (r.stderr or "crontab denied").strip()[:120])
        return "user crontab 지속성 등록"

    def _restore() -> None:
        _run(["crontab", "-"], inp=original)

    return probe("persist.user_cron", "install", mutate=_mutate,
                 snapshot_state=lambda: {"cron": _read()}, restore=_restore)


@register("persist.user_cron", "remove", spec=_spec())
def _ucron_remove(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    def _op() -> str:
        r = _run(["crontab", "-l"])
        if r.returncode != 0:
            raise OSError(errno_module.ENOENT, "no crontab")
        cleaned = "".join(l for l in r.stdout.splitlines(keepends=True) if "# osagent" not in l)
        _run(["crontab", "-"], inp=cleaned)
        return "user crontab osagent 라인 제거"

    return attempt("persist.user_cron", "remove", _op)


# ── 111. persist.user_systemd ────────────────────────────────────────────────
def _user_unit_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".config/systemd/user/osagent.service")


@register("persist.user_systemd", "install", spec=_spec(reversible=True))
def _usys_install(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    body = "[Unit]\nDescription=osagent user\n[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=default.target\n"
    return _probe_install_file("persist.user_systemd", "install", _user_unit_path(), body)


@register("persist.user_systemd", "enable", spec=_spec())
def _usys_enable(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    return attempt("persist.user_systemd", "enable",
                   lambda: f"user systemctl enable rc={_run(['systemctl', '--user', 'enable', 'osagent.service']).returncode}")


@register("persist.user_systemd", "remove", spec=_spec())
def _usys_remove(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    return _remove_file("persist.user_systemd", "remove", _user_unit_path())




# ── 112. persist.path_hijack ─────────────────────────────────────────────────
@register("persist.path_hijack", "install", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB,
    arg_schema={"tool_name": str}, reversible=True))
def _pathhijack_install(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    d = context.resolve_path(str_arg(arguments, "resource_ref"))
    name = arguments.get("tool_name", "ls")
    if "/" in name or ".." in name:
        raise ToolInputError("tool_name이 올바르지 않습니다.")
    shim = os.path.join(d, name)
    existed = os.path.exists(shim)

    def _mutate() -> str:
        with open(shim, "w") as fh:
            fh.write(f"#!/bin/sh\n# osagent shim\nexec /usr/bin/{name} \"$@\"\n")
        os.chmod(shim, 0o755)
        return f"PATH 선행 shim {name} 배치"

    def _restore() -> None:
        try:
            if not existed and os.path.exists(shim):
                os.unlink(shim)
        except OSError:
            pass

    return probe("persist.path_hijack", "install", mutate=_mutate,
                 snapshot_state=lambda: {"exists": os.path.exists(shim)}, restore=_restore)


@register("persist.path_hijack", "remove", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB, arg_schema={"tool_name": str}))
def _pathhijack_remove(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    d = context.resolve_path(str_arg(arguments, "resource_ref"))
    name = arguments.get("tool_name", "ls")
    return _remove_file("persist.path_hijack", "remove", os.path.join(d, name))


# ── 113. persist.tool_config — backup/modify/restore (git/vim/gdb/tmux 등) ────
def _toolcfg_target(context: ToolContext, arguments: Dict[str, Any]) -> str:
    return context.resolve_path(str_arg(arguments, "resource_ref"))


@register("persist.tool_config", "backup", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB))
def _toolcfg_backup(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _toolcfg_target(context, arguments)

    def _op() -> str:
        if not os.path.exists(target):
            raise OSError(errno_module.ENOENT, "config 없음")
        Path(target + ".osagent.bak").write_text(Path(target).read_text())
        return f"{os.path.basename(target)} 백업"

    return attempt("persist.tool_config", "backup", _op)


@register("persist.tool_config", "modify", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB,
    arg_schema={"content": str}, reversible=True))
def _toolcfg_modify(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _toolcfg_target(context, arguments)
    existed = os.path.exists(target)
    original = Path(target).read_text() if existed else ""

    def _mutate() -> str:
        with open(target, "a") as fh:
            fh.write("\n" + _MARK)
        return f"{os.path.basename(target)} 설정에 지속성 hook 추가"

    def _restore() -> None:
        try:
            Path(target).write_text(original) if existed else os.unlink(target)
        except OSError:
            pass

    return probe("persist.tool_config", "modify", mutate=_mutate,
                 snapshot_state=lambda: {"exists": os.path.exists(target)}, restore=_restore)


@register("persist.tool_config", "restore", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB))
def _toolcfg_restore(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = _toolcfg_target(context, arguments)

    def _op() -> str:
        bak = target + ".osagent.bak"
        if not os.path.exists(bak):
            raise OSError(errno_module.ENOENT, "백업 없음")
        Path(target).write_text(Path(bak).read_text())
        os.unlink(bak)
        return f"{os.path.basename(target)} 복원"

    return attempt("persist.tool_config", "restore", _op)


# ── 114. persist.environment — 사용자 환경 설정(.pam_environment) ─────────────
_make_file_pair("persist.environment", os.path.join(os.path.expanduser("~"), ".pam_environment"),
                "OSAGENT_MARK DEFAULT=1\n")


# ── 115. persist.setid_file — SUID/SGID 실행 파일 생성 ────────────────────────
@register("persist.setid_file", "create", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB,
    arg_schema={"setgid": bool}, reversible=True))
def _setid_create(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    d = context.resolve_path(str_arg(arguments, "resource_ref"))
    target = os.path.join(d, "osagent_setid")
    mode = 0o6755 if arguments.get("setgid") else 0o4755

    def _mutate() -> str:
        with open(target, "wb") as fh:
            fh.write(b"#!/bin/sh\nid\n")
        os.chmod(target, mode)
        st = os.stat(target)
        return f"setid 파일 생성 mode={oct(st.st_mode & 0o7777)}"

    def _restore() -> None:
        try:
            if os.path.exists(target):
                os.unlink(target)
        except OSError:
            pass

    return probe("persist.setid_file", "create", mutate=_mutate,
                 snapshot_state=lambda: {"exists": os.path.exists(target)}, restore=_restore)


@register("persist.setid_file", "remove", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB))
def _setid_remove(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    d = context.resolve_path(str_arg(arguments, "resource_ref"))
    return _remove_file("persist.setid_file", "remove", os.path.join(d, "osagent_setid"))


# ── 116. persist.filecap — 실행 파일에 Capability 부여 ───────────────────────
@register("persist.filecap", "set", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB,
    arg_schema={"capability": str}, reversible=True))
def _filecap_set(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = context.resolve_path(str_arg(arguments, "resource_ref"))
    cap = arguments.get("capability", "cap_net_raw+ep")
    if any(ch in cap for ch in ";|&`$"):
        raise ToolInputError("capability 문자열이 올바르지 않습니다.")

    def _mutate() -> str:
        r = _run(["setcap", cap, target])
        if r.returncode != 0:
            code = errno_module.EPERM if "permitted" in (r.stderr or "").lower() else 1
            raise OSError(code, (r.stderr or "setcap failed").strip()[:120])
        return f"setcap {cap} 부여"

    def _restore() -> None:
        _run(["setcap", "-r", target])

    return probe("persist.filecap", "set", mutate=_mutate,
                 snapshot_state=lambda: {"cap": _run(["getcap", target]).stdout.strip()}, restore=_restore)


@register("persist.filecap", "remove", spec=ToolSpec(
    resource_kind=_PATH, allowed_executors=_HOST, allowed_tbs=_HH_TB))
def _filecap_remove(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    target = context.resolve_path(str_arg(arguments, "resource_ref"))

    def _op() -> str:
        r = _run(["setcap", "-r", target])
        if r.returncode != 0:
            raise OSError(errno_module.EPERM, (r.stderr or "setcap -r failed").strip()[:120])
        return "file capability 제거"

    return attempt("persist.filecap", "remove", _op)


# ── 117. persist.account_group — 사용자·그룹 생성·변경 (destructive) ─────────
_ACCT = "persist.account_group"
_OSAGENT_USER = "osagent_probe_user"
_OSAGENT_GROUP = "osagent_probe_group"


@register(_ACCT, "create_user", spec=_spec(destructive=True))
def _acct_create_user(action, arguments, context):
    return attempt(_ACCT, "create_user", lambda: _acct_run(["useradd", "-M", "-s", "/usr/sbin/nologin", _OSAGENT_USER]))


@register(_ACCT, "modify_user", spec=_spec(destructive=True))
def _acct_modify_user(action, arguments, context):
    return attempt(_ACCT, "modify_user", lambda: _acct_run(["usermod", "-c", "osagent", _OSAGENT_USER]))


@register(_ACCT, "create_group", spec=_spec(destructive=True))
def _acct_create_group(action, arguments, context):
    return attempt(_ACCT, "create_group", lambda: _acct_run(["groupadd", _OSAGENT_GROUP]))


@register(_ACCT, "modify_group", spec=_spec(destructive=True))
def _acct_modify_group(action, arguments, context):
    return attempt(_ACCT, "modify_group", lambda: _acct_run(["groupmod", "-n", _OSAGENT_GROUP, _OSAGENT_GROUP]))


@register(_ACCT, "rollback", spec=_spec())
def _acct_rollback(action, arguments, context):
    def _op() -> str:
        _run(["userdel", _OSAGENT_USER])
        _run(["groupdel", _OSAGENT_GROUP])
        return "osagent 계정·그룹 정리"
    return attempt(_ACCT, "rollback", _op)


def _acct_run(argv: list[str]) -> str:
    r = _run(argv)
    if r.returncode != 0:
        err = (r.stderr or "failed").strip()
        code = errno_module.EPERM if ("permission" in err.lower() or "not permitted" in err.lower() or "Only root" in err) else 1
        raise OSError(code, err[:150])
    return f"{argv[0]} 도달"


if __name__ == "__main__":
    from .base import _REGISTRY
    persist = sorted(t for t in _REGISTRY if t.startswith("persist."))
    print(f"5.9 Persistence: {len(persist)} tools")
    for t in persist:
        print(f"  - {t}: {sorted(_REGISTRY[t])}")
