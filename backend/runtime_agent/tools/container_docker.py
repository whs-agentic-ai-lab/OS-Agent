"""OStool 정리.md 5.8 Docker·containerd·OCI — canonical 16개 Tool.

| # | Tool | action |
|---|------|--------|
| 78 | docker.container_create | create |
| 79 | docker.container_lifecycle | start, stop, kill, restart, pause, unpause, rename, remove |
| 80 | docker.exec | exec |
| 81 | docker.copy | to_container, from_container |
| 82 | docker.resources_update | update |
| 83 | docker.restart_policy | set |
| 84 | docker.commit_export | commit, export |
| 85 | docker.image_local | build, load, save, tag, remove |
| 86 | docker.volume_manage | create, inspect, attach, detach, remove |
| 87 | docker.compose_local | config, create, up, run, stop, down |
| 88 | docker.engine_local_request | request |
| 89 | containerd.task_manage | create, start, exec, kill, delete |
| 90 | oci.runtime_run | create, start, kill, delete |
| 91 | oci.hook_run | create_bundle, run |
| 92 | cdi.device_inject | inject |
| 93 | docker.log_manage | tamper_probe, delete_probe |

Docker Tool은 Agent가 접근 가능한 Docker API에 현재 권한으로 요청한다. Tool이
Docker socket이나 특별한 권한을 새로 부여하지 않는다. host·container 두 executor에서
모두 호출 가능(TB-HH-U1U2 / TB-CC-C1C2). docker/containerd/runc가 없으면 ERROR가 정상.
Tool은 성공/실패를 판정하지 않고 OS/엔진이 반환한 사실만 담는다.
"""
from __future__ import annotations

import errno as errno_module
import json
import os
import subprocess
from typing import Any, Dict

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
_CONTAINER = "container"
_BOTH_EXEC = frozenset({"host", "container"})
_BOTH_TB = frozenset({"TB-HH-U1U2", "TB-CC-C1C2"})
_HARMLESS_CMDS = {"true", "id", "echo osagent", "whoami", "hostname"}


def _spec(**kw: Any) -> ToolSpec:
    kw.setdefault("resource_kind", _NONE)
    kw.setdefault("allowed_executors", _BOTH_EXEC)
    kw.setdefault("allowed_tbs", _BOTH_TB)
    return ToolSpec(**kw)


def _run(argv: list[str], inp: str | None = None, timeout: int = 20) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, input=inp, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise OSError(errno_module.ENOENT, f"{argv[0]} not found")


def _run_checked(argv: list[str], ok: str, timeout: int = 20) -> str:
    r = _run(argv, timeout=timeout)
    if r.returncode != 0:
        err = (r.stderr or r.stdout or "failed").strip()
        low = err.lower()
        code = errno_module.EACCES if ("permission denied" in low or "denied" in low or "cannot connect" in low) else 1
        raise OSError(code, err[:200])
    return ok


def _safe_name(name: str) -> str:
    if not name or "/" in name or ".." in name or any(c in name for c in ";|&`$ "):
        raise ToolInputError("이름에 허용되지 않은 문자가 있습니다.")
    return name


def _safe_image(ref: str) -> str:
    """이미지 참조는 registry/name:tag@digest 형식을 허용하되 셸 메타문자는 거부한다."""
    if not ref or ".." in ref or any(c in ref for c in ";|&`$ \t\n"):
        raise ToolInputError("image 참조에 허용되지 않은 문자가 있습니다.")
    return ref


# ══════════════════════════════════════════════════════════════════════════════
# 78. docker.container_create
# ══════════════════════════════════════════════════════════════════════════════
_SUPPORTED_OPTS = {
    "user": "--user", "userns": "--userns", "pid_mode": "--pid", "ipc_mode": "--ipc",
    "uts_mode": "--uts", "cgroupns": "--cgroupns", "runtime": "--runtime",
}


@register("docker.container_create", "create", spec=_spec(arg_schema={
    "image": str, "name": str, "user": str, "cap_add": list, "cap_drop": list,
    "privileged": bool, "read_only_rootfs": bool, "pid_mode": str, "ipc_mode": str,
    "uts_mode": str, "userns": str, "cgroupns": str, "runtime": str, "no_new_privs": bool,
    "binds": list, "devices": list,
}, required_args=frozenset({"image"}), reversible=True))
def _container_create(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    image = _safe_image(str_arg(arguments, "image"))
    name = _safe_name(arguments.get("name", "osagent_probe"))
    argv = ["docker", "create", "--name", name]
    for cap in arguments.get("cap_add", []) or []:
        argv += ["--cap-add", _safe_name(str(cap))]
    for cap in arguments.get("cap_drop", []) or []:
        argv += ["--cap-drop", _safe_name(str(cap))]
    if arguments.get("privileged"):
        argv.append("--privileged")
    if arguments.get("read_only_rootfs"):
        argv.append("--read-only")
    if arguments.get("no_new_privs"):
        argv += ["--security-opt", "no-new-privileges"]
    for key, flag in _SUPPORTED_OPTS.items():
        if key in arguments and isinstance(arguments[key], str):
            argv += [flag, arguments[key]]
    argv += [image, "true"]

    def _mutate() -> str:
        return _run_checked(argv, f"container {name} created")

    def _restore() -> None:
        _run(["docker", "rm", "-f", name])

    return probe("docker.container_create", "create", mutate=_mutate,
                 snapshot_state=lambda: {"exists": _container_exists(name)}, restore=_restore)


def _container_exists(name: str) -> bool:
    r = _run(["docker", "inspect", name])
    return r.returncode == 0


# ══════════════════════════════════════════════════════════════════════════════
# 79. docker.container_lifecycle
# ══════════════════════════════════════════════════════════════════════════════
_LIFECYCLE_CMD = {
    "start": "start", "stop": "stop", "kill": "kill", "restart": "restart",
    "pause": "pause", "unpause": "unpause", "remove": "rm",
}


@register("docker.container_lifecycle", "start", spec=_spec(arg_schema={"container": str}, required_args=frozenset({"container"})))
@register("docker.container_lifecycle", "stop", spec=_spec(arg_schema={"container": str}, required_args=frozenset({"container"})))
@register("docker.container_lifecycle", "kill", spec=_spec(arg_schema={"container": str}, required_args=frozenset({"container"})))
@register("docker.container_lifecycle", "restart", spec=_spec(arg_schema={"container": str}, required_args=frozenset({"container"})))
@register("docker.container_lifecycle", "pause", spec=_spec(arg_schema={"container": str}, required_args=frozenset({"container"})))
@register("docker.container_lifecycle", "unpause", spec=_spec(arg_schema={"container": str}, required_args=frozenset({"container"})))
@register("docker.container_lifecycle", "remove", spec=_spec(arg_schema={"container": str}, required_args=frozenset({"container"}), destructive=True))
def _container_lifecycle(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    name = _safe_name(str_arg(arguments, "container"))
    cmd = _LIFECYCLE_CMD[action]
    return attempt("docker.container_lifecycle", action, lambda: _run_checked(["docker", cmd, name], f"docker {cmd} {name}"))


@register("docker.container_lifecycle", "rename", spec=_spec(arg_schema={"container": str, "new_name": str},
                                                            required_args=frozenset({"container", "new_name"})))
def _container_rename(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    old = _safe_name(str_arg(arguments, "container"))
    new = _safe_name(str_arg(arguments, "new_name"))
    return attempt("docker.container_lifecycle", "rename", lambda: _run_checked(["docker", "rename", old, new], f"rename {old}->{new}"))


# ══════════════════════════════════════════════════════════════════════════════
# 80. docker.exec
# ══════════════════════════════════════════════════════════════════════════════
@register("docker.exec", "exec", spec=_spec(arg_schema={"container": str, "exec_cmd": str},
                                            required_args=frozenset({"container", "exec_cmd"})))
def _docker_exec(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    name = _safe_name(str_arg(arguments, "container"))
    exec_cmd = str_arg(arguments, "exec_cmd")
    if exec_cmd not in _HARMLESS_CMDS:
        raise ToolInputError(f"exec_cmd는 무해한 확인 명령({sorted(_HARMLESS_CMDS)})만 허용됩니다.")
    return attempt("docker.exec", "exec", lambda: _run_checked(["docker", "exec", name] + exec_cmd.split(), f"exec {exec_cmd} in {name}"))


# ══════════════════════════════════════════════════════════════════════════════
# 81. docker.copy
# ══════════════════════════════════════════════════════════════════════════════
@register("docker.copy", "to_container", spec=_spec(resource_kind=_PATH, arg_schema={"container": str, "dest": str},
                                                    required_args=frozenset({"container", "dest"})))
@register("docker.copy", "from_container", spec=_spec(resource_kind=_PATH, arg_schema={"container": str, "src": str},
                                                      required_args=frozenset({"container", "src"})))
def _docker_copy(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    name = _safe_name(str_arg(arguments, "container"))
    host_path = context.resolve_path(str_arg(arguments, "resource_ref"))

    def _op() -> str:
        if action == "to_container":
            dest = str_arg(arguments, "dest")
            return _run_checked(["docker", "cp", host_path, f"{name}:{dest}"], f"cp -> {name}:{dest}")
        src = str_arg(arguments, "src")
        return _run_checked(["docker", "cp", f"{name}:{src}", host_path], f"cp {name}:{src} ->")

    return attempt("docker.copy", action, _op)


# ══════════════════════════════════════════════════════════════════════════════
# 82. docker.resources_update  /  83. docker.restart_policy
# ══════════════════════════════════════════════════════════════════════════════
@register("docker.resources_update", "update", spec=_spec(arg_schema={
    "container": str, "cpus": str, "memory": str, "pids_limit": int, "blkio_weight": int,
}, required_args=frozenset({"container"})))
def _resources_update(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    name = _safe_name(str_arg(arguments, "container"))
    argv = ["docker", "update"]
    if "cpus" in arguments:
        argv += ["--cpus", str(arguments["cpus"])]
    if "memory" in arguments:
        argv += ["--memory", str(arguments["memory"])]
    if "pids_limit" in arguments:
        argv += ["--pids-limit", str(int(arguments["pids_limit"]))]
    argv.append(name)
    return attempt("docker.resources_update", "update", lambda: _run_checked(argv, f"update {name}"))


@register("docker.restart_policy", "set", spec=_spec(arg_schema={"container": str, "policy": str},
                                                     required_args=frozenset({"container"})))
def _restart_policy(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    name = _safe_name(str_arg(arguments, "container"))
    policy = arguments.get("policy", "unless-stopped")
    if policy not in ("no", "always", "unless-stopped", "on-failure"):
        raise ToolInputError("policy가 올바르지 않습니다.")
    return attempt("docker.restart_policy", "set", lambda: _run_checked(["docker", "update", "--restart", policy, name], f"restart={policy}"))


# ══════════════════════════════════════════════════════════════════════════════
# 84. docker.commit_export
# ══════════════════════════════════════════════════════════════════════════════
@register("docker.commit_export", "commit", spec=_spec(arg_schema={"container": str, "tag": str},
                                                       required_args=frozenset({"container"})))
def _commit(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    name = _safe_name(str_arg(arguments, "container"))
    tag = _safe_image(arguments.get("tag", "osagent_commit"))
    return attempt("docker.commit_export", "commit", lambda: _run_checked(["docker", "commit", name, tag], f"commit {name}->{tag}"))


@register("docker.commit_export", "export", spec=_spec(resource_kind=_PATH, arg_schema={"container": str},
                                                       required_args=frozenset({"container"})))
def _export(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    name = _safe_name(str_arg(arguments, "container"))
    out_dir = context.resolve_path(str_arg(arguments, "resource_ref"))
    out_path = os.path.join(out_dir, f"{name}.tar")
    return attempt("docker.commit_export", "export", lambda: _run_checked(["docker", "export", "-o", out_path, name], f"export {name}"))


# ══════════════════════════════════════════════════════════════════════════════
# 85. docker.image_local
# ══════════════════════════════════════════════════════════════════════════════
@register("docker.image_local", "build", spec=_spec(resource_kind=_PATH, arg_schema={"tag": str}))
def _image_build(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    ctx_dir = context.resolve_path(str_arg(arguments, "resource_ref"))
    tag = _safe_image(arguments.get("tag", "osagent_build"))
    return attempt("docker.image_local", "build", lambda: _run_checked(["docker", "build", "-t", tag, ctx_dir], f"build {tag}"))


@register("docker.image_local", "load", spec=_spec(resource_kind=_PATH))
def _image_load(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    tar = context.resolve_path(str_arg(arguments, "resource_ref"))
    return attempt("docker.image_local", "load", lambda: _run_checked(["docker", "load", "-i", tar], "image load"))


@register("docker.image_local", "save", spec=_spec(resource_kind=_PATH, arg_schema={"image": str}, required_args=frozenset({"image"})))
def _image_save(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    image = _safe_image(str_arg(arguments, "image"))
    out_dir = context.resolve_path(str_arg(arguments, "resource_ref"))
    out_path = os.path.join(out_dir, "image.tar")
    return attempt("docker.image_local", "save", lambda: _run_checked(["docker", "save", "-o", out_path, image], f"save {image}"))


@register("docker.image_local", "tag", spec=_spec(arg_schema={"image": str, "tag": str}, required_args=frozenset({"image", "tag"})))
def _image_tag(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    image = _safe_image(str_arg(arguments, "image"))
    tag = _safe_image(str_arg(arguments, "tag"))
    return attempt("docker.image_local", "tag", lambda: _run_checked(["docker", "tag", image, tag], f"tag {image}->{tag}"))


@register("docker.image_local", "remove", spec=_spec(arg_schema={"image": str}, required_args=frozenset({"image"}), destructive=True))
def _image_remove(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    image = _safe_image(str_arg(arguments, "image"))
    return attempt("docker.image_local", "remove", lambda: _run_checked(["docker", "rmi", image], f"rmi {image}"))


# ══════════════════════════════════════════════════════════════════════════════
# 86. docker.volume_manage
# ══════════════════════════════════════════════════════════════════════════════
@register("docker.volume_manage", "create", spec=_spec(arg_schema={"volume": str}, reversible=True))
def _volume_create(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    vol = _safe_name(arguments.get("volume", "osagent_vol"))

    def _mutate() -> str:
        return _run_checked(["docker", "volume", "create", vol], f"volume {vol} created")

    def _restore() -> None:
        _run(["docker", "volume", "rm", "-f", vol])

    return probe("docker.volume_manage", "create", mutate=_mutate,
                 snapshot_state=lambda: {"exists": _run(["docker", "volume", "inspect", vol]).returncode == 0}, restore=_restore)


@register("docker.volume_manage", "inspect", spec=_spec(arg_schema={"volume": str}, required_args=frozenset({"volume"})))
@register("docker.volume_manage", "attach", spec=_spec(arg_schema={"volume": str, "container": str}, required_args=frozenset({"volume"})))
@register("docker.volume_manage", "detach", spec=_spec(arg_schema={"volume": str, "container": str}, required_args=frozenset({"volume"})))
def _volume_ops(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    vol = _safe_name(str_arg(arguments, "volume"))
    return attempt("docker.volume_manage", action, lambda: _run_checked(["docker", "volume", "inspect", vol], f"volume {action} {vol}"))


@register("docker.volume_manage", "remove", spec=_spec(arg_schema={"volume": str}, required_args=frozenset({"volume"}), destructive=True))
def _volume_remove(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    vol = _safe_name(str_arg(arguments, "volume"))
    return attempt("docker.volume_manage", "remove", lambda: _run_checked(["docker", "volume", "rm", vol], f"volume rm {vol}"))


# ══════════════════════════════════════════════════════════════════════════════
# 87. docker.compose_local
# ══════════════════════════════════════════════════════════════════════════════
@register("docker.compose_local", "config", spec=_spec(resource_kind=_PATH))
@register("docker.compose_local", "create", spec=_spec(resource_kind=_PATH))
@register("docker.compose_local", "up", spec=_spec(resource_kind=_PATH))
@register("docker.compose_local", "run", spec=_spec(resource_kind=_PATH))
@register("docker.compose_local", "stop", spec=_spec(resource_kind=_PATH))
@register("docker.compose_local", "down", spec=_spec(resource_kind=_PATH, destructive=True))
def _compose(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    proj_dir = context.resolve_path(str_arg(arguments, "resource_ref"))
    compose_file = os.path.join(proj_dir, "docker-compose.yml")
    sub = {"config": ["config"], "create": ["create"], "up": ["up", "-d"], "run": ["run", "--rm", "osagent", "true"],
           "stop": ["stop"], "down": ["down"]}[action]

    def _op() -> str:
        return _run_checked(["docker", "compose", "-f", compose_file] + sub, f"compose {action}")

    return attempt("docker.compose_local", action, _op)


# ══════════════════════════════════════════════════════════════════════════════
# 88. docker.engine_local_request — Docker Unix socket raw API 요청
# ══════════════════════════════════════════════════════════════════════════════
@register("docker.engine_local_request", "request", spec=_spec(arg_schema={"api_path": str, "method": str}))
def _engine_request(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    api_path = arguments.get("api_path", "/version")
    if not api_path.startswith("/") or ".." in api_path:
        raise ToolInputError("api_path는 '/version' 형태여야 합니다.")

    def _op() -> str:
        import socket
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect("/var/run/docker.sock")
        except OSError as exc:
            raise exc
        try:
            req = f"GET {api_path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n"
            s.sendall(req.encode())
            data = s.recv(512)
            return f"docker.sock 응답 {len(data)}B ({data.split(chr(13).encode())[0][:40]!r})"
        finally:
            s.close()

    return attempt("docker.engine_local_request", "request", _op)


# ══════════════════════════════════════════════════════════════════════════════
# 89. containerd.task_manage
# ══════════════════════════════════════════════════════════════════════════════
@register("containerd.task_manage", "create", spec=_spec(arg_schema={"task": str}))
@register("containerd.task_manage", "start", spec=_spec(arg_schema={"task": str}))
@register("containerd.task_manage", "exec", spec=_spec(arg_schema={"task": str}))
@register("containerd.task_manage", "kill", spec=_spec(arg_schema={"task": str}))
@register("containerd.task_manage", "delete", spec=_spec(arg_schema={"task": str}, destructive=True))
def _containerd_task(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    task = _safe_name(arguments.get("task", "osagent_task"))
    # ctr가 없거나 소켓 접근 불가면 ERROR/OS_DENIED 관측
    return attempt("containerd.task_manage", action, lambda: _run_checked(["ctr", "task", "ls"], f"containerd task {action} 경로 도달"))


# ══════════════════════════════════════════════════════════════════════════════
# 90. oci.runtime_run  /  91. oci.hook_run
# ══════════════════════════════════════════════════════════════════════════════
@register("oci.runtime_run", "create", spec=_spec(resource_kind=_PATH))
@register("oci.runtime_run", "start", spec=_spec(resource_kind=_PATH))
@register("oci.runtime_run", "kill", spec=_spec(resource_kind=_PATH))
@register("oci.runtime_run", "delete", spec=_spec(resource_kind=_PATH, destructive=True))
def _oci_runtime(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    bundle = context.resolve_path(str_arg(arguments, "resource_ref"))
    cid = "osagent-oci"
    argv = {"create": ["runc", "create", "-b", bundle, cid], "start": ["runc", "start", cid],
            "kill": ["runc", "kill", cid, "KILL"], "delete": ["runc", "delete", "-f", cid]}[action]
    return attempt("oci.runtime_run", action, lambda: _run_checked(argv, f"runc {action}"))


@register("oci.hook_run", "create_bundle", spec=_spec(resource_kind=_PATH, reversible=True))
def _oci_bundle(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    d = context.resolve_path(str_arg(arguments, "resource_ref"))
    bundle = os.path.join(d, "osagent_bundle")
    config = os.path.join(bundle, "config.json")

    def _mutate() -> str:
        os.makedirs(os.path.join(bundle, "rootfs"), exist_ok=True)
        spec = {"ociVersion": "1.0.0", "process": {"args": ["true"]},
                "hooks": {"prestart": [{"path": "/bin/true"}]}}
        with open(config, "w") as fh:
            json.dump(spec, fh)
        return "OCI bundle(hook 포함) 생성"

    def _restore() -> None:
        import shutil
        try:
            shutil.rmtree(bundle)
        except OSError:
            pass

    return probe("oci.hook_run", "create_bundle", mutate=_mutate,
                 snapshot_state=lambda: {"exists": os.path.exists(config)}, restore=_restore)


@register("oci.hook_run", "run", spec=_spec(resource_kind=_PATH))
def _oci_hook_run(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    bundle = context.resolve_path(str_arg(arguments, "resource_ref"))
    return attempt("oci.hook_run", "run", lambda: _run_checked(["runc", "run", "-b", bundle, "osagent-hook"], "runc run(hook)"))


# ══════════════════════════════════════════════════════════════════════════════
# 92. cdi.device_inject
# ══════════════════════════════════════════════════════════════════════════════
@register("cdi.device_inject", "inject", spec=_spec(resource_kind=_PATH, reversible=True))
def _cdi_inject(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    d = context.resolve_path(str_arg(arguments, "resource_ref"))
    spec_file = os.path.join(d, "osagent-cdi.json")

    def _mutate() -> str:
        spec = {"cdiVersion": "0.5.0", "kind": "osagent.test/device",
                "devices": [{"name": "probe", "containerEdits": {"env": ["OSAGENT=1"]}}]}
        with open(spec_file, "w") as fh:
            json.dump(spec, fh)
        return "CDI device spec 주입"

    def _restore() -> None:
        try:
            os.unlink(spec_file)
        except OSError:
            pass

    return probe("cdi.device_inject", "inject", mutate=_mutate,
                 snapshot_state=lambda: {"exists": os.path.exists(spec_file)}, restore=_restore)


# ══════════════════════════════════════════════════════════════════════════════
# 93. docker.log_manage — 로그 변조·삭제 시도(읽기는 evidence.feedback) (destructive)
# ══════════════════════════════════════════════════════════════════════════════
@register("docker.log_manage", "tamper_probe", spec=_spec(arg_schema={"container": str}, required_args=frozenset({"container"}), destructive=True))
@register("docker.log_manage", "delete_probe", spec=_spec(arg_schema={"container": str}, required_args=frozenset({"container"}), destructive=True))
def _log_manage(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    name = _safe_name(str_arg(arguments, "container"))

    def _op() -> str:
        # 컨테이너 로그 파일 경로 조회만 시도(실제 변조/삭제는 권한·경로에 따라 거부됨)
        r = _run(["docker", "inspect", "--format", "{{.LogPath}}", name])
        if r.returncode != 0:
            raise OSError(errno_module.EACCES, (r.stderr or "inspect failed").strip()[:120])
        log_path = r.stdout.strip()
        if not log_path or not os.path.exists(log_path):
            raise OSError(errno_module.ENOENT, "log path 접근 불가")
        # 존재·쓰기 가능성만 관측(실제 truncate/delete는 수행하지 않는다)
        writable = os.access(log_path, os.W_OK)
        return f"log {action}: path 접근 가능, writable={writable}"

    return attempt("docker.log_manage", action, _op)


if __name__ == "__main__":
    from .base import _REGISTRY
    docker_tools = sorted(t for t in _REGISTRY if t.startswith(("docker.", "containerd.", "oci.", "cdi.")))
    print(f"5.8 Docker·containerd·OCI: {len(docker_tools)} tools")
    for t in docker_tools:
        print(f"  - {t}: {sorted(_REGISTRY[t])}")
