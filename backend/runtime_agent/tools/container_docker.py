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
import hashlib
import io
import json
import os
import shutil
import socket
import stat as stat_module
import subprocess
import tarfile
import time
import urllib.parse
from typing import Any, Dict

from .base import (
    ResetResult,
    ToolContext,
    ToolContractError,
    ToolDecision,
    ToolDefinition,
    ToolInputError,
    ToolOutcome,
    ToolPolicyBlocked,
    ToolResult,
    ToolSpec,
    VerificationResult,
    attempt,
    probe,
    register,
    register_definition,
    identity_snapshot,
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


# ══════════════════════════════════════════════════════════════════════════════
# ToolDefinition 전환 계층
# ══════════════════════════════════════════════════════════════════════════════

_CONTAINER_EXECUTORS = frozenset({"host", "container"})
_CONTAINER_TBS = frozenset({"TB-HH-U1U2", "TB-CC-C1C2"})
_DESTRUCTIVE_LIMITS = {"max_containers": 1, "max_images": 1, "max_volumes": 1, "max_bytes": 1 << 20}
_DESTRUCTIVE_STOPS = frozenset({"timeout", "daemon_disconnect", "target_escape", "rollback_failure"})
_EXEC_PROFILES = {"true": ["true"], "id": ["id"], "whoami": ["whoami"], "hostname": ["hostname"]}
_ENGINE_PROFILES = {"ping": ("GET", "/_ping"), "version": ("GET", "/version"), "info": ("GET", "/info")}
_RESOURCE_PROFILES = {
    "small": {"NanoCpus": 250_000_000, "Memory": 64 * 1024 * 1024, "PidsLimit": 64},
    "medium": {"NanoCpus": 500_000_000, "Memory": 128 * 1024 * 1024, "PidsLimit": 128},
}
_RESTART_POLICIES = {"none": {"Name": "no", "MaximumRetryCount": 0},
                     "on_failure": {"Name": "on-failure", "MaximumRetryCount": 1},
                     "unless_stopped": {"Name": "unless-stopped", "MaximumRetryCount": 0}}


class _ForbiddenRawArgument:
    """raw command/name/path/API body marker."""


def _container_spec(
    resource_kind: str = _PATH, *, arg_schema: dict[str, Any] | None = None,
    required_args: frozenset[str] = frozenset(), reversible: bool = False,
    destructive: bool = False, timeout_s: float = 20.0,
) -> ToolSpec:
    return ToolSpec(
        resource_kind=resource_kind, allowed_executors=_CONTAINER_EXECUTORS, allowed_tbs=_CONTAINER_TBS,
        arg_schema=dict(arg_schema or {}), required_args=required_args,
        reversible=reversible, destructive=destructive, timeout_s=timeout_s,
        resource_limits=dict(_DESTRUCTIVE_LIMITS) if destructive else {},
        emergency_stop_conditions=_DESTRUCTIVE_STOPS if destructive else frozenset(),
    )


def _safe_fixture_name(context: ToolContext, suffix: str) -> str:
    digest = hashlib.sha256(f"{context.run_id}:{context.action_id}:{suffix}".encode()).hexdigest()[:16]
    return f"osagent-{suffix[:20]}-{digest}"


def _registered_socket(decision: ToolDecision, context: ToolContext) -> str:
    if decision.resource_ref is None: raise ToolInputError("Docker engine socket resource_ref가 필요합니다.")
    path = context.resolve_path(decision.resource_ref)
    if os.path.islink(path) or os.path.realpath(path) != os.path.abspath(path): raise ToolPolicyBlocked("engine socket은 symlink가 아닌 등록 exact path여야 합니다.")
    if os.path.exists(path) and not stat_module.S_ISSOCK(os.stat(path, follow_symlinks=False).st_mode): raise ToolPolicyBlocked("resource_ref가 Unix socket이 아닙니다.")
    return path


def _resolved_string_ref(arguments: dict[str, Any], key: str, context: ToolContext) -> str:
    ref = arguments.get(key)
    if not isinstance(ref, str) or not ref: raise ToolInputError(f"{key}가 필요합니다.")
    value = context.resolve_resource(ref)
    if not isinstance(value, str) or not value or any(ch in value for ch in "\r\n\x00"):
        raise ToolPolicyBlocked(f"{key}가 등록된 문자열 Target을 가리키지 않습니다.")
    return value


def _resolved_path_ref(arguments: dict[str, Any], key: str, context: ToolContext) -> str:
    ref = arguments.get(key)
    if not isinstance(ref, str) or not ref: raise ToolInputError(f"{key}가 필요합니다.")
    path = context.resolve_path(ref)
    if os.path.islink(path) or os.path.realpath(path) != os.path.abspath(path): raise ToolPolicyBlocked(f"{key}는 symlink가 아닌 exact fixture path여야 합니다.")
    return path


def _decode_chunked(data: bytes) -> bytes:
    output = bytearray(); offset = 0
    while True:
        end = data.find(b"\r\n", offset)
        if end < 0: raise OSError(errno_module.EPROTO, "invalid chunked response")
        size = int(data[offset:end].split(b";", 1)[0], 16); offset = end + 2
        if size == 0: return bytes(output)
        output.extend(data[offset:offset + size]); offset += size + 2


class _DockerAPI:
    def __init__(self, socket_path: str): self.socket_path = socket_path

    def request(self, method: str, path: str, body: bytes = b"", *, content_type: str = "application/json") -> tuple[int, dict[str, str], bytes]:
        if method not in {"GET", "POST", "PUT", "DELETE", "HEAD"} or not path.startswith("/") or "\r" in path or "\n" in path:
            raise ToolInputError("Docker API method/path가 allowlist를 벗어났습니다.")
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); client.settimeout(8)
        try:
            client.connect(self.socket_path)
            headers = [f"{method} {path} HTTP/1.1", "Host: docker", "Connection: close", f"Content-Length: {len(body)}"]
            if body: headers.append("Content-Type: " + content_type)
            client.sendall(("\r\n".join(headers) + "\r\n\r\n").encode() + body)
            chunks: list[bytes] = []
            while True:
                part = client.recv(65536)
                if not part: break
                chunks.append(part)
                if sum(map(len, chunks)) > (2 << 20): raise OSError(errno_module.EFBIG, "Docker API response exceeds 2MiB")
        finally: client.close()
        raw = b"".join(chunks); head, separator, payload = raw.partition(b"\r\n\r\n")
        if not separator: raise OSError(errno_module.EPROTO, "Docker API response has no headers")
        lines = head.split(b"\r\n"); status = int(lines[0].split()[1]); parsed_headers = {}
        for line in lines[1:]:
            key, sep, value = line.partition(b":")
            if sep: parsed_headers[key.decode().lower()] = value.decode().strip()
        if parsed_headers.get("transfer-encoding", "").lower() == "chunked": payload = _decode_chunked(payload)
        if status in {401, 403}: raise OSError(errno_module.EACCES, payload[:200].decode(errors="replace"))
        if status == 404: return status, parsed_headers, payload
        if status >= 400: raise OSError(errno_module.EIO, f"Docker API HTTP {status}: {payload[:200]!r}")
        return status, parsed_headers, payload

    def json(self, method: str, path: str, data: dict[str, Any] | None = None) -> tuple[int, Any]:
        body = json.dumps(data, separators=(",", ":")).encode() if data is not None else b""
        status, _headers, payload = self.request(method, path, body)
        return status, json.loads(payload) if payload else None


def _inspect_container(api: _DockerAPI, identifier: str) -> dict[str, Any]:
    status, value = api.json("GET", "/containers/" + urllib.parse.quote(identifier, safe="") + "/json")
    if status == 404: return {"exists": False, "id": identifier}
    return {"exists": True, "id": value.get("Id"), "name": str(value.get("Name", "")).lstrip("/"),
            "running": bool(value.get("State", {}).get("Running")), "paused": bool(value.get("State", {}).get("Paused")),
            "status": value.get("State", {}).get("Status"), "restart_policy": value.get("HostConfig", {}).get("RestartPolicy"),
            "log_path": value.get("LogPath"),
            "resources": {key: value.get("HostConfig", {}).get(key) for key in ("NanoCpus", "Memory", "PidsLimit")},
            "mounts": [{"type": item.get("Type"), "name": item.get("Name"), "destination": item.get("Destination")}
                       for item in value.get("Mounts", [])]}


def _create_container(api: _DockerAPI, context: ToolContext, image: str, *, suffix: str, config: dict[str, Any] | None = None) -> tuple[str, str]:
    name = _safe_fixture_name(context, suffix); payload = {"Image": image, "Cmd": ["sleep", "300"], "Labels": {"osagent.fixture": context.run_id}}
    if config: payload.update(config)
    _status, response = api.json("POST", "/containers/create?name=" + urllib.parse.quote(name, safe=""), payload)
    identifier = response.get("Id") if isinstance(response, dict) else None
    if not isinstance(identifier, str) or not identifier: raise OSError(errno_module.EPROTO, "Docker create returned no Id")
    return identifier, name


def _remove_container(api: _DockerAPI, identifier: str) -> None:
    status, _ = api.json("DELETE", "/containers/" + urllib.parse.quote(identifier, safe="") + "?force=true&v=true")
    if status not in {204, 404}: raise OSError(errno_module.EIO, f"container remove HTTP {status}")


def _image_inspect(api: _DockerAPI, reference: str) -> dict[str, Any]:
    status, value = api.json("GET", "/images/" + urllib.parse.quote(reference, safe="") + "/json")
    if status == 404: return {"exists": False, "reference": reference}
    return {"exists": True, "id": value.get("Id"), "repo_tags": sorted(value.get("RepoTags") or []), "size": value.get("Size")}


def _volume_inspect(api: _DockerAPI, name: str) -> dict[str, Any]:
    status, value = api.json("GET", "/volumes/" + urllib.parse.quote(name, safe=""))
    if status == 404: return {"exists": False, "name": name}
    return {"exists": True, "name": value.get("Name"), "driver": value.get("Driver"), "mountpoint": value.get("Mountpoint"), "labels": value.get("Labels") or {}}


def _tool_result(tool: str, action: str, context: ToolContext, identity_before: dict[str, Any], before: dict[str, Any], reached: dict[str, Any], *, changed: bool, output: str) -> ToolResult:
    return ToolResult(run_id=context.run_id, action_id=context.action_id, tool=tool, action=action,
                      attempted=True, outcome="ALLOWED", exit_code=0, output=output,
                      identity_before=identity_before, identity_reached=identity_snapshot(), state_before=before,
                      state_reached=reached, changed=changed, temporary_changed=changed)


def _verification(name: str, result: ToolResult, observed: dict[str, Any], checks: dict[str, bool], *, changed: bool) -> VerificationResult:
    if result.outcome != "ALLOWED":
        checks = {"outcome_classified": result.outcome in {"OS_DENIED", "POLICY_BLOCKED", "ERROR"}}
        return VerificationResult(name + "_verifier", "VERIFIED_NO_CHANGE" if all(checks.values()) else "REJECTED", checks, observed)
    return VerificationResult(name + "_verifier", ("VERIFIED" if changed else "VERIFIED_NO_CHANGE") if all(checks.values()) else "REJECTED", checks, observed)


def _reset_result(name: str, result: ToolResult, after: dict[str, Any], checks: dict[str, bool], *, changed: bool) -> ResetResult:
    status = "VERIFIED" if changed and all(checks.values()) else ("VERIFIED_NO_CHANGE" if all(checks.values()) else "FAILED")
    return ResetResult(name + "_resetter", status, identity_snapshot(), after, checks)


def _build_container_object_definition(tool: str, action: str) -> ToolDefinition:
    name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot()
        api = _DockerAPI(_registered_socket(decision, context)); image = _resolved_string_ref(decision.arguments, "image_ref", context)
        prepared_output_dir: str | None = None
        if tool == "docker.commit_export" and action == "export":
            prepared_output_dir = _resolved_path_ref(decision.arguments, "output_ref", context)
            if not os.path.isdir(prepared_output_dir): raise ToolPolicyBlocked("output_ref는 fixture directory여야 합니다.")
        before = {"fixture_exists": False}; identifier, container_name = _create_container(api, context, image, suffix=action)
        state.update(api=api, identifier=identifier, container_name=container_name, image=image)
        if tool == "docker.container_lifecycle":
            endpoint = "/containers/" + identifier
            if action in {"stop", "kill", "restart", "pause", "unpause"}: api.json("POST", endpoint + "/start")
            if action == "start": api.json("POST", endpoint + "/start")
            elif action == "stop": api.json("POST", endpoint + "/stop?t=1")
            elif action == "kill": api.json("POST", endpoint + "/kill?signal=SIGKILL")
            elif action == "restart": api.json("POST", endpoint + "/restart?t=1")
            elif action == "pause": api.json("POST", endpoint + "/pause")
            elif action == "unpause": api.json("POST", endpoint + "/pause"); api.json("POST", endpoint + "/unpause")
            elif action == "rename":
                new_name = _safe_fixture_name(context, "renamed"); api.json("POST", endpoint + "/rename?name=" + urllib.parse.quote(new_name, safe="")); state["container_name"] = new_name
            elif action == "remove": _remove_container(api, identifier)
        elif tool == "docker.exec":
            profile = decision.arguments.get("exec_profile", "true")
            if "exec_cmd" in decision.arguments or profile not in _EXEC_PROFILES: raise ToolInputError(f"exec_profile은 {sorted(_EXEC_PROFILES)} 중 하나여야 합니다.")
            api.json("POST", f"/containers/{identifier}/start")
            _status, created = api.json("POST", f"/containers/{identifier}/exec", {"AttachStdout": True, "AttachStderr": True, "Cmd": _EXEC_PROFILES[profile]})
            exec_id = created.get("Id"); state["exec_id"] = exec_id; api.request("POST", f"/exec/{exec_id}/start", json.dumps({"Detach": False, "Tty": False}).encode())
        elif tool == "docker.resources_update":
            profile = decision.arguments.get("resource_profile", "small")
            if any(key in decision.arguments for key in ("cpus", "memory", "pids_limit", "blkio_weight")) or profile not in _RESOURCE_PROFILES:
                raise ToolInputError(f"resource_profile은 {sorted(_RESOURCE_PROFILES)} 중 하나여야 합니다.")
            state["resource_profile"] = profile; api.json("POST", f"/containers/{identifier}/update", _RESOURCE_PROFILES[profile])
        elif tool == "docker.restart_policy":
            profile = decision.arguments.get("policy_profile", "none")
            if "policy" in decision.arguments or profile not in _RESTART_POLICIES: raise ToolInputError(f"policy_profile은 {sorted(_RESTART_POLICIES)} 중 하나여야 합니다.")
            state["policy_profile"] = profile; api.json("POST", f"/containers/{identifier}/update", {"RestartPolicy": _RESTART_POLICIES[profile]})
        elif tool == "docker.commit_export":
            if action == "commit":
                tag = _safe_fixture_name(context, "commit"); state["image_tag"] = tag
                api.json("POST", "/commit?container=" + urllib.parse.quote(identifier, safe="") + "&repo=" + urllib.parse.quote(tag, safe=""))
            else:
                out_path = os.path.join(prepared_output_dir, _safe_fixture_name(context, "export") + ".tar")
                if os.path.lexists(out_path): raise ToolPolicyBlocked("export fixture output already exists")
                _status, _headers, payload = api.request("GET", f"/containers/{identifier}/export")
                if len(payload) > 1 << 20: raise OSError(errno_module.EFBIG, "export exceeds 1MiB fixture limit")
                fd = os.open(out_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                try: os.write(fd, payload)
                finally: os.close(fd)
                state.update(output_path=out_path, output_hash=hashlib.sha256(payload).hexdigest())
        reached = _inspect_container(api, identifier)
        if tool == "docker.exec":
            _status, exec_info = api.json("GET", f"/exec/{state['exec_id']}/json"); reached = {"container": reached, "exec": {"running": exec_info.get("Running"), "exit_code": exec_info.get("ExitCode")}}
        elif tool == "docker.commit_export" and action == "commit": reached = {"container": reached, "image": _image_inspect(api, state["image_tag"])}
        elif tool == "docker.commit_export" and action == "export": reached = {"container": reached, "output_exists": os.path.exists(state["output_path"]), "output_hash": state["output_hash"]}
        return _tool_result(tool, action, context, identity_before, before, reached, changed=True, output=f"Docker API {name}")
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED":
            return _verification(name, result, {}, {}, changed=False)
        api = state.get("api") or _DockerAPI(_registered_socket(decision, context)); identifier = state.get("identifier", "missing")
        container = _inspect_container(api, identifier); observed: dict[str, Any] = {"container": container}; checks: dict[str, bool]
        if tool == "docker.container_lifecycle":
            if action == "remove": checks = {"container_removed": not container["exists"]}
            elif action in {"start", "restart", "unpause"}: checks = {"container_running": container["running"], "container_not_paused": not container["paused"]}
            elif action in {"stop", "kill"}: checks = {"container_stopped": container["exists"] and not container["running"]}
            elif action == "pause": checks = {"container_paused": container["paused"]}
            else: checks = {"container_renamed": container.get("name") == state["container_name"]}
        elif tool == "docker.exec":
            _status, info = api.json("GET", f"/exec/{state['exec_id']}/json"); observed["exec"] = info
            checks = {"exec_completed": info.get("Running") is False, "exec_exit_code_observed": isinstance(info.get("ExitCode"), int)}
        elif tool == "docker.resources_update":
            expected = _RESOURCE_PROFILES[state["resource_profile"]]; checks = {f"{key}_matches": container["resources"].get(key) == value for key, value in expected.items()}
        elif tool == "docker.restart_policy": checks = {"restart_policy_matches": container["restart_policy"] == _RESTART_POLICIES[state["policy_profile"]]}
        elif tool == "docker.commit_export" and action == "commit":
            observed["image"] = _image_inspect(api, state["image_tag"]); checks = {"committed_image_exists": observed["image"]["exists"]}
        elif tool == "docker.commit_export":
            path = state["output_path"]
            with open(path, "rb") as stream: payload = stream.read((1 << 20) + 1)
            observed["output_hash"] = hashlib.sha256(payload).hexdigest(); checks = {"export_hash_matches": len(payload) <= (1 << 20) and observed["output_hash"] == state["output_hash"]}
        else: checks = {"container_created": container["exists"]}
        return _verification(name, result, observed, checks, changed=True)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        api = state.get("api")
        if api is None:
            return _reset_result(name, result, {"fixture_exists": False}, {"no_fixture_created": True}, changed=False)
        if state.get("image_tag"):
            api.json("DELETE", "/images/" + urllib.parse.quote(state["image_tag"], safe="") + "?force=true")
        path = state.get("output_path")
        if isinstance(path, str) and os.path.exists(path): os.unlink(path)
        identifier = state.get("identifier")
        if isinstance(identifier, str) and _inspect_container(api, identifier)["exists"]: _remove_container(api, identifier)
        after = {"container": _inspect_container(api, identifier or "missing"), "image": _image_inspect(api, state["image_tag"]) if state.get("image_tag") else {"exists": False},
                 "output_exists": os.path.exists(path) if isinstance(path, str) else False}
        checks = {"container_absent": not after["container"]["exists"], "image_absent": not after["image"]["exists"], "output_absent": not after["output_exists"]}
        return _reset_result(name, result, after, checks, changed=result.outcome == "ALLOWED")
    schema = {"image_ref": str, "container": _ForbiddenRawArgument, "name": _ForbiddenRawArgument,
              "exec_profile": str, "exec_cmd": _ForbiddenRawArgument, "resource_profile": str,
              "cpus": _ForbiddenRawArgument, "memory": _ForbiddenRawArgument, "pids_limit": _ForbiddenRawArgument,
              "blkio_weight": _ForbiddenRawArgument, "policy_profile": str, "policy": _ForbiddenRawArgument,
              "output_ref": str, "tag": _ForbiddenRawArgument}
    required = {"image_ref"}
    if tool == "docker.commit_export" and action == "export": required.add("output_ref")
    destructive = (tool == "docker.container_lifecycle" and action in {"kill", "remove"})
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _container_spec(arg_schema=schema, required_args=frozenset(required), reversible=True, destructive=destructive))


def _read_limited(path: str, limit: int = 1 << 20) -> bytes:
    with open(path, "rb") as stream:
        payload = stream.read(limit + 1)
    if len(payload) > limit: raise OSError(errno_module.EFBIG, f"fixture exceeds {limit} bytes")
    return payload


def _single_file_tar(filename: str, payload: bytes, mode: int = 0o600) -> bytes:
    if not filename or "/" in filename or ".." in filename: raise ToolInputError("tar fixture filename is invalid")
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        info = tarfile.TarInfo(filename); info.size = len(payload); info.mode = mode; info.mtime = 0
        archive.addfile(info, io.BytesIO(payload))
    return output.getvalue()


def _tar_member_hash(payload: bytes, filename: str) -> str | None:
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
            member = next((item for item in archive.getmembers() if os.path.basename(item.name) == filename and item.isfile()), None)
            if member is None: return None
            stream = archive.extractfile(member)
            return hashlib.sha256(stream.read()).hexdigest() if stream is not None else None
    except (tarfile.TarError, OSError):
        return None


def _build_copy_definition(action: str) -> ToolDefinition:
    tool = "docker.copy"; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); api = _DockerAPI(_registered_socket(decision, context))
        image = _resolved_string_ref(decision.arguments, "image_ref", context)
        source: str | None = None; out_dir: str | None = None
        if action == "to_container":
            source = _resolved_path_ref(decision.arguments, "host_ref", context)
            if not os.path.isfile(source): raise ToolPolicyBlocked("host_ref must be an existing fixture file")
        else:
            out_dir = _resolved_path_ref(decision.arguments, "output_ref", context)
            if not os.path.isdir(out_dir): raise ToolPolicyBlocked("output_ref must be a fixture directory")
        identifier, _container_name = _create_container(api, context, image, suffix="copy")
        state.update(api=api, identifier=identifier); before = {"container_exists": False, "output_exists": False}
        canary_name = "osagent-copy-canary"; state["canary_name"] = canary_name
        if action == "to_container":
            payload = _read_limited(source); state["expected_hash"] = hashlib.sha256(payload).hexdigest()
            archive = _single_file_tar(canary_name, payload)
            api.request("PUT", f"/containers/{identifier}/archive?path=/tmp", archive, content_type="application/x-tar")
        else:
            payload = b"osagent-docker-copy-canary\n"; state["expected_hash"] = hashlib.sha256(payload).hexdigest()
            api.request("PUT", f"/containers/{identifier}/archive?path=/tmp", _single_file_tar(canary_name, payload), content_type="application/x-tar")
            _status, _headers, archive = api.request("GET", f"/containers/{identifier}/archive?path=/tmp/{canary_name}")
            output_path = os.path.join(out_dir, _safe_fixture_name(context, "copy") + ".tar")
            if os.path.lexists(output_path): raise ToolPolicyBlocked("copy output already exists")
            fd = os.open(output_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try: os.write(fd, archive)
            finally: os.close(fd)
            state["output_path"] = output_path; state["output_hash"] = hashlib.sha256(archive).hexdigest()
        reached = {"container": _inspect_container(api, identifier), "payload_hash": state["expected_hash"]}
        return ToolResult(context.run_id, context.action_id, tool, action, True, "ALLOWED", exit_code=0,
                          output="Docker archive API completed", identity_before=identity_before,
                          identity_reached=identity_snapshot(), state_before=before, state_reached=reached,
                          changed=True, temporary_changed=True)
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        api = state["api"]; identifier = state["identifier"]
        _status, _headers, archive = api.request("GET", f"/containers/{identifier}/archive?path=/tmp/{state['canary_name']}")
        observed = {"container": _inspect_container(api, identifier), "member_hash": _tar_member_hash(archive, state["canary_name"])}
        checks = {"container_exists": observed["container"]["exists"], "payload_requeried": observed["member_hash"] == state["expected_hash"]}
        if action == "from_container":
            output_path = state["output_path"]; output_hash = hashlib.sha256(_read_limited(output_path, 2 << 20)).hexdigest()
            observed["output_hash"] = output_hash; checks["host_output_matches"] = output_hash == state["output_hash"]
        return _verification(name, result, observed, checks, changed=True)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        path = state.get("output_path")
        if isinstance(path, str) and os.path.exists(path): os.unlink(path)
        api = state.get("api"); identifier = state.get("identifier")
        if api is not None and isinstance(identifier, str) and _inspect_container(api, identifier)["exists"]: _remove_container(api, identifier)
        after = {"container_exists": bool(api and isinstance(identifier, str) and _inspect_container(api, identifier)["exists"]),
                 "output_exists": bool(isinstance(path, str) and os.path.exists(path))}
        return _reset_result(name, result, after, {"container_absent": not after["container_exists"], "output_absent": not after["output_exists"]}, changed=result.outcome == "ALLOWED")
    schema = {"image_ref": str, "host_ref": str, "output_ref": str, "container": _ForbiddenRawArgument,
              "src": _ForbiddenRawArgument, "dest": _ForbiddenRawArgument}
    required = frozenset({"image_ref", "host_ref"} if action == "to_container" else {"image_ref", "output_ref"})
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _container_spec(arg_schema=schema, required_args=required, reversible=True))


def _tar_directory(directory: str, limit: int = 1 << 20) -> bytes:
    if not os.path.isdir(directory) or os.path.islink(directory): raise ToolPolicyBlocked("context_ref must be an exact fixture directory")
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for entry in sorted(os.listdir(directory)):
            path = os.path.join(directory, entry)
            if os.path.islink(path) or not os.path.isfile(path): raise ToolPolicyBlocked("build context allows regular files only")
            payload = _read_limited(path, limit); info = tarfile.TarInfo(entry); info.size = len(payload); info.mode = 0o600; info.mtime = 0
            archive.addfile(info, io.BytesIO(payload))
            if output.tell() > limit: raise OSError(errno_module.EFBIG, "build context exceeds fixture limit")
    payload = output.getvalue()
    if len(payload) > limit: raise OSError(errno_module.EFBIG, "build context exceeds fixture limit")
    return payload


def _delete_image(api: _DockerAPI, reference: str) -> None:
    status, _headers, _payload = api.request("DELETE", "/images/" + urllib.parse.quote(reference, safe="") + "?force=true&noprune=false")
    if status not in {200, 204, 404}: raise OSError(errno_module.EIO, f"image delete HTTP {status}")


def _build_image_definition(action: str) -> ToolDefinition:
    tool = "docker.image_local"; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); api = _DockerAPI(_registered_socket(decision, context)); state["api"] = api
        before: dict[str, Any] = {}; changed = action != "save"
        if action == "build":
            context_dir = _resolved_path_ref(decision.arguments, "context_ref", context)
            if not os.path.isfile(os.path.join(context_dir, "Dockerfile")): raise ToolPolicyBlocked("registered build context requires Dockerfile")
            tag = _safe_fixture_name(context, "build"); state["image_tag"] = tag; before = _image_inspect(api, tag)
            api.request("POST", "/build?t=" + urllib.parse.quote(tag, safe="") + "&rm=1&forcerm=1", _tar_directory(context_dir), content_type="application/x-tar")
            reached = _image_inspect(api, tag)
        elif action == "load":
            archive_path = _resolved_path_ref(decision.arguments, "archive_ref", context); expected = _resolved_string_ref(decision.arguments, "image_ref", context)
            before = _image_inspect(api, expected); state["image_tag"] = expected
            if before["exists"]: raise ToolPolicyBlocked("load target image must be absent before action")
            api.request("POST", "/images/load?quiet=1", _read_limited(archive_path), content_type="application/x-tar")
            reached = _image_inspect(api, expected)
        elif action == "save":
            image = _resolved_string_ref(decision.arguments, "image_ref", context); out_dir = _resolved_path_ref(decision.arguments, "output_ref", context)
            if not os.path.isdir(out_dir): raise ToolPolicyBlocked("output_ref must be a fixture directory")
            output_path = os.path.join(out_dir, _safe_fixture_name(context, "image") + ".tar")
            if os.path.lexists(output_path): raise ToolPolicyBlocked("image output already exists")
            _status, _headers, payload = api.request("GET", "/images/get?names=" + urllib.parse.quote(image, safe=""))
            if len(payload) > (1 << 20): raise OSError(errno_module.EFBIG, "image archive exceeds 1MiB fixture limit")
            fd = os.open(output_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try: os.write(fd, payload)
            finally: os.close(fd)
            state.update(output_path=output_path, output_hash=hashlib.sha256(payload).hexdigest()); before = {"output_exists": False}; reached = {"output_exists": True, "sha256": state["output_hash"]}; changed = True
        else:
            source = _resolved_string_ref(decision.arguments, "image_ref", context); tag = _safe_fixture_name(context, action); state["image_tag"] = tag
            before = _image_inspect(api, tag)
            api.json("POST", "/images/" + urllib.parse.quote(source, safe="") + "/tag?repo=" + urllib.parse.quote(tag, safe=""))
            if action == "remove": _delete_image(api, tag)
            reached = _image_inspect(api, tag)
        return ToolResult(context.run_id, context.action_id, tool, action, True, "ALLOWED", exit_code=0, output=f"Docker image API {action}",
                          identity_before=identity_before, identity_reached=identity_snapshot(), state_before=before, state_reached=reached,
                          changed=changed, temporary_changed=changed)
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        if action == "save":
            payload = _read_limited(state["output_path"]); observed = {"exists": True, "sha256": hashlib.sha256(payload).hexdigest()}
            checks = {"archive_requeried": observed["sha256"] == state["output_hash"]}
        else:
            observed = _image_inspect(state["api"], state["image_tag"])
            checks = {"image_absent": not observed["exists"]} if action == "remove" else {"image_exists": observed["exists"]}
        return _verification(name, result, observed, checks, changed=True)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        api = state.get("api"); tag = state.get("image_tag"); path = state.get("output_path")
        if api is not None and isinstance(tag, str) and _image_inspect(api, tag)["exists"]: _delete_image(api, tag)
        if isinstance(path, str) and os.path.exists(path): os.unlink(path)
        after = {"image_exists": bool(api and isinstance(tag, str) and _image_inspect(api, tag)["exists"]), "output_exists": bool(isinstance(path, str) and os.path.exists(path))}
        return _reset_result(name, result, after, {"image_absent": not after["image_exists"], "output_absent": not after["output_exists"]}, changed=result.outcome == "ALLOWED")
    schema = {"context_ref": str, "archive_ref": str, "image_ref": str, "output_ref": str,
              "image": _ForbiddenRawArgument, "tag": _ForbiddenRawArgument, "dockerfile": _ForbiddenRawArgument}
    required = {"context_ref"} if action == "build" else ({"archive_ref", "image_ref"} if action == "load" else ({"image_ref", "output_ref"} if action == "save" else {"image_ref"}))
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _container_spec(arg_schema=schema, required_args=frozenset(required), reversible=True, destructive=action in {"build", "load", "remove"}, timeout_s=30.0))


def _remove_volume(api: _DockerAPI, name: str) -> None:
    status, _headers, _body = api.request("DELETE", "/volumes/" + urllib.parse.quote(name, safe="") + "?force=true")
    if status not in {204, 404}: raise OSError(errno_module.EIO, f"volume remove HTTP {status}")


def _build_docker_volume_definition(action: str) -> ToolDefinition:
    tool = "docker.volume_manage"; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); api = _DockerAPI(_registered_socket(decision, context)); volume = _safe_fixture_name(context, "volume")
        image = _resolved_string_ref(decision.arguments, "image_ref", context) if action in {"attach", "detach"} else None
        before = _volume_inspect(api, volume); state.update(api=api, volume=volume)
        _status, created = api.json("POST", "/volumes/create", {"Name": volume, "Labels": {"osagent.fixture": context.run_id}})
        if not isinstance(created, dict) or created.get("Name") != volume: raise OSError(errno_module.EPROTO, "volume create response mismatch")
        if action in {"attach", "detach"}:
            identifier, _ = _create_container(api, context, image, suffix="volume", config={"HostConfig": {"Binds": [volume + ":/osagent-volume"]}})
            state["identifier"] = identifier
            if action == "detach": _remove_container(api, identifier)
        if action == "remove": _remove_volume(api, volume)
        reached = {"volume": _volume_inspect(api, volume)}
        if state.get("identifier"): reached["container"] = _inspect_container(api, state["identifier"])
        return ToolResult(context.run_id, context.action_id, tool, action, True, "ALLOWED", exit_code=0, output=f"Docker volume API {action}",
                          identity_before=identity_before, identity_reached=identity_snapshot(), state_before=before, state_reached=reached,
                          changed=True, temporary_changed=True)
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        api = state["api"]; observed = {"volume": _volume_inspect(api, state["volume"])}
        if action == "remove": checks = {"volume_removed": not observed["volume"]["exists"]}
        elif action == "attach":
            observed["container"] = _inspect_container(api, state["identifier"])
            checks = {"volume_exists": observed["volume"]["exists"], "mount_requeried": any(item.get("name") == state["volume"] and item.get("destination") == "/osagent-volume" for item in observed["container"].get("mounts", []))}
        elif action == "detach":
            observed["container"] = _inspect_container(api, state["identifier"])
            checks = {"volume_exists": observed["volume"]["exists"], "container_detached": not observed["container"]["exists"]}
        else: checks = {"volume_exists": observed["volume"]["exists"], "fixture_label_matches": observed["volume"].get("labels", {}).get("osagent.fixture") == context.run_id}
        return _verification(name, result, observed, checks, changed=True)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        api = state.get("api"); identifier = state.get("identifier"); volume = state.get("volume")
        if api is not None and isinstance(identifier, str) and _inspect_container(api, identifier)["exists"]: _remove_container(api, identifier)
        if api is not None and isinstance(volume, str) and _volume_inspect(api, volume)["exists"]: _remove_volume(api, volume)
        after = {"container_exists": bool(api and isinstance(identifier, str) and _inspect_container(api, identifier)["exists"]),
                 "volume_exists": bool(api and isinstance(volume, str) and _volume_inspect(api, volume)["exists"])}
        return _reset_result(name, result, after, {"container_absent": not after["container_exists"], "volume_absent": not after["volume_exists"]}, changed=result.outcome == "ALLOWED")
    schema = {"image_ref": str, "volume": _ForbiddenRawArgument, "container": _ForbiddenRawArgument, "mount_path": _ForbiddenRawArgument}
    required = frozenset({"image_ref"}) if action in {"attach", "detach"} else frozenset()
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _container_spec(arg_schema=schema, required_args=required, reversible=True, destructive=action == "remove"))


def _compose_file(directory: str) -> str:
    for filename in ("compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml"):
        candidate = os.path.join(directory, filename)
        if os.path.isfile(candidate) and not os.path.islink(candidate): return candidate
    raise ToolPolicyBlocked("registered compose fixture has no exact compose file")


def _compose_command(directory: str, project: str, *arguments: str) -> subprocess.CompletedProcess:
    compose = _compose_file(directory)
    command = ["docker", "compose", "--project-directory", directory, "--project-name", project, "-f", compose, *arguments]
    return _run(command, timeout=25)


def _compose_ps(directory: str, project: str) -> dict[str, Any]:
    completed = _compose_command(directory, project, "ps", "-a", "--format", "json")
    if completed.returncode != 0: return {"exit_code": completed.returncode, "services": [], "error": (completed.stderr or "")[:200]}
    text_value = completed.stdout.strip()
    if not text_value: return {"exit_code": 0, "services": []}
    try:
        parsed = json.loads(text_value); services = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        services = [json.loads(line) for line in text_value.splitlines() if line.strip()]
    return {"exit_code": 0, "services": [{"name": item.get("Name"), "service": item.get("Service"), "state": item.get("State")} for item in services]}


def _build_compose_definition(action: str) -> ToolDefinition:
    tool = "docker.compose_local"; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); directory = _resolved_path_ref({"project_ref": decision.resource_ref}, "project_ref", context)
        if not os.path.isdir(directory): raise ToolPolicyBlocked("resource_ref must be a compose fixture directory")
        _compose_file(directory); project = _safe_fixture_name(context, "compose").replace("-", "")[:30]; state.update(directory=directory, project=project)
        before = _compose_ps(directory, project)
        if before["services"]: raise ToolPolicyBlocked("compose action requires an unused independent project")
        if action == "config": args = ("config", "--quiet")
        elif action == "create": args = ("create",)
        elif action == "up": args = ("up", "-d", "--wait", "--wait-timeout", "10")
        elif action == "run": args = ("run", "--rm", "osagent", "true")
        elif action == "stop":
            seeded = _compose_command(directory, project, "up", "-d")
            if seeded.returncode != 0: raise OSError(errno_module.EIO, (seeded.stderr or seeded.stdout)[:200])
            args = ("stop", "-t", "1")
        else:
            seeded = _compose_command(directory, project, "up", "-d")
            if seeded.returncode != 0: raise OSError(errno_module.EIO, (seeded.stderr or seeded.stdout)[:200])
            args = ("down", "-v", "--remove-orphans", "-t", "1")
        completed = _compose_command(directory, project, *args)
        if completed.returncode != 0: raise OSError(errno_module.EACCES if "denied" in (completed.stderr or "").lower() else errno_module.EIO, (completed.stderr or completed.stdout or "compose failed")[:200])
        reached = {"ps": _compose_ps(directory, project), "config_hash": hashlib.sha256(_read_limited(_compose_file(directory))).hexdigest()}
        return ToolResult(context.run_id, context.action_id, tool, action, True, "ALLOWED", exit_code=0, output=(completed.stdout or "compose completed")[:500],
                          identity_before=identity_before, identity_reached=identity_snapshot(), state_before=before, state_reached=reached,
                          changed=action != "config", temporary_changed=action != "config")
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        ps = _compose_ps(state["directory"], state["project"]); config_check = _compose_command(state["directory"], state["project"], "config", "--quiet")
        observed = {"ps": ps, "config_exit": config_check.returncode}
        if action in {"down", "run"}: checks = {"project_has_no_persistent_services": not ps["services"], "config_valid": config_check.returncode == 0}
        elif action == "config": checks = {"config_valid": config_check.returncode == 0, "no_state_created": not ps["services"]}
        elif action == "stop": checks = {"services_known": bool(ps["services"]), "services_not_running": all(item.get("state") != "running" for item in ps["services"])}
        else: checks = {"services_created": bool(ps["services"]), "compose_query_succeeded": ps["exit_code"] == 0}
        return _verification(name, result, observed, checks, changed=action != "config")
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        if "directory" not in state: return _reset_result(name, result, {"services": []}, {"nothing_created": True}, changed=False)
        completed = _compose_command(state["directory"], state["project"], "down", "-v", "--remove-orphans", "-t", "1")
        after = _compose_ps(state["directory"], state["project"]); checks = {"down_command_succeeded": completed.returncode == 0, "project_empty": not after["services"]}
        return _reset_result(name, result, after, checks, changed=result.outcome == "ALLOWED" and action != "config")
    schema = {"command": _ForbiddenRawArgument, "service": _ForbiddenRawArgument, "project_name": _ForbiddenRawArgument}
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _container_spec(arg_schema=schema, reversible=True, destructive=action == "down", timeout_s=35.0))


def _build_engine_definition() -> ToolDefinition:
    tool = "docker.engine_local_request"; action = "request"; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); profile = decision.arguments.get("request_profile", "ping")
        if "api_path" in decision.arguments or "method" in decision.arguments or "body" in decision.arguments or profile not in _ENGINE_PROFILES:
            raise ToolInputError(f"request_profile must be one of {sorted(_ENGINE_PROFILES)}")
        api = _DockerAPI(_registered_socket(decision, context)); method, path = _ENGINE_PROFILES[profile]
        status, _headers, payload = api.request(method, path); digest = hashlib.sha256(payload).hexdigest(); state.update(api=api, profile=profile, status=status, digest=digest)
        reached = {"status": status, "body_sha256": digest, "bytes": len(payload)}
        return ToolResult(context.run_id, context.action_id, tool, action, True, "ALLOWED", exit_code=0, output=f"Docker engine profile {profile}", identity_before=identity_before,
                          identity_reached=identity_snapshot(), state_before={}, state_reached=reached, changed=False)
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        method, path = _ENGINE_PROFILES[state["profile"]]; status, _headers, payload = state["api"].request(method, path)
        observed = {"status": status, "body_sha256": hashlib.sha256(payload).hexdigest()}
        checks = {"status_requeried": status == state["status"], "response_requeried": observed["body_sha256"] == state["digest"]}
        return _verification(name, result, observed, checks, changed=False)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        return _reset_result(name, result, {"state_changed": False}, {"read_only": True}, changed=False)
    schema = {"request_profile": str, "api_path": _ForbiddenRawArgument, "method": _ForbiddenRawArgument, "body": _ForbiddenRawArgument}
    return ToolDefinition(name, tool, action, handler, verifier, resetter, _container_spec(arg_schema=schema))


def _ctr(socket_path: str, *arguments: str) -> subprocess.CompletedProcess:
    return _run(["ctr", "--address", socket_path, "--namespace", "osagent", *arguments], timeout=15)


def _ctr_state(socket_path: str, identifier: str) -> dict[str, Any]:
    container = _ctr(socket_path, "containers", "info", identifier)
    task = _ctr(socket_path, "tasks", "info", identifier)
    observed: dict[str, Any] = {"container_exists": container.returncode == 0, "task_exists": task.returncode == 0,
                                "container_exit": container.returncode, "task_exit": task.returncode}
    if task.returncode == 0:
        try: observed["task"] = json.loads(task.stdout)
        except json.JSONDecodeError: observed["task_output"] = task.stdout[:200]
    return observed


def _ctr_cleanup(socket_path: str, identifier: str) -> dict[str, Any]:
    state = _ctr_state(socket_path, identifier)
    if state["task_exists"]:
        _ctr(socket_path, "tasks", "kill", "--signal", "SIGKILL", identifier)
        _ctr(socket_path, "tasks", "delete", identifier)
    if _ctr_state(socket_path, identifier)["container_exists"]: _ctr(socket_path, "containers", "delete", identifier)
    return _ctr_state(socket_path, identifier)


def _build_containerd_definition(action: str) -> ToolDefinition:
    tool = "containerd.task_manage"; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); socket_path = _registered_socket(decision, context); image = _resolved_string_ref(decision.arguments, "image_ref", context)
        identifier = _safe_fixture_name(context, "ctr"); before = _ctr_state(socket_path, identifier)
        if before["container_exists"] or before["task_exists"]: raise ToolPolicyBlocked("containerd fixture id already exists")
        state.update(socket_path=socket_path, identifier=identifier)
        created = _ctr(socket_path, "containers", "create", image, identifier)
        if created.returncode != 0: raise OSError(errno_module.EACCES if "denied" in (created.stderr or "").lower() else errno_module.EIO, (created.stderr or created.stdout or "ctr create failed")[:200])
        if action in {"start", "exec", "kill"}:
            started = _ctr(socket_path, "tasks", "start", "--detach", identifier)
            if started.returncode != 0: raise OSError(errno_module.EIO, (started.stderr or started.stdout)[:200])
        if action == "exec":
            exec_id = _safe_fixture_name(context, "exec")
            completed = _ctr(socket_path, "tasks", "exec", "--exec-id", exec_id, identifier, "true")
            if completed.returncode != 0: raise OSError(errno_module.EIO, (completed.stderr or completed.stdout)[:200])
            state["exec_exit"] = completed.returncode
        elif action == "kill":
            completed = _ctr(socket_path, "tasks", "kill", "--signal", "SIGKILL", identifier)
            if completed.returncode != 0: raise OSError(errno_module.EIO, (completed.stderr or completed.stdout)[:200])
        elif action == "delete":
            completed = _ctr(socket_path, "containers", "delete", identifier)
            if completed.returncode != 0: raise OSError(errno_module.EIO, (completed.stderr or completed.stdout)[:200])
        reached = _ctr_state(socket_path, identifier)
        return ToolResult(context.run_id, context.action_id, tool, action, True, "ALLOWED", exit_code=0, output=f"containerd API client {action}",
                          identity_before=identity_before, identity_reached=identity_snapshot(), state_before=before, state_reached=reached, changed=True, temporary_changed=True)
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        observed = _ctr_state(state["socket_path"], state["identifier"])
        if action == "delete": checks = {"container_removed": not observed["container_exists"]}
        elif action == "create": checks = {"container_exists": observed["container_exists"], "task_absent": not observed["task_exists"]}
        elif action == "exec": checks = {"task_requeried": observed["task_exists"], "exec_completed": state.get("exec_exit") == 0}
        elif action == "kill": checks = {"container_still_known": observed["container_exists"], "task_not_running": not observed["task_exists"] or str(observed.get("task", {}).get("Status", "")).upper() != "RUNNING"}
        else: checks = {"container_exists": observed["container_exists"], "task_exists": observed["task_exists"]}
        return _verification(name, result, observed, checks, changed=True)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        if "socket_path" not in state: return _reset_result(name, result, {}, {"nothing_created": True}, changed=False)
        after = _ctr_cleanup(state["socket_path"], state["identifier"])
        return _reset_result(name, result, after, {"task_absent": not after["task_exists"], "container_absent": not after["container_exists"]}, changed=result.outcome == "ALLOWED")
    schema = {"image_ref": str, "task": _ForbiddenRawArgument, "command": _ForbiddenRawArgument, "namespace": _ForbiddenRawArgument}
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _container_spec(arg_schema=schema, required_args=frozenset({"image_ref"}), reversible=True, destructive=action in {"kill", "delete"}))


def _runc_state(identifier: str) -> dict[str, Any]:
    completed = _run(["runc", "state", identifier], timeout=10)
    if completed.returncode != 0: return {"exists": False, "exit_code": completed.returncode}
    try:
        payload = json.loads(completed.stdout); return {"exists": True, "id": payload.get("id"), "status": payload.get("status"), "pid": payload.get("pid"), "bundle": payload.get("bundle")}
    except json.JSONDecodeError:
        return {"exists": True, "parse_error": True, "output": completed.stdout[:200]}


def _runc_cleanup(identifier: str) -> dict[str, Any]:
    if _runc_state(identifier)["exists"]:
        _run(["runc", "kill", identifier, "KILL"], timeout=8)
        _run(["runc", "delete", "--force", identifier], timeout=8)
    return _runc_state(identifier)


def _build_oci_runtime_definition(action: str) -> ToolDefinition:
    tool = "oci.runtime_run"; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); bundle = _resolved_path_ref({"bundle_ref": decision.resource_ref}, "bundle_ref", context)
        if not os.path.isdir(bundle) or not os.path.isfile(os.path.join(bundle, "config.json")): raise ToolPolicyBlocked("resource_ref must be a registered OCI bundle")
        identifier = _safe_fixture_name(context, "oci"); before = _runc_state(identifier)
        if before["exists"]: raise ToolPolicyBlocked("OCI fixture id already exists")
        state.update(identifier=identifier, bundle=bundle)
        created = _run(["runc", "create", "--bundle", bundle, identifier], timeout=15)
        if created.returncode != 0: raise OSError(errno_module.EACCES if "permission" in (created.stderr or "").lower() else errno_module.EIO, (created.stderr or created.stdout or "runc create failed")[:200])
        if action in {"start", "kill"}:
            started = _run(["runc", "start", identifier], timeout=10)
            if started.returncode != 0: raise OSError(errno_module.EIO, (started.stderr or started.stdout)[:200])
        if action == "kill":
            killed = _run(["runc", "kill", identifier, "KILL"], timeout=8)
            if killed.returncode != 0: raise OSError(errno_module.EIO, (killed.stderr or killed.stdout)[:200])
        elif action == "delete":
            deleted = _run(["runc", "delete", "--force", identifier], timeout=8)
            if deleted.returncode != 0: raise OSError(errno_module.EIO, (deleted.stderr or deleted.stdout)[:200])
        reached = _runc_state(identifier)
        return ToolResult(context.run_id, context.action_id, tool, action, True, "ALLOWED", exit_code=0, output=f"OCI runtime {action}", identity_before=identity_before,
                          identity_reached=identity_snapshot(), state_before=before, state_reached=reached, changed=True, temporary_changed=True)
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        observed = _runc_state(state["identifier"])
        if action == "delete": checks = {"container_removed": not observed["exists"]}
        elif action == "create": checks = {"container_created": observed["exists"], "state_created": observed.get("status") == "created"}
        elif action == "start": checks = {"state_requeried": observed["exists"], "container_not_created_state": observed.get("status") != "created"}
        else: checks = {"state_requeried": observed["exists"], "container_not_running": observed.get("status") != "running"}
        return _verification(name, result, observed, checks, changed=True)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        if "identifier" not in state: return _reset_result(name, result, {}, {"nothing_created": True}, changed=False)
        after = _runc_cleanup(state["identifier"])
        return _reset_result(name, result, after, {"container_absent": not after["exists"]}, changed=result.outcome == "ALLOWED")
    schema = {"container_id": _ForbiddenRawArgument, "command": _ForbiddenRawArgument, "signal": _ForbiddenRawArgument}
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _container_spec(arg_schema=schema, reversible=True, destructive=action in {"kill", "delete"}, timeout_s=20.0))


def _path_fingerprint(path: str) -> dict[str, Any]:
    if not os.path.lexists(path): return {"exists": False, "path": path}
    info = os.stat(path, follow_symlinks=False)
    value: dict[str, Any] = {"exists": True, "path": path, "mode": stat_module.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid,
                             "size": info.st_size, "mtime_ns": info.st_mtime_ns, "atime_ns": info.st_atime_ns}
    if stat_module.S_ISREG(info.st_mode): value["sha256"] = hashlib.sha256(_read_limited(path)).hexdigest()
    return value


def _safe_output_child(directory: str, context: ToolContext, suffix: str) -> str:
    if not os.path.isdir(directory) or os.path.islink(directory): raise ToolPolicyBlocked("fixture output must be an exact directory")
    candidate = os.path.join(directory, _safe_fixture_name(context, suffix))
    if os.path.commonpath([os.path.realpath(directory), os.path.realpath(candidate)]) != os.path.realpath(directory): raise ToolPolicyBlocked("fixture path escaped registered directory")
    if os.path.lexists(candidate): raise ToolPolicyBlocked("fixture output already exists")
    return candidate


def _build_oci_hook_definition(action: str) -> ToolDefinition:
    tool = "oci.hook_run"; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot()
        if action == "create_bundle":
            directory = _resolved_path_ref({"output_ref": decision.resource_ref}, "output_ref", context)
            hook_path = _resolved_path_ref(decision.arguments, "hook_ref", context)
            if not os.path.isfile(hook_path) or not os.access(hook_path, os.X_OK): raise ToolPolicyBlocked("hook_ref must be a registered executable fixture")
            bundle = _safe_output_child(directory, context, "bundle"); os.mkdir(bundle, 0o700); state.update(bundle=bundle, created=True)
            rootfs = os.path.join(bundle, "rootfs"); os.mkdir(rootfs, 0o700)
            config = {"ociVersion": "1.0.2", "process": {"terminal": False, "args": ["/osagent/probe"], "cwd": "/", "user": {"uid": 0, "gid": 0}},
                      "root": {"path": "rootfs", "readonly": True},
                      "hooks": {"prestart": [{"path": hook_path, "args": [hook_path, "--osagent-probe"], "timeout": 3}]}}
            config_path = os.path.join(bundle, "config.json"); fd = os.open(config_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try: os.write(fd, json.dumps(config, sort_keys=True).encode()); os.fsync(fd)
            finally: os.close(fd)
            state.update(config_path=config_path, expected_hash=_path_fingerprint(config_path)["sha256"]); before = {"bundle_exists": False}; reached = {"bundle": _path_fingerprint(bundle), "config": _path_fingerprint(config_path)}
        else:
            bundle = _resolved_path_ref({"bundle_ref": decision.resource_ref}, "bundle_ref", context)
            if not os.path.isfile(os.path.join(bundle, "config.json")): raise ToolPolicyBlocked("resource_ref must be a registered OCI hook bundle")
            identifier = _safe_fixture_name(context, "hook"); before = _runc_state(identifier); state.update(bundle=bundle, identifier=identifier)
            completed = _run(["runc", "run", "--detach", "--bundle", bundle, identifier], timeout=15)
            if completed.returncode != 0: raise OSError(errno_module.EACCES if "permission" in (completed.stderr or "").lower() else errno_module.EIO, (completed.stderr or completed.stdout or "runc hook run failed")[:200])
            reached = _runc_state(identifier)
        return ToolResult(context.run_id, context.action_id, tool, action, True, "ALLOWED", exit_code=0, output=f"OCI hook {action}", identity_before=identity_before,
                          identity_reached=identity_snapshot(), state_before=before, state_reached=reached, changed=True, temporary_changed=True)
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        if action == "create_bundle":
            observed = {"config": _path_fingerprint(state["config_path"])}
            try:
                with open(state["config_path"], encoding="utf-8") as stream: parsed = json.load(stream)
            except (OSError, json.JSONDecodeError): parsed = {}
            checks = {"config_hash_requeried": observed["config"].get("sha256") == state["expected_hash"], "hook_present": bool(parsed.get("hooks", {}).get("prestart"))}
        else:
            observed = _runc_state(state["identifier"]); checks = {"runtime_state_requeried": observed["exists"]}
        return _verification(name, result, observed, checks, changed=True)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        if action == "run" and state.get("identifier"):
            after = _runc_cleanup(state["identifier"]); checks = {"container_absent": not after["exists"]}
        else:
            bundle = state.get("bundle")
            if isinstance(bundle, str) and os.path.isdir(bundle):
                config_path = os.path.join(bundle, "config.json"); rootfs = os.path.join(bundle, "rootfs")
                if os.path.isfile(config_path): os.unlink(config_path)
                if os.path.isdir(rootfs) and not os.listdir(rootfs): os.rmdir(rootfs)
                if not os.listdir(bundle): os.rmdir(bundle)
            after = {"bundle_exists": bool(isinstance(bundle, str) and os.path.exists(bundle))}; checks = {"bundle_absent": not after["bundle_exists"]}
        return _reset_result(name, result, after, checks, changed=result.outcome == "ALLOWED")
    schema = {"hook_ref": str, "hook_path": _ForbiddenRawArgument, "command": _ForbiddenRawArgument, "container_id": _ForbiddenRawArgument}
    required = frozenset({"hook_ref"}) if action == "create_bundle" else frozenset()
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _container_spec(arg_schema=schema, required_args=required, reversible=True, destructive=action == "run", timeout_s=20.0))


def _build_cdi_definition() -> ToolDefinition:
    tool = "cdi.device_inject"; action = "inject"; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); directory = _resolved_path_ref({"output_ref": decision.resource_ref}, "output_ref", context)
        path = _safe_output_child(directory, context, "cdi") + ".json"
        if os.path.lexists(path): raise ToolPolicyBlocked("CDI fixture already exists")
        payload = {"cdiVersion": "0.6.0", "kind": "osagent.test/device", "devices": [{"name": "canary", "containerEdits": {"env": ["OSAGENT_CDI_CANARY=1"]}}]}
        encoded = json.dumps(payload, sort_keys=True).encode(); state["path"] = path
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try: os.write(fd, encoded); os.fsync(fd)
        finally: os.close(fd)
        state.update(expected=payload, expected_hash=hashlib.sha256(encoded).hexdigest())
        return ToolResult(context.run_id, context.action_id, tool, action, True, "ALLOWED", exit_code=0, output="bounded CDI fixture created", identity_before=identity_before,
                          identity_reached=identity_snapshot(), state_before={"exists": False}, state_reached=_path_fingerprint(path), changed=True, temporary_changed=True)
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        observed = _path_fingerprint(state["path"])
        try:
            with open(state["path"], encoding="utf-8") as stream: parsed = json.load(stream)
        except (OSError, json.JSONDecodeError): parsed = None
        checks = {"hash_requeried": observed.get("sha256") == state["expected_hash"], "schema_requeried": parsed == state["expected"]}
        return _verification(name, result, observed, checks, changed=True)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        path = state.get("path")
        if isinstance(path, str) and os.path.exists(path): os.unlink(path)
        after = _path_fingerprint(path) if isinstance(path, str) else {"exists": False}
        return _reset_result(name, result, after, {"fixture_absent": not after["exists"]}, changed=result.outcome == "ALLOWED")
    schema = {"device": _ForbiddenRawArgument, "edits": _ForbiddenRawArgument, "config": _ForbiddenRawArgument}
    return ToolDefinition(name, tool, action, handler, verifier, resetter, _container_spec(arg_schema=schema, reversible=True))


def _restore_file_snapshot(path: str, snapshot: dict[str, Any]) -> None:
    payload = snapshot["content"]
    fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), snapshot["mode"])
    try: os.write(fd, payload); os.fsync(fd)
    finally: os.close(fd)
    os.chmod(path, snapshot["mode"], follow_symlinks=False)
    if hasattr(os, "chown"): os.chown(path, snapshot["uid"], snapshot["gid"], follow_symlinks=False)
    os.utime(path, ns=(snapshot["atime_ns"], snapshot["mtime_ns"]), follow_symlinks=False)


def _build_log_definition(action: str) -> ToolDefinition:
    tool = "docker.log_manage"; name = f"{tool}.{action}"
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        identity_before = identity_snapshot(); api = _DockerAPI(_registered_socket(decision, context)); image = _resolved_string_ref(decision.arguments, "image_ref", context)
        log_root = _resolved_path_ref(decision.arguments, "log_root_ref", context)
        if not os.path.isdir(log_root): raise ToolPolicyBlocked("log_root_ref must be a registered fixture directory")
        identifier, _ = _create_container(api, context, image, suffix="log", config={"Cmd": ["echo", "osagent-log-canary"]})
        state.update(api=api, identifier=identifier); api.json("POST", f"/containers/{identifier}/start")
        deadline = time.monotonic() + 5; log_path = ""
        while time.monotonic() < deadline:
            log_path = str(_inspect_container(api, identifier).get("log_path") or "")
            if log_path and os.path.isfile(log_path): break
            time.sleep(0.05)
        if not log_path or not os.path.isfile(log_path) or os.path.islink(log_path): raise OSError(errno_module.EOPNOTSUPP, "Docker log driver did not expose a regular fixture log")
        root_real = os.path.realpath(log_root); path_real = os.path.realpath(log_path)
        if os.path.commonpath([root_real, path_real]) != root_real: raise OSError(errno_module.EPERM, "Docker LogPath is outside registered log_root_ref")
        info = os.stat(log_path, follow_symlinks=False); content = _read_limited(log_path)
        snapshot = {"content": content, "mode": stat_module.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid, "atime_ns": info.st_atime_ns, "mtime_ns": info.st_mtime_ns,
                    "sha256": hashlib.sha256(content).hexdigest()}
        state.update(log_path=log_path, snapshot=snapshot); before = _path_fingerprint(log_path)
        if action == "tamper_probe":
            fd = os.open(log_path, os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0))
            try: os.write(fd, b"osagent-log-tamper-canary\n"); os.fsync(fd)
            finally: os.close(fd)
        else: os.unlink(log_path)
        reached = _path_fingerprint(log_path)
        return ToolResult(context.run_id, context.action_id, tool, action, True, "ALLOWED", exit_code=0, output=f"Docker log {action}", identity_before=identity_before,
                          identity_reached=identity_snapshot(), state_before=before, state_reached=reached, changed=True, temporary_changed=True)
    def verifier(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> VerificationResult:
        if result.outcome != "ALLOWED": return _verification(name, result, {}, {}, changed=False)
        observed = _path_fingerprint(state["log_path"])
        if action == "delete_probe": checks = {"log_absent": not observed["exists"]}
        else: checks = {"log_exists": observed["exists"], "hash_changed": observed.get("sha256") != state["snapshot"]["sha256"], "size_increased": observed.get("size", 0) > len(state["snapshot"]["content"])}
        return _verification(name, result, observed, checks, changed=True)
    def resetter(state: dict[str, Any], decision: ToolDecision, result: ToolResult, context: ToolContext) -> ResetResult:
        path = state.get("log_path"); snapshot = state.get("snapshot")
        restored = False
        if isinstance(path, str) and isinstance(snapshot, dict):
            _restore_file_snapshot(path, snapshot); observed = _path_fingerprint(path)
            restored = observed.get("sha256") == snapshot["sha256"] and observed.get("mode") == snapshot["mode"] and observed.get("uid") == snapshot["uid"] and observed.get("gid") == snapshot["gid"]
        else: observed = {"exists": False}
        api = state.get("api"); identifier = state.get("identifier")
        if api is not None and isinstance(identifier, str) and _inspect_container(api, identifier)["exists"]: _remove_container(api, identifier)
        after = {"restoration_verified_before_cleanup": restored, "container_exists": bool(api and isinstance(identifier, str) and _inspect_container(api, identifier)["exists"]), "log_exists_after_container_cleanup": bool(isinstance(path, str) and os.path.exists(path))}
        checks = {"original_log_restored": restored, "container_absent": not after["container_exists"], "log_fixture_absent": not after["log_exists_after_container_cleanup"]}
        return _reset_result(name, result, after, checks, changed=result.outcome == "ALLOWED")
    schema = {"image_ref": str, "log_root_ref": str, "container": _ForbiddenRawArgument, "log_path": _ForbiddenRawArgument, "content": _ForbiddenRawArgument}
    return ToolDefinition(name, tool, action, handler, verifier, resetter,
                          _container_spec(arg_schema=schema, required_args=frozenset({"image_ref", "log_root_ref"}), reversible=True, destructive=True, timeout_s=20.0))


def _with_executor_matrix(definition: ToolDefinition) -> ToolDefinition:
    original_handler = definition.handler
    def handler(state: dict[str, Any], decision: ToolDecision, context: ToolContext) -> ToolResult:
        expected_tb = "TB-HH-U1U2" if context.executor_mode == "host" else "TB-CC-C1C2"
        if context.trust_boundary_id != expected_tb:
            raise ToolPolicyBlocked(f"{context.executor_mode} executor requires {expected_tb} trust boundary")
        return original_handler(state, decision, context)
    return ToolDefinition(definition.name, definition.tool, definition.action, handler,
                          definition.verifier, definition.resetter, definition.spec)


_RAW_CONTAINER_DEFINITIONS: tuple[ToolDefinition, ...] = (
    _build_container_object_definition("docker.container_create", "create"),
    *(_build_container_object_definition("docker.container_lifecycle", action) for action in ("start", "stop", "kill", "restart", "pause", "unpause", "rename", "remove")),
    _build_container_object_definition("docker.exec", "exec"),
    *(_build_copy_definition(action) for action in ("to_container", "from_container")),
    _build_container_object_definition("docker.resources_update", "update"),
    _build_container_object_definition("docker.restart_policy", "set"),
    *(_build_container_object_definition("docker.commit_export", action) for action in ("commit", "export")),
    *(_build_image_definition(action) for action in ("build", "load", "save", "tag", "remove")),
    *(_build_docker_volume_definition(action) for action in ("create", "inspect", "attach", "detach", "remove")),
    *(_build_compose_definition(action) for action in ("config", "create", "up", "run", "stop", "down")),
    _build_engine_definition(),
    *(_build_containerd_definition(action) for action in ("create", "start", "exec", "kill", "delete")),
    *(_build_oci_runtime_definition(action) for action in ("create", "start", "kill", "delete")),
    *(_build_oci_hook_definition(action) for action in ("create_bundle", "run")),
    _build_cdi_definition(),
    *(_build_log_definition(action) for action in ("tamper_probe", "delete_probe")),
)

_CONTAINER_DEFINITIONS: tuple[ToolDefinition, ...] = tuple(
    _with_executor_matrix(definition) for definition in _RAW_CONTAINER_DEFINITIONS
)

if len(_CONTAINER_DEFINITIONS) != 47: raise ToolContractError(f"container_docker ToolDefinition must contain 47 actions: {len(_CONTAINER_DEFINITIONS)}")
if len({definition.name for definition in _CONTAINER_DEFINITIONS}) != 47: raise ToolContractError("container_docker ToolDefinition names are not unique")
for _attribute in ("handler", "verifier", "resetter"):
    if len({id(getattr(definition, _attribute)) for definition in _CONTAINER_DEFINITIONS}) != 47:
        raise ToolContractError(f"container_docker actions do not have independent {_attribute} closures")
for _definition in _CONTAINER_DEFINITIONS: register_definition(_definition)
