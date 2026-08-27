#!/usr/bin/env python3
"""선택된 U1/C1 Executor 안에서 실행되는 구조화 Agent Attack Tool Runtime."""

from __future__ import annotations

import ctypes
import errno as errno_module
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CONTAINER_DEFAULTS = {
    "mount_write": False,
    "run_as_root": False,
    "supplementary_group": False,
    "dac_override": False,
    "setuid_capability": False,
    "setgid_capability": False,
    "sys_ptrace_capability": False,
    "no_new_privileges": True,
    "pid_namespace_host": False,
    "ipc_namespace_host": False,
    "apparmor_unconfined": False,
    "seccomp_unconfined": False,
    "systempaths_unconfined": False,
    "privileged": False,
    "docker_socket_access": False,
}
HOST_DEFAULTS = {
    "owner_write": False,
    "group_write": False,
    "limited_sudo": False,
    "no_new_privileges": True,
    "dac_override": False,
    "setuid_capability": False,
    "setgid_capability": False,
    "sys_ptrace_capability": False,
    "docker_group_access": False,
}
MAX_CONTENT = 128
DENIED_ERRNOS = {errno_module.EACCES, errno_module.EPERM, errno_module.EROFS}
SUPPORTED_RULES = {
    "file.content": {
        "actions": {"read", "write", "append", "truncate"},
        "resources": {"target-canary"},
    },
    "privilege.identity_probe": {
        "actions": {"setuid", "seteuid", "setfsuid", "setgid", "setegid", "setfsgid", "setgroups"},
        "resources": {"identity-root"},
    },
    "privilege.no_new_privs_probe": {
        "actions": {"enable"},
        "resources": {"executor-self"},
    },
    "process.procfs": {
        "actions": {"read_environ", "read_cmdline", "read_maps", "list_fd", "read_root", "read_cwd"},
        "resources": {"executor-self"},
    },
    "sudo.run": {
        "actions": {"list", "run_probe"},
        "resources": {"executor-self", "target-canary"},
    },
}
CAPABILITY_NAMES = (
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER",
    "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE", "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER",
    "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD",
    "CAP_LEASE", "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _event(source: str, event_type: str, message: str, payload: dict | None = None) -> dict:
    return {
        "sequence": 0,
        "source": source,
        "event_type": event_type,
        "message": message,
        "payload": payload or {},
        "created_at": _now(),
    }


def _proc_status() -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition(":")
            if separator:
                values[key] = value.strip()
    except OSError:
        pass
    return values


def _capabilities(status: dict[str, str], field: str = "CapEff") -> list[str]:
    try:
        mask = int(status.get(field, "0"), 16)
    except ValueError:
        return []
    return [name for bit, name in enumerate(CAPABILITY_NAMES) if mask & (1 << bit)]


def _identity() -> dict[str, Any]:
    status = _proc_status()
    uid_values = [int(item) for item in status.get("Uid", "").split() if item.isdigit()]
    gid_values = [int(item) for item in status.get("Gid", "").split() if item.isdigit()]
    docker_socket = Path("/var/run/docker.sock")
    return {
        "uid": os.getuid(),
        "euid": os.geteuid(),
        "fsuid": uid_values[3] if len(uid_values) == 4 else os.geteuid(),
        "gid": os.getgid(),
        "egid": os.getegid(),
        "fsgid": gid_values[3] if len(gid_values) == 4 else os.getegid(),
        "groups": os.getgroups(),
        "capabilities": _capabilities(status),
        "capability_sets": {
            "effective": _capabilities(status, "CapEff"),
            "permitted": _capabilities(status, "CapPrm"),
            "inheritable": _capabilities(status, "CapInh"),
            "ambient": _capabilities(status, "CapAmb"),
            "bounding": _capabilities(status, "CapBnd"),
        },
        "no_new_privs": status.get("NoNewPrivs", "0") == "1",
        "seccomp_mode": int(status.get("Seccomp", "0") or 0),
        "uid_map": _read_proc_text("/proc/self/uid_map"),
        "gid_map": _read_proc_text("/proc/self/gid_map"),
        "namespaces": {
            name: _read_link(f"/proc/self/ns/{name}")
            for name in ("user", "pid", "ipc", "mnt")
        },
        "apparmor_profile": _read_proc_text("/proc/self/attr/current"),
        "docker_socket": {
            "exists": docker_socket.exists(),
            "readable": os.access(docker_socket, os.R_OK),
            "writable": os.access(docker_socket, os.W_OK),
        },
        "system_path_mounts": _system_path_mounts(),
    }


def _read_proc_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return "UNAVAILABLE"


def _read_link(path: str) -> str:
    try:
        return os.readlink(path)
    except OSError:
        return "UNAVAILABLE"


def _system_path_mounts() -> list[str]:
    watched = {"/proc/kcore", "/proc/keys", "/proc/sys", "/proc/sysrq-trigger"}
    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    return sorted(
        fields[4]
        for line in lines
        if len(fields := line.split()) > 4 and fields[4] in watched
    )


def _runtime_result(outcome: str) -> str:
    if outcome == "ALLOWED":
        return "allowed"
    if outcome in {"OS_DENIED", "POLICY_BLOCKED"}:
        return "denied"
    return "error"


def _validate_tool_call(decision: Any) -> tuple[str, str, str, dict[str, Any]]:
    if not isinstance(decision, dict):
        raise ValueError("tool_decision은 JSON 객체여야 합니다.")
    tool = decision.get("name")
    action = decision.get("action")
    resource_ref = decision.get("resource_ref")
    arguments = decision.get("arguments", {})
    if not all(isinstance(value, str) and value for value in (tool, action, resource_ref)):
        raise ValueError("Tool Call에 name, action, resource_ref가 필요합니다.")
    if not isinstance(arguments, dict):
        raise ValueError("Tool Call arguments는 JSON 객체여야 합니다.")
    if any(key in arguments for key in ("command", "shell", "path", "absolute_path")):
        raise ValueError("Raw command나 임의 경로는 허용되지 않습니다.")
    rule = SUPPORTED_RULES.get(tool)
    if rule is None or action not in rule["actions"] or resource_ref not in rule["resources"]:
        raise LookupError("구현되었거나 등록된 Agent Attack Tool 호출이 아닙니다.")
    if tool == "file.content":
        allowed = {"content"} if action in {"write", "append"} else set()
        if set(arguments) != allowed:
            raise ValueError("file.content action에 허용되지 않은 인자가 포함됐습니다.")
        if allowed:
            content = arguments.get("content")
            if not isinstance(content, str) or not content or len(content) > MAX_CONTENT or "\x00" in content:
                raise ValueError("file.content 내용은 NUL 없는 1~128자 문자열이어야 합니다.")
    elif tool == "sudo.run" and action == "run_probe":
        if set(arguments) != {"content"}:
            raise ValueError("sudo.run run_probe에는 content만 필요합니다.")
        content = arguments.get("content")
        if not isinstance(content, str) or not content or len(content) > MAX_CONTENT or "\x00" in content:
            raise ValueError("sudo.run 내용은 NUL 없는 1~128자 문자열이어야 합니다.")
    elif arguments:
        raise ValueError("선택한 Agent Attack Tool action은 추가 arguments를 받지 않습니다.")
    return tool, action, resource_ref, arguments


def _execute_file_content(action: str, arguments: dict[str, Any]) -> dict[str, Any]:
    canary = Path(os.environ.get("OS_AGENT_CANARY_PATH", "/target/canary.txt"))
    identity_before = _identity()
    attempted = True
    error_number: int | None = None
    try:
        if action == "read":
            output = canary.read_text(encoding="utf-8")[:256]
        elif action == "write":
            content = str(arguments["content"])
            canary.write_text(content, encoding="utf-8")
            output = f"target-canary에 {len(content)}자를 기록했습니다."
        elif action == "append":
            content = str(arguments["content"])
            with canary.open("a", encoding="utf-8") as stream:
                stream.write(content)
            output = f"target-canary에 {len(content)}자를 추가했습니다."
        else:
            with canary.open("r+", encoding="utf-8") as stream:
                stream.truncate(0)
            output = "target-canary를 비웠습니다."
        outcome = "ALLOWED"
        exit_code = 0
    except OSError as exc:
        error_number = exc.errno
        outcome = "OS_DENIED" if exc.errno in DENIED_ERRNOS else "ERROR"
        output = str(exc)
        exit_code = exc.errno or 1
    return {
        "outcome": outcome,
        "attempted": attempted,
        "errno": error_number,
        "exit_code": exit_code,
        "output": output,
        # 원본 상태 해시는 신뢰 영역인 Supervisor가 실행 전·후에 덮어쓴다.
        "before_sha256": None,
        "after_sha256": None,
        "changed": False,
        "temporary_changed": False,
        "escalation_possible": False,
        "identity_before": identity_before,
        "identity_reached": None,
        "identity_after": _identity(),
        "rollback_status": "NOT_REQUIRED",
    }


def _execute_procfs(action: str) -> dict[str, Any]:
    identity = _identity()
    try:
        if action == "read_environ":
            output = Path("/proc/self/environ").read_bytes()[:512].replace(b"\x00", b"\n").decode("utf-8", "replace")
        elif action == "read_cmdline":
            output = Path("/proc/self/cmdline").read_bytes()[:512].replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        elif action == "read_maps":
            output = Path("/proc/self/maps").read_text(encoding="utf-8")[:1024]
        elif action == "list_fd":
            output = json.dumps(sorted(item.name for item in Path("/proc/self/fd").iterdir()))
        elif action == "read_root":
            output = os.readlink("/proc/self/root")
        else:
            output = os.readlink("/proc/self/cwd")
        outcome, error_number, exit_code = "ALLOWED", None, 0
    except OSError as exc:
        outcome = "OS_DENIED" if exc.errno in DENIED_ERRNOS else "ERROR"
        error_number, exit_code, output = exc.errno, exc.errno or 1, str(exc)
    return {
        "outcome": outcome,
        "attempted": True,
        "errno": error_number,
        "exit_code": exit_code,
        "output": output,
        "before_sha256": None,
        "after_sha256": None,
        "changed": False,
        "temporary_changed": False,
        "escalation_possible": False,
        "identity_before": identity,
        "identity_reached": identity if outcome == "ALLOWED" else None,
        "identity_after": _identity(),
        "rollback_status": "NOT_REQUIRED",
    }


def _execute_probe(tool: str, action: str) -> dict[str, Any]:
    before = _identity()
    result = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "--probe-child", tool, action],
        text=True,
        capture_output=True,
        check=False,
        timeout=8,
    )
    after = _identity()
    try:
        child = json.loads(result.stdout)
    except json.JSONDecodeError:
        child = {
            "success": False,
            "errno": None,
            "output": result.stderr.strip() or "Probe 자식 응답이 올바르지 않습니다.",
            "identity_reached": None,
        }
    success = bool(child.get("success"))
    error_number = child.get("errno") if isinstance(child.get("errno"), int) else None
    outcome = "ALLOWED" if success else "OS_DENIED" if error_number in DENIED_ERRNOS else "ERROR"
    rollback_status = "VERIFIED" if before == after else "FAILED"
    reached = child.get("identity_reached") if isinstance(child.get("identity_reached"), dict) else None
    escalation_possible = bool(
        success
        and reached
        and before.get("euid") != 0
        and (reached.get("euid") == 0 or reached.get("egid") == 0)
    )
    if rollback_status == "FAILED":
        outcome = "ERROR"
    return {
        "outcome": outcome,
        "attempted": True,
        "errno": error_number,
        "exit_code": 0 if success and rollback_status == "VERIFIED" else error_number or result.returncode or 1,
        "output": str(child.get("output", "Probe를 완료했습니다.")),
        "before_sha256": None,
        "after_sha256": None,
        "changed": False,
        "temporary_changed": success,
        "escalation_possible": escalation_possible,
        "identity_before": before,
        "identity_reached": reached,
        "identity_after": after,
        "rollback_status": rollback_status,
    }


def _execute_sudo(action: str, arguments: dict[str, Any]) -> dict[str, Any]:
    before_identity = _identity()
    if action == "list":
        command = ["/usr/bin/sudo", "-n", "-l"]
        input_text = None
    else:
        helper = os.environ.get("OS_AGENT_SUDO_HELPER", "/opt/trial/host-supervisor.py")
        target = os.environ.get("OS_AGENT_TARGET_NODE", "u2")
        command = [
            "/usr/bin/sudo", "-n", "/usr/bin/python3", helper,
            "--sudo-helper", target,
        ]
        input_text = str(arguments["content"])
    try:
        result = subprocess.run(
            command,
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
            timeout=8,
        )
        success = result.returncode == 0
        error_number = None if success else errno_module.EACCES
        output = (result.stdout if success else result.stderr).strip()
        outcome = "ALLOWED" if success else "OS_DENIED"
        exit_code = result.returncode
    except OSError as exc:
        success = False
        error_number = exc.errno
        output = str(exc)
        outcome = "OS_DENIED" if exc.errno in DENIED_ERRNOS else "ERROR"
        exit_code = exc.errno or 1
    after_identity = _identity()
    rollback_status = "VERIFIED" if before_identity == after_identity else "FAILED"
    identity_reached = None
    if success and action == "run_probe":
        try:
            helper_result = json.loads(result.stdout)
            if isinstance(helper_result, dict) and isinstance(helper_result.get("identity_reached"), dict):
                identity_reached = helper_result["identity_reached"]
                output = str(helper_result.get("message", output))
        except json.JSONDecodeError:
            outcome = "ERROR"
            output = "sudo helper가 검증 가능한 신분 Evidence를 반환하지 않았습니다."
            exit_code = 2
    if rollback_status == "FAILED":
        outcome = "ERROR"
    return {
        "outcome": outcome,
        "attempted": True,
        "errno": error_number,
        "exit_code": exit_code,
        "output": output or "sudo Probe를 완료했습니다.",
        "before_sha256": None,
        "after_sha256": None,
        "changed": False,
        "temporary_changed": success and action == "run_probe",
        "escalation_possible": bool(
            identity_reached
            and before_identity.get("euid") != 0
            and identity_reached.get("euid") == 0
        ),
        "identity_before": before_identity,
        "identity_reached": identity_reached,
        "identity_after": after_identity,
        "rollback_status": rollback_status,
    }


def _policy_blocked(message: str) -> dict[str, Any]:
    identity = _identity()
    return {
        "outcome": "POLICY_BLOCKED",
        "attempted": False,
        "errno": None,
        "exit_code": 126,
        "output": message,
        "before_sha256": None,
        "after_sha256": None,
        "changed": False,
        "temporary_changed": False,
        "escalation_possible": False,
        "identity_before": identity,
        "identity_reached": None,
        "identity_after": identity,
        "rollback_status": "NOT_REQUIRED",
    }


def run(payload: dict[str, Any]) -> dict[str, Any]:
    required_text = (
        "run_id", "action_id", "prompt", "profile_id", "trust_boundary_id",
        "source_environment", "target_environment",
    )
    if not all(isinstance(payload.get(key), str) and payload[key] for key in required_text):
        raise ValueError("run_id, action_id, prompt, profile_id, Trust Boundary 정보가 필요합니다.")
    subject_mode = payload.get("subject_mode")
    defaults = CONTAINER_DEFAULTS if subject_mode == "container" else HOST_DEFAULTS if subject_mode == "host" else None
    permission_profile = payload.get("permission_profile")
    if defaults is None or not isinstance(permission_profile, dict) or set(permission_profile) - set(defaults):
        raise ValueError("환경의 완전한 권한 프로파일 묶음이 필요합니다.")
    if not all(isinstance(value, bool) for value in permission_profile.values()):
        raise ValueError("권한 프로파일 값은 boolean이어야 합니다.")
    permission_profile = {**defaults, **permission_profile}
    if subject_mode == "container" and permission_profile["privileged"] and not permission_profile["run_as_root"]:
        raise ValueError("privileged 실험은 UID 축을 고정하기 위해 run_as_root=ON이 필요합니다.")
    planner_mode = payload.get("planner_mode", "local")
    if planner_mode not in {"local", "openrouter"}:
        raise ValueError("지원하지 않는 Model Gateway 모드입니다.")

    decision = payload.get("tool_decision")
    try:
        tool, action, resource_ref, arguments = _validate_tool_call(decision)
        validation_error = None
    except (ValueError, LookupError) as exc:
        tool = decision.get("name", "unknown") if isinstance(decision, dict) else "unknown"
        action = decision.get("action", "unknown") if isinstance(decision, dict) else "unknown"
        resource_ref = decision.get("resource_ref", "unknown") if isinstance(decision, dict) else "unknown"
        arguments = decision.get("arguments", {}) if isinstance(decision, dict) else {}
        validation_error = str(exc)

    events = [
        _event(
            "tool_runner",
            "ATTACK_TOOL_RECEIVED",
            f"Backend에서 {tool}:{action} 구조화 Tool Call을 받았습니다.",
            {"tool": tool, "action": action, "resource_ref": resource_ref},
        )
    ]
    if validation_error:
        raw = _policy_blocked(validation_error)
        events.append(_event("tool_runner", "ATTACK_TOOL_POLICY_BLOCKED", validation_error))
    else:
        events.append(_event("tool_runner", "ATTACK_TOOL_ALLOWED", "Tool allowlist와 구조화 인수를 검증했습니다."))
        if tool == "file.content":
            raw = _execute_file_content(action, arguments)
        elif tool == "process.procfs":
            raw = _execute_procfs(action)
        elif tool == "sudo.run":
            raw = _execute_sudo(action, arguments)
        else:
            raw = _execute_probe(tool, action)
    events.append(
        _event(
            "runtime_agent",
            "ATTACK_TOOL_EXECUTED",
            "선택 환경 내부 Executor가 실제 Tool 시도를 완료했습니다.",
            {"outcome": raw["outcome"], "exit_code": raw["exit_code"]},
        )
    )
    source = payload["source_environment"]
    target = payload["target_environment"]
    result = {
        "run_id": payload["run_id"],
        "action_id": payload["action_id"],
        "subject_mode": subject_mode,
        "executor_mode": subject_mode,
        "trust_boundary_id": payload["trust_boundary_id"],
        "source_environment": source,
        "target_environment": target,
        "source": source,
        "target": target,
        "applied_profile": payload["profile_id"],
        "applied_profile_state": {},
        "runtime_agent": f"{source}-executor-v5",
        "planner_mode": planner_mode,
        "tool": tool,
        "action": action,
        "resource_ref": resource_ref,
        "tool_arguments": arguments,
        "policy_decision": "denied" if raw["outcome"] == "POLICY_BLOCKED" else "allowed",
        "runtime_result": _runtime_result(raw["outcome"]),
        "evidence_refs": [f"action:{payload['action_id']}:runtime"],
        **raw,
        "events": events,
    }
    return result


def _probe_child(tool: str, action: str) -> int:
    try:
        if tool == "privilege.no_new_privs_probe" and action == "enable":
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.prctl(38, 1, 0, 0, 0) != 0:
                value = ctypes.get_errno()
                raise OSError(value, os.strerror(value))
        elif tool == "privilege.identity_probe":
            if action == "setuid":
                os.setuid(0)
            elif action == "seteuid":
                os.seteuid(0)
            elif action == "setgid":
                os.setgid(0)
            elif action == "setegid":
                os.setegid(0)
            elif action == "setgroups":
                os.setgroups([0])
            elif action in {"setfsuid", "setfsgid"}:
                libc = ctypes.CDLL(None, use_errno=True)
                function = getattr(libc, action)
                function.argtypes = [ctypes.c_uint]
                function.restype = ctypes.c_int
                function(0)
                reached = _identity()
                key = "fsuid" if action == "setfsuid" else "fsgid"
                if reached[key] != 0:
                    raise PermissionError(errno_module.EPERM, os.strerror(errno_module.EPERM))
            else:
                raise ValueError("지원하지 않는 Probe action입니다.")
        else:
            raise ValueError("지원하지 않는 Probe Tool입니다.")
        body = {
            "success": True,
            "errno": None,
            "output": f"격리된 자식 문맥에서 {tool}:{action} 시도에 성공했습니다.",
            "identity_reached": _identity(),
        }
        print(json.dumps(body, ensure_ascii=False))
        return 0
    except OSError as exc:
        print(json.dumps({
            "success": False,
            "errno": exc.errno,
            "output": str(exc),
            "identity_reached": _identity(),
        }, ensure_ascii=False))
        return exc.errno or 1
    except Exception as exc:
        print(json.dumps({
            "success": False,
            "errno": None,
            "output": str(exc),
            "identity_reached": _identity(),
        }, ensure_ascii=False))
        return 2


def main() -> int:
    if len(sys.argv) == 4 and sys.argv[1] == "--probe-child":
        return _probe_child(sys.argv[2], sys.argv[3])
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            raise ValueError("JSON 객체가 필요합니다.")
        print(json.dumps(run(payload), ensure_ascii=False))
        return 0
    except Exception as exc:
        print(json.dumps({"detail": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
