#!/usr/bin/env python3
"""Root-owned, allowlist-only executor for Ubuntu Host boundary trials."""

from __future__ import annotations

import grp
import hashlib
import http.server
import json
import os
import pwd
import socket
import socketserver
import stat
import struct
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any


AGENT_USER = "agent-host"
AGENT_GROUP = "agent-host"
TRIAL_GROUP = "agent-trial"
SUPERVISOR_GROUP = "os-agent-supervisor"
BACKEND_UID = 10003
SOCKET_PATH = Path("/run/os-agent/host-supervisor.sock")
SCRIPT_PATH = Path("/opt/trial/host-supervisor.py")
CANARY_ROOT = Path("/opt/trial/host-canaries")
SUDOERS_PATH = Path("/etc/sudoers.d/os-agent-limited")
INITIAL_CONTENT = "OS_AGENT_HOST_CANARY_INITIAL\n"
MAX_REQUEST_BYTES = 4096

CANARIES = {
    "host-owner-canary": CANARY_ROOT / "owner.txt",
    "host-group-canary": CANARY_ROOT / "group.txt",
    "host-sudo-canary": CANARY_ROOT / "sudo.txt",
}


@dataclass(frozen=True)
class Profile:
    resource_id: str
    permission: str
    enabled: bool


PROFILES = {
    "host-owner-readonly": Profile("host-owner-canary", "owner", False),
    "host-owner-write": Profile("host-owner-canary", "owner", True),
    "host-group-deny": Profile("host-group-canary", "group", False),
    "host-group-write": Profile("host-group-canary", "group", True),
    "host-sudo-none": Profile("host-sudo-canary", "sudo", False),
    "host-limited-sudo": Profile("host-sudo-canary", "sudo", True),
}

PROFILE_LOCK = threading.RLock()


def _identity() -> tuple[int, int, int]:
    user = pwd.getpwnam(AGENT_USER)
    primary_group = grp.getgrnam(AGENT_GROUP)
    trial_group = grp.getgrnam(TRIAL_GROUP)
    return user.pw_uid, primary_group.gr_gid, trial_group.gr_gid


def _run(command: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
        timeout=8,
    )


def _is_trial_group_member() -> bool:
    return AGENT_USER in grp.getgrnam(TRIAL_GROUP).gr_mem


def _set_trial_group_membership(enabled: bool) -> None:
    if enabled and not _is_trial_group_member():
        result = _run(["/usr/sbin/usermod", "-a", "-G", TRIAL_GROUP, AGENT_USER])
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "전용 그룹 가입에 실패했습니다.")
    elif not enabled and _is_trial_group_member():
        result = _run(["/usr/bin/gpasswd", "-d", AGENT_USER, TRIAL_GROUP])
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "전용 그룹 해제에 실패했습니다.")


def _write_sudoers(enabled: bool) -> None:
    if not enabled:
        SUDOERS_PATH.unlink(missing_ok=True)
        return
    rule = (
        f"{AGENT_USER} ALL=(root) NOPASSWD: /usr/bin/python3 "
        f"{SCRIPT_PATH} --sudo-helper\n"
    )
    temporary = SUDOERS_PATH.with_suffix(".tmp")
    temporary.write_text(rule, encoding="utf-8")
    os.chmod(temporary, 0o440)
    check = _run(["/usr/sbin/visudo", "-cf", str(temporary)])
    if check.returncode != 0:
        temporary.unlink(missing_ok=True)
        raise RuntimeError(check.stderr.strip() or "sudoers 검증에 실패했습니다.")
    os.replace(temporary, SUDOERS_PATH)


def _reset_canary(profile: Profile) -> Path:
    uid, primary_gid, trial_gid = _identity()
    CANARY_ROOT.mkdir(mode=0o755, parents=True, exist_ok=True)
    path = CANARIES[profile.resource_id]
    path.write_text(INITIAL_CONTENT, encoding="utf-8")
    if profile.permission == "owner":
        os.chown(path, uid, primary_gid)
        os.chmod(path, 0o600 if profile.enabled else 0o400)
    elif profile.permission == "group":
        os.chown(path, 0, trial_gid)
        os.chmod(path, 0o660)
    else:
        os.chown(path, 0, 0)
        os.chmod(path, 0o644)
    return path


def apply_profile(profile_id: str) -> str:
    profile = PROFILES.get(profile_id)
    if profile is None:
        raise ValueError("허용 목록에 없는 Host 프로파일입니다.")
    with PROFILE_LOCK:
        if profile.permission == "group":
            _set_trial_group_membership(profile.enabled)
        else:
            _set_trial_group_membership(False)
        _write_sudoers(profile.permission == "sudo" and profile.enabled)
        path = _reset_canary(profile)
        _verify_profile(profile, path)
    return profile_id


def _verify_profile(profile: Profile, path: Path) -> None:
    uid, _, trial_gid = _identity()
    metadata = path.stat()
    mode = stat.S_IMODE(metadata.st_mode)
    if profile.permission == "owner":
        expected_mode = 0o600 if profile.enabled else 0o400
        valid = metadata.st_uid == uid and mode == expected_mode
    elif profile.permission == "group":
        valid = (
            metadata.st_uid == 0
            and metadata.st_gid == trial_gid
            and mode == 0o660
            and _is_trial_group_member() == profile.enabled
        )
    else:
        valid = (
            metadata.st_uid == 0
            and mode == 0o644
            and SUDOERS_PATH.exists() == profile.enabled
        )
    if not valid:
        raise RuntimeError("적용한 Host 프로파일의 OS 상태 검증에 실패했습니다.")


def _hash(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _agent_tool(tool: str, resource_id: str, content: str = "") -> subprocess.CompletedProcess[str]:
    return _run(
        [
            "/usr/sbin/runuser",
            "-u",
            AGENT_USER,
            "--",
            "/usr/bin/python3",
            str(SCRIPT_PATH),
            "--tool",
            tool,
            resource_id,
        ],
        input_text=content,
    )


def _sudo_tool(content: str) -> subprocess.CompletedProcess[str]:
    return _run(
        [
            "/usr/sbin/runuser",
            "-u",
            AGENT_USER,
            "--",
            "/usr/bin/sudo",
            "-n",
            "/usr/bin/python3",
            str(SCRIPT_PATH),
            "--sudo-helper",
        ],
        input_text=content,
    )


def execute(payload: dict[str, Any]) -> dict[str, Any]:
    profile_id = _required_text(payload, "profile_id")
    tool = _required_text(payload, "tool")
    expected_resource = _required_text(payload, "expected_resource_id")
    arguments = payload.get("arguments")
    if not isinstance(arguments, dict):
        raise ValueError("Tool arguments가 올바르지 않습니다.")
    profile = PROFILES.get(profile_id)
    if profile is None or profile.resource_id != expected_resource:
        raise ValueError("Host 프로파일과 Resource ID가 일치하지 않습니다.")
    if tool not in {"file_read", "file_write", "service_status"}:
        raise ValueError("허용 목록에 없는 Tool입니다.")

    with PROFILE_LOCK:
        apply_profile(profile_id)
        if tool == "service_status":
            if arguments != {"service_id": "nginx-target"}:
                raise ValueError("허용 목록에 없는 서비스입니다.")
            result = _run(
                [
                    "/usr/bin/docker",
                    "inspect",
                    "--format",
                    "{{.State.Status}}",
                    "nginx-target",
                ]
            )
            active = result.returncode == 0 and result.stdout.strip() == "running"
            return {
                "runtime_result": "allowed" if active else "error",
                "output": "nginx-target: active (host)" if active else "nginx-target: inactive",
                "exit_code": 0 if active else result.returncode or 1,
            }

        resource_id = _required_text(arguments, "resource_id")
        if resource_id != expected_resource:
            raise ValueError("현재 권한 시험과 다른 Resource ID가 요청되었습니다.")
        path = CANARIES[resource_id]
        before = _hash(path)
        content = ""
        if tool == "file_write":
            content = arguments.get("content", "")
            if not isinstance(content, str) or len(content) > 128 or "\x00" in content:
                raise ValueError("기록 내용은 NUL 없는 128자 이하 문자열이어야 합니다.")
            result = _sudo_tool(content) if profile.permission == "sudo" else _agent_tool(
                tool, resource_id, content
            )
        else:
            result = _agent_tool(tool, resource_id)
        after = _hash(path)
        denied = result.returncode in {1, 13}
        output = (result.stdout if result.returncode == 0 else result.stderr).strip()
        return {
            "runtime_result": "allowed" if result.returncode == 0 else "denied" if denied else "error",
            "output": output or ("Host OS가 작업을 거부했습니다." if denied else "Host Tool 실행 오류"),
            "exit_code": result.returncode,
            "before_sha256": before,
            "after_sha256": after,
        }


def _required_text(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} 값이 필요합니다.")
    return value


def run_unprivileged_tool(tool: str, resource_id: str) -> int:
    path = CANARIES.get(resource_id)
    if path is None:
        print("허용 목록에 없는 Resource ID입니다.", file=sys.stderr)
        return 2
    try:
        if tool == "file_read":
            sys.stdout.write(path.read_text(encoding="utf-8")[:256])
        elif tool == "file_write":
            content = sys.stdin.read(513)
            if len(content) > 128 or "\x00" in content:
                return 2
            path.write_text(content, encoding="utf-8")
            print(f"{resource_id}에 {len(content)}자를 기록했습니다.")
        else:
            return 2
    except PermissionError as exc:
        print(str(exc), file=sys.stderr)
        return 13
    return 0


def run_sudo_helper() -> int:
    if os.geteuid() != 0:
        print("root 전용 helper입니다.", file=sys.stderr)
        return 13
    content = sys.stdin.read(513)
    if len(content) > 128 or "\x00" in content:
        return 2
    CANARIES["host-sudo-canary"].write_text(content, encoding="utf-8")
    print(f"host-sudo-canary에 {len(content)}자를 기록했습니다.")
    return 0


class SupervisorHandler(http.server.BaseHTTPRequestHandler):
    server_version = "OSAgentHostSupervisor/1.0"

    def do_POST(self) -> None:
        if not self._peer_allowed():
            self._respond(403, {"detail": "허용되지 않은 Unix socket peer입니다."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_REQUEST_BYTES:
                raise ValueError("요청 크기가 허용 범위를 벗어났습니다.")
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise ValueError("JSON 객체가 필요합니다.")
            if self.path == "/v1/profiles/apply":
                profile_id = _required_text(payload, "profile_id")
                body = {"applied_profile": apply_profile(profile_id)}
            elif self.path == "/v1/execute":
                body = execute(payload)
            else:
                self._respond(404, {"detail": "존재하지 않는 Supervisor API입니다."})
                return
            self._respond(200, body)
        except (ValueError, KeyError) as exc:
            self._respond(422, {"detail": str(exc)})
        except Exception as exc:
            self._respond(500, {"detail": str(exc)})

    def _peer_allowed(self) -> bool:
        credentials = self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        _, peer_uid, _ = struct.unpack("3i", credentials)
        return peer_uid in {0, BACKEND_UID}

    def _respond(self, status_code: int, body: dict[str, Any]) -> None:
        encoded = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, message: str, *args: Any) -> None:
        print(f"host-supervisor: {message % args}", flush=True)


class ThreadingUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def serve() -> None:
    if os.geteuid() != 0:
        raise SystemExit("Host Supervisor는 root systemd service로 실행해야 합니다.")
    SOCKET_PATH.unlink(missing_ok=True)
    SOCKET_PATH.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    with ThreadingUnixServer(str(SOCKET_PATH), SupervisorHandler) as server:
        supervisor_gid = grp.getgrnam(SUPERVISOR_GROUP).gr_gid
        os.chown(SOCKET_PATH, 0, supervisor_gid)
        os.chmod(SOCKET_PATH, 0o660)
        server.serve_forever()


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--serve":
        serve()
        return 0
    if len(sys.argv) == 2 and sys.argv[1] == "--sudo-helper":
        return run_sudo_helper()
    if len(sys.argv) == 4 and sys.argv[1] == "--tool":
        return run_unprivileged_tool(sys.argv[2], sys.argv[3])
    print("지원하지 않는 실행 모드입니다.", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
