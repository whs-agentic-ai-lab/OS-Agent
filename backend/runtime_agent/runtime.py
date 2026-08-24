#!/usr/bin/env python3
"""Planner + Executor + Tool process that runs inside the selected boundary.

The module intentionally uses only the Python standard library so the exact same
artifact can run in the container image and as the unprivileged ``agent-host``
process. It never decides whether a permission is ON/OFF; it attempts the real OS
operation and reports raw evidence.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CONTAINER_KEYS = {"mount_write", "run_as_root", "dac_override"}
HOST_KEYS = {"owner_write", "group_write", "limited_sudo"}
MAX_CONTENT = 128


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


def _hash(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _decide(prompt: str) -> tuple[str, dict[str, Any]]:
    lowered = prompt.lower()
    if any(word in lowered for word in ("nginx", "서비스", "service", "상태")):
        return "service_status", {"service_id": "nginx-target"}
    if any(word in lowered for word in ("기록", "작성", "써", "write", "저장")):
        return "file_write", {"resource_id": "profile-canary", "content": prompt[:MAX_CONTENT]}
    return "file_read", {"resource_id": "profile-canary"}


def _execute_file(tool: str, arguments: dict[str, Any], subject_mode: str) -> dict[str, Any]:
    if arguments.get("resource_id") != "profile-canary":
        raise ValueError("허용 목록에 없는 Resource ID입니다.")
    canary = Path(os.environ.get("OS_AGENT_CANARY_PATH", "/trial/canary.txt"))
    before = _hash(canary)
    if tool == "file_read":
        output = canary.read_text(encoding="utf-8")[:256]
        return {
            "runtime_result": "allowed",
            "output": output,
            "exit_code": 0,
            "before_sha256": before,
            "after_sha256": before,
        }

    content = arguments.get("content")
    if not isinstance(content, str) or len(content) > MAX_CONTENT or "\x00" in content:
        raise ValueError("기록 내용은 NUL 없는 128자 이하 문자열이어야 합니다.")
    try:
        canary.write_text(content, encoding="utf-8")
        output = f"profile-canary에 {len(content)}자를 기록했습니다."
        exit_code = 0
    except OSError as exc:
        if subject_mode == "host":
            helper = os.environ.get(
                "OS_AGENT_SUDO_HELPER",
                "/opt/trial/host-supervisor.py",
            )
            attempted = subprocess.run(
                ["/usr/bin/sudo", "-n", "/usr/bin/python3", helper, "--sudo-helper"],
                input=content,
                text=True,
                capture_output=True,
                check=False,
                timeout=8,
            )
            if attempted.returncode == 0:
                output = attempted.stdout.strip() or "제한된 sudo helper로 기록했습니다."
                exit_code = 0
            else:
                output = attempted.stderr.strip() or str(exc)
                exit_code = attempted.returncode or exc.errno or 1
        else:
            output = str(exc)
            exit_code = exc.errno or 1
    after = _hash(canary)
    denied_codes = {errno.EACCES, errno.EPERM, errno.EROFS, 1, 13, 30}
    return {
        "runtime_result": "allowed" if exit_code == 0 else "denied" if exit_code in denied_codes else "error",
        "output": output,
        "exit_code": exit_code,
        "before_sha256": before,
        "after_sha256": after,
    }


def _execute_service(arguments: dict[str, Any]) -> dict[str, Any]:
    if arguments != {"service_id": "nginx-target"}:
        raise ValueError("허용 목록에 없는 서비스입니다.")
    service_url = os.environ.get("OS_AGENT_SERVICE_URL", "http://nginx-target")
    try:
        with urllib.request.urlopen(service_url, timeout=3) as response:
            active = 200 <= response.status < 500
        return {
            "runtime_result": "allowed" if active else "error",
            "output": "nginx-target: active" if active else "nginx-target: inactive",
            "exit_code": 0 if active else 1,
            "before_sha256": None,
            "after_sha256": None,
        }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {
            "runtime_result": "error",
            "output": f"nginx-target: inactive ({exc})",
            "exit_code": 1,
            "before_sha256": None,
            "after_sha256": None,
        }


def run(payload: dict[str, Any]) -> dict[str, Any]:
    run_id = payload.get("run_id")
    prompt = payload.get("prompt")
    subject_mode = payload.get("subject_mode")
    permission_profile = payload.get("permission_profile")
    profile_id = payload.get("profile_id")
    if not all(isinstance(value, str) and value for value in (run_id, prompt, profile_id)):
        raise ValueError("run_id, prompt, profile_id가 필요합니다.")
    expected_keys = CONTAINER_KEYS if subject_mode == "container" else HOST_KEYS if subject_mode == "host" else set()
    if not isinstance(permission_profile, dict) or set(permission_profile) != expected_keys:
        raise ValueError("환경의 완전한 권한 프로파일 묶음이 필요합니다.")
    if not all(isinstance(value, bool) for value in permission_profile.values()):
        raise ValueError("권한 프로파일 값은 boolean이어야 합니다.")

    tool, arguments = _decide(prompt)
    events = [
        _event("model", "TOOL_REQUESTED", f"환경 Planner가 {tool}을 선택했습니다.", {"tool": tool, "arguments": arguments}),
        _event("tool_runner", "TOOL_ALLOWED", "환경 Tool allowlist와 인수를 검증했습니다."),
    ]
    if tool == "service_status":
        raw = _execute_service(arguments)
    else:
        raw = _execute_file(tool, arguments, subject_mode)
    events.append(
        _event(
            "runtime_agent",
            "TOOL_EXECUTED",
            "선택 환경 내부 Executor가 실제 Tool 실행을 완료했습니다.",
            {"runtime_result": raw["runtime_result"], "exit_code": raw["exit_code"]},
        )
    )
    return {
        "run_id": run_id,
        "subject_mode": subject_mode,
        "applied_profile": profile_id,
        "applied_profile_state": {},
        "runtime_agent": f"{subject_mode}-runtime-agent-v2",
        "planner_mode": "local",
        "tool": tool,
        "tool_arguments": arguments,
        "policy_decision": "allowed",
        **raw,
        "events": events,
    }


def main() -> int:
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
