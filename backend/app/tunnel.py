from __future__ import annotations

import os
import shutil
import socket
import subprocess
from threading import Lock, Thread
import time
from typing import Literal

import httpx
from pydantic import BaseModel, Field

from .config import Settings
from .executables import find_working_executable


class TunnelRequest(BaseModel):
    confirmation: Literal["START_FIXED_SSM_TUNNEL"]
    target_instance_id: str = Field(pattern=r"^i-[0-9a-f]{8,17}$")


class TunnelStopRequest(BaseModel):
    confirmation: Literal["STOP_FIXED_SSM_TUNNEL"]


class TunnelStatus(BaseModel):
    status: Literal["not_ready", "installing", "idle", "starting", "connected", "failed"]
    target_instance_id: str | None = None
    local_port: int = 8001
    remote_port: int = 8000
    error: str | None = None
    logs: list[str] = Field(default_factory=list)


class SsmTunnelManager:
    """로컬 8001 포트를 고정 EC2의 8000 포트로 연결한다."""

    PLUGIN_DOWNLOAD_URL = (
        "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/windows/"
        "SessionManagerPluginSetup.exe"
    )

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._lock = Lock()
        self._process: subprocess.Popen[str] | None = None
        self._stop_requested = False
        self._status = TunnelStatus(status="idle")
        self.refresh()

    def refresh(self) -> TunnelStatus:
        with self._lock:
            if self._process is not None and self._process.poll() is not None:
                self._process = None
                if self._status.status in {"starting", "connected"} and not self._stop_requested:
                    self._status.status = "failed"
                    self._status.error = "SSM 터널 프로세스가 예기치 않게 종료되었습니다."
            if self._status.status in {"idle", "not_ready"}:
                missing = self._missing_prerequisites()
                if missing:
                    self._status.status = "not_ready"
                    self._status.error = f"필수 프로그램을 찾을 수 없습니다: {', '.join(missing)}"
                elif self._status.status == "not_ready":
                    self._status.status = "idle"
                    self._status.error = None
            return self._status.model_copy(deep=True)

    def start(self, target_instance_id: str) -> TunnelStatus:
        current = self.refresh()
        if current.status in {"installing", "starting", "connected"}:
            return current
        aws = find_working_executable("aws", ["--version"])
        if aws is None:
            raise RuntimeError("AWS CLI 실행 파일을 찾을 수 없습니다.")
        if not self._port_is_available(current.local_port):
            raise RuntimeError(f"로컬 포트 {current.local_port}을 이미 다른 프로세스가 사용 중입니다.")

        plugin = self._find_plugin()
        if plugin is None:
            if os.name != "nt":
                raise RuntimeError("이 자동 설치는 Windows에서만 지원합니다.")
            with self._lock:
                self._stop_requested = False
                self._status = TunnelStatus(
                    status="installing",
                    target_instance_id=target_instance_id,
                    logs=["AWS 공식 Session Manager Plugin을 자동 설치합니다."],
                )
            Thread(
                target=self._install_plugin_and_launch,
                args=(aws, target_instance_id),
                daemon=True,
            ).start()
            return self.refresh()

        return self._start_when_target_online(aws, plugin, target_instance_id)

    def _start_when_target_online(self, aws: str, plugin: str, target_instance_id: str) -> TunnelStatus:
        with self._lock:
            self._stop_requested = False
            self._status = TunnelStatus(
                status="starting",
                target_instance_id=target_instance_id,
                logs=[f"SSM 관리 노드 연결 대기: {target_instance_id}"],
            )
        Thread(
            target=self._wait_for_target_and_launch,
            args=(aws, plugin, target_instance_id),
            daemon=True,
        ).start()
        return self.refresh()

    def _wait_for_target_and_launch(self, aws: str, plugin: str, target_instance_id: str) -> None:
        deadline = time.monotonic() + 300
        last_status = "등록 대기"
        while time.monotonic() < deadline:
            with self._lock:
                if self._stop_requested:
                    return
            completed = subprocess.run(
                [
                    aws,
                    "ssm",
                    "describe-instance-information",
                    "--filters",
                    f"Key=InstanceIds,Values={target_instance_id}",
                    "--query",
                    "InstanceInformationList[0].PingStatus",
                    "--output",
                    "text",
                    "--region",
                    self.settings.aws_region,
                    "--profile",
                    self.settings.aws_profile,
                ],
                cwd=self.settings.backend_context,
                env=self._environment(plugin),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                check=False,
            )
            if completed.returncode != 0:
                message = (completed.stderr or completed.stdout).strip()
                self._set_failed(f"SSM 상태 확인 실패: {message or 'AWS CLI 오류'}")
                return
            last_status = completed.stdout.strip() or "등록 대기"
            if last_status == "Online":
                self._append_log("SSM 관리 노드가 Online 상태입니다.")
                self._launch(aws, plugin, target_instance_id)
                return
            time.sleep(5)
        self._set_failed(f"5분 안에 SSM 관리 노드가 Online이 되지 않았습니다. 마지막 상태: {last_status}")

    def _launch(self, aws: str, plugin: str, target_instance_id: str) -> TunnelStatus:
        with self._lock:
            if self._stop_requested:
                return self._status.model_copy(deep=True)
            local_port = self._status.local_port
            remote_port = self._status.remote_port
        args = [
            aws,
            "ssm",
            "start-session",
            "--target",
            target_instance_id,
            "--document-name",
            "AWS-StartPortForwardingSession",
            "--parameters",
            f"portNumber={remote_port},localPortNumber={local_port}",
            "--region",
            self.settings.aws_region,
            "--profile",
            self.settings.aws_profile,
        ]
        creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        process = subprocess.Popen(
            args,
            cwd=self.settings.backend_context,
            env=self._environment(plugin),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=creationflags,
        )
        with self._lock:
            self._process = process
            self._stop_requested = False
            self._status = TunnelStatus(
                status="starting",
                target_instance_id=target_instance_id,
                logs=self._status.logs
                + [f"SSM 터널 시작: 127.0.0.1:{local_port} → {target_instance_id}:{remote_port}"],
            )
        Thread(target=self._read_output, args=(process,), daemon=True).start()
        Thread(target=self._monitor, args=(process,), daemon=True).start()
        return self.refresh()

    def _install_plugin_and_launch(self, aws: str, target_instance_id: str) -> None:
        try:
            installer_dir = self.settings.runtime_dir / "installers"
            installer_dir.mkdir(parents=True, exist_ok=True)
            installer = installer_dir / "SessionManagerPluginSetup.exe"
            self._append_log("AWS 공식 설치 파일을 다운로드하는 중입니다.")
            with httpx.stream(
                "GET",
                self.PLUGIN_DOWNLOAD_URL,
                follow_redirects=True,
                timeout=120,
            ) as response:
                response.raise_for_status()
                with installer.open("wb") as output:
                    for chunk in response.iter_bytes():
                        output.write(chunk)
            with installer.open("rb") as downloaded:
                signature = downloaded.read(2)
            if installer.stat().st_size < 1_000_000 or signature != b"MZ":
                raise RuntimeError("다운로드한 Session Manager Plugin 설치 파일이 올바르지 않습니다.")

            self._append_log("설치 프로그램을 실행합니다. Windows 권한 확인 창이 나타날 수 있습니다.")
            completed = subprocess.run(
                [str(installer), "/quiet"],
                cwd=installer_dir,
                capture_output=True,
                timeout=300,
                check=False,
            )
            if completed.returncode != 0:
                raise RuntimeError(f"Session Manager Plugin 설치 실패: exit code={completed.returncode}")
            plugin = self._find_plugin()
            if plugin is None:
                raise RuntimeError("설치는 완료됐지만 Session Manager Plugin 실행 파일을 찾지 못했습니다.")
            self._append_log("Session Manager Plugin 설치가 완료되었습니다.")
            self._start_when_target_online(aws, plugin, target_instance_id)
        except Exception as exc:
            self._set_failed(str(exc))

    def _append_log(self, message: str) -> None:
        with self._lock:
            if self._status.logs and self._status.logs[-1] == message:
                return
            self._status.logs.append(message)
            self._status.logs = self._status.logs[-80:]

    def _set_failed(self, message: str) -> None:
        with self._lock:
            self._status.status = "failed"
            self._status.error = message
            self._status.logs.append(message)
            self._status.logs = self._status.logs[-80:]

    def stop(self) -> TunnelStatus:
        with self._lock:
            process = self._process
            self._stop_requested = True
        if process is not None and process.poll() is None:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    capture_output=True,
                    check=False,
                    timeout=15,
                )
            else:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
        with self._lock:
            self._process = None
            self._status.status = "idle"
            self._status.error = None
            self._status.logs.append("SSM 터널을 종료했습니다.")
            return self._status.model_copy(deep=True)

    def close(self) -> None:
        self.stop()

    def _monitor(self, process: subprocess.Popen[str]) -> None:
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            if process.poll() is not None:
                return
            try:
                response = httpx.get(
                    f"http://127.0.0.1:{self._status.local_port}/api/health",
                    timeout=1.5,
                )
                if response.is_success:
                    with self._lock:
                        if self._process is process:
                            self._status.status = "connected"
                            self._status.error = None
                            self._status.logs.append("AWS 백엔드 헬스 체크에 성공했습니다.")
                    process.wait()
                    if not self._stop_requested:
                        with self._lock:
                            if self._process is process:
                                self._process = None
                                self._status.status = "failed"
                                self._status.error = "SSM 터널 연결이 종료되었습니다."
                    return
            except httpx.HTTPError:
                pass
            time.sleep(1)

        if process.poll() is None:
            self._terminate_process(process)
        with self._lock:
            if self._process is process:
                self._process = None
                self._status.status = "failed"
                self._status.error = "5분 안에 AWS 백엔드가 응답하지 않았습니다."

    def _read_output(self, process: subprocess.Popen[str]) -> None:
        if process.stdout is None:
            return
        for line in process.stdout:
            message = line.strip()
            if not message:
                continue
            with self._lock:
                if self._process is process:
                    normalized = message[:1000]
                    if self._status.logs and self._status.logs[-1] == normalized:
                        continue
                    self._status.logs.append(normalized)
                    self._status.logs = self._status.logs[-80:]

    def _terminate_process(self, process: subprocess.Popen[str]) -> None:
        if process.poll() is not None:
            return
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                capture_output=True,
                check=False,
                timeout=15,
            )
        else:
            process.terminate()

    def _missing_prerequisites(self) -> list[str]:
        missing = []
        if find_working_executable("aws", ["--version"]) is None:
            missing.append("AWS CLI")
        if self._find_plugin() is None:
            missing.append("Session Manager Plugin")
        return missing

    @staticmethod
    def _find_plugin() -> str | None:
        discovered = shutil.which("session-manager-plugin")
        if discovered:
            return discovered
        candidates = (
            r"C:\Program Files\Amazon\SessionManagerPlugin\bin\session-manager-plugin.exe",
            r"C:\Program Files (x86)\Amazon\SessionManagerPlugin\bin\session-manager-plugin.exe",
        )
        return next((path for path in candidates if os.path.isfile(path)), None)

    @staticmethod
    def _port_is_available(port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                return False
        return True

    def _environment(self, plugin: str) -> dict[str, str]:
        env = os.environ.copy()
        env["AWS_PROFILE"] = self.settings.aws_profile
        env["AWS_REGION"] = self.settings.aws_region
        env["PATH"] = f"{os.path.dirname(plugin)}{os.pathsep}{env.get('PATH', '')}"
        return env
