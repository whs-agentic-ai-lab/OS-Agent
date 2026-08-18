from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
from threading import Lock, Thread
from typing import Literal

from pydantic import BaseModel, Field

from .config import Settings


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DeploymentRequest(BaseModel):
    confirmation: Literal["DEPLOY_FIXED_OS_ENVIRONMENT"]


class DeploymentLog(BaseModel):
    sequence: int
    level: Literal["info", "error"] = "info"
    message: str
    created_at: datetime = Field(default_factory=utc_now)


class DeploymentStatus(BaseModel):
    status: Literal["disabled", "not_ready", "idle", "running", "succeeded", "failed"]
    enabled: bool
    prerequisites: dict[str, bool]
    fixed_environment: dict[str, str | int]
    logs: list[DeploymentLog] = Field(default_factory=list)
    outputs: dict = Field(default_factory=dict)
    error: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None


class DeploymentManager:
    """로컬에서 고정 Terraform만 실행하는 단일 배포 컨트롤러."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._lock = Lock()
        self._status = DeploymentStatus(
            status="disabled" if not settings.deployment_enabled else "not_ready",
            enabled=settings.deployment_enabled,
            prerequisites={},
            fixed_environment={
                "region": "us-east-1",
                "availability_zone": "us-east-1a",
                "instance_type": "t3.small",
                "instance_count": 1,
                "access": "SSM only",
            },
        )
        self._executables: dict[str, str | None] = {}
        self.refresh_prerequisites()

    def refresh_prerequisites(self) -> DeploymentStatus:
        with self._lock:
            if self._status.status == "running":
                return self._status.model_copy(deep=True)
        checks = {
            "terraform": self._find_working_executable("terraform", ["version"]),
            "aws_cli": self._find_working_executable("aws", ["--version"]),
            "docker": self._find_working_executable("docker", ["version"]),
            "terraform_files": (self.settings.terraform_dir / "fixed.auto.tfvars").is_file(),
        }
        with self._lock:
            self._status.prerequisites = checks
            if not self.settings.deployment_enabled:
                self._status.status = "disabled"
            elif self._status.status not in {"running", "succeeded", "failed"}:
                self._status.status = "idle" if all(checks.values()) else "not_ready"
            return self._status.model_copy(deep=True)

    def get_status(self) -> DeploymentStatus:
        with self._lock:
            return self._status.model_copy(deep=True)

    def start(self) -> DeploymentStatus:
        current = self.refresh_prerequisites()
        if not current.enabled:
            raise RuntimeError("로컬 백엔드의 DEPLOYMENT_ENABLED를 true로 설정해야 합니다.")
        if not all(current.prerequisites.values()):
            missing = ", ".join(key for key, value in current.prerequisites.items() if not value)
            raise RuntimeError(f"배포 사전 요구사항이 준비되지 않았습니다: {missing}")
        with self._lock:
            if self._status.status == "running":
                raise RuntimeError("이미 환경 배포가 진행 중입니다.")
            self._status.status = "running"
            self._status.logs = []
            self._status.outputs = {}
            self._status.error = None
            self._status.started_at = utc_now()
            self._status.completed_at = None
            self._append_locked("고정 OS 환경 배포를 시작합니다.")
            snapshot = self._status.model_copy(deep=True)
        Thread(target=self._deploy, name="fixed-os-deployment", daemon=True).start()
        return snapshot

    def _deploy(self) -> None:
        try:
            terraform = self._required_executable("terraform")
            aws = self._required_executable("aws")
            docker = self._required_executable("docker")
            terraform_dir = self.settings.terraform_dir

            self._command([terraform, "init", "-input=false"], terraform_dir)
            self._command(
                [
                    terraform,
                    "apply",
                    "-auto-approve",
                    "-input=false",
                    "-target=aws_ecr_repository.agent_backend",
                ],
                terraform_dir,
            )
            repository_url = self._capture(
                [terraform, "output", "-raw", "backend_ecr_repository_url"],
                terraform_dir,
            ).strip()
            registry = repository_url.split("/", 1)[0]
            tag = datetime.now(timezone.utc).strftime("dashboard-%Y%m%d%H%M%S")
            local_image = f"os-agent-test-backend:{tag}"
            remote_image = f"{repository_url}:{tag}"

            password = self._capture(
                [
                    aws,
                    "ecr",
                    "get-login-password",
                    "--region",
                    self.settings.aws_region,
                    "--profile",
                    self.settings.aws_profile,
                ],
                self.settings.backend_context,
                log_output=False,
            )
            self._command(
                [docker, "login", "--username", "AWS", "--password-stdin", registry],
                self.settings.backend_context,
                input_text=password,
                log_output=False,
            )
            self._command(
                [docker, "build", "--tag", local_image, "."],
                self.settings.backend_context,
            )
            self._command([docker, "tag", local_image, remote_image], self.settings.backend_context)
            self._command([docker, "push", remote_image], self.settings.backend_context)
            self._command(
                [
                    terraform,
                    "apply",
                    "-auto-approve",
                    "-input=false",
                    f"-var=backend_image_uri={remote_image}",
                ],
                terraform_dir,
            )
            outputs_text = self._capture([terraform, "output", "-json"], terraform_dir)
            outputs = json.loads(outputs_text)
            simplified = {
                key: value.get("value") if isinstance(value, dict) else value
                for key, value in outputs.items()
            }
            with self._lock:
                self._status.status = "succeeded"
                self._status.outputs = simplified
                self._status.completed_at = utc_now()
                self._append_locked("고정 OS 환경 배포가 완료되었습니다.")
        except Exception as exc:
            with self._lock:
                self._status.status = "failed"
                self._status.error = str(exc)
                self._status.completed_at = utc_now()
                self._append_locked(str(exc), level="error")

    def _command(
        self,
        args: list[str],
        cwd: Path,
        input_text: str | None = None,
        log_output: bool = True,
    ) -> None:
        display = " ".join(Path(value).name if index == 0 else value for index, value in enumerate(args))
        self._append(f"> {display}")
        completed = subprocess.run(
            args,
            cwd=cwd,
            env=self._environment(),
            input=input_text,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=1800,
            check=False,
        )
        combined = "\n".join(part for part in (completed.stdout, completed.stderr) if part)
        if log_output:
            for line in combined.splitlines()[-120:]:
                self._append(line[:1000])
        if completed.returncode != 0:
            raise RuntimeError(f"명령이 실패했습니다. exit code={completed.returncode}")

    def _capture(self, args: list[str], cwd: Path, log_output: bool = True) -> str:
        completed = subprocess.run(
            args,
            cwd=cwd,
            env=self._environment(),
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=120,
            check=False,
        )
        if completed.returncode != 0:
            if log_output:
                self._append((completed.stderr or completed.stdout)[-1000:], level="error")
            raise RuntimeError(f"명령이 실패했습니다. exit code={completed.returncode}")
        return completed.stdout

    def _environment(self) -> dict[str, str]:
        env = os.environ.copy()
        env["TF_IN_AUTOMATION"] = "1"
        env["AWS_PROFILE"] = self.settings.aws_profile
        env["AWS_REGION"] = self.settings.aws_region
        return env

    def _find_working_executable(self, name: str, version_args: list[str]) -> bool:
        executable = shutil.which(name)
        self._executables[name] = executable
        if executable is None:
            return False
        try:
            completed = subprocess.run(
                [executable, *version_args],
                capture_output=True,
                timeout=10,
                check=False,
            )
            return completed.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def _required_executable(self, name: str) -> str:
        executable = self._executables.get(name)
        if executable is None:
            raise RuntimeError(f"{name} 실행 파일을 찾을 수 없습니다.")
        return executable

    def _append(self, message: str, level: Literal["info", "error"] = "info") -> None:
        with self._lock:
            self._append_locked(message, level)

    def _append_locked(self, message: str, level: Literal["info", "error"] = "info") -> None:
        self._status.logs.append(
            DeploymentLog(
                sequence=len(self._status.logs) + 1,
                level=level,
                message=message,
            )
        )
        self._status.logs = self._status.logs[-300:]
