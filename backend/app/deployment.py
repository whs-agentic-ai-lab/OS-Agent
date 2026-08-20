from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
from threading import Lock, Thread
from typing import Literal

from pydantic import BaseModel, Field

from .config import Settings
from .executables import find_working_executable


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DeploymentRequest(BaseModel):
    confirmation: Literal["DEPLOY_FIXED_OS_ENVIRONMENT"]


class InitializeRequest(BaseModel):
    confirmation: Literal["INITIALIZE_FIXED_TERRAFORM"]


class DestroyRequest(BaseModel):
    confirmation: Literal["DESTROY_FIXED_OS_ENVIRONMENT"]
    environment_name: Literal["os-agent-test"]


class DeploymentLog(BaseModel):
    sequence: int
    level: Literal["info", "error"] = "info"
    message: str
    created_at: datetime = Field(default_factory=utc_now)


class DeploymentStatus(BaseModel):
    status: Literal["disabled", "not_ready", "idle", "running", "succeeded", "failed"]
    operation: Literal["none", "initialize", "deploy", "destroy"] = "none"
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

    FLOW_LOG_GROUP_NAME = "/os-agent-test/vpc-flow-logs"
    FLOW_LOG_GROUP_ADDRESS = "aws_cloudwatch_log_group.vpc_flow_logs[0]"

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

    def get_trial_instance_id(self) -> str:
        with self._lock:
            if self._status.status == "running":
                raise RuntimeError("인프라 작업이 끝난 뒤 SSM 터널을 시작하세요.")
            output_ids = self._status.outputs.get("trial_ec2_instance_ids", [])
        if isinstance(output_ids, list) and output_ids:
            return str(output_ids[0])

        terraform = self._required_executable("terraform")
        try:
            raw = self._capture(
                [terraform, "output", "-json", "trial_ec2_instance_ids"],
                self.settings.terraform_dir,
                log_output=False,
            )
            instance_ids = json.loads(raw or "[]")
            if isinstance(instance_ids, list) and instance_ids:
                return str(instance_ids[0])
        except (RuntimeError, json.JSONDecodeError):
            pass

        aws = self._required_executable("aws")
        raw = self._capture(
            [
                aws,
                "ec2",
                "describe-instances",
                "--filters",
                "Name=tag:Name,Values=os-agent-test-ec2-*",
                "Name=instance-state-name,Values=pending,running",
                "--query",
                "Reservations[].Instances[].InstanceId",
                "--output",
                "json",
                "--region",
                self.settings.aws_region,
                "--profile",
                self.settings.aws_profile,
            ],
            self.settings.backend_context,
            log_output=False,
        )
        instance_ids = json.loads(raw or "[]")
        if not isinstance(instance_ids, list) or not instance_ids:
            raise RuntimeError("실행 중인 os-agent-test EC2가 없습니다. AWS 환경을 먼저 배포하세요.")
        return str(instance_ids[0])

    def start(self) -> DeploymentStatus:
        snapshot = self._begin(
            operation="deploy",
            required=("terraform", "aws_cli", "docker", "terraform_files"),
            message="고정 OS 환경 배포를 시작합니다.",
        )
        Thread(target=self._deploy, name="fixed-os-deployment", daemon=True).start()
        return snapshot

    def initialize(self) -> DeploymentStatus:
        snapshot = self._begin(
            operation="initialize",
            required=("terraform", "terraform_files"),
            message="고정 Terraform 작업 디렉터리 초기화를 시작합니다.",
        )
        Thread(target=self._initialize, name="fixed-os-initialize", daemon=True).start()
        return snapshot

    def destroy(self) -> DeploymentStatus:
        snapshot = self._begin(
            operation="destroy",
            required=("terraform", "aws_cli", "terraform_files"),
            message="고정 OS 환경 삭제를 시작합니다.",
        )
        Thread(target=self._destroy, name="fixed-os-destroy", daemon=True).start()
        return snapshot

    def _begin(
        self,
        operation: Literal["initialize", "deploy", "destroy"],
        required: tuple[str, ...],
        message: str,
    ) -> DeploymentStatus:
        current = self.refresh_prerequisites()
        if not current.enabled:
            raise RuntimeError("로컬 백엔드의 DEPLOYMENT_ENABLED를 true로 설정해야 합니다.")
        missing = [key for key in required if not current.prerequisites.get(key, False)]
        if missing:
            raise RuntimeError(f"작업 사전 요구사항이 준비되지 않았습니다: {', '.join(missing)}")
        with self._lock:
            if self._status.status == "running":
                raise RuntimeError("이미 다른 인프라 작업이 진행 중입니다.")
            self._status.status = "running"
            self._status.operation = operation
            self._status.logs = []
            self._status.outputs = {}
            self._status.error = None
            self._status.started_at = utc_now()
            self._status.completed_at = None
            self._append_locked(message)
            return self._status.model_copy(deep=True)

    def _initialize(self) -> None:
        try:
            terraform = self._required_executable("terraform")
            self._command(
                [terraform, "init", "-input=false"],
                self.settings.terraform_dir,
            )
            self._succeed("고정 Terraform 작업 디렉터리 초기화가 완료되었습니다.")
        except Exception as exc:
            self._fail(exc)

    def _destroy(self) -> None:
        try:
            terraform = self._required_executable("terraform")
            aws = self._required_executable("aws")
            terraform_dir = self.settings.terraform_dir
            placeholder_image = (
                f"000000000000.dkr.ecr.{self.settings.aws_region}.amazonaws.com/"
                "os-agent-test-backend:destroy"
            )
            self._command([terraform, "init", "-input=false"], terraform_dir)
            self._command(
                [
                    terraform,
                    "destroy",
                    "-auto-approve",
                    "-input=false",
                    f"-var=backend_image_uri={placeholder_image}",
                ],
                terraform_dir,
            )
            self._delete_orphaned_flow_log_group(aws)
            self._succeed("고정 OS 환경 삭제가 완료되었습니다.")
        except Exception as exc:
            self._fail(exc)

    def _deploy(self) -> None:
        try:
            terraform = self._required_executable("terraform")
            aws = self._required_executable("aws")
            docker = self._required_executable("docker")
            terraform_dir = self.settings.terraform_dir

            self._command([terraform, "init", "-input=false"], terraform_dir)
            self._reconcile_flow_log_group(terraform, aws, terraform_dir)
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
            self._fail(exc)

    def _succeed(self, message: str) -> None:
        with self._lock:
            self._status.status = "succeeded"
            self._status.completed_at = utc_now()
            self._append_locked(message)

    def _fail(self, exc: Exception) -> None:
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
            detail = self._command_error_detail(combined)
            suffix = f": {detail}" if detail else ""
            raise RuntimeError(f"명령이 실패했습니다. exit code={completed.returncode}{suffix}")

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
            detail = self._command_error_detail("\n".join((completed.stdout, completed.stderr)))
            suffix = f": {detail}" if detail else ""
            raise RuntimeError(f"명령이 실패했습니다. exit code={completed.returncode}{suffix}")
        return completed.stdout

    def _reconcile_flow_log_group(self, terraform: str, aws: str, terraform_dir: Path) -> None:
        """이전 삭제에서 남은 고정 로그 그룹을 현재 Terraform state에 다시 연결한다."""
        state = self._capture(
            [terraform, "state", "list"],
            terraform_dir,
            log_output=False,
        ).splitlines()
        if self.FLOW_LOG_GROUP_ADDRESS in state:
            return
        if not self._flow_log_group_exists(aws):
            return

        self._append(
            f"기존 CloudWatch 로그 그룹 {self.FLOW_LOG_GROUP_NAME}을 Terraform state로 편입합니다."
        )
        self._command(
            [
                terraform,
                "import",
                "-input=false",
                self.FLOW_LOG_GROUP_ADDRESS,
                self.FLOW_LOG_GROUP_NAME,
            ],
            terraform_dir,
        )

    def _delete_orphaned_flow_log_group(self, aws: str) -> None:
        """Flow Log 제거 뒤 AWS가 남겨 둔 고정 로그 그룹까지 정리한다."""
        if not self._flow_log_group_exists(aws):
            return
        self._append(f"잔여 CloudWatch 로그 그룹 {self.FLOW_LOG_GROUP_NAME}을 삭제합니다.")
        self._command(
            [
                aws,
                "logs",
                "delete-log-group",
                "--log-group-name",
                self.FLOW_LOG_GROUP_NAME,
                "--region",
                self.settings.aws_region,
                "--profile",
                self.settings.aws_profile,
            ],
            self.settings.backend_context,
        )

    def _flow_log_group_exists(self, aws: str) -> bool:
        raw = self._capture(
            [
                aws,
                "logs",
                "describe-log-groups",
                "--log-group-name-prefix",
                self.FLOW_LOG_GROUP_NAME,
                "--region",
                self.settings.aws_region,
                "--profile",
                self.settings.aws_profile,
                "--output",
                "json",
            ],
            self.settings.backend_context,
            log_output=False,
        )
        payload = json.loads(raw or "{}")
        return any(
            group.get("logGroupName") == self.FLOW_LOG_GROUP_NAME
            for group in payload.get("logGroups", [])
        )

    @staticmethod
    def _command_error_detail(output: str) -> str | None:
        ansi_escape = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
        lines = [ansi_escape.sub("", line).strip(" │╷╵") for line in output.splitlines()]
        for line in reversed(lines):
            if "Error:" in line:
                return line.split("Error:", 1)[1].strip()[:500]
        for line in reversed(lines):
            if line:
                return line[:500]
        return None

    def _environment(self) -> dict[str, str]:
        env = os.environ.copy()
        env["TF_IN_AUTOMATION"] = "1"
        env["AWS_PROFILE"] = self.settings.aws_profile
        env["AWS_REGION"] = self.settings.aws_region
        return env

    def _find_working_executable(self, name: str, version_args: list[str]) -> bool:
        executable = find_working_executable(name, version_args)
        self._executables[name] = executable
        return executable is not None

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
