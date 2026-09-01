from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from threading import Lock, Thread
from typing import Literal

from pydantic import BaseModel, Field

from .config import Settings
from .executables import find_working_executable


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DeploymentRequest(BaseModel):
    confirmation: Literal["DEPLOY_FIXED_OS_ENVIRONMENT"]
    environment_name: str = Field(
        min_length=3,
        max_length=16,
        pattern=r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])$",
    )


class InitializeRequest(BaseModel):
    confirmation: Literal["INITIALIZE_FIXED_TERRAFORM"]


class DestroyRequest(BaseModel):
    confirmation: Literal["DESTROY_FIXED_OS_ENVIRONMENT"]
    environment_id: str = Field(
        min_length=3,
        max_length=64,
        pattern=r"^os-agent-test(?:-[a-z0-9]+)+$|^os-agent-test$",
    )


class TerminateInstanceRequest(BaseModel):
    confirmation: Literal["TERMINATE_OS_AGENT_INSTANCE"]
    instance_id: str = Field(pattern=r"^i-[0-9a-f]{8,17}$")


class AwsCallerIdentity(BaseModel):
    account_id: str
    arn: str
    display_name: str
    owner_key: str
    environment_prefix: str


class EnvironmentContext(BaseModel):
    environment_name: str
    environment_id: str
    created_by: str
    owner_arn: str
    account_id: str
    base_ami_id: str | None = None
    image_digests: dict[str, str] = Field(default_factory=dict)
    openrouter_parameter_name: str | None = None


class AwsInstanceSummary(BaseModel):
    instance_id: str
    name: str
    environment_id: str
    created_by: str
    owner_arn: str
    state: str
    instance_type: str
    availability_zone: str
    private_ip: str | None = None
    launch_time: datetime | None = None
    ssm_ping_status: str = "Unknown"
    local_state_available: bool = False


class DeploymentLog(BaseModel):
    sequence: int
    level: Literal["info", "error"] = "info"
    message: str
    created_at: datetime = Field(default_factory=utc_now)


class DeploymentStatus(BaseModel):
    status: Literal["not_ready", "idle", "running", "succeeded", "failed"]
    operation: Literal["none", "initialize", "deploy", "destroy"] = "none"
    prerequisites: dict[str, bool]
    fixed_environment: dict[str, str | int]
    logs: list[DeploymentLog] = Field(default_factory=list)
    outputs: dict = Field(default_factory=dict)
    error: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    caller_identity: AwsCallerIdentity | None = None
    instances: list[AwsInstanceSummary] = Field(default_factory=list)


class DeploymentManager:
    """로컬에서 고정 Terraform만 실행하는 단일 배포 컨트롤러."""

    FLOW_LOG_GROUP_ADDRESS = "aws_cloudwatch_log_group.vpc_flow_logs[0]"
    ENVIRONMENT_ID_PATTERN = re.compile(r"os-agent-test(?:-[a-z0-9]+)*")
    UBUNTU_AMI_PARAMETER = (
        "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/"
        "hvm/ebs-gp3/ami-id"
    )
    VECTOR_ARCHIVE_SHA256 = (
        "4d156e6859e235b366f5b77121ae59d5440c93acab215c45f30f3fc839d20f65"
    )
    IMAGE_DOCKERFILES = {
        "runtime": Path("Dockerfile"),
        "container1": Path("container_images/container1/Dockerfile"),
        "target": Path("container_images/target/Dockerfile"),
    }

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._lock = Lock()
        self._status = DeploymentStatus(
            status="not_ready",
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
        # 앱 import/테스트 수집 단계에서는 AWS 네트워크 호출을 만들지 않는다.
        # 대시보드가 현재 상태 API를 조회할 때 실제 AWS 인벤토리를 갱신한다.
        self.refresh_prerequisites(discover_aws=False)

    def _source_revision(self) -> tuple[str, bool]:
        """Return the exact Git revision and whether the image context is dirty."""
        repository = self.settings.backend_context.parent
        try:
            revision = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repository,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=10,
                check=False,
            )
            status = subprocess.run(
                ["git", "status", "--porcelain", "--untracked-files=no"],
                cwd=repository,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return "unknown", False
        sha = revision.stdout.strip() if revision.returncode == 0 else "unknown"
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            sha = "unknown"
        return sha, status.returncode == 0 and bool(status.stdout.strip())

    def refresh_prerequisites(self, *, discover_aws: bool = True) -> DeploymentStatus:
        with self._lock:
            if self._status.status == "running":
                return self._status.model_copy(deep=True)
        checks = {
            "terraform": self._find_working_executable("terraform", ["version"]),
            "aws_cli": self._find_working_executable("aws", ["--version"]),
            "docker": self._find_working_executable("docker", ["version"]),
            "terraform_files": (self.settings.terraform_dir / "fixed.auto.tfvars").is_file(),
            "openrouter_api_key": bool(self.settings.openrouter_api_key),
        }
        caller_identity = None
        instances: list[AwsInstanceSummary] = []
        if checks["aws_cli"] and discover_aws:
            try:
                caller_identity = self.get_caller_identity()
                instances = self.list_instances()
            except (RuntimeError, json.JSONDecodeError):
                pass
        with self._lock:
            self._status.prerequisites = checks
            self._status.caller_identity = caller_identity
            self._status.instances = instances
            if self._status.status not in {"running", "succeeded", "failed"}:
                if instances:
                    self._status.status = "succeeded"
                    self._status.operation = "none"
                    self._status.outputs["discovered_instance_ids"] = [
                        instance.instance_id for instance in instances
                    ]
                else:
                    self._status.status = "idle" if all(checks.values()) else "not_ready"
            return self._status.model_copy(deep=True)

    def get_status(self) -> DeploymentStatus:
        with self._lock:
            return self._status.model_copy(deep=True)

    def get_caller_identity(self) -> AwsCallerIdentity:
        aws = self._required_executable("aws")
        raw = self._capture(
            [
                aws,
                "sts",
                "get-caller-identity",
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
        payload = json.loads(raw or "{}")
        account_id = str(payload.get("Account") or "")
        arn = str(payload.get("Arn") or "")
        if not account_id or not arn:
            raise RuntimeError("AWS 로그인 사용자 정보를 확인하지 못했습니다.")
        display_name = self._caller_display_name(arn)
        slug = self._slug(display_name, max_length=12) or "member"
        fingerprint = hashlib.sha256(arn.encode("utf-8")).hexdigest()[:6]
        owner_key = f"{slug}-{fingerprint}"
        return AwsCallerIdentity(
            account_id=account_id,
            arn=arn,
            display_name=display_name,
            owner_key=owner_key,
            environment_prefix=f"os-agent-test-{owner_key}",
        )

    def resolve_environment(self, environment_name: str) -> EnvironmentContext:
        normalized = environment_name.strip().lower()
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{1,14}[a-z0-9])", normalized):
            raise RuntimeError("환경 이름은 3~16자의 영문 소문자, 숫자, 하이픈만 사용할 수 있습니다.")
        caller = self.get_caller_identity()
        return EnvironmentContext(
            environment_name=normalized,
            environment_id=f"{caller.environment_prefix}-{normalized}",
            created_by=caller.display_name,
            owner_arn=caller.arn,
            account_id=caller.account_id,
        )

    def list_instances(self) -> list[AwsInstanceSummary]:
        aws = self._required_executable("aws")
        raw = self._capture(
            [
                aws,
                "ec2",
                "describe-instances",
                "--filters",
                "Name=tag:Project,Values=agentic-ai-trust-boundary",
                "Name=instance-state-name,Values=pending,running,stopping,stopped",
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
        payload = json.loads(raw or "{}")
        ssm_statuses = self._ssm_statuses(aws)
        instances: list[AwsInstanceSummary] = []
        for reservation in payload.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                tags = {
                    str(tag.get("Key")): str(tag.get("Value") or "")
                    for tag in instance.get("Tags", [])
                }
                name = tags.get("Name", "")
                environment_id = tags.get("EnvironmentId") or re.sub(
                    r"-ec2-\d+$", "", name
                )
                if (
                    len(environment_id) > 64
                    or self.ENVIRONMENT_ID_PATTERN.fullmatch(environment_id) is None
                ):
                    continue
                instance_id = str(instance.get("InstanceId") or "")
                instances.append(
                    AwsInstanceSummary(
                        instance_id=instance_id,
                        name=name or instance_id,
                        environment_id=environment_id,
                        created_by=tags.get("CreatedBy") or "legacy/unknown",
                        owner_arn=tags.get("OwnerArn") or "",
                        state=str(instance.get("State", {}).get("Name") or "unknown"),
                        instance_type=str(instance.get("InstanceType") or ""),
                        availability_zone=str(
                            instance.get("Placement", {}).get("AvailabilityZone") or ""
                        ),
                        private_ip=instance.get("PrivateIpAddress"),
                        launch_time=instance.get("LaunchTime"),
                        ssm_ping_status=ssm_statuses.get(instance_id, "Unknown"),
                        local_state_available=self._state_path(
                            environment_id, create=False
                        ).is_file(),
                    )
                )
        return sorted(
            instances,
            key=lambda item: item.launch_time or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )

    def get_trial_instance_id(self, requested_instance_id: str | None = None) -> str:
        with self._lock:
            if self._status.status == "running":
                raise RuntimeError("인프라 작업이 끝난 뒤 SSM 터널을 시작하세요.")
        running = [
            instance
            for instance in self.list_instances()
            if instance.state in {"pending", "running"}
        ]
        if requested_instance_id:
            selected = next(
                (item for item in running if item.instance_id == requested_instance_id),
                None,
            )
            if selected is None:
                raise RuntimeError("선택한 EC2가 없거나 실행 가능한 상태가 아닙니다.")
            return selected.instance_id
        if not running:
            raise RuntimeError("실행 중인 os-agent-test EC2가 없습니다. AWS 환경을 먼저 배포하세요.")
        if len(running) > 1:
            raise RuntimeError("실행 중인 EC2가 여러 대입니다. 연결할 인스턴스를 선택하세요.")
        return running[0].instance_id

    def start(self, request: DeploymentRequest) -> DeploymentStatus:
        environment = self.resolve_environment(request.environment_name)
        snapshot = self._begin(
            operation="deploy",
            required=(
                "terraform",
                "aws_cli",
                "docker",
                "terraform_files",
                "openrouter_api_key",
            ),
            message=f"{environment.environment_id} 환경 배포를 시작합니다.",
        )
        Thread(
            target=self._deploy,
            args=(environment,),
            name="fixed-os-deployment",
            daemon=True,
        ).start()
        return snapshot

    def initialize(self) -> DeploymentStatus:
        snapshot = self._begin(
            operation="initialize",
            required=("terraform", "terraform_files"),
            message="고정 Terraform 작업 디렉터리 초기화를 시작합니다.",
        )
        Thread(target=self._initialize, name="fixed-os-initialize", daemon=True).start()
        return snapshot

    def destroy(self, request: DestroyRequest) -> DeploymentStatus:
        state_path = self._state_path(request.environment_id, create=False)
        if not state_path.is_file():
            raise RuntimeError(
                "이 PC에 해당 환경의 Terraform state가 없습니다. "
                "EC2만 종료하거나 환경을 만든 팀원의 PC에서 전체 삭제하세요."
            )
        snapshot = self._begin(
            operation="destroy",
            required=("terraform", "aws_cli", "terraform_files"),
            message=f"{request.environment_id} 환경 전체 삭제를 시작합니다.",
        )
        Thread(
            target=self._destroy,
            args=(request.environment_id,),
            name="fixed-os-destroy",
            daemon=True,
        ).start()
        return snapshot

    def terminate_instance(self, request: TerminateInstanceRequest) -> DeploymentStatus:
        with self._lock:
            if self._status.status == "running":
                raise RuntimeError("진행 중인 인프라 작업이 끝난 뒤 EC2를 종료하세요.")
        selected = next(
            (
                instance
                for instance in self.list_instances()
                if instance.instance_id == request.instance_id
            ),
            None,
        )
        if selected is None:
            raise RuntimeError("종료할 수 있는 os-agent-test EC2를 찾지 못했습니다.")
        aws = self._required_executable("aws")
        self._command(
            [
                aws,
                "ec2",
                "terminate-instances",
                "--instance-ids",
                request.instance_id,
                "--region",
                self.settings.aws_region,
                "--profile",
                self.settings.aws_profile,
            ],
            self.settings.backend_context,
        )
        self._append(
            f"EC2 {request.instance_id} 종료를 요청했습니다. Terraform의 나머지 리소스는 유지됩니다."
        )
        return self.refresh_prerequisites()

    def _begin(
        self,
        operation: Literal["initialize", "deploy", "destroy"],
        required: tuple[str, ...],
        message: str,
    ) -> DeploymentStatus:
        current = self.refresh_prerequisites()
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
                [terraform, "init", "-reconfigure", "-input=false"],
                self.settings.terraform_dir,
            )
            self._succeed("고정 Terraform 작업 디렉터리 초기화가 완료되었습니다.")
        except Exception as exc:
            self._fail(exc)

    def _destroy(self, environment_id: str) -> None:
        try:
            terraform = self._required_executable("terraform")
            aws = self._required_executable("aws")
            terraform_dir = self.settings.terraform_dir
            state_path = self._state_path(environment_id, create=False)
            environment = self._load_environment_context(environment_id)
            self._command(
                [terraform, "init", "-reconfigure", "-input=false"], terraform_dir
            )
            if not state_path.is_file():
                self._delete_orphaned_flow_log_group(aws, environment_id)
                self._delete_openrouter_parameter(aws, environment)
                self._succeed(f"{environment_id} 환경에는 삭제할 Terraform 리소스가 없습니다.")
                return
            state_resources = self._capture(
                [terraform, "state", "list", f"-state={state_path}"],
                terraform_dir,
                log_output=False,
            ).splitlines()
            if not state_resources:
                self._delete_orphaned_flow_log_group(aws, environment_id)
                self._delete_openrouter_parameter(aws, environment)
                self._succeed(f"{environment_id} 환경에는 삭제할 Terraform 리소스가 없습니다.")
                return
            missing_images = set(self.IMAGE_DOCKERFILES) - set(environment.image_digests)
            if missing_images:
                if "aws_instance.trial" in state_resources:
                    raise RuntimeError(
                        "EC2가 있는 환경의 image digest metadata가 없어 안전하게 삭제할 수 없습니다."
                    )
                targets = []
                if any(item.startswith("aws_ecr_repository.images") for item in state_resources):
                    targets.append("-target=aws_ecr_repository.images")
                if self.FLOW_LOG_GROUP_ADDRESS in state_resources:
                    targets.append(f"-target={self.FLOW_LOG_GROUP_ADDRESS}")
                if targets:
                    self._command(
                        [
                            terraform,
                            "destroy",
                            f"-state={state_path}",
                            "-auto-approve",
                            "-input=false",
                            *targets,
                            *self._terraform_variable_args(environment),
                            *self._terraform_runtime_args(
                                environment, require_images=False
                            ),
                        ],
                        terraform_dir,
                    )
                self._delete_orphaned_flow_log_group(aws, environment_id)
                self._delete_openrouter_parameter(aws, environment)
                self._succeed(f"{environment_id} 부분 배포 환경 삭제가 완료되었습니다.")
                return
            self._command(
                [
                    terraform,
                    "destroy",
                    f"-state={state_path}",
                    "-auto-approve",
                    "-input=false",
                    *self._terraform_variable_args(environment),
                    *self._terraform_runtime_args(environment),
                ],
                terraform_dir,
            )
            self._delete_orphaned_flow_log_group(aws, environment_id)
            self._delete_openrouter_parameter(aws, environment)
            self._succeed(f"{environment_id} 환경 삭제가 완료되었습니다.")
        except Exception as exc:
            self._fail(exc)

    def _deploy(self, environment: EnvironmentContext) -> None:
        try:
            terraform = self._required_executable("terraform")
            aws = self._required_executable("aws")
            docker = self._required_executable("docker")
            terraform_dir = self.settings.terraform_dir
            state_path = self._state_path(environment.environment_id, create=True)
            if not self.settings.openrouter_api_key:
                raise RuntimeError("OPENROUTER_API_KEY가 없어 AI 공격 환경을 배포할 수 없습니다.")
            environment.openrouter_parameter_name = (
                f"/os-agent/{environment.environment_id}/openrouter-api-key"
            )
            self._save_environment_context(environment)
            self._put_openrouter_parameter(
                aws,
                environment.openrouter_parameter_name,
                self.settings.openrouter_api_key,
            )
            environment.base_ami_id = self._resolve_base_ami_id(aws)
            self._save_environment_context(environment)
            variable_args = self._terraform_variable_args(environment)

            self._command(
                [terraform, "init", "-reconfigure", "-input=false"], terraform_dir
            )
            self._reconcile_flow_log_group(
                terraform,
                aws,
                terraform_dir,
                environment,
                state_path,
            )
            self._command(
                [
                    terraform,
                    "apply",
                    f"-state={state_path}",
                    "-auto-approve",
                    "-input=false",
                    "-target=aws_ecr_repository.images",
                    *variable_args,
                    *self._terraform_runtime_args(environment, require_images=False),
                ],
                terraform_dir,
            )
            repository_urls = json.loads(self._capture(
                [
                    terraform,
                    "output",
                    f"-state={state_path}",
                    "-json",
                    "ecr_repository_urls",
                ],
                terraform_dir,
            ))
            if set(repository_urls) != set(self.IMAGE_DOCKERFILES):
                raise RuntimeError("Terraform ECR 출력이 runtime/container1/target 계약과 다릅니다.")
            registry = str(repository_urls["runtime"]).split("/", 1)[0]
            tag = datetime.now(timezone.utc).strftime("dashboard-%Y%m%d%H%M%S")

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
            image_digests: dict[str, str] = {}
            build_git_sha, build_source_dirty = self._source_revision()
            self._append(
                f"이미지 source revision: {build_git_sha}"
                + (" (dirty working tree)" if build_source_dirty else "")
            )
            for component, dockerfile in self.IMAGE_DOCKERFILES.items():
                repository_url = str(repository_urls[component])
                local_image = f"{environment.environment_id}-{component}:{tag}"
                remote_image = f"{repository_url}:{tag}"
                build_context_args = (
                    ["--build-context", f"terraform={self.settings.terraform_dir}"]
                    if component == "runtime"
                    else []
                )
                self._command(
                    [
                        docker,
                        "build",
                        "--platform",
                        "linux/amd64",
                        "--build-arg",
                        f"OS_AGENT_BUILD_GIT_SHA={build_git_sha}",
                        "--build-arg",
                        "OS_AGENT_BUILD_SOURCE_DIRTY=" + str(build_source_dirty).lower(),
                        *build_context_args,
                        "--file",
                        str(self.settings.backend_context / dockerfile),
                        "--tag",
                        local_image,
                        ".",
                    ],
                    self.settings.backend_context,
                )
                self._command(
                    [docker, "tag", local_image, remote_image],
                    self.settings.backend_context,
                )
                self._command(
                    [docker, "push", remote_image], self.settings.backend_context
                )
                image_digests[component] = self._resolve_ecr_digest(
                    aws, repository_url, tag
                )

            environment.image_digests = image_digests
            self._save_environment_context(environment)
            self._command(
                [
                    terraform,
                    "apply",
                    f"-state={state_path}",
                    "-auto-approve",
                    "-input=false",
                    *variable_args,
                    *self._terraform_runtime_args(environment),
                ],
                terraform_dir,
            )
            outputs_text = self._capture(
                [terraform, "output", f"-state={state_path}", "-json"],
                terraform_dir,
            )
            outputs = json.loads(outputs_text)
            simplified = {
                key: value.get("value") if isinstance(value, dict) else value
                for key, value in outputs.items()
            }
            with self._lock:
                self._status.status = "succeeded"
                self._status.outputs = simplified
                self._status.completed_at = utc_now()
                self._append_locked(f"{environment.environment_id} 환경 배포가 완료되었습니다.")
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

    def _reconcile_flow_log_group(
        self,
        terraform: str,
        aws: str,
        terraform_dir: Path,
        environment: EnvironmentContext,
        state_path: Path,
    ) -> None:
        """이전 삭제에서 남은 고정 로그 그룹을 현재 Terraform state에 다시 연결한다."""
        state = []
        if state_path.is_file():
            state = self._capture(
                [terraform, "state", "list", f"-state={state_path}"],
                terraform_dir,
                log_output=False,
            ).splitlines()
        if self.FLOW_LOG_GROUP_ADDRESS in state:
            return
        log_group_name = f"/{environment.environment_id}/vpc-flow-logs"
        if not self._flow_log_group_exists(aws, log_group_name):
            return

        self._append(
            f"기존 CloudWatch 로그 그룹 {log_group_name}을 Terraform state로 편입합니다."
        )
        self._command(
            [
                terraform,
                "import",
                f"-state={state_path}",
                "-input=false",
                *self._terraform_variable_args(environment),
                self.FLOW_LOG_GROUP_ADDRESS,
                log_group_name,
            ],
            terraform_dir,
        )

    def _delete_orphaned_flow_log_group(self, aws: str, environment_id: str) -> None:
        """Flow Log 제거 뒤 AWS가 남겨 둔 고정 로그 그룹까지 정리한다."""
        log_group_name = f"/{environment_id}/vpc-flow-logs"
        if not self._flow_log_group_exists(aws, log_group_name):
            return
        self._append(f"잔여 CloudWatch 로그 그룹 {log_group_name}을 삭제합니다.")
        self._command(
            [
                aws,
                "logs",
                "delete-log-group",
                "--log-group-name",
                log_group_name,
                "--region",
                self.settings.aws_region,
                "--profile",
                self.settings.aws_profile,
            ],
            self.settings.backend_context,
        )

    def _put_openrouter_parameter(
        self,
        aws: str,
        parameter_name: str,
        secret_value: str,
    ) -> None:
        """키를 로그, Terraform 인수, user-data에 노출하지 않고 SecureString으로 저장한다."""
        payload = {
            "Name": parameter_name,
            "Description": "OS Agent OpenRouter API key",
            "Value": secret_value,
            "Type": "SecureString",
            "Overwrite": True,
            "Tier": "Standard",
        }
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                suffix=".json",
                delete=False,
            ) as temporary:
                json.dump(payload, temporary)
                temporary_path = Path(temporary.name)
            os.chmod(temporary_path, 0o600)
            self._append(f"OpenRouter 키를 환경 전용 SSM SecureString {parameter_name}에 저장합니다.")
            completed = subprocess.run(
                [
                    aws,
                    "ssm",
                    "put-parameter",
                    "--cli-input-json",
                    f"file://{temporary_path}",
                    "--region",
                    self.settings.aws_region,
                    "--profile",
                    self.settings.aws_profile,
                ],
                cwd=self.settings.backend_context,
                env=self._environment(),
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=120,
                check=False,
            )
            if completed.returncode != 0:
                detail = self._command_error_detail(completed.stderr or completed.stdout)
                raise RuntimeError(
                    "OpenRouter SecureString 저장에 실패했습니다."
                    + (f" {detail}" if detail else "")
                )
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    def _delete_openrouter_parameter(
        self,
        aws: str,
        environment: EnvironmentContext,
    ) -> None:
        parameter_name = environment.openrouter_parameter_name
        if not parameter_name:
            return
        self._append(f"환경 전용 OpenRouter SecureString {parameter_name}을 삭제합니다.")
        self._command(
            [
                aws,
                "ssm",
                "delete-parameters",
                "--names",
                parameter_name,
                "--region",
                self.settings.aws_region,
                "--profile",
                self.settings.aws_profile,
            ],
            self.settings.backend_context,
        )

    def _flow_log_group_exists(self, aws: str, log_group_name: str) -> bool:
        raw = self._capture(
            [
                aws,
                "logs",
                "describe-log-groups",
                "--log-group-name-prefix",
                log_group_name,
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
            group.get("logGroupName") == log_group_name
            for group in payload.get("logGroups", [])
        )

    def _ssm_statuses(self, aws: str) -> dict[str, str]:
        try:
            raw = self._capture(
                [
                    aws,
                    "ssm",
                    "describe-instance-information",
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
            payload = json.loads(raw or "{}")
        except (RuntimeError, json.JSONDecodeError):
            return {}
        return {
            str(item.get("InstanceId")): str(item.get("PingStatus") or "Unknown")
            for item in payload.get("InstanceInformationList", [])
            if item.get("InstanceId")
        }

    def _state_path(self, environment_id: str, create: bool) -> Path:
        self._validate_environment_id(environment_id)
        legacy_state = self.settings.terraform_dir / "terraform.tfstate"
        if environment_id == "os-agent-test" and legacy_state.is_file():
            return legacy_state
        state_dir = self.settings.runtime_dir / "terraform-states" / environment_id
        if create:
            state_dir.mkdir(parents=True, exist_ok=True)
        return state_dir / "terraform.tfstate"

    def _metadata_path(self, environment_id: str) -> Path:
        self._validate_environment_id(environment_id)
        return self.settings.runtime_dir / "terraform-states" / environment_id / "metadata.json"

    def _save_environment_context(self, environment: EnvironmentContext) -> None:
        metadata_path = self._metadata_path(environment.environment_id)
        metadata_path.parent.mkdir(parents=True, exist_ok=True)
        metadata_path.write_text(
            json.dumps(environment.model_dump(mode="json"), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def _load_environment_context(self, environment_id: str) -> EnvironmentContext:
        metadata_path = self._metadata_path(environment_id)
        if metadata_path.is_file():
            return EnvironmentContext.model_validate_json(
                metadata_path.read_text(encoding="utf-8")
            )
        return EnvironmentContext(
            environment_name=environment_id.removeprefix("os-agent-test-") or "legacy",
            environment_id=environment_id,
            created_by="legacy/unknown",
            owner_arn="unknown",
            account_id="unknown",
        )

    def _terraform_variable_args(self, environment: EnvironmentContext) -> list[str]:
        return [
            "-var=project_name=os-agent",
            f"-var=environment_id={environment.environment_id}",
            f"-var=created_by={environment.created_by}",
            f"-var=owner_arn={environment.owner_arn}",
            f"-var=aws_profile={self.settings.aws_profile}",
            "-var=confirm_new_state=true",
            "-var=openrouter_api_key_parameter_name="
            + (environment.openrouter_parameter_name or ""),
        ]

    def _terraform_runtime_args(
        self,
        environment: EnvironmentContext,
        *,
        require_images: bool = True,
    ) -> list[str]:
        if not environment.base_ami_id:
            if require_images:
                raise RuntimeError("환경 metadata에 고정 Ubuntu AMI ID가 없습니다.")
            base_ami_id = ""
        else:
            base_ami_id = environment.base_ami_id
        missing = set(self.IMAGE_DOCKERFILES) - set(environment.image_digests)
        if require_images and missing:
            raise RuntimeError(
                "환경 metadata에 이미지 digest가 없습니다: " + ", ".join(sorted(missing))
            )
        return [
            f"-var=base_ami_id={base_ami_id}",
            f"-var=vector_archive_sha256={self.VECTOR_ARCHIVE_SHA256}",
            *[
                f"-var={component}_image_digest={environment.image_digests.get(component, '')}"
                for component in self.IMAGE_DOCKERFILES
            ],
        ]

    def _resolve_base_ami_id(self, aws: str) -> str:
        ami_id = self._capture(
            [
                aws,
                "ssm",
                "get-parameter",
                "--name",
                self.UBUNTU_AMI_PARAMETER,
                "--query",
                "Parameter.Value",
                "--output",
                "text",
                "--region",
                self.settings.aws_region,
                "--profile",
                self.settings.aws_profile,
            ],
            self.settings.backend_context,
            log_output=False,
        ).strip()
        if re.fullmatch(r"ami-[0-9a-f]+", ami_id) is None:
            raise RuntimeError("AWS 공식 Ubuntu 24.04 AMI ID 조회 결과가 올바르지 않습니다.")
        return ami_id

    def _resolve_ecr_digest(self, aws: str, repository_url: str, tag: str) -> str:
        repository_name = repository_url.split("/", 1)[-1]
        digest = self._capture(
            [
                aws,
                "ecr",
                "describe-images",
                "--repository-name",
                repository_name,
                "--image-ids",
                f"imageTag={tag}",
                "--query",
                "imageDetails[0].imageDigest",
                "--output",
                "text",
                "--region",
                self.settings.aws_region,
                "--profile",
                self.settings.aws_profile,
            ],
            self.settings.backend_context,
            log_output=False,
        ).strip()
        if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
            raise RuntimeError(f"{repository_name} ECR digest 조회 결과가 올바르지 않습니다.")
        return digest

    @classmethod
    def _validate_environment_id(cls, environment_id: str) -> None:
        if (
            len(environment_id) > 64
            or cls.ENVIRONMENT_ID_PATTERN.fullmatch(environment_id) is None
        ):
            raise RuntimeError("유효하지 않은 AWS 환경 ID입니다.")

    @staticmethod
    def _caller_display_name(arn: str) -> str:
        parts = [part for part in arn.split("/") if part]
        return parts[-1] if parts else arn.rsplit(":", 1)[-1]

    @staticmethod
    def _slug(value: str, max_length: int) -> str:
        normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
        return normalized[:max_length].rstrip("-")

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
        terraform_data_dir = (
            self.settings.runtime_dir / "terraform-data" / "dashboard-controller"
        )
        terraform_data_dir.mkdir(parents=True, exist_ok=True)
        env["TF_IN_AUTOMATION"] = "1"
        env["TF_DATA_DIR"] = str(terraform_data_dir.resolve())
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
