# 0826 OS experiment Terraform

이 디렉터리는 AWS Sandbox의 고정 OS 실험환경만 조성한다.

## Terraform이 만드는 환경

- VPC, Private Subnet, NAT, SSM VPC Endpoints
- Public inbound가 없는 Ubuntu EC2 한 대
- Linux Host User1 `user1`과 User2 `user2`
- Container1, Container2, Container3
- root-owned Host Supervisor
- auditd, persistent journald, Docker json-file
- Docker Events/로그 relay
- Before/After state capture script
- Vector collector와 로컬 disk buffer

FastAPI와 Model Gateway는 runtime digest 이미지로 배포한다. OpenRouter key 값은 Terraform 범위 밖에서 SSM SecureString으로 생성하며, Terraform은 파라미터 이름과 EC2의 단일 `ssm:GetParameter` 권한만 관리한다. Supabase schema는 이 Terraform 범위 밖이다.

고정 배포 조건은 다음과 같다.

- Region/AZ: `us-east-1` / `us-east-1a`
- EC2: `t3.small` 1대
- Network: Private Subnet, public inbound 없음
- Access: SSM only
- Runtime: 같은 EC2의 U1/U2 Host와 C1/C2/C3 Container 방향성 환경 경계

## 고정 topology

`topology.yaml`은 다음만 허용한다.

- Source executor: U1, C1
- Target: U1, U2, C1, C2, C3
- Action paths: U1C1, U1C2, U1U2, U1C3, C1U1, C1C2, C1U2, C1C3

Linux 계정명은 `user1`, `user2`다. `os-agent`는 서비스와 디렉터리 prefix로만 사용한다.

실험 중에는 다음을 지킨다.

- 한 테스트 묶음이 진행되는 동안 `terraform apply`를 다시 실행하지 않는다.
- OpenRouter 및 Supabase secret 값을 `tfvars`, state, `user_data` 원문에 넣지 않는다. OpenRouter key는 환경별 SSM SecureString에서 부팅 시 읽는다.
- 최초 `terraform init` 후 생성되는 `.terraform.lock.hcl`을 고정한다.

## 이미지 계약

Terraform은 이미지를 build하지 않는다. ECR repository만 만들고 immutable digest를 받는다.

- `runtime`: `/app/RUNTIME_CONTRACT` 값이 `action-path-runtime-v1`이어야 하며
  `/app/host_runtime/host_supervisor.py`와 `/app/runtime_agent/runtime.py`를 포함해야 한다.
- `container1`: Container1 Target과 C1 executor를 함께 시작해야 한다.
  `/app/RUNTIME_CONTRACT` 값은 `container1-executor-target-v1`이어야 한다.
- `target`: Container2/Container3 target service를 기본 entrypoint로 시작하고 C1의
  내부-network 요청을 처리해야 한다. `/app/RUNTIME_CONTRACT` 값은
  `target-service-v1`이어야 한다.

두 container image는 `/app/healthcheck` 실행 파일을 제공해야 한다. Container1은
C1 executor/target과 Supervisor socket 연결까지, target image는 target service 준비까지
검사하며 Compose는 세 container가 모두 healthy가 될 때까지 기다린다. C2와 C3는 서로
다른 internal network에 있어 C1을 통하지 않고 통신하지 못한다. 최종 8-path allowlist는
Supervisor와 각 runtime이 `topology.json`을 기준으로 다시 강제해야 한다.

현재 애플리케이션 이미지가 이 계약을 구현하지 않으면 bootstrap은 명시적으로 실패한다.

## Evidence

Vector는 다음 source를 수집한다.

- systemd journal
- `/var/log/audit/audit.log`
- `/var/log/os-agent/docker-events.ndjson`
- `/var/log/os-agent/docker-logs.ndjson`
- `/var/log/os-agent/executor/*.ndjson`
- `/var/log/os-agent/state-captures.ndjson`

기본값은 로컬 sink다.

```text
/var/lib/os-agent/evidence/collected/events.ndjson
```

FastAPI Evidence API가 준비된 후에만 `enable_remote_evidence_sink=true`로 전환한다.
Collector token 값은 기존 SSM SecureString에서 boot 시 읽으며 Terraform 변수/state에 넣지 않는다.

## 재현성 입력

다음 값은 매 실험 전에 고정해야 한다.

- Ubuntu AMI ID
- runtime/container image digest
- Vector 0.57.0 공식 archive SHA-256
- instance type와 EBS 크기
- topology revision

Docker/apt repository 패키지는 이 구성에서 새로 설치되므로 완전한 byte-for-byte 재현성이
필요하면 Docker와 Vector까지 넣은 별도 검증 AMI를 bake해야 한다. 실제 부팅에 설치된 핵심
패키지 버전은 `/var/lib/os-agent/bootstrap-package-versions.txt`에 증거로 남는다.

`terraform.tfvars.example`을 참고하되 실제 `terraform.tfvars`는 Git에 커밋하지 않는다.

## 적용

이 구성은 기존 state를 in-place 변경하기 위한 것이 아니다. 기존 state에는 다른 주소와
리소스가 있으므로 고유한 `environment_id`와 **비어 있는 새 state**로 배포한다. 기존 state
파일은 삭제하거나 migrate하지 말고 별도 보관한다. 이 모듈의 local backend는 기존 기본
state와 분리된 `terraform-0826.tfstate`만 사용한다. 실제 AWS resource prefix는
`<project_name>-<environment_id>`이며 조합은 40자 이하여야 한다. `confirm_new_state=true`는
이 확인을 마친 경우에만 설정한다. 대시보드 컨트롤러는 모든 stateful 명령에 환경별
`-state` 경로를 전달하며, backend block은 기존 state를 자동 migrate하지 않도록 기본
local 경로를 유지한다.

첫 배포는 ECR과 digest 이미지 사이에 의도적인 2단계가 있다.

```powershell
# 0) 기본 local backend를 migrate 없이 초기화한다.
terraform init -reconfigure -input=false
if (Test-Path -LiteralPath './terraform-0826.tfstate') {
  $existingResources = @(terraform state list)
  if ($LASTEXITCODE -ne 0) { throw "state 조회에 실패했습니다" }
  if ($existingResources.Count -gt 0) { throw "기존 state를 사용하면 안 됩니다: $existingResources" }
}

# 1) 빈 새 state에서 immutable repository만 만든다.
terraform apply -target='aws_ecr_repository.images'

# 2) 새 runtime/container1/target 계약 이미지를 각 ECR에 push한다.
# 3) 세 manifest digest를 terraform.tfvars에 고정한 뒤 전체 plan/apply한다.
terraform plan -out=0826.plan
terraform show 0826.plan
terraform apply 0826.plan
```

전체 plan은 `aws_ecr_image.pinned`으로 세 digest가 실제 repository에 존재하는지 먼저
검증한다. 첫 단계에서 EC2를 함께 만들지 않는다. 첫 전체 적용 전 plan summary가 기존
리소스의 change/destroy 없이 새 0826 리소스 create만 포함하는지 확인한다.

```powershell
terraform fmt -check -recursive
terraform validate
```

현재 대시보드 배포 컨트롤러는 이전 resource/output 계약을 사용하므로 이 Terraform을
대시보드 배포 버튼으로 적용하면 안 된다.

## 부팅 후 검증

SSM으로 접속한 뒤:

```bash
sudo cloud-init status --wait
sudo test -f /var/lib/os-agent/bootstrap-complete
sudo /opt/os-agent/scripts/verify_environment.sh
sudo systemctl status vector os-agent-host-supervisor os-agent-experiment
sudo auditctl -l
sudo journalctl --disk-usage
```

Before/After capture는 Supervisor가 다음 형식으로 호출한다.

```bash
sudo /opt/os-agent/scripts/capture_state.sh \
  <run_id> <action_id> <path_id> <before|after> <U1|U2|C1|C2|C3>
```

Terraform은 이 스크립트를 설치하고 Host Supervisor는 `/v2/runs` action lifecycle에서
실행 직전과 직후에 각각 `before`/`after` 캡처를 호출한다.

Supervisor/runtime은 모든 tool 요청에 동일한 `run_id`, `action_id`, `path_id`를 싣고,
Host Supervisor가 실제 실행 결과, stdout/stderr, 종료 코드를 executor NDJSON event로 남긴다. 원격 sink를 켜면
FastAPI가 이 event를 검증해 Supabase Evidence Store에 idempotent하게 적재해야 한다.
NDJSON writer는 rotation 후 새 파일을 따르도록 event마다 append-open해야 한다.

SSM SecureString이 기본 `aws/ssm` key가 아니라 customer-managed KMS key로 암호화되어
있다면 `collector_token_kms_key_arn`도 설정해야 한다. Terraform의 EC2 생성 성공은
cloud-init 성공을 의미하지 않는다. 위 `cloud-init`, `bootstrap-complete`, 환경 검증 세
명령을 모두 통과한 시점만 실제 실험 시작 gate로 취급한다.

`terraform destroy` 전에 세 ECR repository의 이미지를 명시적으로 삭제해야 한다.
repository는 실수로 증거성 실행물을 지우지 않도록 `force_delete=false`다.
