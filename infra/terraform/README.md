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
  `/app/host_runtime/host_supervisor.py`, `/app/runtime_agent/runtime.py`,
  `/app/runtime_agent/recon_tools.py`를 포함해야 한다.
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

출력은 [공통 Evidence JSON](EVIDENCE_SCHEMA.md)으로 정규화한다. 기존 Supervisor의
executor 파일 기록과 before/after 자동 캡처를 유지하고, 기존 백엔드 verify_tool의 반환값만
별도로 기록한다. 새 AgentOrchestrator의 ToolDefinition Verifier 상세 연결은 추가 승인 전까지
미반영이며, 일반 OS 로그에 실행 ID를 추측해서 붙이지 않는다.

```text
/var/lib/os-agent/evidence/collected/events.ndjson
```

FastAPI Evidence API가 준비된 후에만 `enable_remote_evidence_sink=true`로 전환한다.
Collector token 값은 기존 SSM SecureString에서 boot 시 읽으며 Terraform 변수/state에 넣지 않는다.

## Evidence 원격 연결

현재 선택 이식본은 **user-data 용량 검증에 실패해 배포 준비가 끝나지 않았다.**
동일한 검증 입력에서 gzip 크기가 remote OFF 16,038 B / ON 16,273 B로,
기존 15,360 B 상한을 초과한다. 병합 전 HEAD는 두 경우 모두 통과했다.
상한은 그대로 유지했으며, 추가 패키징 조정은 사용자 승인 전 보류했다.
아래 설정 예시는 적용 완료를 의미하지 않는다. 비교 결과는 작업보고서를 참고한다.

이 절은 기존 OS-Tool 구현의 설정 계약이다. 로컬 파일 이식은 배포·DB 적용·원격 검증 완료를
뜻하지 않는다. 실제 대상과 영향을 승인받기 전에는 서비스 재시작·배포·migration을 실행하지 않는다.

### 수신 서버와 DB

신뢰된 FastAPI 수신 서버에만 기존 환경 설정 방식으로 다음을 주입한다.

```dotenv
SUPABASE_URL=https://<approved-project>.supabase.co
SUPABASE_SECRET_KEY=<server-only-secret>
EVIDENCE_COLLECTOR_TOKEN=<collection-only-secret>
```

기존 SUPABASE_SERVICE_ROLE_KEY fallback도 유지한다. collector token은 별도 수집 전용 값이다.
Supabase 관리 키는 실험 Tool/Runtime·Vector·브라우저에 배포하지 않는다.
미설정 API는 503, 잘못된 인증은 401이며 저장 실패에 성공 응답을 보내지 않는다.

기존 프로젝트에는 `data/migrations/20260830090000_add_evidence_storage.sql`만 추가 적용한다.
전체 schema.sql을 재실행하지 않는다. 기존 실행·AgentRun 테이블을 유지하면서 Evidence 테이블
두 개와 private bucket·접근 제한을 추가한다. 실제 적용 전 [migration 안내](../../data/migrations/README.md)의
대상·권한 확인이 필요하다. 이 이식 작업에서는 DB를 변경하지 않는다.

### Vector 설정과 고정 조건

기존 Terraform 입력을 사용하며 아래는 비밀값 없는 예시다.

```hcl
enable_remote_evidence_sink     = true
evidence_api_url                = "https://evidence.example.test"
collector_token_parameter_name = "/os-agent/trial/collector-token"
collector_token_kms_key_arn     = ""
```

기본 false는 로컬 수집만 수행한다. 실제 API 주소는 EC2가 접근 가능한 인증서 검증 HTTPS여야 한다.
개발 PC의 localhost 서버를 띄우는 것만으로 EC2에서 수신할 수 있는 것은 아니다.
API·템플릿 수정만으로 이미 실행 중인 EC2 이미지와 설정이 바뀌지 않는다.

| 항목 | 기존 이식 값 |
|---|---|
| 전송 | Vector 0.57.0, gzip, POST /internal/evidence/events, application/x-ndjson |
| 배치 | 최대 250건, 인코딩 전 1 MiB (1048576 bytes), 대기 2초 |
| 수신 한도 | 압축·해제 각각 8 MiB, 최대 250건 |
| HTTP | timeout 30초, concurrency 1, retry backoff 1~300초 |
| disk buffer | 원격 536870912 bytes, 로컬 268435488 bytes; full 시 block |
| Artifact | 파일당 32 MiB, HTTPS PUT, timeout 30초, 1회·자동 재시도 없음 |

Vector의 기존 재시도·디스크 버퍼를 사용하며 별도 큐나 서비스를 만들지 않는다.
배치 크기는 JSON 직렬화 전 값이다. 401/413/422 등 인증·입력 거부는 장애 복구 재전송으로
해결된다고 가정하지 않는다. 동일 `(environment_id,event_id)` 재전송은 DB 중복을 만들지 않는다.

### Artifact 연결 경계

기존 업로더·공유 마스킹 모듈과 `/etc/os-agent/evidence-upload.json` 설정 생성은 이식한다.
이미 생성된 허용 파일만 전송하는 API 계약은 유지하지만, capture_state.sh에 동기 업로드를
추가하지 않는다. 최신 Supervisor가 적용하는 before/after 호출 순서와 30초 제한을 보존한다.
원격 sink 활성화만으로 Artifact 자동 전송까지 연결됐다고 보아서는 안 된다.
다른 자동 실행 위치·백그라운드 작업·새 수동 운영 절차는 승인 없이 추가하지 않는다.

`STATE_CAPTURED`는 로컬 캡처 완료다. 업로더 호출 시 원격 완료는 `ARTIFACT_UPLOADED`,
실패는 `ARTIFACT_UPLOAD_FAILED`이며 원본 SHA와 마스킹된 저장본 SHA는 별도다.
DB에는 파일 본문 대신 private Storage 참조·크기·해시를 저장한다.

### 로컬 검증

기존 가상환경으로 Evidence/API/업로더/실행 기록 테스트와 최신 AgentRun 회귀 테스트를 실행한다.
Vector 실행 파일이 준비된 경우에만 `VECTOR_BIN`을 지정해 `test_evidence_vector.py`를 실행하고,
`config/vector`에서 `vector test normalize.tests.yaml`을 실행한다. 테스트가 Vector를 설치하지 않는다.
Terraform은 `terraform fmt -check -recursive`, `terraform validate`와 remote off/on 렌더·크기만 검증한다.
실제 Terraform apply·Supabase/RLS/Storage·EC2 원격 E2E는 별도 승인·검증 대상이다.
현재 결과는 [작업보고서](../../OS_로깅_정규화_1단계_작업보고서.md)에 기록한다.

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
