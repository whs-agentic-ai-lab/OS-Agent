# Terraform - Trust Boundary 실험 인프라 (OS 파트)

`EC2-Docker-Compose-통합-아키텍처.md` 다이어그램에서 **실제로 AWS에 떠야 하는 부분**만 코드화한 것. Agent/Gateway 같은 애플리케이션 로직은 여기 없음 (아래 "안 만드는 것" 참고).

---

## 0. 사전 준비

- 팀 공용 AWS 계정의 IAM 사용자로 로그인 (root 아님), VPC·EC2·IAM·S3·CloudTrail 만들 수 있는 권한 필요 → 랩이면 `AdministratorAccess`
- Terraform `>= 1.6.0`, AWS Provider `~> 6.0`

**공용 계정 연결 (최초 1회, 터미널에서)**

```bash
aws configure --profile whs-team   # 팀 공용 계정 Access Key ID / Secret 입력, region은 us-east-1
aws sts get-caller-identity --profile whs-team   # 공용 계정 맞는지 확인
```

Access Key는 절대 git에 올리지 않음 — `aws configure`는 로컬 `~/.aws/credentials`에만 저장됨.

---

## 1. 설정값 입력

```bash
cp terraform.tfvars.example terraform.tfvars
```

`terraform.tfvars`에서 방금 만든 프로필 이름을 넣음 (필수 — 안 넣으면 기본 프로필로 apply되어 엉뚱한 계정에 만들어질 수 있음):

```hcl
aws_profile = "whs-team"
```

나머지는 기본값 그대로 apply해도 동작함. 바꾸고 싶으면 같이:

```hcl
budget_alert_email             = "you@example.com"  # 예산 80% 초과 알림 받을 이메일, 비우면 알림 없이 한도만 생성
create_golden_ami               = false               # true로 apply하면 지금 EC2 상태를 AMI로 저장
attach_cloudwatch_agent_policy  = false               # CloudWatch Agent 쓸 거면만 true
```

`terraform.tfvars`는 `.gitignore`에 들어있어서 git엔 안 올라감. 공유는 `.example`만.

---

## 2. 인프라 생성

```bash
terraform init
terraform plan
terraform apply
```

완료 후 접속 (public IP 없음, SSM으로만):

```bash
aws ssm start-session --target <instance-id>
```
(`terraform apply` 출력의 `ssm_connect_command` 그대로 복사)

---

## 3. 확인

```bash
sudo /opt/trial/scripts/check_canary.sh          # Canary 해시 + auditd 이벤트 확인
sudo /opt/trial/scripts/collect_state.sh <run_id> <phase>   # 상태 스냅샷 (Evidence용)
```

`check_canary.sh`가 확인하는 auditd 키: `canary_access`(Canary 접근) · `exec_trace`(프로세스 실행) · `mount_trace`(마운트) · `perm_change`(권한 변경) · `persistence_cron`/`persistence_systemd`(지속성 경로) · `sudoers_change`/`passwd_change`/`group_change`/`shadow_change`(계정 파일) · `docker_daemon_change`.

**주의**: auditd 로그는 그 EC2 로컬에만 쌓임 (CloudWatch로 안 보냄). `destroy`하면 같이 사라짐.

`collect_state.sh` 결과는 `/opt/trial/evidence/<run_id>/<phase>/`에 남는 것과 별개로, 같은 내용이 `evidence.tf`가 만든 S3 버킷(`s3://<evidence_bucket>/runs/<run_id>/<phase>/`)으로도 자동 업로드됨 — EC2를 지우거나 실험 대상이 침해당해도 그 시점 증거는 S3에 남음. EC2 Role엔 `PutObject`만 있고 `DeleteObject`는 없어서, 이 권한으로는 이미 올라간 증거를 못 지움. 버킷 이름은 `terraform apply` 결과의 `evidence_bucket` 출력값 참고.

---

## 4. Golden AMI / 예산 알림 (선택)

EC2가 `running` 상태인 것과 부트스트랩(Docker/auditd/journald 설치)이 완료된 것은 다른 얘기임. 초기 설정이 덜 끝난 상태에서 Golden AMI를 만들면 불완전한 이미지가 그대로 저장됨. **AMI 만들기 전에 SSM으로 접속해서 아래를 먼저 확인**:

```bash
aws ssm start-session --target <instance-id>

cloud-init status --wait                       # 부팅 초기화 자체가 다 끝났는지
test -f /var/lib/trial-bootstrap-complete && echo OK   # user_data.sh.tpl이 끝까지 성공했는지
sudo docker run --rm hello-world                # Docker가 실제로 컨테이너를 돌릴 수 있는지
sudo systemctl is-active auditd                 # auditd가 떠 있는지
```

넷 다 정상으로 나온 뒤에 Golden AMI를 만듦:

```bash
terraform apply -var="create_golden_ami=true"      # 지금 EC2 상태를 AMI로 저장 → golden_ami_id 출력
terraform apply -var="golden_ami_id=ami-xxxxxxxx"  # 이후 재부트스트랩 없이 바로 이 AMI로 기동
terraform apply -var="budget_alert_email=you@example.com"  # 월 10 USD(기본) 80% 초과시 메일
```

---

## 5. 정리

```bash
terraform destroy
```

---

## 원격 state (아직 비활성화, 팀원 여러 명이 apply할 때 전환)

이제 팀 공용 계정을 같이 쓰니까, 여러 명이 apply하기 시작하는 시점엔 바로 전환하는 걸 권장. (`bootstrap/`도 같은 프로필로 apply)

```bash
cd bootstrap && terraform init && terraform apply -var="aws_profile=whs-team"
# 출력된 state_bucket_name / dynamodb_table_name을 ../backend.tf에 채워넣고 주석 해제
cd .. && terraform init -migrate-state
```

전환 후에도 팀원이 apply해서 같은 결과를 보려면: 같은 AWS 계정 · `backend.tf` 최신 코드 `git pull` · `terraform init` 재실행 · 충분한 IAM 권한, 이 네 가지가 다 맞아야 함. 동시 apply는 DynamoDB 락으로 막힘.

---

## 구조 한눈에

| 파일 | 만드는 것 |
|---|---|
| `vpc.tf` | VPC, Private Subnet, Security Group(inbound 없음, outbound 443/80/53만), SSM VPC Endpoint |
| `nat.tf` | Public Subnet + NAT Gateway (EC2 아웃바운드 인터넷용) |
| `iam.tf` | EC2용 IAM Role (SSM 관리 권한만) |
| `ec2.tf` | Trial EC2 (Ubuntu 24.04, IMDSv2, EBS 암호화) |
| `user_data.sh.tpl` | 부트스트랩 스크립트 — Docker(Compose v2)/auditd 설치, Canary 파일 생성, `check_canary.sh`/`collect_state.sh` 배치 |
| `logging.tf` | VPC Flow Logs, CloudTrail (멀티 리전, 로그 무결성 검증, S3 버킷 암호화·비공개) |
| `budget.tf` | 월간 비용 알림 |
| `ami.tf` | Golden AMI 생성 (`create_golden_ami=true`일 때만) |
| `evidence.tf` | Evidence 반출용 S3 버킷(KMS 암호화, 버저닝, EC2엔 쓰기 전용 권한만) |
| `backend.tf`, `bootstrap/` | 원격 state (S3 + DynamoDB), 지금은 비활성화 |
| `compose/` | Docker Compose 권한 Profile (container-baseline / container-mount-rw) |

## 안 만드는 것

Local Control Panel, Trusted Orchestrator, Policy Gateway, Host/Container Executor, LLM 연동, Evidence Collector/Verifier — 전부 별도 애플리케이션. Terraform은 이것들이 올라갈 EC2·네트워크·권한만 준비함.

## 버전

Terraform `>= 1.6.0` · AWS Provider `~> 6.0` · Ubuntu 24.04(SSM Parameter로 항상 최신) · Docker Compose v2. 버전 올린 뒤엔 `terraform init -upgrade`로 lock 파일 갱신.

## 다음 단계

1. Agent + Policy Gateway + Executor 별도 코드 작성
2. Compose override를 권한 Profile별로 분리
3. Trusted Orchestrator가 이 Terraform을 호출하는 방식 설계
4. 팀원 여러 명 apply 시점에 `bootstrap/`으로 원격 state 전환
