# OS-Agent 0826 Terraform 전면 변경사항

작성 기준: 2026-08-27

> 비교 대상
>
> - 기존판: `C:\Users\oeseo\Desktop\OS-Agent\infra\terraform`
> - 0826 수정안: `C:\Users\oeseo\Documents\ChatGPT\OS Local\terraform-staging\infra\terraform`
>
> **중요:** 쓰기 권한이 승인되지 않아 Desktop의 실제 저장소는 아직 기존판 그대로다. 이 문서는 검증이 끝난 staging 수정안을 기준으로 한 변경 설계서다. Git commit/push와 AWS plan/apply도 실행하지 않았다.

빠르게 읽으려면 다음 순서만 보면 된다.

1. `1. 30초 요약`
2. `2. 새 최종 구조`
3. `3. 완전히 삭제되는 기존 내용`
4. `8. 로깅과 Evidence`
5. `14. Terraform 밖에서 반드시 준비할 것`
6. `17. 최종 반영 전에 고쳐야 할 발견 사항`

나머지는 필요할 때 파일명이나 변수명으로 검색하면 된다.

---

## 1. 30초 요약

기존 Terraform은 다음 실험을 위한 구성이었다.

> Backend 컨테이너 + nginx target + Canary 파일 + RO/RW 권한 Profile 비교

0826 수정안은 이를 전부 걷어내고 다음 구조로 바꾼다.

> Linux Host User1/User2 + Container1/2/3 + U1/C1 두 executor + 정확히 8개 실험 경로 + auditd/journald/Docker/Before·After/Vector Evidence 수집

| 구분 | 기존 | 0826 수정안 |
|---|---|---|
| 실험 중심 | Canary 파일과 mount RO/RW 비교 | U1·C1 executor가 다섯 target에 수행하는 8개 경로 |
| Host 사용자 | 실제 U1/U2 없음, UID 10003 기반 backend 중심 | `user1`=U1, `user2`=U2를 명시적으로 생성 |
| 컨테이너 | Backend, nginx, 별도 Alpine 실습 컨테이너 | C1, C2, C3 세 컨테이너로 고정 |
| Source executor | Backend 컨테이너 | U1 executor, C1 executor |
| Target | nginx 또는 Canary 파일 | U1, U2, C1, C2, C3 |
| 로깅 | optional VPC Flow Logs, 수동 audit/Canary 확인 | auditd, journald, Docker events, stdout/stderr, executor event, Before/After를 Vector가 통합 수집 |
| 이미지 | Backend ECR 한 개, tag URI | runtime/container1/target ECR 세 개, manifest digest 고정 |
| 상태 재현 | 최신 Ubuntu 또는 Golden AMI 선택 | Canonical Ubuntu 24.04 AMI ID를 검증 후 고정 |
| Evidence 저장 | EC2 로컬 수동 snapshot | 로컬 NDJSON은 항상 저장, FastAPI 원격 sink는 선택적 |
| Supabase | 구현 없음 | 여전히 Terraform 밖. Vector → FastAPI → Supabase 구조 |
| 배포 방식 | 기존 대시보드 controller | 새 빈 state에서 수동 2단계 ECR 배포 |

한 줄로 말하면, **가변적인 권한 Profile 실습을 삭제하고 고정된 8-path OS 행동 관측 실험실로 교체**한 것이다.

---

## 2. 새 최종 구조

```text
AWS Sandbox
└─ VPC
   ├─ Public Subnet
   │  └─ NAT Gateway 전용
   ├─ Private Subnet
   │  └─ Ubuntu 24.04 EC2 1대
   │     ├─ Linux Host User1: user1 / UID 21001
   │     │  ├─ Host1 Target
   │     │  └─ U1 executor 실행 주체
   │     ├─ Linux Host User2: user2 / UID 21002
   │     │  └─ Host2 Target
   │     ├─ Container1 / UID 22001
   │     │  ├─ C1 executor
   │     │  └─ C1 Target
   │     ├─ Container2 / UID 22002
   │     │  └─ C2 Target
   │     ├─ Container3 / UID 22003
   │     │  └─ C3 Target
   │     ├─ root-owned Host Supervisor
   │     └─ Evidence collector
   │        ├─ auditd
   │        ├─ systemd-journald
   │        ├─ Docker json-file
   │        ├─ Docker event/log relay
   │        ├─ Before/After capture
   │        └─ Vector
   └─ SSM VPC Endpoints
```

고정된 실험 경로는 아래 8개뿐이다.

| ID | Source | Target |
|---|---|---|
| `U1C1` | U1 executor | C1 Target |
| `U1C2` | U1 executor | C2 Target |
| `U1U2` | U1 executor | U2/Host2 Target |
| `U1C3` | U1 executor | C3 Target |
| `C1U1` | C1 executor | U1/Host1 Target |
| `C1C2` | C1 executor | C2 Target |
| `C1U2` | C1 executor | U2/Host2 Target |
| `C1C3` | C1 executor | C3 Target |

`topology.yaml`이 이 구조의 원본이다. Terraform plan 단계에서는 revision, 사용자 UID/GID, 컨테이너 owner/role/UID/GID와 8개 mapping이 바뀌지 않았는지 precondition으로 검사한다.

단, 네트워크와 UID만으로 8개 요청을 완전히 강제할 수는 없다. **실제 positive/negative path 인가는 새 Host Supervisor와 runtime 이미지가 `topology.json`을 읽어 다시 검사해야 한다.**

---

## 3. 완전히 삭제되는 기존 내용

아래 기능은 이름만 바뀐 것이 아니라 새 0826 범위에서 제거된다.

| 삭제 파일 | 기존 역할 | 삭제 이유 / 대체 여부 |
|---|---|---|
| `ami.tf` | 실행 중 EC2에서 Golden AMI 생성 | 삭제. 새 구성은 이미 준비된 Canonical Ubuntu AMI ID를 검증·고정한다. AMI bake 기능 자체는 대체되지 않는다. |
| `budget.tf` | 월간 AWS Budget과 80% 이메일 알림 | 실험 topology 범위 밖으로 제거. 대체 없음. |
| `logging.tf` | optional VPC Flow Logs → CloudWatch Logs | 제거. Host/Docker 행동 Evidence로 전환하지만 VPC Flow Logs의 직접 대체는 아니다. |
| `runtime-compose.yml.tpl` | `os-agent-backend` + `nginx-target`, 8000 포트 | `experiment-compose.yml.tpl`의 C1/C2/C3 구조로 대체. |
| `compose/docker-compose.yml` | Alpine executor와 Canary read-only baseline | Canary/Profile 실험 폐기로 삭제. |
| `compose/docker-compose.override.mount-rw.yml` | Canary mount를 RO → RW로 변경 | 가변 Profile 실험 제거로 삭제. |
| `compose/README.md` | 위 Profile 실험 수동 실행법 | 더 이상 유효하지 않아 삭제. |
| `SOURCE.lock` | 과거 upstream commit 사본 정보 | 0826 전면 교체안과 맞지 않아 삭제. |
| `UPSTREAM_README.md` | 과거 upstream 설계 문서 | 실제 구현과 어긋나는 내용이 있어 삭제. |

삭제되는 기능만 다시 묶으면 다음과 같다.

- Golden AMI 생성
- AWS Budget/이메일 알림
- VPC Flow Logs/CloudWatch Log Group
- CloudWatch Agent IAM 옵션
- Canary 파일과 해시 비교
- `container-baseline` / `container-mount-rw` Profile
- Backend 컨테이너의 localhost 8000 포트
- nginx target
- Backend용 외부 egress Docker network
- SSM port forwarding용 Backend output
- 기존 대시보드 자동 배포 계약

따라서 새 구성에도 비용 알림이나 VPC network-flow 관측이 필요하다면 별도 범위로 다시 설계해야 한다.

---

## 4. 기존 파일별 Before → After

| 파일 | 기존 | 0826 수정안 |
|---|---|---|
| `.terraform.lock.hcl` | AWS provider lock | 그대로 유지. AWS provider 6.61.0을 사용해 정적 검증했다. |
| `versions.tf` | Terraform `>=1.6`, backend 미선언 | Terraform `>=1.9`, 별도 local backend `terraform-0826.tfstate` 지정 |
| `variables.tf` | EC2 count, Flow Log, Golden AMI, Canary, Budget, Backend tag 중심 | 고정 AMI, 이미지 digest 3개, Vector checksum, Evidence API/SSM/KMS와 새 state 확인값 중심 |
| `fixed.auto.tfvars` | region/AZ/type/count와 여러 on/off flag | region/AZ/type, root EBS 30GiB만 고정 |
| `terraform.tfvars.example` | Budget/CloudWatch/Golden AMI 예시 | 새 state 확인, AMI, digest 3개, Vector SHA, 원격 Evidence 설정 예시 |
| `data.tf` | caller identity와 partition | Canonical Ubuntu 24.04 amd64 AMI 실체 검증 추가 |
| `vpc.tf` | HTTP/HTTPS egress, UDP DNS, endpoint SG 전체 egress | HTTPS 443과 UDP/TCP DNS만 허용, endpoint SG 불필요 egress 제거 |
| `nat.tf` | NAT subnet auto-public-IP 사용 | NAT subnet도 auto-public-IP를 끄고 EIP만 사용; 생성 순서 의존성 강화 |
| `iam.tf` | SSM, optional CloudWatch, Backend ECR 한 개 pull | SSM, 세 ECR 최소 pull, 조건부 SSM token/KMS decrypt |
| `ecr.tf` | Backend repo 한 개, tag 불변, 최근 5개, `force_delete=true` | runtime/container1/target repo 세 개, digest 확인, 자동 만료 없음, `force_delete=false` |
| `ec2.tf` | count형 EC2, 최신/Golden AMI, 20GiB, Backend tag 확인 | singleton EC2, 검증된 AMI, 30GiB, topology/digest/checksum/state/user-data 크기 검증 |
| `user_data.sh.tpl` | Canary와 Backend/nginx 부팅 | 사용자·세 컨테이너·Vector·auditd·journald·relay·Before/After·검증 환경 부팅 |
| `outputs.tf` | 배열형 EC2, Canary, Golden AMI, Backend ECR/port/tunnel | 단일 EC2, ECR 세 개, topology/users/containers/remote sink 상태 |
| `README.md` | 기존 대시보드와 Canary 실험 절차 | 0826 이미지 계약, 새 state, 2단계 ECR, Evidence와 부팅 검증 절차 |

### `versions.tf` / State

- Terraform 최소 버전을 `1.9.0`으로 올렸다.
- `availability_zone` 검증에서 `aws_region`을 참조하므로 Terraform 1.9 이상이 필요하다.
- 기존 암묵적 local state 대신 `terraform-0826.tfstate`를 명시했다.
- `confirm_new_state=true`가 없으면 전체 EC2 배포를 막는다.
- 기존 OS-Agent state를 migrate하거나 in-place 변경하는 구성이 아니다.
- 실제 저장소의 `.gitignore`는 `*.tfstate`, `*.tfstate.*`, `**/.terraform/`을 제외한다.

### `data.tf` / AMI

기존에는 AWS SSM public parameter의 최신 Ubuntu AMI 또는 직접 만든 Golden AMI를 선택했다. 새 구성은 `base_ami_id`가 다음 조건을 만족하는지 AWS에서 조회한다.

- Canonical owner: `099720109477`
- Ubuntu Noble 24.04 server
- amd64/x86_64
- HVM
- EBS root device
- available 상태
- 사용자가 입력한 정확한 AMI ID

즉, 최신 이미지로 자동 이동하는 drift를 없앴다.

### `vpc.tf` / `nat.tf`

유지되는 큰 틀은 VPC, Public NAT Subnet, Private EC2 Subnet, IGW, NAT Gateway, SSM endpoints다.

세부 변경은 다음과 같다.

- 모든 AWS 리소스 이름을 `<project_name>-<environment_id>` prefix로 통일
- EC2 public IP 없음 유지
- inbound 없음 유지
- outbound HTTP 80 제거
- HTTPS 443 허용
- VPC DNS에 UDP 53뿐 아니라 TCP 53 fallback 추가
- endpoint SG의 명시적 전체 egress 제거
- NAT 전용 public subnet도 public IP 자동 할당 비활성화
- NAT 생성 전 public route-table association까지 완료되도록 의존성 추가
- Ubuntu apt mirror도 bootstrap에서 HTTPS로 변환

### `iam.tf`

EC2 role의 권한은 다음만 남긴다.

- `AmazonSSMManagedInstanceCore`
- runtime/container1/target ECR repository pull
- 원격 Evidence sink가 켜진 경우에만 지정 SSM SecureString `GetParameter`
- 그 SecureString이 customer-managed KMS key를 쓰는 경우에만 해당 key `kms:Decrypt`

제거되는 IAM 범위는 CloudWatch Agent, VPC Flow Logs, 단일 Backend ECR pull이다.

Supabase DB credential은 EC2/Vector IAM이나 Terraform 변수에 넣지 않는다.

### `ecr.tf`

기존 `${project}-backend` 한 개를 다음 세 repository로 분리한다.

| Repository | 용도 | 필수 contract marker |
|---|---|---|
| `runtime` | Host Supervisor와 U1 runtime 원본 | `action-path-runtime-v1` |
| `container1` | C1 executor + C1 Target | `container1-executor-target-v1` |
| `target` | C2/C3 공용 Target | `target-service-v1` |

공통 정책은 다음과 같다.

- tag immutable
- AES256 encryption
- push scan
- 실제 manifest digest 존재 확인
- lifecycle 자동 만료 제거
- `force_delete=false`

태그가 아니라 `sha256:...` digest를 입력해야 한다.

### `ec2.tf`

- `count`를 제거하고 EC2 한 대를 코드 구조로 고정했다.
- root EBS 기본값을 20GiB → 30GiB로 늘렸다.
- root EBS encryption과 delete-on-termination은 유지했다.
- IMDSv2와 hop limit 1은 유지했다.
- user-data 변경 시 EC2 replacement는 유지했다.
- 18개 설정/스크립트를 하나의 minified JSON bundle로 묶어 gzip+base64로 전달한다.
- 전체 user-data도 gzip+base64하며 내부 크기 상한을 20,480 base64 문자로 검사한다.
- 다음 precondition을 추가했다.
  - 새 state 사용 확인
  - topology revision과 정확한 8 paths
  - U1/U2 UID/GID/source capability
  - C1/C2/C3 name/owner/UID/GID/role
  - base AMI 입력
  - 이미지 digest 3개와 Vector checksum 입력
  - 원격 sink 사용 시 URL과 token parameter 입력
  - user-data 크기
- ECR manifest가 실제로 존재해야 full plan이 진행된다.

---

## 5. 새로 추가되는 파일

### Topology와 Docker

| 신규 파일 | 역할 |
|---|---|
| `topology.yaml` | U1/U2, C1/C2/C3, Supervisor group, 8개 경로의 단일 원본 |
| `locals.tf` | topology decode, resource prefix, UID/role/path 계약 검증, digest URI 생성 |
| `experiment-compose.yml.tpl` | C1/C2/C3의 실행, network, UID, healthcheck, 보안 설정 |

### 로깅/보안 설정

| 신규 파일 | 역할 |
|---|---|
| `config/docker/daemon.json` | Docker json-file, 20MB×5, label metadata, live-restore |
| `config/audit/os-agent.rules.tpl` | U1/U2/C1/C2/C3 실행과 경계·target·계정·설정 변경 감사 |
| `config/journald/99-os-agent.conf` | persistent/sealed journal과 용량·보존·rate limit |
| `config/nftables/os-agent.nft.tpl` | U1/U2의 직접 IP egress 차단, loopback 허용 |
| `config/vector/vector.yaml.tpl` | 여섯 종류 source와 local/remote sink |
| `config/vector/normalize.vrl.tpl` | event metadata, event ID, 시간 정규화, 민감 필드 제거 |
| `config/logrotate/os-agent` | relay/executor/state/local evidence NDJSON rotation |

### 실행 스크립트

| 신규 파일 | 역할 |
|---|---|
| `scripts/relay_docker_events.sh` | 세 컨테이너의 Docker lifecycle event를 NDJSON으로 기록 |
| `scripts/relay_docker_logs.sh` | 세 컨테이너의 stdout/stderr를 분리해 NDJSON으로 기록 |
| `scripts/capture_state.sh` | action별 Before/After snapshot, diff, hash, manifest 생성 |
| `scripts/verify_environment.sh` | topology, UID, socket, service, container, network, collector 검증 |

### systemd 서비스

| 신규 파일 | 시작 조건 / 역할 |
|---|---|
| `systemd/os-agent-docker-events.service` | Docker 다음, 컨테이너보다 먼저 event relay 시작 |
| `systemd/os-agent-host-supervisor.service` | root-owned Supervisor와 Unix socket 제공 |
| `systemd/os-agent-experiment.service` | Supervisor socket 확인 후 C1/C2/C3 기동 및 health 대기 |
| `systemd/os-agent-docker-logs.service` | 실험 컨테이너 뒤 stdout/stderr relay 시작 |
| `systemd/vector.service` | 최소 권한 `vector` 사용자로 Evidence 수집 |

---

## 6. Linux 사용자와 권한 모델

### 기존

- 암묵적 Backend UID `10003`
- `agent-host` UID/GID `10004`
- 실질적으로 사용되지 않은 `agent-trial` GID `10005`
- Supervisor GID `10006`
- 실제 Linux Host User1/User2 구분 없음
- Canary 디렉터리를 Backend UID가 소유

### 0826 수정안

| ID | 실제 identity | 역할 |
|---|---|---|
| U1 | `user1`, UID/GID 21001 | Host1 Target + Host executor 주체 |
| U2 | `user2`, UID/GID 21002 | Host2 Target 전용 |
| C1 | UID/GID 22001 | Container1 executor + Target |
| C2 | UID/GID 22002 | Container2 Target |
| C3 | UID/GID 22003 | Container3 Target |
| Supervisor group | GID 21010 | `user1`과 C1만 socket 사용 |
| Vector | 별도 system user | journal/audit 읽기와 Evidence sink 쓰기 |

추가 통제:

- `user1`과 `user2`의 password를 lock한다.
- `user1`만 `os-agent-supervisor` group에 넣는다.
- `user2`는 Supervisor socket 접근이 거부되어야 한다.
- `user1`, `user2`, `vector`를 Docker group에 넣지 않는다.
- 컨테이너에도 Docker socket을 mount하지 않는다.
- Host target은 해당 Linux user가 소유한다.
- Container target은 22001/22002/22003 numeric identity가 각각 소유한다.

---

## 7. Docker 구조 변경

### 기존

```text
os-agent-backend
├─ localhost:8000 공개
├─ Supervisor socket
├─ control network
└─ egress network

nginx-target
└─ control network

별도 수동 실습:
alpine agent-executor → Canary RO/RW mount 전환
```

### 0826 수정안

```text
C2 ── internal c1_c2 ── C1 ── internal c1_c3 ── C3
                         │
                         └─ Host Supervisor Unix socket
```

- C1은 두 internal network에 모두 연결한다.
- C2와 C3는 서로 같은 network를 공유하지 않는다.
- C1만 Supervisor socket directory를 mount한다.
- 외부로 공개되는 container port가 없다.
- 세 컨테이너 모두 non-root numeric UID를 사용한다.
- root filesystem은 read-only다.
- `/workspace` target directory와 제한된 tmpfs만 쓸 수 있다.
- 모든 Linux capability를 drop한다.
- `no-new-privileges`를 켠다.
- PID, memory, CPU 한도를 둔다.
- `/app/healthcheck`가 성공해야 Compose `up --wait`가 끝난다.
- Docker log driver는 json-file이다.
- topology owner/role/revision label을 붙인다.

네트워크 분리는 C2↔C3 직접 통신은 막지만 bridge 자체는 양방향이다. 정확히 8개 path만 허용하는 최종 인증은 Supervisor와 각 runtime의 peer identity/path allowlist가 담당해야 한다.

---

## 8. 로깅과 Evidence: 무엇이 서비스이고 무엇이 파일인가

| 구성 | 정체 | 설치/생성 방식 | 자동 여부 |
|---|---|---|---|
| `auditd` | Ubuntu OS 감사 서비스 | apt 설치 후 rules load | rules가 로드되면 자동 |
| `systemd-journald` | Ubuntu 기본 systemd 로그 서비스 | drop-in 설정으로 persistent 전환 | 자동 |
| Docker `json-file` | Docker 내장 logging driver | daemon/Compose 설정 | 컨테이너 stdout/stderr 자동 기록 |
| Docker event relay | 이번 구성의 custom systemd service | shell script + unit 설치 | 자동 |
| Docker log relay | 이번 구성의 custom systemd service | shell script + unit 설치 | 자동 |
| Before/After capture | 이번 구성의 custom script | EC2에 설치 | Supervisor가 action 전후 호출해야 함 |
| Vector | 무료 OSS collector daemon | 공식 archive 설치 후 systemd service화 | service 시작 후 자동 수집 |
| 로컬 Evidence file | Vector file sink | Vector가 생성 | 자동 |
| Supabase Evidence Store | 외부 DB | FastAPI가 적재 | Terraform 범위 밖 |

핵심 파이프라인은 다음과 같다.

```text
auditd
systemd-journald
Docker events relay
Docker stdout/stderr relay
executor NDJSON
Before/After NDJSON
        │
        ▼
Vector normalize
        ├─ 항상: EC2 local events.ndjson + disk buffer
        └─ 선택: HTTPS FastAPI Evidence API
                         │
                         ▼
                 Supabase Evidence Store
```

Vector가 Supabase에 직접 연결하지 않는다. Vector가 아는 비밀은 원격 sink용 bearer token뿐이며, 이 값도 Terraform 변수/state/user-data에 넣지 않고 부팅 시 SSM SecureString에서 읽는다.

### 실험 흐름별 기록 책임

| 기록 대상 | 누가 생성하는가 | Terraform 수정안이 하는 일 |
|---|---|---|
| 모델 요청/응답 | Model Gateway/FastAPI 애플리케이션 | 직접 기록하지 않음 |
| FastAPI tool 요청 | FastAPI | 직접 기록하지 않음 |
| executor 실제 명령 | U1/C1 runtime | NDJSON 저장 경로와 Vector source만 준비 |
| stdout/stderr/exit code | U1/C1 runtime | runtime이 executor NDJSON으로 반드시 기록해야 함 |
| Host exec/identity/경계 변경 | kernel + auditd | rules 설치 후 자동 수집 |
| systemd service 로그 | journald | 보존 설정과 Vector source 구성 |
| Docker lifecycle | Docker API + relay | custom service로 자동 NDJSON 변환 |
| 컨테이너 stdout/stderr | json-file + relay | custom service로 자동 NDJSON 변환 |
| Before/After state | capture script | 설치만 함. Supervisor가 호출해야 함 |
| 통합·정규화·전송 | Vector | Terraform이 설치·설정·서비스화 |
| Supabase 적재 | FastAPI Evidence API | Terraform 범위 밖 |

따라서 Terraform만 바꾸면 OS·Docker 관측 장치는 생기지만, 모델 요청부터 Supabase까지 하나의 action으로 묶으려면 애플리케이션이 모든 단계에 동일한 `run_id`, `action_id`, `path_id`를 전달해야 한다.

---

## 9. 수집원별 상세 변경

### auditd

기존은 Canary, cron/systemd/account 파일과 모든 b64 exec/mount/chmod/chown를 광범위하게 감시했다. 새 rules는 topology identity 중심으로 바뀐다.

- U1/U2/C1/C2/C3의 `execve`, `execveat`를 euid별 기록
- U1/U2의 setuid/setgid/capability 변경 기록
- root Supervisor의 namespace/mount 경계 기록
- root의 Docker CLI 실행 기록
- Host1/Host2/C1/C2/C3 target directory 변경 기록
- runtime/config/systemd/Docker socket 설정 변경 기록
- passwd/group/shadow/sudo/cron 변경 기록
- audit log 100MB×5
- Vector가 current/rotated audit log를 읽음

### journald

기존은 `Storage=persistent`만 설정했다. 새 drop-in은 다음을 고정한다.

- persistent
- compression
- seal
- 최대 512MB
- 2GB free reserve
- runtime journal 128MB
- 최대 7일
- rate limit
- Vector cursor/checkpoint 기반 수집

### Docker json-file / event / stdout·stderr

- 기존 10MB×5 → 새 20MB×5
- 세 container 모두 topology label 포함
- Docker lifecycle event를 별도 NDJSON으로 relay
- stdout와 stderr를 분리해 container ID/name/timestamp와 stable event ID를 붙임
- relay가 각 event마다 append-open하여 logrotate 뒤 새 파일을 따름
- timestamp 경계 재시작 시 같은 event가 중복될 수 있으나 stable event ID로 downstream idempotency를 기대함

### Before/After state

기존 `collect_state.sh`는 `run_id`와 `phase`만 받아 Host 전체 상태를 수동 dump했다.

새 `capture_state.sh`는 다음 다섯 인자를 요구한다.

```text
run_id action_id path_id before|after target_id
```

새 동작:

- ID 형식 검증
- 8개 path와 target 조합 검증
- action 단위 file lock
- `after` 전에 정상 `before` 존재·무결성 강제
- Host target이면 identity와 user process 기록
- Container target이면 inspect/top/diff 기록
- target 파일 hash와 metadata 기록
- Before 대비 file hash diff 기록
- journal cursor와 audit status 기록
- temp directory에서 완성 후 atomic rename
- manifest와 artifact hash index 생성
- 재호출 시 무결성 확인 후 같은 stable event 재발행
- STARTED/FAILED/COMPLETE boundary를 journal과 audit에 기록

호출 자동화는 Terraform이 아니라 Supervisor의 책임이다.

### Vector

고정 버전은 Vector `0.57.0`이며 공식 archive SHA-256이 일치해야 설치한다.

Vector source:

- journald
- auditd files
- Docker event relay file
- Docker log relay file
- executor NDJSON files
- state-capture NDJSON file

공통 처리:

- collector channel
- environment ID
- topology revision
- collector 수신 시각
- stable event ID
- occurred_at 정규화
- authorization/header/environment 계열 필드 제거

Sink:

- local file sink는 항상 활성화
- local disk buffer 약 256MiB
- remote HTTP sink는 선택 활성화
- remote disk buffer 512MiB
- gzip NDJSON, batch 250건/2초
- timeout/retry/backpressure/acknowledgement
- bearer token은 Vector directory secret backend 사용

---

## 10. 보존과 유실 범위

| 데이터 | 보존/회전 | 주의 |
|---|---|---|
| Docker native json-file | 컨테이너별 20MB×5 | 원본 Docker 로그 |
| relay/executor/state NDJSON | 50MB×7, 압축 | logrotate 적용 |
| normalized local Evidence | 100MB×7, 압축 | Vector HUP으로 새 파일 reopen |
| auditd | 100MB×5 | `adm` 읽기, Vector 쓰기 불가 |
| journald | 최대 512MB, 최대 7일 | 2GB 여유 공간 예약 |
| Vector local buffer | 약 256MiB | sink backpressure 시 사용 |
| Vector remote buffer | 512MiB | remote sink 활성화 때 사용 |
| Before/After artifact directory | 현재 자동 GC 없음 | 장기 실험 시 계속 증가 가능 |

로컬 Evidence와 Before/After artifact는 EC2 root EBS에 있다. EBS는 instance replacement/destroy 시 삭제되므로 실제 실험에서는 다음 중 하나가 필요하다.

- remote Evidence sink를 먼저 활성화
- 교체/삭제 전에 artifact export
- 향후 별도 보존 EBS/S3 정책 추가

Vector 자체는 무료 OSS지만 EC2, EBS, NAT Gateway, EIP, VPC endpoints와 원격 저장소 사용료는 별도다. 기존 AWS Budget 파일이 삭제되므로 비용 알림도 자동으로 만들어지지 않는다.

---

## 11. 변수 변경표

### 삭제되는 변수

| 변수 | 삭제 이유 |
|---|---|
| `trial_ec2_count` | EC2 한 대를 코드로 고정 |
| `enable_flow_logs` | VPC Flow Logs 제거 |
| `golden_ami_id` | Golden/latest 분기 제거 |
| `canary_file_path` | Canary 실험 제거 |
| `create_golden_ami` | AMI 생성 제거 |
| `attach_cloudwatch_agent_policy` | CloudWatch Agent 제거 |
| `budget_limit_usd` | Budget 제거 |
| `budget_alert_email` | Budget 알림 제거 |
| `backend_image_uri` | 단일 tagged Backend 이미지를 digest 이미지 세 개로 교체 |

### 추가되는 변수

| 변수 | 용도 |
|---|---|
| `confirm_new_state` | 기존 state를 쓰지 않는다는 명시적 확인 |
| `root_volume_size_gib` | root EBS 크기, 기본 30GiB |
| `base_ami_id` | 검증 후 고정한 Ubuntu AMI ID |
| `runtime_image_digest` | Host Supervisor/U1 runtime artifact digest |
| `container1_image_digest` | C1 executor+target image digest |
| `target_image_digest` | C2/C3 target image digest |
| `vector_archive_sha256` | Vector archive 무결성 |
| `enable_remote_evidence_sink` | FastAPI Evidence API 전송 여부 |
| `evidence_api_url` | HTTPS FastAPI 기본 URL |
| `collector_token_parameter_name` | 기존 SSM SecureString 경로 |
| `collector_token_kms_key_arn` | customer-managed KMS key 사용 시 ARN |

### 강화되거나 이동된 변수

- `public_subnet_cidr`: `nat.tf` 내부 선언 → `variables.tf`로 이동
- `project_name`: 기본 `trial` → `os-agent`, 최대 길이 19자로 축소
- `environment_id`: 기본 `trial` → `trial-0826`, 형식 검증 추가
- `aws_region`: AWS region 형식 검증 추가
- `availability_zone`: 선택한 region 소속인지 교차 검증
- Evidence URL: HTTPS, query/fragment/trailing slash 금지
- digest/SHA/KMS ARN: 형식 검증 추가

---

## 12. Output 변경표

### 삭제되는 output

- `trial_ec2_instance_ids`
- `trial_ec2_private_ips`
- `canary_file_path`
- `golden_ami_id`
- `backend_ecr_repository_url`
- `environment_id`
- `created_by`
- `backend_local_port`
- `backend_ssm_port_forward_commands`

### 새 output

- `trial_ec2_instance_id`
- `trial_ec2_private_ip`
- AWS profile을 선택 반영하는 `ssm_connect_command`
- `ecr_repository_urls` map
- `topology_revision`
- `topology_action_path_ids`
- `expected_linux_users`
- `expected_containers`
- `remote_evidence_sink_enabled`

기존 대시보드 controller는 옛 resource address와 output을 사용하므로 새 Terraform에 연결하면 안 된다.

---

## 13. 부팅 순서 변경

새 `user_data`는 다음 순서로 동작한다.

1. Ubuntu apt source를 HTTPS로 변경
2. apt retry 설정으로 필수 package 설치
3. Docker 공식 repository와 Docker/Compose 설치
4. Vector archive 다운로드, SHA-256 검증, 설치
5. `user1`, `user2`, Supervisor group, Vector user 생성
6. Host/Container target directory와 Evidence directory 생성
7. 압축 asset bundle에서 config/scripts/systemd units 복원
8. journald, Docker, nftables, auditd 설정 적용
9. ECR 로그인 후 digest image 3개 pull
10. 세 이미지의 `RUNTIME_CONTRACT` marker 검사
11. runtime image에서 Host Supervisor/U1 runtime Python 파일 추출
12. 원격 sink 사용 시 SSM token 복호화
13. Vector config와 Compose config 사전 검증
14. Docker events → Supervisor → C1/C2/C3 → Docker logs → Vector 순서로 시작
15. `verify_environment.sh` 전체 검사
16. 모든 검사가 성공한 경우에만 `/var/lib/os-agent/bootstrap-complete` 생성

apt, curl, ECR authorization/image pull, SSM parameter 조회에는 retry를 추가했다. 설치된 package 버전은 `/var/lib/os-agent/bootstrap-package-versions.txt`에 남긴다.

Terraform의 EC2 resource 생성 성공이 cloud-init 성공을 의미하지는 않는다. 실험 시작 전 다음 세 검증을 반드시 통과해야 한다.

```bash
sudo cloud-init status --wait
sudo test -f /var/lib/os-agent/bootstrap-complete
sudo /opt/os-agent/scripts/verify_environment.sh
```

---

## 14. Terraform 밖에서 반드시 준비할 것

Terraform은 이미지를 build하지 않는다. 새 이미지가 없으면 ECR repository 생성까지만 가능하고 전체 bootstrap은 의도적으로 실패한다.

### runtime image

- Linux amd64
- `/app/RUNTIME_CONTRACT` = `action-path-runtime-v1`
- `/app/host_runtime/host_supervisor.py`
- `/app/runtime_agent/runtime.py`
- 두 Python 파일은 Host Python에서 단독 실행 가능해야 함
- Supervisor `--serve` 지원
- GID 21010 Unix socket 계약
- U1/C1 peer identity와 8-path allowlist 검사
- action 전후 capture 호출
- executor command/stdout/stderr/exit code NDJSON 기록

### container1 image

- `/app/RUNTIME_CONTRACT` = `container1-executor-target-v1`
- C1 executor와 C1 Target을 함께 시작
- `/app/healthcheck` 실행 파일
- UID/GID 22001과 supplemental GID 21010에서 동작
- read-only rootfs와 `/workspace` 조건에서 동작
- Supervisor socket 연결 검사
- `C1U1`, `C1C2`, `C1U2`, `C1C3`만 허용

### target image

- `/app/RUNTIME_CONTRACT` = `target-service-v1`
- C2/C3 공용 이미지
- `/app/healthcheck` 실행 파일
- `OS_AGENT_TARGET_ID`로 C2/C3 구분
- UID/GID 22002 또는 22003에서 동작
- root/capability/privileged port 없이 동작
- internet, Supervisor socket, Docker socket에 의존하지 않음

현재 기존 `backend/Dockerfile`과 legacy Supervisor는 이 marker, healthcheck, UID 21001/22001 계약을 만족하지 않는다. 따라서 기존 Backend 이미지를 그대로 push해서는 새 환경이 부팅되지 않는다.

Terraform 밖인 항목:

- OpenRouter API
- Model Gateway
- FastAPI의 모델/tool/action logging
- FastAPI Evidence API
- Supabase schema와 idempotent insert
- collector token 발급
- 실제 8-path 요청/거부 통합 테스트
- 대시보드 controller 개편

---

## 15. 새 적용 절차

기존 state를 재사용하지 않는다.

1. 수정안을 실제 `infra/terraform`에 반영
2. `terraform init -reconfigure -input=false`
3. `terraform-0826.tfstate`가 없거나 비어 있는지 확인
4. `terraform apply -target='aws_ecr_repository.images'`
5. 새 runtime/container1/target 이미지 build 및 push
6. 세 manifest digest와 AMI/Vector SHA를 `terraform.tfvars`에 입력
7. 원격 Evidence가 준비됐으면 URL과 SSM parameter/KMS ARN 입력
8. `terraform plan -out=0826.plan`
9. 첫 plan이 기존 resource 변경/삭제 없이 새 0826 resource create만 포함하는지 확인
10. `terraform apply 0826.plan`
11. SSM 접속 후 cloud-init/marker/verifier 확인
12. remote sink를 쓰는 실제 실험이면 Supabase까지 한 action이 조회되는지 end-to-end 확인

기존 대시보드의 배포 버튼은 사용하지 않는다.

---

## 16. 현재 검증 결과

staging 수정안에서 통과한 검사:

- Terraform 1.9.5
- AWS provider 6.61.0
- `terraform fmt -check -recursive`
- `terraform validate`
- `terraform graph`
- 대표 값으로 Docker Compose config 검사
- Docker daemon JSON parse
- `user_data.sh.tpl` Bash 문법 검사
- `capture_state.sh` Bash 문법 검사
- Docker event/log relay Bash 문법 검사
- `verify_environment.sh` Bash 문법 검사
- 18개 asset bundle round-trip
- compressed user-data 내부 크기 상한 이내

아직 실행하지 않은 검사:

- 실제 AWS credential과 실제 AMI/digest/checksum을 사용한 `terraform plan`
- 실제 `terraform apply`
- Ubuntu 24.04 cloud-init 부팅
- Vector 0.57.0 실제 config/VRL runtime 검증
- 새 이미지 세 개의 실제 healthcheck
- 8개 positive path와 그 외 negative path 통합 테스트
- FastAPI → Supabase end-to-end 적재

---

## 17. 최종 반영 전에 고쳐야 할 발견 사항

정적 검증은 통과했지만 문서화 과정의 추가 리뷰에서 다음 runtime 위험을 발견했다.

### 1) JSON 형식 Docker 로그의 `message` 유실 가능성

`normalize.vrl.tpl`은 `.message`가 JSON object이면 object를 event에 merge한 뒤 원본 `.message`를 삭제한다. JSON 로그 안에도 `message` 필드가 있으면 merge 후 같이 삭제되어 실제 stdout/stderr payload가 사라질 수 있다.

권장 수정:

- raw payload를 별도 `raw_message`/`log_message` 필드에 보존
- parse한 JSON의 `message`를 삭제하지 않도록 순서 조정
- JSON/non-JSON Docker 로그 샘플로 Vector unit test 추가

### 2) Vector archive에서 잘못된 `vector` 파일 선택 가능성

현재 bootstrap은 archive를 푼 뒤 `find ... -name vector -print -quit`로 첫 파일을 고른다. archive에는 실행 binary 외 init script도 `vector`라는 이름으로 존재할 수 있어 탐색 순서에 따라 잘못 설치할 가능성이 있다.

권장 수정:

- archive 구조를 확인해 정확한 binary 경로를 지정
- 또는 ELF executable 여부를 검사
- 설치 직후 exact version 검사를 유지

### 3) ECR destroy 절차와 pinned digest 조회 충돌

ECR repository는 `force_delete=false`이고 `data.aws_ecr_image.pinned`가 이미지 존재를 조회한다. 이미지를 먼저 수동 삭제한 뒤 바로 `terraform destroy`하면 refresh 단계에서 digest 조회가 실패할 수 있다.

권장 수정:

- EC2와 image-dependent resource를 먼저 제거
- pinned data lookup을 안전하게 해제하는 teardown 절차를 별도로 설계
- repository 비우기와 destroy 순서를 실제 AWS에서 검증
- 검증 전에는 README의 단순 “이미지 삭제 후 destroy”만 믿고 실행하지 않기

---

## 18. 최종 파일 구조

```text
infra/terraform/
├─ .terraform.lock.hcl
├─ versions.tf
├─ variables.tf
├─ fixed.auto.tfvars
├─ terraform.tfvars.example
├─ data.tf
├─ locals.tf
├─ topology.yaml
├─ vpc.tf
├─ nat.tf
├─ iam.tf
├─ ecr.tf
├─ ec2.tf
├─ outputs.tf
├─ experiment-compose.yml.tpl
├─ user_data.sh.tpl
├─ README.md
├─ config/
│  ├─ audit/os-agent.rules.tpl
│  ├─ docker/daemon.json
│  ├─ journald/99-os-agent.conf
│  ├─ logrotate/os-agent
│  ├─ nftables/os-agent.nft.tpl
│  └─ vector/
│     ├─ vector.yaml.tpl
│     └─ normalize.vrl.tpl
├─ scripts/
│  ├─ capture_state.sh
│  ├─ relay_docker_events.sh
│  ├─ relay_docker_logs.sh
│  └─ verify_environment.sh
└─ systemd/
   ├─ os-agent-docker-events.service
   ├─ os-agent-docker-logs.service
   ├─ os-agent-experiment.service
   ├─ os-agent-host-supervisor.service
   └─ vector.service
```

---

## 19. 결론

이 수정은 기존 Terraform에 몇 개 resource를 더하는 수준이 아니다.

- Canary/Profile 실험을 삭제하고
- U1/U2/C1/C2/C3 topology를 새로 고정하며
- Backend/nginx를 세 역할 이미지로 교체하고
- OS/Docker 행동 Evidence pipeline을 새로 만들고
- 기존 state와 대시보드 배포 계약을 끊는

**별도 신규 환경용 전면 교체안**이다.

Terraform이 담당하는 최종 범위는 AWS/Ubuntu/Docker/사용자/서비스/collector 골격까지다. 모델 호출, tool correlation, 실제 executor event, Before/After 호출, 8-path runtime 인가, FastAPI 검증과 Supabase 저장까지 완성되어야 비로소 전체 실험이 end-to-end로 동작한다.
