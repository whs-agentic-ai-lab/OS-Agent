# OS Agent Minimum Test

하나의 EC2 Ubuntu 안에서 Host 사용자와 Docker Container 사이의 방향성 환경 경계를 시험하는 프로젝트다. 모든 구현과 테스트 파일은 이 디렉터리 안에만 둔다.

## 구조

```text
os-Agent-test/
├─ frontend/           # 로컬 React·Vite 대시보드
├─ backend/            # Control Backend, 환경 Runtime Agent, root Supervisor 소스
├─ infra/
│  └─ terraform/       # 고정 인프라와 root-owned Supervisor 설치
├─ data/
│  ├─ schema.sql       # Supabase bootstrap SQL
│  └─ migrations/      # CLI로 생성할 정식 migration 위치
├─ DESIGN.md
└─ OS-최소환경테스트-계획.md
```

## 현재 동작 범위

- 환경 노드: Host `U1`, `U2`와 Container `C1`, `C2`, `C3`
- 시작 Executor: Host Executor=`U1`, Container Executor=`C1`이며 공통 실행 잠금으로 한 Trial에는 반드시 하나만 활성화
- 환경 TB: `U1→U2`, `U1→C1/C2/C3`, `C1→U1/U2`, `C1→C2/C3`의 8개 방향
- 경계별 권한 시험: 세 OFF/ON 값을 하나의 `permission_profile` 묶음으로 적용
- AgentRun 의미: 등록 권한 자동 최대화 + 8개 TB 실행·판정 + Attack Contract + 1-minimal 권한 검증 = `run_id` 1개
- Agent Orchestrator: `권한 수집·최대화 → Recon → 상태 기반 다음 Tool 선택·실행 반복 → 체인 검증·1회 Rollback → 피해 점수 비교 → 전체 Attack Chain 고정 → 권한 축소 재현` 순서로 동작
- TB 판정: 경계마다 `BROKEN`, `BLOCKED`, `INCONCLUSIVE`와 L0~L4 증명 수준, 증거 참조, 복구 상태를 독립 기록
- Agent Tool 카탈로그: 설계된 129개 family와 최소 action enum을 `/api/options`에 동일하게 제공하며 실제 구현 여부를 `implemented`/`implemented_actions`로 구분
- 현재 실제 Tool: `file.content`, `privilege.identity_probe`, `privilege.no_new_privs_probe`, `process.procfs`, `sudo.run`
- Tool Call: Backend의 Model Gateway가 `action`, `resource_ref`, 구조화 `arguments`를 검증해 선택된 Executor로 전달하고 raw shell·임의 절대 경로는 차단
- Agent Runtime: U1/C1에서 동일한 Executor artifact가 allowlist Tool만 실행하며 프롬프트를 다시 해석하지 않음
- Control Backend: Agent Orchestrator·규칙 기반 Planner·Run 배포·결과 수집·독립 Verifier·Supabase 저장을 담당하며 Canary를 직접 읽거나 쓰지 않음
- 결과 분류: `ALLOWED`, `OS_DENIED`, `ERROR`, `POLICY_BLOCKED`; Probe는 자식 문맥 종료 후 초기 신분 복구를 검증
- Evidence: 원본 실행 전·후 해시는 Agent가 아니라 root Supervisor가 수집하고, 전체 `attack_tool_result`는 Executor별 Run의 `applied_profile_state` JSONB에 저장
- 로그: Profile → Model Tool Call → Supervisor → U1/C1 Executor·Tool → Control Verifier 이벤트
- 저장소: Supabase 설정 시 Host 결과는 `host_executor_runs/events`, Container 결과는 `container_executor_runs/events`에 물리 분리 저장하고, 미설정 시 로컬 메모리도 두 실행 레인으로 분리
- 로그 조회: 메인 네비게이션의 `로그 조회`에서 U1 Host/C1 Container 탭을 전환해 각 Executor 결과와 이벤트를 별도로 확인
- 로그 삭제: 목록에서 Run ID를 다시 입력해 단일 실행을 삭제하며 연결된 `run_events`도 함께 삭제
- OS 권한: Container는 실제 mount mode·UID·capability, Ubuntu Host는 실제 소유자·그룹·제한된 sudo 상태로 검증
- 환경 배포: 로컬 대시보드 → 로컬 FastAPI → 고정 Terraform 순서로 AWS 환경과 백엔드 이미지를 자동 배포
- 환경 삭제: 동일한 로컬 Terraform state로 AWS 리소스와 ECR 저장소를 자동 삭제
- SSM 연결: 관리 노드가 Online이 될 때까지 대기한 뒤 `127.0.0.1:8001 → EC2:8000` 자동 연결
- 워크플로우 제어: 7단계 방향성 그래프, 자동 상태 동기화, 수동 체크포인트, 노드별 실제 오류 로그와 상태 복원

## 실제 OS Agent 실험

대시보드의 주 실험 진입점은 `POST /api/remote/agent-runs`다. 로컬 백엔드는 SSM으로 EC2의 `POST /api/agent-runs`를 호출하고, Host·Container 두 Executor를 한 Run 안에서 순차 잠금해 8개 TB를 모두 시험한다. 기존 `POST /api/runs`는 단일 TB 로그와 호환 클라이언트를 위해 유지한다.

Agent Orchestrator v5부터 실행 요청은 전체 실험 완료를 기다리지 않는다. `POST`는 저장된 `RECEIVED` 레코드와 `run_id`를 즉시 반환하고, 실제 실행은 Executor 잠금을 보유한 background worker가 이어서 수행한다. 대시보드는 `#/agent-runs/{run_id}?source=remote` 전용 화면에서 `/api/remote/agent-runs/{run_id}`를 1초 간격으로 조회한다. 일시적인 연결 오류에는 마지막 정상 스냅샷을 유지하고 자동 재연결하며, 완료·실패·복구까지 끝난 취소 상태에서만 자동 조회를 멈춘다.

- 등록된 Host·Container control 전체를 공격에 유리한 방향으로 합치고 최대 권한 `profile_hash`를 고정 (`no_new_privileges` 같은 방어 통제는 OFF)
- 읽기 전용 Recon으로 유효 UID/GID, capability, namespace, mount와 socket 상태를 확인
- 8개 TB 각각에서 Agent가 최신 구조화 증거와 state fingerprint를 보고 다음 최적 Tool 하나를 동적으로 선택
- 같은 TB의 Tool 사이에는 fixture 상태를 보존하고, 의미 기반 종료·오류·Watchdog 뒤 Supervisor가 시나리오 전체를 한 번만 Reset
- Watchdog 중단은 안전 판정이 아니라 `INCONCLUSIVE`이며, 복구 검증 후 저장한 checkpoint의 Tool prefix를 replay해 `/resume`에서 이어서 탐색
- L3/L4로 검증된 성공 결과를 피해 점수로 비교하고 최고 경로의 전체 Tool 순서·상태 fingerprint·Verifier·Rollback을 `attack_contract`로 고정
- 별도 최소화 LLM은 허용된 권한 ID만 제안하며 profile/policy를 작성하지 않음. 프로그램이 고정된 전체 Attack Chain을 Tool 사이 Reset 없이 재실행하고 trial 끝에 한 번 복구해 `permission_minimization`의 1-minimal 목록을 확정
- AgentRun과 이벤트는 Supabase의 `agent_runs`, `agent_run_events`에 저장하며 미설정 또는 장애 시 메모리 저장소로 복원
- 메모리 Fixture와 Dashboard 전용 Fixture API는 운영 화면과 Production API에서 제거

Harness Core와 Fixture Adapter는 내부 단위 테스트에서만 수명주기 회귀 검증에 사용한다. 현재 실제 Runtime은 129개 Tool 카탈로그 중 권한 프로파일과 직접 연결되는 5개 family를 OS 동작까지 구현하며, 나머지는 `implemented` 상태를 명시한다.

AgentRun 조회 API는 `/api/agent-runs/{run_id}`를 기준으로 events, recon, findings, plan 하위 경로를 제공한다. 실행 중에는 Planner 판단 요청, Runtime dispatch, Tool 결과, 누적 상태 전이, Rollback을 조회 가능한 스냅샷으로 계속 저장한다. `/resume`도 즉시 `RECEIVED`를 반환한 뒤 복구가 검증된 미완료 체인을 background에서 replay하며, `/rollback`은 8개 등록 Target의 기준 상태를 다시 검증한다.

AgentRun 요청은 사용자 Prompt와 수동 권한 선택을 받지 않는다. 공격 에이전트는 서버에 고정된 임무, 자동 최대 권한과 실제 Recon 증거를 바탕으로 finding, TB별 scenario와 구조화 Tool plan을 생성한다. 요청에 `prompt`를 넣으면 API가 `422`로 거부한다.

## 워크플로우 상태 관리

대시보드 상단의 `최소 운영 워크플로우`는 로컬 개발부터 테스트 종료까지 7단계를 노드와 화살표로 표시한다.

- 로컬 백엔드, 배포, Agent 테스트 노드는 실제 API 응답을 기준으로 자동 갱신
- SSM 노드는 실제 터널·원격 헬스 체크로 자동 갱신하고 테스트 종료만 사용자가 확인
- 모든 노드는 필요할 때 수동 상태로 보정하고 실제 백엔드·배포·SSM·실행 오류를 노드별로 확인 가능
- `자동 상태로 복원`은 선택한 노드의 수동 상태만 제거
- 수동 상태와 오류 메모는 브라우저 `localStorage`에만 저장되며 AWS나 Supabase로 전송하지 않음

## 고정 AWS 환경

팀 [OS 저장소](https://github.com/whs-agentic-ai-lab/OS.git)의 commit
`a0152804ddc64d67f220b17125f7987abf24cdec`을 기준으로 Terraform을 고정했다.
대시보드에서는 Region, 인스턴스 유형, 개수 또는 Terraform 경로를 변경할 수 없다.

- Region/AZ: `us-east-1` / `us-east-1a`
- Compute: `t3.small` 1대
- Network: private subnet, public inbound 없음
- Access: AWS Systems Manager(SSM) 전용
- Runtime: 한 EC2 안에 U1/U2/C1/C2/C3 논리 환경을 두고 방향성 환경 TB를 시험
- Network: C1/C2/C3 Target 서비스는 내부 `control` 망에 격리하고, 백엔드만 OpenRouter·Supabase 통신용 `egress` 망 사용

| 시작 Executor | 환경 TB |
| --- | --- |
| Host Executor (`U1`) | `TB-HH-U1U2`, `TB-HC-U1C1`, `TB-HC-U1C2`, `TB-HC-U1C3` |
| Container Executor (`C1`) | `TB-HC-C1U1`, `TB-HC-C1U2`, `TB-CC-C1C2`, `TB-CC-C1C3` |

두 Executor Run은 동시에 실행되지 않는다. 다른 Executor 실행 중 새 요청은 대기열에 넣지 않고 HTTP `409`로 거부한다. 이렇게 해야 한 Executor가 적용한 권한 Profile이나 Reset 과정이 다른 Executor Trial의 Evidence에 섞이지 않는다.

### Ubuntu Host 실행 경계

실제 권한 실험은 로컬 백엔드에서 실행되지 않으며, SSM 터널로 연결된 EC2 Runtime에서만 활성화된다. EC2의 root-owned `os-agent-host-supervisor`는 완전한 프로파일 묶음을 allowlist 검증한 뒤 권한을 적용하고 환경 Runtime Agent를 시작한다.

`OS팀_권한카탈로그 (2026.08.27)`의 307개 항목은 독립 권한 307개가 아니라 설정값·전제조건·관측값·중복 관점을 포함한 원천 카탈로그다. Runtime v5는 그중 핵심 축이며 현재 Tool로 검증 가능한 제어를 실제 실행 프로파일로 제공한다.

| Executor | 실제 제어 축 |
| --- | --- |
| Container C1 | mount RO/RW, UID 10003/0, 보조 GID, `CAP_DAC_OVERRIDE`·`CAP_SETUID`·`CAP_SETGID`·`CAP_SYS_PTRACE`, `no_new_privs`, Host PID/IPC namespace, AppArmor/seccomp/system paths unconfined, privileged, Docker socket mount |
| Host U1 | owner/group write, 제한 sudo, `no_new_privs`, `CAP_DAC_OVERRIDE`·`CAP_SETUID`·`CAP_SETGID`·`CAP_SYS_PTRACE`, docker 그룹 소속 |

`no_new_privs`는 기본 ON이고, privileged·Docker socket·unconfined·Host namespace 공유는 기본 OFF다. Supervisor는 요청 프로파일뿐 아니라 Agent가 관측한 real/effective/fs UID·GID, 보조 그룹, capability P/E/I/A/B set, namespace ID, seccomp·AppArmor 상태와 Docker socket 접근성을 `applied_profile_state`에 저장한다. privileged와 개별 완화 옵션을 동시에 선택해 결과 원인이 섞이면 경고도 남긴다.

`limited_sudo=ON`이어도 `no_new_privs=ON`이면 sudo의 setuid root 전환은 차단되는 것이 정상이다. sudo 허용 자체를 확인하는 Trial은 두 값을 각각 `ON`, `OFF`로 두고, NNP 차단 Trial은 둘 다 `ON`으로 둔다.

백엔드 컨테이너 자체에는 Docker socket이나 root 권한을 주지 않는다. 실험용 Docker socket/그룹 권한은 선택된 Runtime Agent에만 Trial 동안 적용하고 Reset에서 제거한다. 최종 PASS/FAIL은 환경 Runtime이 아닌 Control Backend의 독립 Verifier가 판정한다.

배포 버튼은 Terraform으로 ECR을 준비하고, 백엔드 Docker 이미지를 push한 다음 전체 인프라를 apply한다. NAT Gateway, EC2, VPC Endpoint와 CloudWatch Logs 등 **비용이 발생할 수 있는 AWS 리소스**를 만든다.

AWS 리소스 이름과 태그에는 로그인한 IAM/SSO 사용자 식별자와 사용자가 입력한 환경 이름이 포함된다. 대시보드는 AWS의 실제 EC2 목록을 다시 조회하므로 여러 팀원의 인스턴스 중 연결 대상을 선택할 수 있다. 환경 전체 삭제는 생성 PC에 보관된 환경별 Terraform state가 있을 때만 가능하며, EC2 단독 종료는 다른 리소스를 남길 수 있다.

## 로컬 실행

Python 3.10과 Node.js 22 이상을 기준으로 한다.

### Windows 팀원 최초 환경설정

Git만 설치된 Windows PC에서는 저장소를 clone한 뒤 최초 한 번만 다음 파일을 실행한다.

```cmd
setup.cmd
```

`setup.cmd`는 `winget`을 사용해 Python, Node.js, AWS CLI, Terraform, Docker Desktop을 설치하고 AWS Session Manager Plugin을 준비한다. Docker Desktop 약관, WSL/재부팅, Windows 관리자 권한처럼 자동화할 수 없는 단계는 화면 안내를 완료한 뒤 `Y`를 입력하면 이어서 진행한다. 이미 완료된 항목은 다시 실행해도 건너뛴다.

환경설정이 끝난 뒤부터는 다음 파일만 실행한다.

```cmd
run.cmd
```

`run.cmd`는 AWS 로그인 상태, Docker 실행 상태와 프로젝트 의존성을 확인하고 로컬 프론트엔드와 백엔드를 함께 시작한다. `backend/.env`가 없으면 실행을 중단하고 관리자에게 파일을 받아 넣으라고 안내한다. 실제 키 값은 Git에 커밋하지 않는다.

```powershell
cd C:\Users\vinny\Desktop\whs_team\os-Agent-test\backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

다른 터미널에서:

```powershell
cd C:\Users\vinny\Desktop\whs_team\os-Agent-test\frontend
npm run dev -- --host 127.0.0.1
```

대시보드는 `http://127.0.0.1:5173`에서 열고, Vite가 `/api`를 로컬 백엔드로 프록시한다.
배포된 프론트는 [OS Agent Dashboard](https://os-agent-dashboard.vercel.app/)에서 확인할 수 있으며, AWS 배포와 SSM 제어에는 사용자 PC의 로컬 FastAPI가 실행 중이어야 한다.

대시보드 배포 기능의 준비와 활성화 방법은 [실행방법.md](./실행방법.md)를 따른다. AWS 자격 증명과 OpenRouter 키는 프론트에 입력하거나 저장하지 않는다.

## 검증

```powershell
cd C:\Users\vinny\Desktop\whs_team\os-Agent-test\backend
python -m pytest -q

cd C:\Users\vinny\Desktop\whs_team\os-Agent-test\frontend
npm run lint
npm run build
```

검증 완료 기준은 백엔드 테스트 통과, 프론트 lint·production build 성공, `terraform validate` 성공이다. 실제 Host 권한의 최종 E2E 검증은 변경된 `user_data`로 EC2를 새로 배포한 뒤 수행한다.

OpenRouter key와 Supabase secret/service-role key는 프론트에 두지 않는다. OpenRouter key는 배포 컨트롤러가 환경별 SSM SecureString으로 저장하고 EC2 IAM이 해당 파라미터 하나만 복호화해 AI Planner runtime에 주입한다. 키 값은 이미지, Terraform 변수/state, user-data 원문과 배포 로그에 넣지 않는다. Supabase 저장은 로컬 백엔드가 담당하므로 EC2 Agent 런타임에는 Supabase Secret Key를 전달하지 않는다.
