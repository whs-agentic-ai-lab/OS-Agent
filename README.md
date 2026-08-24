# OS Agent Minimum Test

고정된 AWS 인프라에서 Container와 Ubuntu Host 권한 경계를 비교하기 위한 최소 테스트 프로젝트다. 모든 구현과 테스트 파일은 이 디렉터리 안에만 둔다.

## 구조

```text
os-Agent-test/
├─ frontend/           # 로컬/Vercel React·Vite 대시보드
├─ backend/            # FastAPI·Tool Runner·Host client와 Supervisor 배포 소스
├─ infra/
│  └─ terraform/       # 고정 인프라와 root-owned Supervisor 설치
├─ data/
│  ├─ schema.sql       # Supabase bootstrap SQL
│  └─ migrations/      # CLI로 생성할 정식 migration 위치
├─ DESIGN.md
└─ OS-최소환경테스트-계획.md
```

## 현재 동작 범위

- 실행 경계: `Container`, `Ubuntu Host`
- 경계별 권한 시험: 3개, 한 번에 하나만 OFF/ON
- Tool: `file_read`, `file_write`, `service_status`
- 모델: `OPENROUTER_API_KEY`가 없으면 로컬 규칙 플래너, 있으면 OpenRouter Tool Call
- 로그: Profile → Model → Tool Runner → Executor → Verifier 이벤트
- 저장소: Supabase 설정 시 `runs`·`run_events` 영구 저장, 미설정 시 로컬 메모리 fallback
- 로그 조회: 메인 네비게이션의 `로그 조회`에서 Supabase 전체 실행을 최신순·20건 단위로 탐색하고 실행별 공통 결과와 모든 이벤트 확인
- 로그 삭제: 목록에서 Run ID를 다시 입력해 단일 실행을 삭제하며 연결된 `run_events`도 함께 삭제
- OS 권한: Container는 로컬 fixture, Ubuntu Host는 EC2의 실제 사용자·그룹·파일 모드·제한된 sudo로 검증
- 환경 배포: 로컬 대시보드 → 로컬 FastAPI → 고정 Terraform 순서로 AWS 환경과 백엔드 이미지를 자동 배포
- 환경 삭제: 동일한 로컬 Terraform state로 AWS 리소스와 ECR 저장소를 자동 삭제
- SSM 연결: 관리 노드가 Online이 될 때까지 대기한 뒤 `127.0.0.1:8001 → EC2:8000` 자동 연결
- 워크플로우 제어: 7단계 방향성 그래프, 자동 상태 동기화, 수동 체크포인트, 노드별 실제 오류 로그와 상태 복원

## Agent Harness Core

기존 단일 권한 Run과 실행 경계를 변경하지 않고, 향후 OS 권한·Tool·Verifier를 연결할 `os-harness-v1` Core를 별도 API로 제공한다.

- `GET /api/harness/status`: Permission Provider, Tool Catalog, Planner, Executor, Verifier, Resetter 연결 상태 조회
- `POST /api/harness/runs`: Harness Run 생성과 상태·Budget·종료 수명주기 실행
- `GET /api/harness/runs/{run_id}`: In-memory Harness 실행 기록 조회
- `GET /api/harness/fixtures/status`: 메모리 전용 Fixture 자가진단 준비 상태 조회
- `POST /api/harness/fixture-runs`: Dashboard에서 안전한 Fixture 수명주기 실행
- 현재 실제 OS Adapter는 연결 전이므로 Harness Run은 Tool을 실행하지 않고 `BLOCKED / MISSING_REQUIRED_COMPONENTS`로 종료
- `create_fixture_harness_components()`를 테스트에서 주입하면 State → Frontier → Planner → Execute → Verify → Reset 전체 흐름 실행
- Dashboard의 `Agent Harness` Panel에서 실제 Adapter 상태와 Fixture 실행 결과를 분리해 표시
- 기존 `POST /api/runs`, Runtime Agent, root Supervisor, Terraform, SSM, Supabase 실행 경로는 그대로 유지

OS 권한 모델, 최종 Tool과 Independent Verifier가 확정되면 각각의 Harness Port에 Adapter로 연결한다. Harness Core가 Domain 구현을 직접 import하거나 임시 권한 규칙을 만들지 않는다.

### 메모리 전용 Fixture Adapter

실제 OS 권한으로 오해하지 않도록 모든 이름에 `fixture-`를 사용하며 파일·명령·Network를 사용하지 않는다.

- 권한 Profile: `fixture-container-readonly`, `fixture-container-write`, `fixture-host-readonly`, `fixture-host-write`
- Tool: `fixture_file_read`, `fixture_file_write`, `fixture_service_status`
- Planner: 미실행 Candidate를 등록 순서대로 선택
- Verifier: Profile의 기대 허용·거부와 메모리 상태 변화를 독립 Evidence ID로 판정
- Resetter: 성공한 fixture write를 메모리 baseline으로 복구
- 실제 Harness 실행에는 주입하지 않는다. 별도 `/api/harness/fixture-runs` 자가진단에서만 사용하며 외부 시스템에 Side effect를 만들지 않는다.

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
- Runtime: 한 EC2 안에서 Container와 Ubuntu Host 경계를 시험
- Network: 테스트 대상은 내부 `control` 망에 격리하고, 백엔드만 OpenRouter·Supabase 통신용 `egress` 망 사용

### Ubuntu Host 실행 경계

Host 실험은 로컬 백엔드에서 실행되지 않으며, SSM 터널로 연결된 EC2 백엔드에서만 활성화된다. EC2의 root-owned `os-agent-host-supervisor`가 고정된 여섯 Profile ID만 받아 다음 상태를 실제 OS에 적용하고 재확인한다.

- `owner_write`: `agent-host` 소유 Canary의 owner write bit OFF/ON
- `group_write`: `agent-host`의 전용 `agent-trial` 그룹 미가입/가입
- `limited_sudo`: 고정 `--sudo-helper` 한 개에 대한 sudoers drop-in 없음/있음

백엔드 컨테이너는 Docker socket이나 root 권한을 받지 않는다. UID 10003 백엔드와 UID 10004 실험 사용자를 분리하고, 전용 GID 10006 Unix socket만 Supervisor에 연결한다. Tool 이름, Resource ID, Profile ID와 입력 길이는 Supervisor에서 다시 allowlist 검증한다.

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

OpenRouter key와 Supabase secret/service-role key는 프론트에 두지 않는다. 실제 값을 Git에 커밋하지 말고 신뢰된 로컬 백엔드 런타임 secret으로만 주입한다. SSM 원격 실행 결과도 로컬 백엔드가 받아 Supabase에 저장하므로 EC2 Agent 런타임에는 Supabase Secret Key를 전달하지 않는다.
