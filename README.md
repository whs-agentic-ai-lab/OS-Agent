# OS Agent Minimum Test

고정된 AWS 인프라에서 Container와 Ubuntu Host 권한 경계를 비교하기 위한 최소 테스트 프로젝트다. 모든 구현과 테스트 파일은 이 디렉터리 안에만 둔다.

## 구조

```text
os-Agent-test/
├─ frontend/           # 로컬 React/Vite 대시보드
├─ backend/            # EC2 배포 대상 FastAPI·Executor·Tool Runner·Collector
├─ infra/
│  └─ terraform/       # 승인된 고정 OS Terraform 사본 위치
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
- 저장소: 현재 로컬 메모리, Supabase 스키마와 저장 구현은 분리
- OS 권한: 현재 안전한 로컬 fixture simulation, 실제 EC2 Profile Controller는 후속 범위
- 환경 배포: 로컬 대시보드 → 로컬 FastAPI → 고정 Terraform 순서로 AWS 환경과 백엔드 이미지를 자동 배포
- 워크플로우 제어: 7단계 방향성 그래프, 자동 상태 동기화, 수동 체크포인트, 오류 메모와 상태 복원

## 워크플로우 상태 관리

대시보드 상단의 `최소 운영 워크플로우`는 로컬 개발부터 테스트 종료까지 7단계를 노드와 화살표로 표시한다.

- 로컬 백엔드, 배포, Agent 테스트 노드는 실제 API 응답을 기준으로 자동 갱신
- SSM 연결과 테스트 종료 노드는 사용자가 확인 후 상태 변경
- 모든 노드는 필요할 때 수동 상태로 보정하고 오류 원인을 기록 가능
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

배포 버튼은 Terraform으로 ECR을 준비하고, 백엔드 Docker 이미지를 push한 다음 전체 인프라를 apply한다. NAT Gateway, EC2, VPC Endpoint와 CloudWatch Logs 등 **비용이 발생할 수 있는 AWS 리소스**를 만든다.

## 로컬 실행

Python 3.10과 Node.js 22 이상을 기준으로 한다.

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

대시보드 배포 기능의 준비와 활성화 방법은 [실행방법.md](./실행방법.md)를 따른다. AWS 자격 증명과 OpenRouter 키는 프론트에 입력하거나 저장하지 않는다.

## 검증

```powershell
cd C:\Users\vinny\Desktop\whs_team\os-Agent-test\backend
python -m pytest -q

cd C:\Users\vinny\Desktop\whs_team\os-Agent-test\frontend
npm run lint
npm run build
```

OpenRouter key와 Supabase service-role key는 프론트에 두지 않는다. 실제 값을 Git에 커밋하지 말고 백엔드 런타임 secret으로만 주입한다.
