# OS 로깅 선택 이식 작업보고서

## 현재 대상: Desktop/OS-Agent (2026-08-30)

**현재 배포 준비 완료 상태가 아니다.** 기존 로깅 코드를 선택 이식했지만, 최종 검증에서 이번 이식으로 EC2 user-data의 기존 15 KiB 상한을 초과한 것을 확인했다. 상한을 늘리거나 새 배포 경로를 추가하지 않았으며, 추가 패키징 조정은 사용자 승인 전 중단한다.

- 대상의 최신 AgentOrchestrator, 모델 설정, 실행·Verifier 기준, Supervisor 캡처·기록과 프론트엔드는 유지한다.
- 원본의 로깅 모듈·스키마·설정·테스트만 선택 이식한다. 아래 원본 작업 기록은 대상 검증 결과가 아니다.

### 이식 범위와 보류 항목

- Evidence API·인증·마스킹·멱등 저장·SQL migration과 공통 Vector 스키마를 이식한다.
- 실행 결과는 기존 Supervisor NDJSON을 사용하고, 기존 백엔드 verify_tool 반환값만 별도 기록한다.
- 원본의 TOOL_RESULT/실행 오류 stdout 중복 훅과 action ID 생성 위치 변경은 가져오지 않는다.
- ToolDefinition Verifier의 상세 결과 전달은 Runtime/Supervisor 추가 수정 승인을 요청했으며, 승인 전까지 이식 범위 밖이다.
- 기존 업로더/API는 포함하지만 `capture_state.sh`의 동기 업로드 훅은 이식하지 않는다. 최신 before/after 자동 캡처의 30초 제한·호출 순서를 보존한다.
- 다른 종료 훅·백그라운드 작업·새 수동 업로드 운영 절차는 추가하지 않는다. 자동 Artifact 연결은 미완료로 남긴다.
- 원본의 사용자 변경 `schemas.py`, `runtime_agent/runtime.py`는 복사하지 않는다. 실제 `.env`, `.git`, Terraform state, 가상환경도 복사하지 않는다.

### 7단계별 대상 상태

| 단계 | 이번 이식 결과 | 검증·남은 부분 |
|---|---|---|
| 1 실행 컨텍스트·Verifier | 기존 Supervisor 실행 결과와 RunCoordinator/Harness의 Verifier 반환값 연결 | 기록 때문에 실행·검증을 추가 호출하지 않는 테스트 통과. 최신 AgentRun의 native Verifier 상세 연결은 승인 전 보류. |
| 2 정규화·오류·마스킹 | 원본 공통 스키마·마스킹·parse/collection 오류 분류 이식 | API/원문/Artifact 마스킹 테스트 통과. Vector fixture 17개는 원본 그대로지만 현재 대상에서는 실행 파일이 없어 미실행. |
| 3 Evidence API | 기존 FastAPI에 collector 전용 router와 설정 연결 | 인증·NDJSON/gzip·크기·스키마·저장 실패·중복 방지 계약 테스트 통과. |
| 4 Supabase 저장 | Evidence 테이블·제약·인덱스·private bucket migration 이식 | SDK MockTransport/저장 double 검증. 실제 DB/RLS/Storage 적용은 하지 않음. |
| 5 Artifact | 기존 업로더/API/설정만 이식 | 완성본·허용 경로·해시·실패 계약 테스트 통과. 자동 캡처→업로드 훅은 이식하지 않음. |
| 6 원격 Vector sink | 기존 선택형 sink·디스크 버퍼·로컬 출력 유지, API 전송 계약 이식 | Terraform 문법·구성 검증은 통과했지만 user-data 용량 검증 실패. 실제 Vector 전송은 미실행, 원격 기본값 false 유지. |
| 7 원격 E2E | 수행하지 않음 | EC2·서비스·실제 DB에 접속하거나 배포하지 않음. 로컬 테스트를 원격 완료로 보지 않음. |

### 수정 파일과 이유

아래 25개 파일만 대상에서 변경됐다. 원본의 새 파일을 대상에 옮긴 것이며 새 기능·의존성은 추가하지 않았다.

| 파일 | 이유 |
|---|---|
| `backend/app/evidence.py`, `backend/app/evidence_security.py` | 기존 수신·인증·멱등 저장·마스킹 코드 이식. |
| `backend/app/evidence_emitter.py` | 기존 결과의 마스킹 사본 기록 코드 이식. |
| `backend/app/config.py`, `backend/.env.example`, `backend/app/main.py` | collector token 설정과 router만 추가. 모델 기본값 `openai/gpt-5-mini`, 최신 AgentRun API/종료 처리 유지. |
| `backend/app/executor.py`, `backend/app/harness/os_adapters.py` | 이미 실행된 기존 `verify_tool` 반환값만 기록. 중복 TOOL_RESULT·오류 훅은 제외. |
| `backend/host_runtime/evidence_upload.py` | 기존 완성된 캡처 파일만 전송하는 업로더 이식. 자동 호출은 미연결. |
| `backend/tests/test_evidence.py`, `backend/tests/test_evidence_upload.py`, `backend/tests/test_evidence_vector.py`, `backend/tests/test_execution_evidence.py` | 기존 관련 테스트 이식. 실행 테스트만 현재 Supervisor 중복 방지와 mocked runtime fixture에 맞춤. |
| `data/migrations/20260830090000_add_evidence_storage.sql`, `data/schema.sql` | Evidence 저장 구조만 추가. 최신 `agent_runs`, PAUSED 및 기존 데이터 구조 유지. |
| `data/migrations/README.md` | 이식한 migration의 미적용 상태와 저장 계약 설명. |
| `infra/terraform/config/vector/normalize.vrl.tpl`, `infra/terraform/config/vector/normalize.tests.yaml` | 원본 공통 Evidence 정규화와 17개 fixture 이식. |
| `infra/terraform/config/vector/vector.yaml.tpl` | 안전한 오류 출력, NDJSON Content-Type, 1 MiB batch 상한. 최신 `vector.service` 수집 및 `rotate_wait_secs` 제거는 유지. |
| `infra/terraform/ec2.tf`, `infra/terraform/user_data.sh.tpl` | 원본 단일 gzip 자산 패키징과 업로더 배치·설정 이식. 최신 OpenRouter SSM·Recon·runtime_agent 전체 디렉터리 설치 유지. |
| `infra/terraform/EVIDENCE_SCHEMA.md`, `infra/terraform/README.md` | 스키마·설정·검증 및 자동 업로드 미연결 경계 설명. |
| `대시보드_추가사항.md` | 필요한 필드·저장 위치·현재 제공/미연결 상태만 설명. 화면 코드는 미변경. |
| `OS_로깅_정규화_1단계_작업보고서.md` | 현재 이식 결과와 아래 원본 이력을 분리. |

### 대상 검증 결과

- 대상의 기존 `.venv` 사용. 패키지 설치·업데이트 없음.
- Evidence 관련 4개 테스트 파일: **123 passed, 4 skipped** (9.13초).
  skip은 Windows 심볼릭 링크 생성 권한 2개, `VECTOR_BIN` 미설정으로 실제 Vector 테스트 2개다.
- API·실행 기록과 기존 회귀 8개 파일을 함께 실행: **161 passed, 16 failed** (19.48초).
  같은 기존 회귀 8개를 병합 전 HEAD 코드로 비교: **70 passed, 동일한 16 failed** (17.71초).
  두 실행에 공통인 기존 실패를 이식으로 해결됐다고 숨기거나 테스트에서 제외하지 않았다.
- 기존 실패의 직접 원인: 최신 `runtime_agent/validated_actions.py`의 기대 툴 SHA와 실제 HEAD 툴 파일 SHA가 달라 허용 툴 목록이 빈 집합이 된다.
  기대 값은 `42c76ab0…14246`, HEAD 원본(LF) 값도 `70b4e9e6…f170f`로 다르다.
  단순 Windows 줄바꿈 차이만의 문제는 아니다. 검증 해시·툴 등록·기존 테스트는 변경하지 않았다.
- `terraform fmt -check -diff`, `terraform validate -no-color`: **통과**.
  설치된 Terraform 1.9.5와 기존 AWS provider 6.61.0 사용. init/download/plan/apply 없음.
- 실제 `templatefile`의 remote off/on 렌더, 각 19개 자산 내용 일치, JSON/YAML 파싱: **통과**.
  가상 ECR 계정·`example.invalid` 주소·서로 다른 SHA 4개·SSM parameter 이름만 사용했다. 실제 비밀값 없음.
- 렌더된 두 부팅 스크립트의 `bash -n`: **통과**. 최초 sandbox 실행은 권한 오류였으며, 권한 승인 후 문법 검사만 수행했다. 부팅 명령은 실행하지 않았다.
- **EC2 user-data 용량 검증: 실패.** 같은 fixture의 HEAD 원본과 비교해 이번 이식으로 발생한 회귀임을 확인했다.

| 원격 설정 | 병합 전 HEAD gzip | 병합 후 gzip | 병합 후 base64 길이 | 기존 15,360 B 상한 대비 |
|---|---:|---:|---:|---:|
| OFF | 14,829 B | 16,038 B | 21,384자 | 678 B 초과 |
| ON | 14,995 B | 16,273 B | 21,700자 | 913 B 초과 |

  `ec2.tf`의 기존 precondition(base64 20,480자)을 그대로 유지했다. 이 검증 입력으로는 EC2 생성 조건을 통과하지 못한다. 문법 검증 통과를 배포 가능으로 해석하면 안 된다.

- `git diff --check`: **통과**. 원본 코드·fixture 등 10개 파일은 줄바꿈을 제외하고 동일함을 확인했다.
- 모델·프롬프트·Runtime tools·Verifier·AgentOrchestrator·Supervisor·캡처 스크립트·프론트엔드는 HEAD 대비 변경 없음.
- 실제 Vector 검증, Linux 생산 경로, Supabase DB/RLS/Storage, EC2 원격 E2E는 **미검증**.

### 적용에 필요한 설정과 보류 사항

- 수신 서버: 기존 `SUPABASE_URL`, `SUPABASE_SECRET_KEY`(또는 기존 service-role fallback), `EVIDENCE_COLLECTOR_TOKEN`.
- 원격 Vector: 기존 `enable_remote_evidence_sink`, `evidence_api_url`, `collector_token_parameter_name` 사용. 비밀값은 저장소나 Terraform 변수에 복사하지 않음.
- 실제 DB 변경은 승인 후 Evidence migration 한 개만 적용한다. 기존 전체 schema를 재실행하지 않는다.
- 정확한 설정·한도·검증 안내는 [Terraform README](infra/terraform/README.md#evidence-원격-연결), DB 적용 설명은 [migrations README](data/migrations/README.md#evidence-저장-마이그레이션)에 있다.
- 최신 AgentRun의 native Verifier 결과 전달과 Artifact 자동 호출은 추가 수정 승인을 받기 전 구현하지 않는다.
- 위 부팅 데이터 크기 회귀 때문에 인프라 이식은 적용 가능한 완료 상태가 아니다. 기존 기능을 유지한 패키징 조정도 사용자 확인 후 진행한다. 상한 확대·기능 제거·새 의존성·새 전송 경로를 임의로 적용하지 않았다.
- 현재 툴 검증 SHA 불일치도 별도 기존 문제다. 승인 없이 기대 해시를 바꿔 검증을 우회하지 않는다.
- Source 폴더, 실제 `.env`, 최신 사용자 코드와 기존 실행 결과를 덮어쓰지 않았다.
- **Git pull·commit·push, terraform apply, 배포·서비스 재시작·실제 DB 변경은 하지 않았다.**

---

## OS-Tool 원본 작업 기록: 7단계 확장 (2026-08-30)

이 절은 원본 OS-Tool 폴더의 당시 구현·검증 이력이다. 대상 Desktop/OS-Agent의 완료 근거로 사용하지 않는다.
아래의 **이전 1단계 기록** 역시 해당 시점의 수행 범위다.

기준 저장소: `C:\Users\oeseo\Desktop\OS-Tool\OS-Agent`  
기준 HEAD: `d05da05868285bee50e8d893417ebdb03e07b537` / `not-verified-tool`

이번 확장 시작 때 git status/HEAD와 실제 Terraform·Vector·FastAPI·실행·Verifier·DB 코드를
다시 확인했다. 기존 공통 정규화와 선택형 HTTP sink는 재사용했다. 사용자 변경으로 표시된
`backend/app/schemas.py`, `backend/runtime_agent/runtime.py`는 이번 확장에서 수정하지 않았다.

### 7단계별 상태

| 단계 | 로컬 구현 | 검증·남은 경계 |
|---|---|---|
| 1 실행 컨텍스트·Verifier | 실제 run_id/action_id, TOOL_RESULT/VERIFIER_RESULT 분리. 기존 반환값만 stdout으로 기록. | 기존 호출 횟수·판정 불변 테스트 통과. OS correlation/step/tool-call ID 추측 없음. |
| 2 누락·파싱·마스킹 | 기존 runtime Docker stdout 경로 연결. 명시적 parse/collection 오류, 원문 포함 최소 마스킹. | 6종 source 및 추가 오류/마스킹 fixture 검증. 실제 Linux 생산 경로는 별도 확인 필요. |
| 3 수신 API·인증 | NDJSON/gzip, collector Bearer 인증, 크기·스키마 검사, 실패 503, 멱등 저장. | FastAPI 테스트 및 실제 Vector loopback HTTP 검증. 외부 HTTPS endpoint는 미검증. |
| 4 Supabase | evidence_events/evidence_artifacts, private bucket, 최소 index·제약·접근 제한 SQL. | SDK 직렬화/실패 계약 테스트. 실제 DB migration·RLS·Storage 적용은 미수행. |
| 5 Artifact | 기존 완성본만 검증·마스킹·업로드, private 참조/해시/크기, 부분 실패 구분. | 기존 host/container/after-diff fixture와 실제 API 계약 테스트. 원격 Storage는 미검증. |
| 6 Vector 원격 sink | 기존 선택형 sink에 Content-Type/1 MiB batch 상한·실패 경로 연결. 로컬 sink 유지. | 실제 503→Vector 재전송→200, 별도 재전송 중복 없음 확인. 배포는 미수행. |
| 7 실제 원격 E2E | 로컬에서 가능한 연결·실패 테스트 구현. | **실제 EC2→API→Supabase E2E는 아직 미수행. 로컬 통과를 원격 완료로 보지 않는다.** |

### 변경 파일과 이유

| 파일 | 이유 |
|---|---|
| `backend/app/evidence_emitter.py` | 기존 runtime/Verifier 반환값의 비파괴 마스킹 복사본 출력, 동시 행 출력 보호, 크기 초과 명시. |
| `backend/app/executor.py`, `backend/app/harness/os_adapters.py` | 기존 호출 반환 직후 로깅만 연결. |
| `backend/app/evidence.py` | 수신 API, 인증·입력 검증, strict Supabase 이벤트/Artifact 저장. |
| `backend/app/evidence_security.py` | 출력·원문·오류·Artifact 사본의 작은 공통 마스킹 규칙과 기존 파일 allowlist. |
| `backend/app/config.py`, `backend/.env.example`, `backend/app/main.py` | 기존 설정 방식의 collector token 및 기존 FastAPI router 연결. |
| `backend/host_runtime/evidence_upload.py` | 고정 root의 기존 완성본만 보내는 1회 업로더. |
| `infra/terraform/scripts/capture_state.sh` | 기존 COMPLETE/REPUBLISHED 뒤 업로더 호출만 추가. |
| `infra/terraform/config/vector/normalize.vrl.tpl` | context/status, 구조화 runtime stdout 인식, 오류·마스킹·시간 파싱 보완. |
| `infra/terraform/config/vector/vector.yaml.tpl` | 기존 HTTP 계약 맞춤, 안전한 normalization_error 출력. |
| `infra/terraform/ec2.tf`, `infra/terraform/user_data.sh.tpl` | 비밀값 없는 업로드 설정, 이미지 helper 추출, user-data 크기 제한을 유지하는 단일 gzip 패키징. |
| `infra/terraform/variables.tf` | 기존 원격 전송 on/off 설정이 기존 Artifact 업로드에도 적용됨을 설명. |
| `data/migrations/20260830090000_add_evidence_storage.sql`, `data/schema.sql` | 새 Evidence 저장 영역만 추가. 기존 실행 데이터 삭제/초기화 없음. |
| `backend/tests/test_evidence.py`, `test_evidence_upload.py`, `test_execution_evidence.py`, `test_evidence_vector.py`, `infra/terraform/config/vector/normalize.tests.yaml` | 변경 기능과 기존 실행 불변성에 직접 관련된 검증. |
| `infra/terraform/EVIDENCE_SCHEMA.md`, `infra/terraform/README.md`, `data/migrations/README.md` | 실제 스키마·설정·적용/원격 검증 절차 보완. |
| `대시보드_추가사항.md` | 기존 실행 상세 연결에 필요한 필드/저장 위치/미구현 조회 API만 정리. 프론트엔드 코드는 미변경. |

`OS-Agent_0826_Terraform_변경사항.md`에는 앞선 1단계 변경이 이미 있었다. 이번 확장은 이
파일의 과거 내용을 새로운 원격 완료 근거로 사용하지 않았다. 새 패키지 의존성은 추가하지
않았고 기존 requirements.txt를 저장소 내부 `.venv`에 설치해 테스트했다.

### 검증 결과

- 관련 Backend 신규+기존 회귀 테스트: **187 passed, 2 skipped**.
  skip은 Windows에서 실제 symlink 생성 권한이 없는 두 경로 테스트다. Linux 재실행 필요.
- 실제 portable Vector 0.57.0의 로컬 HTTP 연결 테스트: **2 passed**.
  실제 Vector, FastAPI, gzip, NDJSON, 토큰, batch/retry, local file/disk buffer 설정을 사용했다.
  저장소는 메모리 uniqueness double이다. 초기 503 후 같은 배치 재전송, 성공 후 별도
  동일 event_id 전송에서도 4개 고유 저장/6개 로컬 출력을 확인했다.
  제어문자 escaping이 많은 기존 source 한도 이내 26줄도 실제 API에 모두 저장되었고,
  각 배치가 해제 후 8 MiB 이하·응답 200임을 확인했다. 4 MiB 설정의 별도 재현에서는
  24,526,097 bytes 본문이 413으로 폐기되었으며 1 MiB 설정으로 이 누락을 방지했다.
- Vector 정규화 source/오류/마스킹 fixture: **17개 통과**.
- Terraform provider는 기존 lock의 AWS 6.61.0을 `-backend=false -lockfile=readonly`로
  검증용 준비했다. AWS 인프라 조회·plan·apply 용도로 사용하지 않았다.
  `terraform fmt -check -recursive`, `terraform validate`는 최종 설정으로 통과했다.
- 원격 off/on 렌더의 19개 자산 내용과 YAML/JSON 의미 일치를 확인했다. 서로 다른 4개
  SHA-256과 예시 URL을 사용한 provider-free 렌더에서 gzip 크기는 off **14,868 bytes**,
  on **15,142 bytes**(base64 19,824/20,192자)였다. 기존 내부 상한 15,360 bytes를
  유지했다. 실제 배포 변수 값의 크기는 기존 Terraform precondition으로 재확인해야 한다.
- CASE 부트스트랩 off/on의 `bash -n`은 통과했다. 이후 마지막 1 MiB 변경은 quoted
  heredoc 안의 배치 숫자 한 곳만 다름을 비교 확인했다. 그 변경 이후 추가 `bash -n`
  실행 완료 결과는 없으며, 실제 Linux bootstrap 실행 검증은 하지 않았다.
- 실제 Supabase SDK의 wire 직렬화는 MockTransport로 확인했다. 실제 SQL 실행·RLS·Storage
  보안 검증, Linux journald/auditd/Docker end-to-end, 프로세스 재시작 후 디스크 재생은 미검증이다.

Vector는 전역 설치·서비스 등록·PATH 변경 없이 임시 portable 실행 파일로만 검증했다.
검증 뒤 `.tmp-evidence-validation`의 portable binary와 생성 테스트 출력만 삭제했다.
테스트 소스·보고서와 저장소 내부의 검증용 `.venv`·Terraform provider cache는 유지했다.
Windows 실행에서는 Linux journald를 포함한 전체 production 설정 검증을 대신할 수 없다.

### 적용에 필요한 것

정확한 명령과 고정 batch/buffer 조건은
[기존 Terraform README](infra/terraform/README.md#evidence-원격-연결)에 한곳으로 정리했다.

- 신뢰된 수신 서버: 기존 `SUPABASE_URL`, `SUPABASE_SECRET_KEY` 또는 service-role fallback,
  별도 `EVIDENCE_COLLECTOR_TOKEN`.
- EC2: 기존 `enable_remote_evidence_sink`, HTTPS `evidence_api_url`, collector token의 SSM
  parameter 경로. 관리 키는 Vector/수집기/실험 Runtime에 배포하지 않는다.
- 대상 Supabase 프로젝트 확인·승인 후 신규 migration 하나만 적용. 이 작업에서는 미적용.
- 새 runtime 이미지 digest와 승인된 환경 적용이 필요하다. 현재 로컬 수정은 원격 실행 중
  이미지/서비스를 자동으로 바꾸지 않는다.
- AWS 기본 프로필 `whs-team`은 확인 시 세션 만료였다. CLI 재로그인은 브라우저 승인 대기
  만료로 끝났다. 인증된 대상 인스턴스 조회나 원격 E2E는 수행하지 않았다.

### 실험 조건 영향·남은 제약

- 모델·프롬프트·툴 동작·기존 Verifier 판정/호출 횟수·실행 순서는 변경하지 않았다.
  로깅 실패 때문에 툴을 다시 실행하지 않는다.
- 수집 자체 범위·시각·원본 snapshot 파일/해시는 유지한다. 원격 업로드를 켜면
  capture 명령의 **반환 대기 시간**에는 동기 업로드 시간이 추가된다.
- 기존 Before/After 자동 lifecycle 연결은 없다. 임의의 새 snapshot 호출을 추가하지 않았다.
- 일반 OS 증거는 실행 ID를 정확히 알 수 없어 null이다. Harness 저장소는 기존대로 메모리이므로
  모든 Evidence run_id가 DB 실행 행을 가진다고 보장하지 않는다.
- 마스킹 때문에 일부 audit argv/proctitle과 비밀값은 생략되며 원본 SHA와 저장본 SHA는 다르다.
  64 KiB 초과 executor 로그는 명시적 collection_error와 함께 복사본 일부가 생략된다.
- Vector batch 상한은 JSON escaping 여유를 두어 인코딩 전 1 MiB로 고정했다. 기존 파일
  source 한도 안에서도 4 MiB 배치는 직렬화 후 8 MiB를 넘고 413으로 폐기됨을 재현했다.
  기존 max_events=250, timeout/backoff/disk buffer는 유지했다. 이 조건을 실험마다
  동일하게 사용해야 한다. API 한도를 넘는 단일 이벤트까지 자동 분할하지는 않는다.
- 파일당 32 MiB를 넘는 Artifact는 실패 상태로 남는다. 자동 압축·분할·재전송/정리 시스템은 없다.
- Storage 성공 후 metadata 실패 시 객체가 먼저 남을 수 있다. 같은 파일의 수동 재전송으로
  다시 저장할 수 있으나 고아 객체 자동 정리는 하지 않는다.
- 수집 전용 API만 구현했다. 대시보드 조회·다운로드 경로는 별도 단계다.

원격 배포·서비스 중단/재시작·DB 변경은 대상과 영향을 설명하고 별도 확인받아야 한다.
`git pull`, `git commit`, `git push`, `terraform apply`는 실행하지 않았다.

---

## 이전 1단계 기록 (당시 범위, 현재 상태 아님)

## 1. 작업 개요

| 항목 | 내용 |
|---|---|
| 작업일 | 2026-08-30 |
| 기준 저장소 | `C:\Users\oeseo\Desktop\OS-Tool\OS-Agent` |
| 기준 브랜치 | `not-verified-tool` |
| 기준 HEAD | `d05da05868285bee50e8d893417ebdb03e07b537` |
| 목표 | 현재 Vector 입력을 공통 JSON Evidence 형식으로 정규화 |
| 공통 스키마 | `os-agent-evidence-v1` |
| 배포 방식 | Terraform template → EC2 user-data → `/etc/vector/*` |
| Git 작업 | `commit`, `push`, `pull` 모두 미실행 |

이번 작업은 Evidence API, Supabase, Artifact 업로드, 새 원격 sink, 실행 컨텍스트와
Verifier 연동을 포함하지 않는다. 프론트엔드와 기존 대시보드 코드도 수정하지 않았다.

## 2. 작업 전 상태와 완료 여부 판단

작업 전 Vector에는 여섯 source와 하나의 공통 `normalize` transform이 이미 선언되어 있었다.
그러나 기존 `normalize.vrl.tpl`은 다음 메타데이터만 원본 event 최상위에 추가했다.

- `collector_channel`
- `environment_id`
- `topology_revision`
- `collector_received_at`
- `event_id`
- `occurred_at`

따라서 source마다 서로 다른 필드가 최상위에 섞였고, 공통 schema version,
`source_type`, `event_type`, 고정 `payload` 구조가 없었다. 이 상태는 “일부 공통 필드
추가”이지 “공통 Evidence JSON 스키마 정규화 완료”로 볼 수 없어 미완료로 판단했다.

기존 구현에는 다음 결함도 있었다.

1. file source의 JSON `.message`를 root에 merge한 뒤 `.message`를 삭제했다.
2. Docker log JSON 안의 실제 stdout/stderr `message`도 함께 사라질 수 있었다.
3. source-specific 필드가 공통 필드를 덮을 수 있었다.
4. Docker Event의 `time`보다 Vector file ingest `.timestamp`가 먼저 선택될 수 있었다.
5. `occurred_at`이 source에 따라 timestamp, string, integer가 될 수 있었다.

## 3. 실제 Vector 연결 구조

수정 원본과 생성 결과의 관계는 다음과 같다.

```text
infra/terraform/config/vector/vector.yaml.tpl
infra/terraform/config/vector/normalize.vrl.tpl
                    │
                    ▼ templatefile
            infra/terraform/ec2.tf
                    │
                    ▼ asset bundle + base64gzip
       infra/terraform/user_data.sh.tpl
                    │
                    ▼ EC2 bootstrap
          /etc/vector/vector.yaml
          /etc/vector/normalize.vrl
                    │
                    ▼
               Vector 0.57.0
                    │
                    ▼
/var/lib/os-agent/evidence/collected/events.ndjson
```

`/etc/vector/*`는 생성 결과물이므로 직접 수정하지 않고 Terraform 원본 template만 수정했다.

### Source별 실제 상태

| 대상 | Vector 연결 | producer 상태 | 실제 의미 |
|---|---|---|---|
| auditd | 연결됨 | 자동 생산 | `/var/log/audit/audit.log*`를 직접 읽음 |
| journald | 연결됨 | 자동 생산 | 지정된 systemd unit의 journal을 읽음 |
| Supervisor | journald 경유 | 일부 생산 | Supervisor 접근 로그는 수집되지만 executor 결과 본문은 별도 기록되지 않음 |
| Docker Events | 연결됨 | 자동 생산 | relay가 `docker-events.ndjson` 생성 |
| Docker stdout/stderr | 연결됨 | 자동 생산 | relay가 `docker-logs.ndjson` 생성 |
| Executor NDJSON | 연결 선언됨 | 미생산 | `/var/log/os-agent/executor/*.ndjson` writer가 없음 |
| Before/After snapshot | 연결 선언됨 | 조건부 생산 | script는 있으나 Supervisor lifecycle 호출이 없음 |

Executor source는 Vector 설정에는 존재하지만 현재 실행 결과가 이 경로로 들어오지 않는다.
Supervisor가 U1/C1 실행 결과를 `capture_output`으로 가져가며 NDJSON 파일로 쓰지 않는다.
또한 임시 `docker run --rm` executor는 고정 컨테이너 이름만 추적하는 Docker relay 대상에도
포함되지 않는다.

## 4. 공통 Evidence JSON 스키마

정규화 후 모든 event는 다음 열두 필드를 동일하게 가진다.

| 필드 | 타입 | 생성 규칙 |
|---|---|---|
| `schema_version` | string | `os-agent-evidence-v1` 고정 |
| `event_id` | string | producer ID 우선, 없으면 수집 정보로 SHA-256 생성 |
| `source_type` | string | 정규화된 source 종류 |
| `source` | string | 실제 producer 또는 source fallback |
| `event_type` | string | 실제 event 종류 또는 source별 기본값 |
| `occurred_at` | timestamp | producer 발생시각 우선 |
| `collector_received_at` | timestamp | Vector normalize 수신시각 |
| `environment_id` | string | Terraform 환경 ID |
| `topology_revision` | string | Terraform topology revision |
| `message` | string | 사람이 확인할 핵심 메시지 |
| `collector` | object | Vector가 붙인 수집 메타데이터 |
| `payload` | object | 원본 source-specific 데이터 |

`collector`는 다음 key를 항상 가진다. 값이 없는 source에서는 `null`이다.

```json
{
  "channel": "docker_json",
  "vector_source_type": "file",
  "host": "host-a",
  "file": "/var/log/os-agent/docker-logs.ndjson",
  "file_offset": 84,
  "journal_cursor": null,
  "vector_timestamp": "2026-08-30T01:00:04Z"
}
```

## 5. 정규화 처리 순서

정규화 transform은 event 한 건마다 다음 순서로 처리한다.

```text
1. 원본 event 보관
        ↓
2. Vector 수집 메타데이터를 collector에 먼저 복사
        ↓
3. collector channel을 공통 source_type으로 변환
        ↓
4. 구조화 file source만 JSON object로 파싱
        ↓
5. 기존 최소 마스킹 적용
        ↓
6. source / event_type / message 결정
        ↓
7. occurred_at을 timestamp로 통일
        ↓
8. producer event_id 보존 또는 fallback ID 생성
        ↓
9. 고정된 os-agent-evidence-v1 root object 재구성
```

### 5.1 Source 분류

기존 Vector tag를 다음처럼 공통 `source_type`으로 변환한다.

| 기존 `collector_channel` | 정규화 `source_type` | 기본 `event_type` |
|---|---|---|
| `journald` | `journald` | `journal_entry` |
| `auditd` | `auditd` | `audit_record` 또는 `audit.<type>` |
| `docker_json` | `docker_log` | `docker_log` |
| `docker_event` | `docker_event` | `docker_event` 또는 `docker_event.<action>` |
| `executor` | `executor` | producer 값 또는 `executor_event` |
| `state` | `snapshot` | producer 값 또는 `snapshot` |

### 5.2 원본 payload 보존

- Docker Events, Docker log, executor, snapshot은 file source의 `.message`를 JSON object로
  파싱해 `payload`에 둔다.
- JSON이 깨졌거나 object가 아니면 event를 버리지 않고 다음 형태로 보존한다.

```json
{
  "raw_message": "원본 한 줄",
  "parse_error": true
}
```

- journald와 auditd는 Vector가 전달한 원본 event object를 `payload`로 유지한다.
- JSON object를 공통 root에 merge하지 않으므로 source-specific 필드가 공통 필드를
  덮지 못한다.
- Docker stdout/stderr의 내부 JSON 문자열도 `payload.message`와 공통 `message`에 그대로
  보존한다.

### 5.3 Source와 event type 결정

- producer가 non-empty `source`를 주면 그대로 사용한다.
- journald는 `_SYSTEMD_UNIT`, `SYSLOG_IDENTIFIER`, `journald` 순으로 fallback한다.
- auditd는 원문 앞의 `type=SYSCALL` 같은 값을 읽어 `audit.syscall` 형태로 만든다.
- Docker Events는 `Action=start` 같은 값을 읽어 `docker_event.start` 형태로 만든다.
- executor와 snapshot은 producer가 준 `event_type`을 보존한다.

### 5.4 발생시각 정규화

`occurred_at`은 Vector 내부 timestamp 타입으로 통일하고 JSON sink에서는 RFC 3339
문자열로 출력한다. 우선순위는 다음과 같다.

1. `payload.occurred_at`
2. `payload.created_at`
3. audit message의 `msg=audit(<epoch>:<serial>)` epoch seconds
4. Docker Event `timeNano`
5. Docker Event `time`
6. `payload.timestamp`
7. Vector input `timestamp`
8. normalize transform 수신시각

이 순서로 Docker Events의 실제 발생시각이 file ingest 시각에 의해 덮이는 문제를 막았다.

### 5.5 Event ID 정규화

- producer가 non-empty string `event_id`를 제공하면 그대로 보존한다.
- journald는 `__CURSOR`를 seed로 사용한다.
- 나머지는 `collector_channel`, 원문, file path, file offset을 조합한 뒤 SHA-256으로
  `collected-<hash>`를 생성한다.

### 5.6 기존 마스킹 유지

기존 동작과 동일하게 payload 최상위의 다음 필드는 제거한다.

- `authorization`, `Authorization`
- `headers.authorization`, `headers.Authorization`
- `environment`, `env`

새로운 재귀 마스킹 시스템은 이번 단계에 추가하지 않았다.

## 6. Docker log 변환 예시

### Vector file source 입력

```json
{
  "collector_channel": "docker_json",
  "file": "/var/log/os-agent/docker-logs.ndjson",
  "file_offset": 84,
  "host": "host-a",
  "source_type": "file",
  "timestamp": "2026-08-30T01:00:04Z",
  "message": "{\"event_id\":\"docker-log-abc\",\"occurred_at\":\"2026-08-30T01:00:03Z\",\"source\":\"docker-logs-relay\",\"stream\":\"stdout\",\"message\":\"{\\\"message\\\":\\\"inner-json-must-survive\\\"}\"}"
}
```

### 공통 Evidence 출력

```json
{
  "schema_version": "os-agent-evidence-v1",
  "event_id": "docker-log-abc",
  "source_type": "docker_log",
  "source": "docker-logs-relay",
  "event_type": "docker_log",
  "occurred_at": "2026-08-30T01:00:03Z",
  "collector_received_at": "2026-08-30T01:00:03.050Z",
  "environment_id": "trial-0826",
  "topology_revision": "0826-v1",
  "message": "{\"message\":\"inner-json-must-survive\"}",
  "collector": {
    "channel": "docker_json",
    "vector_source_type": "file",
    "host": "host-a",
    "file": "/var/log/os-agent/docker-logs.ndjson",
    "file_offset": 84,
    "journal_cursor": null,
    "vector_timestamp": "2026-08-30T01:00:04Z"
  },
  "payload": {
    "event_id": "docker-log-abc",
    "occurred_at": "2026-08-30T01:00:03Z",
    "source": "docker-logs-relay",
    "stream": "stdout",
    "message": "{\"message\":\"inner-json-must-survive\"}"
  }
}
```

기존 구현에서는 위 `payload.message`가 root merge 뒤 삭제될 수 있었지만, 현재는 원문과
공통 메시지에 모두 보존된다.

## 7. 수정 파일

| 파일 | 변경 내용 |
|---|---|
| `infra/terraform/config/vector/normalize.vrl.tpl` | 공통 Evidence envelope와 source별 정규화 구현 |
| `infra/terraform/config/vector/normalize.tests.yaml` | 여섯 source fixture 테스트 추가 |
| `infra/terraform/EVIDENCE_SCHEMA.md` | 필드 계약, source 상태, JSON 예시 문서화 |
| `infra/terraform/README.md` | 공통 schema와 테스트 문서 연결 |
| `OS-Agent_0826_Terraform_변경사항.md` | 기존 Docker message 유실 이슈 해결 상태 반영 |
| `대시보드_추가사항.md` | 향후 Evidence 필터와 표시 항목만 기록 |

`vector.yaml.tpl`의 기존 source/tag/normalize/sink 연결은 이미 필요한 구조였으므로 중복
수정하지 않았다. 생성된 `/etc/vector/vector.yaml`, `/etc/vector/normalize.vrl`도 직접
수정하지 않았다.

## 8. 검증 결과

| 검증 | 결과 | 비고 |
|---|---|---|
| Vector 버전 | 통과 | 공식 portable `vector 0.57.0`, build `8832452` 사용 |
| VRL transform 구성 검증 | 통과 | Windows에서 지원되는 fixture topology로 검증 |
| auditd fixture | 통과 | audit type과 epoch time 확인 |
| journald fixture | 통과 | unit, cursor, timestamp 확인 |
| Docker log fixture | 통과 | 내부 JSON message 보존 확인 |
| Docker Event fixture | 통과 | action 분류와 `timeNano` 우선 확인 |
| Executor fixture | 통과 | producer type과 기존 마스킹 확인 |
| Snapshot fixture | 통과 | `STATE_CAPTURED`, phase 보존 확인 |
| `terraform fmt -check -recursive` | 통과 | Terraform formatting 정상 |
| Terraform template 렌더링 | 통과 | remote sink false/true 분기 모두 평가 가능 |
| `git diff --check` | 통과 | whitespace 오류 없음 |
| 문서 JSON 예시 파싱 | 통과 | JSON code block 파싱 확인 |
| 압축 user-data 크기 | 통과 | `19,196 / 20,480` bytes |
| `terraform validate` | 실행 차단 | 로컬 `.terraform/providers`에 AWS provider 6.61.0 package가 없어 검사 시작 전 종료 |
| 전체 Linux Vector topology | 로컬 제약 | Windows Vector에는 Linux 전용 journald source가 없어 EC2에서 최종 확인 필요 |

검증을 위해 내려받은 portable Vector ZIP, 실행 폴더, 렌더링 임시 폴더는 검증 후 모두
삭제했다. Vector를 시스템에 설치하거나 PATH, 서비스, 레지스트리를 변경하지 않았다.

## 9. 기존 수집 호환성

- 기존 auditd, journald, Docker relay source 설정을 변경하지 않았다.
- 기존 local file sink 경로를 변경하지 않았다.
- 기존 조건부 원격 HTTP sink를 추가·삭제·변경하지 않았다.
- 기존 masking 범위를 유지했다.
- producer의 원본 event ID와 source-specific 필드를 `payload`에 보존했다.
- parse 실패 event도 버리지 않고 공통 envelope로 보존한다.

단, 정규화 출력 root는 의도적으로 공통 schema로 변경되므로 향후 consumer는 source별
원본 필드를 root가 아니라 `payload`에서 읽어야 한다. 현재 Evidence API와 저장 consumer는
구현되어 있지 않다.

## 10. 미연결 항목과 다음 단계

이번 단계에서 발견했지만 구현하지 않은 항목은 다음과 같다.

1. Executor NDJSON writer 구현
2. U1/C1 실행 결과를 `/var/log/os-agent/executor/*.ndjson`에 안전하게 기록하는 권한·rotation 계약
3. Supervisor action lifecycle에서 Before/After capture 자동 호출
4. 임시 `docker run --rm` executor의 Evidence 생산 경로
5. Linux EC2에서 정확한 Vector 0.57.0 전체 설정 검증
6. Evidence API, Supabase 저장, Artifact 업로드
7. 공통 run/action/path correlation과 Verifier 연결
8. 대시보드 Evidence 조회 API와 화면

대시보드 후속 요구사항은 코드 대신 `대시보드_추가사항.md`에만 기록했다.

## 11. 재검증 명령

Vector 0.57.0을 사용할 수 있는 개발 환경:

```powershell
Set-Location infra/terraform/config/vector
vector test normalize.tests.yaml
```

Terraform provider가 준비된 환경:

```powershell
Set-Location infra/terraform
terraform fmt -check -recursive
terraform validate
```

실제 Ubuntu EC2:

```bash
sudo -u vector /usr/local/bin/vector validate --skip-healthchecks /etc/vector/vector.yaml
sudo /opt/os-agent/scripts/verify_environment.sh
```

## 12. 결론

이번 작업으로 Vector에 선언된 모든 source가 동일한 `os-agent-evidence-v1` root 구조로
정규화된다. 자동 producer가 존재하는 auditd, journald, Docker Events, Docker log는 즉시
이 구조로 출력되며, 현재 미생산 상태인 executor와 snapshot도 향후 원본 event가 들어오면
동일한 transform을 거친다.

이번 단계에서는 수집 범위를 확장하지 않고 기존 연결을 정규화하는 데만 집중했다.
Executor writer와 Before/After lifecycle 연결은 별도 단계로 남겼다.
