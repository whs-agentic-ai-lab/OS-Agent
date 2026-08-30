# Supabase migrations

현재 로컬에는 Supabase CLI가 설치되어 있지 않다. 기존 파일은 연결된 프로젝트의 migration version을 사용한다. `20260830090000_add_evidence_storage.sql`은 기존 로깅 작업에서 이식한 **미적용 로컬 마이그레이션**이며 원격 적용 이력이 아니다.

`../schema.sql`은 검토 가능한 bootstrap SQL이다. 실제 Supabase 프로젝트를 연결할 때 다음 순서로 정식 마이그레이션을 생성한다.

현재 bootstrap 스키마에는 `common-minimum-v2` 실행 결과 필드와 방향성 TB 필드가 포함되어 있다. `permission_profile` 객체 하나가 한 `run_id`를 나타내며 `applied_profile_state`, `runtime_agent`, `tool_arguments`와 단일 Runtime Evidence를 함께 저장한다. 기존 v1의 `permissions`, `permission_results` 열은 과거 로그 읽기 호환을 위해 유지한다.

Executor 결과는 다음 네 테이블로 물리 분리한다.

- `host_executor_runs`, `host_executor_run_events`
- `container_executor_runs`, `container_executor_run_events`

`schema.sql`을 기존 프로젝트에 적용하면 legacy `runs`/`run_events`를 `subject_mode`에 따라 각 Executor 테이블로 복사한다. 신규 Backend는 이후 legacy 테이블에 쓰지 않는다.

원격 프로젝트에는 `profile_runtime_v2`와 `split_executor_run_storage` 마이그레이션이 적용되어 있으며, `schema.sql`의 idempotent 구문으로 같은 상태를 재현할 수 있다.

8개 TB 전체 Orchestrator 실행은 `agent_runs`, `agent_run_events`에 별도로 저장한다. 두 Executor의 단일 실행 로그를 물리적으로 합치지 않고, AgentRun에는 고정 `profile_hash`, Recon/Infrastructure snapshot, findings, TB별 plan/result, worst-case와 참조 이벤트를 저장한다. 적용 SQL은 `20260828194500_add_agent_orchestrator_runs.sql`이다.

상태 누적형 탐색이 Watchdog에서 멈추면 `PAUSED`와 replay checkpoint로 저장한다. 기존 `agent_runs.status` 제약에는 `20260829013000_add_agent_run_paused_status.sql`을 적용한다.

1. Supabase CLI를 설치하고 `supabase --version` 및 `supabase migration new --help`를 확인한다.
2. 신규 변경은 `supabase migration new <name>`으로 파일을 생성한다.
3. `schema.sql`의 해당 변경 내용을 생성된 파일에 옮긴다.
4. 로컬 DB에 적용한 뒤 RLS, grants와 두 테이블을 검증한다.
5. `supabase db advisors`를 실행하고 마이그레이션 목록을 확인한다.

프론트엔드는 Supabase에 직접 접근하지 않는다. `service_role` 또는 secret key는 신뢰된 수신 API 서버 환경변수로만 주입한다. Vector, snapshot uploader, 실험 Tool/Runtime 컨테이너에 배포하지 않는다.

## Evidence 저장 마이그레이션

`20260830090000_add_evidence_storage.sql`은 `evidence_events`, `evidence_artifacts`와 private Storage bucket `os-agent-evidence`만 추가한다. 기존 실행 테이블·데이터는 변경하지 않는다. 같은 bucket이 이미 있다면 public 설정을 false, 단일 파일 제한을 32 MiB로 맞춘다. 해당 bucket만 대상으로 하는 restrictive RLS policy를 추가하여 기존의 광범위한 Storage policy로 인한 anon/authenticated 접근도 차단한다.

- 이벤트 유일키는 `(environment_id, event_id)`이다. 환경을 구분하면서 기존 Vector event ID를 유지하고 재전송은 최초 저장을 덮어쓰지 않는다.
- Artifact 유일키는 `(environment_id, event_id, filename)`이다. 본문은 Storage에만 있고 DB에는 private object key·크기·저장 SHA-256·producer가 제시한 원본 SHA-256 및 실제 run/action/phase가 있다.
- 실행 컨텍스트는 `evidence_events.context`에 있다. `(environment_id, context.run_id, context.action_id)`로 기존 실행 기록과 연결한다. 비동기 도착 순서, host/container/AgentRun 테이블 분리 및 Harness의 메모리 저장을 고려하여 run FK는 강제하지 않는다.
- API는 strict 저장만 사용한다. 이벤트 DB 장애 및 Artifact Storage/DB 장애는 503이며 메모리 fallback이나 성공 응답을 하지 않는다.
- Storage 성공 후 metadata DB 실패 시 object가 먼저 남을 수 있다. 같은 파일 재전송은 동일한 content-addressed object key로 upsert하고 metadata 저장을 다시 시도한다. 자동 삭제·정리 작업은 추가하지 않았다.
- `original_sha256`는 uploader가 로컬 원본을 해시한 값이다. 서버는 받은 전송본 및 최종 마스킹 저장본 해시를 검증/계산하며, 받지 않은 원본의 내용까지 원격 검증했다고 보장하지 않는다.

원격 DB 연결·변경은 대상 프로젝트와 영향을 확인받은 뒤 수행한다. 기존 프로젝트에는 전체 bootstrap 재실행 대신 이 migration만 적용한다. 예시(비밀값은 환경변수로 관리):

```powershell
# 대상 확인 및 승인 후, 저장소 루트에서만 실행
psql $env:SUPABASE_DB_URL -v ON_ERROR_STOP=1 --single-transaction -f data/migrations/20260830090000_add_evidence_storage.sql
```

위 명령과 실제 DB/RLS/Storage 검증은 이번 로컬 구현에서 실행하지 않았다. `EVIDENCE_COLLECTOR_TOKEN`, `SUPABASE_URL`, `SUPABASE_SECRET_KEY`(또는 기존 service-role fallback)는 수신 API 서버에 설정한다. 기존 운영 문서의 원격 E2E 절차로 인증·저장·private 접근 차단·재전송을 별도로 검증해야 한다.
