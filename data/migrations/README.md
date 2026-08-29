# Supabase migrations

현재 로컬에는 Supabase CLI가 설치되어 있지 않다. 연결된 Supabase 프로젝트가 발급한 실제 migration version을 파일명으로 사용한다.

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

프론트엔드는 Supabase에 직접 접근하지 않는다. `service_role` 또는 secret key는 EC2 백엔드 환경변수로만 주입한다.
