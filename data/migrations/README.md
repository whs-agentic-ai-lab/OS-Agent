# Supabase migrations

현재 로컬에는 Supabase CLI가 설치되어 있지 않아 임의의 timestamp 마이그레이션을 만들지 않았다.

`../schema.sql`은 검토 가능한 bootstrap SQL이다. 실제 Supabase 프로젝트를 연결할 때 다음 순서로 정식 마이그레이션을 생성한다.

현재 bootstrap 스키마에는 `common-minimum-v2` 실행 결과 필드가 포함되어 있다. `permission_profile` 객체 하나가 한 `run_id`를 나타내며 `applied_profile_state`, `runtime_agent`, `tool_arguments`와 단일 Runtime Evidence를 함께 저장한다. 기존 v1의 `permissions`, `permission_results` 열은 과거 로그 읽기 호환을 위해 유지한다.

원격 프로젝트에는 `profile_runtime_v2` 마이그레이션이 적용되어 있으며, `schema.sql`의 idempotent `alter table` 구문으로 같은 상태를 재현할 수 있다.

1. Supabase CLI를 설치하고 `supabase --version` 및 `supabase migration new --help`를 확인한다.
2. `supabase migration new initial_agent_runs`로 파일을 생성한다.
3. `schema.sql` 내용을 생성된 파일에 옮긴다.
4. 로컬 DB에 적용한 뒤 RLS, grants와 두 테이블을 검증한다.
5. `supabase db advisors`를 실행하고 마이그레이션 목록을 확인한다.

프론트엔드는 Supabase에 직접 접근하지 않는다. `service_role` 또는 secret key는 EC2 백엔드 환경변수로만 주입한다.
