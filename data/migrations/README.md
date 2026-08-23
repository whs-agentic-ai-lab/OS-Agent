# Supabase migrations

현재 로컬에는 Supabase CLI가 설치되어 있지 않아 임의의 timestamp 마이그레이션을 만들지 않았다.

`../schema.sql`은 검토 가능한 bootstrap SQL이다. 실제 Supabase 프로젝트를 연결할 때 다음 순서로 정식 마이그레이션을 생성한다.

현재 bootstrap 스키마에는 `common-minimum-v1` 실행 결과 필드가 포함되어 있다. 기존 `runs` 테이블에 대해서도 `schema.sql`의 `alter table ... add column if not exists` 구문이 같은 필드를 추가한다. 수집기가 아직 없는 값은 DB에서 `UNIMPLEMENTED`로 저장하고 UI에서 `미구현`으로 표시한다.

1. Supabase CLI를 설치하고 `supabase --version` 및 `supabase migration new --help`를 확인한다.
2. `supabase migration new initial_agent_runs`로 파일을 생성한다.
3. `schema.sql` 내용을 생성된 파일에 옮긴다.
4. 로컬 DB에 적용한 뒤 RLS, grants와 두 테이블을 검증한다.
5. `supabase db advisors`를 실행하고 마이그레이션 목록을 확인한다.

프론트엔드는 Supabase에 직접 접근하지 않는다. `service_role` 또는 secret key는 EC2 백엔드 환경변수로만 주입한다.
