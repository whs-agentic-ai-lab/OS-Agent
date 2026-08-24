-- Supabase bootstrap schema for the minimum OS agent test.
-- Frontend access is intentionally disabled; only the EC2 backend service role may write/read.

create table if not exists public.runs (
  run_id text primary key,
  prompt text not null check (char_length(prompt) between 1 and 4000),
  subject_mode text not null check (subject_mode in ('container', 'host')),
  permission_id text not null,
  permission_enabled boolean not null,
  permission_profile jsonb not null default '{}'::jsonb
    check (jsonb_typeof(permission_profile) = 'object'),
  permissions jsonb not null default '[]'::jsonb
    check (jsonb_typeof(permissions) = 'array'),
  permission_results jsonb not null default '[]'::jsonb
    check (jsonb_typeof(permission_results) = 'array'),
  requested_profile text not null,
  applied_profile text,
  applied_profile_state jsonb not null default '{}'::jsonb
    check (jsonb_typeof(applied_profile_state) = 'object'),
  result_format_version text not null default 'common-minimum-v2',
  profile_version text not null default 'UNIMPLEMENTED',
  workload_type text not null default 'UNIMPLEMENTED'
    check (workload_type in ('normal', 'attack', 'UNIMPLEMENTED')),
  action_path_id text not null default 'UNIMPLEMENTED',
  changed_variable text not null default 'UNIMPLEMENTED',
  planner_mode text not null check (planner_mode in ('local', 'openrouter')),
  runtime_agent text not null default 'UNIMPLEMENTED',
  tool text check (tool in ('file_read', 'file_write', 'service_status')),
  tool_arguments jsonb not null default '{}'::jsonb
    check (jsonb_typeof(tool_arguments) = 'object'),
  policy_decision text not null default 'UNIMPLEMENTED'
    check (policy_decision in ('allowed', 'denied', 'UNIMPLEMENTED')),
  authentication_result text not null default 'UNIMPLEMENTED'
    check (authentication_result in ('succeeded', 'failed', 'UNIMPLEMENTED')),
  authorization_result text not null default 'UNIMPLEMENTED'
    check (authorization_result in ('allowed', 'denied', 'error', 'UNIMPLEMENTED')),
  runtime_result text check (runtime_result in ('allowed', 'denied', 'error')),
  output text,
  exit_code integer,
  before_sha256 text,
  after_sha256 text,
  verifier_name text not null default 'UNIMPLEMENTED',
  verifier_effect jsonb not null default '{}'::jsonb
    check (jsonb_typeof(verifier_effect) = 'object'),
  evidence_references jsonb not null default '[]'::jsonb
    check (jsonb_typeof(evidence_references) = 'array'),
  status text not null,
  test_result text check (test_result in ('PASS', 'FAIL', 'INCONCLUSIVE')),
  created_at timestamptz not null default now(),
  completed_at timestamptz
);

-- 기존 bootstrap 스키마로 생성된 runs 테이블도 같은 파일을 다시 실행해 확장할 수 있다.
alter table public.runs add column if not exists result_format_version text not null default 'common-minimum-v1';
alter table public.runs alter column result_format_version set default 'common-minimum-v2';
alter table public.runs add column if not exists permission_profile jsonb not null default '{}'::jsonb
  check (jsonb_typeof(permission_profile) = 'object');
alter table public.runs add column if not exists applied_profile_state jsonb not null default '{}'::jsonb
  check (jsonb_typeof(applied_profile_state) = 'object');
alter table public.runs add column if not exists runtime_agent text not null default 'UNIMPLEMENTED';
alter table public.runs add column if not exists tool_arguments jsonb not null default '{}'::jsonb
  check (jsonb_typeof(tool_arguments) = 'object');
alter table public.runs add column if not exists permissions jsonb not null default '[]'::jsonb
  check (jsonb_typeof(permissions) = 'array');
alter table public.runs add column if not exists permission_results jsonb not null default '[]'::jsonb
  check (jsonb_typeof(permission_results) = 'array');
alter table public.runs add column if not exists profile_version text not null default 'UNIMPLEMENTED';
alter table public.runs add column if not exists workload_type text not null default 'UNIMPLEMENTED'
  check (workload_type in ('normal', 'attack', 'UNIMPLEMENTED'));
alter table public.runs add column if not exists action_path_id text not null default 'UNIMPLEMENTED';
alter table public.runs add column if not exists changed_variable text not null default 'UNIMPLEMENTED';
alter table public.runs add column if not exists policy_decision text not null default 'UNIMPLEMENTED'
  check (policy_decision in ('allowed', 'denied', 'UNIMPLEMENTED'));
alter table public.runs add column if not exists authentication_result text not null default 'UNIMPLEMENTED'
  check (authentication_result in ('succeeded', 'failed', 'UNIMPLEMENTED'));
alter table public.runs add column if not exists authorization_result text not null default 'UNIMPLEMENTED'
  check (authorization_result in ('allowed', 'denied', 'error', 'UNIMPLEMENTED'));
alter table public.runs add column if not exists verifier_name text not null default 'UNIMPLEMENTED';
alter table public.runs add column if not exists verifier_effect jsonb not null default '{}'::jsonb
  check (jsonb_typeof(verifier_effect) = 'object');
alter table public.runs add column if not exists evidence_references jsonb not null default '[]'::jsonb
  check (jsonb_typeof(evidence_references) = 'array');

create table if not exists public.run_events (
  event_id uuid primary key default gen_random_uuid(),
  run_id text not null references public.runs(run_id) on delete cascade,
  sequence integer not null check (sequence > 0),
  source text not null check (source in ('profile', 'model', 'tool_runner', 'executor', 'runtime_agent', 'supervisor', 'verifier')),
  event_type text not null,
  message text not null,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  unique (run_id, sequence)
);

create index if not exists run_events_run_id_sequence_idx
  on public.run_events (run_id, sequence);

alter table public.runs enable row level security;
alter table public.run_events enable row level security;

-- 기존 테이블의 자동 생성 check 이름을 v2 source 목록으로 교체합니다.
alter table public.run_events drop constraint if exists run_events_source_check;
alter table public.run_events add constraint run_events_source_check
  check (source in ('profile', 'model', 'tool_runner', 'executor', 'runtime_agent', 'supervisor', 'verifier'));

revoke all on table public.runs from anon, authenticated;
revoke all on table public.run_events from anon, authenticated;

grant select, insert, update, delete on table public.runs to service_role;
grant select, insert, update, delete on table public.run_events to service_role;
