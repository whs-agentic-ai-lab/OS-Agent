-- Supabase bootstrap schema for the minimum OS agent test.
-- Frontend access is intentionally disabled; only the EC2 backend service role may write/read.

create table if not exists public.runs (
  run_id text primary key,
  prompt text not null check (char_length(prompt) between 1 and 4000),
  subject_mode text not null check (subject_mode in ('container', 'host')),
  trust_boundary_id text not null default 'UNASSIGNED',
  source_environment text check (source_environment in ('u1', 'c1')),
  target_environment text check (target_environment in ('u1', 'u2', 'c1', 'c2', 'c3')),
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
  planner_model text,
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
alter table public.runs add column if not exists planner_model text;
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
alter table public.runs add column if not exists trust_boundary_id text not null default 'UNASSIGNED';
alter table public.runs add column if not exists source_environment text
  check (source_environment in ('u1', 'c1'));
alter table public.runs add column if not exists target_environment text
  check (target_environment in ('u1', 'u2', 'c1', 'c2', 'c3'));

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

-- U1 Host Executor와 C1 Container Executor 결과는 물리적으로 다른 테이블에 저장한다.
-- public.runs/run_events는 기존 로그를 한 번 이관하기 위한 legacy source로만 유지한다.
create table if not exists public.host_executor_runs
  (like public.runs including all);
create table if not exists public.container_executor_runs
  (like public.runs including all);
create table if not exists public.host_executor_run_events
  (like public.run_events including all);
create table if not exists public.container_executor_run_events
  (like public.run_events including all);

alter table public.host_executor_runs add column if not exists planner_model text;
alter table public.container_executor_runs add column if not exists planner_model text;

alter table public.host_executor_runs drop constraint if exists host_executor_runs_subject_mode_check;
alter table public.host_executor_runs add constraint host_executor_runs_subject_mode_check
  check (subject_mode = 'host');
alter table public.container_executor_runs drop constraint if exists container_executor_runs_subject_mode_check;
alter table public.container_executor_runs add constraint container_executor_runs_subject_mode_check
  check (subject_mode = 'container');

do $$
begin
  if not exists (
    select 1 from pg_constraint where conname = 'host_executor_run_events_run_id_fkey'
  ) then
    alter table public.host_executor_run_events
      add constraint host_executor_run_events_run_id_fkey
      foreign key (run_id) references public.host_executor_runs(run_id) on delete cascade;
  end if;
  if not exists (
    select 1 from pg_constraint where conname = 'container_executor_run_events_run_id_fkey'
  ) then
    alter table public.container_executor_run_events
      add constraint container_executor_run_events_run_id_fkey
      foreign key (run_id) references public.container_executor_runs(run_id) on delete cascade;
  end if;
end $$;

insert into public.host_executor_runs
  select * from public.runs where subject_mode = 'host'
  on conflict (run_id) do nothing;
insert into public.container_executor_runs
  select * from public.runs where subject_mode = 'container'
  on conflict (run_id) do nothing;
insert into public.host_executor_run_events
  select events.*
  from public.run_events as events
  join public.runs as runs using (run_id)
  where runs.subject_mode = 'host'
  on conflict (run_id, sequence) do nothing;
insert into public.container_executor_run_events
  select events.*
  from public.run_events as events
  join public.runs as runs using (run_id)
  where runs.subject_mode = 'container'
  on conflict (run_id, sequence) do nothing;

alter table public.host_executor_runs enable row level security;
alter table public.container_executor_runs enable row level security;
alter table public.host_executor_run_events enable row level security;
alter table public.container_executor_run_events enable row level security;

revoke all on table public.runs from anon, authenticated;
revoke all on table public.run_events from anon, authenticated;
revoke all on table public.host_executor_runs from anon, authenticated;
revoke all on table public.container_executor_runs from anon, authenticated;
revoke all on table public.host_executor_run_events from anon, authenticated;
revoke all on table public.container_executor_run_events from anon, authenticated;
revoke all on table public.host_executor_runs from service_role;
revoke all on table public.container_executor_runs from service_role;
revoke all on table public.host_executor_run_events from service_role;
revoke all on table public.container_executor_run_events from service_role;

grant select, insert, update, delete on table public.runs to service_role;
grant select, insert, update, delete on table public.run_events to service_role;
grant select, insert, update, delete on table public.host_executor_runs to service_role;
grant select, insert, update, delete on table public.container_executor_runs to service_role;
grant select, insert, update, delete on table public.host_executor_run_events to service_role;
grant select, insert, update, delete on table public.container_executor_run_events to service_role;

-- Host 또는 Container 출발 경계를 분리 실행하는 AgentRun 저장소.
create table if not exists public.agent_runs (
  run_id text primary key,
  objective text not null,
  scope text not null check (scope in ('host', 'container', 'all_trust_boundaries')),
  status text not null check (status in ('RECEIVED', 'RUNNING', 'PAUSED', 'COMPLETED', 'FAILED', 'CANCELLED')),
  agent_stage text not null check (agent_stage in ('profile', 'maximize', 'recon', 'analyze', 'plan', 'execute', 'compare', 'contract', 'minimize', 'reverify', 'finished')),
  fixed_permission_profiles jsonb not null,
  profile_hash text not null,
  effective_permissions jsonb not null default '{}'::jsonb,
  recon_snapshot jsonb not null default '{}'::jsonb,
  infrastructure_snapshot jsonb not null default '{}'::jsonb,
  findings jsonb not null default '[]'::jsonb,
  tb_scenarios jsonb not null default '[]'::jsonb,
  tb_results jsonb not null default '[]'::jsonb,
  campaign_search jsonb not null default '{}'::jsonb,
  worst_case_scenario jsonb,
  attack_contract jsonb,
  permission_minimization jsonb not null default '{}'::jsonb,
  summary jsonb not null default '{}'::jsonb,
  budget jsonb not null default '{}'::jsonb,
  planner_mode text not null check (planner_mode in ('local', 'openrouter')),
  planner_model text,
  rollback_status text not null check (rollback_status in ('NOT_REQUIRED', 'VERIFIED', 'FAILED')),
  profile_application_checks jsonb not null default '{}'::jsonb,
  profile_warnings jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now(),
  completed_at timestamptz
);
alter table public.agent_runs add column if not exists objective text;
alter table public.agent_runs add column if not exists campaign_search jsonb not null default '{}'::jsonb;
update public.agent_runs
set objective = '고정 권한과 Recon 증거를 기반으로 8개 Trust Boundary를 자율 검증한다.'
where objective is null;
alter table public.agent_runs alter column objective set not null;
do $$
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'agent_runs' and column_name = 'prompt'
  ) then
    alter table public.agent_runs alter column prompt drop not null;
  end if;
end $$;
create table if not exists public.agent_run_events (
  event_id uuid primary key default gen_random_uuid(),
  run_id text not null references public.agent_runs(run_id) on delete cascade,
  sequence integer not null check (sequence > 0),
  source text not null,
  event_type text not null,
  message text not null,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  unique (run_id, sequence)
);
create index if not exists agent_run_events_run_id_sequence_idx on public.agent_run_events (run_id, sequence);
alter table public.agent_runs enable row level security;
alter table public.agent_run_events enable row level security;
revoke all on table public.agent_runs from anon, authenticated;
revoke all on table public.agent_run_events from anon, authenticated;
grant select, insert, update, delete on table public.agent_runs to service_role;
grant select, insert, update, delete on table public.agent_run_events to service_role;

-- Evidence-only, additive migration. No experiment run data is changed.
-- This migration has not been applied remotely by the logging implementation.

create table if not exists public.evidence_events (
  environment_id text not null check (environment_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
  event_id text not null check (event_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$'),
  schema_version text not null check (schema_version = 'os-agent-evidence-v1'),
  source_type text not null check (source_type in (
    'auditd', 'journald', 'docker_log', 'docker_event', 'executor', 'snapshot', 'unknown'
  )),
  source text not null check (char_length(source) between 1 and 512),
  event_type text not null check (char_length(event_type) between 1 and 256),
  occurred_at timestamptz not null,
  collector_received_at timestamptz not null,
  topology_revision text not null check (char_length(topology_revision) between 1 and 256),
  message text not null,
  collector jsonb not null check (jsonb_typeof(collector) = 'object'),
  payload jsonb not null check (jsonb_typeof(payload) = 'object'),
  context jsonb not null default '{"run_id":null,"action_id":null,"step_id":null,"tool_call_id":null}'::jsonb
    check (jsonb_typeof(context) = 'object'),
  status text not null default 'ok' check (status in ('ok', 'parse_error', 'collection_error')),
  received_at timestamptz not null default now(),
  primary key (environment_id, event_id)
);

-- Deliberately no run FK: events may arrive before run persistence, host and
-- container runs use separate tables, and Harness runs currently live in memory.
create index if not exists evidence_events_environment_time_idx
  on public.evidence_events (environment_id, occurred_at);
create index if not exists evidence_events_run_action_idx
  on public.evidence_events (environment_id, (context->>'run_id'), (context->>'action_id'))
  where context->>'run_id' is not null;

create table if not exists public.evidence_artifacts (
  environment_id text not null check (environment_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
  event_id text not null check (event_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$'),
  run_id text not null check (run_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
  action_id text not null check (action_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
  phase text not null check (phase in ('before', 'after')),
  filename text not null check (filename in (
    'timestamp_utc.txt', 'boot_id.txt', 'journal_cursor.txt', 'audit_status.txt',
    'processes.txt', 'listeners.txt', 'identity.txt', 'target_processes.txt',
    'container_inspect.json', 'container_processes.txt', 'container_diff.txt',
    'files.sha256', 'files.metadata', 'diff-from-before.txt', 'manifest.json',
    'artifact-sha256.txt'
  )),
  bucket text not null check (bucket = 'os-agent-evidence'),
  object_path text not null,
  size_bytes bigint not null check (size_bytes between 0 and 33554432),
  sha256 text not null check (sha256 ~ '^[0-9a-f]{64}$'),
  original_sha256 text not null check (original_sha256 ~ '^[0-9a-f]{64}$'),
  status text not null check (status = 'uploaded'),
  created_at timestamptz not null default now(),
  primary key (environment_id, event_id, filename)
);

alter table public.evidence_events enable row level security;
alter table public.evidence_artifacts enable row level security;
revoke all on table public.evidence_events from public, anon, authenticated, service_role;
revoke all on table public.evidence_artifacts from public, anon, authenticated, service_role;
grant select, insert on table public.evidence_events to service_role;
grant select, insert on table public.evidence_artifacts to service_role;

insert into storage.buckets (id, name, public, file_size_limit)
  values ('os-agent-evidence', 'os-agent-evidence', false, 33554432)
  on conflict (id) do update set public = false, file_size_limit = 33554432;

-- Restrictive policies protect only this bucket, even if an existing permissive
-- policy allows anonymous/authenticated access to unrelated application buckets.
-- service_role bypasses RLS and is held exclusively by the trusted API server.
drop policy if exists evidence_objects_private_guard on storage.objects;
create policy evidence_objects_private_guard on storage.objects
  as restrictive for all to anon, authenticated
  using (bucket_id <> 'os-agent-evidence')
  with check (bucket_id <> 'os-agent-evidence');

drop policy if exists evidence_bucket_private_guard on storage.buckets;
create policy evidence_bucket_private_guard on storage.buckets
  as restrictive for all to anon, authenticated
  using (id <> 'os-agent-evidence')
  with check (id <> 'os-agent-evidence');
