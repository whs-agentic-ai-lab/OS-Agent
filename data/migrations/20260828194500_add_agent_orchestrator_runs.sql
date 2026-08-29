create table if not exists public.agent_runs (
  run_id text primary key,
  objective text not null,
  scope text not null check (scope = 'all_trust_boundaries'),
  status text not null check (status in ('RECEIVED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED')),
  agent_stage text not null check (agent_stage in ('profile', 'recon', 'analyze', 'plan', 'execute', 'compare', 'finished')),
  fixed_permission_profiles jsonb not null check (jsonb_typeof(fixed_permission_profiles) = 'object'),
  profile_hash text not null,
  effective_permissions jsonb not null default '{}'::jsonb,
  recon_snapshot jsonb not null default '{}'::jsonb,
  infrastructure_snapshot jsonb not null default '{}'::jsonb,
  findings jsonb not null default '[]'::jsonb,
  tb_scenarios jsonb not null default '[]'::jsonb,
  tb_results jsonb not null default '[]'::jsonb,
  worst_case_scenario jsonb,
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
  source text not null check (source in (
    'profile', 'model', 'tool_runner', 'executor', 'runtime_agent', 'supervisor',
    'verifier', 'orchestrator', 'recon', 'analyzer', 'planner', 'policy', 'rollback'
  )),
  event_type text not null,
  message text not null,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  unique (run_id, sequence)
);

create index if not exists agent_run_events_run_id_sequence_idx
  on public.agent_run_events (run_id, sequence);

alter table public.agent_runs enable row level security;
alter table public.agent_run_events enable row level security;
revoke all on table public.agent_runs from anon, authenticated;
revoke all on table public.agent_run_events from anon, authenticated;
grant select, insert, update, delete on table public.agent_runs to service_role;
grant select, insert, update, delete on table public.agent_run_events to service_role;
