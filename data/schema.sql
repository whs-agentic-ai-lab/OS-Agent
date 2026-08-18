-- Supabase bootstrap schema for the minimum OS agent test.
-- Frontend access is intentionally disabled; only the EC2 backend service role may write/read.

create table if not exists public.runs (
  run_id text primary key,
  prompt text not null check (char_length(prompt) between 1 and 4000),
  subject_mode text not null check (subject_mode in ('container', 'host')),
  permission_id text not null,
  permission_enabled boolean not null,
  requested_profile text not null,
  applied_profile text,
  planner_mode text not null check (planner_mode in ('local', 'openrouter')),
  tool text check (tool in ('file_read', 'file_write', 'service_status')),
  runtime_result text check (runtime_result in ('allowed', 'denied', 'error')),
  output text,
  exit_code integer,
  before_sha256 text,
  after_sha256 text,
  status text not null,
  test_result text check (test_result in ('PASS', 'FAIL', 'INCONCLUSIVE')),
  created_at timestamptz not null default now(),
  completed_at timestamptz
);

create table if not exists public.run_events (
  event_id uuid primary key default gen_random_uuid(),
  run_id text not null references public.runs(run_id) on delete cascade,
  sequence integer not null check (sequence > 0),
  source text not null check (source in ('profile', 'model', 'tool_runner', 'executor', 'verifier')),
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

revoke all on table public.runs from anon, authenticated;
revoke all on table public.run_events from anon, authenticated;

grant select, insert, update, delete on table public.runs to service_role;
grant select, insert, update, delete on table public.run_events to service_role;

