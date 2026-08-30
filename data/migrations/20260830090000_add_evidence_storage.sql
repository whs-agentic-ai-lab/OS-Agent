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

