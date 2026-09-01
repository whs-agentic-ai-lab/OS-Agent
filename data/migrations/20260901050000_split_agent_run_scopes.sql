alter table public.agent_runs
  drop constraint if exists agent_runs_scope_check;

alter table public.agent_runs
  add constraint agent_runs_scope_check
  check (scope in ('host', 'container', 'all_trust_boundaries'));

comment on column public.agent_runs.scope is
  'New runs select host or container. all_trust_boundaries is retained for historical rows only.';
