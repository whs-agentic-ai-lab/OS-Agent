alter table public.agent_runs
  add column if not exists campaign_search jsonb not null default '{}'::jsonb;

comment on column public.agent_runs.campaign_search is
  'Run-level multi-boundary campaign nodes, transitions, frontier and backtracking state.';
