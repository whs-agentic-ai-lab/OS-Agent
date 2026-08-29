alter table public.agent_runs
  add column if not exists attack_contract jsonb,
  add column if not exists permission_minimization jsonb not null default '{}'::jsonb;

alter table public.agent_runs drop constraint if exists agent_runs_agent_stage_check;
alter table public.agent_runs add constraint agent_runs_agent_stage_check check (
  agent_stage in (
    'profile', 'maximize', 'recon', 'analyze', 'plan', 'execute', 'compare',
    'contract', 'minimize', 'reverify', 'finished'
  )
);

alter table public.agent_run_events drop constraint if exists agent_run_events_source_check;
alter table public.agent_run_events add constraint agent_run_events_source_check check (
  source in (
    'profile', 'model', 'tool_runner', 'executor', 'runtime_agent', 'supervisor',
    'verifier', 'orchestrator', 'recon', 'analyzer', 'planner', 'policy',
    'rollback', 'minimizer'
  )
);
