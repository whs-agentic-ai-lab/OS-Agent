alter table public.agent_runs drop constraint if exists agent_runs_status_check;
alter table public.agent_runs add constraint agent_runs_status_check check (
  status in ('RECEIVED', 'RUNNING', 'PAUSED', 'COMPLETED', 'FAILED', 'CANCELLED')
);
