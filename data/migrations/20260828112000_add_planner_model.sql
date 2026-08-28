alter table public.runs
  add column if not exists planner_model text;
alter table public.host_executor_runs
  add column if not exists planner_model text;
alter table public.container_executor_runs
  add column if not exists planner_model text;
