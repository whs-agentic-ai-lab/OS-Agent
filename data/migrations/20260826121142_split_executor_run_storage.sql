alter table public.runs add column if not exists trust_boundary_id text not null default 'UNASSIGNED';
alter table public.runs add column if not exists source_environment text
  check (source_environment in ('u1', 'c1'));
alter table public.runs add column if not exists target_environment text
  check (target_environment in ('u1', 'u2', 'c1', 'c2', 'c3'));

create table public.host_executor_runs
  (like public.runs including all);
create table public.container_executor_runs
  (like public.runs including all);
create table public.host_executor_run_events
  (like public.run_events including all);
create table public.container_executor_run_events
  (like public.run_events including all);

alter table public.host_executor_runs
  add constraint host_executor_runs_host_only_check
  check (subject_mode = 'host');
alter table public.container_executor_runs
  add constraint container_executor_runs_container_only_check
  check (subject_mode = 'container');
alter table public.host_executor_run_events
  add constraint host_executor_run_events_run_id_fkey
  foreign key (run_id) references public.host_executor_runs(run_id) on delete cascade;
alter table public.container_executor_run_events
  add constraint container_executor_run_events_run_id_fkey
  foreign key (run_id) references public.container_executor_runs(run_id) on delete cascade;

insert into public.host_executor_runs
  select * from public.runs where subject_mode = 'host';
insert into public.container_executor_runs
  select * from public.runs where subject_mode = 'container';
insert into public.host_executor_run_events
  select events.*
  from public.run_events as events
  join public.runs as runs using (run_id)
  where runs.subject_mode = 'host';
insert into public.container_executor_run_events
  select events.*
  from public.run_events as events
  join public.runs as runs using (run_id)
  where runs.subject_mode = 'container';

alter table public.host_executor_runs enable row level security;
alter table public.container_executor_runs enable row level security;
alter table public.host_executor_run_events enable row level security;
alter table public.container_executor_run_events enable row level security;

revoke all on table public.host_executor_runs from anon, authenticated;
revoke all on table public.container_executor_runs from anon, authenticated;
revoke all on table public.host_executor_run_events from anon, authenticated;
revoke all on table public.container_executor_run_events from anon, authenticated;

grant select, insert, update, delete on table public.host_executor_runs to service_role;
grant select, insert, update, delete on table public.container_executor_runs to service_role;
grant select, insert, update, delete on table public.host_executor_run_events to service_role;
grant select, insert, update, delete on table public.container_executor_run_events to service_role;
