revoke all on table public.host_executor_runs from service_role;
revoke all on table public.container_executor_runs from service_role;
revoke all on table public.host_executor_run_events from service_role;
revoke all on table public.container_executor_run_events from service_role;

grant select, insert, update, delete on table public.host_executor_runs to service_role;
grant select, insert, update, delete on table public.container_executor_runs to service_role;
grant select, insert, update, delete on table public.host_executor_run_events to service_role;
grant select, insert, update, delete on table public.container_executor_run_events to service_role;
