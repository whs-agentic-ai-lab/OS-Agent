from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock

from app.repository import SupabaseRunRepository, create_run_repository
from app.schemas import RunEvent, RunRecord


def make_run() -> RunRecord:
    return RunRecord(
        run_id="os-repository-test",
        status="COMPLETED",
        prompt="Canary 파일을 읽어줘",
        subject_mode="container",
        permission_id="mount_write",
        permission_enabled=False,
        requested_profile="container-mount-ro",
        applied_profile="container-mount-ro",
        changed_variable="mount_write:OFF",
        planner_mode="local",
        tool="file_read",
        policy_decision="allowed",
        authorization_result="allowed",
        runtime_result="allowed",
        output="canary",
        exit_code=0,
        before_sha256="same",
        after_sha256="same",
        verifier_name="file_read_verifier",
        verifier_effect={"evidence_complete": True, "read_allowed": True},
        test_result="PASS",
        events=[
            RunEvent(
                sequence=1,
                source="verifier",
                event_type="VERIFIED",
                message="검증 완료",
                payload={"verifier": "file_read_verifier"},
                created_at=datetime(2026, 8, 24, tzinfo=timezone.utc),
            )
        ],
        created_at=datetime(2026, 8, 24, tzinfo=timezone.utc),
        completed_at=datetime(2026, 8, 24, tzinfo=timezone.utc),
    )


def fluent_query(response_data: list[dict], count: int | None = None) -> Mock:
    query = Mock()
    query.select.return_value = query
    query.eq.return_value = query
    query.limit.return_value = query
    query.order.return_value = query
    query.range.return_value = query
    query.delete.return_value = query
    query.upsert.return_value = query
    query.execute.return_value = SimpleNamespace(data=response_data, count=count)
    return query


def test_supabase_repository_upserts_run_and_events() -> None:
    client = Mock()
    runs_query = fluent_query([])
    events_query = fluent_query([])
    client.table.side_effect = lambda name: runs_query if name == "runs" else events_query
    repository = SupabaseRunRepository("https://example.supabase.co", "secret", client=client)

    repository.save(make_run())

    run_payload = runs_query.upsert.call_args.args[0]
    assert run_payload["run_id"] == "os-repository-test"
    assert "events" not in run_payload
    assert runs_query.upsert.call_args.kwargs["on_conflict"] == "run_id"
    event_payload = events_query.upsert.call_args.args[0]
    assert event_payload[0]["run_id"] == "os-repository-test"
    assert event_payload[0]["sequence"] == 1
    assert events_query.upsert.call_args.kwargs["on_conflict"] == "run_id,sequence"


def test_supabase_repository_rebuilds_run_with_ordered_events() -> None:
    run = make_run()
    client = Mock()
    runs_query = fluent_query([run.model_dump(mode="json", exclude={"events"})])
    events_query = fluent_query([run.events[0].model_dump(mode="json")])
    client.table.side_effect = lambda name: runs_query if name == "runs" else events_query
    repository = SupabaseRunRepository("https://example.supabase.co", "secret", client=client)

    restored = repository.get(run.run_id)

    assert restored is not None
    assert restored.run_id == run.run_id
    assert restored.events[0].event_type == "VERIFIED"
    events_query.order.assert_called_once_with("sequence")


def test_supabase_repository_lists_latest_runs_with_exact_count() -> None:
    run = make_run()
    client = Mock()
    runs_query = fluent_query(
        [run.model_dump(mode="json", exclude={"events"})],
        count=42,
    )
    client.table.return_value = runs_query
    repository = SupabaseRunRepository("https://example.supabase.co", "secret", client=client)

    items, total = repository.list_runs(page=2, page_size=20)

    assert items[0].run_id == run.run_id
    assert items[0].events == []
    assert total == 42
    runs_query.select.assert_called_once_with("*", count="exact")
    runs_query.order.assert_called_once_with("created_at", desc=True)
    runs_query.range.assert_called_once_with(20, 39)


def test_supabase_repository_restores_legacy_changed_variable() -> None:
    run = make_run()
    legacy_row = run.model_dump(mode="json", exclude={"events"})
    legacy_row["permission_id"] = "group_write"
    legacy_row["permission_enabled"] = True
    legacy_row["changed_variable"] = "UNIMPLEMENTED"
    client = Mock()
    runs_query = fluent_query([legacy_row], count=1)
    client.table.return_value = runs_query
    repository = SupabaseRunRepository("https://example.supabase.co", "secret", client=client)

    items, total = repository.list_runs(page=1, page_size=20)

    assert total == 1
    assert items[0].changed_variable == "group_write:ON"


def test_supabase_repository_deletes_only_the_selected_run() -> None:
    client = Mock()
    runs_query = fluent_query([{"run_id": "os-repository-test"}])
    client.table.return_value = runs_query
    repository = SupabaseRunRepository("https://example.supabase.co", "secret", client=client)

    deleted = repository.delete("os-repository-test")

    assert deleted is True
    runs_query.delete.assert_called_once_with()
    runs_query.eq.assert_called_once_with("run_id", "os-repository-test")
    runs_query.select.assert_called_once_with("run_id")


def test_repository_requires_complete_supabase_configuration() -> None:
    try:
        create_run_repository("https://example.supabase.co", None)
    except RuntimeError as error:
        assert "모두 설정" in str(error)
    else:
        raise AssertionError("부분 Supabase 설정은 거부해야 합니다.")
