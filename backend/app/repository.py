from threading import Lock
from typing import Protocol

from supabase import Client, create_client

from .schemas import RunRecord


class RunRepository(Protocol):
    storage_name: str

    def save(self, run: RunRecord) -> None: ...

    def get(self, run_id: str) -> RunRecord | None: ...

    def list_runs(self, page: int, page_size: int) -> tuple[list[RunRecord], int]: ...

    def delete(self, run_id: str) -> bool: ...


class InMemoryRunRepository:
    """로컬 최소 테스트용 저장소. 프론트는 저장소에 직접 접근하지 않습니다."""

    storage_name = "memory"

    def __init__(self) -> None:
        self._items: dict[str, RunRecord] = {}
        self._lock = Lock()

    def save(self, run: RunRecord) -> None:
        with self._lock:
            self._items[run.run_id] = run.model_copy(deep=True)

    def get(self, run_id: str) -> RunRecord | None:
        with self._lock:
            item = self._items.get(run_id)
            return item.model_copy(deep=True) if item else None

    def list_runs(self, page: int, page_size: int) -> tuple[list[RunRecord], int]:
        with self._lock:
            ordered = sorted(
                self._items.values(),
                key=lambda item: item.created_at,
                reverse=True,
            )
            start = (page - 1) * page_size
            items = ordered[start : start + page_size]
            summaries = [
                item.model_copy(deep=True, update={"events": []}) for item in items
            ]
            return summaries, len(ordered)

    def delete(self, run_id: str) -> bool:
        with self._lock:
            return self._items.pop(run_id, None) is not None


class SupabaseRunRepository:
    """서버 전용 Secret Key로 runs와 run_events를 저장합니다."""

    storage_name = "supabase"

    def __init__(
        self,
        url: str,
        secret_key: str,
        client: Client | None = None,
    ) -> None:
        self._client = client or create_client(url, secret_key)

    def save(self, run: RunRecord) -> None:
        run_row = run.model_dump(mode="json", exclude={"events"})
        self._client.table("runs").upsert(
            run_row,
            on_conflict="run_id",
        ).execute()

        if run.events:
            event_rows = [
                {
                    "run_id": run.run_id,
                    **event.model_dump(mode="json"),
                }
                for event in run.events
            ]
            self._client.table("run_events").upsert(
                event_rows,
                on_conflict="run_id,sequence",
            ).execute()

    def get(self, run_id: str) -> RunRecord | None:
        run_response = (
            self._client.table("runs")
            .select("*")
            .eq("run_id", run_id)
            .limit(1)
            .execute()
        )
        if not run_response.data:
            return None

        event_response = (
            self._client.table("run_events")
            .select("sequence,source,event_type,message,payload,created_at")
            .eq("run_id", run_id)
            .order("sequence")
            .execute()
        )
        payload = dict(run_response.data[0])
        payload["events"] = event_response.data
        return RunRecord.model_validate(payload)

    def list_runs(self, page: int, page_size: int) -> tuple[list[RunRecord], int]:
        start = (page - 1) * page_size
        response = (
            self._client.table("runs")
            .select("*", count="exact")
            .order("created_at", desc=True)
            .range(start, start + page_size - 1)
            .execute()
        )
        items = [RunRecord.model_validate(row) for row in response.data]
        total = response.count if response.count is not None else len(items)
        return items, total

    def delete(self, run_id: str) -> bool:
        response = (
            self._client.table("runs")
            .delete()
            .eq("run_id", run_id)
            .select("run_id")
            .execute()
        )
        return bool(response.data)


def create_run_repository(
    supabase_url: str | None,
    supabase_secret_key: str | None,
) -> RunRepository:
    if bool(supabase_url) != bool(supabase_secret_key):
        raise RuntimeError(
            "SUPABASE_URL과 SUPABASE_SECRET_KEY(또는 SUPABASE_SERVICE_ROLE_KEY)를 모두 설정하세요."
        )
    if supabase_url and supabase_secret_key:
        return SupabaseRunRepository(supabase_url, supabase_secret_key)
    return InMemoryRunRepository()
