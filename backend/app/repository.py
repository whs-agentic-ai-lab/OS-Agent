import logging
from threading import Lock
from typing import Protocol

from supabase import Client, create_client

from .schemas import RunRecord, SubjectMode


RUN_TABLES = {
    SubjectMode.host: ("host_executor_runs", "host_executor_run_events"),
    SubjectMode.container: (
        "container_executor_runs",
        "container_executor_run_events",
    ),
}

logger = logging.getLogger(__name__)


class RunRepository(Protocol):
    storage_name: str

    def save(self, run: RunRecord) -> None: ...

    def get(self, run_id: str) -> RunRecord | None: ...

    def list_runs(
        self,
        subject_mode: SubjectMode,
        page: int,
        page_size: int,
    ) -> tuple[list[RunRecord], int]: ...

    def delete(self, run_id: str) -> bool: ...


class InMemoryRunRepository:
    """로컬 최소 테스트용 저장소. 프론트는 저장소에 직접 접근하지 않습니다."""

    storage_name = "memory"

    def __init__(self) -> None:
        self._items: dict[SubjectMode, dict[str, RunRecord]] = {
            SubjectMode.host: {},
            SubjectMode.container: {},
        }
        self._lock = Lock()

    def save(self, run: RunRecord) -> None:
        with self._lock:
            self._items[run.subject_mode][run.run_id] = run.model_copy(deep=True)

    def get(self, run_id: str) -> RunRecord | None:
        with self._lock:
            for lane in self._items.values():
                item = lane.get(run_id)
                if item is not None:
                    return item.model_copy(deep=True)
            return None

    def list_runs(
        self,
        subject_mode: SubjectMode,
        page: int,
        page_size: int,
    ) -> tuple[list[RunRecord], int]:
        with self._lock:
            ordered = sorted(
                self._items[subject_mode].values(),
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
            return any(lane.pop(run_id, None) is not None for lane in self._items.values())


class SupabaseRunRepository:
    """서버 전용 Secret Key로 Executor별 Run/Event 테이블을 분리 저장합니다."""

    storage_name = "supabase"

    def __init__(
        self,
        url: str,
        secret_key: str,
        client: Client | None = None,
    ) -> None:
        self._client = client or create_client(url, secret_key)

    def save(self, run: RunRecord) -> None:
        run_table, event_table = RUN_TABLES[run.subject_mode]
        run_row = run.model_dump(mode="json", exclude={"events"})
        self._client.table(run_table).upsert(
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
            self._client.table(event_table).upsert(
                event_rows,
                on_conflict="run_id,sequence",
            ).execute()

    def get(self, run_id: str) -> RunRecord | None:
        for run_table, event_table in RUN_TABLES.values():
            run_response = (
                self._client.table(run_table)
                .select("*")
                .eq("run_id", run_id)
                .limit(1)
                .execute()
            )
            if run_response.data:
                event_response = (
                    self._client.table(event_table)
                    .select("sequence,source,event_type,message,payload,created_at")
                    .eq("run_id", run_id)
                    .order("sequence")
                    .execute()
                )
                payload = dict(run_response.data[0])
                payload["events"] = event_response.data
                return RunRecord.model_validate(payload)
        return None

    def list_runs(
        self,
        subject_mode: SubjectMode,
        page: int,
        page_size: int,
    ) -> tuple[list[RunRecord], int]:
        start = (page - 1) * page_size
        run_table, _ = RUN_TABLES[subject_mode]
        response = (
            self._client.table(run_table)
            .select("*", count="exact")
            .order("created_at", desc=True)
            .range(start, start + page_size - 1)
            .execute()
        )
        items = [RunRecord.model_validate(row) for row in response.data]
        total = response.count if response.count is not None else len(items)
        return items, total

    def delete(self, run_id: str) -> bool:
        for run_table, _ in RUN_TABLES.values():
            response = (
                self._client.table(run_table)
                .delete()
                .eq("run_id", run_id)
                .select("run_id")
                .execute()
            )
            if response.data:
                return True
        return False


class ResilientRunRepository:
    """Supabase 장애가 실제 실험 응답까지 실패시키지 않게 로컬로 복원합니다."""

    def __init__(self, primary: RunRepository) -> None:
        self._primary = primary
        self._fallback = InMemoryRunRepository()
        self._degraded = False

    @property
    def storage_name(self) -> str:
        return "supabase+memory-fallback" if self._degraded else self._primary.storage_name

    def _mark_degraded(self, operation: str) -> None:
        self._degraded = True
        logger.exception(
            "Supabase %s 실패: 이번 프로세스의 로컬 메모리 저장소로 복원합니다.",
            operation,
        )

    def save(self, run: RunRecord) -> None:
        try:
            self._primary.save(run)
        except Exception:
            self._mark_degraded("save")
            self._fallback.save(run)

    def get(self, run_id: str) -> RunRecord | None:
        try:
            stored = self._primary.get(run_id)
            if stored is not None:
                return stored
        except Exception:
            self._mark_degraded("get")
        return self._fallback.get(run_id)

    def list_runs(
        self,
        subject_mode: SubjectMode,
        page: int,
        page_size: int,
    ) -> tuple[list[RunRecord], int]:
        if not self._degraded:
            try:
                return self._primary.list_runs(subject_mode, page, page_size)
            except Exception:
                self._mark_degraded("list")
        return self._fallback.list_runs(subject_mode, page, page_size)

    def delete(self, run_id: str) -> bool:
        deleted = self._fallback.delete(run_id)
        try:
            return self._primary.delete(run_id) or deleted
        except Exception:
            self._mark_degraded("delete")
            return deleted


def create_run_repository(
    supabase_url: str | None,
    supabase_secret_key: str | None,
) -> RunRepository:
    if bool(supabase_url) != bool(supabase_secret_key):
        raise RuntimeError(
            "SUPABASE_URL과 SUPABASE_SECRET_KEY(또는 SUPABASE_SERVICE_ROLE_KEY)를 모두 설정하세요."
        )
    if supabase_url and supabase_secret_key:
        return ResilientRunRepository(
            SupabaseRunRepository(supabase_url, supabase_secret_key)
        )
    return InMemoryRunRepository()
