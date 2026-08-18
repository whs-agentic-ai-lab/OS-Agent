from threading import Lock

from .schemas import RunRecord


class InMemoryRunRepository:
    """로컬 최소 테스트용 저장소. 프론트는 저장소에 직접 접근하지 않습니다."""

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

