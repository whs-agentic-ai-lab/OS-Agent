from __future__ import annotations

from threading import Lock
from typing import Protocol

from .models import HarnessRunRecord


class HarnessRunRepository(Protocol):
    def save(self, run: HarnessRunRecord) -> None: ...

    def get(self, run_id: str) -> HarnessRunRecord | None: ...


class InMemoryHarnessRunRepository:
    def __init__(self) -> None:
        self._runs: dict[str, HarnessRunRecord] = {}
        self._lock = Lock()

    def save(self, run: HarnessRunRecord) -> None:
        with self._lock:
            self._runs[run.run_id] = run.model_copy(deep=True)

    def get(self, run_id: str) -> HarnessRunRecord | None:
        with self._lock:
            run = self._runs.get(run_id)
            return run.model_copy(deep=True) if run is not None else None
