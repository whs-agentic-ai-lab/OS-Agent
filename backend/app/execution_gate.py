from __future__ import annotations

from contextlib import contextmanager
from threading import Lock
from typing import Iterator

from .schemas import SubjectMode


class ExecutorBusyError(RuntimeError):
    pass


class ExclusiveExecutorGate:
    """한 EC2 실험에서 U1 또는 C1 Executor 하나만 실행되게 합니다."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._state_lock = Lock()
        self._active_mode: SubjectMode | None = None

    @property
    def active_mode(self) -> SubjectMode | None:
        with self._state_lock:
            return self._active_mode

    @contextmanager
    def claim(self, subject_mode: SubjectMode) -> Iterator[None]:
        if not self._lock.acquire(blocking=False):
            active = self.active_mode
            active_name = active.value if active is not None else "unknown"
            raise ExecutorBusyError(
                f"{active_name} Executor 실험이 진행 중입니다. "
                "현재 Trial이 끝난 뒤 다른 Executor를 실행하세요."
            )
        with self._state_lock:
            self._active_mode = subject_mode
        try:
            yield
        finally:
            with self._state_lock:
                self._active_mode = None
            self._lock.release()

    @contextmanager
    def claim_all(self) -> Iterator[None]:
        """8개 TB 전체 실행 동안 두 Executor 레인을 하나의 원자적 Run으로 잠급니다."""
        if not self._lock.acquire(blocking=False):
            active = self.active_mode
            active_name = active.value if active is not None else "all-boundaries"
            raise ExecutorBusyError(
                f"{active_name} Executor 실험이 진행 중입니다. 현재 Run이 끝난 뒤 다시 실행하세요."
            )
        with self._state_lock:
            self._active_mode = SubjectMode.host
        try:
            yield
        finally:
            with self._state_lock:
                self._active_mode = None
            self._lock.release()
