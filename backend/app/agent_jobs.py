from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from threading import Event, Lock
from typing import Callable

from .execution_gate import ExclusiveExecutorGate, ExecutorBusyError


logger = logging.getLogger(__name__)


class AgentRunJobManager:
    """8개 TB AgentRun 하나를 별도 worker에서 실행합니다.

    요청 스레드가 반환되기 전에 worker의 Executor gate 획득 여부까지만
    확인합니다. 실제 실험 시간에는 worker가 gate를 계속 보유합니다.
    """

    def __init__(self, executor_gate: ExclusiveExecutorGate) -> None:
        self._executor_gate = executor_gate
        self._executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="agent-run",
        )
        self._state_lock = Lock()
        self._active_run_id: str | None = None

    @property
    def active_run_id(self) -> str | None:
        with self._state_lock:
            return self._active_run_id

    def start(
        self,
        run_id: str,
        work: Callable[[], None],
        *,
        on_error: Callable[[Exception], None] | None = None,
    ) -> None:
        ready = Event()
        start_error: list[Exception] = []

        with self._state_lock:
            if self._active_run_id is not None:
                raise ExecutorBusyError(
                    f"{self._active_run_id} Agent 실험이 진행 중입니다. "
                    "현재 Run이 끝난 뒤 다시 실행하세요."
                )
            self._active_run_id = run_id

        def execute() -> None:
            try:
                with self._executor_gate.claim_all():
                    # POST는 실제 실행 레인을 확보한 뒤에만 성공 응답을 반환한다.
                    ready.set()
                    work()
            except ExecutorBusyError as exc:
                start_error.append(exc)
                ready.set()
            except Exception as exc:  # pragma: no cover - 최종 안전망
                logger.exception("AgentRun background worker 실패: %s", run_id)
                if on_error is not None:
                    try:
                        on_error(exc)
                    except Exception:
                        logger.exception("AgentRun 실패 상태 저장 실패: %s", run_id)
            finally:
                ready.set()
                with self._state_lock:
                    if self._active_run_id == run_id:
                        self._active_run_id = None

        try:
            self._executor.submit(execute)
        except Exception:
            with self._state_lock:
                if self._active_run_id == run_id:
                    self._active_run_id = None
            raise

        if not ready.wait(timeout=5):
            raise RuntimeError("AgentRun worker가 실행 레인을 확보하지 못했습니다.")
        if start_error:
            raise start_error[0]

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=False)
