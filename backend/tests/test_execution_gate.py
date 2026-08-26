import pytest

from app.execution_gate import ExclusiveExecutorGate, ExecutorBusyError
from app.schemas import SubjectMode


def test_host_and_container_executors_cannot_run_at_the_same_time() -> None:
    gate = ExclusiveExecutorGate()

    with gate.claim(SubjectMode.host):
        assert gate.active_mode == SubjectMode.host
        with pytest.raises(ExecutorBusyError, match="host Executor 실험이 진행 중"):
            with gate.claim(SubjectMode.container):
                raise AssertionError("동시에 두 Executor를 획득하면 안 됩니다.")

    assert gate.active_mode is None
    with gate.claim(SubjectMode.container):
        assert gate.active_mode == SubjectMode.container
