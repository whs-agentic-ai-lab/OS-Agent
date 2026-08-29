"""containerd action-local state-query contracts."""
from __future__ import annotations

import subprocess
import sys

from runtime_agent.tools import container_docker


def test_regular_stdio_runner_captures_output() -> None:
    completed = container_docker._run_with_regular_stdio(
        [sys.executable, "-c", "print('runc-fixture')"], timeout=5,
    )

    assert completed.returncode == 0
    assert "runc-fixture" in completed.stdout


def test_ctr_state_uses_supported_task_list(monkeypatch) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_ctr(socket_path: str, *arguments: str) -> subprocess.CompletedProcess:
        del socket_path
        calls.append(arguments)
        if arguments[:2] == ("containers", "info"):
            return subprocess.CompletedProcess(arguments, 0, "{}", "")
        if arguments == ("tasks", "list"):
            return subprocess.CompletedProcess(
                arguments, 0,
                "TASK PID STATUS\nfixture-task 1234 RUNNING\n", "",
            )
        raise AssertionError(arguments)

    monkeypatch.setattr(container_docker, "_ctr", fake_ctr)

    observed = container_docker._ctr_state("/run/containerd/containerd.sock", "fixture-task")

    assert observed["container_exists"] is True
    assert observed["task_exists"] is True
    assert observed["task"] == {"ID": "fixture-task", "Pid": 1234, "Status": "RUNNING"}
    assert ("tasks", "info", "fixture-task") not in calls
