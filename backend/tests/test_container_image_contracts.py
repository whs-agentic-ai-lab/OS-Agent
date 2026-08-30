"""Container image and Compose bootstrap contracts."""
from __future__ import annotations

from pathlib import Path


def test_target_healthchecks_do_not_depend_on_checkout_line_endings() -> None:
    """Windows CRLF checkouts must not turn the Python shebang into python3\\r."""
    repository_root = Path(__file__).resolve().parents[2]
    compose_template = (
        repository_root / "infra" / "terraform" / "experiment-compose.yml.tpl"
    ).read_text(encoding="utf-8")

    explicit_interpreter = 'test: ["CMD", "python3", "/app/healthcheck"]'
    assert compose_template.count(explicit_interpreter) == 3
    assert 'test: ["CMD", "/app/healthcheck"]' not in compose_template


def test_host_bootstrap_installs_tool_runtime_dependencies() -> None:
    repository_root = Path(__file__).resolve().parents[2]
    bootstrap = (
        repository_root / "infra" / "terraform" / "user_data.sh.tpl"
    ).read_text(encoding="utf-8")
    assert "  acl \\\n" in bootstrap
    assert "  libcap2-bin \\\n" in bootstrap
    assert "  pkexec \\\n" in bootstrap
