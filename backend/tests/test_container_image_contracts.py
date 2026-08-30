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


def test_host_bootstrap_waits_for_nat_data_path_before_apt() -> None:
    repository_root = Path(__file__).resolve().parents[2]
    bootstrap = (
        repository_root / "infra" / "terraform" / "user_data.sh.tpl"
    ).read_text(encoding="utf-8")

    assert "wait_for_https https://security.ubuntu.com/ubuntu/" in bootstrap
    assert "wait_for_https https://${aws_region}.ec2.archive.ubuntu.com/ubuntu/" in bootstrap
    assert bootstrap.count("APT::Update::Error-Mode=any") == 2


def test_vector_normalizer_is_packaged_outside_ec2_user_data() -> None:
    repository_root = Path(__file__).resolve().parents[2]
    dockerfile = (repository_root / "backend" / "Dockerfile").read_text(encoding="utf-8")
    deployment = (
        repository_root / "backend" / "app" / "deployment.py"
    ).read_text(encoding="utf-8")
    terraform = (
        repository_root / "infra" / "terraform" / "ec2.tf"
    ).read_text(encoding="utf-8")
    bootstrap = (
        repository_root / "infra" / "terraform" / "user_data.sh.tpl"
    ).read_text(encoding="utf-8")

    assert "COPY --from=terraform config/vector/normalize.vrl.tpl" in dockerfile
    assert '"--build-context", f"terraform={self.settings.terraform_dir}"' in deployment
    assert "normalize_vrl = templatefile" not in terraform
    assert "write_asset normalize_vrl" not in bootstrap
    assert (
        "docker cp os-agent-runtime-source:/app/bootstrap_assets/normalize.vrl.tpl "
        "/etc/vector/normalize.vrl"
    ) in bootstrap
    assert "s|$${environment_id}|${environment_id}|g" in bootstrap
    assert "s|$${topology_revision}|${topology_revision}|g" in bootstrap
