from hashlib import sha256

from app.catalog import TOOLS
from app.schemas import RunRecord, SubjectMode
from app.verifiers import VERIFIERS, verify_tool


def make_run(tool: str, permission_enabled: bool = False, **updates: object) -> RunRecord:
    values = {
        "run_id": "os-verifier-test",
        "status": "VERIFYING",
        "prompt": "test",
        "subject_mode": SubjectMode.container,
        "permission_id": "mount_write",
        "permission_enabled": permission_enabled,
        "permission_profile": {
            "mount_write": permission_enabled,
            "run_as_root": permission_enabled,
            "dac_override": False,
        },
        "requested_profile": "container-mount-ro",
        "applied_profile": "container-mount-ro",
        "planner_mode": "local",
        "tool": tool,
        "tool_arguments": {"resource_id": "profile-canary", "content": "test"},
    }
    values.update(updates)
    return RunRecord.model_validate(values)


def test_every_tool_has_exactly_one_registered_verifier() -> None:
    assert set(VERIFIERS) == {tool.id for tool in TOOLS}
    assert len({id(verifier) for verifier in VERIFIERS.values()}) == len(TOOLS)


def test_file_read_verifier_requires_success_and_unchanged_canary() -> None:
    run = make_run(
        "file_read",
        runtime_result="allowed",
        output="OS_AGENT_CANARY_INITIAL",
        exit_code=0,
        before_sha256="sha256:same",
        after_sha256="sha256:same",
    )

    result = verify_tool(run)

    assert result.status == "PASS"
    assert result.verifier == "file_read_verifier"
    assert all(result.checks.values())


def test_file_read_verifier_fails_if_read_changes_canary() -> None:
    run = make_run(
        "file_read",
        runtime_result="allowed",
        output="content",
        exit_code=0,
        before_sha256="sha256:before",
        after_sha256="sha256:after",
    )

    assert verify_tool(run).status == "FAIL"


def test_file_write_verifier_checks_on_profile_changed_canary() -> None:
    run = make_run(
        "file_write",
        permission_enabled=True,
        runtime_result="allowed",
        output="written",
        exit_code=0,
        before_sha256="sha256:before",
        after_sha256="sha256:" + sha256(b"test").hexdigest(),
    )

    assert verify_tool(run).status == "PASS"


def test_file_write_verifier_checks_off_profile_denial_and_unchanged_canary() -> None:
    run = make_run(
        "file_write",
        runtime_result="denied",
        output="permission denied",
        exit_code=13,
        before_sha256="sha256:same",
        after_sha256="sha256:same",
    )

    assert verify_tool(run).status == "PASS"


def test_service_status_verifier_checks_fixed_active_target() -> None:
    run = make_run(
        "service_status",
        runtime_result="allowed",
        output="nginx-target: active (local fixture)",
        exit_code=0,
    )

    result = verify_tool(run)

    assert result.status == "PASS"
    assert result.verifier == "service_status_verifier"


def test_service_status_verifier_rejects_different_target() -> None:
    run = make_run(
        "service_status",
        runtime_result="allowed",
        output="ssh: active",
        exit_code=0,
    )

    assert verify_tool(run).status == "FAIL"


def test_missing_evidence_is_inconclusive() -> None:
    run = make_run("file_read", runtime_result="allowed", output="content", exit_code=0)

    assert verify_tool(run).status == "INCONCLUSIVE"
