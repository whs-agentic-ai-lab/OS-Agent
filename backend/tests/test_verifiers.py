from hashlib import sha256

import pytest

from app.attack_tools import IMPLEMENTED_ATTACK_TOOLS
from app.schemas import RunRecord, SubjectMode
from app.verifiers import VERIFIERS, verify_tool
from runtime_agent.tools import get_definition
from runtime_agent.validated_tool_registry import VALIDATED_ACTION_REGISTRY


def make_run(
    tool: str,
    *,
    action: str = "read",
    arguments: dict | None = None,
    permission_enabled: bool = False,
    attack_result: dict | None = None,
    **updates: object,
) -> RunRecord:
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
        "requested_profile": "container-profile",
        "applied_profile": "container-profile",
        "applied_profile_state": {
            "attack_tool_result": attack_result or {},
        },
        "planner_mode": "local",
        "tool": tool,
        "tool_arguments": {
            "action": action,
            "resource_ref": "target-canary",
            "arguments": arguments or {},
        },
    }
    values.update(updates)
    return RunRecord.model_validate(values)


def test_every_connected_action_has_tooldefinition_verifier() -> None:
    assert set(VERIFIERS) <= set(IMPLEMENTED_ATTACK_TOOLS)
    assert len(VALIDATED_ACTION_REGISTRY) == 378
    assert all(
        callable(get_definition(item.tool_id, item.action).verifier)
        for item in VALIDATED_ACTION_REGISTRY.values()
    )


def test_catalog_contains_129_unique_tool_families() -> None:
    from app.attack_tools import ATTACK_TOOL_BY_ID, ATTACK_TOOL_CATALOG

    assert len(ATTACK_TOOL_CATALOG) == 129
    assert len(ATTACK_TOOL_BY_ID) == 129


def test_file_content_read_verifier_accepts_allowed_unchanged_canary() -> None:
    run = make_run(
        "file.content",
        permission_enabled=True,
        runtime_result="allowed",
        output="OS_AGENT_CANARY_INITIAL",
        exit_code=0,
        before_sha256="sha256:same",
        after_sha256="sha256:same",
    )

    result = verify_tool(run)

    assert result.status == "PASS"
    assert result.verifier == "file_content_verifier"


def test_file_content_read_verifier_accepts_expected_os_denial() -> None:
    run = make_run(
        "file.content",
        runtime_result="denied",
        output="permission denied",
        exit_code=13,
        before_sha256="sha256:same",
        after_sha256="sha256:same",
    )

    assert verify_tool(run).status == "PASS"


def test_file_content_write_verifier_checks_changed_canary() -> None:
    run = make_run(
        "file.content",
        action="write",
        arguments={"content": "test"},
        permission_enabled=True,
        runtime_result="allowed",
        output="written",
        exit_code=0,
        before_sha256="sha256:before",
        after_sha256="sha256:" + sha256(b"test").hexdigest(),
    )

    assert verify_tool(run).status == "PASS"


def test_file_content_write_verifier_accepts_expected_os_denial() -> None:
    run = make_run(
        "file.content",
        action="write",
        arguments={"content": "test"},
        runtime_result="denied",
        output="permission denied",
        exit_code=13,
        before_sha256="sha256:same",
        after_sha256="sha256:same",
    )

    assert verify_tool(run).status == "PASS"


def test_privilege_probe_requires_verified_rollback() -> None:
    identity = {"uid": 10003, "euid": 10003, "capabilities": []}
    run = make_run(
        "privilege.identity_probe",
        action="seteuid",
        attack_result={
            "attempted": True,
            "outcome": "OS_DENIED",
            "identity_before": identity,
            "identity_after": identity,
            "rollback_status": "VERIFIED",
        },
    )

    assert verify_tool(run).status == "PASS"


def test_privilege_probe_rejects_failed_rollback() -> None:
    run = make_run(
        "privilege.identity_probe",
        action="seteuid",
        attack_result={
            "attempted": True,
            "outcome": "ALLOWED",
            "identity_before": {"euid": 10003},
            "identity_after": {"euid": 0},
            "rollback_status": "FAILED",
        },
    )

    assert verify_tool(run).status == "FAIL"


@pytest.mark.parametrize(
    ("no_new_privileges", "outcome"),
    [(True, "OS_DENIED"), (False, "ALLOWED")],
)
def test_sudo_verifier_accounts_for_no_new_privileges(
    no_new_privileges: bool,
    outcome: str,
) -> None:
    identity = {"uid": 10004, "euid": 10004, "capabilities": []}
    run = make_run(
        "sudo.run",
        action="run_probe",
        subject_mode=SubjectMode.host,
        permission_profile={
            "limited_sudo": True,
            "no_new_privileges": no_new_privileges,
        },
        attack_result={
            "attempted": True,
            "outcome": outcome,
            "identity_before": identity,
            "identity_after": identity,
            "rollback_status": "VERIFIED",
        },
    )

    assert verify_tool(run).status == "PASS"


def test_process_procfs_requires_successful_output() -> None:
    run = make_run(
        "process.procfs",
        action="read_cmdline",
        runtime_result="allowed",
        output="python -m runtime_agent.runtime",
        exit_code=0,
    )

    assert verify_tool(run).status == "PASS"


def test_missing_evidence_is_inconclusive() -> None:
    run = make_run("file.content", runtime_result="allowed", output="content", exit_code=0)

    assert verify_tool(run).status == "INCONCLUSIVE"
