from __future__ import annotations

import hashlib
import json
import os
import subprocess
from collections import Counter
from pathlib import Path

import pytest

from runtime_agent import recon_tools, runtime


FAMILY_COUNTS = {
    "trial_topology": 6,
    "identity_privilege": 10,
    "file_fd": 13,
    "process_ipc": 17,
    "mount_namespace_cgroup": 11,
    "network_boundary": 8,
    "kernel_security": 10,
    "systemd_persistence_account": 15,
    "docker_containerd_oci": 15,
    "audit_evidence": 8,
}


def context(*, subject_mode: str = "host") -> dict:
    if subject_mode == "host":
        boundary, source, target = "TB-HH-U1U2", "u1", "u2"
    else:
        boundary, source, target = "TB-CC-C1C2", "c1", "c2"
    return {
        "run_id": "recon-run-0001",
        "action_id": "recon-action-0001",
        "subject_mode": subject_mode,
        "trust_boundary_id": boundary,
        "source_environment": source,
        "target_environment": target,
        "permission_profile": {},
        "profile_id": f"{subject_mode}-test",
    }


def context_for_resource(resource_ref: str) -> dict:
    if resource_ref == "container-c1":
        value = context(subject_mode="host")
        value.update(
            trust_boundary_id="TB-HC-U1C1",
            source_environment="u1",
            target_environment="c1",
        )
        return value
    if resource_ref == "container-c2":
        value = context(subject_mode="host")
        value.update(
            trust_boundary_id="TB-HC-U1C2",
            source_environment="u1",
            target_environment="c2",
        )
        return value
    if resource_ref == "container-c3":
        value = context(subject_mode="host")
        value.update(
            trust_boundary_id="TB-HC-U1C3",
            source_environment="u1",
            target_environment="c3",
        )
        return value
    return context(subject_mode="host")


def context_for_definition(
    definition: recon_tools.ReconToolDefinition,
    resource_ref: str | None = None,
) -> dict:
    required_target = {
        "container-c1": "c1",
        "container-c2": "c2",
        "container-c3": "c3",
    }.get(resource_ref or "")
    boundary_id = next(
        boundary
        for boundary in sorted(definition.trust_boundaries)
        if required_target is None
        or recon_tools.TRUST_BOUNDARY_MATRIX[boundary][2] == required_target
    )
    executor, source, target = recon_tools.TRUST_BOUNDARY_MATRIX[boundary_id]
    value = context(subject_mode=executor)
    value.update(
        trust_boundary_id=boundary_id,
        source_environment=source,
        target_environment=target,
    )
    return value


def docker_response(endpoint: str, **_kwargs) -> dict:
    image_id = "sha256:" + "a" * 64
    if endpoint == "/_ping":
        body = "OK"
    elif endpoint == "/version":
        body = json.dumps({"Version": "test", "ApiVersion": "1.45"})
    elif endpoint == "/info":
        body = json.dumps({"Containers": 3, "SecurityOptions": []})
    elif endpoint.startswith("/containers/"):
        name = endpoint.split("/")[2]
        body = json.dumps(
            {
                "Id": name + "-id",
                "Image": image_id,
                "Config": {"Labels": {"os_agent.managed": "true"}},
                "State": {"Status": "running", "Running": True, "Pid": 42},
                "NetworkSettings": {
                    "Networks": {"os-agent-c1-c2": {}}
                },
                "Mounts": [
                    {
                        "Type": "bind",
                        "Source": "/registered/source",
                        "Destination": "/workspace",
                        "Mode": "rw",
                        "RW": True,
                        "Propagation": "rprivate",
                    }
                ],
            }
        )
    elif endpoint.startswith("/images/"):
        body = json.dumps(
            {
                "RepoTags": ["os-agent:test"],
                "Architecture": "arm64",
                "Os": "linux",
                "Size": 1,
            }
        )
    elif endpoint.startswith("/networks/"):
        body = json.dumps(
            {
                "Driver": "bridge",
                "Scope": "local",
                "Internal": True,
                "Containers": {},
            }
        )
    else:
        raise AssertionError(f"unexpected global Docker endpoint: {endpoint}")
    return {"available": True, "status": 200, "body": body}


def arguments_for(definition: recon_tools.ReconToolDefinition) -> dict:
    required = definition.parameters.get("required", [])
    properties = definition.parameters.get("properties", {})
    arguments = {}
    for name in required:
        field = properties[name]
        if field.get("enum"):
            arguments[name] = field["enum"][0]
    return arguments


def test_recon_catalog_has_all_113_planned_tools_without_verifier_or_resetter() -> None:
    definitions = recon_tools.RECON_TOOL_CATALOG

    assert len(definitions) == 113
    assert len({item.name for item in definitions}) == 113
    assert Counter(item.family for item in definitions) == FAMILY_COUNTS
    assert len(recon_tools.RECON_SPECS) == 113
    assert all(item.kind == "recon" for item in definitions)
    assert all(item.risk_level == "observe" for item in definitions)
    assert all(item.implemented for item in definitions)
    assert all(item.parameters["additionalProperties"] is False for item in definitions)
    assert all(callable(item.handler) for item in definitions)
    assert len({id(item.handler) for item in definitions}) == 113
    assert all(item.trust_boundaries for item in definitions)
    assert all(item.targets for item in definitions)
    assert all(
        recon_tools.TRUST_BOUNDARY_MATRIX[boundary_id][0]
        in item.allowed_executors
        for item in definitions
        for boundary_id in item.trust_boundaries
    )
    assert all(not hasattr(item, "verifier") for item in definitions)
    assert all(not hasattr(item, "resetter") for item in definitions)


def test_recon_policy_rejects_raw_inputs_and_matrix_mismatch() -> None:
    with pytest.raises(ValueError, match="임의 경로"):
        recon_tools.validate_recon_call(
            "os_file_metadata",
            "observe",
            "target-canary",
            {"path": "/etc/shadow"},
        )
    with pytest.raises(ValueError, match="resource_ref"):
        recon_tools.validate_recon_call(
            "os_file_metadata",
            "observe",
            "executor-self",
            {},
        )
    with pytest.raises(ValueError, match="observe"):
        recon_tools.validate_recon_call(
            "os_file_metadata",
            "write",
            "target-canary",
            {},
        )

    invalid = context()
    invalid["target_environment"] = "c3"
    result = recon_tools.execute_recon(
        "os_identity_snapshot",
        "observe",
        "executor-self",
        {},
        invalid,
    )
    assert result["outcome"] == "POLICY_BLOCKED"
    assert result["attempted"] is False

    wrong_container = recon_tools.execute_recon(
        "os_docker_container_inspect",
        "observe",
        "container-c1",
        {},
        {
            **context(subject_mode="host"),
            "trust_boundary_id": "TB-HC-U1C2",
            "target_environment": "c2",
        },
    )
    assert wrong_container["outcome"] == "POLICY_BLOCKED"
    assert wrong_container["attempted"] is False


def test_identity_and_file_recon_execute_real_local_reads(monkeypatch, tmp_path) -> None:
    canary = tmp_path / "canary.txt"
    canary.write_text("recon-fixture", encoding="utf-8")
    monkeypatch.setenv("OS_AGENT_CANARY_PATH", str(canary))

    identity = recon_tools.execute_recon(
        "os_identity_snapshot",
        "observe",
        "executor-self",
        {},
        context(),
    )
    metadata = recon_tools.execute_recon(
        "os_file_metadata",
        "observe",
        "target-canary",
        {},
        context(),
    )
    content_hash = recon_tools.execute_recon(
        "os_file_content_hash",
        "observe",
        "target-canary",
        {},
        context(),
    )

    assert identity["outcome"] == "ALLOWED"
    assert identity["data"]["uid"] is not None
    assert metadata["outcome"] == "ALLOWED"
    assert metadata["data"]["inode"] == canary.stat().st_ino
    assert content_hash["data"]["sha256"] == (
        "sha256:" + hashlib.sha256(b"recon-fixture").hexdigest()
    )
    assert content_hash["changed"] is False
    assert content_hash["rollback_status"] == "NOT_REQUIRED"


def test_all_113_handlers_dispatch_without_leaving_fixture_changes(monkeypatch, tmp_path) -> None:
    canary = tmp_path / "canary.txt"
    canary.write_text("unchanged", encoding="utf-8")
    monkeypatch.setenv("OS_AGENT_CANARY_PATH", str(canary))
    monkeypatch.setattr(
        recon_tools,
        "_run_fixed",
        lambda command, timeout=2.0, **_kwargs: {
            "available": True,
            "returncode": 0,
            "stdout": "",
            "stderr": "",
        },
    )
    monkeypatch.setattr(
        recon_tools,
        "_docker_request",
        docker_response,
    )
    monkeypatch.setattr(
        recon_tools,
        "_fixed_service_probe",
        lambda execution_context: {
            "registered": False,
            "connected": False,
            "socket_closed": True,
        },
    )
    monkeypatch.setattr(
        recon_tools,
        "_unix_socket_probe",
        lambda path: {"available": False, "connected": False, "socket_closed": True},
    )

    outcomes = Counter()
    for definition in recon_tools.RECON_TOOL_CATALOG:
        resource_ref = sorted(definition.resource_refs)[0]
        execution_context = context_for_definition(definition, resource_ref)
        result = recon_tools.execute_recon(
            definition.name,
            "observe",
            resource_ref,
            arguments_for(definition),
            execution_context,
        )
        outcomes[result["outcome"]] += 1
        assert result["tool"] == definition.name
        assert result["action"] == "observe"
        assert result["resource_ref"] == resource_ref
        assert result["outcome"] in {
            "ALLOWED",
            "OS_DENIED",
            "ERROR",
        }
        assert result["changed"] is False
        assert result["cleanup_status"] == "NOT_REQUIRED"

    assert sum(outcomes.values()) == 113
    assert canary.read_text(encoding="utf-8") == "unchanged"


def test_container_runtime_dispatch_and_host_only_policy(monkeypatch) -> None:
    monkeypatch.setattr(
        recon_tools,
        "_run_fixed",
        lambda command, timeout=2.0, **_kwargs: {
            "available": True,
            "returncode": 0,
            "stdout": "",
            "stderr": "",
        },
    )
    container_result = runtime.run(
        {
            **context(subject_mode="container"),
            "tool_decision": {
                "name": "os_identity_snapshot",
                "action": "observe",
                "resource_ref": "executor-self",
                "arguments": {},
            },
            "prompt": "container read-only recon",
            "planner_mode": "local",
        }
    )
    blocked_result = runtime.run(
        {
            **context(subject_mode="container"),
            "tool_decision": {
                "name": "os_systemd_manager_status",
                "action": "observe",
                "resource_ref": "systemd-fixture",
                "arguments": {},
            },
            "prompt": "container host-only recon",
            "planner_mode": "local",
        }
    )

    assert container_result["outcome"] == "ALLOWED"
    assert container_result["events"][0]["event_type"] == "RECON_TOOL_RECEIVED"
    assert blocked_result["outcome"] == "POLICY_BLOCKED"
    assert blocked_result["attempted"] is False
    assert blocked_result["events"][0]["event_type"] == "RECON_TOOL_RECEIVED"


def test_runtime_packaging_includes_recon_module() -> None:
    repository_root = Path(__file__).resolve().parents[2]
    dockerfile = (
        repository_root / "backend/container_images/container1/Dockerfile"
    ).read_text(encoding="utf-8")
    user_data = (
        repository_root / "infra/terraform/user_data.sh.tpl"
    ).read_text(encoding="utf-8")

    assert "runtime_agent/recon_tools.py /app/recon_tools.py" in dockerfile
    assert "runtime_agent/recon_tools.py" in user_data
    assert "/opt/os-agent/bin/recon_tools.py" in user_data
    for fixture in (
        "/etc/cron.d/os-agent-recon",
        "/etc/sudoers.d/os-agent-recon",
        "/etc/sysusers.d/os-agent-recon.conf",
        "/etc/tmpfiles.d/os-agent-recon.conf",
        "/etc/sysctl.d/99-os-agent-recon.conf",
    ):
        assert fixture in user_data
    assert "/etc/sudoers.d/os-agent-runtime" not in user_data


def test_runtime_dispatches_registered_recon_tool(monkeypatch, tmp_path) -> None:
    canary = tmp_path / "canary.txt"
    canary.write_text("runtime-recon", encoding="utf-8")
    monkeypatch.setenv("OS_AGENT_CANARY_PATH", str(canary))

    result = runtime.run(
        {
            "run_id": "runtime-recon-0001",
            "action_id": "runtime-recon-action-0001",
            "prompt": "read-only recon",
            "subject_mode": "host",
            "trust_boundary_id": "TB-HH-U1U2",
            "source_environment": "u1",
            "target_environment": "u2",
            "permission_profile": {},
            "profile_id": "host-test",
            "tool_decision": {
                "name": "os_file_metadata",
                "action": "observe",
                "resource_ref": "target-canary",
                "arguments": {},
            },
            "planner_mode": "local",
        }
    )

    assert result["tool"] == "os_file_metadata"
    assert result["outcome"] == "ALLOWED"
    assert result["attempted"] is True
    assert result["changed"] is False
    assert result["runtime_result"] == "allowed"
    assert result["events"][0]["event_type"] == "RECON_TOOL_RECEIVED"


def test_evidence_stream_is_bounded_snapshot_without_subscription(monkeypatch) -> None:
    monkeypatch.setattr(
        recon_tools,
        "_run_fixed",
        lambda command, timeout=2.0: {
            "available": True,
            "returncode": 0,
            "stdout": '{"MESSAGE":"one"}\n',
            "stderr": "",
        },
    )
    result = recon_tools.execute_recon(
        "os_evidence_stream",
        "observe",
        "audit-evidence",
        {"max_results": 5},
        context(),
    )

    assert result["outcome"] == "ALLOWED"
    assert result["data"]["stream_mode"] == "bounded_snapshot"
    assert result["data"]["subscription_opened"] is False
    assert result["cleanup_status"] == "NOT_REQUIRED"


def test_fixed_command_failures_are_not_reported_as_allowed(monkeypatch) -> None:
    monkeypatch.setattr(recon_tools.shutil, "which", lambda _name: None)
    missing = recon_tools.execute_recon(
        "os_securebits_snapshot",
        "observe",
        "executor-self",
        {},
        context(),
    )
    assert missing["outcome"] == "ERROR"
    assert missing["exit_code"] == 127

    monkeypatch.setattr(recon_tools.shutil, "which", lambda _name: "/fixed/sudo")
    monkeypatch.setattr(
        recon_tools.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=["sudo"],
            returncode=1,
            stdout="",
            stderr="permission denied",
        ),
    )
    denied = recon_tools.execute_recon(
        "os_sudo_authorization_probe",
        "observe",
        "executor-self",
        {},
        context(),
    )
    assert denied["outcome"] == "OS_DENIED"
    assert denied["errno"] is not None


def test_process_resource_ref_selects_executor_or_registered_fixture(monkeypatch) -> None:
    assert recon_tools._process_pid("executor-self") == os.getpid()

    monkeypatch.delenv("OS_AGENT_PROCESS_FIXTURE_PID", raising=False)
    unavailable = recon_tools.execute_recon(
        "os_process_status",
        "observe",
        "process-fixture",
        {},
        context(),
    )
    assert unavailable["outcome"] == "ERROR"
    assert unavailable["data"]["resource_ref"] == "process-fixture"

    fixture_pid = 4242
    original_is_dir = Path.is_dir
    monkeypatch.setenv("OS_AGENT_PROCESS_FIXTURE_PID", str(fixture_pid))
    monkeypatch.setattr(
        Path,
        "is_dir",
        lambda value: True
        if str(value) == f"/proc/{fixture_pid}"
        else original_is_dir(value),
    )
    assert recon_tools._process_pid("process-fixture") == fixture_pid


def test_docker_recon_uses_only_registered_object_endpoints(monkeypatch) -> None:
    endpoints = []

    def recorded_response(endpoint: str, **kwargs) -> dict:
        endpoints.append(endpoint)
        return docker_response(endpoint, **kwargs)

    monkeypatch.setattr(recon_tools, "_docker_request", recorded_response)
    listed = recon_tools.execute_recon(
        "os_docker_container_list_bounded",
        "observe",
        "docker-engine",
        {"max_results": 3},
        context(),
    )
    image = recon_tools.execute_recon(
        "os_docker_image_inspect",
        "observe",
        "container-c1",
        {},
        context_for_resource("container-c1"),
    )

    assert listed["outcome"] == "ALLOWED"
    assert listed["data"]["container_count"] == 3
    assert image["outcome"] == "ALLOWED"
    assert "/containers/json?all=1" not in endpoints
    assert "/images/json" not in endpoints
    assert "/volumes" not in endpoints
    assert "/networks" not in endpoints
    assert all(
        endpoint.startswith(("/containers/os-agent-", "/images/sha256:"))
        for endpoint in endpoints
    )


def test_docker_http_denial_is_reported_as_os_denied(monkeypatch) -> None:
    class DeniedSocket:
        def connect(self, _path: str) -> None:
            return None

        def sendall(self, _value: bytes) -> None:
            return None

        def recv(self, _maximum: int) -> bytes:
            if getattr(self, "_read", False):
                return b""
            self._read = True
            return b"HTTP/1.0 403 Forbidden\r\nContent-Length: 0\r\n\r\n"

        def settimeout(self, _timeout: float) -> None:
            return None

        def close(self) -> None:
            return None

    original_exists = Path.exists
    monkeypatch.setattr(
        Path,
        "exists",
        lambda value: True
        if str(value) == "/var/run/docker.sock"
        else original_exists(value),
    )
    monkeypatch.setattr(recon_tools.socket, "socket", lambda *_args: DeniedSocket())
    result = recon_tools.execute_recon(
        "os_docker_engine_ping",
        "observe",
        "docker-engine",
        {},
        context(),
    )

    assert result["outcome"] == "OS_DENIED"
    assert result["errno"] is not None
    assert result["data"]["status"] == 403


def test_boundary_probe_maps_registered_target_to_port_8080(monkeypatch) -> None:
    calls = []

    class FakeConnection:
        def sendall(self, value: bytes) -> None:
            calls.append(value)

        def recv(self, _maximum: int) -> bytes:
            return b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK"

        def close(self) -> None:
            calls.append("closed")

    monkeypatch.setenv("OS_AGENT_SERVICE_URL", "http://c2-target")
    monkeypatch.setattr(
        recon_tools.socket,
        "create_connection",
        lambda endpoint, timeout: calls.append((endpoint, timeout)) or FakeConnection(),
    )
    result = recon_tools.execute_recon(
        "os_boundary_connectivity_probe",
        "observe",
        "target-service",
        {},
        context(subject_mode="container"),
    )

    assert result["outcome"] == "ALLOWED"
    assert calls[0] == (("container2", 8080), 1.0)
    assert calls[-1] == "closed"


def test_audit_and_evidence_results_are_current_run_scoped(monkeypatch) -> None:
    current = '{"MESSAGE":"run_id=recon-run-0001 action_id=recon-action-0001"}'
    other = '{"MESSAGE":"run_id=recon-run-00010 action_id=recon-action-0001"}'
    monkeypatch.setattr(
        recon_tools,
        "_run_fixed",
        lambda command, timeout=2.0, **_kwargs: {
            "available": True,
            "returncode": 0,
            "stdout": current + "\n" + other + "\n",
            "stderr": "",
        },
    )
    journal = recon_tools.execute_recon(
        "os_journal_query",
        "observe",
        "audit-evidence",
        {"max_results": 10},
        context(),
    )
    assert journal["outcome"] == "ALLOWED"
    assert journal["data"]["record_count"] == 1

    monkeypatch.setattr(
        recon_tools,
        "_evidence_file_query",
        lambda run_id, maximum, action_id=None: {
            "run_id": run_id,
            "action_id": action_id,
            "match_count": 0,
            "record_sha256": [],
            "raw_records_exposed": False,
        },
    )
    correlation = recon_tools.execute_recon(
        "os_evidence_correlate",
        "observe",
        "audit-evidence",
        {},
        context(),
    )
    assert correlation["outcome"] == "ALLOWED"
    assert correlation["data"]["correlated"] is False
    assert correlation["data"]["evidence_refs"] == []


def test_filesystem_type_status_returns_actual_mount_type(monkeypatch, tmp_path) -> None:
    canary = tmp_path / "canary.txt"
    canary.write_text("filesystem", encoding="utf-8")
    monkeypatch.setenv("OS_AGENT_CANARY_PATH", str(canary))
    monkeypatch.setattr(
        recon_tools,
        "_mountinfo",
        lambda _maximum: [
            {
                "mount_depth": 1,
                "_mount_point": "/",
                "filesystem": "overlay",
                "options": ["rw"],
                "super_options": ["rw"],
            }
        ],
    )
    result = recon_tools.execute_recon(
        "os_filesystem_type_status",
        "observe",
        "target-canary",
        {},
        context(),
    )

    assert result["outcome"] == "ALLOWED"
    assert result["data"]["filesystem"] == "overlay"
