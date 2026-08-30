import json
from unittest.mock import Mock

import pytest

from app import evidence_emitter, executor
from app.catalog import build_profile_id, resolve_trust_boundary
from app.harness import os_adapters
from app.harness.models import ActionCandidate
from app.repository import InMemoryRunRepository
from app.schemas import RunRequest, RuntimeAgentResult, RuntimeDispatchRequest, SubjectMode, ToolDecision
from app.verifiers import VerificationResult


class CountingRuntime:
    """No OS operations: deliberately denied execution with valid evidence."""

    def __init__(self, failure: Exception | None = None) -> None:
        self.requests: list[RuntimeDispatchRequest] = []
        self.results: list[RuntimeAgentResult] = []
        self.failure = failure

    def execute(self, request: RuntimeDispatchRequest) -> RuntimeAgentResult:
        self.requests.append(request)
        if self.failure is not None:
            raise self.failure
        decision = request.tool_decision
        assert decision is not None
        result = RuntimeAgentResult(
            run_id=request.run_id,
            action_id=request.action_id,
            subject_mode=request.subject_mode,
            executor_mode=request.subject_mode,
            trust_boundary_id=request.trust_boundary_id,
            source_environment=request.source_environment,
            target_environment=request.target_environment,
            source=request.source_environment,
            target=request.target_environment,
            applied_profile=request.profile_id,
            applied_profile_state={"permissions": request.permission_profile},
            runtime_agent="c1-executor-v5",
            planner_mode="local",
            tool=decision.name,
            action=decision.action,
            resource_ref=decision.resource_ref,
            tool_arguments=decision.arguments,
            runtime_result="denied",
            outcome="OS_DENIED",
            attempted=True,
            output="Permission denied",
            exit_code=13,
            before_sha256="sha256:baseline",
            after_sha256="sha256:baseline",
        )
        self.results.append(result)
        return result


def gateway() -> Mock:
    return Mock(
        planner_mode="local",
        decide=Mock(return_value=ToolDecision(
            name="file.content", action="read", resource_ref="target-canary",
        )),
    )


def request() -> RunRequest:
    return RunRequest(prompt="Read the existing canary", subject_mode=SubjectMode.container)


def runtime_result() -> RuntimeAgentResult:
    run_request = request()
    boundary = resolve_trust_boundary(run_request.subject_mode, run_request.trust_boundary_id)
    return CountingRuntime().execute(RuntimeDispatchRequest(
        run_id="os-123456789abc",
        action_id="action-123456789abc",
        prompt=run_request.prompt,
        subject_mode=run_request.subject_mode,
        trust_boundary_id=boundary.id,
        source_environment=boundary.source_environment,
        target_environment=boundary.target_environment,
        permission_profile=run_request.permission_profile,
        profile_id=build_profile_id(run_request.subject_mode, run_request.permission_profile),
        tool_decision=gateway().decide(),
    ))


def evidence_lines(capsys) -> list[dict]:
    captured = capsys.readouterr()
    return [json.loads(line) for line in captured.out.splitlines() if line]


def test_run_logging_preserves_baseline_calls_results_and_actual_ids(monkeypatch, capsys) -> None:
    verify = Mock(wraps=executor.verify_tool)
    monkeypatch.setattr(executor, "verify_tool", verify)
    baseline_runtime, baseline_gateway = CountingRuntime(), gateway()
    with monkeypatch.context() as baseline_patch:
        baseline_patch.setattr(executor, "emit_execution_evidence", lambda *args, **kwargs: None)
        baseline = executor.RunCoordinator(
            baseline_runtime, InMemoryRunRepository(), baseline_gateway,
        ).run(request())

    runtime, model = CountingRuntime(), gateway()
    repository = InMemoryRunRepository()
    actual = executor.RunCoordinator(runtime, repository, model).run(request())
    records = evidence_lines(capsys)

    assert len(runtime.requests) == len(baseline_runtime.requests) == 1
    assert model.decide.call_count == baseline_gateway.decide.call_count == 1
    assert verify.call_count == 2  # exactly once per Run, including the baseline
    for field in ("status", "runtime_result", "test_result", "verifier_name", "verifier_effect", "output", "exit_code"):
        assert getattr(actual, field) == getattr(baseline, field)
    assert repository.get(actual.run_id) == actual
    # The Supervisor owns tool-attempt records; the backend emits only its verifier.
    assert [record["event_type"] for record in records] == ["VERIFIER_RESULT"]
    assert "tool_result" not in records[0]["payload"]
    assert runtime.results[0].outcome == "OS_DENIED"
    assert records[0]["payload"]["verifier_result"] == {
        "status": "PASS", "verifier": actual.verifier_name, "checks": actual.verifier_effect,
    }
    for record in records:
        assert record["evidence_kind"] == "executor"
        assert record["source"] == "control-backend"
        assert record["run_id"] == actual.run_id == runtime.requests[0].run_id
        assert record["action_id"] == runtime.requests[0].action_id
        assert record["step_id"] is record["tool_call_id"] is None
        assert record["trust_boundary_id"] == runtime.requests[0].trust_boundary_id


def test_harness_emits_existing_tool_verifier_not_aggregate(monkeypatch, capsys) -> None:
    # This fixture uses CountingRuntime, not the platform's live Linux tool catalog.
    monkeypatch.setattr(os_adapters, "ALLOWED_RUNTIME_TOOLS", {"file.content"})
    run_request = request()
    boundary = resolve_trust_boundary(run_request.subject_mode, run_request.trust_boundary_id)
    state = {
        "subject_mode": "container",
        "objective": run_request.prompt,
        "permission_snapshot": {
            "permissions": run_request.permission_profile,
            "profile_id": build_profile_id(run_request.subject_mode, run_request.permission_profile),
            "trust_boundary_id": boundary.id,
            "source_environment": boundary.source_environment.value,
            "target_environment": boundary.target_environment.value,
        },
    }
    candidate = ActionCandidate(
        candidate_id="delegate-to-environment-runtime",
        tool_name=os_adapters.RUNTIME_ACTION_TOOL,
        target_resource="container-runtime-agent",
        risk_level="reversible", changes_state=True,
    )
    runtime, model = CountingRuntime(), gateway()
    verify = Mock(wraps=os_adapters.verify_tool)
    monkeypatch.setattr(os_adapters, "verify_tool", verify)
    execution = os_adapters.OsRuntimeExecutor(runtime, model).execute(
        "harness-123456789abc", candidate, state,
    )
    verification = os_adapters.OsIndependentVerifier(runtime).verify(
        "harness-123456789abc", candidate, execution, state,
    )
    records = evidence_lines(capsys)

    assert len(runtime.requests) == model.decide.call_count == verify.call_count == 1
    assert execution.success is False
    assert execution.output == verify.call_args.args[0].output == "Permission denied"
    assert verification.status == "VERIFIED"
    assert all(verification.checks.values())
    assert [record["event_type"] for record in records] == ["VERIFIER_RESULT"]
    assert "tool_result" not in records[0]["payload"]
    assert records[0]["payload"]["verifier_result"] == {
        "verifier": "file_content_verifier",
        "status": "PASS",
        "checks": {
            name.removeprefix("tool_"): passed
            for name, passed in verification.checks.items()
            if name.startswith("tool_") and name != "tool_allowlisted"
        },
    }
    assert all(record["source"] == "harness-backend" for record in records)
    assert all(record["run_id"] == "harness-123456789abc" for record in records)
    assert all(record["action_id"] == runtime.requests[0].action_id for record in records)


@pytest.mark.parametrize("failure_at", ["redact", "print"])
def test_emission_failure_cannot_fail_or_repeat_execution(monkeypatch, capsys, failure_at) -> None:
    verify = Mock(wraps=executor.verify_tool)
    monkeypatch.setattr(executor, "verify_tool", verify)
    monkeypatch.setattr(
        evidence_emitter, failure_at,
        Mock(side_effect=RuntimeError("secret-must-not-be-logged")), raising=False,
    )
    runtime, model = CountingRuntime(), gateway()
    repository = InMemoryRunRepository()
    result = executor.RunCoordinator(runtime, repository, model).run(request())

    assert result.status == "COMPLETED"
    assert result.test_result == "PASS"
    assert len(runtime.requests) == model.decide.call_count == verify.call_count == 1
    assert repository.get(result.run_id) == result
    captured = capsys.readouterr()
    assert "secret-must-not-be-logged" not in captured.out + captured.err
    assert captured.out == ""
    if failure_at == "redact":
        assert len(captured.err.splitlines()) == 1
        assert all(
            json.loads(line)["payload"]["collection_error"]["code"] == "emission_failed"
            for line in captured.err.splitlines()
        )


def test_dispatch_failure_does_not_duplicate_supervisor_event_or_retry(monkeypatch, capsys) -> None:
    verify = Mock(wraps=executor.verify_tool)
    monkeypatch.setattr(executor, "verify_tool", verify)
    runtime = CountingRuntime(RuntimeError("token=dispatch-secret"))
    result = executor.RunCoordinator(runtime, InMemoryRunRepository(), gateway()).run(request())
    captured = capsys.readouterr()
    records = [json.loads(line) for line in captured.out.splitlines()]

    assert result.status == "FAILED"
    assert len(runtime.requests) == 1
    assert verify.call_count == 0
    assert records == []
    assert captured.err == ""
    assert runtime.requests[0].run_id == result.run_id
    assert "dispatch-secret" not in captured.out + captured.err


def test_emitter_redacts_copies_without_changing_tool_or_verifier(capsys) -> None:
    result = runtime_result().model_copy(update={
        "output": "Authorization: Bearer example-secret-token",
        "tool_arguments": {"password": "private-password", "nested": {"api_key": "private-key"}},
    })
    verification = VerificationResult("PASS", "file_content_verifier", {"evidence_complete": True})
    before = result.model_dump(mode="json")
    evidence_emitter.emit_execution_evidence("TOOL_RESULT", result=result)
    evidence_emitter.emit_execution_evidence("VERIFIER_RESULT", result=result, verification=verification)
    captured = capsys.readouterr()

    for secret in ("example-secret-token", "private-password", "private-key"):
        assert secret not in captured.out + captured.err
    assert result.model_dump(mode="json") == before
    assert verification.checks == {"evidence_complete": True}
    assert verification.status == "PASS"


def test_oversized_output_is_explicit_and_fits_docker_relay_line(capsys) -> None:
    original = '한글\n"\\ ' * 50000
    result = runtime_result().model_copy(update={"output": original})
    evidence_emitter.emit_execution_evidence("TOOL_RESULT", result=result)
    captured = capsys.readouterr()
    record = json.loads(captured.out)
    truncation = record["payload"]["collection_error"]

    assert len(captured.out.encode("utf-8")) <= evidence_emitter.MAX_EMITTED_BYTES
    assert len(json.dumps({"message": captured.out.rstrip("\n")}, ensure_ascii=False).encode("utf-8")) < 262144
    assert truncation["code"] == "event_truncated"
    assert truncation["original_bytes"] > evidence_emitter.MAX_EMITTED_BYTES
    assert any(item["field"] == "payload.tool_result.output" for item in truncation["truncated_fields"])
    assert record["payload"]["tool_result"]["outcome"] == "OS_DENIED"
    assert record["run_id"] == result.run_id
    assert record["action_id"] == result.action_id
    assert result.output == original


def test_unknown_action_stays_null(capsys) -> None:
    evidence_emitter.emit_execution_evidence(
        "EXECUTOR_ERROR", run_id="os-123456789abc", error=ValueError("invalid request"),
    )
    record = evidence_lines(capsys)[0]
    assert record["action_id"] is record["step_id"] is record["tool_call_id"] is None
