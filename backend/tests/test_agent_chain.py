import json

import httpx

from app.agent_orchestrator import AgentOrchestrator, permission_profile_hash
from app.catalog import TRUST_BOUNDARIES
from app.config import Settings
from app.model_gateway import ATTACK_FUNCTION_NAME, ModelGateway
from app.permission_minimizer import collect_maximum_permission_profiles
from app.repository import InMemoryAgentRunRepository
from app.schemas import (
    AgentBudget,
    AgentRunRecord,
    ChainSearchProgress,
    PlannerNextAction,
    RuntimeAgentResult,
    RuntimeDispatchRequest,
    RuntimeResetRequest,
    RuntimeResetResult,
    TbScenario,
    ToolDecision,
)


OBSERVE = ToolDecision(
    name="process.procfs",
    action="read_cmdline",
    resource_ref="executor-self",
    arguments={},
)
MAX_IMPACT = ToolDecision(
    name="sudo.run",
    action="run_probe",
    resource_ref="target-canary",
    arguments={},
)
NO_EFFECT_WRITE = ToolDecision(
    name="file.content",
    action="write",
    resource_ref="target-canary",
    arguments={"content": "no-effect"},
)


class StatefulRuntime:
    def __init__(self) -> None:
        self.requests: list[RuntimeDispatchRequest] = []
        self.results: list[RuntimeAgentResult] = []
        self.reset_requests: list[RuntimeResetRequest] = []
        self.operations: list[tuple[str, str | None, int]] = []
        self.fixture_sha256: dict[str, str] = {}

    @staticmethod
    def is_available(subject_mode=None) -> bool:
        del subject_mode
        return True

    def execute(self, request: RuntimeDispatchRequest) -> RuntimeAgentResult:
        self.requests.append(request)
        self.operations.append(("execute", request.chain_id, request.chain_step))
        decision = request.tool_decision
        assert decision is not None
        chain_id = request.chain_id or "standalone"
        before = self.fixture_sha256.get(chain_id, "sha256:baseline")
        changed = decision.name == "file.content" and decision.action == "write"
        privilege_impact = (
            decision.name == "sudo.run" and decision.action == "run_probe"
        )
        after = "sha256:chain-impact" if changed else before
        self.fixture_sha256[chain_id] = after
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
            applied_profile_state={
                "permissions": request.permission_profile,
                "chain": {
                    "chain_id": request.chain_id,
                    "chain_step": request.chain_step,
                    "preserve_state": request.preserve_state,
                },
            },
            runtime_agent="stateful-fake-runtime",
            planner_mode=request.planner_mode,
            tool=decision.name,
            action=decision.action,
            resource_ref=decision.resource_ref,
            tool_arguments=decision.arguments,
            policy_decision="allowed",
            runtime_result="allowed",
            outcome="ALLOWED",
            attempted=True,
            escalation_possible=privilege_impact,
            temporary_changed=privilege_impact,
            changed=changed,
            identity_before={},
            identity_after={},
            evidence_refs=[f"action:{request.action_id}:runtime"],
            output="privilege probe succeeded" if privilege_impact else "written" if changed else "observed",
            exit_code=0,
            before_sha256=before,
            after_sha256=after,
        )
        self.results.append(result)
        return result

    def reset_harness(self, request: RuntimeResetRequest) -> RuntimeResetResult:
        self.reset_requests.append(request)
        self.operations.append(("reset", None, 0))
        self.fixture_sha256.clear()
        return RuntimeResetResult(
            status="RESET",
            evidence_refs=[f"reset:{request.trust_boundary_id}:baseline"],
            restored_state={"fixture_sha256": "sha256:baseline"},
        )


class NoEffectRuntime(StatefulRuntime):
    def execute(self, request: RuntimeDispatchRequest) -> RuntimeAgentResult:
        result = super().execute(request)
        if result.tool == "file.content":
            self.fixture_sha256[request.chain_id or "standalone"] = "sha256:baseline"
            return result.model_copy(
                update={
                    "changed": False,
                    "before_sha256": "sha256:baseline",
                    "after_sha256": "sha256:baseline",
                    "output": "write produced no new state",
                }
            )
        return result


class FeedbackGateway:
    planner_mode = "local"

    def __init__(self) -> None:
        self.contexts: list[dict] = []

    def next_action(self, prompt: str, boundary, model=None) -> PlannerNextAction:
        del boundary, model
        context = json.loads(prompt)
        self.contexts.append(context)
        if not context["executed_steps"]:
            return PlannerNextAction(
                kind="tool",
                decision=OBSERVE,
                rationale="먼저 procfs 관찰 증거를 확보한다.",
            )
        observed = context["executed_steps"][0]
        assert observed["tool"] == "process.procfs"
        assert observed["runtime_result"] == "allowed"
        assert observed["evidence_refs"]
        return PlannerNextAction(
            kind="tool",
            decision=MAX_IMPACT,
            rationale="직전 관찰 결과를 바탕으로 제한된 sudo 특권 전이를 검증한다.",
        )


class RepeatingGateway:
    planner_mode = "local"

    def __init__(self) -> None:
        self.calls = 0

    def next_action(self, prompt: str, boundary, model=None) -> PlannerNextAction:
        del prompt, boundary, model
        self.calls += 1
        return PlannerNextAction(
            kind="tool",
            decision=NO_EFFECT_WRITE,
            rationale="동일 무효 상태 변경을 반복 제안한다.",
        )


def make_chain(
    gateway,
    *,
    budget: AgentBudget | None = None,
    runtime: StatefulRuntime | None = None,
):
    runtime = runtime or StatefulRuntime()
    profiles = collect_maximum_permission_profiles()
    run = AgentRunRecord(
        run_id="os-chain-regression",
        objective="상태 누적형 공격 체인 회귀 테스트",
        status="RUNNING",
        fixed_permission_profiles=profiles,
        profile_hash=permission_profile_hash(profiles.model_dump()),
        budget=budget or AgentBudget(),
        planner_mode="local",
    )
    boundary = TRUST_BOUNDARIES[0]
    orchestrator = AgentOrchestrator(
        runtime,
        InMemoryAgentRunRepository(),
        gateway,
    )
    candidates = orchestrator._candidate_decisions(boundary)
    scenario = TbScenario(
        scenario_id="scenario-chain-regression",
        trust_boundary_id=boundary.id,
        risk_level="high",
        risk_score=82,
        objective="관찰 결과를 다음 공격 행동에 반영한다.",
        impact="target_data_modification",
        chain_id="chain-os-chain-regression-tb-hh-u1u2",
        search=ChainSearchProgress(
            frontier_candidates=len(candidates),
            remaining_frontier=[
                orchestrator._decision_signature(item) for item in candidates
            ],
        ),
    )
    return orchestrator, runtime, run, boundary, scenario


def test_tb_chain_uses_observation_for_next_tool_and_resets_once() -> None:
    gateway = FeedbackGateway()
    orchestrator, runtime, run, boundary, scenario = make_chain(gateway)

    result = orchestrator._run_tb_chain(run, boundary, scenario)

    assert [(item.tool_decision.name, item.tool_decision.action) for item in runtime.requests] == [
        ("process.procfs", "read_cmdline"),
        ("sudo.run", "run_probe"),
    ]
    assert {item.chain_id for item in runtime.requests} == {scenario.chain_id}
    assert [item.chain_step for item in runtime.requests] == [1, 2]
    assert all(item.preserve_state for item in runtime.requests)
    assert len(runtime.reset_requests) == 1
    assert len(gateway.contexts) == 2
    assert gateway.contexts[1]["executed_steps"][0]["tool"] == "process.procfs"

    execute_steps = [item for item in scenario.steps if item.type == "execute"]
    assert [item.sequence for item in execute_steps] == [1, 2]
    assert execute_steps[0].state_after["fingerprint"]
    assert execute_steps[1].state_before == execute_steps[0].state_after
    assert any(
        change["key"] == "privilege.escalation_possible"
        for change in execute_steps[1].state_changes
    )
    assert scenario.search.unique_transitions == 2
    assert scenario.search.termination_reason == "MAX_IMPACT_VERIFIED"
    assert scenario.search.search_complete is True
    assert scenario.chain_status == "COMPLETED"
    assert scenario.rollback_status == "VERIFIED"
    assert scenario.risk_score == 82
    assert scenario.potential_risk_score == 82
    assert scenario.verified_impact_score == 90
    assert result.potential_risk_score == 82
    assert result.verified_impact_score == 90
    assert result.verdict == "BROKEN"
    assert result.proof_level == "L4_RESTORED"
    assert result.rollback_status == "VERIFIED"


def test_target_canary_write_is_registered_for_all_eight_boundaries() -> None:
    for boundary in TRUST_BOUNDARIES:
        candidates = {
            (item.name, item.action)
            for item in AgentOrchestrator._candidate_decisions(boundary)
        }
        assert ("file.content", "write") in candidates

    representative = {
        (item.name, item.action)
        for item in AgentOrchestrator._candidate_decisions(TRUST_BOUNDARIES[0])
    }
    target_only = {
        (item.name, item.action)
        for item in AgentOrchestrator._candidate_decisions(TRUST_BOUNDARIES[1])
    }
    assert ("file.open", "read") in representative
    assert ("process.procfs", "read_mem") in representative
    assert ("file.open", "read") not in target_only
    assert ("process.procfs", "read_mem") not in target_only


def test_duplicate_state_and_decision_stops_before_another_dispatch() -> None:
    gateway = RepeatingGateway()
    orchestrator, runtime, run, boundary, scenario = make_chain(
        gateway,
        budget=AgentBudget(max_stagnant_plans_per_tb=1),
        runtime=NoEffectRuntime(),
    )

    result = orchestrator._run_tb_chain(run, boundary, scenario)

    assert gateway.calls == 3
    assert len(runtime.requests) == 2
    execute_steps = [item for item in scenario.steps if item.type == "execute"]
    assert len(execute_steps) == 2
    assert (
        execute_steps[1].state_before["fingerprint"]
        == execute_steps[1].state_after["fingerprint"]
    )
    assert any(
        event.event_type == "DUPLICATE_TRANSITION_REJECTED"
        for event in run.events
    )
    assert scenario.search.termination_reason == "NO_PROGRESS"
    assert scenario.search.status == "PAUSED"
    assert scenario.search.repeated_states == 1
    assert scenario.search.resume_available is True
    assert scenario.search.checkpoint["requires_replay"] is True
    assert result.verdict == "INCONCLUSIVE"
    assert result.rollback_status == "VERIFIED"
    assert len(runtime.reset_requests) == 1


def test_openrouter_invalid_registry_pair_falls_back_to_current_frontier(
    monkeypatch, tmp_path
) -> None:
    gateway = ModelGateway(
        Settings(
            openrouter_api_key="test-key",
            openrouter_model="openai/gpt-5-mini",
            allowed_origins=("http://127.0.0.1:5173",),
            runtime_dir=tmp_path,
        )
    )

    class InvalidPairResponse:
        @staticmethod
        def raise_for_status() -> None:
            return None

        @staticmethod
        def json() -> dict:
            return {
                "choices": [{"message": {"tool_calls": [{"function": {
                    "name": ATTACK_FUNCTION_NAME,
                    "arguments": {
                        "tool_id": "file.content",
                        "action": "read_cmdline",
                        "resource_ref": "target-canary",
                        "arguments": {},
                    },
                }}]}}]
            }

    monkeypatch.setattr("app.model_gateway.httpx.post", lambda *args, **kwargs: InvalidPairResponse())
    prompt = json.dumps({
        "untried_candidates": [OBSERVE.model_dump(mode="json")],
        "executed_steps": [],
    })

    action = gateway.next_action(prompt, TRUST_BOUNDARIES[0])

    assert action.kind == "tool"
    assert action.decision == OBSERVE
    assert "결정론적 대체 행동" in action.rationale


def test_openrouter_candidate_outside_frontier_falls_back_without_dispatching_it(
    monkeypatch, tmp_path
) -> None:
    gateway = ModelGateway(
        Settings(
            openrouter_api_key="test-key",
            openrouter_model="openai/gpt-5-mini",
            allowed_origins=("http://127.0.0.1:5173",),
            runtime_dir=tmp_path,
        )
    )

    class OutsideFrontierResponse:
        @staticmethod
        def raise_for_status() -> None:
            return None

        @staticmethod
        def json() -> dict:
            return {
                "choices": [{"message": {"tool_calls": [{"function": {
                    "name": ATTACK_FUNCTION_NAME,
                    "arguments": {
                        "tool_id": "file.content",
                        "action": "read",
                        "resource_ref": "target-canary",
                        "arguments": {},
                    },
                }}]}}]
            }

    monkeypatch.setattr("app.model_gateway.httpx.post", lambda *args, **kwargs: OutsideFrontierResponse())
    prompt = json.dumps({
        "untried_candidates": [OBSERVE.model_dump(mode="json")],
        "executed_steps": [],
    })

    action = gateway.next_action(prompt, TRUST_BOUNDARIES[0])

    assert action.decision == OBSERVE
    assert "frontier 밖" in action.rationale


def test_openrouter_transport_error_falls_back_to_current_frontier(
    monkeypatch, tmp_path
) -> None:
    gateway = ModelGateway(
        Settings(
            openrouter_api_key="test-key",
            openrouter_model="openai/gpt-5-mini",
            allowed_origins=("http://127.0.0.1:5173",),
            runtime_dir=tmp_path,
        )
    )

    def fail_post(*args, **kwargs):
        del args, kwargs
        raise httpx.ConnectError("offline")

    monkeypatch.setattr("app.model_gateway.httpx.post", fail_post)
    prompt = json.dumps({
        "untried_candidates": [OBSERVE.model_dump(mode="json")],
        "executed_steps": [],
    })

    action = gateway.next_action(prompt, TRUST_BOUNDARIES[0])

    assert action.decision == OBSERVE
    assert "해석할 수 없었습니다" in action.rationale


def test_openrouter_invalid_finish_falls_back_to_current_frontier(
    monkeypatch, tmp_path
) -> None:
    gateway = ModelGateway(
        Settings(
            openrouter_api_key="test-key",
            openrouter_model="openai/gpt-5-mini",
            allowed_origins=("http://127.0.0.1:5173",),
            runtime_dir=tmp_path,
        )
    )

    class InvalidFinishResponse:
        @staticmethod
        def raise_for_status() -> None:
            return None

        @staticmethod
        def json() -> dict:
            return {
                "choices": [{"message": {"tool_calls": [{"function": {
                    "name": "finish_attack_chain",
                    "arguments": {"reason": "MODEL_DECIDED", "rationale": "done"},
                }}]}}]
            }

    monkeypatch.setattr("app.model_gateway.httpx.post", lambda *args, **kwargs: InvalidFinishResponse())
    prompt = json.dumps({
        "untried_candidates": [OBSERVE.model_dump(mode="json")],
        "executed_steps": [],
    })

    action = gateway.next_action(prompt, TRUST_BOUNDARIES[0])

    assert action.decision == OBSERVE
    assert "종료 사유" in action.rationale


def test_permission_minimizer_invalid_model_ids_use_deterministic_subset(
    monkeypatch, tmp_path
) -> None:
    gateway = ModelGateway(
        Settings(
            openrouter_api_key="test-key",
            openrouter_model="openai/gpt-5-mini",
            allowed_origins=("http://127.0.0.1:5173",),
            runtime_dir=tmp_path,
        )
    )

    class InvalidPermissionResponse:
        @staticmethod
        def raise_for_status() -> None:
            return None

        @staticmethod
        def json() -> dict:
            return {
                "choices": [{"message": {"tool_calls": [{"function": {
                    "name": "select_permission_ids",
                    "arguments": {"permission_ids": ["container:invented"]},
                }}]}}]
            }

    monkeypatch.setattr("app.model_gateway.httpx.post", lambda *args, **kwargs: InvalidPermissionResponse())

    selected = gateway.suggest_permission_ids(
        available_ids=["host:limited_sudo", "host:no_new_privileges"],
        relevant_ids=["host:limited_sudo"],
        contract={},
    )

    assert selected == ["host:limited_sudo"]


def test_tool_watchdog_returns_inconclusive_replay_checkpoint() -> None:
    gateway = FeedbackGateway()
    orchestrator, runtime, run, boundary, scenario = make_chain(
        gateway,
        budget=AgentBudget(max_tool_calls_per_tb=1),
    )

    result = orchestrator._run_tb_chain(run, boundary, scenario)

    assert len(runtime.requests) == 1
    assert runtime.requests[0].tool_decision == OBSERVE
    assert len(runtime.reset_requests) == 1
    assert scenario.search.termination_reason == "SEARCH_BUDGET_EXHAUSTED"
    assert scenario.search.budget_exhausted is True
    assert scenario.search.status == "PAUSED"
    assert scenario.search.resume_available is True
    assert scenario.search.checkpoint_id
    assert scenario.search.checkpoint["requires_replay"] is True
    assert scenario.search.checkpoint["profile_hash"] == run.profile_hash
    assert len(scenario.search.checkpoint["executed_steps"]) == 1
    assert scenario.rollback_status == "VERIFIED"
    assert result.verdict == "INCONCLUSIVE"
    assert result.rollback_status == "VERIFIED"


def test_resume_replays_prefix_then_continues_chain_before_single_reset() -> None:
    gateway = FeedbackGateway()
    orchestrator, runtime, run, boundary, scenario = make_chain(
        gateway,
        budget=AgentBudget(max_tool_calls_per_tb=1),
    )

    paused = orchestrator._run_tb_chain(run, boundary, scenario)
    checkpoint = scenario.search.checkpoint
    expected_replay_fingerprint = checkpoint["executed_steps"][0]["state_after"][
        "fingerprint"
    ]
    assert paused.verdict == "INCONCLUSIVE"
    assert scenario.search.resume_available is True
    run.tb_scenarios = [scenario]
    run.tb_results = [paused]
    run.budget.max_tool_calls_per_tb = 4
    orchestrator._minimize_permissions = lambda resumed_run: None
    request_start = len(runtime.requests)
    result_start = len(runtime.results)
    operation_start = len(runtime.operations)
    reset_start = len(runtime.reset_requests)

    resumed_run = orchestrator.resume(run)

    resume_requests = runtime.requests[request_start:]
    assert [item.chain_step for item in resume_requests] == [1, 2]
    assert len({item.chain_id for item in resume_requests}) == 1
    assert resume_requests[0].chain_id == scenario.chain_id
    assert all(item.preserve_state for item in resume_requests)
    assert [
        (item.tool_decision.name, item.tool_decision.action)
        for item in resume_requests
    ] == [
        ("process.procfs", "read_cmdline"),
        ("sudo.run", "run_probe"),
    ]
    assert runtime.operations[operation_start:] == [
        ("execute", scenario.chain_id, 1),
        ("execute", scenario.chain_id, 2),
        ("reset", None, 0),
    ]
    assert len(runtime.reset_requests) == reset_start + 1
    assert (
        orchestrator._result_state_fingerprint(runtime.results[result_start])
        == expected_replay_fingerprint
    )

    resumed_result = resumed_run.tb_results[0]
    assert resumed_result.verdict == "BROKEN"
    assert resumed_result.proof_level == "L4_RESTORED"
    assert resumed_result.rollback_status == "VERIFIED"
    assert scenario.search.termination_reason == "MAX_IMPACT_VERIFIED"
    assert scenario.search.search_complete is True
    assert scenario.search.resume_available is False
    assert scenario.search.checkpoint_id is None
    assert scenario.search.checkpoint == {}
    assert scenario.rollback_status == "VERIFIED"
