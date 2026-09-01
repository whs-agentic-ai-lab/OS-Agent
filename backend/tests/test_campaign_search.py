from pathlib import Path

from app.agent_orchestrator import AgentOrchestrator, permission_profile_hash
from app.catalog import TRUST_BOUNDARIES
from app.config import Settings
from app.model_gateway import ModelGateway
from app.permission_minimizer import collect_maximum_permission_profiles
from app.repository import InMemoryAgentRunRepository
from app.schemas import (
    AgentBudget,
    AgentRunRecord,
    AgentRunRequest,
    RuntimeAgentResult,
    RuntimeBacktrackRequest,
    RuntimeBacktrackResult,
    RuntimeDispatchRequest,
    RuntimeResetRequest,
    RuntimeResetResult,
)


class CampaignRuntime:
    def __init__(self, *, fail_backtrack: bool = False) -> None:
        self.requests: list[RuntimeDispatchRequest] = []
        self.backtrack_requests: list[RuntimeBacktrackRequest] = []
        self.reset_requests: list[RuntimeResetRequest] = []
        self.fail_backtrack = fail_backtrack
        self.chain_boundaries: dict[str, str] = {}
        self.chain_last_steps: dict[tuple[str, str], int] = {}

    @staticmethod
    def is_available(subject_mode=None) -> bool:
        del subject_mode
        return True

    def execute(self, request: RuntimeDispatchRequest) -> RuntimeAgentResult:
        if (
            request.preserve_state
            and request.chain_id is not None
            and request.chain_id.startswith("min-")
        ):
            owner = self.chain_boundaries.setdefault(
                request.chain_id,
                request.trust_boundary_id,
            )
            assert owner == request.trust_boundary_id
            chain_key = (request.trust_boundary_id, request.chain_id)
            expected_step = self.chain_last_steps.get(chain_key, 0) + 1
            assert request.chain_step == expected_step
            self.chain_last_steps[chain_key] = request.chain_step
        self.requests.append(request)
        decision = request.tool_decision
        assert decision is not None
        privilege = decision.name in {"sudo.run", "privilege.identity_probe"}
        profile = request.permission_profile
        if decision.name == "file.content" and decision.action == "write":
            allowed = (
                profile["owner_write"]
                or profile["group_write"]
                or profile["dac_override"]
                if request.subject_mode.value == "host"
                else profile["mount_write"]
                and (
                    profile["run_as_root"]
                    or profile["supplementary_group"]
                    or profile["dac_override"]
                )
            )
        elif decision.name == "sudo.run":
            allowed = (
                request.subject_mode.value == "host"
                and profile["limited_sudo"]
                and not profile["no_new_privileges"]
            )
        elif decision.name == "privilege.identity_probe":
            capability = (
                "setgid_capability"
                if decision.action in {"setgid", "setegid", "setfsgid", "setgroups"}
                else "setuid_capability"
            )
            allowed = profile[capability]
        else:
            allowed = True
        changed = (
            allowed
            and decision.name == "file.content"
            and decision.action == "write"
        )
        identity = {"uid": 10001, "euid": 10001, "gid": 10001, "egid": 10001}
        return RuntimeAgentResult(
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
            runtime_agent="campaign-test-runtime",
            planner_mode=request.planner_mode,
            tool=decision.name,
            action=decision.action,
            resource_ref=decision.resource_ref,
            tool_arguments=decision.arguments,
            policy_decision="allowed",
            runtime_result="allowed" if allowed else "denied",
            outcome="ALLOWED" if allowed else "OS_DENIED",
            attempted=True,
            escalation_possible=privilege and allowed,
            temporary_changed=privilege and allowed,
            changed=changed,
            identity_before=identity,
            identity_reached={**identity, "euid": 0} if privilege else identity,
            identity_after=identity,
            evidence_refs=[f"action:{request.action_id}"],
            output=(
                "campaign transition verified"
                if allowed
                else "permission denied"
            ),
            exit_code=0 if allowed else 13,
            before_sha256="sha256:baseline",
            after_sha256="sha256:changed" if changed else "sha256:baseline",
        )

    def backtrack(self, request: RuntimeBacktrackRequest) -> RuntimeBacktrackResult:
        self.backtrack_requests.append(request)
        return RuntimeBacktrackResult(
            status="RESTORE_FAILED" if self.fail_backtrack else "RESTORED",
            restored_step=request.to_step,
            state_fingerprint=("sha256:mismatch" if self.fail_backtrack else request.expected_fingerprint),
            evidence_refs=[f"checkpoint:{request.chain_id}:{request.to_step}"],
        )

    def reset_harness(self, request: RuntimeResetRequest) -> RuntimeResetResult:
        self.reset_requests.append(request)
        return RuntimeResetResult(status="RESET", evidence_refs=["full-reset:fallback"])


def make_campaign(*, fail_backtrack: bool = False):
    runtime = CampaignRuntime(fail_backtrack=fail_backtrack)
    profiles = collect_maximum_permission_profiles()
    identity = {"uid": 10001, "euid": 10001, "gid": 10001, "egid": 10001}
    run = AgentRunRecord(
        run_id="campaign-search-test",
        objective="Campaign graph search",
        status="RUNNING",
        fixed_permission_profiles=profiles,
        profile_hash=permission_profile_hash(profiles.model_dump()),
        effective_permissions={"host": identity, "container": identity},
        budget=AgentBudget(
            max_campaign_nodes=8,
            max_campaign_depth=3,
            campaign_beam_width=1,
        ),
    )
    orchestrator = AgentOrchestrator(
        runtime,
        InMemoryAgentRunRepository(),
        ModelGateway(Settings(
            openrouter_api_key=None,
            openrouter_model="test-model",
            allowed_origins=("http://127.0.0.1:5173",),
            runtime_dir=Path("runtime"),
        )),
    )
    orchestrator._prepare_campaign(run)
    return orchestrator, runtime, run


def test_campaign_has_one_global_root_and_ranked_frontier() -> None:
    orchestrator, _, run = make_campaign()
    search = run.campaign_search
    root = search.nodes[0]

    assert search.root_node_id == root.node_id
    assert search.frontier_node_ids == [root.node_id]
    assert root.controlled_environments == ["u1"]
    candidates = orchestrator._campaign_candidates(run, root)
    assert candidates
    assert all(boundary.source_environment.value == "u1" for _, boundary, _ in candidates)
    assert candidates == sorted(candidates, key=lambda item: item[0], reverse=True)


def test_campaign_expansion_backtracks_to_parent_without_full_reset() -> None:
    orchestrator, runtime, run = make_campaign()
    root = run.campaign_search.nodes[0]

    orchestrator._campaign_expand_node(run, root)

    search = run.campaign_search
    assert len(search.nodes) == 2
    assert len(search.transitions) == 1
    assert search.transitions[0].rollback_status == "VERIFIED"
    assert search.transitions[0].status == "ROLLED_BACK"
    assert runtime.backtrack_requests[0].expected_fingerprint == root.state_fingerprint
    assert runtime.backtrack_requests[0].to_step == 0
    assert runtime.reset_requests == []
    assert search.backtrack_count == 1


def test_failed_parent_restore_escalates_to_full_reset_and_stops_search() -> None:
    orchestrator, runtime, run = make_campaign(fail_backtrack=True)
    root = run.campaign_search.nodes[0]

    orchestrator._campaign_expand_node(run, root)

    assert run.campaign_search.status == "FAILED"
    assert run.campaign_search.termination_reason == "RESET_FAILED"
    assert runtime.reset_requests
    assert run.campaign_search.transitions[0].rollback_status == "FAILED"


def test_campaign_resume_extends_budget_and_preserves_frontier() -> None:
    orchestrator, _, run = make_campaign()
    run.status = "PAUSED"
    run.campaign_search.status = "PAUSED"
    original_frontier = list(run.campaign_search.frontier_node_ids)
    original_limit = run.budget.max_campaign_nodes

    orchestrator.prepare_resume(run)

    assert run.status == "RECEIVED"
    assert run.campaign_search.frontier_node_ids == original_frontier
    assert run.budget.max_campaign_nodes > original_limit
    assert any(event.event_type == "CAMPAIGN_RESUME_RECEIVED" for event in run.events)


def test_campaign_with_narrow_beam_verifies_coverage_and_deep_chain() -> None:
    orchestrator, _, run = make_campaign()
    run.budget.max_campaign_nodes = 32
    run.budget.max_campaign_depth = 8
    run.budget.campaign_beam_width = 1

    orchestrator._execute_campaign(run)

    assert run.campaign_search.status == "COMPLETED"
    assert run.campaign_search.search_complete is True
    assert run.campaign_search.termination_reason == (
        "ALL_TRUST_BOUNDARIES_AND_ENVIRONMENTS_VERIFIED"
    )
    assert run.campaign_search.boundary_coverage_complete is True
    assert orchestrator._campaign_covered_boundary_ids(run.campaign_search) == {
        boundary.id for boundary in TRUST_BOUNDARIES
    }
    best = orchestrator._campaign_node(
        run.campaign_search,
        run.campaign_search.best_node_id or "",
    )
    assert best.depth >= 4
    assert {item.value for item in best.controlled_environments} == {
        "u1", "u2", "c1", "c2", "c3",
    }
    assert run.campaign_search.max_controlled_environment_count == 5
    assert run.campaign_search.deepest_verified_depth >= best.depth
    assert all(
        transition.potential_risk_score == 82
        and transition.impact_score == 82
        for transition in run.campaign_search.transitions
    )
    assert {
        event.event_type for event in run.events
    } >= {"ALL_TRUST_BOUNDARIES_VERIFIED", "DEEP_CAMPAIGN_VERIFIED"}


def test_completed_host_campaign_finds_verified_one_minimal_profile() -> None:
    orchestrator, runtime, run = make_campaign()
    run.scope = "host"
    orchestrator._prepare_campaign(run)
    run.budget.max_campaign_nodes = 32
    run.budget.max_campaign_depth = 8
    run.budget.campaign_beam_width = 1

    orchestrator._execute_campaign(run)
    orchestrator._finalize_campaign(run)

    assert run.attack_contract is not None
    assert run.permission_minimization.status == "NOT_STARTED"
    expected_boundaries = {
        boundary.id
        for boundary in TRUST_BOUNDARIES
        if boundary.source_mode.value == "host"
    }
    assert {
        step.trust_boundary_id for step in run.attack_contract.chain_steps
    } == expected_boundaries
    assert all(
        step.step_id != "contract-step"
        and step.required_impact_score > 0
        for step in run.attack_contract.chain_steps
    )

    orchestrator._minimize_permissions(run)

    minimized = run.permission_minimization
    assert minimized.status == "COMPLETED"
    assert minimized.one_minimal_verified is True
    assert minimized.minimal_permission_ids
    assert set(minimized.essential_permission_ids) == set(
        minimized.minimal_permission_ids
    )
    assert len(minimized.minimal_permission_ids) < len(
        minimized.initial_permission_ids
    )
    assert minimized.trials[-1].strategy == "final_verify"
    assert minimized.trials[-1].success is True
    minimization_requests = [
        request
        for request in runtime.requests
        if request.chain_id is not None
        and request.chain_id.startswith("min-")
    ]
    assert minimization_requests
    assert {
        request.trust_boundary_id for request in minimization_requests
    } == expected_boundaries
    assert all(request.preserve_state for request in minimization_requests)
    chain_requests: dict[str, list[RuntimeDispatchRequest]] = {}
    for request in minimization_requests:
        assert request.chain_id is not None
        chain_requests.setdefault(request.chain_id, []).append(request)
    assert all(
        len({request.trust_boundary_id for request in requests}) == 1
        and [request.chain_step for request in requests]
        == list(range(1, len(requests) + 1))
        for requests in chain_requests.values()
    )
    assert {
        event.event_type for event in run.events
    } >= {"PERMISSION_TRIAL_VERIFIED", "ONE_MINIMAL_PROFILE_VERIFIED"}


def test_campaign_failure_preserves_verified_boundaries_and_resets_environment(
    monkeypatch,
) -> None:
    orchestrator, runtime, run = make_campaign()
    monkeypatch.setattr(orchestrator, "_recon", lambda _run: None)
    monkeypatch.setattr(orchestrator, "_collect_infrastructure", lambda _run: None)
    monkeypatch.setattr(orchestrator, "_prepare_campaign", lambda _run: None)

    def fail_after_first_verified_transition(active_run: AgentRunRecord) -> None:
        root = active_run.campaign_search.nodes[0]
        orchestrator._campaign_expand_node(active_run, root)
        raise RuntimeError("fixture initialization failed")

    monkeypatch.setattr(
        orchestrator,
        "_execute_campaign",
        fail_after_first_verified_transition,
    )

    failed = orchestrator.run(
        AgentRunRequest(),
        prepared_run=run,
    )

    assert failed.status == "FAILED"
    assert failed.campaign_search.status == "FAILED"
    assert failed.campaign_search.termination_reason == "RUNTIME_ERROR"
    assert failed.rollback_status == "VERIFIED"
    assert len(runtime.reset_requests) == len(TRUST_BOUNDARIES)
    assert len(failed.tb_results) == len(TRUST_BOUNDARIES)
    assert failed.summary.broken == 1
    assert failed.summary.inconclusive == len(TRUST_BOUNDARIES) - 1
    assert any(result.verdict == "BROKEN" for result in failed.tb_results)
    assert {event.event_type for event in failed.events} >= {
        "RUN_FAILED",
        "FAILURE_RECOVERY_VERIFIED",
        "PARTIAL_RESULTS_PRESERVED",
        "RUN_FINISHED",
    }
