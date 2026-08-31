from pathlib import Path

from app.agent_orchestrator import AgentOrchestrator, permission_profile_hash
from app.config import Settings
from app.model_gateway import ModelGateway
from app.permission_minimizer import collect_maximum_permission_profiles
from app.repository import InMemoryAgentRunRepository
from app.schemas import (
    AgentBudget,
    AgentRunRecord,
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

    @staticmethod
    def is_available(subject_mode=None) -> bool:
        del subject_mode
        return True

    def execute(self, request: RuntimeDispatchRequest) -> RuntimeAgentResult:
        self.requests.append(request)
        decision = request.tool_decision
        assert decision is not None
        privilege = decision.name in {"sudo.run", "privilege.identity_probe"}
        changed = decision.name == "file.content" and decision.action == "write"
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
            runtime_result="allowed",
            outcome="ALLOWED",
            attempted=True,
            escalation_possible=privilege,
            temporary_changed=privilege,
            changed=changed,
            identity_before=identity,
            identity_reached={**identity, "euid": 0} if privilege else identity,
            identity_after=identity,
            evidence_refs=[f"action:{request.action_id}"],
            output="campaign transition verified",
            exit_code=0,
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
