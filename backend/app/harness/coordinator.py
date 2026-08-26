from __future__ import annotations

from time import monotonic
from uuid import uuid4

from ..schemas import EnvironmentNode

from .models import (
    ActionCandidate,
    HarnessActionRecord,
    HarnessBudgetState,
    HarnessComponentName,
    HarnessComponentStatus,
    HarnessEvent,
    HarnessRunRecord,
    HarnessRunRequest,
    HarnessStatus,
    ResetRecord,
    utc_now,
)
from .ports import HarnessComponents
from .repository import HarnessRunRepository


class HarnessCoordinator:
    def __init__(
        self,
        components: HarnessComponents,
        repository: HarnessRunRepository,
    ) -> None:
        self.components = components
        self.repository = repository

    def get_status(self) -> HarnessStatus:
        missing = self.components.missing()
        return HarnessStatus(
            status="waiting_for_components" if missing else "ready",
            ready=not missing,
            components=[
                HarnessComponentStatus(name=name, ready=name not in missing)
                for name in HarnessComponentName
            ],
            missing_components=missing,
        )

    def run(self, request: HarnessRunRequest) -> HarnessRunRecord:
        budget = HarnessBudgetState(**request.budget.model_dump())
        run = HarnessRunRecord(
            run_id=f"harness-{uuid4().hex[:12]}",
            status="RECEIVED",
            objective=request.objective,
            subject_mode=request.subject_mode,
            trust_boundary_id=request.trust_boundary_id,
            scenario_id=request.scenario_id,
            budget=budget,
            state={
                "objective": request.objective,
                "subject_mode": request.subject_mode.value,
                "trust_boundary_id": request.trust_boundary_id,
                "scenario_id": request.scenario_id,
                "history": [],
            },
        )
        self._event(run, "harness", "RUN_RECEIVED", "Harness Run을 생성했습니다.")
        missing = self.components.missing()
        if missing:
            run.status = "BLOCKED"
            run.missing_components = missing
            run.termination_reason = "MISSING_REQUIRED_COMPONENTS"
            self._event(
                run,
                "harness",
                "COMPONENTS_MISSING",
                "필수 OS Adapter가 아직 연결되지 않아 실행하지 않았습니다.",
                {"missing_components": [item.value for item in missing]},
            )
            return self._finish(run)

        started = monotonic()
        run.status = "RUNNING"
        self._event(run, "harness", "RUN_STARTED", "Harness 실행을 시작했습니다.")

        try:
            permission_provider = self._require("permission_provider")
            tool_catalog = self._require("tool_catalog")
            planner = self._require("planner")
            executor = self._require("executor")
            verifier = self._require("verifier")
            resetter = self._require("resetter")

            run.state["permission_snapshot"] = permission_provider.snapshot(request)
            snapshot = run.state["permission_snapshot"]
            if snapshot.get("trust_boundary_id"):
                run.trust_boundary_id = snapshot["trust_boundary_id"]
                run.source_environment = EnvironmentNode(snapshot["source_environment"])
                run.target_environment = EnvironmentNode(snapshot["target_environment"])
                run.state["trust_boundary_id"] = snapshot["trust_boundary_id"]
                run.state["source_environment"] = snapshot.get("source_environment")
                run.state["target_environment"] = snapshot.get("target_environment")
            run.state_version += 1
            self._event(
                run,
                "permission_provider",
                "PERMISSION_SNAPSHOT_COLLECTED",
                "OS Permission Provider가 상태 Snapshot을 반환했습니다.",
            )

            last_fingerprint: str | None = None
            while True:
                termination = self._budget_termination(run, started)
                if termination is not None:
                    run.status = "BLOCKED"
                    run.termination_reason = termination
                    break

                candidates = tool_catalog.candidates(run.state)
                self._event(
                    run,
                    "tool_catalog",
                    "FRONTIER_BUILT",
                    f"{len(candidates)}개의 Action Candidate를 생성했습니다.",
                    {"candidate_ids": [item.candidate_id for item in candidates]},
                )
                if not candidates:
                    run.status = "COMPLETED"
                    run.termination_reason = "FRONTIER_EXHAUSTED"
                    break

                decision = planner.select(run.state, candidates, run.budget)
                self._event(
                    run,
                    "planner",
                    "PLAN_SELECTED",
                    "Planner가 Candidate 또는 종료를 선택했습니다.",
                    {
                        "candidate_id": decision.candidate_id,
                        "stop_reason": decision.stop_reason,
                    },
                )
                if decision.stop_reason is not None:
                    run.status = "COMPLETED"
                    run.termination_reason = "PLANNER_STOPPED"
                    run.state["planner_stop_reason"] = decision.stop_reason
                    break

                candidate = self._selected_candidate(candidates, decision.candidate_id)
                fingerprint = candidate.model_dump_json()
                run.budget.used_iterations += 1
                run.budget.used_tool_calls += 1
                execution = executor.execute(run.run_id, candidate, run.state)
                self._event(
                    run,
                    "executor",
                    "ACTION_EXECUTED",
                    f"{candidate.tool_name} 실행 결과를 수집했습니다.",
                    {
                        "candidate_id": candidate.candidate_id,
                        "success": execution.success,
                        "error_code": execution.error_code,
                    },
                )

                verification = verifier.verify(
                    run.run_id,
                    candidate,
                    execution,
                    run.state,
                )
                self._event(
                    run,
                    "verifier",
                    "ACTION_VERIFIED",
                    f"Independent Verifier가 {verification.status}로 판정했습니다.",
                    {"candidate_id": candidate.candidate_id},
                )

                reset = (
                    resetter.reset(run.run_id, candidate, execution, run.state)
                    if candidate.changes_state
                    else ResetRecord(status="NOT_REQUIRED")
                )
                self._event(
                    run,
                    "resetter",
                    "ACTION_RESET",
                    f"Action Reset 상태: {reset.status}",
                    {"candidate_id": candidate.candidate_id},
                )

                run.actions.append(
                    HarnessActionRecord(
                        sequence=len(run.actions) + 1,
                        candidate=candidate,
                        execution=execution,
                        verification=verification,
                        reset=reset,
                    )
                )
                run.state["history"].append(
                    {
                        "candidate_id": candidate.candidate_id,
                        "tool_name": candidate.tool_name,
                        "execution": execution.model_dump(mode="json"),
                        "verification": verification.model_dump(mode="json"),
                        "reset": reset.model_dump(mode="json"),
                    }
                )
                run.state_version += 1

                if reset.status == "RESET_FAILED":
                    run.status = "BLOCKED"
                    run.termination_reason = "RESET_FAILED"
                    break
                if verification.status == "REJECTED":
                    run.status = "FAILED"
                    run.termination_reason = "VERIFICATION_REJECTED"
                    break
                if verification.status == "INCONCLUSIVE":
                    run.status = "BLOCKED"
                    run.termination_reason = "VERIFICATION_INCONCLUSIVE"
                    break

                if fingerprint == last_fingerprint:
                    run.budget.no_progress_iterations += 1
                else:
                    run.budget.no_progress_iterations = 0
                last_fingerprint = fingerprint
        except Exception as exc:
            run.status = "FAILED"
            run.termination_reason = "HARNESS_ERROR"
            self._event(
                run,
                "harness",
                "RUN_FAILED",
                str(exc),
                {"error_type": type(exc).__name__},
            )

        return self._finish(run)

    def _require(self, name: str):
        component = getattr(self.components, name)
        if component is None:
            raise RuntimeError(f"필수 Harness 구성요소가 없습니다: {name}")
        return component

    @staticmethod
    def _selected_candidate(
        candidates: list[ActionCandidate],
        candidate_id: str | None,
    ) -> ActionCandidate:
        for candidate in candidates:
            if candidate.candidate_id == candidate_id:
                return candidate
        raise ValueError("Planner가 현재 Frontier에 없는 Candidate를 선택했습니다.")

    @staticmethod
    def _budget_termination(
        run: HarnessRunRecord,
        started: float,
    ) -> str | None:
        if monotonic() - started >= run.budget.max_elapsed_seconds:
            return "TIME_BUDGET_EXHAUSTED"
        if run.budget.used_iterations >= run.budget.max_iterations:
            return "ITERATION_BUDGET_EXHAUSTED"
        if run.budget.used_tool_calls >= run.budget.max_tool_calls:
            return "TOOL_BUDGET_EXHAUSTED"
        if (
            run.budget.no_progress_iterations
            >= run.budget.max_no_progress_iterations
        ):
            return "NO_PROGRESS"
        return None

    def _finish(self, run: HarnessRunRecord) -> HarnessRunRecord:
        run.completed_at = utc_now()
        self._event(
            run,
            "harness",
            "RUN_FINISHED",
            f"Harness 종료 상태: {run.status}",
            {"termination_reason": run.termination_reason},
        )
        self.repository.save(run)
        return run

    @staticmethod
    def _event(
        run: HarnessRunRecord,
        source: str,
        event_type: str,
        message: str,
        payload: dict | None = None,
    ) -> None:
        run.events.append(
            HarnessEvent(
                sequence=len(run.events) + 1,
                source=source,
                event_type=event_type,
                message=message,
                payload=payload or {},
            )
        )
