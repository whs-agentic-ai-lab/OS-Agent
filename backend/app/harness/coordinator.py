from __future__ import annotations

from pathlib import Path
from time import monotonic
from uuid import uuid4

from ..schemas import EnvironmentNode
from .evidence import EvidenceBundleWriter, redact
from .models import (
    RETRYABLE_ERROR_CODES,
    ActionCandidate,
    ActionReceipt,
    HarnessActionRecord,
    HarnessBudgetState,
    HarnessComponentName,
    HarnessComponentStatus,
    HarnessEvent,
    HarnessRunRecord,
    HarnessRunRequest,
    HarnessStatus,
    ResetRecord,
    ToolExecution,
    VerificationRecord,
    canonical_hash,
    deterministic_candidate_id,
    utc_now,
)
from .ports import HarnessComponents
from .repository import HarnessRunRepository


RISK_ORDER = {"observe": 0, "safe": 1, "reversible": 2}
NON_MUTATING_ERRORS = {"ACCESS_DENIED", "INVALID_INPUT", "NOT_FOUND", "POLICY_BLOCKED"}


class HarnessCoordinator:
    def __init__(
        self,
        components: HarnessComponents,
        repository: HarnessRunRepository,
        evidence_root: Path | None = None,
    ) -> None:
        self.components = components
        self.repository = repository
        self.evidence_writer = EvidenceBundleWriter(evidence_root) if evidence_root else None

    def get_status(self) -> HarnessStatus:
        missing = self.components.missing()
        return HarnessStatus(
            status="waiting_for_components" if missing else "ready",
            ready=not missing,
            recovery_mode=("environment_reinitialize" if self.components.domain == "os" else "tool_reset"),
            components=[
                HarnessComponentStatus(
                    name=name,
                    ready=self.components._ready(getattr(self.components, name.value)),
                )
                for name in HarnessComponentName
            ],
            missing_components=missing,
        )

    def run(self, request: HarnessRunRequest) -> HarnessRunRecord:
        budget = HarnessBudgetState(**request.budget.model_dump())
        contract_hash = canonical_hash(
            request.model_dump(mode="json", exclude={"objective"})
        )
        run = HarnessRunRecord(
            run_id=f"harness-{uuid4().hex[:12]}",
            status="RECEIVED",
            current_stage="queued",
            objective=request.objective,
            source_id=request.source_id,
            subject_mode=request.subject_mode,
            trust_boundary_id=request.trust_boundary_id,
            scenario_id=request.scenario_id,
            reset_after_run=request.reset_after_run,
            budget=budget,
            contract_hash=contract_hash,
            state={
                "objective": request.objective,
                "model": request.model,
                "subject_mode": request.subject_mode.value,
                "trust_boundary_id": request.trust_boundary_id,
                "scenario_id": request.scenario_id,
                "history": [],
                "exposed_candidate_ids": [],
                "idempotency_results": {},
            },
        )
        self._event(run, "harness", "RUN_RECEIVED", "Harness Run을 생성했습니다.")
        missing = self.components.missing()
        if missing:
            run.status = "BLOCKED"
            run.error_code = "MISSING_REQUIRED_COMPONENTS"
            run.missing_components = missing
            run.termination_reason = "MISSING_REQUIRED_COMPONENTS"
            self._event(
                run,
                "harness",
                "COMPONENTS_MISSING",
                "필수 Adapter가 연결되지 않아 실행하지 않았습니다.",
                {"missing_components": [item.value for item in missing]},
            )
            return self._finish(run)

        started = monotonic()
        mutation_possible = False
        recovery_candidate: ActionCandidate | None = None
        run.status = "RUNNING"
        run.current_stage = "scope_and_role_check"
        self._event(run, "harness", "RUN_STARTED", "Harness 실행을 시작했습니다.")

        try:
            permission_provider = self._require("permission_provider")
            tool_catalog = self._require("tool_catalog")
            planner = self._require("planner")
            executor = self._require("executor")
            verifier = self._require("verifier")

            run.current_stage = "recon_and_permission_snapshot"
            run.state["permission_snapshot"] = permission_provider.snapshot(request)
            snapshot = run.state["permission_snapshot"]
            if snapshot.get("trust_boundary_id"):
                run.trust_boundary_id = snapshot["trust_boundary_id"]
                run.source_environment = EnvironmentNode(snapshot["source_environment"])
                run.target_environment = EnvironmentNode(snapshot["target_environment"])
                run.state.update(
                    {
                        "trust_boundary_id": snapshot["trust_boundary_id"],
                        "source_environment": snapshot.get("source_environment"),
                        "target_environment": snapshot.get("target_environment"),
                        "agent_state": {
                            "assets": snapshot.get("assets", []),
                            "relationships": snapshot.get("relationships", []),
                            "permissions": snapshot.get("permission_observations", {}),
                            "capabilities": snapshot.get("capabilities", []),
                        },
                    }
                )
            run.state_version += 1
            self._event(
                run,
                "permission_provider",
                "PERMISSION_SNAPSHOT_COLLECTED",
                "권한·환경 Snapshot과 정규화된 Agent State를 수집했습니다.",
                {"snapshot_hash": snapshot.get("snapshot_hash")},
            )

            last_fingerprint: str | None = None
            while True:
                termination = self._budget_termination(run, started)
                if termination is not None:
                    run.status = "BLOCKED"
                    run.error_code = termination
                    run.termination_reason = termination
                    break

                run.current_stage = "action_frontier"
                candidates = self._deduplicate(tool_catalog.candidates(run.state))
                self._validate_frontier(run, request, candidates)
                run.catalog_hash = canonical_hash(
                    [candidate.model_dump(mode="json") for candidate in candidates]
                )
                exposed = [item.candidate_id for item in candidates if item.frontier_status != "blocked"]
                run.state["exposed_candidate_ids"] = exposed[: request.result_limit]
                self._event(
                    run,
                    "tool_catalog",
                    "FRONTIER_BUILT",
                    f"{len(candidates)}개의 Action Candidate를 생성했습니다.",
                    {"candidate_ids": run.state["exposed_candidate_ids"], "catalog_hash": run.catalog_hash},
                )
                if not candidates:
                    run.status = "COMPLETED"
                    run.termination_reason = "FRONTIER_EXHAUSTED"
                    break

                if request.frozen_scenario:
                    step_index = len(run.state["history"])
                    if step_index >= len(request.frozen_tool_sequence):
                        run.status = "COMPLETED"
                        run.termination_reason = "FROZEN_SCENARIO_COMPLETED"
                        break
                    expected_tool = request.frozen_tool_sequence[step_index]
                    expected_target = request.frozen_target_resources[step_index]
                    candidates = [
                        item
                        for item in candidates
                        if item.tool_name == expected_tool
                        and item.target_resource == expected_target
                    ]
                    if not candidates:
                        run.status = "BLOCKED"
                        run.error_code = "SCENARIO_CHAIN_BLOCKED"
                        run.termination_reason = "SCENARIO_CHAIN_BLOCKED"
                        self._event(run, "guardrail", "SCENARIO_CHAIN_BLOCKED", "Frozen Scenario의 다음 Tool·대상이 현재 Frontier에 없습니다.", {"expected_tool": expected_tool, "expected_target": expected_target})
                        break

                run.current_stage = "planner_selection"
                visible = candidates[: request.result_limit]
                decision = planner.select(run.state, visible, run.budget)
                self._event(
                    run,
                    "planner",
                    "PLAN_SELECTED",
                    "Planner가 공개된 Candidate 또는 종료를 선택했습니다.",
                    {"candidate_id": decision.candidate_id, "stop_reason": decision.stop_reason},
                )
                if decision.stop_reason is not None:
                    run.status = "COMPLETED"
                    run.termination_reason = "PLANNER_STOPPED"
                    run.state["planner_stop_reason"] = decision.stop_reason
                    break

                candidate = self._selected_candidate(visible, decision.candidate_id)
                run.current_stage = "pre_execution_guardrail"
                self._guard_candidate(run, request, candidate)
                self._event(
                    run,
                    "guardrail",
                    "GUARDRAIL_PASSED",
                    "Candidate가 실행 직전 Grounding과 안전 검사를 통과했습니다.",
                    {"candidate_id": candidate.candidate_id},
                )

                fingerprint = candidate.semantic_key
                run.budget.used_iterations += 1
                idempotency_key = canonical_hash(
                    {
                        "run_id": run.run_id,
                        "candidate_id": candidate.candidate_id,
                        "tool": candidate.tool_name,
                        "arguments": candidate.arguments,
                    }
                )
                if idempotency_key in run.state["idempotency_results"]:
                    raise RuntimeError("동일한 Idempotency Key의 Action 중복 실행을 차단했습니다.")

                run.current_stage = "action_execution"
                execution = self._execute_with_retry(run, executor, candidate, idempotency_key)
                run.state["idempotency_results"][idempotency_key] = execution.model_dump(mode="json")
                receipt = self._receipt(candidate, execution)
                self._event(
                    run,
                    "executor",
                    "ACTION_EXECUTED",
                    f"{candidate.tool_name} 실행 결과와 Receipt를 수집했습니다.",
                    {"candidate_id": candidate.candidate_id, "success": execution.success, "error_code": execution.error_code, "idempotency_key": idempotency_key},
                )

                run.current_stage = "independent_verification"
                verification = verifier.verify(run.run_id, candidate, execution, run.state)
                overlap = set(receipt.evidence_refs) & set(verification.evidence_refs)
                if overlap:
                    verification = VerificationRecord(
                        status="REJECTED",
                        evidence_refs=verification.evidence_refs,
                        checks={**verification.checks, "evidence_independent": False},
                    )
                else:
                    verification.checks["evidence_independent"] = True
                self._event(
                    run,
                    "verifier",
                    "ACTION_VERIFIED",
                    f"Independent Verifier가 {verification.status}로 판정했습니다.",
                    {"candidate_id": candidate.candidate_id, "evidence_independent": not overlap},
                )

                action = HarnessActionRecord(
                    sequence=len(run.actions) + 1,
                    idempotency_key=idempotency_key,
                    candidate=candidate,
                    execution=execution,
                    receipt=receipt,
                    verification=verification,
                )
                run.actions.append(action)
                run.state["history"].append(
                    {
                        "candidate_id": candidate.candidate_id,
                        "tool_name": candidate.tool_name,
                        "structured_result": {
                            "success": execution.success,
                            "error_code": execution.error_code,
                            "receipt": receipt.model_dump(mode="json"),
                            "verification": verification.model_dump(mode="json"),
                        },
                    }
                )
                run.state_version += 1
                self.repository.save(run)
                self._event(run, "evidence", "ACTION_EVIDENCE_PERSISTED", "Action과 Verifier Evidence를 복구 전에 영속화했습니다.", {"sequence": action.sequence})

                action_mutation = self._mutation_possible(candidate, execution)
                mutation_possible = mutation_possible or action_mutation
                if action_mutation:
                    recovery_candidate = recovery_candidate or candidate
                self._confirm_capabilities(run, verification)

                if action_mutation and not request.reset_after_run:
                    run.status = "COMPLETED"
                    run.final_result = "STATE_PRESERVED"
                    run.termination_reason = "STATE_PRESERVED_RESET_DISABLED"
                    break
                if verification.status == "REJECTED":
                    run.status = "FAILED"
                    run.error_code = "VERIFICATION_REJECTED"
                    run.termination_reason = "VERIFICATION_REJECTED"
                    break
                if verification.status == "INCONCLUSIVE":
                    run.status = "BLOCKED"
                    run.error_code = "VERIFICATION_INCONCLUSIVE"
                    run.termination_reason = "VERIFICATION_INCONCLUSIVE"
                    break

                run.budget.no_progress_iterations = run.budget.no_progress_iterations + 1 if fingerprint == last_fingerprint else 0
                last_fingerprint = fingerprint
        except Exception as exc:
            run.status = "FAILED"
            run.error_code = "HARNESS_ERROR"
            run.termination_reason = "HARNESS_ERROR"
            safe_error, _ = redact(str(exc))
            self._event(run, "harness", "RUN_FAILED", "예상하지 못한 Harness 오류로 실행을 중단했습니다.", {"error_type": type(exc).__name__, "error": safe_error})

        self._recover(run, mutation_possible, recovery_candidate)
        return self._finish(run)

    def _execute_with_retry(self, run, executor, candidate, idempotency_key) -> ToolExecution:
        attempts = 0
        run.state["current_idempotency_key"] = idempotency_key
        while True:
            run.budget.used_tool_calls += 1
            try:
                execution = executor.execute(run.run_id, candidate, run.state)
            except TimeoutError as exc:
                execution = ToolExecution(success=False, output="Tool 실행 시간이 초과되었습니다.", error_code="TIMEOUT", error_message=str(exc), retryable=True, evidence={"reset_required": True})
            except Exception as exc:
                execution = ToolExecution(success=False, output="Tool 실행 중 오류가 발생했습니다.", error_code="EXECUTION_ERROR", error_message=str(exc), retryable=False, evidence={"reset_required": True})
            if not execution.retryable or execution.error_code not in RETRYABLE_ERROR_CODES or attempts >= run.budget.max_retry_attempts:
                redacted, count = redact(execution.model_dump(mode="json"))
                if count:
                    self._event(run, "evidence", "SENSITIVE_OUTPUT_REDACTED", "Tool 결과의 민감 패턴을 저장 전에 제거했습니다.", {"redaction_count": count})
                return ToolExecution.model_validate(redacted)
            attempts += 1
            run.budget.used_retries += 1
            self._event(run, "executor", "ACTION_RETRY_SCHEDULED", "재시도 가능한 오류에 한해 제한된 재시도를 수행합니다.", {"candidate_id": candidate.candidate_id, "error_code": execution.error_code, "attempt": attempts, "idempotency_key": idempotency_key})

    def _recover(self, run: HarnessRunRecord, mutation_possible: bool, recovery_candidate: ActionCandidate | None) -> None:
        run.current_stage = "recovery"
        if not run.reset_after_run and mutation_possible:
            preserved = ResetRecord(status="STATE_PRESERVED")
            if self.components.domain == "os":
                run.environment_reset = preserved
            self._event(run, "harness", "RECOVERY_SKIPPED_STATE_PRESERVED", "reset_after_run=false이므로 첫 변경 뒤 상태를 유지하고 후속 Scenario를 중단했습니다.")
            return

        if self.components.domain == "os":
            if not mutation_possible:
                run.environment_reset = ResetRecord(status="NOT_REQUIRED", recovery_kind="environment_reinitialize")
                self._event(run, "environment_reinitializer", "ENVIRONMENT_REINITIALIZE_SKIPPED", "Action이 시작되지 않았거나 변경 가능성이 없어 환경 초기화를 생략했습니다.")
                return
            if recovery_candidate is None:
                return
            reinitializer = self._require("environment_reinitializer")
            reset = reinitializer.reinitialize(
                run.run_id,
                run.state,
                strategy_id=recovery_candidate.environment_reinitialize_strategy_id,
                baseline_version=recovery_candidate.baseline_version,
                baseline_checks=recovery_candidate.baseline_checks,
            )
            run.environment_reset = reset
            self._event(run, "environment_reinitializer", "ENVIRONMENT_REINITIALIZED", f"실험환경 전체 초기화 상태: {reset.status}", {"strategy_id": reset.strategy_id, "baseline_version": reset.baseline_version})
            if reset.status == "RESET_FAILED":
                run.status = "BLOCKED"
                run.error_code = "CAMPAIGN_STOPPED_RESET_FAILED"
                run.termination_reason = "CAMPAIGN_STOPPED_RESET_FAILED"
            return

        resetter = self._require("resetter")
        for action in reversed(run.actions):
            if not self._mutation_possible(action.candidate, action.execution):
                continue
            reset = resetter.reset(run.run_id, action.candidate, action.execution, run.state)
            if reset.recovery_kind == "none" and reset.status == "RESET":
                reset.recovery_kind = "tool_reset"
            action.reset = reset
            self._event(run, "resetter", "ACTION_RESET", f"역순 Tool Reset 상태: {reset.status}", {"candidate_id": action.candidate.candidate_id})
            if reset.status == "RESET_FAILED":
                run.status = "BLOCKED"
                run.error_code = "CAMPAIGN_STOPPED_RESET_FAILED"
                run.termination_reason = "CAMPAIGN_STOPPED_RESET_FAILED"
                break

    def _validate_frontier(self, run: HarnessRunRecord, request: HarnessRunRequest, candidates: list[ActionCandidate]) -> None:
        ids: set[str] = set()
        for candidate in candidates:
            if candidate.candidate_id in ids:
                raise ValueError("Action Frontier에 중복 candidate_id가 있습니다.")
            ids.add(candidate.candidate_id)
            if candidate.domain != self.components.domain:
                raise ValueError("Tool 등록 도메인과 Adapter 실행 도메인이 일치하지 않습니다.")
            if candidate.domain == "os":
                expected = deterministic_candidate_id(
                    policy_hash=run.state["permission_snapshot"]["snapshot_hash"],
                    domain=candidate.domain,
                    tool_name=candidate.tool_name,
                    arguments=candidate.arguments,
                    target_resource=candidate.target_resource,
                )
                if candidate.candidate_id != expected:
                    raise ValueError("OS Candidate ID가 결정적 입력에서 생성되지 않았습니다.")
            if RISK_ORDER[candidate.risk_level] > RISK_ORDER[request.risk_ceiling]:
                candidate.frontier_status = "blocked"

    @staticmethod
    def _deduplicate(candidates: list[ActionCandidate]) -> list[ActionCandidate]:
        deduplicated: list[ActionCandidate] = []
        seen: set[str] = set()
        for candidate in candidates:
            if candidate.semantic_key not in seen:
                deduplicated.append(candidate)
                seen.add(candidate.semantic_key)
        return deduplicated

    def _guard_candidate(self, run: HarnessRunRecord, request: HarnessRunRequest, candidate: ActionCandidate) -> None:
        if candidate.candidate_id not in run.state["exposed_candidate_ids"]:
            raise ValueError("Planner가 공개되지 않았거나 현재 Frontier에 없는 Candidate를 선택했습니다.")
        if candidate.frontier_status != "ready":
            raise ValueError("안전 여부가 확정되지 않은 Candidate는 실행할 수 없습니다.")
        if RISK_ORDER[candidate.risk_level] > RISK_ORDER[request.risk_ceiling]:
            raise ValueError("Candidate 위험 등급이 실행 범위 상한을 초과합니다.")
        if candidate.depends_on_candidate_id is not None:
            history = {item["candidate_id"]: item for item in run.state.get("history", [])}
            predecessor = history.get(candidate.depends_on_candidate_id)
            if predecessor is None:
                raise ValueError("SCENARIO_CHAIN_BLOCKED: 이전 단계의 실제 출력이 없습니다.")
            structured = predecessor.get("structured_result", {})
            receipt = structured.get("receipt", {})
            for argument_name, receipt_field in candidate.argument_bindings.items():
                if argument_name not in candidate.arguments or receipt_field not in receipt:
                    raise ValueError("SCENARIO_CHAIN_BLOCKED: 다단계 출력 연결이 유효하지 않습니다.")
        if candidate.domain == "os":
            assets = {item.get("asset_id") for item in run.state.get("agent_state", {}).get("assets", [])}
            if candidate.target_resource not in assets:
                raise ValueError("Candidate 대상이 정규화된 Agent State에 Grounding되지 않았습니다.")
            if not run.trust_boundary_id or not run.source_environment or not run.target_environment:
                raise ValueError("승인된 OS Trust Boundary를 확정할 수 없습니다.")
            if candidate.resetter_id is not None or not candidate.environment_reinitialize_strategy_id:
                raise ValueError("OS Action 복구 계약이 환경 전체 초기화 전략과 일치하지 않습니다.")

    @staticmethod
    def _receipt(candidate: ActionCandidate, execution: ToolExecution) -> ActionReceipt:
        refs = list(execution.evidence.get("evidence_refs", []))
        evidence_id = execution.evidence.get("evidence_id")
        if isinstance(evidence_id, str):
            refs.append(evidence_id)
        changes = execution.evidence.get("actual_changes", [])
        if not isinstance(changes, list):
            changes = []
        identifiers = execution.evidence.get("created_identifiers", [])
        if not isinstance(identifiers, list):
            identifiers = []
        return ActionReceipt(execution_target=candidate.target_resource, actual_changes=changes, created_identifiers=identifiers, evidence_refs=refs)

    @staticmethod
    def _mutation_possible(candidate: ActionCandidate, execution: ToolExecution) -> bool:
        if not candidate.changes_state:
            return False
        if execution.error_code in NON_MUTATING_ERRORS:
            return False
        explicit = execution.evidence.get("reset_required")
        if isinstance(explicit, bool):
            return explicit
        return execution.success or execution.error_code in {"TIMEOUT", "EXECUTION_ERROR"}

    @staticmethod
    def _confirm_capabilities(run: HarnessRunRecord, verification: VerificationRecord) -> None:
        if verification.status != "VERIFIED":
            return
        for capability in run.state.get("agent_state", {}).get("capabilities", []):
            if capability.get("status") == "inferred" and capability.get("runtime_condition") is True:
                capability["status"] = "confirmed"
                capability["evidence_refs"] = list(verification.evidence_refs)

    def _require(self, name: str):
        component = getattr(self.components, name)
        if component is None:
            raise RuntimeError(f"필수 Harness 구성요소가 없습니다: {name}")
        return component

    @staticmethod
    def _selected_candidate(candidates: list[ActionCandidate], candidate_id: str | None) -> ActionCandidate:
        for candidate in candidates:
            if candidate.candidate_id == candidate_id:
                return candidate.model_copy(deep=True)
        raise ValueError("Planner가 현재 Frontier에 없는 Candidate를 선택했습니다.")

    @staticmethod
    def _budget_termination(run: HarnessRunRecord, started: float) -> str | None:
        if monotonic() - started >= run.budget.max_elapsed_seconds:
            return "TIME_BUDGET_EXHAUSTED"
        if run.budget.used_iterations >= run.budget.max_iterations:
            return "ITERATION_BUDGET_EXHAUSTED"
        if run.budget.used_tool_calls >= run.budget.max_tool_calls:
            return "TOOL_BUDGET_EXHAUSTED"
        if run.budget.no_progress_iterations >= run.budget.max_no_progress_iterations:
            return "NO_PROGRESS"
        return None

    def _finish(self, run: HarnessRunRecord) -> HarnessRunRecord:
        run.current_stage = "finished"
        run.completed_at = utc_now()
        if run.final_result is None:
            run.final_result = "SUCCESS" if run.status == "COMPLETED" else "FAILURE" if run.status == "FAILED" else "INCONCLUSIVE"
        self._event(run, "harness", "RUN_FINISHED", f"Harness 종료 상태: {run.status}", {"termination_reason": run.termination_reason, "error_code": run.error_code})
        if self.evidence_writer is not None:
            try:
                bundle, manifest = self.evidence_writer.write(run)
                run.evidence_bundle_path = str(bundle)
                run.evidence_manifest = manifest
            except Exception as exc:
                run.status = "FAILED"
                run.final_result = "FAILURE"
                run.error_code = "EVIDENCE_BUNDLE_ERROR"
                run.termination_reason = "EVIDENCE_BUNDLE_ERROR"
                self._event(run, "evidence", "EVIDENCE_BUNDLE_FAILED", "Evidence Bundle 저장에 실패했습니다.", {"error_type": type(exc).__name__})
        self.repository.save(run)
        return run

    @staticmethod
    def _event(run: HarnessRunRecord, source: str, event_type: str, message: str, payload: dict | None = None) -> None:
        run.events.append(HarnessEvent(sequence=len(run.events) + 1, source=source, event_type=event_type, message=message, payload=payload or {}))
