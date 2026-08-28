from __future__ import annotations

import hashlib
import json
from collections import Counter
from uuid import uuid4

from .catalog import TRUST_BOUNDARIES, build_profile_id
from .agent_policy import AgentPolicyGate, CommandCompiler
from .repository import AgentRunRepository
from .runtime_client import EnvironmentRuntime
from .schemas import (
    AgentFinding,
    AgentPlanStep,
    AgentRunRecord,
    AgentRunRequest,
    AgentRunSummary,
    RunEvent,
    RuntimeDispatchRequest,
    RuntimeResetRequest,
    SubjectMode,
    TbResult,
    TbScenario,
    ToolDecision,
    TrustBoundaryOption,
    utc_now,
)


ATTACK_AGENT_MISSION = (
    "고정된 Host·Container 유효 권한과 Recon 증거만 사용해 EC2 내부 8개 "
    "Trust Boundary의 공격 가설을 스스로 생성하고, 실행 가능한 최고 위험 "
    "시나리오를 검증·복구한 뒤 실제 최악 경로를 선정한다."
)


def permission_profile_hash(profiles: dict[str, dict[str, bool]]) -> str:
    canonical = json.dumps(
        profiles,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


class AgentOrchestrator:
    """고정된 두 권한 프로파일로 EC2 내부 8개 TB를 모두 시험합니다."""

    def __init__(
        self,
        runtime: EnvironmentRuntime,
        repository: AgentRunRepository,
        planner_mode: str = "local",
    ) -> None:
        self.runtime = runtime
        self.repository = repository
        self.planner_mode = planner_mode
        self.policy_gate = AgentPolicyGate()
        self.command_compiler = CommandCompiler()

    def run(self, request: AgentRunRequest) -> AgentRunRecord:
        profiles = request.fixed_permission_profiles.model_dump()
        run = AgentRunRecord(
            run_id=f"os-{uuid4().hex[:12]}",
            objective=ATTACK_AGENT_MISSION,
            fixed_permission_profiles=request.fixed_permission_profiles,
            profile_hash=permission_profile_hash(profiles),
            budget=request.budget,
            planner_mode="local",
            planner_model=(request.planner_model if self.planner_mode == "openrouter" else None),
        )
        self._event(run, "profile", "PROFILE_REQUESTED", "Host와 Container 전체 권한 프로파일을 요청했습니다.")
        self._event(
            run,
            "profile",
            "PROFILE_HASH_LOCKED",
            "정규화된 두 권한 프로파일의 해시를 Run 전체에 고정했습니다.",
            {"profile_hash": run.profile_hash},
        )
        run.status = "RUNNING"
        self._event(run, "orchestrator", "AGENT_STARTED", "8개 Trust Boundary 전체 실행 Agent를 시작했습니다.")
        self.repository.save(run)
        try:
            self._recon(run)
            self._collect_infrastructure(run)
            self._analyze_and_plan(run)
            self._execute_all(run)
            if run.status != "CANCELLED":
                self._compare(run)
                run.status = "COMPLETED"
        except Exception as exc:
            run.status = "FAILED"
            self._event(
                run,
                "orchestrator",
                "RUN_FAILED",
                str(exc),
                {"stage": run.agent_stage},
            )
        run.agent_stage = "finished"
        run.completed_at = utc_now()
        self._event(run, "orchestrator", "RUN_FINISHED", f"최종 상태: {run.status}")
        self.repository.save(run)
        return run

    def rollback(self, run: AgentRunRecord) -> AgentRunRecord:
        failed = False
        for boundary in TRUST_BOUNDARIES:
            try:
                reset = self.runtime.reset_harness(
                    RuntimeResetRequest(
                        run_id=run.run_id,
                        subject_mode=boundary.source_mode,
                        trust_boundary_id=boundary.id,
                        target_environment=boundary.target_environment,
                    )
                )
                failed = failed or reset.status != "RESET"
            except Exception as exc:
                failed = True
                self._event(run, "rollback", "ROLLBACK_FAILED", str(exc), {"trust_boundary_id": boundary.id})
        run.rollback_status = "FAILED" if failed else "VERIFIED"
        self.repository.save(run)
        return run

    def _recon(self, run: AgentRunRecord) -> None:
        run.agent_stage = "recon"
        self._event(run, "recon", "RECON_STARTED", "U1과 C1의 읽기 전용 Recon을 시작했습니다.")
        snapshots: dict[str, dict] = {}
        for mode, boundary in (
            (SubjectMode.host, TRUST_BOUNDARIES[0]),
            (SubjectMode.container, TRUST_BOUNDARIES[4]),
        ):
            try:
                result = self._dispatch(
                    run,
                    boundary,
                    ToolDecision(
                        name="process.procfs",
                        action="read_cmdline",
                        resource_ref="executor-self",
                        arguments={},
                    ),
                    phase="recon",
                )
            finally:
                self._reset(run, boundary)
            if result.policy_decision != "allowed" or result.runtime_result == "error":
                raise RuntimeError(f"{mode.value} Recon을 완료하지 못했습니다: {result.output}")
            state = result.applied_profile_state
            self._event(
                run,
                "profile",
                "PROFILE_APPLIED",
                f"{mode.value} 고정 권한 프로파일을 Supervisor가 적용했습니다.",
                {"mode": mode.value, "applied_profile": result.applied_profile},
            )
            identity = state.get("effective_identity") or result.identity_before
            checks = state.get("application_checks") or {
                "permissions_match": state.get("permissions") == self._profile(run, mode)
            }
            if not all(bool(value) for value in checks.values()):
                raise RuntimeError(f"{mode.value} 유효 권한이 요청 프로파일과 일치하지 않습니다.")
            run.effective_permissions[mode.value] = identity
            run.profile_application_checks[mode.value] = checks
            warnings = state.get("profile_warnings", [])
            run.profile_warnings.extend(str(item) for item in warnings)
            snapshots[mode.value] = {
                "identity": identity,
                "mount_mode": state.get("mount_mode"),
                "network": state.get("network"),
                "target_path": state.get("target_path"),
                "docker_socket": identity.get("docker_socket", {}),
                "application_checks": checks,
                "evidence_refs": result.evidence_refs,
            }
            self._event(
                run,
                "recon",
                "RECON_OBSERVED",
                f"{mode.value} Executor의 유효 신분과 격리 상태를 관측했습니다.",
                {"mode": mode.value, "evidence_refs": result.evidence_refs},
            )
        run.recon_snapshot = {
            "scope": "single_ec2_internal",
            "executors": snapshots,
            "excluded": ["aws_control_plane", "external_internet", "other_ec2"],
        }
        self._event(run, "profile", "PROFILE_VERIFIED", "두 Executor의 요청 권한과 유효 권한이 일치합니다.")
        self.repository.save(run)

    def _collect_infrastructure(self, run: AgentRunRecord) -> None:
        run.infrastructure_snapshot = {
            "nodes": ["u1", "u2", "c1", "c2", "c3"],
            "trust_boundaries": [
                {
                    "id": boundary.id,
                    "source": boundary.source_environment.value,
                    "target": boundary.target_environment.value,
                    "action_path": (
                        boundary.source_environment.value.upper()
                        + boundary.target_environment.value.upper()
                    ),
                }
                for boundary in TRUST_BOUNDARIES
            ],
            "registered_resources": ["target-canary", "executor-self", "identity-root"],
            "implemented_tools": [
                "file.content",
                "privilege.identity_probe",
                "privilege.no_new_privs_probe",
                "process.procfs",
                "sudo.run",
            ],
        }
        self._event(run, "recon", "INFRASTRUCTURE_COLLECTED", "EC2 내부 8개 Action Path를 정규화했습니다.")

    def _analyze_and_plan(self, run: AgentRunRecord) -> None:
        run.agent_stage = "analyze"
        for index, boundary in enumerate(TRUST_BOUNDARIES, start=1):
            profile = self._profile(run, boundary.source_mode)
            unavailable = self._unavailable_high_risk(boundary.source_mode, profile)
            if unavailable is not None:
                unavailable_finding = AgentFinding(
                    finding_id=f"finding-risk-{index:03d}",
                    trust_boundary_id=boundary.id,
                    title=unavailable[0],
                    preconditions=unavailable[2],
                    impact=unavailable[1],
                    confidence=0.9,
                    evidence_refs=[f"recon:{boundary.source_mode.value}:identity"],
                    executable=False,
                    blocked_reason="해당 위험의 폐기 가능한 fixture/Impact Verifier가 아직 등록되지 않았습니다.",
                )
                run.findings.append(unavailable_finding)
                self._event(run, "analyzer", "FINDING_CREATED", unavailable_finding.title, unavailable_finding.model_dump(mode="json"))
            writable, used = self._expected_file_write(boundary.source_mode, profile)
            risk_score = 82 if writable else 34
            risk_level = "high" if writable else "low"
            finding = AgentFinding(
                finding_id=f"finding-{index:03d}",
                trust_boundary_id=boundary.id,
                title=(
                    f"{boundary.label} Target 데이터 변조 가능"
                    if writable
                    else f"{boundary.label} Target 쓰기 통제 검증 필요"
                ),
                preconditions=used,
                impact="target_data_modification",
                confidence=0.95 if writable else 0.8,
                evidence_refs=[f"recon:{boundary.source_mode.value}:identity"],
            )
            run.findings.append(finding)
            self._event(run, "analyzer", "FINDING_CREATED", finding.title, finding.model_dump(mode="json"))
            scenario = TbScenario(
                scenario_id=f"scenario-{index:03d}",
                trust_boundary_id=boundary.id,
                risk_level=risk_level,
                risk_score=risk_score,
                objective=f"{boundary.label} 전용 fixture의 무결성 영향 검증",
                impact="target_data_modification",
                steps=[
                    AgentPlanStep(step_id="observe", type="observe", tool="file.content", action="read", resource_ref="target-canary", expected_result="observed"),
                    AgentPlanStep(step_id="execute", type="execute", tool="file.content", action="write", resource_ref="target-canary", expected_result="allowed" if writable else "denied"),
                    AgentPlanStep(step_id="verify", type="verify", tool="impact.file_hash", action="compare", resource_ref="target-canary", expected_result="observed"),
                    AgentPlanStep(step_id="rollback", type="rollback", tool="fixture.reset", action="restore", resource_ref="target-canary", expected_result="restored"),
                ],
            )
            run.tb_scenarios.append(scenario)
            self._event(run, "planner", "SCENARIO_CANDIDATE_CREATED", scenario.objective, {"scenario_id": scenario.scenario_id, "risk_score": risk_score})
        run.agent_stage = "plan"
        self._event(run, "planner", "SCENARIO_SELECTED", "8개 TB 각각의 최고 실행 가능 시나리오를 선택했습니다.")
        self.repository.save(run)

    def _execute_all(self, run: AgentRunRecord) -> None:
        run.agent_stage = "execute"
        for boundary, scenario in zip(TRUST_BOUNDARIES, run.tb_scenarios, strict=True):
            stored = self.repository.get(run.run_id)
            if stored is not None and stored.status == "CANCELLED":
                run.status = "CANCELLED"
                self._event(run, "orchestrator", "RUN_CANCELLED", "사용자 요청으로 다음 TB 실행 전에 중단했습니다.")
                return
            self._event(run, "orchestrator", "TB_TEST_STARTED", f"{boundary.id} 시험을 시작했습니다.")
            self._event(run, "planner", "PLAN_CREATED", scenario.objective, {"scenario": scenario.model_dump(mode="json")})
            decision = ToolDecision(
                name="file.content",
                action="write",
                resource_ref="target-canary",
                arguments={"content": f"os-agent-{boundary.id}"},
            )
            self.policy_gate.validate(run, boundary, scenario, decision)
            self._event(run, "policy", "POLICY_ALLOWED", "구조화 Tool, TB, profile_hash, budget과 rollback을 확인했습니다.", {"trust_boundary_id": boundary.id, "profile_hash": run.profile_hash})
            compiled = self.command_compiler.compile(decision)
            self._event(
                run,
                "policy",
                "COMMAND_COMPILED",
                "file.content/write를 고정 Runtime 진입점으로 컴파일했습니다.",
                {
                    "runtime_entrypoint": compiled.runtime_entrypoint,
                    "tool": compiled.tool,
                    "action": compiled.action,
                    "resource_ref": compiled.resource_ref,
                },
            )
            try:
                result = self._dispatch(
                    run,
                    boundary,
                    decision,
                    phase="execute",
                )
            finally:
                reset = self._reset(run, boundary)
            scenario.steps[0].status = "VERIFIED"
            scenario.steps[1].status = "EXECUTED" if result.attempted else "POLICY_BLOCKED"
            scenario.steps[2].status = "VERIFIED" if result.runtime_result != "error" else "VERIFICATION_FAILED"
            scenario.steps[3].status = "COMPLETED" if reset.status == "RESET" else "ROLLBACK_FAILED"
            tb_result = self._verify_result(run, boundary, scenario, result, reset.status)
            run.tb_results.append(tb_result)
            self._event(run, "verifier", "STEP_VERIFIED", tb_result.explanation, {"proof_level": tb_result.proof_level, "evidence_refs": tb_result.evidence_refs})
            self._event(run, "verifier", "TB_VERDICT_RECORDED", f"{boundary.id}: {tb_result.verdict}", tb_result.model_dump(mode="json"))
            stored = self.repository.get(run.run_id)
            if stored is not None and stored.status == "CANCELLED":
                run.status = "CANCELLED"
                self._event(run, "orchestrator", "RUN_CANCELLED", "사용자 요청으로 현재 TB 복구 후 실행을 중단했습니다.")
                self.repository.save(run)
                return
            self.repository.save(run)

    def _compare(self, run: AgentRunRecord) -> None:
        run.agent_stage = "compare"
        counts = Counter(result.verdict for result in run.tb_results)
        run.summary = AgentRunSummary(
            broken=counts["BROKEN"],
            blocked=counts["BLOCKED"],
            inconclusive=counts["INCONCLUSIVE"],
        )
        broken = [result for result in run.tb_results if result.verdict == "BROKEN"]
        if broken:
            run.worst_case_scenario = max(broken, key=lambda item: item.risk_score).scenario
            self._event(run, "planner", "WORST_CASE_SELECTED", "실제 BROKEN 판정 중 최고 위험 경로를 선택했습니다.", {"scenario": run.worst_case_scenario.model_dump(mode="json")})
        run.rollback_status = "FAILED" if any(result.rollback_status == "FAILED" for result in run.tb_results) else "VERIFIED"

    def _dispatch(self, run: AgentRunRecord, boundary: TrustBoundaryOption, decision: ToolDecision, phase: str):
        profile = self._profile(run, boundary.source_mode)
        self._event(run, "planner", "TOOL_SELECTED", f"{decision.name}:{decision.action}", {"trust_boundary_id": boundary.id, "phase": phase})
        self._event(run, "supervisor", "RUNTIME_DISPATCHED", f"{boundary.source_environment.value.upper()} Executor에 요청했습니다.")
        result = self.runtime.execute(
            RuntimeDispatchRequest(
                run_id=run.run_id,
                action_id=f"action-{uuid4().hex[:12]}",
                prompt=(
                    "유효 권한과 격리 상태를 읽기 전용으로 관측한다."
                    if phase == "recon"
                    else f"{boundary.id}에서 {decision.name}:{decision.action}으로 계획된 영향을 검증한다."
                ),
                subject_mode=boundary.source_mode,
                trust_boundary_id=boundary.id,
                source_environment=boundary.source_environment,
                target_environment=boundary.target_environment,
                permission_profile=profile,
                profile_id=build_profile_id(boundary.source_mode, profile),
                tool_decision=decision,
                planner_mode="local",
            )
        )
        if result.run_id != run.run_id or result.trust_boundary_id != boundary.id:
            raise RuntimeError("Runtime 응답이 현재 AgentRun 또는 Trust Boundary와 일치하지 않습니다.")
        if result.applied_profile_state.get("permissions") != profile:
            raise RuntimeError("Supervisor가 고정된 권한과 다른 프로파일을 적용했습니다.")
        checks = result.applied_profile_state.get("application_checks", {})
        if checks and not all(bool(value) for value in checks.values()):
            raise RuntimeError("TB 실행 직전 유효 권한 Snapshot 검증에 실패했습니다.")
        baseline = run.effective_permissions.get(boundary.source_mode.value)
        if baseline and self._identity_fingerprint(result.identity_before) != self._identity_fingerprint(baseline):
            raise RuntimeError("TB 실행 중 유효 UID/GID/capability 프로파일이 변경됐습니다.")
        encoded_output = result.output.encode("utf-8", "replace")
        if len(encoded_output) > run.budget.max_output_bytes_per_tool:
            result.output = encoded_output[: run.budget.max_output_bytes_per_tool].decode(
                "utf-8", "ignore"
            ) + "\n[OUTPUT_TRUNCATED]"
            result.runtime_result = "error"
            result.outcome = "ERROR"
            result.evidence_refs.append("budget:output-bytes-exceeded")
        for runtime_event in result.events:
            self._event(
                run,
                runtime_event.source,
                runtime_event.event_type,
                runtime_event.message,
                runtime_event.payload,
            )
        self._event(run, "executor", "TOOL_RESULT", result.output, {"outcome": result.outcome, "action_id": result.action_id})
        return result

    def _reset(self, run: AgentRunRecord, boundary: TrustBoundaryOption):
        self._event(run, "rollback", "ROLLBACK_STARTED", f"{boundary.id} fixture 복구를 시작했습니다.")
        reset = self.runtime.reset_harness(
            RuntimeResetRequest(
                run_id=run.run_id,
                subject_mode=boundary.source_mode,
                trust_boundary_id=boundary.id,
                target_environment=boundary.target_environment,
            )
        )
        self._event(run, "rollback", "ROLLBACK_VERIFIED", f"{boundary.id}: {reset.status}", {"evidence_refs": reset.evidence_refs, "restored_state": reset.restored_state})
        return reset

    def _verify_result(self, run, boundary, scenario, result, reset_status: str) -> TbResult:
        rollback_status = "VERIFIED" if reset_status == "RESET" else "FAILED"
        evidence = list(result.evidence_refs)
        evidence.append(f"profile:{run.profile_hash}")
        changed = bool(result.changed and result.before_sha256 != result.after_sha256)
        if rollback_status == "FAILED":
            verdict, proof, explanation = "INCONCLUSIVE", "L3_IMPACTED" if changed else "L2_EXECUTED", "영향 또는 차단을 관측했지만 원상 복구를 검증하지 못했습니다."
        elif result.policy_decision == "denied" or result.outcome == "POLICY_BLOCKED":
            verdict, proof, explanation = "BLOCKED", "L1_REACHABLE", "Policy Gate가 등록되지 않은 실행을 차단했습니다."
        elif result.runtime_result == "denied":
            unavailable = any(
                finding.trust_boundary_id == boundary.id and not finding.executable
                for finding in run.findings
            )
            if unavailable:
                verdict, proof, explanation = "INCONCLUSIVE", "L2_EXECUTED", "파일 영향은 OS가 차단했지만 더 높은 위험 후보의 전용 Verifier가 없어 경계 전체를 확정하지 않았습니다."
            else:
                verdict, proof, explanation = "BLOCKED", "L2_EXECUTED", "실제 OS 권한 검사가 Target 변경을 거부했습니다."
        elif result.runtime_result == "allowed" and changed:
            verdict, proof, explanation = "BROKEN", "L4_RESTORED", "Target 상태 변경을 해시로 확인하고 fixture를 원상 복구했습니다."
        else:
            verdict, proof, explanation = "INCONCLUSIVE", "L2_EXECUTED", "Tool은 실행됐지만 L3 영향 증거가 충분하지 않습니다."
        used = [key for key, enabled in self._profile(run, boundary.source_mode).items() if enabled]
        return TbResult(
            trust_boundary_id=boundary.id,
            source_environment=boundary.source_environment,
            target_environment=boundary.target_environment,
            verdict=verdict,
            highest_impact=scenario.impact,
            attack_path=["recon", "analyze", "plan", "policy_check", "execute", "verify", "rollback"],
            fixed_permissions_used=used,
            effective_identity=result.identity_before,
            risk_score=scenario.risk_score,
            proof_level=proof,
            evidence_refs=evidence,
            rollback_status=rollback_status,
            scenario=scenario,
            runtime_result=result.runtime_result,
            explanation=explanation,
        )

    @staticmethod
    def _expected_file_write(mode: SubjectMode, profile: dict[str, bool]) -> tuple[bool, list[str]]:
        if mode == SubjectMode.host:
            used = [key for key in ("owner_write", "group_write", "dac_override") if profile[key]]
            return bool(used), used or ["host DAC blocks write"]
        bypass = [key for key in ("run_as_root", "supplementary_group", "dac_override") if profile[key]]
        used = (["mount_write"] if profile["mount_write"] else []) + bypass
        return bool(profile["mount_write"] and bypass), used or ["container mount/DAC blocks write"]

    @staticmethod
    def _unavailable_high_risk(
        mode: SubjectMode,
        profile: dict[str, bool],
    ) -> tuple[str, str, list[str]] | None:
        if mode == SubjectMode.host and profile["docker_group_access"]:
            return (
                "U1 Docker daemon 제어 가능성",
                "docker_control",
                ["docker_group_access"],
            )
        if mode == SubjectMode.container and profile["docker_socket_access"]:
            return (
                "C1 Docker socket을 통한 Host 제어 가능성",
                "container_to_host_control",
                ["docker_socket_access"],
            )
        if mode == SubjectMode.container and profile["privileged"]:
            return (
                "Privileged C1의 Host kernel 영향 가능성",
                "host_control",
                ["privileged", "run_as_root"],
            )
        if (
            mode == SubjectMode.container
            and profile["pid_namespace_host"]
            and profile["sys_ptrace_capability"]
        ):
            return (
                "Host PID 가시성과 CAP_SYS_PTRACE 조합",
                "host_process_control",
                ["pid_namespace_host", "sys_ptrace_capability"],
            )
        return None

    @staticmethod
    def _profile(run: AgentRunRecord, mode: SubjectMode) -> dict[str, bool]:
        return dict(getattr(run.fixed_permission_profiles, mode.value))

    @staticmethod
    def _identity_fingerprint(identity: dict) -> dict:
        keys = (
            "uid", "euid", "fsuid", "gid", "egid", "fsgid", "groups",
            "capabilities", "capability_sets", "no_new_privs", "seccomp_mode",
            "apparmor_profile", "docker_socket", "system_path_mounts",
        )
        return {key: identity.get(key) for key in keys if key in identity}

    @staticmethod
    def _event(run: AgentRunRecord, source: str, event_type: str, message: str, payload: dict | None = None) -> None:
        event_payload = dict(payload or {})
        event_payload["profile_hash"] = run.profile_hash
        event_payload["stage"] = run.agent_stage
        run.events.append(RunEvent(sequence=len(run.events) + 1, source=source, event_type=event_type, message=message, payload=event_payload))
