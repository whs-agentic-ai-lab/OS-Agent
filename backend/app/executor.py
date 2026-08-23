from uuid import uuid4

from .catalog import ProfileSelection, select_profiles
from .host_client import HostRunner
from .planner import Planner, PlannerError
from .repository import RunRepository
from .schemas import PermissionRunResult, RunEvent, RunRecord, RunRequest, utc_now
from .tools import ExecutionResult, ToolRunner
from .verifiers import verify_tool


class AgentExecutor:
    def __init__(
        self,
        planner: Planner,
        tool_runner: ToolRunner,
        repository: RunRepository,
        host_runner: HostRunner,
    ) -> None:
        self.planner = planner
        self.tool_runner = tool_runner
        self.repository = repository
        self.host_runner = host_runner

    def run(self, request: RunRequest) -> RunRecord:
        selections = select_profiles(request.subject_mode, request.permissions)
        profile_ids = [item.profile_id for item in selections]
        changed_variables = [
            f"{item.permission_id}:{'ON' if item.enabled else 'OFF'}"
            for item in selections
        ]
        first = selections[0]
        run = RunRecord(
            run_id=f"os-{uuid4().hex[:12]}",
            status="RECEIVED",
            prompt=request.prompt,
            subject_mode=request.subject_mode,
            permission_id=first.permission_id,
            permission_enabled=first.enabled,
            permissions=request.permissions,
            requested_profile=", ".join(profile_ids),
            changed_variable=", ".join(changed_variables),
            planner_mode=self.planner.mode,
        )
        try:
            self._event(run, "profile", "PROFILE_APPLYING", "고정 프로파일 적용을 시작했습니다.")
            run.status = "MODEL_CALLING"
            decision = self.planner.decide(request.prompt, first.resource_id)
            run.tool = decision.name
            self._event(
                run,
                "model",
                "TOOL_REQUESTED",
                f"{decision.name} Tool Call을 받았습니다.",
                {"tool": decision.name, "arguments": decision.arguments},
            )
            self._event(run, "tool_runner", "TOOL_ALLOWED", "Tool schema와 Resource ID를 검증합니다.")
            run.policy_decision = "allowed"
            executions = [
                {
                    "tool": decision.name,
                    "arguments": self._arguments_for_resource(
                        decision.name, decision.arguments, item.resource_id
                    ),
                    "expected_resource_id": item.resource_id,
                }
                for item in selections
            ]
            run.status = "EXECUTING"
            if request.subject_mode.value == "host":
                if len(selections) == 1 and not hasattr(self.host_runner, "execute_integrated"):
                    run.applied_profile = self.host_runner.apply_profile(first.profile_id)
                    results = [self.host_runner.execute(
                        decision.name, executions[0]["arguments"], first.resource_id, first.profile_id
                    )]
                else:
                    applied_profiles, results = self.host_runner.execute_integrated(
                        profile_ids, executions
                    )
                    run.applied_profile = ", ".join(applied_profiles)
            else:
                run.applied_profile = ", ".join(profile_ids)
                results = [
                    self.tool_runner.execute(
                        decision.name,
                        execution["arguments"],
                        selection.resource_id,
                        selection.enabled,
                    )
                    for selection, execution in zip(selections, executions, strict=True)
                ]
            run.status = "PROFILE_VERIFIED"
            self._event(
                run,
                "profile",
                "PROFILE_VERIFIED",
                "선택한 권한 조합이 하나의 통합 프로파일로 적용되었습니다.",
                {"profile_ids": profile_ids},
            )
            run.status = "VERIFYING"
            run.permission_results = [
                self._permission_result(run, selection, result)
                for selection, result in zip(selections, results, strict=True)
            ]
            self._apply_aggregate(run)
            self._event(
                run,
                "verifier",
                "VERIFIED",
                f"통합 권한 검증기가 {len(run.permission_results)}개 결과를 {run.test_result}로 판정했습니다.",
                {
                    "verifier": run.verifier_name,
                    "checks": run.verifier_effect,
                },
            )
            run.status = "COMPLETED"
        except PlannerError as exc:
            run.status = "INCONCLUSIVE"
            run.test_result = "INCONCLUSIVE"
            run.output = str(exc)
            self._event(run, "model", "MODEL_INVALID", str(exc))
        except Exception as exc:
            run.status = "FAILED"
            run.test_result = "INCONCLUSIVE"
            run.output = str(exc)
            run.runtime_result = "error"
            profile_failed = run.applied_profile is None
            if not profile_failed:
                run.policy_decision = "denied"
                run.authorization_result = "error"
            self._event(
                run,
                "profile" if profile_failed else "tool_runner",
                "PROFILE_FAILED" if profile_failed else "TOOL_DENIED",
                str(exc),
            )

        run.completed_at = utc_now()
        self._event(run, "verifier", "RUN_FINISHED", f"최종 상태: {run.status}")
        self.repository.save(run)
        return run

    @staticmethod
    def _arguments_for_resource(
        tool: str, arguments: dict, resource_id: str
    ) -> dict:
        if tool == "service_status":
            return {"service_id": "nginx-target"}
        updated = {**arguments, "resource_id": resource_id}
        return updated

    @staticmethod
    def _permission_result(
        run: RunRecord, selection: ProfileSelection, result: ExecutionResult
    ) -> PermissionRunResult:
        candidate = run.model_copy(
            deep=True,
            update={
                "permission_id": selection.permission_id,
                "permission_enabled": selection.enabled,
                "requested_profile": selection.profile_id,
                "applied_profile": selection.profile_id,
                "runtime_result": result.runtime_result,
                "output": result.output,
                "exit_code": result.exit_code,
                "before_sha256": result.before_sha256,
                "after_sha256": result.after_sha256,
            },
        )
        verification = verify_tool(candidate)
        return PermissionRunResult(
            permission_id=selection.permission_id,
            permission_enabled=selection.enabled,
            requested_profile=selection.profile_id,
            applied_profile=selection.profile_id,
            resource_id=selection.resource_id,
            runtime_result=result.runtime_result,
            output=result.output,
            exit_code=result.exit_code,
            before_sha256=result.before_sha256,
            after_sha256=result.after_sha256,
            verifier_name=verification.verifier,
            verifier_effect=verification.checks,
            test_result=verification.status,
        )

    @staticmethod
    def _apply_aggregate(run: RunRecord) -> None:
        statuses = [item.test_result for item in run.permission_results]
        run.test_result = (
            "FAIL" if "FAIL" in statuses
            else "INCONCLUSIVE" if "INCONCLUSIVE" in statuses
            else "PASS"
        )
        if len(run.permission_results) == 1:
            item = run.permission_results[0]
            run.runtime_result = item.runtime_result
            run.exit_code = item.exit_code
            run.output = item.output
            run.before_sha256 = item.before_sha256
            run.after_sha256 = item.after_sha256
            run.authorization_result = item.runtime_result or "error"
            run.verifier_name = item.verifier_name
            run.verifier_effect = item.verifier_effect
        else:
            runtime_results = {item.runtime_result for item in run.permission_results}
            run.runtime_result = next(iter(runtime_results)) if len(runtime_results) == 1 else None
            exit_codes = {item.exit_code for item in run.permission_results}
            run.exit_code = next(iter(exit_codes)) if len(exit_codes) == 1 else None
            run.output = "\n".join(
                f"[{item.permission_id}] {item.output or '출력 없음'}"
                for item in run.permission_results
            )
            run.before_sha256 = None
            run.after_sha256 = None
            run.authorization_result = "allowed" if run.test_result == "PASS" else "error"
            run.verifier_name = "integrated_permission_verifier"
            run.verifier_effect = {
                f"{item.permission_id}.{name}": passed
                for item in run.permission_results
                for name, passed in item.verifier_effect.items()
            }
        run.events.append(
            RunEvent(
                sequence=len(run.events) + 1,
                source="executor",
                event_type="EXECUTION_FINISHED",
                message=f"{len(run.permission_results)}개 권한 조건을 하나의 Run에서 실행했습니다.",
                payload={"permission_results": len(run.permission_results)},
            )
        )

    @staticmethod
    def _event(
        run: RunRecord,
        source: str,
        event_type: str,
        message: str,
        payload: dict | None = None,
    ) -> None:
        run.events.append(
            RunEvent(
                sequence=len(run.events) + 1,
                source=source,
                event_type=event_type,
                message=message,
                payload=payload or {},
            )
        )
