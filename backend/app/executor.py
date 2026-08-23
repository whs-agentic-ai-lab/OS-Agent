from uuid import uuid4

from .catalog import select_profile
from .host_client import HostRunner
from .planner import Planner, PlannerError
from .repository import RunRepository
from .schemas import RunEvent, RunRecord, RunRequest, utc_now
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
        selection = select_profile(
            request.subject_mode,
            request.permission_id,
            request.permission_enabled,
        )
        run = RunRecord(
            run_id=f"os-{uuid4().hex[:12]}",
            status="RECEIVED",
            prompt=request.prompt,
            subject_mode=request.subject_mode,
            permission_id=request.permission_id,
            permission_enabled=request.permission_enabled,
            requested_profile=selection.profile_id,
            changed_variable=(
                f"{request.permission_id}:{'ON' if request.permission_enabled else 'OFF'}"
            ),
            planner_mode=self.planner.mode,
        )
        try:
            self._event(run, "profile", "PROFILE_APPLYING", "고정 프로파일 적용을 시작했습니다.")
            if request.subject_mode.value == "host":
                run.applied_profile = self.host_runner.apply_profile(selection.profile_id)
            else:
                run.applied_profile = selection.profile_id
            run.status = "PROFILE_VERIFIED"
            self._event(
                run,
                "profile",
                "PROFILE_VERIFIED",
                "요청 프로파일과 적용 프로파일이 일치합니다.",
                {"profile_id": selection.profile_id},
            )
            run.status = "MODEL_CALLING"
            decision = self.planner.decide(request.prompt, selection.resource_id)
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
            run.status = "EXECUTING"
            if request.subject_mode.value == "host":
                result = self.host_runner.execute(
                    decision.name,
                    decision.arguments,
                    selection.resource_id,
                    selection.profile_id,
                )
            else:
                result = self.tool_runner.execute(
                    decision.name,
                    decision.arguments,
                    selection.resource_id,
                    request.permission_enabled,
                )
            self._apply_result(run, result)
            run.status = "VERIFYING"
            verification = verify_tool(run)
            run.test_result = verification.status
            run.verifier_name = verification.verifier
            run.verifier_effect = verification.checks
            self._event(
                run,
                "verifier",
                "VERIFIED",
                f"{verification.verifier}가 실험 결과를 {run.test_result}로 판정했습니다.",
                {
                    "verifier": verification.verifier,
                    "checks": verification.checks,
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
    def _apply_result(run: RunRecord, result: ExecutionResult) -> None:
        run.runtime_result = result.runtime_result
        run.authorization_result = result.runtime_result
        run.output = result.output
        run.exit_code = result.exit_code
        run.before_sha256 = result.before_sha256
        run.after_sha256 = result.after_sha256
        run.events.append(
            RunEvent(
                sequence=len(run.events) + 1,
                source="executor",
                event_type="EXECUTION_FINISHED",
                message=result.output,
                payload={"exit_code": result.exit_code, "runtime_result": result.runtime_result},
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
