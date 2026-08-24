from uuid import uuid4

from .catalog import build_profile_id
from .repository import RunRepository
from .runtime_client import EnvironmentRuntime
from .schemas import (
    PROFILE_KEYS,
    RunEvent,
    RunRecord,
    RunRequest,
    RuntimeAgentResult,
    RuntimeDispatchRequest,
    utc_now,
)
from .verifiers import verify_tool


class RunCoordinator:
    """Control Backend의 Run 수명주기만 담당합니다.

    Planner, Executor, Tool은 이 클래스에 두지 않습니다. 선택 환경의 Runtime
    Agent가 반환한 원시 결과를 수집한 뒤 독립 Verifier로 최종 판정합니다.
    """

    def __init__(self, runtime: EnvironmentRuntime, repository: RunRepository) -> None:
        self.runtime = runtime
        self.repository = repository

    def run(self, request: RunRequest) -> RunRecord:
        profile_id = build_profile_id(request.subject_mode, request.permission_profile)
        changed_variables = [
            f"{key}:{'ON' if request.permission_profile[key] else 'OFF'}"
            for key in PROFILE_KEYS[request.subject_mode]
        ]
        run = RunRecord(
            run_id=f"os-{uuid4().hex[:12]}",
            status="RECEIVED",
            prompt=request.prompt,
            subject_mode=request.subject_mode,
            permission_profile=request.permission_profile,
            permissions=request.permissions,
            requested_profile=profile_id,
            changed_variable=", ".join(changed_variables),
            planner_mode="local",
        )
        try:
            self._event(
                run,
                "profile",
                "PROFILE_REQUESTED",
                "완전한 권한 프로파일 묶음을 환경 Supervisor에 요청했습니다.",
                {"profile_id": profile_id, "permission_profile": request.permission_profile},
            )
            run.status = "DISPATCHING"
            self._event(
                run,
                "supervisor",
                "RUNTIME_DISPATCHED",
                f"{request.subject_mode.value} Runtime Agent로 Run을 전달했습니다.",
            )
            result = self.runtime.execute(
                RuntimeDispatchRequest(
                    run_id=run.run_id,
                    prompt=request.prompt,
                    subject_mode=request.subject_mode,
                    permission_profile=request.permission_profile,
                    profile_id=profile_id,
                )
            )
            self._validate_runtime_response(run, result)
            self._apply_runtime_result(run, result)
            run.status = "VERIFYING"
            verification = verify_tool(run)
            run.verifier_name = verification.verifier
            run.verifier_effect = verification.checks
            run.test_result = verification.status
            self._event(
                run,
                "verifier",
                "VERIFIED",
                f"Control Backend 독립 Verifier가 단일 Runtime 결과를 {run.test_result}로 판정했습니다.",
                {"verifier": run.verifier_name, "checks": run.verifier_effect},
            )
            run.status = "COMPLETED"
        except Exception as exc:
            run.status = "FAILED"
            run.test_result = "INCONCLUSIVE"
            run.runtime_result = "error"
            run.output = str(exc)
            self._event(run, "supervisor", "RUNTIME_FAILED", str(exc))

        run.completed_at = utc_now()
        self._event(run, "verifier", "RUN_FINISHED", f"최종 상태: {run.status}")
        self.repository.save(run)
        return run

    @staticmethod
    def _validate_runtime_response(run: RunRecord, result: RuntimeAgentResult) -> None:
        if result.run_id != run.run_id:
            raise RuntimeError("Runtime Agent가 요청과 다른 run_id를 반환했습니다.")
        if result.subject_mode != run.subject_mode:
            raise RuntimeError("Runtime Agent가 요청과 다른 환경 결과를 반환했습니다.")
        if result.applied_profile != run.requested_profile:
            raise RuntimeError("Supervisor가 요청과 다른 권한 프로파일을 적용했습니다.")
        applied_values = result.applied_profile_state.get("permissions")
        if applied_values != run.permission_profile:
            raise RuntimeError("Supervisor의 실제 적용 상태가 요청 프로파일과 다릅니다.")

    @staticmethod
    def _apply_runtime_result(run: RunRecord, result: RuntimeAgentResult) -> None:
        run.applied_profile = result.applied_profile
        run.applied_profile_state = result.applied_profile_state
        run.runtime_agent = result.runtime_agent
        run.planner_mode = result.planner_mode
        run.tool = result.tool
        run.tool_arguments = result.tool_arguments
        run.policy_decision = result.policy_decision
        run.authorization_result = result.runtime_result
        run.runtime_result = result.runtime_result
        run.output = result.output
        run.exit_code = result.exit_code
        run.before_sha256 = result.before_sha256
        run.after_sha256 = result.after_sha256
        for event in result.events:
            run.events.append(event.model_copy(update={"sequence": len(run.events) + 1}))
        run.events.append(
            RunEvent(
                sequence=len(run.events) + 1,
                source="executor",
                event_type="EXECUTION_FINISHED",
                message="환경 내부 Planner·Executor·Tool이 단일 실행을 완료했습니다.",
                payload={"runtime_agent": result.runtime_agent, "tool": result.tool},
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


# 이전 import 경로와 이름을 사용하는 코드의 전환 기간을 위한 별칭입니다.
AgentExecutor = RunCoordinator
