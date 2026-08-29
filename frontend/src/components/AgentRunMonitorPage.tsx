import { useEffect, useMemo, useState } from "react";

import type {
  AgentPlanStep,
  AgentRunRecord,
  AgentSearchState,
  TbScenario,
  TrustBoundaryOption,
} from "../types";
import { AgentRunResult } from "./AgentRunResult";

interface AgentRunMonitorPageProps {
  run: AgentRunRecord | null;
  runId: string;
  remote: boolean;
  boundaries: TrustBoundaryOption[];
  monitorError: string | null;
  lastRefreshAt: Date | null;
  onBack: () => void;
  onCancel?: () => void;
  onResume?: () => void;
  isCancelling?: boolean;
  isResuming?: boolean;
}

const stageOrder: AgentRunRecord["agent_stage"][] = [
  "profile",
  "maximize",
  "recon",
  "analyze",
  "plan",
  "execute",
  "compare",
  "contract",
  "minimize",
  "reverify",
  "finished",
];

const stageLabels: Record<AgentRunRecord["agent_stage"], string> = {
  profile: "프로필 고정",
  maximize: "권한 최대화",
  recon: "Recon",
  analyze: "분석",
  plan: "계획",
  execute: "체인 실행",
  compare: "TB 비교",
  contract: "경로 고정",
  minimize: "권한 축소",
  reverify: "재검증",
  finished: "종료",
};

const statusLabels: Record<AgentRunRecord["status"], string> = {
  RECEIVED: "실행 대기",
  RUNNING: "실시간 실행 중",
  PAUSED: "체크포인트 일시중지",
  COMPLETED: "완료",
  FAILED: "실패",
  CANCELLED: "취소",
};

const sourceLabels: Record<string, string> = {
  profile: "Profile",
  model: "Model",
  tool_runner: "Tool runner",
  executor: "Executor",
  runtime_agent: "Runtime Agent",
  supervisor: "Supervisor",
  verifier: "Verifier",
  orchestrator: "Orchestrator",
  recon: "Recon",
  analyzer: "Analyzer",
  planner: "Planner",
  policy: "Policy Gate",
  rollback: "Rollback",
};

const eventTimeFormatter = new Intl.DateTimeFormat("ko-KR", {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
});

function isLiveRun(run: AgentRunRecord): boolean {
  return run.status === "RECEIVED"
    || run.status === "RUNNING"
    || (run.status === "CANCELLED" && run.completed_at === null);
}

function formatElapsed(startedAt: string, endedAt: string | null, now: number): string {
  const start = new Date(startedAt).getTime();
  const end = endedAt ? new Date(endedAt).getTime() : now;
  if (!Number.isFinite(start) || !Number.isFinite(end)) return "—";
  const totalSeconds = Math.max(0, Math.floor((end - start) / 1000));
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  return hours > 0
    ? `${hours}시간 ${String(minutes).padStart(2, "0")}분 ${String(seconds).padStart(2, "0")}초`
    : `${minutes}분 ${String(seconds).padStart(2, "0")}초`;
}

function shortFingerprint(value?: string): string {
  if (!value) return "아직 없음";
  return value.length > 22 ? `${value.slice(0, 11)}…${value.slice(-8)}` : value;
}

function searchTotals(scenarios: TbScenario[]): AgentSearchState {
  return scenarios.reduce<AgentSearchState>((total, scenario) => {
    const search = scenario.search;
    if (!search) return total;
    return {
      ...total,
      discovered_states: total.discovered_states + search.discovered_states,
      explored_states: total.explored_states + search.explored_states,
      unique_transitions: total.unique_transitions + search.unique_transitions,
      repeated_states: total.repeated_states + search.repeated_states,
      frontier_candidates: total.frontier_candidates + search.frontier_candidates,
      policy_pruned_candidates: total.policy_pruned_candidates + search.policy_pruned_candidates,
      tool_calls_used: total.tool_calls_used + search.tool_calls_used,
      planner_calls_used: (total.planner_calls_used ?? 0) + (search.planner_calls_used ?? 0),
      automatic_extensions: total.automatic_extensions + search.automatic_extensions,
    };
  }, {
    status: "PENDING",
    discovered_states: 0,
    explored_states: 0,
    unique_transitions: 0,
    repeated_states: 0,
    frontier_candidates: 0,
    policy_pruned_candidates: 0,
    tool_calls_used: 0,
    planner_calls_used: 0,
    automatic_extensions: 0,
    termination_reason: null,
    termination_explanation: null,
    search_complete: false,
    budget_exhausted: false,
    resume_available: false,
    checkpoint_id: null,
  });
}

function stepState(step: AgentPlanStep | undefined): { version: number | null; fingerprint: string } {
  const state = step?.state_after ?? step?.state_before;
  return {
    version: typeof state?.version === "number" ? state.version : null,
    fingerprint: typeof state?.fingerprint === "string" ? state.fingerprint : "",
  };
}

export function AgentRunMonitorPage({
  run,
  runId,
  remote,
  boundaries,
  monitorError,
  lastRefreshAt,
  onBack,
  onCancel,
  onResume,
  isCancelling = false,
  isResuming = false,
}: AgentRunMonitorPageProps) {
  const [now, setNow] = useState(() => Date.now());
  const [selectedBoundaryId, setSelectedBoundaryId] = useState<string | null>(null);

  useEffect(() => {
    if (!run || !isLiveRun(run)) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [run]);

  const currentScenario = useMemo(() => {
    if (!run) return null;
    return run.tb_scenarios.find((scenario) => scenario.chain_status === "RUNNING")
      ?? [...run.tb_scenarios].reverse().find((scenario) => scenario.chain_status !== "PENDING")
      ?? run.tb_scenarios[0]
      ?? null;
  }, [run]);

  const selectedScenario = useMemo(() => {
    if (!run) return null;
    return run.tb_scenarios.find((scenario) => scenario.trust_boundary_id === selectedBoundaryId)
      ?? currentScenario;
  }, [currentScenario, run, selectedBoundaryId]);

  const decisions = useMemo(() => {
    if (!run) return [];
    return run.tb_scenarios
      .flatMap((scenario) => scenario.steps
        .filter((step) => step.type === "execute")
        .map((step) => ({ boundaryId: scenario.trust_boundary_id, step })))
      .reverse()
      .slice(0, 12);
  }, [run]);

  const totals = useMemo(() => searchTotals(run?.tb_scenarios ?? []), [run]);
  const latestEvents = useMemo(() => [...(run?.events ?? [])].reverse().slice(0, 120), [run]);
  const currentStep = currentScenario
    ? [...currentScenario.steps].reverse().find((step) => step.type === "execute") ?? currentScenario.steps.at(-1)
    : undefined;
  const currentState = stepState(currentStep);
  const currentStageIndex = run ? stageOrder.indexOf(run.agent_stage) : -1;

  if (!run) {
    return (
      <main className="agent-monitor-page">
        <section className="agent-monitor-loading" aria-live="polite">
          <span className="live-pulse" aria-hidden="true" />
          <div>
            <h1>실험 상태 연결 중</h1>
            <p><code>{runId}</code>의 첫 상태 스냅샷을 기다리고 있습니다.</p>
            {monitorError ? <p className="error-message">{monitorError} · 자동으로 다시 시도합니다.</p> : null}
          </div>
          <button type="button" onClick={onBack}>컨트롤 패널로</button>
        </section>
      </main>
    );
  }

  const completedCount = Math.min(8, run.tb_results.length);
  const live = isLiveRun(run);
  const availableBoundaries = boundaries.length > 0
    ? boundaries
    : run.tb_scenarios.map((scenario) => ({
        id: scenario.trust_boundary_id,
        label: scenario.trust_boundary_id,
        boundary_type: "HH" as const,
        source_mode: "host" as const,
        source_environment: "u1" as const,
        target_environment: "u2" as const,
        description: scenario.objective,
      }));

  return (
    <main className="agent-monitor-page">
      <section className="agent-monitor-hero" aria-labelledby="agent-monitor-title">
        <div className="agent-monitor-hero-copy">
          <button className="monitor-back-button" type="button" onClick={onBack}>← 컨트롤 패널</button>
          <span>Experiment live trace</span>
          <h1 id="agent-monitor-title">에이전트 실시간 모니터</h1>
          <p>공격 Agent가 지금 무엇을 보고, 어떤 Tool을 왜 선택하고, 상태를 어떻게 누적하는지 한 실험 단위로 추적합니다.</p>
          <code>{run.run_id}</code>
          {(run.status === "RECEIVED" || run.status === "RUNNING") && onCancel ? (
            <button className="monitor-cancel-button" disabled={isCancelling} type="button" onClick={onCancel}>
              {isCancelling ? "중단 요청 중" : "실험 중단"}
            </button>
          ) : null}
        </div>
        <dl className="agent-monitor-headline">
          <div>
            <dt>상태</dt>
            <dd className={`is-${run.status.toLowerCase()}`}>
              {live ? <span className="live-pulse" aria-hidden="true" /> : null}
              {run.status === "CANCELLED" && run.completed_at === null ? "취소·복구 처리 중" : statusLabels[run.status]}
            </dd>
          </div>
          <div><dt>현재 단계</dt><dd>{stageLabels[run.agent_stage]}</dd></div>
          <div><dt>경과 시간</dt><dd>{formatElapsed(run.created_at, run.completed_at, now)}</dd></div>
          <div><dt>실행 위치</dt><dd>{remote ? "EC2 · SSM" : "로컬 Runtime"}</dd></div>
        </dl>
      </section>

      <div className="agent-monitor-refresh" role="status">
        <span>{live ? "1초 간격 자동 갱신" : "최종 스냅샷"}</span>
        <span>{lastRefreshAt ? `${eventTimeFormatter.format(lastRefreshAt)} 갱신` : "동기화 중"}</span>
        {monitorError ? <strong>연결 재시도 중 · {monitorError}</strong> : null}
      </div>

      <section className="agent-stage-panel" aria-labelledby="agent-stage-title">
        <div className="monitor-section-heading">
          <div><span>Agent pipeline</span><h2 id="agent-stage-title">현재 Agent 단계</h2></div>
          <strong>{currentStageIndex + 1}/{stageOrder.length}</strong>
        </div>
        <ol className="agent-stage-track">
          {stageOrder.map((stage, index) => (
            <li className={index < currentStageIndex ? "is-complete" : index === currentStageIndex ? "is-current" : "is-pending"} key={stage}>
              <span>{String(index + 1).padStart(2, "0")}</span>
              <strong>{stageLabels[stage]}</strong>
            </li>
          ))}
        </ol>
      </section>

      <section className="agent-tb-panel" aria-labelledby="agent-tb-title">
        <div className="monitor-section-heading">
          <div><span>8 Trust Boundaries</span><h2 id="agent-tb-title">경계별 진행 상황</h2></div>
          <strong>{completedCount}/8 판정 완료</strong>
        </div>
        <div className="agent-tb-progress" role="progressbar" aria-valuemin={0} aria-valuemax={8} aria-valuenow={completedCount}>
          <span style={{ width: `${(completedCount / 8) * 100}%` }} />
        </div>
        <div className="agent-tb-grid">
          {availableBoundaries.map((boundary, index) => {
            const scenario = run.tb_scenarios.find((item) => item.trust_boundary_id === boundary.id);
            const result = run.tb_results.find((item) => item.trust_boundary_id === boundary.id);
            const status = result?.verdict ?? scenario?.chain_status ?? "PENDING";
            const active = scenario?.trust_boundary_id === currentScenario?.trust_boundary_id;
            const selected = scenario?.trust_boundary_id === selectedScenario?.trust_boundary_id;
            return (
              <button
                className={`agent-tb-tile is-${status.toLowerCase()}${active ? " is-active" : ""}${selected ? " is-selected" : ""}`}
                disabled={!scenario}
                key={boundary.id}
                onClick={() => setSelectedBoundaryId(boundary.id)}
                type="button"
              >
                <span>{String(index + 1).padStart(2, "0")}</span>
                <strong>{boundary.id}</strong>
                <small>{boundary.label}</small>
                <b>{active ? "NOW · " : ""}{status}</b>
              </button>
            );
          })}
        </div>
      </section>

      <div className="agent-monitor-grid">
        <section className="agent-current-panel" aria-labelledby="agent-current-title">
          <div className="monitor-section-heading compact">
            <div><span>Current decision</span><h2 id="agent-current-title">현재 공격 판단</h2></div>
            <strong>{currentScenario?.trust_boundary_id ?? "준비 중"}</strong>
          </div>
          {currentScenario ? (
            <>
              <div className="current-objective">
                <span>Agent 목표</span>
                <strong>{currentScenario.objective}</strong>
                <p>{currentScenario.impact}</p>
              </div>
              <dl className="current-decision-grid">
                <div><dt>선택 Tool</dt><dd><code>{currentStep ? `${currentStep.tool}:${currentStep.action}` : "Planner 선택 대기"}</code></dd></div>
                <div><dt>대상</dt><dd><code>{currentStep?.resource_ref ?? "—"}</code></dd></div>
                <div><dt>정책 판정</dt><dd>{currentStep?.policy_decision ?? "검사 전"}</dd></div>
                <div><dt>실행/검증</dt><dd>{currentStep?.execution_status ?? "대기"} · {currentStep?.verification_status ?? "대기"}</dd></div>
              </dl>
              <div className="decision-rationale">
                <span>Planner 선택 이유</span>
                <p>{currentStep?.selection_rationale || "Recon과 현재 누적 상태를 바탕으로 다음 Tool을 선택하고 있습니다."}</p>
              </div>
              <div className="current-state-card">
                <div><span>누적 상태 버전</span><strong>v{currentState.version ?? 0}</strong></div>
                <div><span>State fingerprint</span><code title={currentState.fingerprint}>{shortFingerprint(currentState.fingerprint)}</code></div>
                <div><span>상태 변화</span><strong>{currentStep?.state_changes?.length ?? 0}개</strong></div>
              </div>
              {currentStep?.state_changes && currentStep.state_changes.length > 0 ? (
                <ul className="current-state-changes">
                  {currentStep.state_changes.map((change, index) => (
                    <li key={`${change.key}-${index}`}><code>{change.key}</code><span>{String(change.before)} → {String(change.after)}</span></li>
                  ))}
                </ul>
              ) : null}
            </>
          ) : <p className="monitor-empty">Recon 및 TB 시나리오 생성을 기다리고 있습니다.</p>}
        </section>

        <section className="agent-search-panel" aria-labelledby="agent-search-title">
          <div className="monitor-section-heading compact">
            <div><span>Search & watchdog</span><h2 id="agent-search-title">탐색 상태</h2></div>
            <strong>{selectedScenario?.search?.status ?? "PENDING"}</strong>
          </div>
          <dl className="agent-search-metrics">
            <div><dt>Tool 호출</dt><dd>{totals.tool_calls_used}</dd></div>
            <div><dt>Planner 호출</dt><dd>{totals.planner_calls_used ?? 0}</dd></div>
            <div><dt>발견 상태</dt><dd>{totals.discovered_states}</dd></div>
            <div><dt>고유 전이</dt><dd>{totals.unique_transitions}</dd></div>
            <div><dt>현재 Frontier</dt><dd>{totals.frontier_candidates}</dd></div>
            <div><dt>중복 제거</dt><dd>{totals.repeated_states}</dd></div>
            <div><dt>Policy 제외</dt><dd>{totals.policy_pruned_candidates}</dd></div>
            <div><dt>자동 확장</dt><dd>{totals.automatic_extensions}</dd></div>
          </dl>
          <div className="watchdog-state">
            <span>선택 TB 탐색 판단</span>
            <strong>{selectedScenario?.search?.termination_reason ?? (selectedScenario?.chain_status === "RUNNING" ? "최악 영향 탐색 중" : "종료 판단 대기")}</strong>
            <p>{selectedScenario?.search?.termination_explanation ?? "Agent가 현재 상태에서 실행할 최적 후보를 계속 비교합니다."}</p>
            {selectedScenario?.search?.checkpoint_id ? <code>{selectedScenario.search.checkpoint_id}</code> : null}
          </div>
        </section>
      </div>

      <section className="agent-decision-panel" aria-labelledby="agent-decisions-title">
        <div className="monitor-section-heading">
          <div><span>Planner trace</span><h2 id="agent-decisions-title">최근 Tool 선택과 상태 전이</h2></div>
          <strong>{decisions.length} recent decisions</strong>
        </div>
        {decisions.length > 0 ? (
          <ol className="agent-decision-list">
            {decisions.map(({ boundaryId, step }) => {
              const state = stepState(step);
              return (
                <li key={`${boundaryId}-${step.step_id}`}>
                  <span className="decision-sequence">{step.sequence ?? "—"}</span>
                  <div className="decision-tool"><small>{boundaryId}</small><strong>{step.tool}:{step.action}</strong><code>{step.resource_ref}</code></div>
                  <p>{step.selection_rationale || "선택 근거 기록 대기"}</p>
                  <div className="decision-state"><span>{step.status}</span><code>v{state.version ?? 0} · {shortFingerprint(state.fingerprint)}</code></div>
                </li>
              );
            })}
          </ol>
        ) : <p className="monitor-empty">Planner의 첫 실행 Tool 선택을 기다리고 있습니다.</p>}
      </section>

      <section className="agent-event-panel" aria-labelledby="agent-events-title">
        <div className="monitor-section-heading">
          <div><span>Live event stream</span><h2 id="agent-events-title">최신 Agent 이벤트</h2></div>
          <strong>{run.events.length} events</strong>
        </div>
        {latestEvents.length > 0 ? (
          <ol className="agent-live-event-list" aria-live="polite">
            {latestEvents.map((event) => (
              <li key={`${event.sequence}-${event.event_type}`}>
                <span className="event-sequence">#{event.sequence}</span>
                <div>
                  <header><span>{sourceLabels[event.source] ?? event.source}</span><time dateTime={event.created_at}>{eventTimeFormatter.format(new Date(event.created_at))}</time></header>
                  <strong>{event.event_type}</strong>
                  <p>{event.message}</p>
                  {Object.keys(event.payload).length > 0 ? (
                    <details><summary>payload 보기</summary><pre>{JSON.stringify(event.payload, null, 2)}</pre></details>
                  ) : null}
                </div>
              </li>
            ))}
          </ol>
        ) : <p className="monitor-empty">첫 이벤트를 기다리고 있습니다.</p>}
      </section>

      {!live ? (
        <section className="agent-final-result" aria-label="완료된 실험 통합 결과">
          <AgentRunResult run={run} onResume={onResume} isResuming={isResuming} />
        </section>
      ) : null}
    </main>
  );
}
