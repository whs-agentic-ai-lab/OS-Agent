import { useEffect, useMemo, useState } from "react";

import type { AgentRunRecord, TrustBoundaryOption } from "../types";
import { AgentRunResult } from "./AgentRunResult";
import { CampaignSearchTree } from "./CampaignSearchTree";

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
  "profile", "maximize", "recon", "analyze", "plan", "execute", "compare",
  "contract", "minimize", "reverify", "finished",
];

const stageLabels: Record<AgentRunRecord["agent_stage"], string> = {
  profile: "프로필 고정", maximize: "권한 적용", recon: "Recon",
  analyze: "그래프 분석", plan: "Campaign 루트", execute: "그래프 탐색",
  compare: "최고 경로 선택", contract: "경로 고정", minimize: "권한 축소",
  reverify: "재검증", finished: "종료",
};

const statusLabels: Record<AgentRunRecord["status"], string> = {
  RECEIVED: "실행 대기", RUNNING: "실시간 실행 중", PAUSED: "Frontier 보존",
  COMPLETED: "완료", FAILED: "실패", CANCELLED: "취소",
};

const sourceLabels: Record<string, string> = {
  profile: "Profile", model: "Model", tool_runner: "Tool runner", executor: "Executor",
  runtime_agent: "Runtime Agent", supervisor: "Supervisor", verifier: "Verifier",
  orchestrator: "Orchestrator", recon: "Recon", analyzer: "Analyzer", planner: "Planner",
  policy: "Policy Gate", rollback: "Resetter",
};

const eventTimeFormatter = new Intl.DateTimeFormat("ko-KR", {
  hour: "2-digit", minute: "2-digit", second: "2-digit",
});

function isLiveRun(run: AgentRunRecord): boolean {
  return run.status === "RECEIVED" || run.status === "RUNNING"
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

export function AgentRunMonitorPage(props: AgentRunMonitorPageProps) {
  const { run, runId, remote, monitorError, lastRefreshAt, onBack, onCancel, isCancelling = false } = props;
  const [now, setNow] = useState(() => Date.now());
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  useEffect(() => {
    if (!run || !isLiveRun(run)) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [run]);

  const search = run?.campaign_search;
  const activeSelectedNodeId = selectedNodeId ?? search?.current_node_id ?? search?.root_node_id ?? null;
  const selectedNode = useMemo(
    () => search?.nodes.find((node) => node.node_id === activeSelectedNodeId) ?? null,
    [activeSelectedNodeId, search?.nodes],
  );
  const selectedTransition = useMemo(
    () => search?.transitions.find((item) => item.to_node_id === selectedNode?.node_id) ?? null,
    [search?.transitions, selectedNode?.node_id],
  );
  const recentTransitions = useMemo(
    () => [...(search?.transitions ?? [])].reverse().slice(0, 16),
    [search?.transitions],
  );
  const latestEvents = useMemo(
    () => [...(run?.events ?? [])].reverse().slice(0, 120),
    [run?.events],
  );

  if (!run || !search) {
    return (
      <main className="agent-monitor-page">
        <section className="agent-monitor-loading" aria-live="polite">
          <span className="live-pulse" aria-hidden="true" />
          <div>
            <h1>실험 상태 연결 중</h1>
            <p><code>{runId}</code>의 첫 Campaign 스냅샷을 기다리고 있습니다.</p>
            {monitorError ? <p className="error-message">{monitorError} · 자동으로 다시 시도합니다.</p> : null}
          </div>
          <button type="button" onClick={onBack}>컨트롤 패널로</button>
        </section>
      </main>
    );
  }

  const live = isLiveRun(run);
  const currentStageIndex = stageOrder.indexOf(run.agent_stage);
  const nodeBudget = run.budget.max_campaign_nodes || 1;
  const budgetProgress = Math.min(100, Math.round((search.nodes.length / nodeBudget) * 100));
  const deepestVerifiedDepth = search.deepest_verified_depth
    ?? search.nodes.reduce((depth, node) => Math.max(depth, node.depth), 0);
  const maxControlledEnvironmentCount = search.max_controlled_environment_count
    ?? search.nodes.reduce((count, node) => Math.max(count, node.controlled_environments.length), 1);

  return (
    <main className="agent-monitor-page">
      <section className="agent-monitor-hero" aria-labelledby="agent-monitor-title">
        <div className="agent-monitor-hero-copy">
          <button className="monitor-back-button" type="button" onClick={onBack}>← 컨트롤 패널</button>
          <span>Campaign graph live trace</span>
          <h1 id="agent-monitor-title">에이전트 실시간 모니터</h1>
          <p>환경 상태를 노드로 만들고 Trust Boundary를 연쇄 통과하면서, 실패 경로를 가지치기하고 부모 노드로 복귀하는 전 과정을 추적합니다.</p>
          <code>{run.run_id}</code>
          {(run.status === "RECEIVED" || run.status === "RUNNING") && onCancel ? (
            <button className="monitor-cancel-button" disabled={isCancelling} type="button" onClick={onCancel}>
              {isCancelling ? "중단 요청 중" : "실험 중단"}
            </button>
          ) : null}
        </div>
        <dl className="agent-monitor-headline">
          <div><dt>상태</dt><dd className={`is-${run.status.toLowerCase()}`}>{live ? <span className="live-pulse" aria-hidden="true" /> : null}{statusLabels[run.status]}</dd></div>
          <div><dt>탐색 단계</dt><dd>{stageLabels[run.agent_stage]}</dd></div>
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
              <span>{String(index + 1).padStart(2, "0")}</span><strong>{stageLabels[stage]}</strong>
            </li>
          ))}
        </ol>
      </section>

      <section className="campaign-graph-panel" aria-labelledby="campaign-graph-title">
        <div className="monitor-section-heading">
          <div><span>Live state graph</span><h2 id="campaign-graph-title">Campaign 탐색 노드 트리</h2></div>
          <strong>{search.nodes.length} nodes · {search.frontier_node_ids.length} frontier</strong>
        </div>
        <div className="campaign-legend" aria-label="노드 상태 범례">
          <span className="is-current">현재 위치</span><span className="is-best-path">최고 위험 경로</span>
          <span className="is-pruned">가지치기</span><span className="is-rolled-back">부모 복귀</span>
        </div>
        <CampaignSearchTree onSelectNode={setSelectedNodeId} search={search} selectedNodeId={activeSelectedNodeId} />
      </section>

      <div className="agent-monitor-grid">
        <section className="agent-current-panel" aria-labelledby="agent-current-title">
          <div className="monitor-section-heading compact">
            <div><span>Selected state</span><h2 id="agent-current-title">선택 노드 상세</h2></div>
            <strong>{selectedNode?.status ?? "준비 중"}</strong>
          </div>
          {selectedNode ? (
            <>
              <div className="current-objective"><span>현재 활성 환경</span><strong>{selectedNode.active_environment.toUpperCase()}</strong><p>제어 확보: {selectedNode.controlled_environments.map((item) => item.toUpperCase()).join(" → ")}</p></div>
              <dl className="current-decision-grid">
                <div><dt>진입 경계</dt><dd><code>{selectedTransition?.trust_boundary_id ?? "ROOT"}</code></dd></div>
                <div><dt>실행 Tool</dt><dd><code>{selectedTransition ? `${selectedTransition.tool}:${selectedTransition.action}` : "초기 foothold"}</code></dd></div>
                <div><dt>누적 영향</dt><dd>{selectedNode.highest_impact} · {selectedNode.highest_impact_score}</dd></div>
                <div><dt>복구 판정</dt><dd>{selectedTransition?.rollback_status ?? "NOT_REQUIRED"}</dd></div>
              </dl>
              <div className="current-state-card">
                <div><span>깊이</span><strong>D{selectedNode.depth}</strong></div>
                <div><span>State fingerprint</span><code title={selectedNode.state_fingerprint}>{shortFingerprint(selectedNode.state_fingerprint)}</code></div>
                <div><span>우선순위</span><strong>{selectedNode.priority_score.toFixed(1)}</strong></div>
              </div>
              <div className="decision-rationale"><span>누적 Boundary 경로</span><p>{selectedNode.boundary_path.length > 0 ? selectedNode.boundary_path.join(" → ") : "Campaign root"}</p></div>
            </>
          ) : <p className="monitor-empty">Campaign 루트 노드 생성을 기다리고 있습니다.</p>}
        </section>

        <section className="agent-search-panel" aria-labelledby="agent-search-title">
          <div className="monitor-section-heading compact"><div><span>Best-first search</span><h2 id="agent-search-title">탐색 상태</h2></div><strong>{search.status}</strong></div>
          <dl className="agent-search-metrics">
            <div><dt>발견 노드</dt><dd>{search.nodes.length}</dd></div><div><dt>탐색 완료</dt><dd>{search.explored_nodes}</dd></div>
            <div><dt>현재 Frontier</dt><dd>{search.frontier_node_ids.length}</dd></div><div><dt>가지치기</dt><dd>{search.pruned_nodes}</dd></div>
            <div><dt>Tool 호출</dt><dd>{search.tool_calls_used}</dd></div><div><dt>Planner 호출</dt><dd>{search.planner_calls_used}</dd></div>
            <div><dt>최대 경로 깊이</dt><dd>D{deepestVerifiedDepth}</dd></div><div><dt>누적 제어 환경</dt><dd>{maxControlledEnvironmentCount}/5</dd></div>
            <div><dt>부모 복귀</dt><dd>{search.backtrack_count}</dd></div><div><dt>최고 영향</dt><dd>{search.best_impact_score}</dd></div>
          </dl>
          <div className="live-run-progress" role="progressbar" aria-label="Campaign 노드 예산 사용률" aria-valuemin={0} aria-valuemax={nodeBudget} aria-valuenow={search.nodes.length}><span style={{ width: `${budgetProgress}%` }} /></div>
          <div className="watchdog-state"><span>탐색 종료 조건</span><strong>{search.termination_reason ?? "Frontier 평가 중"}</strong><p>{search.termination_explanation ?? "위험도 우선순위가 가장 높은 상태를 선택해 다음 전이를 실행합니다."}</p></div>
        </section>
      </div>

      <section className="agent-decision-panel" aria-labelledby="agent-decisions-title">
        <div className="monitor-section-heading"><div><span>Transition trace</span><h2 id="agent-decisions-title">최근 경계 전이와 복구</h2></div><strong>{recentTransitions.length} recent transitions</strong></div>
        {recentTransitions.length > 0 ? (
          <ol className="agent-decision-list">
            {recentTransitions.map((transition) => (
              <li key={transition.transition_id}>
                <span className="decision-sequence">{transition.sequence}</span>
                <div className="decision-tool"><small>{transition.trust_boundary_id}</small><strong>{transition.tool}:{transition.action}</strong><code>{transition.source_environment.toUpperCase()} → {transition.target_environment.toUpperCase()}</code></div>
                <p>{transition.prune_reason ?? `${transition.impact} 영향 ${transition.impact_score} · ${transition.outcome ?? "실행 대기"}`}</p>
                <div className="decision-state"><span>{transition.status}</span><code>Rollback · {transition.rollback_status}</code></div>
              </li>
            ))}
          </ol>
        ) : <p className="monitor-empty">첫 Trust Boundary 전이 실행을 기다리고 있습니다.</p>}
      </section>

      <section className="agent-event-panel" aria-labelledby="agent-events-title">
        <div className="monitor-section-heading"><div><span>Live event stream</span><h2 id="agent-events-title">최신 Agent 이벤트</h2></div><strong>{run.events.length} events</strong></div>
        {latestEvents.length > 0 ? (
          <ol className="agent-live-event-list" aria-live="polite">
            {latestEvents.map((event) => (
              <li key={`${event.sequence}-${event.event_type}`}><span className="event-sequence">#{event.sequence}</span><div>
                <header><span>{sourceLabels[event.source] ?? event.source}</span><time dateTime={event.created_at}>{eventTimeFormatter.format(new Date(event.created_at))}</time></header>
                <strong>{event.event_type}</strong><p>{event.message}</p>
                {Object.keys(event.payload).length > 0 ? <details><summary>payload 보기</summary><pre>{JSON.stringify(event.payload, null, 2)}</pre></details> : null}
              </div></li>
            ))}
          </ol>
        ) : <p className="monitor-empty">첫 이벤트를 기다리고 있습니다.</p>}
      </section>

      {!live ? <section className="agent-final-result" aria-label="완료된 Campaign 결과"><AgentRunResult run={run} /></section> : null}
    </main>
  );
}
