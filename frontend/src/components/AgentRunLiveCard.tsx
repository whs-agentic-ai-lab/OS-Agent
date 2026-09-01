import type { AgentRunRecord } from "../types";

interface AgentRunLiveCardProps {
  run: AgentRunRecord | null;
  monitorError?: string | null;
  onOpen: () => void;
}

const statusLabels: Record<AgentRunRecord["status"], string> = {
  RECEIVED: "실행 대기",
  RUNNING: "실시간 실행 중",
  PAUSED: "체크포인트 일시중지",
  COMPLETED: "실험 완료",
  FAILED: "실험 실패",
  CANCELLED: "실험 취소",
};

const stageLabels: Record<AgentRunRecord["agent_stage"], string> = {
  profile: "권한 프로필 고정",
  maximize: "최대 권한 적용",
  recon: "환경 정찰",
  analyze: "공격면 분석",
  plan: "Campaign 루트 생성",
  execute: "Campaign 그래프 탐색",
  compare: "최고 위험 경로 선택",
  contract: "최악 경로 고정",
  minimize: "권한 최소화",
  reverify: "최종 재검증",
  finished: "실험 종료",
};

function currentNode(run: AgentRunRecord): string {
  const current = run.campaign_search.nodes.find(
    (node) => node.node_id === run.campaign_search.current_node_id,
  );
  return current
    ? `${current.active_environment.toUpperCase()} · D${current.depth}`
    : "루트 준비 중";
}

export function AgentRunLiveCard({ run, monitorError, onOpen }: AgentRunLiveCardProps) {
  if (!run) {
    return (
      <section className="result-panel live-run-card is-empty" aria-labelledby="live-run-title">
        <span className="section-index">03</span>
        <h2 id="live-run-title">실험 실시간 모니터</h2>
        <p>실험을 시작하면 run_id를 받은 즉시 상세 모니터가 열립니다. 메인 화면에는 핵심 진행률만 표시됩니다.</p>
      </section>
    );
  }

  const isLive = run.status === "RECEIVED"
    || run.status === "RUNNING"
    || (run.status === "CANCELLED" && run.completed_at === null);
  const nodeCount = run.campaign_search.nodes.length;
  const nodeBudget = run.budget.max_campaign_nodes || 1;
  const progress = Math.min(100, Math.round((nodeCount / nodeBudget) * 100));
  const latestEvent = run.events.at(-1);

  return (
    <section className={`result-panel live-run-card is-${run.status.toLowerCase()}`} aria-labelledby="live-run-title">
      <div className="live-run-card-heading">
        <div>
          <span className="section-index">03</span>
          <h2 id="live-run-title">실험 실시간 모니터</h2>
        </div>
        <output className={`agent-run-status is-${run.status.toLowerCase()}`} aria-live="polite">
          {isLive ? <span className="live-pulse" aria-hidden="true" /> : null}
          {run.status === "CANCELLED" && run.completed_at === null ? "취소·복구 처리 중" : statusLabels[run.status]}
        </output>
      </div>

      <div className="live-run-progress-copy">
        <div>
          <span>현재 Agent 단계</span>
          <strong>{stageLabels[run.agent_stage]}</strong>
          <small>{currentNode(run)} · {nodeCount} nodes · {run.campaign_search.frontier_node_ids.length} frontier</small>
        </div>
        <b>{progress}%</b>
      </div>
      <div className="live-run-progress" role="progressbar" aria-label="Campaign 노드 예산 사용률" aria-valuemin={0} aria-valuemax={nodeBudget} aria-valuenow={nodeCount}>
        <span style={{ width: `${progress}%` }} />
      </div>

      {latestEvent ? (
        <p className="live-run-latest-event">
          <span>{latestEvent.source}</span>
          <strong>{latestEvent.event_type}</strong>
          {latestEvent.message}
        </p>
      ) : (
        <p className="live-run-latest-event">첫 Agent 이벤트를 기다리고 있습니다.</p>
      )}

      {monitorError ? <p className="live-run-retry" role="status">연결 재시도 중 · {monitorError}</p> : null}

      <button className="live-run-open-button" type="button" onClick={onOpen}>
        <span>{isLive ? "실시간 상세 보기" : "실험 결과 상세 보기"}</span>
        <span aria-hidden="true">→</span>
      </button>
      <code className="live-run-id">{run.run_id}</code>
    </section>
  );
}
