import type { RunEvent } from "../types";

interface EventTimelineProps {
  events: RunEvent[];
}

const sourceLabels: Record<RunEvent["source"], string> = {
  profile: "Profile",
  model: "Model",
  tool_runner: "Tool runner",
  executor: "Executor",
  verifier: "Verifier",
};

export function EventTimeline({ events }: EventTimelineProps) {
  return (
    <section className="timeline-panel" aria-labelledby="timeline-title">
      <div className="section-heading compact">
        <div>
          <span className="section-index">04</span>
          <h2 id="timeline-title">로그 타임라인</h2>
        </div>
        <span className="event-count">{events.length} events</span>
      </div>

      {events.length === 0 ? (
        <p className="timeline-empty">Profile부터 Verifier까지 실행 이벤트를 순서대로 수집합니다.</p>
      ) : (
        <ol className="timeline-list">
          {events.map((event) => (
            <li key={`${event.sequence}-${event.event_type}`}>
              <span className="timeline-sequence">{String(event.sequence).padStart(2, "0")}</span>
              <div className="timeline-content">
                <div>
                  <span className="source-label">{sourceLabels[event.source]}</span>
                  <time dateTime={event.created_at}>
                    {new Intl.DateTimeFormat("ko-KR", {
                      hour: "2-digit",
                      minute: "2-digit",
                      second: "2-digit",
                    }).format(new Date(event.created_at))}
                  </time>
                </div>
                <strong>{event.event_type}</strong>
                <p>{event.message}</p>
              </div>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
