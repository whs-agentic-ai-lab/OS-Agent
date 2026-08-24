import type { RunRecord } from "../types";

interface RunResultProps {
  run: RunRecord | null;
}

function shortHash(value: string | null): string {
  return value ? `${value.slice(0, 18)}…${value.slice(-8)}` : "—";
}

export function RunResult({ run }: RunResultProps) {
  if (!run) {
    return (
      <section className="result-panel empty-state" aria-labelledby="result-title">
        <span className="section-index">03</span>
        <h2 id="result-title">실행 결과</h2>
        <p>실험을 실행하면 프로파일 묶음 하나의 Run ID와 단일 검증 결과가 표시됩니다.</p>
      </section>
    );
  }

  const resultClass = run.test_result?.toLowerCase() ?? "inconclusive";
  return (
    <section className="result-panel" aria-labelledby="result-title" aria-live="polite">
      <div className="section-heading compact">
        <div>
          <span className="section-index">03</span>
          <h2 id="result-title">실행 결과</h2>
        </div>
        <span className={`result-label ${resultClass}`}>{run.test_result ?? run.status}</span>
      </div>

      <dl className="result-grid">
        <div><dt>Run ID</dt><dd>{run.run_id}</dd></div>
        <div><dt>적용 Profile</dt><dd>{run.applied_profile ?? "—"}</dd></div>
        <div><dt>Tool</dt><dd>{run.tool ?? "—"}</dd></div>
        <div><dt>Runtime</dt><dd>{run.runtime_result ?? "—"}</dd></div>
        <div><dt>Exit code</dt><dd>{run.exit_code ?? "—"}</dd></div>
        <div><dt>Planner</dt><dd>{run.planner_mode}</dd></div>
        <div><dt>Runtime Agent</dt><dd>{run.runtime_agent}</dd></div>
      </dl>

      <div className="profile-bundle-summary" aria-label="단일 Run 권한 프로파일 묶음">
        <span>권한 프로파일 묶음</span>
        <strong>{run.applied_profile ?? run.requested_profile}</strong>
        <ul>
          {Object.entries(run.permission_profile).map(([name, enabled]) => (
            <li key={name}>{name}:{enabled ? "ON" : "OFF"}</li>
          ))}
        </ul>
      </div>

      <div className="hash-comparison">
        <div><span>Before SHA-256</span><strong>{shortHash(run.before_sha256)}</strong></div>
        <span className="hash-arrow" aria-hidden="true">→</span>
        <div><span>After SHA-256</span><strong>{shortHash(run.after_sha256)}</strong></div>
      </div>

      <div className="output-block">
        <span>Executor output</span>
        <p>{run.output ?? "출력 없음"}</p>
      </div>

      <a className="result-detail-link" href={`#/os-results/${encodeURIComponent(run.run_id)}`}>
        <span>전체 로그에서 상세보기</span>
        <span aria-hidden="true">→</span>
      </a>
    </section>
  );
}
