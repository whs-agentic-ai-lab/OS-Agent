import type { AgentRunRecord, TbResult } from "../types";

interface AgentRunResultProps {
  run: AgentRunRecord | null;
}

const verdictCopy: Record<TbResult["verdict"], string> = {
  BROKEN: "경계 침해",
  BLOCKED: "차단됨",
  INCONCLUSIVE: "판정 보류",
};

const stepTypeCopy = {
  observe: "관찰",
  execute: "공격 실행",
  verify: "검증",
  rollback: "복구",
} as const;

const expectedResultCopy = {
  allowed: "허용 예상",
  denied: "차단 예상",
  observed: "관찰 예상",
  restored: "복구 예상",
} as const;

function shortHash(value: string): string {
  return value.length > 32 ? `${value.slice(0, 20)}…${value.slice(-10)}` : value;
}

export function AgentRunResult({ run }: AgentRunResultProps) {
  if (!run) {
    return (
      <section className="result-panel empty-state" aria-labelledby="result-title">
        <span className="section-index">03</span>
        <h2 id="result-title">8개 TB 통합 판정</h2>
        <p>두 권한 프로파일을 고정한 뒤 Recon부터 복구까지 실행하면 경계별 판정과 실제 최악 경로가 표시됩니다.</p>
      </section>
    );
  }

  const worst = run.worst_case_scenario;
  return (
    <section className="result-panel agent-result" aria-labelledby="result-title" aria-live="polite">
      <div className="section-heading compact">
        <div>
          <span className="section-index">03</span>
          <h2 id="result-title">8개 TB 통합 판정</h2>
        </div>
        <span className={`agent-run-status is-${run.status.toLowerCase()}`}>{run.status}</span>
      </div>

      <dl className="agent-summary-grid">
        <div><dt>BROKEN</dt><dd>{run.summary.broken}</dd></div>
        <div><dt>BLOCKED</dt><dd>{run.summary.blocked}</dd></div>
        <div><dt>INCONCLUSIVE</dt><dd>{run.summary.inconclusive}</dd></div>
        <div><dt>Rollback</dt><dd>{run.rollback_status}</dd></div>
      </dl>

      <div className="profile-lock-card">
        <span>고정 profile_hash</span>
        <code title={run.profile_hash}>{shortHash(run.profile_hash)}</code>
        <small>모든 TB 이벤트가 같은 해시를 사용합니다.</small>
      </div>

      <div className={`worst-case-card${worst ? " has-result" : ""}`}>
        <span>실제 검증된 최악 경로</span>
        {worst ? (
          <>
            <strong>{worst.trust_boundary_id}</strong>
            <p>{worst.objective}</p>
            <small>{worst.risk_level.toUpperCase()} · Risk {worst.risk_score}</small>
          </>
        ) : (
          <p>BROKEN으로 검증된 경로가 없습니다.</p>
        )}
      </div>

      <div className="tb-result-table-wrap">
        <table className="tb-result-table">
          <thead>
            <tr>
              <th>Trust Boundary</th>
              <th>에이전트 테스트 시나리오</th>
              <th>판정</th>
              <th>위험</th>
              <th>증명</th>
              <th>복구</th>
            </tr>
          </thead>
          <tbody>
            {run.tb_results.map((result) => (
              <tr key={result.trust_boundary_id}>
                <td>
                  <strong>{result.trust_boundary_id}</strong>
                  <small>{result.source_environment.toUpperCase()} → {result.target_environment.toUpperCase()}</small>
                </td>
                <td className="tb-scenario-preview">
                  <strong>{result.scenario.objective}</strong>
                  <small>{result.scenario.steps.length}단계 · {result.scenario.risk_level.toUpperCase()}</small>
                </td>
                <td><span className={`tb-verdict is-${result.verdict.toLowerCase()}`}>{verdictCopy[result.verdict]}</span></td>
                <td>{result.risk_score}</td>
                <td>{result.proof_level}</td>
                <td>{result.rollback_status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <section className="scenario-section" aria-labelledby="scenario-title">
        <div className="scenario-section-heading">
          <div>
            <span>Autonomous attack plan</span>
            <h3 id="scenario-title">에이전트가 실행한 TB별 테스트 시나리오</h3>
            <p>각 항목을 열면 공격 가설, 사용 권한, 공격 경로와 단계별 실행 결과를 확인할 수 있습니다.</p>
          </div>
          <strong>{run.tb_results.length} scenarios</strong>
        </div>

        <div className="scenario-list">
          {run.tb_results.map((result, index) => (
            <details
              className={`scenario-card is-${result.verdict.toLowerCase()}`}
              key={result.trust_boundary_id}
              open={index === 0 ? true : undefined}
            >
              <summary>
                <span className="scenario-number">{String(index + 1).padStart(2, "0")}</span>
                <span className="scenario-summary-copy">
                  <strong>{result.trust_boundary_id}</strong>
                  <span>{result.scenario.objective}</span>
                  <small>{result.source_environment.toUpperCase()} → {result.target_environment.toUpperCase()}</small>
                </span>
                <span className={`tb-verdict is-${result.verdict.toLowerCase()}`}>{verdictCopy[result.verdict]}</span>
              </summary>

              <div className="scenario-body">
                <dl className="scenario-metadata">
                  <div><dt>Scenario ID</dt><dd>{result.scenario.scenario_id}</dd></div>
                  <div><dt>위험도</dt><dd>{result.scenario.risk_level.toUpperCase()} · {result.scenario.risk_score}</dd></div>
                  <div><dt>증명 수준</dt><dd>{result.proof_level}</dd></div>
                  <div><dt>복구</dt><dd>{result.rollback_status}</dd></div>
                </dl>

                <div className="scenario-narrative">
                  <div>
                    <span>공격 영향</span>
                    <p>{result.scenario.impact}</p>
                  </div>
                  <div>
                    <span>최종 판정 근거</span>
                    <p>{result.explanation}</p>
                  </div>
                </div>

                <div className="scenario-path-block">
                  <span>공격 경로</span>
                  <ol className="scenario-path">
                    {result.attack_path.map((node, pathIndex) => (
                      <li key={`${result.trust_boundary_id}-path-${pathIndex}`}>{node}</li>
                    ))}
                  </ol>
                </div>

                <div className="scenario-permission-block">
                  <span>실제로 사용한 고정 권한</span>
                  {result.fixed_permissions_used.length > 0 ? (
                    <ul>
                      {result.fixed_permissions_used.map((permission) => <li key={permission}>{permission}</li>)}
                    </ul>
                  ) : (
                    <p>추가 권한을 사용하지 않았습니다.</p>
                  )}
                </div>

                <div className="scenario-step-block">
                  <span>단계별 실행 결과</span>
                  <ol className="scenario-steps">
                    {result.scenario.steps.map((step, stepIndex) => (
                      <li key={step.step_id}>
                        <span className={`step-index is-${step.type}`}>{stepIndex + 1}</span>
                        <div className="step-copy">
                          <div>
                            <strong>{stepTypeCopy[step.type]}</strong>
                            <code>{step.tool}:{step.action}</code>
                          </div>
                          <p>{step.resource_ref}</p>
                        </div>
                        <div className="step-outcome">
                          <span>{expectedResultCopy[step.expected_result]}</span>
                          <strong>{step.status}</strong>
                        </div>
                      </li>
                    ))}
                  </ol>
                </div>

                {result.evidence_refs.length > 0 ? (
                  <div className="scenario-evidence">
                    <span>증거 참조</span>
                    <ul>
                      {result.evidence_refs.map((evidence) => <li key={evidence}><code>{evidence}</code></li>)}
                    </ul>
                  </div>
                ) : null}
              </div>
            </details>
          ))}
        </div>
      </section>

      {run.profile_warnings.length > 0 ? (
        <ul className="agent-warning-list">
          {run.profile_warnings.map((warning) => <li key={warning}>{warning}</li>)}
        </ul>
      ) : null}
    </section>
  );
}
