import type {
  AgentPlanStep,
  AgentRunRecord,
  AgentSearchState,
  TbResult,
} from "../types";

interface AgentRunResultProps {
  run: AgentRunRecord | null;
  onResume?: () => void;
  isResuming?: boolean;
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

const chainStatusCopy: Record<string, string> = {
  PENDING: "대기",
  RUNNING: "탐색 중",
  COMPLETED: "완료",
  SEARCH_COMPLETE: "탐색 완료",
  PAUSED: "일시 중단",
  FAILED: "실패",
};

const terminationReasonCopy: Record<string, string> = {
  MAX_IMPACT_VERIFIED: "등록된 피해 상한을 실제로 검증했습니다.",
  FRONTIER_EXHAUSTED: "새로운 상태로 이어지는 실행 가능 후보가 없습니다.",
  POLICY_FRONTIER_EXHAUSTED: "남은 후보가 모두 정책 검사에서 제외됐습니다.",
  NO_PROGRESS: "새로운 증거나 상태 변화가 없어 탐색을 종료했습니다.",
  SEARCH_BUDGET_EXHAUSTED: "탐색 안전 예산이 소진되어 일시 중단했습니다.",
  TOOL_BUDGET_EXHAUSTED: "Tool 호출 안전 예산이 소진되어 일시 중단했습니다.",
  TIME_BUDGET_EXHAUSTED: "실행 시간 안전 예산이 소진되어 일시 중단했습니다.",
  WATCHDOG_TIMEOUT: "외부 안전 Watchdog이 실행을 중단했습니다.",
  CANCELLED: "사용자 요청으로 탐색을 중단했습니다.",
  POLICY_VIOLATION: "정책 계약을 벗어난 선택을 차단하고 긴급 복구했습니다.",
  RESET_FAILED: "원상 복구를 검증하지 못해 탐색을 중단했습니다.",
  ERROR: "실행 오류로 탐색을 완료하지 못했습니다.",
};

function shortHash(value: string): string {
  return value.length > 32 ? `${value.slice(0, 20)}…${value.slice(-10)}` : value;
}

function formatStateValue(value: unknown): string {
  if (value === undefined) return "없음";
  if (value === null) return "null";
  if (typeof value === "string") {
    return value.length > 120 ? `${value.slice(0, 117)}…` : value;
  }

  try {
    const serialized = JSON.stringify(value);
    return serialized.length > 120 ? `${serialized.slice(0, 117)}…` : serialized;
  } catch {
    return String(value);
  }
}

function readableStatus(value: string): string {
  return chainStatusCopy[value] ?? value;
}

function ChainStepList({ idPrefix, steps }: { idPrefix: string; steps: AgentPlanStep[] }) {
  return (
    <ol className="scenario-steps">
      {steps.map((step, stepIndex) => {
        const sequence = step.sequence ?? stepIndex + 1;
        const stateChanges = step.state_changes ?? [];
        const stepEvidence = step.evidence_refs ?? [];
        const hasStateTransition = Boolean(step.state_before || step.state_after);
        const executionStatus = step.execution_status ?? step.status;

        return (
          <li key={`${idPrefix}-${step.step_id}-${sequence}`}>
            <span className={`step-index is-${step.type}`}>{sequence}</span>
            <div className="step-copy">
              <div>
                <strong>{stepTypeCopy[step.type]}</strong>
                <code>{step.tool}:{step.action}</code>
              </div>
              <p>{step.resource_ref}</p>

              {step.selection_rationale ? (
                <p><strong>선택 이유</strong> · {step.selection_rationale}</p>
              ) : null}

              {hasStateTransition ? (
                <dl className="permission-hash-grid" aria-label={`${sequence}단계 상태 전이`}>
                  <div>
                    <dt>실행 전 State v{step.state_before?.version ?? "—"}</dt>
                    <dd title={step.state_before?.fingerprint}>
                      {step.state_before?.fingerprint ? shortHash(step.state_before.fingerprint) : "기록 없음"}
                    </dd>
                  </div>
                  <div>
                    <dt>실행 후 State v{step.state_after?.version ?? "—"}</dt>
                    <dd title={step.state_after?.fingerprint}>
                      {step.state_after?.fingerprint ? shortHash(step.state_after.fingerprint) : "기록 없음"}
                    </dd>
                  </div>
                </dl>
              ) : null}

              {stateChanges.length > 0 ? (
                <div className="scenario-evidence">
                  <span>이 단계가 만든 상태 변화</span>
                  <ul>
                    {stateChanges.map((change, changeIndex) => (
                      <li key={`${idPrefix}-${step.step_id}-change-${change.key}-${changeIndex}`}>
                        <code>{change.key}</code>: {formatStateValue(change.before)} → {formatStateValue(change.after)}
                        {change.evidence_refs.length > 0 ? ` · 증거 ${change.evidence_refs.join(", ")}` : ""}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}

              {stepEvidence.length > 0 ? (
                <div className="scenario-evidence">
                  <span>단계 증거</span>
                  <ul>
                    {stepEvidence.map((evidence) => <li key={evidence}><code>{evidence}</code></li>)}
                  </ul>
                </div>
              ) : null}
            </div>
            <div className="step-outcome">
              {step.policy_decision ? <span>Policy {step.policy_decision}</span> : null}
              <span>{expectedResultCopy[step.expected_result]}</span>
              <strong>{executionStatus}</strong>
              {step.verification_status ? <span>Verifier {step.verification_status}</span> : null}
              {step.runtime_result ? <span>Runtime {step.runtime_result}</span> : null}
              {step.outcome ? <span title={step.outcome}>{formatStateValue(step.outcome)}</span> : null}
            </div>
          </li>
        );
      })}
    </ol>
  );
}

function SearchProgress({ search }: { search: AgentSearchState }) {
  const terminationCopy = search.termination_reason
    ? terminationReasonCopy[search.termination_reason] ?? search.termination_reason
    : search.status === "RUNNING"
      ? "실행 결과를 바탕으로 다음 최적 후보를 선택하고 있습니다."
      : "종료 사유가 아직 기록되지 않았습니다.";
  const completenessCopy = search.search_complete
    ? search.termination_reason === "MAX_IMPACT_VERIFIED"
      ? "독립 Verifier가 구현된 공격 표면의 최대 영향을 확인해 더 낮은 후보를 생략했습니다."
      : "현재 등록된 Tool과 고정 정책에서 탐색 가능한 새로운 상태가 없습니다."
    : search.budget_exhausted
      ? "탐색이 끝난 것이 아닙니다. 남은 Frontier를 재개해야 최악 경로를 확정할 수 있습니다."
      : "현재까지 발견된 탐색 공간을 기준으로 진행 중이거나 미완료 상태입니다.";
  const resumeCopy = search.resume_available
    ? `재개 가능${search.checkpoint_id ? ` · checkpoint ${shortHash(search.checkpoint_id)}` : ""}`
    : "재개 불가";

  return (
    <>
      <dl className="scenario-metadata" aria-label="상태 기반 공격 탐색 현황">
        <div><dt>탐색 상태</dt><dd>{readableStatus(search.status)}</dd></div>
        <div><dt>발견/탐색 State</dt><dd>{search.explored_states} / {search.discovered_states}</dd></div>
        <div><dt>현재 Frontier</dt><dd>{search.frontier_candidates} candidates</dd></div>
        <div><dt>실제 Tool 호출</dt><dd>{search.tool_calls_used}</dd></div>
        {search.planner_calls_used !== undefined ? <div><dt>Planner 판단</dt><dd>{search.planner_calls_used}</dd></div> : null}
        <div><dt>고유 상태 전이</dt><dd>{search.unique_transitions}</dd></div>
        <div><dt>중복 상태</dt><dd>{search.repeated_states}</dd></div>
        <div><dt>정책 제외 후보</dt><dd>{search.policy_pruned_candidates}</dd></div>
        <div><dt>자동 예산 연장</dt><dd>{search.automatic_extensions}</dd></div>
      </dl>

      <div className="scenario-narrative">
        <div>
          <span>탐색 종료 사유</span>
          <p>{terminationCopy}{search.termination_explanation ? ` ${search.termination_explanation}` : ""}</p>
        </div>
        <div>
          <span>탐색 완결성과 재개</span>
          <p>{completenessCopy}<br />{resumeCopy}</p>
        </div>
      </div>

      {search.budget_exhausted ? (
        <ul className="agent-warning-list" role="status">
          <li>안전 예산으로 일시 중단됐습니다. 현재 결과를 전체 탐색이 끝난 최악 경로로 해석하면 안 됩니다.</li>
          {search.resume_available ? <li>Checkpoint에서 검증된 체인을 재현한 뒤 남은 Frontier 탐색을 이어갈 수 있습니다.</li> : null}
        </ul>
      ) : null}
    </>
  );
}

export function AgentRunResult({ run, onResume, isResuming = false }: AgentRunResultProps) {
  if (!run) {
    return (
      <section className="result-panel empty-state" aria-labelledby="result-title">
        <span className="section-index">03</span>
        <h2 id="result-title">Campaign 그래프 통합 판정</h2>
        <p>Recon 이후 전역 Frontier 탐색과 부모 상태 복구가 시작되면 결과가 표시됩니다.</p>
      </section>
    );
  }

  const worst = run.worst_case_scenario;
  const resumeAvailable = run.campaign_search.status === "PAUSED"
    && run.campaign_search.frontier_node_ids.length > 0;
  return (
    <section className="result-panel agent-result" aria-labelledby="result-title">
      <div className="section-heading compact">
        <div>
          <span className="section-index">03</span>
          <h2 id="result-title">Campaign 그래프 통합 판정</h2>
        </div>
        <output
          aria-atomic="true"
          aria-live="polite"
          className={`agent-run-status is-${run.status.toLowerCase()}`}
        >
          {readableStatus(run.status)}
        </output>
      </div>

      <dl className="agent-summary-grid">
        <div><dt>BROKEN</dt><dd>{run.summary.broken}</dd></div>
        <div><dt>BLOCKED</dt><dd>{run.summary.blocked}</dd></div>
        <div><dt>INCONCLUSIVE</dt><dd>{run.summary.inconclusive}</dd></div>
        <div><dt>Rollback</dt><dd>{run.rollback_status}</dd></div>
      </dl>

      {resumeAvailable && onResume ? (
        <div className="chain-resume-card">
          <div>
            <strong>미완료 Frontier가 남아 있습니다.</strong>
            <p>복구된 루트에서 보존한 전역 Frontier의 다음 최고 우선순위 노드부터 이어갑니다.</p>
          </div>
          <button type="button" onClick={onResume} disabled={isResuming}>
            {isResuming ? "Campaign 재개 중…" : "Campaign Frontier 재개"}
          </button>
        </div>
      ) : null}

      <div className="profile-lock-card">
        <span>고정 profile_hash</span>
        <code title={run.profile_hash}>{shortHash(run.profile_hash)}</code>
        <small>모든 Campaign 노드와 전이가 같은 권한 프로필을 사용합니다.</small>
      </div>

      <div className="planner-selection-card">
        <span>실행 Planner</span>
        <strong>
          {run.planner_mode === "openrouter"
            ? run.planner_model ?? "OpenRouter 기본 모델"
            : "Local deterministic planner"}
        </strong>
        <small>{run.planner_mode.toUpperCase()}</small>
      </div>

      <div className="permission-pipeline" aria-label="권한 최소화 파이프라인">
        <div><span>01</span><strong>자동 수집</strong><small>{Object.values(run.fixed_permission_profiles.host).length + Object.values(run.fixed_permission_profiles.container).length} controls</small></div>
        <div><span>02</span><strong>그래프 탐색</strong><small>{run.campaign_search.nodes.length} nodes</small></div>
        <div><span>03</span><strong>목표 고정</strong><small>{run.attack_contract ? run.attack_contract.trust_boundary_id : "없음"}</small></div>
        <div><span>04</span><strong>상태 복구</strong><small>{run.campaign_search.backtrack_count} backtracks</small></div>
      </div>

      {run.attack_contract ? (
        <section className="attack-contract-card" aria-labelledby="attack-contract-title">
          <div>
            <span>Frozen attack contract</span>
            <h3 id="attack-contract-title">{run.attack_contract.trust_boundary_id} · 피해 점수 {run.attack_contract.damage_score.total}</h3>
            <p>{run.attack_contract.objective}</p>
          </div>
          <dl>
            <div><dt>{run.attack_contract.chain_steps?.length ? "최종 영향 Tool" : "고정 Tool"}</dt><dd><code>{run.attack_contract.tool}:{run.attack_contract.action}</code></dd></div>
            <div><dt>{run.attack_contract.chain_steps?.length ? "최종 Target" : "고정 Target"}</dt><dd><code>{run.attack_contract.resource_ref}</code></dd></div>
            <div><dt>Verifier</dt><dd>{run.attack_contract.verifier}</dd></div>
            <div><dt>Rollback</dt><dd>{run.attack_contract.rollback}</dd></div>
            {run.attack_contract.chain_hash ? (
              <div><dt>고정 Chain Hash</dt><dd><code title={run.attack_contract.chain_hash}>{shortHash(run.attack_contract.chain_hash)}</code></dd></div>
            ) : null}
            {run.attack_contract.chain_steps?.length ? (
              <div><dt>고정 Chain 길이</dt><dd>{run.attack_contract.chain_steps.length}단계</dd></div>
            ) : null}
          </dl>
          <ul>
            {run.attack_contract.success_criteria.map((criterion) => <li key={criterion}>{criterion}</li>)}
          </ul>
          {run.attack_contract.chain_steps?.length ? (
            <div className="scenario-step-block">
              <span>권한 최소화에서 동일하게 재현할 전체 Tool 체인</span>
              <ChainStepList
                idPrefix={`${run.attack_contract.contract_id}-contract`}
                steps={run.attack_contract.chain_steps}
              />
            </div>
          ) : null}
        </section>
      ) : null}

      <section className="minimization-card" aria-labelledby="minimization-title">
        <div>
          <span>Permission minimizer</span>
          <h3 id="minimization-title">1-minimal 권한 결과</h3>
          <strong className={run.permission_minimization.one_minimal_verified ? "is-verified" : ""}>
            {run.permission_minimization.one_minimal_verified ? "VERIFIED" : run.permission_minimization.status}
          </strong>
        </div>
        <dl>
          <div><dt>최대 권한</dt><dd>{run.permission_minimization.initial_permission_ids.length}</dd></div>
          <div><dt>LLM 제안</dt><dd>{run.permission_minimization.llm_suggested_permission_ids.length}</dd></div>
          <div><dt>최종 권한</dt><dd>{run.permission_minimization.minimal_permission_ids.length}</dd></div>
          <div><dt>재실행</dt><dd>{run.permission_minimization.trials.length}</dd></div>
        </dl>
        {run.permission_minimization.minimal_permission_ids.length > 0 ? (
          <ul className="minimal-permission-list">
            {run.permission_minimization.minimal_permission_ids.map((permission) => <li key={permission}><code>{permission}</code></li>)}
          </ul>
        ) : <p>고정할 수 있는 성공 공격이 없어 권한 축소를 수행하지 않았습니다.</p>}
      </section>

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
              <th>실행 전이</th>
              <th>상태</th>
              <th>영향</th>
              <th>순서</th>
              <th>복구</th>
            </tr>
          </thead>
          <tbody>
            {run.campaign_search.transitions.map((transition) => (
              <tr key={transition.transition_id}>
                <td>
                  <strong>{transition.trust_boundary_id}</strong>
                  <small>{transition.source_environment.toUpperCase()} → {transition.target_environment.toUpperCase()}</small>
                </td>
                <td className="tb-scenario-preview">
                  <strong>{transition.tool}:{transition.action}</strong>
                  <small>{transition.resource_ref}</small>
                </td>
                <td>{transition.status}</td>
                <td>{transition.impact} · {transition.impact_score}</td>
                <td>{transition.sequence}</td>
                <td>{transition.rollback_status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {run.tb_results.length > 0 ? <section className="scenario-section" aria-labelledby="scenario-title">
        <div className="scenario-section-heading">
          <div>
            <span>Autonomous attack plan</span>
            <h3 id="scenario-title">에이전트가 실제 선택한 TB별 Tool 체인</h3>
            <p>각 항목을 열면 Tool 선택 이유, 누적 상태 변화, Frontier와 탐색 종료 사유를 확인할 수 있습니다.</p>
          </div>
          <strong>{run.tb_results.length} scenarios</strong>
        </div>

        <div className="scenario-list">
          {run.tb_results.map((result, index) => (
            <details
              className={`scenario-card is-${result.verdict.toLowerCase()}`}
              key={result.trust_boundary_id}
            >
              <summary>
                <span className="scenario-number">{String(index + 1).padStart(2, "0")}</span>
                <span className="scenario-summary-copy">
                  <strong>{result.trust_boundary_id}</strong>
                  <span>{result.scenario.objective}</span>
                  <small>
                    {result.source_environment.toUpperCase()} → {result.target_environment.toUpperCase()}
                    {result.scenario.chain_status ? ` · ${readableStatus(result.scenario.chain_status)}` : ""}
                    {result.scenario.search ? ` · ${result.scenario.search.tool_calls_used} Tool calls` : ""}
                  </small>
                </span>
                <span className={`tb-verdict is-${result.verdict.toLowerCase()}`}>
                  {verdictCopy[result.verdict]} <span aria-hidden="true">⌄</span>
                </span>
              </summary>

              <div className="scenario-body">
                <dl className="scenario-metadata">
                  <div><dt>Scenario ID</dt><dd>{result.scenario.scenario_id}</dd></div>
                  <div><dt>위험도</dt><dd>{result.scenario.risk_level.toUpperCase()} · {result.scenario.risk_score}</dd></div>
                  <div><dt>증명 수준</dt><dd>{result.proof_level}</dd></div>
                  <div><dt>시나리오 전체 복구</dt><dd>{result.scenario.rollback_status ?? result.rollback_status}</dd></div>
                  {result.scenario.chain_id ? <div><dt>Chain ID</dt><dd>{result.scenario.chain_id}</dd></div> : null}
                  {result.scenario.chain_status ? <div><dt>Chain 상태</dt><dd>{readableStatus(result.scenario.chain_status)}</dd></div> : null}
                </dl>

                {result.scenario.search ? <SearchProgress search={result.scenario.search} /> : null}

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
                  <span>{result.scenario.chain_id ? "실제로 선택·실행한 누적 Tool 체인" : "단계별 실행 결과"}</span>
                  <ChainStepList
                    idPrefix={`${result.trust_boundary_id}-${result.scenario.chain_id ?? result.scenario.scenario_id}`}
                    steps={result.scenario.steps}
                  />
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
      </section> : null}

      {run.profile_warnings.length > 0 ? (
        <ul className="agent-warning-list">
          {run.profile_warnings.map((warning) => <li key={warning}>{warning}</li>)}
        </ul>
      ) : null}
    </section>
  );
}
