import { EventTimeline } from "./EventTimeline";
import type { RunEvent, RunRecord } from "../types";

interface OsResultDetailPageProps {
  error: string | null;
  isLoading: boolean;
  run: RunRecord | null;
  runId: string;
}

const UNIMPLEMENTED = "미구현";

function collectedValue(value: string | null | undefined): string {
  return !value || value === "UNIMPLEMENTED" ? UNIMPLEMENTED : value;
}

function translateSubjectMode(mode: RunRecord["subject_mode"]): string {
  return mode === "host" ? "Ubuntu Host" : "Container";
}

function translateVerdict(result: RunRecord["test_result"]): string {
  if (result === "PASS") return "성공";
  if (result === "FAIL") return "실패";
  if (result === "INCONCLUSIVE") return "판정 불가";
  return UNIMPLEMENTED;
}

function findLatestEvent(run: RunRecord, eventType: string): RunEvent | undefined {
  for (let index = run.events.length - 1; index >= 0; index -= 1) {
    const event = run.events[index];
    if (event.event_type === eventType) return event;
  }
  return undefined;
}

function policyDecision(run: RunRecord): string {
  if (run.policy_decision === "allowed") return "허용";
  if (run.policy_decision === "denied") return "거부";
  for (let index = run.events.length - 1; index >= 0; index -= 1) {
    const eventType = run.events[index].event_type;
    if (eventType === "TOOL_DENIED") return "거부";
    if (eventType === "TOOL_ALLOWED") return "허용";
  }
  return UNIMPLEMENTED;
}

function executionResult(run: RunRecord): string {
  const authentication = collectedValue(run.authentication_result);
  const authorization = collectedValue(run.authorization_result);
  const runtime = collectedValue(run.runtime_result);
  const exitCode = run.exit_code === null ? UNIMPLEMENTED : String(run.exit_code);
  return `인증: ${authentication} · 인가: ${authorization} · 실행: ${runtime} · exit code: ${exitCode}`;
}

function verifierEffect(run: RunRecord): string {
  if (run.verifier_name && run.verifier_name !== "UNIMPLEMENTED") {
    const checkSummary = Object.entries(run.verifier_effect ?? {})
      .map(([name, passed]) => `${name}=${passed ? "true" : "false"}`)
      .join(", ");
    return `${run.verifier_name} · ${checkSummary || UNIMPLEMENTED}`;
  }
  const event = findLatestEvent(run, "VERIFIED");
  if (!event) return UNIMPLEMENTED;

  const verifier = typeof event.payload.verifier === "string" ? event.payload.verifier : UNIMPLEMENTED;
  const checks = event.payload.checks;
  const checkSummary =
    checks && typeof checks === "object"
      ? Object.entries(checks)
          .map(([name, passed]) => `${name}=${passed ? "true" : "false"}`)
          .join(", ")
      : UNIMPLEMENTED;
  return `${verifier} · ${checkSummary}`;
}

function ResultValue({ children }: { children: string }) {
  const unimplemented = children.includes(UNIMPLEMENTED);
  return (
    <span className={unimplemented ? "detail-value is-unimplemented" : "detail-value"}>
      {children}
    </span>
  );
}

export function OsResultDetailPage({ error, isLoading, run, runId }: OsResultDetailPageProps) {
  if (isLoading) {
    return (
      <main className="result-detail-main" id="main">
        <p className="detail-loading" role="status">OS 실험 결과를 불러오는 중입니다.</p>
      </main>
    );
  }

  if (error || !run) {
    return (
      <main className="result-detail-main" id="main">
        <a className="detail-back-link" href="#main">← 컨트롤 패널로 돌아가기</a>
        <section className="detail-error" role="alert">
          <span className="section-index">OS RESULT</span>
          <h1>결과를 불러오지 못했습니다</h1>
          <p>{error ?? `${runId} 실행 기록을 찾을 수 없습니다.`}</p>
        </section>
      </main>
    );
  }

  const profile = run.applied_profile ?? run.requested_profile;
  const profileValue = `${profile} · 버전: ${collectedValue(run.profile_version)}`;
  const workloadType =
    run.workload_type === "normal"
      ? "정상"
      : run.workload_type === "attack"
        ? "공격"
        : UNIMPLEMENTED;
  const behaviorPath = `${run.tool ?? UNIMPLEMENTED} · 경로 ID: ${collectedValue(run.action_path_id)}`;
  const changedVariable = collectedValue(run.changed_variable);
  const evidenceReferences = (run.evidence_references?.length ?? 0) > 0
    ? run.evidence_references?.join(", ") ?? UNIMPLEMENTED
    : UNIMPLEMENTED;
  const resultClass = run.test_result?.toLowerCase() ?? "unimplemented";

  return (
    <main className="result-detail-main" id="main">
      <a className="detail-back-link" href="#main">← 컨트롤 패널로 돌아가기</a>

      <header className="result-detail-hero">
        <div>
          <span className="eyebrow">공통 최소 실험 결과 양식 · 01</span>
          <h1>OS 결과 상세보기</h1>
          <p>한 번의 실행 조건과 정책 판정, 실제 효과를 같은 run_id로 연결합니다.</p>
        </div>
        <div className="detail-verdict">
          <span>최종 판정</span>
          <strong className={`result-label ${resultClass}`}>{translateVerdict(run.test_result)}</strong>
        </div>
      </header>

      <section className="common-result-section" aria-labelledby="common-result-title">
        <div className="common-result-heading">
          <div>
            <span className="section-index">01</span>
            <h2 id="common-result-title">실행 조건과 실제 효과</h2>
          </div>
          <p><strong>{run.run_id}</strong> 기준 단일 실행 결과</p>
        </div>

        <div className="common-result-table-wrap">
          <table className="common-result-table">
            <caption className="sr-only">공통 최소 실험 결과 양식의 실행 조건과 실제 효과</caption>
            <thead>
              <tr>
                <th scope="col">run_id</th>
                <th scope="col">환경</th>
                <th scope="col">profile·버전</th>
                <th scope="col">정상/공격 workload</th>
                <th scope="col">Agent 행동·경로 ID</th>
                <th scope="col">변경 변수 1개</th>
                <th scope="col">정책 판정</th>
                <th scope="col">실제 인증·인가 및 실행 결과</th>
                <th scope="col">독립 Verifier 실제 효과</th>
                <th scope="col">최종 판정</th>
                <th scope="col">Evidence 참조</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><ResultValue>{run.run_id}</ResultValue></td>
                <td><ResultValue>{translateSubjectMode(run.subject_mode)}</ResultValue></td>
                <td><ResultValue>{profileValue}</ResultValue></td>
                <td><ResultValue>{workloadType}</ResultValue></td>
                <td><ResultValue>{behaviorPath}</ResultValue></td>
                <td><ResultValue>{changedVariable}</ResultValue></td>
                <td><ResultValue>{policyDecision(run)}</ResultValue></td>
                <td><ResultValue>{executionResult(run)}</ResultValue></td>
                <td><ResultValue>{verifierEffect(run)}</ResultValue></td>
                <td><ResultValue>{translateVerdict(run.test_result)}</ResultValue></td>
                <td><ResultValue>{evidenceReferences}</ResultValue></td>
              </tr>
            </tbody>
          </table>
        </div>

        <aside className="classification-note" aria-label="결과 분류 기준">
          <strong>분류 기준</strong>
          <p><b>미구현</b>은 해당 항목이 수집되지 않았음을 뜻합니다. 데이터는 수집됐지만 결론을 낼 수 없을 때만 <b>판정 불가</b>로 표시합니다.</p>
        </aside>
      </section>

      <section className="detail-context" aria-labelledby="detail-context-title">
        <div className="common-result-heading">
          <div>
            <span className="section-index">CONTEXT</span>
            <h2 id="detail-context-title">실행 원문</h2>
          </div>
        </div>
        <dl>
          <div><dt>Prompt</dt><dd>{run.prompt}</dd></div>
          <div><dt>Executor output</dt><dd>{run.output ?? UNIMPLEMENTED}</dd></div>
          <div><dt>Before SHA-256</dt><dd>{run.before_sha256 ?? UNIMPLEMENTED}</dd></div>
          <div><dt>After SHA-256</dt><dd>{run.after_sha256 ?? UNIMPLEMENTED}</dd></div>
          <div><dt>시작 시각</dt><dd>{run.created_at}</dd></div>
          <div><dt>완료 시각</dt><dd>{run.completed_at ?? UNIMPLEMENTED}</dd></div>
        </dl>
      </section>

      <section className="detail-events" aria-label="실행 이벤트 Evidence">
        <EventTimeline events={run.events} />
      </section>
    </main>
  );
}
