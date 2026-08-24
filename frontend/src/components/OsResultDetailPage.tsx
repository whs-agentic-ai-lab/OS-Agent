import { useEffect, useState } from "react";

import { deleteRun, getRun, getRuns } from "../api";
import type { RunEvent, RunListResponse, RunRecord } from "../types";
import { EventTimeline } from "./EventTimeline";

interface OsResultDetailPageProps {
  initialRunId: string | null;
  storageName: string | null;
}

const PAGE_SIZE = 20;
const UNIMPLEMENTED = "미구현";
const KOREAN_DATE_TIME_FORMATTER = new Intl.DateTimeFormat("ko-KR", {
  dateStyle: "medium",
  timeStyle: "medium",
});

function collectedValue(value: string | null | undefined): string {
  return !value || value === "UNIMPLEMENTED" ? UNIMPLEMENTED : value;
}

function changedVariableValue(run: RunRecord): string {
  const storedValue = collectedValue(run.changed_variable);
  if (storedValue !== UNIMPLEMENTED) return storedValue;
  const profileEntries = Object.entries(run.permission_profile ?? {});
  if (profileEntries.length > 0) {
    return profileEntries.map(([name, enabled]) => `${name}:${enabled ? "ON" : "OFF"}`).join(", ");
  }
  if (!run.permission_id) return UNIMPLEMENTED;
  return `${run.permission_id}:${run.permission_enabled ? "ON" : "OFF"}`;
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

function formatTimestamp(value: string | null): string {
  if (!value) return UNIMPLEMENTED;
  return KOREAN_DATE_TIME_FORMATTER.format(new Date(value));
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

function RunDetail({ run }: { run: RunRecord }) {
  const profile = run.applied_profile ?? run.requested_profile;
  const profileValue = `${profile} · 버전: ${collectedValue(run.profile_version)}`;
  const workloadType =
    run.workload_type === "normal"
      ? "정상"
      : run.workload_type === "attack"
        ? "공격"
        : UNIMPLEMENTED;
  const behaviorPath = `${run.tool ?? UNIMPLEMENTED} · 경로 ID: ${collectedValue(run.action_path_id)}`;
  const changedVariable = changedVariableValue(run);
  const evidenceReferences = (run.evidence_references?.length ?? 0) > 0
    ? run.evidence_references?.join(", ") ?? UNIMPLEMENTED
    : UNIMPLEMENTED;
  const resultClass = run.test_result?.toLowerCase() ?? "unimplemented";

  return (
    <div className="selected-log-detail">
      <header className="result-detail-hero">
        <div>
          <span className="eyebrow">선택한 실행 · {run.run_id}</span>
          <h2>OS 결과 상세</h2>
          <p>실행 조건과 정책 판정, 실제 효과, 이벤트 Evidence를 같은 run_id로 연결합니다.</p>
        </div>
        <div className="detail-verdict">
          <span>최종 판정</span>
          <strong className={`result-label ${resultClass}`}>{translateVerdict(run.test_result)}</strong>
        </div>
      </header>

      {Object.keys(run.permission_profile ?? {}).length > 0 ? (
        <section className="common-result-section" aria-labelledby="permission-profile-title">
          <div className="common-result-heading">
            <div>
              <span className="section-index">PROFILE</span>
              <h2 id="permission-profile-title">적용 권한 프로파일 묶음</h2>
            </div>
            <p><strong>1 Run ID</strong> · 프로파일 적용 1회 · Tool 실행 1회</p>
          </div>
          <div className="profile-bundle-detail">
            <div>
              <span>Profile ID</span>
              <strong>{profile}</strong>
              <small>Runtime Agent: {collectedValue(run.runtime_agent)}</small>
            </div>
            <ul>
              {Object.entries(run.permission_profile).map(([name, enabled]) => (
                <li key={name}><span>{name}</span><strong>{enabled ? "ON" : "OFF"}</strong></li>
              ))}
            </ul>
            <details>
              <summary>Supervisor 적용 상태</summary>
              <pre>{JSON.stringify(run.applied_profile_state ?? {}, null, 2)}</pre>
            </details>
          </div>
        </section>
      ) : null}

      <section className="common-result-section" aria-labelledby="common-result-title">
        <div className="common-result-heading">
          <div>
            <span className="section-index">RESULT</span>
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
                <th scope="col">권한 프로파일 묶음</th>
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
          <div>
            <dt>Before SHA-256</dt>
            <dd>{run.before_sha256 ?? UNIMPLEMENTED}</dd>
          </div>
          <div>
            <dt>After SHA-256</dt>
            <dd>{run.after_sha256 ?? UNIMPLEMENTED}</dd>
          </div>
          <div><dt>시작 시각</dt><dd>{formatTimestamp(run.created_at)}</dd></div>
          <div><dt>완료 시각</dt><dd>{formatTimestamp(run.completed_at)}</dd></div>
        </dl>
      </section>

      <section className="detail-events" aria-label="실행 이벤트 Evidence">
        <EventTimeline events={run.events} />
      </section>
    </div>
  );
}

export function OsResultDetailPage({ initialRunId, storageName }: OsResultDetailPageProps) {
  const [page, setPage] = useState(1);
  const [refreshVersion, setRefreshVersion] = useState(0);
  const [listResponse, setListResponse] = useState<RunListResponse | null>(null);
  const [listError, setListError] = useState<string | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [deletingRunId, setDeletingRunId] = useState<string | null>(null);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(initialRunId);
  const [detailState, setDetailState] = useState<{
    runId: string;
    run: RunRecord | null;
    error: string | null;
  } | null>(null);

  useEffect(() => {
    let isActive = true;
    getRuns(page, PAGE_SIZE)
      .then((response) => {
        if (!isActive) return;
        setListResponse(response);
        setSelectedRunId((current) => current ?? response.items[0]?.run_id ?? null);
      })
      .catch((reason) => {
        if (!isActive) return;
        setListError(reason instanceof Error ? reason.message : "실행 로그 목록을 불러오지 못했습니다.");
      });
    return () => {
      isActive = false;
    };
  }, [page, refreshVersion]);

  useEffect(() => {
    if (!selectedRunId) return;
    let isActive = true;
    getRun(selectedRunId)
      .then((response) => {
        if (isActive) setDetailState({ runId: selectedRunId, run: response, error: null });
      })
      .catch((reason) => {
        if (!isActive) return;
        setDetailState({
          runId: selectedRunId,
          run: null,
          error: reason instanceof Error ? reason.message : "실행 상세를 불러오지 못했습니다.",
        });
      });
    return () => {
      isActive = false;
    };
  }, [refreshVersion, selectedRunId]);

  const total = listResponse?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const selectedRun = detailState?.runId === selectedRunId ? detailState.run : null;
  const detailError = detailState?.runId === selectedRunId ? detailState.error : null;

  function selectRun(runId: string) {
    setSelectedRunId(runId);
    setDetailState(null);
  }

  function changePage(nextPage: number) {
    setSelectedRunId(null);
    setDetailState(null);
    setListError(null);
    setListResponse(null);
    window.history.replaceState(null, "", "#/logs");
    setPage(nextPage);
  }

  function refreshLogs() {
    setListError(null);
    setDeleteError(null);
    setListResponse(null);
    setDetailState(null);
    setRefreshVersion((value) => value + 1);
  }

  async function removeRun(runId: string) {
    const confirmation = window.prompt(
      `실행 로그와 연결된 이벤트를 영구 삭제합니다. 계속하려면 ${runId}를 입력하세요.`,
    );
    if (confirmation === null) return;
    if (confirmation !== runId) {
      setDeleteError("Run ID가 일치하지 않아 삭제를 취소했습니다.");
      return;
    }

    setDeletingRunId(runId);
    setDeleteError(null);
    try {
      await deleteRun(runId);
      if (selectedRunId === runId) {
        setSelectedRunId(null);
        setDetailState(null);
        window.history.replaceState(null, "", "#/logs");
      }
      if (listResponse?.items.length === 1 && page > 1) {
        setPage((current) => current - 1);
      }
      setListResponse(null);
      setRefreshVersion((value) => value + 1);
    } catch (reason) {
      setDeleteError(reason instanceof Error ? reason.message : "실행 로그를 삭제하지 못했습니다.");
    } finally {
      setDeletingRunId(null);
    }
  }

  return (
    <main className="result-detail-main" id="main">
      <header className="log-page-hero">
        <div>
          <span className="eyebrow">SUPABASE RUN LOGS · 전체 기록</span>
          <h1>OS 실행 로그 조회</h1>
          <p>Supabase에 저장된 모든 실행을 최신순으로 탐색하고, 실행별 결과와 이벤트 Evidence를 확인합니다.</p>
        </div>
        <dl className="log-summary">
          <div><dt>저장소</dt><dd>{storageName === "supabase" ? "Supabase" : storageName ?? "확인 중"}</dd></div>
          <div><dt>전체 실행</dt><dd>{total.toLocaleString("ko-KR")}</dd></div>
        </dl>
      </header>

      <section className="log-browser" aria-labelledby="log-list-title">
        <div className="common-result-heading log-list-heading">
          <div>
            <span className="section-index">LOG INDEX</span>
            <h2 id="log-list-title">실행 기록</h2>
          </div>
          <button className="log-refresh-button" onClick={refreshLogs} type="button">
            목록 새로고침
          </button>
        </div>

        {listError ? <p className="log-state-message is-error" role="alert">{listError}</p> : null}
        {deleteError ? <p className="log-state-message is-error" role="alert">{deleteError}</p> : null}
        {!listResponse && !listError ? <p className="log-state-message" role="status">Supabase 로그를 불러오는 중입니다.</p> : null}
        {listResponse?.items.length === 0 ? <p className="log-state-message">저장된 실행 로그가 없습니다.</p> : null}

        {listResponse?.items.length ? (
          <div className="log-list-table-wrap">
            <table className="log-list-table">
              <caption className="sr-only">Supabase에 저장된 OS Agent 실행 로그 목록</caption>
              <thead>
                <tr>
                  <th scope="col">실행 시각</th>
                  <th scope="col">Run ID</th>
                  <th scope="col">환경</th>
                  <th scope="col">권한 변경</th>
                  <th scope="col">Tool</th>
                  <th scope="col">판정</th>
                  <th scope="col">Prompt</th>
                  <th scope="col">관리</th>
                </tr>
              </thead>
              <tbody>
                {listResponse.items.map((item) => {
                  const selected = item.run_id === selectedRunId;
                  const resultClass = item.test_result?.toLowerCase() ?? "unimplemented";
                  return (
                    <tr className={selected ? "is-selected" : undefined} key={item.run_id}>
                      <td><time dateTime={item.created_at}>{formatTimestamp(item.created_at)}</time></td>
                      <td>
                        <a
                          className="log-run-link"
                          href={`#/os-results/${encodeURIComponent(item.run_id)}`}
                          onClick={() => selectRun(item.run_id)}
                        >
                          {item.run_id}
                        </a>
                      </td>
                      <td>{translateSubjectMode(item.subject_mode)}</td>
                      <td>{changedVariableValue(item)}</td>
                      <td>{item.tool ?? UNIMPLEMENTED}</td>
                      <td><span className={`result-label ${resultClass}`}>{translateVerdict(item.test_result)}</span></td>
                      <td className="log-prompt">{item.prompt}</td>
                      <td>
                        <button
                          className="log-delete-button"
                          disabled={deletingRunId !== null}
                          onClick={() => removeRun(item.run_id)}
                          type="button"
                        >
                          {deletingRunId === item.run_id ? "삭제 중" : "삭제"}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : null}

        {total > PAGE_SIZE ? (
          <nav className="log-pagination" aria-label="실행 로그 페이지">
            <button disabled={page <= 1} onClick={() => changePage(page - 1)} type="button">이전</button>
            <span>{page} / {totalPages}</span>
            <button disabled={page >= totalPages} onClick={() => changePage(page + 1)} type="button">다음</button>
          </nav>
        ) : null}
      </section>

      {selectedRunId && !detailState ? <p className="detail-loading" role="status">선택한 실행의 전체 로그를 불러오는 중입니다.</p> : null}
      {detailError ? (
        <section className="detail-error" role="alert">
          <span className="section-index">DETAIL ERROR</span>
          <h2>상세 로그를 불러오지 못했습니다</h2>
          <p>{detailError}</p>
        </section>
      ) : null}
      {selectedRun ? <RunDetail run={selectedRun} /> : null}
    </main>
  );
}
