import { useEffect, useState } from "react";

import {
  createFixtureHarnessRun,
  createHarnessRun,
  getFixtureHarnessStatus,
  getHarnessStatus,
} from "../api";
import type {
  HarnessComponentName,
  HarnessRunRecord,
  HarnessStatus,
  SubjectModeId,
} from "../types";

const COMPONENT_LABELS: Record<HarnessComponentName, string> = {
  permission_provider: "Permission",
  tool_catalog: "Tool Catalog",
  planner: "Planner",
  executor: "Executor",
  verifier: "Verifier",
  resetter: "Resetter",
};

const FIXTURE_PROFILES: Array<{
  id: string;
  label: string;
  mode: SubjectModeId;
  write: boolean;
}> = [
  { id: "fixture-container-readonly", label: "Container · Read only", mode: "container", write: false },
  { id: "fixture-container-write", label: "Container · Write", mode: "container", write: true },
  { id: "fixture-host-readonly", label: "Host · Read only", mode: "host", write: false },
  { id: "fixture-host-write", label: "Host · Write", mode: "host", write: true },
];

const FIXTURE_TOOLS = [
  { id: "fixture_file_read", label: "File read", effect: "관찰" },
  { id: "fixture_file_write", label: "File write", effect: "변경 후 Reset" },
  { id: "fixture_service_status", label: "Service status", effect: "관찰" },
];

function statusLabel(status: HarnessStatus | null): string {
  if (!status) return "확인 중";
  return status.ready ? "READY" : "ADAPTER 대기";
}

interface HarnessPanelProps {
  permissionProfile: Record<string, boolean>;
  remote: boolean;
  subjectMode: SubjectModeId;
  trustBoundaryId: string;
}

export function HarnessPanel({
  permissionProfile,
  remote,
  subjectMode,
  trustBoundaryId,
}: HarnessPanelProps) {
  const [liveStatus, setLiveStatus] = useState<HarnessStatus | null>(null);
  const [fixtureStatus, setFixtureStatus] = useState<HarnessStatus | null>(null);
  const [selectedProfileId, setSelectedProfileId] = useState(FIXTURE_PROFILES[0].id);
  const [objective, setObjective] = useState("권한별 Tool 실행, 독립 검증, 상태 Reset을 확인한다.");
  const [run, setRun] = useState<HarnessRunRecord | null>(null);
  const [runLane, setRunLane] = useState<"live" | "fixture" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loadedRemote, setLoadedRemote] = useState<boolean | null>(null);
  const [isRunning, setIsRunning] = useState(false);

  useEffect(() => {
    let isActive = true;
    Promise.allSettled([getHarnessStatus(remote), getFixtureHarnessStatus()])
      .then(([liveResult, fixtureResult]) => {
        if (!isActive) return;
        if (liveResult.status === "fulfilled") {
          setLiveStatus(liveResult.value);
        } else {
          setLiveStatus(null);
        }
        if (fixtureResult.status === "fulfilled") {
          setFixtureStatus(fixtureResult.value);
        } else {
          setFixtureStatus(null);
        }
        const failedResult = [liveResult, fixtureResult].find(
          (result): result is PromiseRejectedResult => result.status === "rejected",
        );
        setError(
          failedResult
            ? failedResult.reason instanceof Error
              ? failedResult.reason.message
              : "Harness 상태를 불러오지 못했습니다."
            : null,
        );
      })
      .finally(() => {
        if (isActive) setLoadedRemote(remote);
      });
    return () => {
      isActive = false;
    };
  }, [remote]);

  const selectedProfile =
    FIXTURE_PROFILES.find((profile) => profile.id === selectedProfileId) ?? FIXTURE_PROFILES[0];
  const isLiveStatusLoading = loadedRemote !== remote;

  async function submitFixtureRun(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!objective.trim() || !fixtureStatus?.ready) return;
    setIsRunning(true);
    setRun(null);
    setRunLane("fixture");
    setError(null);
    try {
      setRun(await createFixtureHarnessRun({
        objective: objective.trim(),
        subject_mode: selectedProfile.mode,
        scenario_id: "dashboard-self-test",
        permission_profile_id: selectedProfile.id,
      }));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Fixture Harness 실행에 실패했습니다.");
    } finally {
      setIsRunning(false);
    }
  }

  async function submitLiveRun() {
    if (
      !objective.trim()
      || isLiveStatusLoading
      || !liveStatus?.ready
      || !trustBoundaryId
      || Object.keys(permissionProfile).length === 0
    ) return;
    setIsRunning(true);
    setRun(null);
    setRunLane("live");
    setError(null);
    try {
      setRun(await createHarnessRun({
        objective: objective.trim(),
        subject_mode: subjectMode,
        trust_boundary_id: trustBoundaryId,
        scenario_id: "dashboard-live-run",
        permission_profile: permissionProfile,
      }, remote));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Live Harness 실행에 실패했습니다.");
    } finally {
      setIsRunning(false);
    }
  }

  const permissionSummary = Object.entries(permissionProfile)
    .map(([name, enabled]) => `${name}:${enabled ? "ON" : "OFF"}`)
    .join(" · ");

  return (
    <section className="harness-panel" aria-labelledby="harness-title">
      <div className="harness-heading">
        <div>
          <span className="section-index">H1</span>
          <h2 id="harness-title">Agent Harness</h2>
          <p>실제 OS Adapter 연결 상태와 안전한 메모리 Fixture 자가진단을 분리해 확인합니다.</p>
        </div>
        <div className="harness-status-group" aria-live="polite">
          <span className={`harness-status ${!isLiveStatusLoading && liveStatus?.ready ? "is-ready" : "is-waiting"}`}>
            Live · {statusLabel(isLiveStatusLoading ? null : liveStatus)}
          </span>
          <span className={`harness-status ${fixtureStatus?.ready ? "is-ready" : "is-waiting"}`}>
            Fixture · {statusLabel(fixtureStatus)}
          </span>
        </div>
      </div>

      <div className="harness-component-grid" aria-label="Harness 구성요소 연결 상태">
        {(isLiveStatusLoading ? [] : liveStatus?.components ?? []).map((component) => (
          <div className={component.ready ? "is-ready" : "is-waiting"} key={component.name}>
            <span>{COMPONENT_LABELS[component.name]}</span>
            <strong>{component.ready ? "연결됨" : "추후 연결"}</strong>
          </div>
        ))}
        {isLiveStatusLoading ? <p className="loading-message">Adapter 상태 확인 중…</p> : null}
      </div>

      <div className="harness-workspace">
        <div className="fixture-catalog">
          <div className="harness-subheading">
            <span>MEMORY-ONLY</span>
            <h3>테스트 Fixture</h3>
            <p>실제 파일·명령·네트워크를 건드리지 않는 Harness 자가진단입니다.</p>
          </div>
          <dl className="fixture-summary">
            <div><dt>권한 Profile</dt><dd>4</dd></div>
            <div><dt>Tool</dt><dd>3</dd></div>
            <div><dt>Verifier</dt><dd>1</dd></div>
            <div><dt>Resetter</dt><dd>1</dd></div>
          </dl>
          <ul className="fixture-tool-list">
            {FIXTURE_TOOLS.map((tool) => (
              <li key={tool.id}>
                <div><strong>{tool.label}</strong><code>{tool.id}</code></div>
                <span>{tool.effect}</span>
              </li>
            ))}
          </ul>
        </div>

        <form className="fixture-run-form" onSubmit={submitFixtureRun}>
          <div className="harness-subheading">
            <span>SELF TEST</span>
            <h3>Harness Run 실행</h3>
            <p>State → Plan → Execute → Verify → Reset 전체 수명주기를 실행합니다.</p>
          </div>

          <label htmlFor="fixture-objective">Objective</label>
          <textarea id="fixture-objective" maxLength={4000} onChange={(event) => setObjective(event.target.value)} rows={3} value={objective} />

          <div className="live-harness-control">
            <span>LIVE RUNTIME</span>
            <strong>{trustBoundaryId || subjectMode} · {remote ? "EC2 via SSM" : "현재 Backend"}</strong>
            <code>{permissionSummary || "권한 Profile 준비 중"}</code>
            <button
              className="live-run-button"
              disabled={
                isRunning
                || isLiveStatusLoading
                || !liveStatus?.ready
                || !trustBoundaryId
                || !objective.trim()
                || Object.keys(permissionProfile).length === 0
              }
              onClick={submitLiveRun}
              type="button"
            >
              {isRunning && runLane === "live" ? "Live 실행 중" : "Live Harness 실행"}
            </button>
          </div>

          <div className="harness-run-divider"><span>MEMORY FIXTURE</span></div>

          <label htmlFor="fixture-profile">Fixture 권한 Profile</label>
          <select id="fixture-profile" onChange={(event) => setSelectedProfileId(event.target.value)} value={selectedProfileId}>
            {FIXTURE_PROFILES.map((profile) => (
              <option key={profile.id} value={profile.id}>{profile.label}</option>
            ))}
          </select>
          <div className="fixture-profile-meta">
            <span>Boundary · {selectedProfile.mode}</span>
            <span>Write · {selectedProfile.write ? "ALLOW" : "DENY"}</span>
          </div>
          {error ? <p className="error-message" role="alert">{error}</p> : null}
          <button className="fixture-run-button" disabled={isRunning || !fixtureStatus?.ready || !objective.trim()} type="submit">
            <span>{isRunning && runLane === "fixture" ? "Fixture 실행 중" : "Fixture Harness 실행"}</span>
            <span aria-hidden="true">↗</span>
          </button>
        </form>

        <div className="harness-result" aria-live="polite">
          <div className="harness-subheading">
            <span>{runLane === "live" ? "LIVE VERIFICATION" : "FIXTURE VERIFICATION"}</span>
            <h3>검증 결과</h3>
          </div>
          {run ? (
            <>
              <div className="harness-result-summary">
                <div><span>Run</span><code>{run.run_id}</code></div>
                <strong className={`is-${run.status.toLowerCase()}`}>{run.status}</strong>
              </div>
              <ul className="harness-action-list">
                {run.actions.map((action) => {
                  const checks = Object.values(action.verification.checks);
                  const runtimeTool = action.execution.evidence.runtime_result?.tool;
                  return (
                    <li key={action.candidate.candidate_id}>
                      <div>
                        <span>{String(action.sequence).padStart(2, "0")}</span>
                        <strong>{runtimeTool ?? action.candidate.tool_name}</strong>
                        <small>{action.execution.success ? "실행 허용" : action.execution.error_code}</small>
                      </div>
                      <div>
                        <span className={`verification-badge is-${action.verification.status.toLowerCase()}`}>{action.verification.status}</span>
                        <small>{checks.filter(Boolean).length}/{checks.length} checks · {action.reset.status}</small>
                      </div>
                    </li>
                  );
                })}
              </ul>
              <div className="harness-budget-line">
                <span>종료 · {run.termination_reason}</span>
                <span>Tool {run.budget.used_tool_calls ?? 0}/{run.budget.max_tool_calls}</span>
              </div>
            </>
          ) : (
            <p className="harness-result-empty">Profile을 선택해 실행하면 Tool별 허용·거부, 독립 검증, Reset 결과가 표시됩니다.</p>
          )}
        </div>
      </div>
    </section>
  );
}
