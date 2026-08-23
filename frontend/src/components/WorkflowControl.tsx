import { useMemo, useState } from "react";

import type { DeploymentStatus, RunRecord, TunnelStatus, WorkflowNode, WorkflowNodeStatus } from "../types";

interface WorkflowControlProps {
  deployment: DeploymentStatus | null;
  environmentName: string;
  deploymentActionError: string | null;
  tunnelActionError: string | null;
  tunnel: TunnelStatus | null;
  isStartingTunnel: boolean;
  isLoadingBackend: boolean;
  isRunningTest: boolean;
  isStartingDeployment: boolean;
  optionsReady: boolean;
  backendError: string | null;
  run: RunRecord | null;
  runError: string | null;
  onDeploy: (environmentName: string) => void;
  onEnvironmentNameChange: (environmentName: string) => void;
  onStartTunnel: () => void;
  onStopTunnel: () => void;
  onFocusExperiment: () => void;
}

interface WorkflowOverride {
  status: WorkflowNodeStatus;
  error: string | null;
}

interface WorkflowErrorLog {
  id: string;
  source: string;
  message: string;
  createdAt: string | null;
}

type WorkflowOverrides = Record<string, WorkflowOverride>;

const LEGACY_STORAGE_KEY = "os-agent-test.workflow-overrides.v1";
const workflowLogTimeFormatter = new Intl.DateTimeFormat("ko-KR", {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
});

const statusLabels: Record<WorkflowNodeStatus, string> = {
  pending: "대기",
  running: "실행 중",
  succeeded: "완료",
  failed: "오류",
  blocked: "차단",
};

function loadOverrides(): WorkflowOverrides {
  try {
    // 수동 표시는 현재 대시보드 세션에서만 사용한다. 새로고침이나 로컬
    // Orchestrator 재시작 뒤에는 AWS/Terraform의 최신 상태를 우선한다.
    window.localStorage.removeItem(LEGACY_STORAGE_KEY);
  } catch {
    // 저장소 접근이 막힌 환경에서도 워크플로 자동 동기화는 계속한다.
  }
  return {};
}

function deploymentNodes(deployment: DeploymentStatus | null, actionError: string | null): Pick<WorkflowNode, "status" | "error">[] {
  const empty: Pick<WorkflowNode, "status" | "error"> = { status: "pending", error: null };
  if (!deployment) return [empty, empty, empty];

  if (deployment.status === "not_ready") {
    const reason = actionError ?? "배포 CLI 또는 AWS 인증 준비가 필요합니다.";
    return [
      { status: reason ? "blocked" : "pending", error: reason },
      empty,
      empty,
    ];
  }

  if (deployment.operation === "initialize") {
    if (deployment.status === "running") {
      return [empty, { status: "running", error: null }, empty];
    }
    if (deployment.status === "failed") {
      return [empty, { status: "failed", error: deployment.error ?? actionError ?? "Terraform 초기화 중 오류가 발생했습니다." }, empty];
    }
    return [empty, empty, empty];
  }

  if (deployment.operation === "destroy") {
    if (deployment.status === "running") {
      return [empty, { status: "running", error: null }, empty];
    }
    if (deployment.status === "failed") {
      return [empty, { status: "failed", error: deployment.error ?? actionError ?? "Terraform 삭제 중 오류가 발생했습니다." }, empty];
    }
    return [empty, empty, empty];
  }

  if (deployment.status === "idle") return [empty, empty, empty];
  if (deployment.status === "succeeded") {
    return [
      { status: "succeeded", error: null },
      { status: "succeeded", error: null },
      { status: "succeeded", error: null },
    ];
  }

  const infrastructureApplyStarted = deployment.logs.some((entry) => entry.message.includes("-var=backend_image_uri="));
  if (deployment.status === "running") {
    return infrastructureApplyStarted
      ? [
          { status: "succeeded", error: null },
          { status: "running", error: null },
          empty,
        ]
      : [{ status: "running", error: null }, empty, empty];
  }

  return infrastructureApplyStarted
    ? [
        { status: "succeeded", error: null },
        { status: "failed", error: deployment.error ?? actionError ?? "Terraform 적용 중 오류가 발생했습니다." },
        empty,
      ]
    : [
        { status: "failed", error: deployment.error ?? actionError ?? "이미지 배포 중 오류가 발생했습니다." },
        empty,
        empty,
      ];
}

function formatWorkflowLogTime(value: string | null): string {
  return value ? workflowLogTimeFormatter.format(new Date(value)) : "시각 정보 없음";
}

export function WorkflowControl({
  deployment,
  environmentName,
  deploymentActionError,
  tunnelActionError,
  tunnel,
  isStartingTunnel,
  isLoadingBackend,
  isRunningTest,
  isStartingDeployment,
  optionsReady,
  backendError,
  run,
  runError,
  onDeploy,
  onEnvironmentNameChange,
  onStartTunnel,
  onStopTunnel,
  onFocusExperiment,
}: WorkflowControlProps) {
  const [overrides, setOverrides] = useState<WorkflowOverrides>(loadOverrides);
  const [selectedId, setSelectedId] = useState("local");

  const nodes = useMemo(() => {
    const [image, terraform, runtime] = deploymentNodes(deployment, deploymentActionError);
    const tunnelNode: Pick<WorkflowNode, "status" | "error"> = tunnelActionError
      ? { status: "failed", error: tunnelActionError }
      : tunnel?.status === "connected"
      ? { status: "succeeded", error: null }
      : tunnel?.status === "installing" || tunnel?.status === "starting"
        ? { status: "running", error: null }
        : tunnel?.status === "failed"
          ? { status: "failed", error: tunnel.error }
          : { status: "pending", error: tunnel?.error ?? null };
    const automaticNodes: WorkflowNode[] = [
      {
        id: "local",
        step: 1,
        title: "로컬 개발 · 단위 테스트",
        summary: "FastAPI, OpenRouter, Tool Runner, Executor, Collector, React",
        status: isLoadingBackend ? "running" : optionsReady ? "succeeded" : "failed",
        error: optionsReady ? null : backendError,
        automatic: true,
      },
      {
        id: "image",
        step: 2,
        title: "Docker 이미지 · ECR",
        summary: "백엔드 이미지를 빌드하고 고정 ECR repository에 push",
        ...image,
        automatic: true,
      },
      {
        id: "terraform",
        step: 3,
        title: "Terraform apply",
        summary: "VPC, EC2, IAM, ECR 권한과 Secret 경로 생성",
        ...terraform,
        automatic: true,
      },
      {
        id: "runtime",
        step: 4,
        title: "EC2 Runtime 기동",
        summary: "이미지를 pull하고 Compose로 Backend/Executor/Collector 실행",
        ...runtime,
        automatic: true,
      },
      {
        id: "tunnel",
        step: 5,
        title: "SSM 포트 포워딩",
        summary: "로컬 8001 포트를 EC2 백엔드 8000 포트에 연결",
        ...tunnelNode,
        automatic: true,
      },
      {
        id: "test",
        step: 6,
        title: "Agent 최소 테스트",
        summary: "Prompt와 Profile을 선택해 Tool 실행 및 로그 확인",
        status: isRunningTest ? "running" : run ? "succeeded" : runError ? "failed" : "pending",
        error: runError,
        automatic: true,
      },
      {
        id: "teardown",
        step: 7,
        title: "테스트 종료",
        summary: "결과를 확인하고 필요할 때 terraform destroy 수행",
        status: "pending",
        error: null,
        automatic: false,
      },
    ];

    return automaticNodes.map((node) => {
      const override = node.id === "tunnel" ? undefined : overrides[node.id];
      return override ? { ...node, ...override } : node;
    });
  }, [backendError, deployment, deploymentActionError, isLoadingBackend, isRunningTest, optionsReady, overrides, run, runError, tunnel, tunnelActionError]);

  const selected = nodes.find((node) => node.id === selectedId) ?? nodes[0];
  const completedCount = nodes.filter((node) => node.status === "succeeded").length;
  const failedCount = nodes.filter((node) => node.status === "failed" || node.status === "blocked").length;
  const validEnvironmentName = /^[a-z0-9](?:[a-z0-9-]{1,14}[a-z0-9])$/.test(environmentName);
  const deploymentReady = Object.values(deployment?.prerequisites ?? {}).every(Boolean);
  const errorLogs = useMemo(() => {
    const entries: WorkflowErrorLog[] = [];
    const messages = new Set<string>();
    const addLog = (source: string, message: string | null | undefined, createdAt: string | null = null) => {
      const normalized = message?.trim();
      if (!normalized || messages.has(normalized)) return;
      messages.add(normalized);
      entries.push({
        id: `${source}-${entries.length}`,
        source,
        message: normalized,
        createdAt,
      });
    };

    if (selected.id === "local") addLog("Backend", backendError);

    if (["image", "terraform", "runtime", "teardown"].includes(selected.id)) {
      for (const entry of deployment?.logs ?? []) {
        if (entry.level === "error") {
          addLog("AWS 배포", entry.message, entry.created_at);
        }
      }
      addLog("AWS 배포", deployment?.error);
      addLog("AWS 배포", deploymentActionError);
    }

    if (selected.id === "tunnel") {
      addLog("SSM", tunnelActionError);
      addLog("SSM", tunnel?.error);
      for (const [index, message] of (tunnel?.logs ?? []).entries()) {
        if (/error|failed|failure|denied|오류|실패|거부/i.test(message)) {
          addLog(`SSM #${index + 1}`, message);
        }
      }
    }

    if (selected.id === "test") {
      addLog("Agent 실행", runError);
      for (const event of run?.events ?? []) {
        if (/ERROR|FAILED|FAILURE/.test(event.event_type)) {
          addLog(event.source, `${event.event_type}: ${event.message}`, event.created_at);
        }
      }
    }

    addLog("상태", selected.error);

    return entries;
  }, [backendError, deployment, deploymentActionError, run, runError, selected.error, selected.id, tunnel, tunnelActionError]);

  function saveOverrides(next: WorkflowOverrides) {
    setOverrides(next);
  }

  function setManualStatus(status: WorkflowNodeStatus, error: string | null = null) {
    saveOverrides({ ...overrides, [selected.id]: { status, error } });
  }

  function clearSelectedOverride() {
    const next = { ...overrides };
    delete next[selected.id];
    saveOverrides(next);
  }

  function clearAllOverrides() {
    saveOverrides({});
  }

  return (
    <section className="workflow-control" aria-labelledby="workflow-title">
      <div className="workflow-heading">
        <div>
          <span className="section-index">00</span>
          <h2 id="workflow-title">최소 운영 워크플로우</h2>
          <p>실제 실행 상태와 수동 체크포인트를 하나의 방향성 그래프로 관리합니다.</p>
        </div>
        <dl className="workflow-summary">
          <div><dt>완료</dt><dd>{completedCount} / 7</dd></div>
          <div><dt>오류·차단</dt><dd>{failedCount}</dd></div>
        </dl>
      </div>

      <ol className="workflow-graph" aria-label="OS 환경 테스트 워크플로우">
        {nodes.map((node, index) => (
          <li key={node.id}>
            <button
              className={`workflow-node is-${node.status}${selected.id === node.id ? " is-selected" : ""}`}
              onClick={() => setSelectedId(node.id)}
              type="button"
            >
              <span className="workflow-node-meta">
                <span>{String(node.step).padStart(2, "0")}</span>
                <span className="workflow-node-status">{statusLabels[node.status]}</span>
              </span>
              <strong>{node.title}</strong>
              <small>{node.summary}</small>
              <span className="workflow-node-source">{overrides[node.id] ? "수동 상태" : node.automatic ? "자동 동기화" : "수동 확인"}</span>
            </button>
            {index < nodes.length - 1 ? <span className="workflow-arrow" aria-hidden="true">→</span> : null}
          </li>
        ))}
      </ol>

      <div className="workflow-inspector">
        <div className="workflow-inspector-copy">
          <span>선택한 노드 · {String(selected.step).padStart(2, "0")}</span>
          <h3>{selected.title}</h3>
          <p>{selected.error ?? selected.summary}</p>
        </div>

        <div className="workflow-state-control">
          <span>상태 제어</span>
          <div>
            {(["pending", "running", "succeeded", "blocked"] as WorkflowNodeStatus[]).map((status) => (
              <button className={selected.status === status ? "is-active" : ""} key={status} onClick={() => setManualStatus(status)} type="button">
                {statusLabels[status]}
              </button>
            ))}
          </div>
          <button className="workflow-reset-node" disabled={!overrides[selected.id]} onClick={clearSelectedOverride} type="button">
            자동 상태로 복원
          </button>
          <button className="workflow-reset-node" disabled={Object.keys(overrides).length === 0} onClick={clearAllOverrides} type="button">
            전체 수동 상태 초기화
          </button>
        </div>

        <div className="workflow-error-log" aria-live="polite">
          <div className="workflow-error-log-heading">
            <span>오류 로그</span>
            <b>{errorLogs.length}</b>
          </div>
          {errorLogs.length > 0 ? (
            <ol>
              {errorLogs.map((entry) => (
                <li key={entry.id}>
                  <div>
                    <strong>{entry.source}</strong>
                    <time>{formatWorkflowLogTime(entry.createdAt)}</time>
                  </div>
                  <p>{entry.message}</p>
                </li>
              ))}
            </ol>
          ) : (
            <p className="workflow-error-empty">선택한 노드에서 수집된 오류가 없습니다.</p>
          )}
        </div>

        <div className="workflow-context-action">
          {selected.id === "image" || selected.id === "terraform" || selected.id === "runtime" ? (
            <div className="workflow-deploy-action">
              <label htmlFor="workflow-environment-name">환경 이름</label>
              <input
                autoComplete="off"
                id="workflow-environment-name"
                maxLength={16}
                onChange={(event) => onEnvironmentNameChange(event.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ""))}
                placeholder="permission-test"
                value={environmentName}
              />
              <button
                disabled={
                  !deploymentReady ||
                  !validEnvironmentName ||
                  isStartingDeployment ||
                  deployment?.status === "running"
                }
                onClick={() => onDeploy(environmentName)}
                type="button"
              >
                {deployment?.status === "failed" ? "배포 다시 실행" : "환경 배포 실행"}
              </button>
            </div>
          ) : null}
          {selected.id === "test" ? <button onClick={onFocusExperiment} type="button">실험 구성으로 이동</button> : null}
          {selected.id === "tunnel" ? (
            tunnel?.status === "connected" ? (
              <button disabled={isStartingTunnel} onClick={onStopTunnel} type="button">SSM 연결 종료</button>
            ) : (
              <button disabled={isStartingTunnel || tunnel?.status === "installing" || tunnel?.status === "starting"} onClick={onStartTunnel} type="button">
                {tunnel?.status === "installing" ? "플러그인 설치 중" : tunnel?.status === "starting" ? "SSM 연결 중" : "SSM 자동 연결"}
              </button>
            )
          ) : null}
          {selected.id === "teardown" ? <p>삭제는 대시보드에서 자동 실행하지 않습니다. 리소스를 확인한 뒤 Terraform CLI에서 수행합니다.</p> : null}
        </div>
      </div>
    </section>
  );
}
