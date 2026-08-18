import { useMemo, useState } from "react";

import type { DeploymentStatus, RunRecord, WorkflowNode, WorkflowNodeStatus } from "../types";

interface WorkflowControlProps {
  deployment: DeploymentStatus | null;
  deploymentActionError: string | null;
  isLoadingBackend: boolean;
  isRunningTest: boolean;
  isStartingDeployment: boolean;
  optionsReady: boolean;
  backendError: string | null;
  run: RunRecord | null;
  runError: string | null;
  onDeploy: () => void;
  onFocusExperiment: () => void;
}

interface WorkflowOverride {
  status: WorkflowNodeStatus;
  error: string | null;
}

type WorkflowOverrides = Record<string, WorkflowOverride>;

const STORAGE_KEY = "os-agent-test.workflow-overrides.v1";

const statusLabels: Record<WorkflowNodeStatus, string> = {
  pending: "대기",
  running: "실행 중",
  succeeded: "완료",
  failed: "오류",
  blocked: "차단",
};

function loadOverrides(): WorkflowOverrides {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    return stored ? (JSON.parse(stored) as WorkflowOverrides) : {};
  } catch {
    return {};
  }
}

function deploymentNodes(deployment: DeploymentStatus | null, actionError: string | null): Pick<WorkflowNode, "status" | "error">[] {
  const empty: Pick<WorkflowNode, "status" | "error"> = { status: "pending", error: null };
  if (!deployment) return [empty, empty, empty];

  if (deployment.status === "disabled" || deployment.status === "not_ready") {
    const reason = actionError ?? (deployment.status === "not_ready" ? "배포 CLI 또는 AWS 인증 준비가 필요합니다." : null);
    return [
      { status: reason ? "blocked" : "pending", error: reason },
      empty,
      empty,
    ];
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

export function WorkflowControl({
  deployment,
  deploymentActionError,
  isLoadingBackend,
  isRunningTest,
  isStartingDeployment,
  optionsReady,
  backendError,
  run,
  runError,
  onDeploy,
  onFocusExperiment,
}: WorkflowControlProps) {
  const [overrides, setOverrides] = useState<WorkflowOverrides>(loadOverrides);
  const [selectedId, setSelectedId] = useState("local");
  const [errorDraft, setErrorDraft] = useState("");

  const nodes = useMemo(() => {
    const [image, terraform, runtime] = deploymentNodes(deployment, deploymentActionError);
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
        summary: "로컬 대시보드를 EC2 백엔드 8000 포트에 연결",
        status: "pending",
        error: null,
        automatic: false,
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
      const override = overrides[node.id];
      return override ? { ...node, ...override } : node;
    });
  }, [backendError, deployment, deploymentActionError, isLoadingBackend, isRunningTest, optionsReady, overrides, run, runError]);

  const selected = nodes.find((node) => node.id === selectedId) ?? nodes[0];
  const completedCount = nodes.filter((node) => node.status === "succeeded").length;
  const failedCount = nodes.filter((node) => node.status === "failed" || node.status === "blocked").length;

  function saveOverrides(next: WorkflowOverrides) {
    setOverrides(next);
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
  }

  function setManualStatus(status: WorkflowNodeStatus, error: string | null = null) {
    saveOverrides({ ...overrides, [selected.id]: { status, error } });
  }

  function clearSelectedOverride() {
    const next = { ...overrides };
    delete next[selected.id];
    saveOverrides(next);
    setErrorDraft("");
  }

  function clearAllOverrides() {
    saveOverrides({});
    setErrorDraft("");
  }

  function recordError() {
    const message = errorDraft.trim();
    if (!message) return;
    setManualStatus("failed", message);
    setErrorDraft("");
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
              onClick={() => {
                setSelectedId(node.id);
                setErrorDraft(node.error ?? "");
              }}
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
        </div>

        <div className="workflow-error-control">
          <label htmlFor="workflow-error">오류 기록</label>
          <textarea
            id="workflow-error"
            onChange={(event) => setErrorDraft(event.target.value)}
            placeholder="재현 조건이나 실패 원인을 기록하세요."
            rows={2}
            value={errorDraft}
          />
          <div>
            <button disabled={!errorDraft.trim()} onClick={recordError} type="button">오류로 기록</button>
            <button disabled={Object.keys(overrides).length === 0} onClick={clearAllOverrides} type="button">전체 수동 상태 초기화</button>
          </div>
        </div>

        <div className="workflow-context-action">
          {selected.id === "image" || selected.id === "terraform" || selected.id === "runtime" ? (
            <button disabled={isStartingDeployment || deployment?.status === "running"} onClick={onDeploy} type="button">
              {deployment?.status === "failed" ? "배포 다시 실행" : "환경 배포 실행"}
            </button>
          ) : null}
          {selected.id === "test" ? <button onClick={onFocusExperiment} type="button">실험 구성으로 이동</button> : null}
          {selected.id === "tunnel" ? <p>Terraform output의 <code>backend_ssm_port_forward_commands</code>를 실행한 뒤 완료 처리합니다.</p> : null}
          {selected.id === "teardown" ? <p>삭제는 대시보드에서 자동 실행하지 않습니다. 리소스를 확인한 뒤 Terraform CLI에서 수행합니다.</p> : null}
        </div>
      </div>
    </section>
  );
}
