import type { DeploymentState, DeploymentStatus } from "../types";

interface DeploymentPanelProps {
  deployment: DeploymentStatus | null;
  actionError: string | null;
  isStarting: boolean;
  onDeploy: () => void;
}

const statusLabels: Record<DeploymentState, string> = {
  disabled: "비활성",
  not_ready: "준비 필요",
  idle: "배포 가능",
  running: "배포 중",
  succeeded: "배포 완료",
  failed: "배포 실패",
};

const prerequisiteLabels: Record<string, string> = {
  terraform: "Terraform CLI",
  aws_cli: "AWS CLI",
  docker: "Docker",
  terraform_files: "고정 Terraform",
};

export function DeploymentPanel({ deployment, actionError, isStarting, onDeploy }: DeploymentPanelProps) {
  const status = deployment?.status ?? "not_ready";
  const canDeploy = Boolean(
    deployment?.enabled &&
      Object.values(deployment.prerequisites).every(Boolean) &&
      status !== "running" &&
      !isStarting,
  );
  const environment = deployment?.fixed_environment;
  const outputs = Object.entries(deployment?.outputs ?? {});

  return (
    <section className="deployment-panel" aria-labelledby="deployment-title">
      <div className="deployment-heading">
        <div>
          <span className="section-index">01</span>
          <h2 id="deployment-title">고정 환경 배포</h2>
          <p>AWS 콘솔 작업 없이 승인된 Terraform과 백엔드 이미지를 한 번에 배포합니다.</p>
        </div>
        <span className={`deployment-status is-${status}`}>{statusLabels[status]}</span>
      </div>

      <div className="deployment-body">
        <dl className="fixed-environment">
          <div><dt>Region / AZ</dt><dd>{environment ? `${environment.region} / ${environment.availability_zone}` : "—"}</dd></div>
          <div><dt>Compute</dt><dd>{environment ? `${environment.instance_type} × ${environment.instance_count}` : "—"}</dd></div>
          <div><dt>Access</dt><dd>{environment?.access ?? "—"}</dd></div>
          <div><dt>Runtime</dt><dd>Container + Ubuntu Host</dd></div>
        </dl>

        <div className="deployment-actions">
          <div className="prerequisite-list" aria-label="배포 사전 요구사항">
            {Object.entries(deployment?.prerequisites ?? {}).map(([key, ready]) => (
              <span className={ready ? "is-ready" : "is-missing"} key={key}>
                <i aria-hidden="true" />
                {prerequisiteLabels[key] ?? key}
              </span>
            ))}
          </div>
          <button className="deploy-button" disabled={!canDeploy} onClick={onDeploy} type="button">
            <span>{status === "running" || isStarting ? "AWS 환경 배포 중" : "AWS 환경 배포"}</span>
            <span aria-hidden="true">↗</span>
          </button>
          {!deployment?.enabled ? (
            <p className="deployment-notice">
              로컬 백엔드에서 <code>DEPLOYMENT_ENABLED=true</code>를 설정하면 배포 버튼이 활성화됩니다.
            </p>
          ) : null}
          {status === "not_ready" ? (
            <p className="deployment-notice">표시된 CLI와 AWS 인증을 먼저 준비해 주세요.</p>
          ) : null}
          {actionError ? <p className="error-message" role="alert">{actionError}</p> : null}
        </div>
      </div>

      {deployment && (deployment.logs.length > 0 || deployment.error) ? (
        <div className="deployment-log" aria-live="polite">
          <div>
            <span>Deployment log</span>
            <span>{deployment.logs.length} lines</span>
          </div>
          <ol>
            {deployment.logs.map((entry) => (
              <li className={entry.level === "error" ? "is-error" : ""} key={entry.sequence}>
                <span>{String(entry.sequence).padStart(2, "0")}</span>
                <p>{entry.message}</p>
              </li>
            ))}
          </ol>
        </div>
      ) : null}

      {outputs.length > 0 ? (
        <div className="deployment-outputs">
          <h3>Terraform outputs</h3>
          <dl>
            {outputs.map(([key, value]) => (
              <div key={key}>
                <dt>{key}</dt>
                <dd>{typeof value === "string" ? value : JSON.stringify(value)}</dd>
              </div>
            ))}
          </dl>
        </div>
      ) : null}
    </section>
  );
}
