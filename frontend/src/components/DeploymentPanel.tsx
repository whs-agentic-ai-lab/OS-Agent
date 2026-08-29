import type { DeploymentState, DeploymentStatus, ExperimentEnvironmentResetResult, TunnelStatus } from "../types";

interface DeploymentPanelProps {
  deployment: DeploymentStatus | null;
  environmentName: string;
  actionError: string | null;
  isStarting: boolean;
  isStartingTunnel: boolean;
  isResettingExperiment: boolean;
  experimentResetResult: ExperimentEnvironmentResetResult | null;
  experimentResetError: string | null;
  onDeploy: (environmentName: string) => void;
  onEnvironmentNameChange: (environmentName: string) => void;
  onDestroy: (environmentId: string) => void;
  onRefresh: () => void;
  onResetExperiment: () => void;
  onSelectInstance: (instanceId: string) => void;
  onStartTunnel: () => void;
  onStopTunnel: () => void;
  onTerminateInstance: (instanceId: string) => void;
  selectedInstanceId: string | null;
  tunnel: TunnelStatus | null;
}

const statusLabels: Record<DeploymentState, string> = {
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

function statusLabel(deployment: DeploymentStatus | null): string {
  if (!deployment) return statusLabels.not_ready;
  if (deployment.status === "running") {
    if (deployment.operation === "initialize") return "초기화 중";
    if (deployment.operation === "destroy") return "삭제 중";
  }
  if (deployment.status === "succeeded") {
    if (deployment.operation === "initialize") return "초기화 완료";
    if (deployment.operation === "destroy") return "삭제 완료";
  }
  return statusLabels[deployment.status];
}

export function DeploymentPanel({
  deployment,
  environmentName,
  actionError,
  isStarting,
  isStartingTunnel,
  isResettingExperiment,
  experimentResetResult,
  experimentResetError,
  onDeploy,
  onEnvironmentNameChange,
  onDestroy,
  onRefresh,
  onResetExperiment,
  onSelectInstance,
  onStartTunnel,
  onStopTunnel,
  onTerminateInstance,
  selectedInstanceId,
  tunnel,
}: DeploymentPanelProps) {
  const status = deployment?.status ?? "not_ready";
  const prerequisites = deployment?.prerequisites ?? {};
  const isBusy = status === "running" || isStarting || isResettingExperiment;
  const canDeploy = Boolean(
    Object.values(prerequisites).every(Boolean) &&
      !isBusy,
  );
  const selectedInstance = deployment?.instances.find(
    (instance) => instance.instance_id === selectedInstanceId,
  );
  const selectedInstanceHasTunnel = Boolean(
    selectedInstance &&
      tunnel?.target_instance_id === selectedInstance.instance_id &&
      ["installing", "starting", "connected"].includes(tunnel.status),
  );
  const selectedInstanceTunnelConnected = Boolean(
    selectedInstance &&
      tunnel?.target_instance_id === selectedInstance.instance_id &&
      tunnel.status === "connected",
  );
  const canResetExperiment = Boolean(
    selectedInstanceTunnelConnected &&
      selectedInstance?.state === "running" &&
      !isBusy &&
      !isResettingExperiment,
  );
  const canDestroy = Boolean(
    prerequisites.terraform &&
      prerequisites.aws_cli &&
      prerequisites.terraform_files &&
      selectedInstance?.local_state_available &&
      !isBusy,
  );
  const validEnvironmentName = /^[a-z0-9](?:[a-z0-9-]{1,14}[a-z0-9])$/.test(environmentName);
  const environmentPreview = deployment?.caller_identity && validEnvironmentName
    ? `${deployment.caller_identity.environment_prefix}-${environmentName}`
    : null;
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
        <span className={`deployment-status is-${status}`}>{statusLabel(deployment)}</span>
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
          <div className="environment-create">
            <label htmlFor="environment-name">환경 이름</label>
            <div>
              <input
                autoComplete="off"
                id="environment-name"
                maxLength={16}
                onChange={(event) => onEnvironmentNameChange(event.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ""))}
                placeholder="permission-test"
                value={environmentName}
              />
              <button
                className="infrastructure-button is-primary"
                disabled={!canDeploy || !validEnvironmentName}
                onClick={() => onDeploy(environmentName)}
                type="button"
              >
              AWS 환경 배포
              </button>
            </div>
            <p>
              로그인 사용자: <strong>{deployment?.caller_identity?.display_name ?? "확인 중"}</strong>
              {environmentPreview ? <code>{environmentPreview}</code> : <span>3~16자의 영문 소문자·숫자·하이픈</span>}
            </p>
          </div>
          {status === "not_ready" ? (
            <p className="deployment-notice">표시된 CLI와 AWS 인증을 먼저 준비해 주세요.</p>
          ) : null}
          {actionError ? <p className="error-message" role="alert">{actionError}</p> : null}
        </div>
      </div>

      <div className="instance-inventory">
        <div className="instance-inventory-heading">
          <div>
            <h3>AWS EC2 인스턴스</h3>
            <p>실제 AWS 목록을 기준으로 연결할 환경을 선택합니다.</p>
          </div>
          <button className="infrastructure-button is-secondary" disabled={isBusy} onClick={onRefresh} type="button">
            목록 새로고침
          </button>
        </div>

        {deployment?.instances.length ? (
          <div className="instance-table-wrap">
            <table className="instance-table">
              <thead>
                <tr>
                  <th scope="col">선택</th>
                  <th scope="col">환경</th>
                  <th scope="col">생성자</th>
                  <th scope="col">EC2</th>
                  <th scope="col">상태</th>
                  <th scope="col">SSM</th>
                </tr>
              </thead>
              <tbody>
                {deployment.instances.map((instance) => (
                  <tr className={instance.instance_id === selectedInstanceId ? "is-selected" : ""} key={instance.instance_id}>
                    <td>
                      <input
                        aria-label={`${instance.environment_id} 선택`}
                        checked={instance.instance_id === selectedInstanceId}
                        name="selected-instance"
                        onChange={() => onSelectInstance(instance.instance_id)}
                        type="radio"
                      />
                    </td>
                    <td><strong>{instance.environment_id}</strong><small>{instance.name}</small></td>
                    <td>{instance.created_by}</td>
                    <td><code>{instance.instance_id}</code><small>{instance.instance_type} · {instance.availability_zone}</small></td>
                    <td><span className={`instance-state is-${instance.state}`}>{instance.state}</span></td>
                    <td>{instance.ssm_ping_status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="deployment-notice">현재 AWS 계정에서 os-agent-test EC2를 찾지 못했습니다.</p>
        )}

        <div className="instance-actions">
          {selectedInstanceTunnelConnected ? (
            <button
              className="infrastructure-button is-secondary"
              disabled={isStartingTunnel || isResettingExperiment}
              onClick={onStopTunnel}
              type="button"
            >
              {isStartingTunnel ? "SSM 연결 종료 중" : "SSM 연결 종료"}
            </button>
          ) : (
            <button
              className="infrastructure-button is-primary"
              disabled={
                !selectedInstance ||
                selectedInstance.state !== "running" ||
                isStartingTunnel ||
                isResettingExperiment ||
                tunnel?.status === "connected" ||
                tunnel?.status === "installing" ||
                tunnel?.status === "starting"
              }
              onClick={onStartTunnel}
              type="button"
            >
              {tunnel?.status === "installing" || tunnel?.status === "starting"
                ? "SSM 연결 중"
                : "선택 EC2 SSM 연결"}
            </button>
          )}
          <button
            className="infrastructure-button is-secondary"
            disabled={!canResetExperiment}
            onClick={onResetExperiment}
            type="button"
          >
            {isResettingExperiment ? "실험 환경 초기화 중" : "실험 환경 초기화"}
          </button>
          <button
            className="infrastructure-button is-danger"
            disabled={!canDestroy || !selectedInstance || selectedInstanceHasTunnel}
            onClick={() => selectedInstance && onDestroy(selectedInstance.environment_id)}
            type="button"
          >
            환경 전체 삭제
          </button>
          <button
            className="infrastructure-button is-danger is-outline"
            disabled={!selectedInstance || isBusy || selectedInstanceHasTunnel}
            onClick={() => selectedInstance && onTerminateInstance(selectedInstance.instance_id)}
            type="button"
          >
            EC2만 종료
          </button>
        </div>
        {experimentResetResult?.status === "RESET" ? (
          <p className="deployment-notice is-success">
            실험 환경 초기화와 기준 상태 검증이 완료되었습니다. ({(experimentResetResult.duration_ms / 1000).toFixed(1)}초)
          </p>
        ) : null}
        {experimentResetError ? <p className="error-message">{experimentResetError}</p> : null}
        {selectedInstance && !selectedInstance.local_state_available ? (
          <p className="deployment-notice">
            이 PC에는 {selectedInstance.environment_id}의 Terraform state가 없어 전체 삭제할 수 없습니다. EC2 단독 종료는 다른 AWS 리소스를 남깁니다.
          </p>
        ) : null}
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
