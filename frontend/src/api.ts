import type { DeploymentStatus, HealthResponse, OptionsResponse, RunDeleteResponse, RunListResponse, RunRecord, RunRequest, SubjectModeId, TunnelStatus } from "./types";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, init);
  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as { detail?: unknown } | null;
    const detail = typeof body?.detail === 'string'
      ? body.detail
      : Array.isArray(body?.detail)
        ? body.detail
          .map((item) => typeof item === 'object' && item !== null && 'msg' in item ? String(item.msg) : String(item))
          .join(', ')
        : null;
    throw new Error(detail ?? `요청에 실패했습니다. (${response.status})`);
  }
  return response.json() as Promise<T>;
}

function agentPath(path: string, remote: boolean): string {
  return remote ? path.replace("/api/", "/api/remote/") : path;
}

export function getOptions(remote = false): Promise<OptionsResponse> {
  return request<OptionsResponse>(agentPath("/api/options", remote));
}

export function getHealth(remote = false): Promise<HealthResponse> {
  return request<HealthResponse>(agentPath("/api/health", remote));
}

export function createRun(payload: RunRequest, remote = false): Promise<RunRecord> {
  return request<RunRecord>(agentPath("/api/runs", remote), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export function getRun(runId: string, remote = false): Promise<RunRecord> {
  return request<RunRecord>(agentPath(`/api/runs/${encodeURIComponent(runId)}`, remote));
}

export function getRuns(subjectMode: SubjectModeId, page = 1, pageSize = 20): Promise<RunListResponse> {
  const query = new URLSearchParams({
    subject_mode: subjectMode,
    page: String(page),
    page_size: String(pageSize),
  });
  return request<RunListResponse>(`/api/runs?${query.toString()}`);
}

export function deleteRun(runId: string): Promise<RunDeleteResponse> {
  return request<RunDeleteResponse>(`/api/runs/${encodeURIComponent(runId)}`, {
    method: "DELETE",
  });
}

export function getDeployment(): Promise<DeploymentStatus> {
  return request<DeploymentStatus>("/api/deployments/current");
}

export function createDeployment(environmentName: string): Promise<DeploymentStatus> {
  return request<DeploymentStatus>("/api/deployments", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      confirmation: "DEPLOY_FIXED_OS_ENVIRONMENT",
      environment_name: environmentName,
    }),
  });
}

export function initializeInfrastructure(): Promise<DeploymentStatus> {
  return request<DeploymentStatus>("/api/deployments/initialize", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ confirmation: "INITIALIZE_FIXED_TERRAFORM" }),
  });
}

export function destroyInfrastructure(environmentId: string): Promise<DeploymentStatus> {
  return request<DeploymentStatus>("/api/deployments/destroy", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      confirmation: "DESTROY_FIXED_OS_ENVIRONMENT",
      environment_id: environmentId,
    }),
  });
}

export function terminateInstance(instanceId: string): Promise<DeploymentStatus> {
  return request<DeploymentStatus>("/api/deployments/instances/terminate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      confirmation: "TERMINATE_OS_AGENT_INSTANCE",
      instance_id: instanceId,
    }),
  });
}

export function getTunnel(): Promise<TunnelStatus> {
  return request<TunnelStatus>("/api/tunnel");
}

export function startTunnel(instanceId: string): Promise<TunnelStatus> {
  return request<TunnelStatus>("/api/tunnel", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      confirmation: "START_FIXED_SSM_TUNNEL",
      target_instance_id: instanceId,
    }),
  });
}

export function stopTunnel(): Promise<TunnelStatus> {
  return request<TunnelStatus>("/api/tunnel/stop", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ confirmation: "STOP_FIXED_SSM_TUNNEL" }),
  });
}
