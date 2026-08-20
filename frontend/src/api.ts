import type { DeploymentStatus, HealthResponse, OptionsResponse, RunRecord, RunRequest, TunnelStatus } from "./types";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, init);
  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as { detail?: string } | null;
    throw new Error(body?.detail ?? `요청에 실패했습니다. (${response.status})`);
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

export function getDeployment(): Promise<DeploymentStatus> {
  return request<DeploymentStatus>("/api/deployments/current");
}

export function createDeployment(): Promise<DeploymentStatus> {
  return request<DeploymentStatus>("/api/deployments", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ confirmation: "DEPLOY_FIXED_OS_ENVIRONMENT" }),
  });
}

export function initializeInfrastructure(): Promise<DeploymentStatus> {
  return request<DeploymentStatus>("/api/deployments/initialize", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ confirmation: "INITIALIZE_FIXED_TERRAFORM" }),
  });
}

export function destroyInfrastructure(): Promise<DeploymentStatus> {
  return request<DeploymentStatus>("/api/deployments/destroy", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      confirmation: "DESTROY_FIXED_OS_ENVIRONMENT",
      environment_name: "os-agent-test",
    }),
  });
}

export function getTunnel(): Promise<TunnelStatus> {
  return request<TunnelStatus>("/api/tunnel");
}

export function startTunnel(): Promise<TunnelStatus> {
  return request<TunnelStatus>("/api/tunnel", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ confirmation: "START_FIXED_SSM_TUNNEL" }),
  });
}

export function stopTunnel(): Promise<TunnelStatus> {
  return request<TunnelStatus>("/api/tunnel/stop", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ confirmation: "STOP_FIXED_SSM_TUNNEL" }),
  });
}
