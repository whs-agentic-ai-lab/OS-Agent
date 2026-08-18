import type { DeploymentStatus, HealthResponse, OptionsResponse, RunRecord, RunRequest } from "./types";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, init);
  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as { detail?: string } | null;
    throw new Error(body?.detail ?? `요청에 실패했습니다. (${response.status})`);
  }
  return response.json() as Promise<T>;
}

export function getOptions(): Promise<OptionsResponse> {
  return request<OptionsResponse>("/api/options");
}

export function getHealth(): Promise<HealthResponse> {
  return request<HealthResponse>("/api/health");
}

export function createRun(payload: RunRequest): Promise<RunRecord> {
  return request<RunRecord>("/api/runs", {
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
