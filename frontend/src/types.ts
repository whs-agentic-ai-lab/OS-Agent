export type SubjectModeId = "container" | "host";
export type TestResult = "PASS" | "FAIL" | "INCONCLUSIVE";

export interface SubjectMode {
  id: SubjectModeId;
  label: string;
  description: string;
  enabled: boolean;
}

export interface PermissionTest {
  id: string;
  label: string;
  description: string;
  off_profile: string;
  on_profile: string;
}

export interface ToolOption {
  id: string;
  label: string;
  description: string;
}

export interface OptionsResponse {
  subject_modes: SubjectMode[];
  permission_tests: Record<SubjectModeId, PermissionTest[]>;
  tools: ToolOption[];
  planner_mode: "local" | "openrouter";
}

export interface HealthResponse {
  status: string;
  planner: string;
  storage: string;
}

export interface RunRequest {
  prompt: string;
  subject_mode: SubjectModeId;
  permission_id: string;
  permission_enabled: boolean;
}

export interface RunEvent {
  sequence: number;
  source: "profile" | "model" | "tool_runner" | "executor" | "verifier";
  event_type: string;
  message: string;
  payload: Record<string, unknown>;
  created_at: string;
}

export interface RunRecord extends RunRequest {
  run_id: string;
  status: string;
  requested_profile: string;
  applied_profile: string | null;
  planner_mode: "local" | "openrouter";
  tool: string | null;
  runtime_result: "allowed" | "denied" | "error" | null;
  output: string | null;
  exit_code: number | null;
  before_sha256: string | null;
  after_sha256: string | null;
  test_result: TestResult | null;
  events: RunEvent[];
  created_at: string;
  completed_at: string | null;
}

export type DeploymentState = "disabled" | "not_ready" | "idle" | "running" | "succeeded" | "failed";

export interface DeploymentLog {
  sequence: number;
  level: "info" | "error";
  message: string;
  created_at: string;
}

export interface DeploymentStatus {
  status: DeploymentState;
  enabled: boolean;
  prerequisites: Record<string, boolean>;
  fixed_environment: {
    region: string;
    availability_zone: string;
    instance_type: string;
    instance_count: number;
    access: string;
  };
  logs: DeploymentLog[];
  outputs: Record<string, unknown>;
  error: string | null;
  started_at: string | null;
  completed_at: string | null;
}

export type WorkflowNodeStatus = "pending" | "running" | "succeeded" | "failed" | "blocked";

export interface WorkflowNode {
  id: string;
  step: number;
  title: string;
  summary: string;
  status: WorkflowNodeStatus;
  error: string | null;
  automatic: boolean;
}
