export type SubjectModeId = "container" | "host";
export type EnvironmentNodeId = "u1" | "u2" | "c1" | "c2" | "c3";
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
  off_description: string;
  on_description: string;
  catalog_ids: string[];
  axis: string;
  default_enabled: boolean;
}

export interface PermissionCatalogSummary {
  source_version: string;
  total_entries: number;
  independent_permission_count: number | null;
  policy: string;
}

export interface ToolOption {
  id: string;
  label: string;
  description: string;
  family: string;
  actions: string[];
  implemented: boolean;
  implemented_actions: string[];
}

export interface TrustBoundaryOption {
  id: string;
  boundary_type: "HH" | "HC" | "CC";
  source_mode: SubjectModeId;
  source_environment: EnvironmentNodeId;
  target_environment: EnvironmentNodeId;
  label: string;
  description: string;
}

export interface OptionsResponse {
  subject_modes: SubjectMode[];
  permission_tests: Record<SubjectModeId, PermissionTest[]>;
  tools: ToolOption[];
  trust_boundaries: TrustBoundaryOption[];
  permission_catalog_summary: PermissionCatalogSummary;
  planner_mode: "local" | "openrouter";
  planner_models: PlannerModelOption[];
}

export type PlannerModelId =
  | "openai/gpt-5-mini"
  | "z-ai/glm-5.3-flash"
  | "deepseek/deepseek-v4-flash-0731";

export interface PlannerModelOption {
  id: PlannerModelId;
  label: string;
  description: string;
}

export interface HealthResponse {
  status: string;
  run_api_version?: "permission-control-runtime-v5" | "permission-control-runtime-v6";
  harness_api_version?: "os-harness-v1";
  planner: string;
  storage: string;
  host_supervisor: "connected" | "unavailable";
  active_executor?: SubjectModeId | null;
}

export interface RunRequest {
  prompt: string;
  subject_mode: SubjectModeId;
  trust_boundary_id: string;
  permission_profile: Record<string, boolean>;
  planner_model?: PlannerModelId;
}

export interface PermissionSelection {
  permission_id: string;
  enabled: boolean;
}

export interface PermissionRunResult {
  permission_id: string;
  permission_enabled: boolean;
  requested_profile: string;
  applied_profile: string | null;
  resource_id: string;
  runtime_result: "allowed" | "denied" | "error" | null;
  output: string | null;
  exit_code: number | null;
  before_sha256: string | null;
  after_sha256: string | null;
  verifier_name: string;
  verifier_effect: Record<string, boolean>;
  test_result: TestResult | null;
}

export interface RunEvent {
  sequence: number;
  source: "profile" | "model" | "tool_runner" | "executor" | "runtime_agent" | "supervisor" | "verifier";
  event_type: string;
  message: string;
  payload: Record<string, unknown>;
  created_at: string;
}

export interface RunRecord {
  prompt: string;
  subject_mode: SubjectModeId;
  trust_boundary_id: string;
  source_environment: EnvironmentNodeId | null;
  target_environment: EnvironmentNodeId | null;
  permission_id: string;
  permission_enabled: boolean;
  permission_profile: Record<string, boolean>;
  permissions?: PermissionSelection[];
  permission_results?: PermissionRunResult[];
  run_id: string;
  status: string;
  requested_profile: string;
  applied_profile: string | null;
  applied_profile_state: Record<string, unknown>;
  result_format_version?: "common-minimum-v1" | "common-minimum-v2";
  profile_version?: string;
  workload_type?: "normal" | "attack" | "UNIMPLEMENTED";
  action_path_id?: string;
  changed_variable?: string;
  planner_mode: "local" | "openrouter";
  planner_model: PlannerModelId | null;
  runtime_agent: string;
  tool: string | null;
  tool_arguments: Record<string, unknown>;
  policy_decision?: "allowed" | "denied" | "UNIMPLEMENTED";
  authentication_result?: "succeeded" | "failed" | "UNIMPLEMENTED";
  authorization_result?: "allowed" | "denied" | "error" | "UNIMPLEMENTED";
  runtime_result: "allowed" | "denied" | "error" | null;
  output: string | null;
  exit_code: number | null;
  before_sha256: string | null;
  after_sha256: string | null;
  verifier_name?: string;
  verifier_effect?: Record<string, boolean>;
  evidence_references?: string[];
  test_result: TestResult | null;
  events: RunEvent[];
  created_at: string;
  completed_at: string | null;
}

export interface RunListResponse {
  items: RunRecord[];
  total: number;
  page: number;
  page_size: number;
}

export interface RunDeleteResponse {
  run_id: string;
  deleted: boolean;
}

export type DeploymentState = "not_ready" | "idle" | "running" | "succeeded" | "failed";

export interface DeploymentLog {
  sequence: number;
  level: "info" | "error";
  message: string;
  created_at: string;
}

export interface AwsCallerIdentity {
  account_id: string;
  arn: string;
  display_name: string;
  owner_key: string;
  environment_prefix: string;
}

export interface AwsInstanceSummary {
  instance_id: string;
  name: string;
  environment_id: string;
  created_by: string;
  owner_arn: string;
  state: string;
  instance_type: string;
  availability_zone: string;
  private_ip: string | null;
  launch_time: string | null;
  ssm_ping_status: string;
  local_state_available: boolean;
}

export interface DeploymentStatus {
  status: DeploymentState;
  operation: "none" | "initialize" | "deploy" | "destroy";
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
  caller_identity: AwsCallerIdentity | null;
  instances: AwsInstanceSummary[];
}

export type TunnelState = "not_ready" | "installing" | "idle" | "starting" | "connected" | "failed";

export interface TunnelStatus {
  status: TunnelState;
  target_instance_id: string | null;
  local_port: number;
  remote_port: number;
  error: string | null;
  logs: string[];
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
