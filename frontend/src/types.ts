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
  agent_run_api_version?: "os-agent-orchestrator-v1" | "os-agent-orchestrator-v2" | "os-agent-orchestrator-v3" | "os-agent-orchestrator-v4" | "os-agent-orchestrator-v5";
  harness_api_version?: "os-harness-v1";
  planner: string;
  storage: string;
  host_supervisor: "connected" | "unavailable";
  active_executor?: SubjectModeId | null;
  active_agent_run_id?: string | null;
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
  source: "profile" | "model" | "tool_runner" | "executor" | "runtime_agent" | "supervisor" | "verifier" | "orchestrator" | "recon" | "analyzer" | "planner" | "policy" | "rollback";
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

export interface AgentBudget {
  max_steps_per_tb: number;
  max_tool_calls_per_tb: number;
  max_elapsed_seconds_per_tb: number;
  max_stagnant_plans_per_tb: number;
  max_changed_targets_per_tb: number;
  max_output_bytes_per_tool: number;
  max_minimization_trials: number;
}

export interface FixedPermissionProfiles {
  host: Record<string, boolean>;
  container: Record<string, boolean>;
}

export interface AgentRunRequest {
  scope: "all_trust_boundaries";
  planner_model?: PlannerModelId;
}

export interface DamageScore {
  total: number;
  impact: number;
  proof: number;
  blast_radius: number;
  reproducibility: number;
}

export interface AttackContract {
  contract_id: string;
  trust_boundary_id: string;
  objective: string;
  impact: string;
  source_environment: EnvironmentNodeId;
  target_environment: EnvironmentNodeId;
  tool: string;
  action: string;
  resource_ref: string;
  arguments: Record<string, unknown>;
  verifier: string;
  success_criteria: string[];
  rollback: string;
  original_evidence_refs: string[];
  maximum_profile_hash: string;
  damage_score: DamageScore;
  chain_hash?: string;
  chain_steps?: AgentPlanStep[];
}

export interface PermissionTrial {
  sequence: number;
  strategy: "llm_seed" | "service_group" | "partition" | "single" | "restore_verify" | "final_verify";
  candidate_permission_ids: string[];
  removed_permission_ids: string[];
  success: boolean;
  proof_level: string;
  verifier: string;
  evidence_refs: string[];
}

export interface PermissionMinimizationResult {
  status: "NOT_STARTED" | "SKIPPED" | "COMPLETED" | "FAILED";
  initial_permission_ids: string[];
  llm_suggested_permission_ids: string[];
  minimal_permission_ids: string[];
  essential_permission_ids: string[];
  minimal_permission_profiles: FixedPermissionProfiles;
  trials: PermissionTrial[];
  one_minimal_verified: boolean;
  fallback_to_maximum: boolean;
}

export interface AgentFinding {
  finding_id: string;
  trust_boundary_id: string;
  title: string;
  preconditions: string[];
  impact: string;
  confidence: number;
  evidence_refs: string[];
  executable: boolean;
  blocked_reason: string | null;
}

export interface AgentPlanStep {
  step_id: string;
  type: "observe" | "execute" | "verify" | "rollback";
  tool: string;
  action: string;
  resource_ref: string;
  arguments?: Record<string, unknown>;
  expected_result: "allowed" | "denied" | "observed" | "restored";
  status: string;
  sequence?: number;
  selection_rationale?: string;
  policy_decision?: "ALLOWED" | "DENIED";
  execution_status?: "EXECUTED" | "FAILED" | "SKIPPED";
  verification_status?: "VERIFIED" | "REJECTED" | "INCONCLUSIVE";
  state_before?: AgentChainState;
  state_after?: AgentChainState;
  state_changes?: AgentStateChange[];
  evidence_refs?: string[];
  runtime_result?: "allowed" | "denied" | "error" | null;
  outcome?: string | null;
}

export interface AgentChainState {
  version: number;
  fingerprint: string;
}

export interface AgentStateChange {
  key: string;
  before: unknown;
  after: unknown;
  evidence_refs: string[];
}

export interface AgentSearchState {
  status: string;
  discovered_states: number;
  explored_states: number;
  unique_transitions: number;
  repeated_states: number;
  frontier_candidates: number;
  policy_pruned_candidates: number;
  tool_calls_used: number;
  planner_calls_used?: number;
  automatic_extensions: number;
  termination_reason: string | null;
  termination_explanation: string | null;
  search_complete: boolean;
  budget_exhausted: boolean;
  resume_available: boolean;
  checkpoint_id: string | null;
  checkpoint?: Record<string, unknown>;
  visited_transitions?: string[];
  remaining_frontier?: string[];
  last_state_fingerprint?: string;
}

export interface TbScenario {
  scenario_id: string;
  trust_boundary_id: string;
  risk_level: "critical" | "high" | "medium" | "low";
  risk_score: number;
  objective: string;
  impact: string;
  tool_implemented: boolean;
  steps: AgentPlanStep[];
  chain_id?: string;
  chain_status?: "PENDING" | "RUNNING" | "COMPLETED" | "PAUSED" | "FAILED";
  search?: AgentSearchState;
  rollback_status?: "NOT_REQUIRED" | "VERIFIED" | "FAILED";
}

export interface TbResult {
  trust_boundary_id: string;
  source_environment: EnvironmentNodeId;
  target_environment: EnvironmentNodeId;
  verdict: "BROKEN" | "BLOCKED" | "INCONCLUSIVE";
  highest_impact: string;
  attack_path: string[];
  fixed_permissions_used: string[];
  effective_identity: Record<string, unknown>;
  risk_score: number;
  proof_level: "L0_INFERRED" | "L1_REACHABLE" | "L2_EXECUTED" | "L3_IMPACTED" | "L4_RESTORED";
  evidence_refs: string[];
  rollback_status: "NOT_REQUIRED" | "VERIFIED" | "FAILED";
  scenario: TbScenario;
  runtime_result: "allowed" | "denied" | "error" | null;
  explanation: string;
}

export interface AgentRunRecord {
  run_id: string;
  objective: string;
  scope: "all_trust_boundaries";
  status: "RECEIVED" | "RUNNING" | "PAUSED" | "COMPLETED" | "FAILED" | "CANCELLED";
  agent_stage: "profile" | "maximize" | "recon" | "analyze" | "plan" | "execute" | "compare" | "contract" | "minimize" | "reverify" | "finished";
  fixed_permission_profiles: FixedPermissionProfiles;
  profile_hash: string;
  effective_permissions: Record<string, Record<string, unknown>>;
  recon_snapshot: Record<string, unknown>;
  infrastructure_snapshot: Record<string, unknown>;
  findings: AgentFinding[];
  tb_scenarios: TbScenario[];
  tb_results: TbResult[];
  worst_case_scenario: TbScenario | null;
  attack_contract: AttackContract | null;
  permission_minimization: PermissionMinimizationResult;
  summary: { broken: number; blocked: number; inconclusive: number };
  budget: AgentBudget;
  planner_mode: "local" | "openrouter";
  planner_model: PlannerModelId | null;
  rollback_status: "NOT_REQUIRED" | "VERIFIED" | "FAILED";
  profile_application_checks: Record<string, Record<string, boolean>>;
  profile_warnings: string[];
  events: RunEvent[];
  created_at: string;
  completed_at: string | null;
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

export interface ExperimentEnvironmentResetResult {
  status: "RESET" | "RESET_FAILED";
  duration_ms: number;
  reset_scopes: string[];
  evidence_refs: string[];
  restored_state: Record<string, unknown>;
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
