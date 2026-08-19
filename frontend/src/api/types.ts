export type JsonObject = Record<string, unknown>;

export type BrowserRuntimeName = "obscura" | "playwright";
export type BrowserSessionState =
  | "queued"
  | "starting"
  | "ready"
  | "navigating"
  | "active"
  | "waiting"
  | "completed"
  | "cancelled"
  | "failed"
  | "expired";
export type BrowserActionStatus = "queued" | "running" | "completed" | "blocked" | "failed" | "cancelled";
export type BrowserActionType =
  | "navigate"
  | "snapshot"
  | "read_page"
  | "get_links"
  | "get_interactive_elements"
  | "detect_forms"
  | "get_attribute"
  | "count"
  | "search_text"
  | "click"
  | "fill"
  | "type"
  | "press_key"
  | "select_option"
  | "scroll"
  | "wait"
  | "wait_for_text"
  | "get_network_requests"
  | "get_console_messages"
  | "take_screenshot"
  | "get_current_url";

export interface BrowserRuntimeCapabilities {
  runtime?: BrowserRuntimeName;
  version?: string;
  mcp_available?: boolean;
  screenshot_available?: boolean;
  network_available?: boolean;
  console_available?: boolean;
  forms_available?: boolean;
  interactive_elements_available?: boolean;
  evaluate_available?: boolean;
  [key: string]: unknown;
}

export interface BrowserSession {
  session_id: string;
  assessment_id: string;
  attempt_id?: string | null;
  workspace_id: string;
  owner_id?: string;
  authorization_id: string;
  target_url: string;
  allowed_origins?: string[];
  mode?: "passive" | "controlled_interactive";
  runtime: BrowserRuntimeName;
  runtime_version?: string;
  capabilities?: BrowserRuntimeCapabilities;
  state?: BrowserSessionState;
  current_url?: string | null;
  action_count?: number;
  expires_at?: string;
  [key: string]: unknown;
}

export interface BrowserActionReceipt {
  action_id?: string;
  session_id?: string;
  sequence?: number;
  action_type: BrowserActionType | string;
  status: BrowserActionStatus | string;
  current_url?: string | null;
  result_summary?: JsonObject;
  evidence_ids?: string[];
  error_category?: string | null;
  error_message?: string | null;
  [key: string]: unknown;
}

export interface BrowserNetworkObservation {
  observation_id?: string;
  method?: string;
  scheme?: string;
  host?: string;
  port?: number | null;
  path?: string;
  status_code?: number | null;
  same_origin?: boolean;
  request_body_present?: boolean;
  evidence_id?: string | null;
  [key: string]: unknown;
}

export interface BrowserConsoleObservation {
  observation_id?: string;
  level?: string;
  message?: string;
  current_url?: string | null;
  evidence_id?: string | null;
  [key: string]: unknown;
}

export interface BrowserScreenshotArtifact {
  artifact_type?: "screenshot" | string;
  evidence_id?: string;
  relative_path?: string;
  media_type?: string;
  sha256?: string;
  size_bytes?: number;
  viewport_width?: number;
  viewport_height?: number;
  current_url?: string | null;
  runtime?: BrowserRuntimeName;
  runtime_version?: string;
  [key: string]: unknown;
}

export interface BrowserIntelligenceReport {
  report_id?: string;
  report_sha256?: string;
  assessment_id?: string;
  attempt_id?: string | null;
  workspace_id?: string;
  session_id?: string;
  target_url?: string;
  current_url?: string | null;
  runtime?: BrowserRuntimeName;
  runtime_version?: string;
  action_receipts?: BrowserActionReceipt[];
  network_observations?: BrowserNetworkObservation[];
  console_observations?: BrowserConsoleObservation[];
  screenshots?: BrowserScreenshotArtifact[];
  endpoint_paths?: string[];
  pages_visited?: number;
  forms_observed?: number;
  source_hunt_correlation_ids?: string[];
  limitations?: string[];
  [key: string]: unknown;
}

export interface MePayload {
  id: string;
  username: string;
  roles: string[];
  reviewer_id: string;
}

export interface ReadinessPayload {
  status?: string;
  ready?: boolean;
  checks?: Record<string, unknown>;
  [key: string]: unknown;
}

export type MobileRecordType = "observation" | "finding" | "candidate" | "operational_issue";

export type MobileEvidenceState =
  | "verified_configuration"
  | "verified_security_finding"
  | "evidence_required"
  | "operational_failure"
  | "partial_tool_result"
  | "not_applicable"
  | "blocked"
  | "rejected"
  | "inconclusive";

export type MobileOwnership = "app_owned" | "sdk_owned" | "platform_framework" | "unknown";

export type MobileToolExecutionStatus =
  | "completed"
  | "partial"
  | "not_run"
  | "not_applicable"
  | "blocked"
  | "failed";

export interface MobileSecurityRecord {
  record_id?: string;
  record_type?: MobileRecordType;
  weakness_id?: string;
  title?: string;
  severity?: string;
  evidence_state?: MobileEvidenceState;
  ownership?: MobileOwnership;
  confidence?: string;
  security_property?: string;
  affected_component?: string | null;
  source?: JsonObject;
  evidence_references?: string[];
  related_record_ids?: string[];
  details?: JsonObject;
  [key: string]: unknown;
}

export interface MobileOperationalIssue {
  issue_id?: string;
  tool?: string | null;
  title?: string;
  evidence_state?: MobileEvidenceState;
  failure_type?: string;
  retryable?: boolean;
  partial_output?: boolean;
  evidence_references?: string[];
  details?: JsonObject;
  [key: string]: unknown;
}

export interface MobileToolExecution {
  tool?: string;
  status?: MobileToolExecutionStatus;
  version?: string | null;
  exit_code?: number | null;
  partial?: boolean;
  failure_reason?: string | null;
  generated_files?: number | null;
  processed_units?: number | null;
  total_units?: number | null;
  coverage_limitations?: string[];
  downstream_usable?: boolean;
  evidence_references?: string[];
  [key: string]: unknown;
}

export interface MobileEndpointReference {
  endpoint_id?: string;
  endpoint?: string;
  normalized_endpoint?: string;
  host?: string | null;
  port?: number | null;
  protocol?: string;
  likely_role?: string;
  ownership?: MobileOwnership;
  source_file?: string;
  source_offset?: number | null;
  source_references?: string[];
  static_or_runtime?: string;
  confidence?: string;
  reachability?: string;
  evidence_references?: string[];
  [key: string]: unknown;
}

export interface MobileTransportCorrelation {
  correlation_id?: string;
  title?: string;
  summary?: string;
  observation_ids?: string[];
  endpoint_ids?: string[];
  ownership?: MobileOwnership;
  security_property?: string;
  priority?: string;
  confidence?: string;
  status?: string;
  limitations?: string[];
  [key: string]: unknown;
}

export interface MobileComponentSurface {
  component_id?: string;
  name?: string;
  kind?: string;
  exported?: boolean;
  permission?: string | null;
  ownership?: MobileOwnership;
  intent_filters?: JsonObject[];
  validation_scope?: string[];
  security_impact?: string;
  evidence_references?: string[];
  [key: string]: unknown;
}

export interface MobileCapabilityStatus {
  capability?: string;
  status?: MobileToolExecutionStatus;
  detail?: string | null;
  evidence_references?: string[];
  [key: string]: unknown;
}

export type MobileSourceHuntState =
  | "verified"
  | "rejected"
  | "inconclusive"
  | "evidence_required"
  | "blocked";

export interface MobileGraphProvenance {
  artifact_sha256?: string;
  source_identity?: string;
  source_path?: string | null;
  source_sha256?: string | null;
  line_start?: number | null;
  line_end?: number | null;
  analysis_run_id?: string;
  confidence?: string;
  coverage?: string;
  evidence_references?: string[];
  [key: string]: unknown;
}

export interface MobileAttackGraphNode {
  node_id?: string;
  node_type?: string;
  label?: string;
  ownership?: MobileOwnership;
  state?: MobileSourceHuntState | null;
  evidence_references?: string[];
  provenance?: MobileGraphProvenance[];
  attributes?: JsonObject;
  [key: string]: unknown;
}

export interface MobileAttackGraphEdge {
  edge_id?: string;
  source_node_id?: string;
  target_node_id?: string;
  relation?: string;
  confidence?: string;
  state?: MobileSourceHuntState | null;
  evidence_references?: string[];
  provenance?: MobileGraphProvenance[];
  attributes?: JsonObject;
  [key: string]: unknown;
}

export interface MobileAttackGraph {
  graph_id?: string;
  artifact_sha256?: string;
  source_identity?: string;
  analysis_run_id?: string;
  nodes?: MobileAttackGraphNode[];
  edges?: MobileAttackGraphEdge[];
  coverage?: {
    status?: string;
    source_file_count?: number;
    source_bytes?: number;
    limitations?: string[];
    evidence_references?: string[];
    [key: string]: unknown;
  };
  graph_sha256?: string;
  [key: string]: unknown;
}

export interface MobileSourceHuntSeed {
  seed_id?: string;
  seed_type?: string;
  title?: string;
  weakness_id?: string | null;
  component_name?: string | null;
  ownership?: MobileOwnership;
  evidence_references?: string[];
  source_intelligence_record_id?: string | null;
  attributes?: JsonObject;
  [key: string]: unknown;
}

export interface MobileSourceHuntResult {
  seed?: MobileSourceHuntSeed;
  state?: MobileSourceHuntState;
  summary?: string;
  entry_point?: string | null;
  source_symbols?: string[];
  sink_symbols?: string[];
  controls_observed?: string[];
  missing_evidence?: string[];
  source_references?: JsonObject[];
  graph_node_ids?: string[];
  graph_edge_ids?: string[];
  bounded_negative?: boolean;
  verified_finding?: boolean;
  remediation?: string | null;
  deterministic_validation?: string | null;
  [key: string]: unknown;
}

export interface MobileSourceHuntReport {
  report_id?: string;
  artifact_id?: string;
  artifact_sha256?: string;
  source_identity?: string;
  analysis_run_id?: string;
  coverage?: MobileAttackGraph["coverage"];
  seeds_examined?: number;
  results?: MobileSourceHuntResult[];
  graph?: MobileAttackGraph;
  verified_finding_count?: number;
  rejected_count?: number;
  inconclusive_count?: number;
  evidence_required_count?: number;
  blocked_count?: number;
  created_at?: string;
  safe_error?: string | null;
  selected_seed_id?: string | null;
  [key: string]: unknown;
}

export interface MobileSourceHuntProjection {
  state?: "not_started" | "queued" | "running" | "completed" | MobileSourceHuntState;
  available?: boolean;
  report_id?: string | null;
  report_ready?: boolean;
  selected_seed_id?: string | null;
  selected_result?: MobileSourceHuntResult;
  coverage?: MobileAttackGraph["coverage"];
  graph?: MobileAttackGraph & { node_count?: number; edge_count?: number };
  error?: string | null;
  [key: string]: unknown;
}

export interface MobileIntelligence {
  schema_version?: string;
  intelligence_sha256?: string;
  observations?: MobileSecurityRecord[];
  verified_configurations?: MobileSecurityRecord[];
  verified_findings?: MobileSecurityRecord[];
  candidates?: MobileSecurityRecord[];
  operational_issues?: MobileOperationalIssue[];
  tool_executions?: MobileToolExecution[];
  hypotheses?: JsonObject[];
  endpoint_references?: MobileEndpointReference[];
  transport_correlations?: MobileTransportCorrelation[];
  exported_component_surfaces?: MobileComponentSurface[];
  bounded_negative_claims?: string[];
  remediation_recommendations?: string[];
  coverage?: {
    state?: string;
    completed?: number;
    partial?: number;
    not_run?: number;
    not_applicable?: number;
    blocked?: number;
    failed?: number;
    capabilities?: MobileCapabilityStatus[];
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export interface AssessmentFinding {
  id?: string;
  title?: string;
  severity?: string;
  status?: string;
  summary?: string;
  [key: string]: unknown;
}

export interface AssessmentArtifact {
  id?: string;
  name?: string;
  kind?: string;
  [key: string]: unknown;
}

export interface ApprovalState {
  state?: string;
  required?: boolean;
  [key: string]: unknown;
}

export interface AssessmentEvent {
  event_id?: string;
  assessment_id?: string;
  type?: string;
  stage?: string;
  occurred_at?: string;
  sequence: number;
  summary?: string;
  detail?: string;
  metadata?: JsonObject;
  resource?: JsonObject;
  [key: string]: unknown;
}

export interface Assessment {
  run_id: string;
  state: string;
  task_state?: string;
  approval_state?: string;
  execution_state?: string;
  target?: string;
  profile?: string;
  scanner?: string;
  created_at?: string;
  updated_at?: string;
  terminal?: boolean;
  blocking_reason?: string | null;
  evaluation_result?: unknown;
  findings?: AssessmentFinding[];
  mobile_intelligence?: MobileIntelligence;
  source_hunt?: MobileSourceHuntProjection;
  artifacts?: AssessmentArtifact[];
  events?: AssessmentEvent[];
  last_sequence?: number;
  approval?: ApprovalState;
  authorization_id?: string | null;
  detail_url?: string;
  findings_url?: string;
  task_graph?: JsonObject;
  chat_stage?: string;
  [key: string]: unknown;
}

export interface AssessmentListPayload {
  results: Assessment[];
  count: number;
}

export interface AssessmentEventsPayload {
  assessment_id: string;
  events: AssessmentEvent[];
  last_sequence: number;
  task_state?: string | null;
  run_state?: string | null;
  active_summary?: string | null;
  approval_state?: string | null;
  execution_state?: string | null;
  workflow_state?: string | null;
  execution_enabled?: boolean;
  execution_blocking_reason?: string | null;
  readiness?: ReadinessPayload;
  evaluation_result?: unknown;
  updated_at?: string | null;
  activity_tree?: JsonObject;
  mobile_intelligence?: MobileIntelligence;
  source_hunt?: MobileSourceHuntProjection;
  terminal: boolean;
}

export interface RealtimeTicketPayload {
  ticket: string;
  expires_in: number;
  assessment_id: string;
}

export interface AssessmentSnapshot extends AssessmentEventsPayload {
  type?: string;
}
