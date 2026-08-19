export type JsonObject = Record<string, unknown>;

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
