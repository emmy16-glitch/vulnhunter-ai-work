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
  run_state?: string | null;
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
