export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type DetectionCategory =
  | 'Credential Attack'
  | 'Account Compromise'
  | 'Privilege Escalation'
  | 'Suspicious Network Transfer'
  | 'Secret Exposure';

export interface SecurityLogEvent {
  id: string;
  line_number?: number;
  timestamp: string; // ISO 8601 with timezone (e.g. 2026-10-07T12:00:00Z)
  timestamp_epoch: number; // millisecond timestamp for exact window comparisons
  event_type: string;
  user?: string;
  source_ip?: string;
  destination_ip?: string;
  destination_port?: number;
  bytes?: number;
  status?: string;
  new_role?: string;
  message?: string;
  raw?: Record<string, unknown>;
  has_redacted_secret?: boolean;
}

export interface RejectedRow {
  row_number: number;
  raw_content: string;
  error: string;
}

export interface ValidationSummary {
  file_name: string;
  file_size_bytes: number;
  total_rows: number;
  valid_count: number;
  rejected_count: number;
  rejected_rows: RejectedRow[];
  earliest_event_utc?: string;
  latest_event_utc?: string;
  analysis_timestamp_utc: string;
}

export interface DetectionFinding {
  id: string;
  rule_id: 'TG001' | 'TG002' | 'TG003' | 'TG004' | 'TG005';
  rule_title: string;
  category: DetectionCategory;
  severity: Severity;
  summary: string;
  explanation: string;
  entity_source_ip?: string;
  entity_user?: string;
  trigger_event_ids: string[];
  first_seen_utc: string;
  last_seen_utc: string;
  supporting_events: SecurityLogEvent[];
  suggested_investigation_steps: string[];
  caveat_notice: string; // Explicit indicator disclaimer / legitimate causes
}

export interface DetectionResult {
  validation: ValidationSummary;
  events: SecurityLogEvent[];
  findings: DetectionFinding[];
}

export interface RuleMetadata {
  id: 'TG001' | 'TG002' | 'TG003' | 'TG004' | 'TG005';
  name: string;
  category: DetectionCategory;
  severity: Severity;
  threshold_summary: string;
  rationale: string;
  legitimate_causes: string;
  investigation_steps: string[];
}
