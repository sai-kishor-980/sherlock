export type PriorityLevel = "Low" | "Medium" | "High" | "Critical";
export type CaseStatus = "Active" | "Closed" | "Archived";
export type VaultStatus = "OPEN" | "LOCKED";

export interface Case {
  case_id: string;
  case_name: string;
  investigator_name: string;
  description?: string;
  priority: PriorityLevel;
  status: CaseStatus;
  created_at: string;
  vault_status?: VaultStatus;
  vault_locked_at?: string;
  vault_locked_by?: string;
  vault_unlock_reason?: string;
  evidence_count?: number;
}

export interface Evidence {
  evidence_id: string;
  case_id: string;
  name: string;
  type: string;
  path: string;
  file_size: number;
  sha256_hash: string;
  hmac_signature?: string;
  is_readonly: boolean;
  status: string;
  created_at: string;
}

export interface ObservationAccounting {
  total_observations: number;
  analyzed_observations: number;
  skipped_observations: number;
  failed_observations: number;
  batch_count: number;
  accounting_status: "COMPLETE" | "PARTIAL" | "FAILED";
  source_artifact?: string;
}

export interface DomainFinding {
  finding_id: string;
  domain: "network" | "memory" | "disk" | "logs" | "registry" | "supervisor" | string;
  agent: string;
  team_member: string;
  artifact_type: string;
  evidence_type: string;
  observation: string;
  assessment: "BENIGN" | "SUSPICIOUS" | "MALICIOUS";
  classification: "BENIGN" | "SUSPICIOUS" | "MALICIOUS";
  risk: "INFORMATIONAL" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  risk_level: "INFORMATIONAL" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  reasoning: string;
  supporting_evidence?: Array<{ evidence_type: string; indicators: string[] }>;
  key_evidence: string[];
  timeline?: {
    timestamp_utc: string | null;
    timestamp_type: string;
    event_description: string;
  };
  confidence: number;
  recommended_next_evidence?: string[];
  adapter_model?: string;
  contract_validated?: boolean;
  analysis_mode: "AI-assisted" | "Rule-based";
  inference_provider: string;
  observation_accounting?: ObservationAccounting;
}

export interface SISTimelineEvent {
  event_id: string;
  timestamp_utc: string | null;
  timestamp_type: string;
  domain: string;
  event_type: string;
  description: string;
  evidence_ref?: string;
  confidence: number;
}

export interface CorrelationPivot {
  pivot_id: string;
  source_domain: string;
  target_domain: string;
  correlation_key: string;
  key_value: string;
  rationale: string;
  confidence: number;
}

export interface SISState {
  case_id: string;
  version: number;
  status: string;
  confidence_score: number;
  timeline: SISTimelineEvent[];
  entities: Array<Record<string, any>>;
  attack_hypotheses: Array<{
    hypothesis_id: string;
    description: string;
    stage: string;
    confidence: number;
    evidence_references: string[];
  }>;
  cross_domain_correlations: CorrelationPivot[];
  review_gate?: {
    status?: string;
    reviewed_by?: string;
    reviewed_at?: string;
    notes?: string;
  };
  review?: {
    reviewed_by?: string;
    reviewed_at?: string;
    notes?: string;
    action?: string;
  };
}

export interface InferenceTierStatus {
  active_tier: "Tier 1: Local GPU Accelerated" | "Tier 2: Remote GPU Accelerated" | "Tier 3: Rule-based Engine" | string;
  analysis_mode: "AI-assisted" | "Rule-based";
  mode: string;
  is_connected: boolean;
  inference_status: "Connected" | "Disconnected";
  service_status: "Available" | "Unavailable";
  active_device: string;
  local_hardware: {
    cuda_available: boolean;
    device_name: string | null;
    total_vram_gb: number;
    gpu_eligible: boolean;
    qualification_reason: string;
    model_cached_in_vram: boolean;
  };
  remote_service: {
    configured: boolean;
    url: string | null;
    reachable: boolean;
    remote_model: string | null;
    remote_device: string | null;
  };
}
