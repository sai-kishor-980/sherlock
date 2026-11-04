import type { Case, Evidence, SISState, InferenceTierStatus, DomainFinding } from "../types/forensic";

const API_BASE = "/api/v1";

export interface CaseCitation {
  file: string;
  sha256: string;
  category: string;
  timestamp: string;
}

export interface SubgraphNode {
  id: string;
  label: string;
  entity_type: string;
  confidence: number;
  risk_level: string;
  is_seed?: boolean;
}

export interface SubgraphEdge {
  source: string;
  target: string;
  relationship_type: string;
  nature: string;
  confidence: number;
}

export interface ChatResponse {
  status: string;
  case_id: string;
  query: string;
  answer: string;
  citations: CaseCitation[];
  vector_hits: string[];
  subgraph?: {
    nodes: SubgraphNode[];
    edges: SubgraphEdge[];
    matched_seed_nodes: string[];
  };
  confidence: number;
  execution_mode: string;
  sis_review_status: string;
  mitre_techniques: string[];
}

class ApiService {
  getToken(): string | null {
    return localStorage.getItem("sherlock_token");
  }

  setToken(token: string | null) {
    if (token) {
      localStorage.setItem("sherlock_token", token);
    } else {
      localStorage.removeItem("sherlock_token");
    }
  }

  getUser(): any {
    const raw = localStorage.getItem("sherlock_user");
    return raw ? JSON.parse(raw) : null;
  }

  setUser(user: any) {
    if (user) {
      localStorage.setItem("sherlock_user", JSON.stringify(user));
    } else {
      localStorage.removeItem("sherlock_user");
    }
  }

  private getHeaders(isJson = true): HeadersInit {
    const headers: Record<string, string> = {};
    if (isJson) {
      headers["Content-Type"] = "application/json";
    }
    const token = this.getToken();
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    return headers;
  }

  // Auth
  async login(username: string, password: string): Promise<any> {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Invalid investigator credentials");
    }
    const data = await res.json();
    this.setToken(data.access_token);
    this.setUser(data.user);
    return data;
  }

  logout() {
    this.setToken(null);
    this.setUser(null);
  }

  // 3-Tier Hardware & Inference Service Status
  async getInferenceStatus(): Promise<InferenceTierStatus> {
    const res = await fetch(`${API_BASE}/cases/models/colab-bridge`, {
      headers: this.getHeaders()
    });
    if (!res.ok) {
      throw new Error("Failed to fetch inference tier status");
    }
    return res.json();
  }

  async setRemoteInferenceUrl(url: string): Promise<any> {
    const res = await fetch(`${API_BASE}/cases/models/colab-bridge`, {
      method: "POST",
      headers: this.getHeaders(),
      body: JSON.stringify({ colab_url: url })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Failed to update inference service URL");
    }
    return res.json();
  }

  // Cases
  async getCases(): Promise<Case[]> {
    const res = await fetch(`${API_BASE}/cases/`, {
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error("Failed to load investigation cases");
    return res.json();
  }

  async getCase(caseId: string): Promise<Case> {
    const res = await fetch(`${API_BASE}/cases/${caseId}`, {
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error(`Case ${caseId} not found`);
    return res.json();
  }

  async createCase(data: {
    case_id?: string;
    case_name: string;
    investigator_name: string;
    description?: string;
    priority: string;
  }): Promise<Case> {
    const res = await fetch(`${API_BASE}/cases/`, {
      method: "POST",
      headers: this.getHeaders(),
      body: JSON.stringify(data)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Failed to initialize case file");
    }
    return res.json();
  }

  // Evidence & Vault
  async getEvidence(caseId: string): Promise<Evidence[]> {
    const res = await fetch(`${API_BASE}/cases/${caseId}/evidence`, {
      headers: this.getHeaders()
    });
    if (!res.ok) return [];
    return res.json();
  }

  async uploadEvidence(caseId: string, file: File, category?: string): Promise<any> {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("case_id", caseId);
    formData.append("investigator", this.getUser()?.username || "investigator1");
    if (category) {
      formData.append("category", category);
    }

    const token = this.getToken();
    const headers: Record<string, string> = {};
    if (token) headers["Authorization"] = `Bearer ${token}`;

    const res = await fetch(`${API_BASE}/upload/`, {
      method: "POST",
      headers,
      body: formData
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Upload failed for ${file.name}`);
    }
    return res.json();
  }

  async getArtifacts(caseId: string): Promise<any> {
    let res = await fetch(`${API_BASE}/analysis/${caseId}/artifacts`, {
      headers: this.getHeaders()
    });
    if (!res.ok) {
      res = await fetch(`${API_BASE}/cases/${caseId}/extracted-artifacts`, {
        headers: this.getHeaders()
      });
    }
    if (!res.ok) return { summary: {}, artifacts: {}, categories: {} };
    const data = await res.json();
    if (!data.categories && data.artifacts) {
      data.categories = data.artifacts;
    }
    return data;
  }

  async lockVault(caseId: string): Promise<any> {
    const res = await fetch(`${API_BASE}/cases/${caseId}/vault/lock`, {
      method: "POST",
      headers: this.getHeaders()
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Failed to lock evidence vault");
    }
    return res.json();
  }

  async unlockVault(caseId: string, reason: string): Promise<any> {
    const res = await fetch(`${API_BASE}/cases/${caseId}/vault/unlock`, {
      method: "POST",
      headers: this.getHeaders(),
      body: JSON.stringify({ reason })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Failed to unlock evidence vault");
    }
    return res.json();
  }

  // Extraction & Multi-Agent Analysis
  async triggerExtraction(caseId: string): Promise<any> {
    let res = await fetch(`${API_BASE}/analysis/${caseId}/extract`, {
      method: "POST",
      headers: this.getHeaders()
    });
    if (!res.ok) {
      res = await fetch(`${API_BASE}/cases/${caseId}/extract`, {
        method: "POST",
        headers: this.getHeaders()
      });
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Artifact extraction failed");
    }
    return res.json();
  }

  async runAnalysis(caseId: string): Promise<any> {
    let res = await fetch(`${API_BASE}/analysis/${caseId}/run`, {
      method: "POST",
      headers: this.getHeaders()
    });
    if (!res.ok) {
      res = await fetch(`${API_BASE}/analysis/start`, {
        method: "POST",
        headers: this.getHeaders(),
        body: JSON.stringify({ case_id: caseId, case_name: caseId })
      });
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Multi-agent forensic analysis failed");
    }
    return res.json();
  }

  async getAnalysisTask(taskId: string): Promise<any> {
    const res = await fetch(`${API_BASE}/analysis/tasks/${taskId}`, {
      headers: this.getHeaders()
    });
    if (!res.ok) return null;
    return res.json();
  }

  async getFindings(caseId: string): Promise<DomainFinding[]> {
    let res = await fetch(`${API_BASE}/cases/${caseId}/findings`, {
      headers: this.getHeaders()
    });
    if (!res.ok) {
      res = await fetch(`${API_BASE}/analysis/${caseId}/findings`, {
        headers: this.getHeaders()
      });
    }
    if (!res.ok) return [];
    const data = await res.json();
    if (Array.isArray(data)) return data;
    if (Array.isArray(data.findings)) return data.findings;
    return [];
  }

  async getManifest(caseId: string): Promise<any> {
    let res = await fetch(`${API_BASE}/cases/${caseId}/manifest`, {
      headers: this.getHeaders()
    });
    if (!res.ok) {
      res = await fetch(`${API_BASE}/cases/${caseId}/supervisor/status`, {
        headers: this.getHeaders()
      });
    }
    if (!res.ok) return null;
    const data = await res.json();
    return data.supervisor_manifest || data;
  }

  // SIS State & Review
  async getSIS(caseId: string): Promise<SISState | null> {
    const res = await fetch(`${API_BASE}/cases/${caseId}/sis`, {
      headers: this.getHeaders()
    });
    if (!res.ok) return null;
    const data = await res.json();
    if (!data) return null;

    // Normalize timeline events
    const rawTimeline = data.timeline || data.attack_timeline || [];
    const normalizedTimeline = rawTimeline.map((evt: any, idx: number) => ({
      event_id: evt.event_id || `EVT-${idx + 1}`,
      timestamp_utc: evt.timestamp_utc || evt.timestamp || null,
      timestamp_type: evt.timestamp_type || (evt.timestamp ? "EXACT" : "UNAVAILABLE"),
      domain: evt.domain || evt.phase || "GENERAL",
      event_type: evt.event_type || evt.title || "Observation",
      description: evt.description || evt.event_description || "",
      evidence_ref: evt.evidence_ref || evt.artifact_id || evt.source,
      confidence: typeof evt.confidence === "number" ? evt.confidence : 0.9
    }));

    // Normalize attack hypotheses
    const rawHypotheses = data.attack_hypotheses || data.causal_hypotheses || [];
    const normalizedHypotheses = rawHypotheses.map((h: any, idx: number) => ({
      hypothesis_id: h.hypothesis_id || `HYP-${idx + 1}`,
      description: h.description || h.claim || h.title || "",
      stage: h.stage || h.title || `Stage ${idx + 1}`,
      confidence: typeof h.confidence === "number" ? h.confidence : 0.9,
      evidence_references: h.evidence_references || h.supporting_artifacts || []
    }));

    // Normalize cross-domain correlations
    const rawCorrelations = data.cross_domain_correlations || data.correlations || [];
    const normalizedCorrelations = rawCorrelations.map((c: any, idx: number) => ({
      pivot_id: c.pivot_id || c.rule_id || `PIVOT-${idx + 1}`,
      source_domain: c.source_domain || "DISK",
      target_domain: c.target_domain || "NETWORK",
      correlation_key: c.correlation_key || c.pivot_point || "entity",
      key_value: c.key_value || c.target_entity || "",
      rationale: c.rationale || c.reasoning || c.title || "",
      confidence: typeof c.confidence === "number" ? c.confidence : 0.95
    }));

    return {
      ...data,
      timeline: normalizedTimeline,
      attack_hypotheses: normalizedHypotheses,
      cross_domain_correlations: normalizedCorrelations,
      status: data.status || data.investigation_status || (data.review_gate?.status === "APPROVED" ? "LOCKED_APPROVED" : "PENDING")
    };
  }

  async reviewSIS(caseId: string, action: "APPROVE" | "REJECT_REANALYZE", notes: string): Promise<any> {
    const res = await fetch(`${API_BASE}/cases/${caseId}/sis/review`, {
      method: "POST",
      headers: this.getHeaders(),
      body: JSON.stringify({ action, notes })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Failed to submit investigator review");
    }
    return res.json();
  }

  async getReport(caseId: string): Promise<any> {
    const res = await fetch(`${API_BASE}/cases/${caseId}/report`, {
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error("Court report not found or not yet synthesized");
    return res.json();
  }

  async downloadReportPdf(caseId: string): Promise<void> {
    const res = await fetch(`${API_BASE}/cases/${caseId}/report/pdf`, {
      headers: this.getHeaders()
    });
    if (!res.ok) {
      if (res.status === 423) {
        throw new Error("Report is LOCKED: The human investigator must formally approve the Structured Investigation State (SIS) in Workstation 4 before official PDF report generation.");
      }
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Failed to download forensic PDF report");
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `Sherlock_Forensic_Report_${caseId}.pdf`;
    a.click();
    URL.revokeObjectURL(url);
  }

  // Knowledge Graph & RAG
  async getEvidenceGraph(caseId: string): Promise<any> {
    const res = await fetch(`${API_BASE}/cases/${caseId}/graph`, {
      headers: this.getHeaders()
    });
    if (!res.ok) return null;
    return res.json();
  }

  // Interactive Case Chatbot (G-RAG)
  async sendCaseChat(caseId: string, query: string): Promise<ChatResponse> {
    const res = await fetch(`${API_BASE}/cases/${caseId}/chat`, {
      method: "POST",
      headers: this.getHeaders(),
      body: JSON.stringify({ query })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Forensic AI chat request failed");
    }
    return res.json();
  }

  // Slide 13 Interactive Visual Case Board: Raw Hex & xAI Attribution
  async getClueHex(caseId: string, clueId: string, offset = 0, length = 512): Promise<any> {
    const encoded = encodeURIComponent(clueId);
    const res = await fetch(`${API_BASE}/cases/${caseId}/clues/${encoded}/hex?offset=${offset}&length=${length}`, {
      headers: this.getHeaders()
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Failed to load clue hex stream");
    }
    return res.json();
  }

  // Slide 13 Relationship Trace: Deterministic Proof Linking Two Clues
  async getRelationshipProof(caseId: string, sourceId: string, targetId: string): Promise<any> {
    const sEnc = encodeURIComponent(sourceId);
    const tEnc = encodeURIComponent(targetId);
    const res = await fetch(`${API_BASE}/cases/${caseId}/relationships/proof?source_id=${sEnc}&target_id=${tEnc}`, {
      headers: this.getHeaders()
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Failed to load relationship proof");
    }
    return res.json();
  }
}

export const api = new ApiService();
