/* HMACFR API Client Service with Authentication & Authorization Headers */
const API_BASE_URL = "/api/v1";

const HMACFR_API = {
  // Auth Helpers
  getToken() {
    return localStorage.getItem("hmacfr_access_token");
  },

  setToken(token) {
    if (token) {
      localStorage.setItem("hmacfr_access_token", token);
    } else {
      localStorage.removeItem("hmacfr_access_token");
    }
  },

  getUser() {
    const raw = localStorage.getItem("hmacfr_user_profile");
    return raw ? JSON.parse(raw) : null;
  },

  setUser(user) {
    if (user) {
      localStorage.setItem("hmacfr_user_profile", JSON.stringify(user));
    } else {
      localStorage.removeItem("hmacfr_user_profile");
    }
  },

  logout() {
    this.setToken(null);
    this.setUser(null);
  },

  isTokenExpired() {
    const token = this.getToken();
    if (!token) return true;
    try {
      const parts = token.split('.');
      if (parts.length < 2) return false;
      let base64Url = parts[1];
      let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      while (base64.length % 4) {
        base64 += '=';
      }
      const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
      }).join(''));
      const payload = JSON.parse(jsonPayload);
      if (payload && payload.exp) {
        return (payload.exp * 1000) < Date.now();
      }
    } catch (e) {
      return false;
    }
    return false;
  },

  handleUnauthorized(msg) {
    this.logout();
    if (window.handleSessionExpired) {
      window.handleSessionExpired(msg || "Your JWT authentication session has expired. Please sign in again.");
    }
  },

  getHeaders(includeAuth = true, extraHeaders = {}) {
    const headers = { ...extraHeaders };
    if (includeAuth) {
      const token = this.getToken();
      if (token) {
        if (this.isTokenExpired()) {
          this.handleUnauthorized("Session expired: JWT token expiration timestamp reached.");
        } else {
          headers["Authorization"] = `Bearer ${token}`;
        }
      }
    }
    return headers;
  },

  // Auth Endpoints
  async login(username, password) {
    const res = await fetch(`${API_BASE_URL}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Authentication failed");
    }
    const data = await res.json();
    this.setToken(data.access_token);
    this.setUser(data.user);
    return data;
  },

  async getMe() {
    const res = await fetch(`${API_BASE_URL}/auth/me`, {
      headers: this.getHeaders()
    });
    if (!res.ok) {
      this.logout();
      throw new Error("Session expired");
    }
    const user = await res.json();
    this.setUser(user);
    return user;
  },

  // Admin User & Credential Endpoints
  async registerUser(userData) {
    const res = await fetch(`${API_BASE_URL}/auth/register`, {
      method: "POST",
      headers: this.getHeaders(true, { "Content-Type": "application/json" }),
      body: JSON.stringify(userData)
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Failed to create user account");
    }
    return res.json();
  },

  async getUsers() {
    const res = await fetch(`${API_BASE_URL}/auth/users`, {
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error("Failed to list user accounts");
    return res.json();
  },

  async resetPassword(userId, newPassword) {
    const res = await fetch(`${API_BASE_URL}/auth/users/${userId}/password`, {
      method: "PUT",
      headers: this.getHeaders(true, { "Content-Type": "application/json" }),
      body: JSON.stringify({ new_password: newPassword })
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Failed to reset password");
    }
    return res.json();
  },

  async updateUserRole(userId, newRole) {
    const res = await fetch(`${API_BASE_URL}/auth/users/${userId}/role`, {
      method: "PUT",
      headers: this.getHeaders(true, { "Content-Type": "application/json" }),
      body: JSON.stringify({ role: newRole })
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Failed to update user role");
    }
    return res.json();
  },

  async deleteUser(userId, adminPassword) {
    const res = await fetch(`${API_BASE_URL}/auth/users/${userId}`, {
      method: "DELETE",
      headers: this.getHeaders(true, { "Content-Type": "application/json" }),
      body: JSON.stringify({ admin_password: adminPassword })
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Failed to delete user account");
    }
    return res.json();
  },


  // Case Endpoints
  async getCases() {
    const res = await fetch(`${API_BASE_URL}/cases/`, {
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error("Failed to fetch cases");
    return res.json();
  },

  async getAllEvidence(caseId = null) {
    const url = caseId ? `${API_BASE_URL}/evidence/?case_id=${encodeURIComponent(caseId)}` : `${API_BASE_URL}/evidence/`;
    const res = await fetch(url, {
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error("Failed to fetch evidence repository items");
    return res.json();
  },

  async getEvidences(caseId = null) {
    return this.getAllEvidence(caseId);
  },

  async getCaseEvidence(caseId) {
    return this.getAllEvidence(caseId);
  },


  async createCase(caseData) {
    const res = await fetch(`${API_BASE_URL}/cases/`, {
      method: "POST",
      headers: this.getHeaders(true, { "Content-Type": "application/json" }),
      body: JSON.stringify(caseData)
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Failed to create case");
    }
    return res.json();
  },

  async deleteCase(caseId) {
    const res = await fetch(`${API_BASE_URL}/cases/${caseId}?archive_only=false`, {
      method: "DELETE",
      headers: this.getHeaders(true)
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Failed to purge case and evidence data");
    }
    return res.json();
  },

  async requestCaseDeletion(caseId, reason) {
    const res = await fetch(`${API_BASE_URL}/cases/${caseId}/request-deletion`, {
      method: "POST",
      headers: this.getHeaders(true, { "Content-Type": "application/json" }),
      body: JSON.stringify({ reason: reason || "Case deletion requested by investigator" })
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Failed to submit deletion request");
    }
    return res.json();
  },

  async getPendingDeletionRequests() {
    const res = await fetch(`${API_BASE_URL}/cases/deletion-requests/pending`, {
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error("Failed to fetch pending deletion requests");
    return res.json();
  },

  async resolveCaseDeletion(caseId, action) {
    const res = await fetch(`${API_BASE_URL}/cases/${caseId}/deletion-resolution`, {
      method: "POST",
      headers: this.getHeaders(true, { "Content-Type": "application/json" }),
      body: JSON.stringify({ action: action })
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Failed to resolve deletion request");
    }
    return res.json();
  },



  // Upload Endpoint
  async uploadEvidence(formData) {
    const res = await fetch(`${API_BASE_URL}/upload/`, {
      method: "POST",
      headers: this.getHeaders(true),
      body: formData
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Upload failed");
    }
    return res.json();
  },

  // Preservation Endpoints
  async preserveEvidence(preserveInput) {
    const res = await fetch(`${API_BASE_URL}/preservation/preserve`, {
      method: "POST",
      headers: this.getHeaders(true, { "Content-Type": "application/json" }),
      body: JSON.stringify(preserveInput)
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Preservation pipeline failed");
    }
    return res.json();
  },

  async preserveCase(caseId) {
    const res = await fetch(`${API_BASE_URL}/preservation/preserve-case/${caseId}`, {
      method: "POST",
      headers: this.getHeaders(true)
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Batch case preservation failed");
    }
    return res.json();
  },

  // Evidence Endpoints
  async getCaseEvidence(caseId) {
    const res = await fetch(`${API_BASE_URL}/evidence/case/${caseId}`, {
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error("Failed to fetch case evidence");
    return res.json();
  },

  // Verification & Audit Endpoints
  async auditEvidence(evidenceId) {
    const res = await fetch(`${API_BASE_URL}/verification/audit/${evidenceId}`, {
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error("Verification audit failed");
    return res.json();
  },

  async auditCase(caseId) {
    const res = await fetch(`${API_BASE_URL}/verification/audit-case/${caseId}`, {
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error("Case audit failed");
    return res.json();
  },

  async lockEvidence(evidenceId) {
    const res = await fetch(`${API_BASE_URL}/verification/lock/${evidenceId}`, {
      method: "POST",
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error("Failed to lock evidence");
    return res.json();
  },

  // Custody Logs Endpoint
  async getCustodyLogs(evidenceId) {
    const res = await fetch(`${API_BASE_URL}/custody/evidence/${evidenceId}`, {
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error("Failed to fetch chain of custody logs");
    return res.json();
  },

  // Real-time Forensic Analysis & WebSocket Endpoints
  async startAnalysis(caseId, caseName, totalDurationSeconds = 30) {
    const res = await fetch(`${API_BASE_URL}/analysis/start`, {
      method: "POST",
      headers: this.getHeaders(true, { "Content-Type": "application/json" }),
      body: JSON.stringify({
        case_id: caseId,
        case_name: caseName,
        total_duration_seconds: totalDurationSeconds
      })
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Failed to start analysis task");
    }
    return res.json();
  },

  async getAnalysisTasks() {
    const res = await fetch(`${API_BASE_URL}/analysis/tasks`, {
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error("Failed to list analysis tasks");
    return res.json();
  },

  connectAnalysisWebSocket(taskId, onMessage, onError, onClose) {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/api/v1/analysis/ws/stream/${taskId}`;
    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      console.log(`[WebSocket] Connected to analysis stream for task ${taskId}`);
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (onMessage) onMessage(data);
      } catch (e) {
        console.error("[WebSocket] Failed to parse message:", e);
      }
    };

    ws.onerror = (err) => {
      console.error("[WebSocket] Stream error:", err);
      if (onError) onError(err);
    };

    ws.onclose = () => {
      console.log(`[WebSocket] Stream closed for task ${taskId}`);
      if (onClose) onClose();
    };

    return ws;
  },

  async getForensicData(caseId) {
    const res = await fetch(`${API_BASE_URL}/analysis/${encodeURIComponent(caseId)}/data`, {
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error("Failed to fetch synthesized forensic data");
    return res.json();
  },

  async getArtifacts(caseId) {
    const res = await fetch(`${API_BASE_URL}/analysis/${encodeURIComponent(caseId)}/artifacts`, {
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error("Failed to fetch forensic artifacts");
    return res.json();
  },

  async getTimeline(caseId) {
    const res = await fetch(`${API_BASE_URL}/analysis/${encodeURIComponent(caseId)}/timeline`, {
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error("Failed to fetch attack timeline");
    return res.json();
  },

  async getFindings(caseId) {
    const res = await fetch(`${API_BASE_URL}/analysis/${encodeURIComponent(caseId)}/findings`, {
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error("Failed to fetch key findings");
    return res.json();
  },

  async getReport(caseId) {
    const res = await fetch(`${API_BASE_URL}/analysis/${encodeURIComponent(caseId)}/report`, {
      headers: this.getHeaders()
    });
    if (!res.ok) throw new Error("Failed to fetch court report");
    return res.json();
  }
};

window.HMACFR_API = HMACFR_API;

