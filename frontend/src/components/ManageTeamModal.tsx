import React, { useState } from "react";
import type { Case } from "../types/forensic";

interface ManageTeamModalProps {
  isOpen: boolean;
  onClose: () => void;
  caseItem: Case | null;
}

export const ManageTeamModal: React.FC<ManageTeamModalProps> = ({
  isOpen,
  onClose,
  caseItem
}) => {
  const [selectedUser, setSelectedUser] = useState("investigator2");
  const [roles, setRoles] = useState({
    lead: false,
    investigator: true,
    analyst: true,
    reviewer: false,
    auditor: false
  });
  const [teamMembers, setTeamMembers] = useState([
    {
      username: caseItem?.investigator_name || "investigator1",
      roles: ["Lead Investigator", "Investigator"]
    }
  ]);
  const [saveNotice, setSaveNotice] = useState<string | null>(null);

  if (!isOpen || !caseItem) return null;

  const handleRoleToggle = (key: keyof typeof roles) => {
    setRoles((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const handleSave = () => {
    const granted: string[] = [];
    if (roles.lead) granted.push("Lead Investigator");
    if (roles.investigator) granted.push("Investigator");
    if (roles.analyst) granted.push("Forensic Analyst");
    if (roles.reviewer) granted.push("Reviewer");
    if (roles.auditor) granted.push("Case Auditor");

    if (granted.length === 0) {
      alert("Please select at least one role to grant.");
      return;
    }

    const existingIdx = teamMembers.findIndex((m) => m.username === selectedUser);
    if (existingIdx >= 0) {
      const updated = [...teamMembers];
      updated[existingIdx].roles = granted;
      setTeamMembers(updated);
    } else {
      setTeamMembers([...teamMembers, { username: selectedUser, roles: granted }]);
    }

    setSaveNotice(`Assigned ${selectedUser} to case successfully!`);
    setTimeout(() => setSaveNotice(null), 3000);
  };

  return (
    <div
      id="modal-manage-case-team"
      className="modal-overlay"
      style={{
        display: "flex",
        position: "fixed",
        inset: 0,
        background: "rgba(11, 17, 30, 0.85)",
        backdropFilter: "blur(12px)",
        zIndex: 99999,
        alignItems: "center",
        justifyContent: "center",
        padding: "1rem"
      }}
    >
      <div
        style={{
          background: "#0f172a",
          borderRadius: "18px",
          width: "100%",
          maxWidth: "680px",
          padding: "1.85rem",
          boxShadow: "0 25px 60px -15px rgba(0, 0, 0, 0.7), 0 0 35px rgba(56, 189, 248, 0.15)",
          border: "1px solid rgba(56, 189, 248, 0.25)",
          fontFamily: "'Plus Jakarta Sans', sans-serif",
          position: "relative",
          color: "#f8fafc"
        }}
      >
        {/* Modal Header */}
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-start",
            marginBottom: "1.25rem",
            borderBottom: "1px solid rgba(148, 163, 184, 0.15)",
            paddingBottom: "1rem"
          }}
        >
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", marginBottom: "0.35rem" }}>
              <span
                style={{
                  background: "rgba(56, 189, 248, 0.12)",
                  color: "#38bdf8",
                  border: "1px solid rgba(56, 189, 248, 0.3)",
                  fontSize: "0.7rem",
                  fontWeight: 800,
                  padding: "2px 8px",
                  borderRadius: "6px",
                  letterSpacing: "0.05em"
                }}
              >
                CASE GOVERNANCE
              </span>
              <span
                style={{
                  fontSize: "0.78rem",
                  fontFamily: "'JetBrains Mono', monospace",
                  color: "#38bdf8",
                  fontWeight: 700
                }}
              >
                {caseItem.case_id}
              </span>
            </div>
            <h3 style={{ fontSize: "1.25rem", fontWeight: 800, color: "#ffffff", margin: 0 }}>
              Manage Case Team &amp; Access Matrix
            </h3>
            <div style={{ fontSize: "0.76rem", color: "#94a3b8", marginTop: "0.3rem" }}>
              Case Creator: <span style={{ color: "#f1f5f9", fontWeight: 700 }}>{caseItem.investigator_name}</span> • Created:{" "}
              <span style={{ color: "#cbd5e1" }}>{caseItem.created_at || "Recent"}</span>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            style={{
              background: "rgba(255,255,255,0.05)",
              border: "1px solid rgba(255,255,255,0.1)",
              width: "32px",
              height: "32px",
              borderRadius: "8px",
              fontSize: "1.3rem",
              color: "#94a3b8",
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              lineHeight: 1
            }}
          >
            &times;
          </button>
        </div>

        {saveNotice && (
          <div className="mb-3 p-2 bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs rounded-lg">
            {saveNotice}
          </div>
        )}

        {/* Current Assigned Members Table */}
        <div style={{ marginBottom: "1.35rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.6rem" }}>
            <div style={{ fontSize: "0.75rem", fontWeight: 800, color: "#38bdf8", letterSpacing: "0.08em", textTransform: "uppercase" }}>
              Active Assigned Personnel
            </div>
            <span style={{ fontSize: "0.72rem", color: "#94a3b8", fontFamily: "'JetBrains Mono', monospace" }}>
              {teamMembers.length} members
            </span>
          </div>
          <div style={{ maxHeight: "180px", overflowY: "auto", border: "1px solid rgba(148, 163, 184, 0.15)", borderRadius: "10px", background: "rgba(15, 23, 42, 0.6)" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.82rem" }}>
              <thead>
                <tr style={{ background: "rgba(30, 41, 59, 0.7)", borderBottom: "1px solid rgba(148, 163, 184, 0.15)", textAlign: "left" }}>
                  <th style={{ padding: "0.6rem 0.85rem", color: "#94a3b8", fontWeight: 700, fontSize: "0.72rem", textTransform: "uppercase" }}>Personnel</th>
                  <th style={{ padding: "0.6rem 0.85rem", color: "#94a3b8", fontWeight: 700, fontSize: "0.72rem", textTransform: "uppercase" }}>Assigned Responsibilities</th>
                </tr>
              </thead>
              <tbody>
                {teamMembers.map((m, idx) => (
                  <tr key={idx} style={{ borderBottom: "1px solid rgba(148, 163, 184, 0.1)" }}>
                    <td style={{ padding: "0.6rem 0.85rem", color: "#f8fafc", fontWeight: 600 }}>{m.username}</td>
                    <td style={{ padding: "0.6rem 0.85rem" }}>
                      <div className="flex flex-wrap gap-1">
                        {m.roles.map((r, ri) => (
                          <span
                            key={ri}
                            className="text-[10px] px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/40"
                          >
                            {r}
                          </span>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Assign / Update Member Form */}
        <div style={{ background: "rgba(30, 41, 59, 0.45)", border: "1px solid rgba(56, 189, 248, 0.18)", borderRadius: "14px", padding: "1.15rem" }}>
          <div style={{ fontSize: "0.85rem", fontWeight: 800, color: "#ffffff", marginBottom: "0.75rem", display: "flex", alignItems: "center", gap: "0.45rem" }}>
            Assign / Update Personnel Responsibilities
          </div>

          <div style={{ marginBottom: "0.85rem" }}>
            <label style={{ fontSize: "0.72rem", fontWeight: 700, color: "#94a3b8", display: "block", marginBottom: "0.35rem", textTransform: "uppercase" }}>
              Select Investigator / Staff User:
            </label>
            <select
              value={selectedUser}
              onChange={(e) => setSelectedUser(e.target.value)}
              style={{
                width: "100%",
                fontSize: "0.84rem",
                padding: "0.55rem 0.85rem",
                background: "#0b111e",
                border: "1px solid rgba(148, 163, 184, 0.25)",
                color: "#f8fafc",
                borderRadius: "8px"
              }}
            >
              <option value="investigator1">investigator1 (Primary Lead)</option>
              <option value="investigator2">investigator2 (Field Investigator)</option>
              <option value="analyst_qwen">analyst_qwen (AI Telemetry Specialist)</option>
              <option value="auditor1">auditor1 (Compliance Auditor)</option>
            </select>
          </div>

          <div style={{ marginBottom: "1rem" }}>
            <label style={{ fontSize: "0.72rem", fontWeight: 700, color: "#94a3b8", display: "block", marginBottom: "0.45rem", textTransform: "uppercase" }}>
              Grant Case Responsibilities:
            </label>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.65rem" }}>
              <label style={{ fontSize: "0.8rem", display: "flex", alignItems: "center", gap: "0.45rem", cursor: "pointer", color: "#e2e8f0", background: "rgba(15, 23, 42, 0.7)", padding: "0.45rem 0.65rem", borderRadius: "8px", border: "1px solid rgba(148, 163, 184, 0.15)" }}>
                <input type="checkbox" checked={roles.lead} onChange={() => handleRoleToggle("lead")} />
                <span><strong>Lead Investigator</strong> (Case Head)</span>
              </label>
              <label style={{ fontSize: "0.8rem", display: "flex", alignItems: "center", gap: "0.45rem", cursor: "pointer", color: "#e2e8f0", background: "rgba(15, 23, 42, 0.7)", padding: "0.45rem 0.65rem", borderRadius: "8px", border: "1px solid rgba(148, 163, 184, 0.15)" }}>
                <input type="checkbox" checked={roles.investigator} onChange={() => handleRoleToggle("investigator")} />
                <span><strong>Investigator</strong> (Evidence &amp; Analysis)</span>
              </label>
              <label style={{ fontSize: "0.8rem", display: "flex", alignItems: "center", gap: "0.45rem", cursor: "pointer", color: "#e2e8f0", background: "rgba(15, 23, 42, 0.7)", padding: "0.45rem 0.65rem", borderRadius: "8px", border: "1px solid rgba(148, 163, 184, 0.15)" }}>
                <input type="checkbox" checked={roles.analyst} onChange={() => handleRoleToggle("analyst")} />
                <span><strong>Forensic Analyst</strong> (Inference &amp; Correl)</span>
              </label>
              <label style={{ fontSize: "0.8rem", display: "flex", alignItems: "center", gap: "0.45rem", cursor: "pointer", color: "#e2e8f0", background: "rgba(15, 23, 42, 0.7)", padding: "0.45rem 0.65rem", borderRadius: "8px", border: "1px solid rgba(148, 163, 184, 0.15)" }}>
                <input type="checkbox" checked={roles.reviewer} onChange={() => handleRoleToggle("reviewer")} />
                <span><strong>Reviewer</strong> (Validate &amp; Sign-off)</span>
              </label>
              <label style={{ fontSize: "0.8rem", display: "flex", alignItems: "center", gap: "0.45rem", cursor: "pointer", color: "#e2e8f0", background: "rgba(15, 23, 42, 0.7)", padding: "0.45rem 0.65rem", borderRadius: "8px", border: "1px solid rgba(148, 163, 184, 0.15)", gridColumn: "span 2" }}>
                <input type="checkbox" checked={roles.auditor} onChange={() => handleRoleToggle("auditor")} />
                <span><strong>Case Auditor</strong> (Read-Only Compliance Inspection)</span>
              </label>
            </div>
          </div>

          <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.65rem", paddingTop: "0.5rem", borderTop: "1px solid rgba(148, 163, 184, 0.12)" }}>
            <button
              type="button"
              onClick={onClose}
              style={{
                border: "1px solid rgba(148, 163, 184, 0.3)",
                background: "transparent",
                color: "#cbd5e1",
                fontSize: "0.8rem",
                padding: "0.4rem 0.9rem",
                borderRadius: "8px",
                cursor: "pointer"
              }}
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleSave}
              style={{
                background: "#0284c7",
                border: "1px solid #38bdf8",
                color: "#ffffff",
                fontSize: "0.8rem",
                fontWeight: 700,
                padding: "0.4rem 1.1rem",
                borderRadius: "8px",
                cursor: "pointer"
              }}
            >
              Save Assignment &rarr;
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
