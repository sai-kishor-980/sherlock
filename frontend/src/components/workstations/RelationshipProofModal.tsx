import React, { useState, useEffect } from "react";
import { api } from "../../services/api";

interface RelationshipProofModalProps {
  isOpen: boolean;
  onClose: () => void;
  caseId: string;
  sourceId: string;
  targetId: string;
}

export const RelationshipProofModal: React.FC<RelationshipProofModalProps> = ({
  isOpen,
  onClose,
  caseId,
  sourceId,
  targetId
}) => {
  const [proofData, setProofData] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen && sourceId && targetId) {
      loadProof();
    }
  }, [isOpen, sourceId, targetId]);

  const loadProof = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await api.getRelationshipProof(caseId, sourceId, targetId);
      setProofData(res);
    } catch (err: any) {
      setError(err.message || "Failed to load relationship proof");
    } finally {
      setIsLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 10000,
        background: "rgba(10, 15, 29, 0.8)",
        backdropFilter: "blur(6px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: "1.25rem"
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        style={{
          width: "100%",
          maxWidth: "760px",
          background: "#0c1222",
          border: "1px solid rgba(168, 85, 247, 0.4)",
          borderRadius: "16px",
          display: "flex",
          flexDirection: "column",
          boxShadow: "0 25px 60px -15px rgba(0, 0, 0, 0.85), 0 0 35px rgba(168, 85, 247, 0.2)",
          overflow: "hidden"
        }}
      >
        {/* Header */}
        <header
          style={{
            padding: "1rem 1.25rem",
            background: "linear-gradient(90deg, #18102a 0%, #0d1222 100%)",
            borderBottom: "1px solid rgba(168, 85, 247, 0.25)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between"
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <div
              style={{
                width: "36px",
                height: "36px",
                borderRadius: "8px",
                background: "rgba(168, 85, 247, 0.15)",
                border: "1px solid rgba(168, 85, 247, 0.35)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#c084fc"
              }}
            >
              <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="6" cy="6" r="3" />
                <circle cx="18" cy="18" r="3" />
                <line x1="8.5" y1="8.5" x2="15.5" y2="15.5" />
              </svg>
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: "1rem", fontWeight: 700, color: "#f8fafc" }}>
                SLIDE 13 RELATIONSHIP TRACE &bull; DETERMINISTIC PROOF
              </h3>
              <p style={{ margin: 0, fontSize: "0.75rem", color: "#94a3b8" }}>
                Cryptographic link verification between forensic clues
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            style={{
              background: "transparent",
              border: "none",
              color: "#94a3b8",
              cursor: "pointer",
              padding: "6px"
            }}
          >
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2.5">
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </header>

        {/* Content */}
        <div style={{ padding: "1.25rem", display: "flex", flexDirection: "column", gap: "1rem" }}>
          {error && (
            <div
              style={{
                padding: "0.75rem",
                borderRadius: "8px",
                background: "rgba(239, 68, 68, 0.15)",
                color: "#f87171",
                fontSize: "0.8rem"
              }}
            >
              {error}
            </div>
          )}

          {proofData && (
            <>
              {/* Linked Clues Diagram */}
              <div
                style={{
                  background: "#080c16",
                  border: "1px solid rgba(168, 85, 247, 0.25)",
                  borderRadius: "10px",
                  padding: "1rem",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: "1rem"
                }}
              >
                {/* Source Node */}
                <div style={{ flex: 1, overflow: "hidden" }}>
                  <div style={{ fontSize: "0.68rem", color: "#64748b", textTransform: "uppercase" }}>Source Clue</div>
                  <div style={{ fontSize: "0.85rem", fontWeight: 700, color: "#38bdf8", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {proofData.source?.label}
                  </div>
                  <div style={{ fontSize: "0.68rem", color: "#94a3b8", fontFamily: "JetBrains Mono, monospace" }}>
                    {proofData.source?.id}
                  </div>
                </div>

                {/* Arrow / Relationship Type */}
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", minWidth: "120px" }}>
                  <span
                    style={{
                      background: "rgba(168, 85, 247, 0.15)",
                      color: "#c084fc",
                      border: "1px solid rgba(168, 85, 247, 0.3)",
                      padding: "2px 8px",
                      borderRadius: "12px",
                      fontSize: "0.68rem",
                      fontWeight: 700,
                      fontFamily: "JetBrains Mono, monospace"
                    }}
                  >
                    {proofData.relationship_type}
                  </span>
                  <div style={{ color: "#a855f7", fontSize: "1.2rem", lineHeight: 1 }}>&rarr;</div>
                  <span style={{ fontSize: "0.65rem", color: "#34d399", fontWeight: 600 }}>
                    {proofData.nature}
                  </span>
                </div>

                {/* Target Node */}
                <div style={{ flex: 1, overflow: "hidden", textAlign: "right" }}>
                  <div style={{ fontSize: "0.68rem", color: "#64748b", textTransform: "uppercase" }}>Target Clue</div>
                  <div style={{ fontSize: "0.85rem", fontWeight: 700, color: "#fb7185", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {proofData.target?.label}
                  </div>
                  <div style={{ fontSize: "0.68rem", color: "#94a3b8", fontFamily: "JetBrains Mono, monospace" }}>
                    {proofData.target?.id}
                  </div>
                </div>
              </div>

              {/* Deterministic Proof Specification */}
              {proofData.deterministic_proof && (
                <div
                  style={{
                    background: "#090f1d",
                    border: "1px solid rgba(56, 189, 248, 0.25)",
                    borderRadius: "10px",
                    padding: "1rem",
                    display: "flex",
                    flexDirection: "column",
                    gap: "0.6rem"
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                    <span
                      style={{
                        fontSize: "0.72rem",
                        color: "#38bdf8",
                        fontWeight: 700,
                        textTransform: "uppercase",
                        letterSpacing: "0.5px"
                      }}
                    >
                      DETERMINISTIC CORRELATION PROOF
                    </span>
                    <span
                      style={{
                        background: "rgba(16, 185, 129, 0.15)",
                        color: "#34d399",
                        border: "1px solid rgba(16, 185, 129, 0.3)",
                        padding: "2px 8px",
                        borderRadius: "4px",
                        fontSize: "0.68rem",
                        fontFamily: "JetBrains Mono, monospace",
                        fontWeight: 700
                      }}
                    >
                      {proofData.deterministic_proof.rule_id}
                    </span>
                  </div>

                  <p
                    style={{
                      margin: 0,
                      fontSize: "0.85rem",
                      color: "#f8fafc",
                      lineHeight: "1.5",
                      background: "rgba(15, 23, 42, 0.6)",
                      border: "1px solid rgba(148, 163, 184, 0.15)",
                      borderRadius: "6px",
                      padding: "0.75rem"
                    }}
                  >
                    {proofData.deterministic_proof.proof_summary}
                  </p>

                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      fontSize: "0.72rem",
                      color: "#94a3b8"
                    }}
                  >
                    <span>
                      Standard: <strong style={{ color: "#cbd5e1" }}>{proofData.deterministic_proof.evidentiary_standard}</strong>
                    </span>
                    <span style={{ color: "#38bdf8", fontWeight: 700 }}>
                      Calibrated Weight: {Math.round(proofData.deterministic_proof.xai_confidence_weight * 100)}%
                    </span>
                  </div>
                </div>
              )}
            </>
          )}

          {isLoading && (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: "2rem" }}>
              <span style={{ color: "#c084fc", fontSize: "0.8rem" }}>
                Retrieving deterministic edge provenance proof...
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
