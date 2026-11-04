import React, { useState, useEffect } from "react";
import { api } from "../../services/api";

interface VisualClueInspectionModalProps {
  isOpen: boolean;
  onClose: () => void;
  caseId: string;
  clueId: string;
  clueLabel: string;
  onSyncToTimeline?: (timestamp?: string) => void;
}

export const VisualClueInspectionModal: React.FC<VisualClueInspectionModalProps> = ({
  isOpen,
  onClose,
  caseId,
  clueId,
  clueLabel,
  onSyncToTimeline
}) => {
  const [data, setData] = useState<any>(null);
  const [offset, setOffset] = useState(0);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState(false);

  useEffect(() => {
    if (isOpen && clueId) {
      loadHexData(0);
    }
  }, [isOpen, clueId]);

  const loadHexData = async (newOffset: number) => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await api.getClueHex(caseId, clueId, newOffset, 512);
      setData(res);
      setOffset(newOffset);
    } catch (err: any) {
      setError(err.message || "Failed to load raw hex stream");
    } finally {
      setIsLoading(false);
    }
  };

  if (!isOpen) return null;

  const handleCopyHash = () => {
    if (data?.sha256) {
      navigator.clipboard.writeText(data.sha256);
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 2000);
    }
  };

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
          maxWidth: "960px",
          height: "88vh",
          maxHeight: "880px",
          background: "#0c1222",
          border: "1px solid rgba(56, 189, 248, 0.4)",
          borderRadius: "16px",
          display: "flex",
          flexDirection: "column",
          boxShadow: "0 25px 60px -15px rgba(0, 0, 0, 0.85), 0 0 35px rgba(56, 189, 248, 0.2)",
          overflow: "hidden"
        }}
      >
        {/* Header */}
        <header
          style={{
            padding: "1rem 1.25rem",
            background: "linear-gradient(90deg, #101a33 0%, #0d1527 100%)",
            borderBottom: "1px solid rgba(56, 189, 248, 0.25)",
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
                background: "rgba(56, 189, 248, 0.15)",
                border: "1px solid rgba(56, 189, 248, 0.35)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#38bdf8"
              }}
            >
              <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="2" y="3" width="20" height="14" rx="2" />
                <line x1="8" y1="21" x2="16" y2="21" />
                <line x1="12" y1="17" x2="12" y2="21" />
              </svg>
            </div>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <h3 style={{ margin: 0, fontSize: "1rem", fontWeight: 700, color: "#f8fafc" }}>
                  SLIDE 13 VISUAL CASE BOARD &bull; RAW BYTE &amp; xAI INSPECTOR
                </h3>
                <span
                  style={{
                    background: "rgba(56, 189, 248, 0.15)",
                    color: "#38bdf8",
                    padding: "2px 7px",
                    borderRadius: "4px",
                    fontSize: "0.68rem",
                    fontWeight: 700
                  }}
                >
                  ISO/IEC 27037 ZERO-ALTERATION
                </span>
              </div>
              <p style={{ margin: 0, fontSize: "0.75rem", color: "#94a3b8" }}>
                Clue: <strong style={{ color: "#38bdf8" }}>{clueLabel}</strong> ({clueId})
              </p>
            </div>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            {onSyncToTimeline && (
              <button
                type="button"
                onClick={() => {
                  onClose();
                  onSyncToTimeline(data?.acquisition_timestamp);
                }}
                style={{
                  background: "rgba(16, 185, 129, 0.15)",
                  border: "1px solid rgba(16, 185, 129, 0.4)",
                  color: "#34d399",
                  padding: "6px 12px",
                  borderRadius: "6px",
                  fontSize: "0.75rem",
                  fontWeight: 600,
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  gap: "6px"
                }}
                title="Slide 13 Timeline Sync: Center SIS timeline on this clue"
              >
                <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <polyline points="12 6 12 12 16 14" />
                  <circle cx="12" cy="12" r="10" />
                </svg>
                <span>Timeline Sync</span>
              </button>
            )}

            <button
              type="button"
              onClick={onClose}
              style={{
                background: "transparent",
                border: "none",
                color: "#94a3b8",
                cursor: "pointer",
                padding: "6px",
                display: "flex",
                alignItems: "center",
                justifyContent: "center"
              }}
            >
              <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2.5">
                <line x1="18" y1="6" x2="6" y2="18" />
                <line x1="6" y1="6" x2="18" y2="18" />
              </svg>
            </button>
          </div>
        </header>

        {/* Content Body */}
        <div
          style={{
            flex: 1,
            overflowY: "auto",
            padding: "1.25rem",
            display: "flex",
            flexDirection: "column",
            gap: "1.25rem"
          }}
        >
          {error && (
            <div
              style={{
                padding: "0.75rem 1rem",
                borderRadius: "8px",
                background: "rgba(239, 68, 68, 0.15)",
                border: "1px solid rgba(239, 68, 68, 0.3)",
                color: "#f87171",
                fontSize: "0.8rem"
              }}
            >
              {error}
            </div>
          )}

          {data && (
            <>
              {/* Metadata Cards */}
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
                  gap: "0.75rem"
                }}
              >
                {/* SHA-256 Custody Card */}
                <div
                  style={{
                    background: "#090f1d",
                    border: "1px solid rgba(56, 189, 248, 0.2)",
                    borderRadius: "8px",
                    padding: "0.75rem",
                    display: "flex",
                    flexDirection: "column",
                    gap: "4px"
                  }}
                >
                  <span style={{ fontSize: "0.7rem", color: "#64748b", textTransform: "uppercase", fontWeight: 700 }}>
                    SHA-256 Custody Seal
                  </span>
                  <div
                    style={{
                      fontFamily: "JetBrains Mono, monospace",
                      fontSize: "0.7rem",
                      color: "#38bdf8",
                      wordBreak: "break-all"
                    }}
                  >
                    {data.sha256}
                  </div>
                  <button
                    type="button"
                    onClick={handleCopyHash}
                    style={{
                      marginTop: "4px",
                      alignSelf: "flex-start",
                      background: copiedHash ? "rgba(16, 185, 129, 0.2)" : "rgba(56, 189, 248, 0.1)",
                      border: `1px solid ${copiedHash ? "rgba(16, 185, 129, 0.4)" : "rgba(56, 189, 248, 0.3)"}`,
                      color: copiedHash ? "#34d399" : "#38bdf8",
                      padding: "2px 8px",
                      borderRadius: "4px",
                      fontSize: "0.68rem",
                      cursor: "pointer"
                    }}
                  >
                    {copiedHash ? "✓ Hash Copied" : "Copy Hash"}
                  </button>
                </div>

                {/* Entropy & Anomaly */}
                <div
                  style={{
                    background: "#090f1d",
                    border: "1px solid rgba(56, 189, 248, 0.2)",
                    borderRadius: "8px",
                    padding: "0.75rem",
                    display: "flex",
                    flexDirection: "column",
                    gap: "4px"
                  }}
                >
                  <span style={{ fontSize: "0.7rem", color: "#64748b", textTransform: "uppercase", fontWeight: 700 }}>
                    Shannon Byte Entropy
                  </span>
                  <div style={{ display: "flex", alignItems: "baseline", gap: "6px" }}>
                    <span
                      style={{
                        fontSize: "1.25rem",
                        fontWeight: 800,
                        color: data.is_high_entropy ? "#fb7185" : "#34d399"
                      }}
                    >
                      {data.entropy}
                    </span>
                    <span style={{ fontSize: "0.75rem", color: "#64748b" }}>/ 8.000 max</span>
                  </div>
                  <span
                    style={{
                      fontSize: "0.68rem",
                      color: data.is_high_entropy ? "#fda4af" : "#94a3b8"
                    }}
                  >
                    {data.is_high_entropy
                      ? "⚠️ Elevated Entropy (Potential encrypted / packed payload)"
                      : "✓ Normal Entropy baseline (Standard structure)"}
                  </span>
                </div>

                {/* Acquisition Metadata */}
                <div
                  style={{
                    background: "#090f1d",
                    border: "1px solid rgba(56, 189, 248, 0.2)",
                    borderRadius: "8px",
                    padding: "0.75rem",
                    display: "flex",
                    flexDirection: "column",
                    gap: "4px"
                  }}
                >
                  <span style={{ fontSize: "0.7rem", color: "#64748b", textTransform: "uppercase", fontWeight: 700 }}>
                    Acquisition Provenance
                  </span>
                  <div style={{ fontSize: "0.75rem", color: "#f8fafc", fontWeight: 600 }}>
                    {data.filename}
                  </div>
                  <div style={{ fontSize: "0.68rem", color: "#64748b" }}>
                    Category: <strong style={{ color: "#94a3b8" }}>{data.category}</strong>
                  </div>
                  <div style={{ fontSize: "0.68rem", color: "#64748b", fontFamily: "JetBrains Mono, monospace" }}>
                    UTC: {data.acquisition_timestamp}
                  </div>
                </div>
              </div>

              {/* xAI Anomaly Attribution Matrix */}
              {data.xai_telemetry && (
                <div
                  style={{
                    background: "#090e1b",
                    border: "1px solid rgba(168, 85, 247, 0.25)",
                    borderRadius: "10px",
                    padding: "0.85rem 1rem"
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      marginBottom: "0.6rem"
                    }}
                  >
                    <span
                      style={{
                        fontSize: "0.75rem",
                        fontWeight: 700,
                        color: "#c084fc",
                        display: "flex",
                        alignItems: "center",
                        gap: "6px"
                      }}
                    >
                      <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2">
                        <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
                      </svg>
                      xAI Explainability Matrix ({data.xai_telemetry.model_family})
                    </span>
                    <span
                      style={{
                        background: "rgba(168, 85, 247, 0.15)",
                        color: "#c084fc",
                        border: "1px solid rgba(168, 85, 247, 0.3)",
                        padding: "1px 6px",
                        borderRadius: "4px",
                        fontSize: "0.68rem",
                        fontFamily: "JetBrains Mono, monospace"
                      }}
                    >
                      Anomaly Score: {data.xai_telemetry.anomaly_score}
                    </span>
                  </div>

                  <p style={{ margin: "0 0 0.65rem 0", fontSize: "0.74rem", color: "#cbd5e1" }}>
                    {data.xai_telemetry.interpretation}
                  </p>

                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
                      gap: "0.5rem"
                    }}
                  >
                    {data.xai_telemetry.feature_attribution?.map((feat: any, idx: number) => (
                      <div
                        key={idx}
                        style={{
                          background: "rgba(15, 23, 42, 0.7)",
                          border: "1px solid rgba(148, 163, 184, 0.15)",
                          borderRadius: "6px",
                          padding: "0.45rem 0.65rem",
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "space-between"
                        }}
                      >
                        <div>
                          <div style={{ fontSize: "0.7rem", color: "#94a3b8" }}>{feat.feature}</div>
                          <div style={{ fontSize: "0.72rem", color: "#f8fafc", fontWeight: 600 }}>{feat.value}</div>
                        </div>
                        <span
                          style={{
                            fontSize: "0.65rem",
                            fontWeight: 700,
                            padding: "2px 5px",
                            borderRadius: "3px",
                            background:
                              feat.verdict === "SUSPICIOUS"
                                ? "rgba(244, 63, 94, 0.2)"
                                : feat.verdict === "ELEVATED"
                                ? "rgba(251, 146, 60, 0.2)"
                                : "rgba(16, 185, 129, 0.2)",
                            color:
                              feat.verdict === "SUSPICIOUS"
                                ? "#fb7185"
                                : feat.verdict === "ELEVATED"
                                ? "#fb923c"
                                : "#34d399"
                          }}
                        >
                          {feat.verdict}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Raw Hex Table */}
              <div
                style={{
                  background: "#080c16",
                  border: "1px solid rgba(56, 189, 248, 0.25)",
                  borderRadius: "10px",
                  padding: "0.85rem",
                  fontFamily: "JetBrains Mono, monospace",
                  fontSize: "0.74rem"
                }}
              >
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    paddingBottom: "0.5rem",
                    marginBottom: "0.5rem",
                    borderBottom: "1px solid rgba(56, 189, 248, 0.15)",
                    fontFamily: "sans-serif"
                  }}
                >
                  <span style={{ fontSize: "0.75rem", fontWeight: 700, color: "#38bdf8" }}>
                    HEX VIEWPORT (Offset: 0x{offset.toString(16).padStart(8, "0")})
                  </span>
                  <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                    <button
                      type="button"
                      disabled={offset === 0 || isLoading}
                      onClick={() => loadHexData(Math.max(0, offset - 512))}
                      style={{
                        background: "rgba(56, 189, 248, 0.1)",
                        border: "1px solid rgba(56, 189, 248, 0.3)",
                        color: "#38bdf8",
                        padding: "2px 8px",
                        borderRadius: "4px",
                        fontSize: "0.68rem",
                        cursor: offset === 0 ? "not-allowed" : "pointer"
                      }}
                    >
                      &larr; Prev 512B
                    </button>
                    <button
                      type="button"
                      disabled={isLoading}
                      onClick={() => loadHexData(offset + 512)}
                      style={{
                        background: "rgba(56, 189, 248, 0.1)",
                        border: "1px solid rgba(56, 189, 248, 0.3)",
                        color: "#38bdf8",
                        padding: "2px 8px",
                        borderRadius: "4px",
                        fontSize: "0.68rem",
                        cursor: "pointer"
                      }}
                    >
                      Next 512B &rarr;
                    </button>
                  </div>
                </div>

                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "85px 1fr 140px",
                    gap: "12px",
                    color: "#64748b",
                    fontSize: "0.68rem",
                    fontWeight: 700,
                    borderBottom: "1px solid rgba(148, 163, 184, 0.1)",
                    paddingBottom: "4px",
                    marginBottom: "6px"
                  }}
                >
                  <span>OFFSET</span>
                  <span>HEX BYTES (00 - 0F)</span>
                  <span>ASCII DECODE</span>
                </div>

                <div style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
                  {data.hex_rows?.map((row: any, idx: number) => (
                    <div
                      key={idx}
                      style={{
                        display: "grid",
                        gridTemplateColumns: "85px 1fr 140px",
                        gap: "12px",
                        lineHeight: "1.4"
                      }}
                    >
                      <span style={{ color: "#0284c7" }}>{row.offset}</span>
                      <span style={{ color: "#cbd5e1" }}>{row.hex}</span>
                      <span style={{ color: "#34d399", whiteSpace: "pre" }}>{row.ascii}</span>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}

          {isLoading && (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: "2rem" }}>
              <span style={{ color: "#38bdf8", fontSize: "0.8rem" }}>
                Reading raw byte stream &amp; calculating Shannon entropy...
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

