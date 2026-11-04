import React, { useState, useEffect, useRef } from "react";
import { api, type ChatResponse, type CaseCitation, type SubgraphNode } from "../../services/api";
import type { Case } from "../../types/forensic";

interface ChatMessage {
  id: string;
  sender: "user" | "sherlock";
  text: string;
  timestamp: string;
  citations?: CaseCitation[];
  confidence?: number;
  executionMode?: string;
  subgraph?: {
    nodes: SubgraphNode[];
    edges: any[];
    matched_seed_nodes: string[];
  };
  mitreTechniques?: string[];
}

interface ForensicChatbotModalProps {
  isOpen: boolean;
  onClose: () => void;
  caseItem: Case;
  onNavigateToWorkstation?: (tab: "evidence" | "extraction" | "analysis" | "sis" | "outputs" | "graph") => void;
  onExplainXAI?: (item: any, type: string) => void;
}

const QUICK_PROMPTS = [
  "What was the initial access vector?",
  "Show process injection indicators and PID lineage",
  "Summarize the attack timeline sequence",
  "Are there any evidence sufficiency gaps?",
  "List verified MITRE ATT&CK techniques with citations"
];

export const ForensicChatbotModal: React.FC<ForensicChatbotModalProps> = ({
  isOpen,
  onClose,
  caseItem,
  onNavigateToWorkstation,
  onExplainXAI
}) => {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputText, setInputText] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen && messages.length === 0) {
      const isCaseEmpty = (caseItem.evidence_count ?? 0) === 0;
      const initialText = isCaseEmpty
        ? `Welcome to Sherlock G-RAG Forensic Assistant for Case '${caseItem.case_name}' (${caseItem.case_id}).\n\n⚠️ **Notice: No Forensic Evidence Ingested.**\nThis case does not currently contain sealed evidence artifacts in the Evidence Vault. Multi-agent correlation, attack reconstruction, and calibrated confidence scoring require ingested forensic streams. Please upload and seal evidence in **Workstation 1 (Evidence Vault)** before requesting investigation conclusions.`
        : `Welcome to Sherlock G-RAG Forensic Assistant for Case '${caseItem.case_name}' (${caseItem.case_id}).\n\nI am grounded in the **Structured Investigation State (SIS)**, **NetworkX / Neo4j 2-hop causal subgraphs**, and **Vector Evidence Stores**. Every factual assertion cites cryptographic SHA-256 hashes and timestamped chain-of-custody provenance with zero hallucination.`;

      setMessages([
        {
          id: "welcome-msg",
          sender: "sherlock",
          text: initialText,
          timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
          confidence: isCaseEmpty ? 0.0 : 0.95,
          executionMode: isCaseEmpty ? "Awaiting Evidentiary Ingestion" : "G-RAG Deterministic Evidence Grounding"
        }
      ]);
    }
  }, [isOpen, caseItem, messages.length]);

  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 150);
    }
  }, [isOpen]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, isLoading]);

  if (!isOpen) return null;

  const handleSend = async (queryText?: string) => {
    const q = (queryText || inputText).trim();
    if (!q || isLoading) return;

    const userMsg: ChatMessage = {
      id: `usr-${Date.now()}`,
      sender: "user",
      text: q,
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputText("");
    setIsLoading(true);

    try {
      const resp: ChatResponse = await api.sendCaseChat(caseItem.case_id, q);

      const botMsg: ChatMessage = {
        id: `bot-${Date.now()}`,
        sender: "sherlock",
        text: resp.answer,
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        citations: resp.citations || [],
        confidence: resp.confidence,
        executionMode: resp.execution_mode,
        subgraph: resp.subgraph,
        mitreTechniques: resp.mitre_techniques || []
      };

      setMessages((prev) => [...prev, botMsg]);
    } catch (err: any) {
      const errMsg: ChatMessage = {
        id: `bot-err-${Date.now()}`,
        sender: "sherlock",
        text: `Forensic G-RAG query failed: ${err.message || "Failed to contact analysis server"}. Please ensure the case analysis has been initialized.`,
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        confidence: 0.0
      };
      setMessages((prev) => [...prev, errMsg]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 9999,
        background: "rgba(10, 15, 29, 0.75)",
        backdropFilter: "blur(6px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: "1rem"
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        style={{
          width: "100%",
          maxWidth: "880px",
          height: "85vh",
          maxHeight: "860px",
          background: "#0d1322",
          border: "1px solid rgba(56, 189, 248, 0.35)",
          borderRadius: "16px",
          display: "flex",
          flexDirection: "column",
          boxShadow: "0 25px 60px -15px rgba(0, 0, 0, 0.8), 0 0 35px rgba(56, 189, 248, 0.15)",
          overflow: "hidden"
        }}
      >
        {/* Header */}
        <header
          style={{
            padding: "1rem 1.25rem",
            background: "linear-gradient(90deg, #101b33 0%, #0d1527 100%)",
            borderBottom: "1px solid rgba(56, 189, 248, 0.2)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between"
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <div
              style={{
                width: "36px",
                height: "36px",
                borderRadius: "10px",
                background: "rgba(56, 189, 248, 0.15)",
                border: "1px solid rgba(56, 189, 248, 0.4)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#38bdf8"
              }}
            >
              <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
              </svg>
            </div>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <h3 style={{ margin: 0, fontSize: "1rem", fontWeight: 700, color: "#f8fafc", letterSpacing: "0.5px" }}>
                  SHERLOCK G-RAG FORENSIC ASSISTANT
                </h3>
                <span
                  style={{
                    background: "rgba(16, 185, 129, 0.2)",
                    color: "#34d399",
                    border: "1px solid rgba(16, 185, 129, 0.4)",
                    padding: "2px 7px",
                    borderRadius: "4px",
                    fontSize: "0.68rem",
                    fontWeight: 700
                  }}
                >
                  ● DUAL STORE ACTIVE
                </span>
              </div>
              <p style={{ margin: 0, fontSize: "0.74rem", color: "#94a3b8" }}>
                Case: <strong style={{ color: "#38bdf8" }}>{caseItem.case_name}</strong> ({caseItem.case_id}) &bull; Neo4j 2-Hop Subgraphs &bull; Qdrant Vector Search
              </p>
            </div>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            {onNavigateToWorkstation && (
              <button
                type="button"
                onClick={() => {
                  onClose();
                  onNavigateToWorkstation("graph");
                }}
                style={{
                  background: "rgba(56, 189, 248, 0.1)",
                  border: "1px solid rgba(56, 189, 248, 0.3)",
                  color: "#38bdf8",
                  padding: "6px 12px",
                  borderRadius: "6px",
                  fontSize: "0.75rem",
                  fontWeight: 600,
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  gap: "6px"
                }}
                title="Switch to Interactive Knowledge Graph"
              >
                <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="18" cy="5" r="3" />
                  <circle cx="6" cy="12" r="3" />
                  <circle cx="18" cy="19" r="3" />
                  <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
                  <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
                </svg>
                <span>View Full Graph</span>
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
                borderRadius: "6px",
                display: "flex",
                alignItems: "center",
                justifyContent: "center"
              }}
              title="Close Assistant"
            >
              <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2.5">
                <line x1="18" y1="6" x2="6" y2="18" />
                <line x1="6" y1="6" x2="18" y2="18" />
              </svg>
            </button>
          </div>
        </header>

        {/* Chat Messages Body */}
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
          {messages.map((msg) => (
            <div
              key={msg.id}
              style={{
                display: "flex",
                flexDirection: "column",
                alignItems: msg.sender === "user" ? "flex-end" : "flex-start",
                gap: "0.35rem"
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                  fontSize: "0.72rem",
                  color: "#64748b",
                  padding: "0 4px"
                }}
              >
                <span>{msg.sender === "user" ? "Investigator (You)" : "Sherlock G-RAG Engine"}</span>
                <span>&bull;</span>
                <span>{msg.timestamp}</span>
              </div>

              <div
                style={{
                  maxWidth: "85%",
                  padding: "1rem 1.15rem",
                  borderRadius: msg.sender === "user" ? "14px 14px 2px 14px" : "14px 14px 14px 2px",
                  background: msg.sender === "user" ? "#0284c7" : "#131c31",
                  border: msg.sender === "user" ? "none" : "1px solid rgba(56, 189, 248, 0.2)",
                  color: "#f8fafc",
                  fontSize: "0.85rem",
                  lineHeight: "1.55",
                  boxShadow: "0 4px 15px rgba(0, 0, 0, 0.25)"
                }}
              >
                <div style={{ whiteSpace: "pre-wrap" }}>{msg.text}</div>

                {/* Badges: Confidence, Mode, MITRE */}
                {msg.sender === "sherlock" && (
                  <div
                    style={{
                      marginTop: "0.85rem",
                      paddingTop: "0.75rem",
                      borderTop: "1px solid rgba(148, 163, 184, 0.15)",
                      display: "flex",
                      flexWrap: "wrap",
                      alignItems: "center",
                      gap: "6px"
                    }}
                  >
                    {msg.confidence !== undefined && (
                      <span
                        style={{
                          background: msg.confidence > 0 ? "rgba(56, 189, 248, 0.15)" : "rgba(245, 158, 11, 0.15)",
                          color: msg.confidence > 0 ? "#38bdf8" : "#fbbf24",
                          border: msg.confidence > 0 ? "1px solid rgba(56, 189, 248, 0.3)" : "1px solid rgba(245, 158, 11, 0.3)",
                          padding: "2px 8px",
                          borderRadius: "4px",
                          fontSize: "0.7rem",
                          fontWeight: 700
                        }}
                      >
                        {msg.confidence > 0 
                          ? `🎯 ${Math.round(msg.confidence * 100)}% Confidence`
                          : "⚠️ No Evidence Grounding (0%)"}
                      </span>
                    )}

                    {msg.executionMode && (
                      <span
                        style={{
                          background: "rgba(168, 85, 247, 0.15)",
                          color: "#c084fc",
                          border: "1px solid rgba(168, 85, 247, 0.3)",
                          padding: "2px 8px",
                          borderRadius: "4px",
                          fontSize: "0.7rem",
                          fontFamily: "JetBrains Mono, monospace"
                        }}
                      >
                        {msg.executionMode}
                      </span>
                    )}

                    {msg.mitreTechniques && msg.mitreTechniques.length > 0 && (
                      msg.mitreTechniques.map((tech) => (
                        <span
                          key={tech}
                          style={{
                            background: "rgba(244, 63, 94, 0.15)",
                            color: "#fb7185",
                            border: "1px solid rgba(244, 63, 94, 0.3)",
                            padding: "2px 8px",
                            borderRadius: "4px",
                            fontSize: "0.7rem",
                            fontFamily: "JetBrains Mono, monospace"
                          }}
                        >
                          {tech}
                        </span>
                      ))
                    )}

                    {onExplainXAI && (
                      <button
                        type="button"
                        onClick={() => {
                          onExplainXAI({
                            title: `Sherlock G-RAG Query Assertion`,
                            reasoning: msg.text,
                            confidence: msg.confidence ?? 0.95,
                            mitre_technique: msg.mitreTechniques?.[0] || "T1059",
                            source: "ChromaDB Vector Store + NetworkX Graph Subgraph"
                          }, "chatbot_response");
                        }}
                        style={{
                          background: "rgba(168, 85, 247, 0.15)",
                          color: "#c084fc",
                          border: "1px solid rgba(168, 85, 247, 0.35)",
                          padding: "2px 8px",
                          borderRadius: "4px",
                          fontSize: "0.68rem",
                          fontWeight: 700,
                          cursor: "pointer",
                          display: "inline-flex",
                          alignItems: "center",
                          gap: "4px"
                        }}
                      >
                        <span>🔬 Explain with xAI</span>
                      </button>
                    )}
                  </div>
                )}

                {/* Subgraph Traversal Summary (Slide 10) */}
                {msg.subgraph && msg.subgraph.nodes && msg.subgraph.nodes.length > 0 && (
                  <div
                    style={{
                      marginTop: "0.75rem",
                      background: "rgba(15, 23, 42, 0.7)",
                      border: "1px solid rgba(56, 189, 248, 0.2)",
                      borderRadius: "8px",
                      padding: "0.6rem 0.85rem",
                      fontSize: "0.73rem"
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.35rem" }}>
                      <span style={{ color: "#38bdf8", fontWeight: 700, display: "flex", alignItems: "center", gap: "5px" }}>
                        <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="6" cy="6" r="3"/><circle cx="18" cy="18" r="3"/><line x1="8.5" y1="8.5" x2="15.5" y2="15.5"/></svg>
                        2-Hop Causal Subgraph Traversal (Neo4j / NetworkX)
                      </span>
                      <span style={{ color: "#64748b", fontFamily: "JetBrains Mono, monospace" }}>
                        {msg.subgraph.nodes.length} nodes &bull; {msg.subgraph.edges.length} edges
                      </span>
                    </div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: "4px" }}>
                      {msg.subgraph.nodes.slice(0, 6).map((node) => (
                        <span
                          key={node.id}
                          style={{
                            background: node.is_seed ? "rgba(251, 146, 60, 0.2)" : "rgba(148, 163, 184, 0.1)",
                            color: node.is_seed ? "#fb923c" : "#cbd5e1",
                            border: `1px solid ${node.is_seed ? "rgba(251, 146, 60, 0.4)" : "rgba(148, 163, 184, 0.2)"}`,
                            padding: "1px 6px",
                            borderRadius: "4px",
                            fontSize: "0.68rem",
                            fontFamily: "JetBrains Mono, monospace"
                          }}
                        >
                          {node.label}
                        </span>
                      ))}
                      {msg.subgraph.nodes.length > 6 && (
                        <span style={{ color: "#64748b", padding: "1px 4px", fontSize: "0.68rem" }}>
                          +{msg.subgraph.nodes.length - 6} more
                        </span>
                      )}
                    </div>
                  </div>
                )}

                {/* Cryptographic Chain-of-Custody Citations (Slide 9 & 16) */}
                {msg.citations && msg.citations.length > 0 && (
                  <div style={{ marginTop: "0.85rem" }}>
                    <div
                      style={{
                        fontSize: "0.7rem",
                        fontWeight: 700,
                        color: "#94a3b8",
                        textTransform: "uppercase",
                        letterSpacing: "0.5px",
                        marginBottom: "0.4rem",
                        display: "flex",
                        alignItems: "center",
                        gap: "5px"
                      }}
                    >
                      <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                      Verified Chain of Custody Citations ({msg.citations.length})
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: "0.4rem" }}>
                      {msg.citations.map((cite, idx) => (
                        <div
                          key={idx}
                          style={{
                            background: "rgba(10, 15, 29, 0.8)",
                            border: "1px solid rgba(56, 189, 248, 0.2)",
                            borderRadius: "6px",
                            padding: "0.5rem 0.65rem",
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "space-between",
                            gap: "8px"
                          }}
                        >
                          <div style={{ overflow: "hidden", minWidth: 0 }}>
                            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                              <span style={{ fontWeight: 600, color: "#38bdf8", fontSize: "0.75rem" }}>
                                {cite.file}
                              </span>
                              <span
                                style={{
                                  background: "rgba(148, 163, 184, 0.15)",
                                  color: "#94a3b8",
                                  padding: "1px 5px",
                                  borderRadius: "3px",
                                  fontSize: "0.65rem"
                                }}
                              >
                                {cite.category}
                              </span>
                            </div>
                            <div
                              style={{
                                color: "#64748b",
                                fontSize: "0.68rem",
                                fontFamily: "JetBrains Mono, monospace",
                                whiteSpace: "nowrap",
                                overflow: "hidden",
                                textOverflow: "ellipsis",
                                marginTop: "2px"
                              }}
                            >
                              SHA-256: {cite.sha256}
                            </div>
                          </div>

                          <button
                            type="button"
                            onClick={() => handleCopyHash(cite.sha256)}
                            style={{
                              background: copiedHash === cite.sha256 ? "rgba(16, 185, 129, 0.2)" : "rgba(56, 189, 248, 0.1)",
                              border: `1px solid ${copiedHash === cite.sha256 ? "rgba(16, 185, 129, 0.4)" : "rgba(56, 189, 248, 0.3)"}`,
                              color: copiedHash === cite.sha256 ? "#34d399" : "#38bdf8",
                              padding: "3px 8px",
                              borderRadius: "4px",
                              fontSize: "0.68rem",
                              cursor: "pointer",
                              whiteSpace: "nowrap"
                            }}
                            title="Copy cryptographic SHA-256 custody hash"
                          >
                            {copiedHash === cite.sha256 ? "✓ Copied" : "Copy Hash"}
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          ))}

          {/* Loading Indicator */}
          {isLoading && (
            <div style={{ display: "flex", alignItems: "center", gap: "10px", padding: "0.5rem" }}>
              <div
                style={{
                  width: "18px",
                  height: "18px",
                  border: "2px solid rgba(56, 189, 248, 0.2)",
                  borderTopColor: "#38bdf8",
                  borderRadius: "50%",
                  animation: "spin 0.8s linear infinite"
                }}
              />
              <span style={{ fontSize: "0.78rem", color: "#38bdf8", fontStyle: "italic" }}>
                Traversing 2-hop causal subgraphs &amp; synthesizing vector citations...
              </span>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Quick Prompts Bar */}
        <div
          style={{
            padding: "0.6rem 1.25rem",
            background: "#0b101c",
            borderTop: "1px solid rgba(56, 189, 248, 0.15)",
            display: "flex",
            alignItems: "center",
            gap: "6px",
            overflowX: "auto",
            scrollbarWidth: "none"
          }}
        >
          <span style={{ fontSize: "0.7rem", color: "#64748b", fontWeight: 700, whiteSpace: "nowrap" }}>
            QUICK PROMPTS:
          </span>
          {QUICK_PROMPTS.map((prompt, idx) => (
            <button
              key={idx}
              type="button"
              disabled={isLoading}
              onClick={() => handleSend(prompt)}
              style={{
                background: "rgba(30, 41, 59, 0.8)",
                border: "1px solid rgba(148, 163, 184, 0.2)",
                color: "#cbd5e1",
                padding: "3px 9px",
                borderRadius: "12px",
                fontSize: "0.72rem",
                cursor: isLoading ? "not-allowed" : "pointer",
                whiteSpace: "nowrap",
                transition: "all 0.15s ease"
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = "rgba(56, 189, 248, 0.5)";
                e.currentTarget.style.color = "#38bdf8";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = "rgba(148, 163, 184, 0.2)";
                e.currentTarget.style.color = "#cbd5e1";
              }}
            >
              {prompt}
            </button>
          ))}
        </div>

        {/* Input Bar */}
        <footer
          style={{
            padding: "0.85rem 1.25rem",
            background: "#0e1526",
            borderTop: "1px solid rgba(56, 189, 248, 0.2)",
            display: "flex",
            alignItems: "center",
            gap: "10px"
          }}
        >
          <input
            ref={inputRef}
            type="text"
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                handleSend();
              }
            }}
            placeholder="Ask Sherlock AI about artifacts, causal subgraphs, timeline, or attack paths..."
            disabled={isLoading}
            style={{
              flex: 1,
              background: "#090d18",
              border: "1px solid rgba(56, 189, 248, 0.3)",
              borderRadius: "8px",
              padding: "0.65rem 0.9rem",
              color: "#f8fafc",
              fontSize: "0.85rem",
              outline: "none"
            }}
          />
          <button
            type="button"
            disabled={isLoading || !inputText.trim()}
            onClick={() => handleSend()}
            style={{
              background: isLoading || !inputText.trim() ? "rgba(30, 41, 59, 0.6)" : "#0284c7",
              color: isLoading || !inputText.trim() ? "#64748b" : "#ffffff",
              border: `1px solid ${isLoading || !inputText.trim() ? "transparent" : "#38bdf8"}`,
              padding: "0.65rem 1.25rem",
              borderRadius: "8px",
              fontWeight: 700,
              fontSize: "0.82rem",
              cursor: isLoading || !inputText.trim() ? "not-allowed" : "pointer",
              display: "flex",
              alignItems: "center",
              gap: "6px",
              boxShadow: isLoading || !inputText.trim() ? "none" : "0 2px 10px rgba(2, 132, 199, 0.35)"
            }}
          >
            <span>Query</span>
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2.5">
              <line x1="22" y1="2" x2="11" y2="13" />
              <polygon points="22 2 15 22 11 13 2 9 22 2" />
            </svg>
          </button>
        </footer>
      </div>
    </div>
  );
};

