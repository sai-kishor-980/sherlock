import React, { useState, useEffect } from "react";
import { Lock, Sparkles } from "lucide-react";
import type { Case, Evidence, DomainFinding, SISState, InferenceTierStatus } from "../types/forensic";
import { EvidenceVaultWorkstation } from "./workstations/EvidenceVaultWorkstation";
import { ArtifactExtractionWorkstation } from "./workstations/ArtifactExtractionWorkstation";
import { MultiAgentAnalysisWorkstation } from "./workstations/MultiAgentAnalysisWorkstation";
import { SISTimelineWorkstation } from "./workstations/SISTimelineWorkstation";
import { CourtReportWorkstation } from "./workstations/CourtReportWorkstation";
import { GraphExplorerWorkstation } from "./workstations/GraphExplorerWorkstation";
import { XAIWorkstation } from "./workstations/XAIWorkstation";
import { ExplainXAIModal } from "./xai/ExplainXAIModal";
import { ManageTeamModal } from "./ManageTeamModal";
import { ForensicChatbotModal } from "./chat/ForensicChatbotModal";
import { ErrorBoundary } from "./ErrorBoundary";

export type LabWorkstationTab = "evidence" | "extraction" | "analysis" | "sis" | "outputs" | "graph" | "xai";

interface ForensicLabWorkspaceProps {
  caseItem: Case;
  onExitLab: () => void;
  tierStatus: InferenceTierStatus | null;
  evidenceList: Evidence[];
  findings: DomainFinding[];
  sisState: SISState | null;
  reportData: any;
  artifactsData?: any;
  manifest: any;
  isAnalyzing: boolean;
  isLoading: boolean;
  initialTab?: LabWorkstationTab;
  onTabChange?: (tab: LabWorkstationTab) => void;
  onUploadEvidence: (file: File, category?: string) => Promise<void>;
  onLockVault: () => Promise<void>;
  onUnlockVault: (reason: string) => Promise<void>;
  onTriggerExtraction: () => Promise<void>;
  onRunAnalysis: () => Promise<void>;
  onReviewSubmit: (action: "APPROVE" | "REJECT_REANALYZE", notes: string) => Promise<void>;
  onDownloadReportJson: () => void;
}

export const ForensicLabWorkspace: React.FC<ForensicLabWorkspaceProps> = ({
  caseItem,
  onExitLab,
  tierStatus,
  evidenceList,
  findings,
  sisState,
  reportData,
  artifactsData,
  manifest,
  isAnalyzing,
  isLoading,
  initialTab,
  onTabChange,
  onUploadEvidence,
  onLockVault,
  onUnlockVault,
  onTriggerExtraction,
  onRunAnalysis,
  onReviewSubmit,
  onDownloadReportJson
}) => {
  const [activeTab, setActiveTab] = useState<LabWorkstationTab>(initialTab || "evidence");
  const [isTeamModalOpen, setIsTeamModalOpen] = useState(false);
  const [isChatOpen, setIsChatOpen] = useState(false);

  // Universal xAI Inspection State
  const [explainModalItem, setExplainModalItem] = useState<any>(null);
  const [explainModalType, setExplainModalType] = useState<string>("finding");
  const [isExplainModalOpen, setIsExplainModalOpen] = useState(false);

  useEffect(() => {
    if (initialTab && initialTab !== activeTab) {
      setActiveTab(initialTab);
    }
  }, [initialTab]);

  const handleSelectTab = (tab: LabWorkstationTab) => {
    setActiveTab(tab);
    if (onTabChange) onTabChange(tab);
  };

  const handleOpenExplainModal = (item: any, type: string = "finding") => {
    setExplainModalItem(item);
    setExplainModalType(type);
    setIsExplainModalOpen(true);
  };

  const priorityLower = (caseItem.priority || "Medium").toLowerCase();

  return (
    <section
      id="sec-forensic-lab"
      className="workspace-section forensic-lab-sandbox-container active"
      style={{ display: "flex", minHeight: "100vh", width: "100%" }}
    >
      {/* Left: In-Case Sidebar Navigation */}
      <aside className="lab-case-subnav" id="lab-case-sidebar">
        {/* Return to Cases Header */}
        <div className="lab-back-header">
          <button type="button" className="btn-lab-back" onClick={onExitLab} title="Return to My Cases">
            <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2.5">
              <line x1="19" y1="12" x2="5" y2="12" />
              <polyline points="12 19 5 12 12 5" />
            </svg>
            <span>Back to My Cases</span>
          </button>
        </div>

        {/* Scoped Case Header Metadata Card */}
        <div className="lab-case-meta-card">
          <div className="lab-case-title-row">
            <h3 id="lab-active-case-title" className="lab-case-title">{caseItem.case_name}</h3>
            <span id="lab-active-case-id" className="lab-case-id-badge">{caseItem.case_id}</span>
          </div>
          <div className="lab-case-badges-row">
            <span id="lab-active-case-priority" className={`lab-pill-priority priority-${priorityLower}`}>
              {String(caseItem.priority || "Medium").toUpperCase()}
            </span>
            <span id="lab-active-case-status" className="lab-pill-status">
              {String(caseItem.status || "Active").toUpperCase()}
            </span>
          </div>

          <div
            className="lab-case-lead-info"
            style={{
              display: "flex",
              flexDirection: "column",
              gap: "0.35rem",
              marginTop: "0.5rem",
              paddingTop: "0.5rem",
              borderTop: "1px solid rgba(148, 163, 184, 0.15)"
            }}
          >
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: "0.75rem" }}>
              <span style={{ color: "#64748b", display: "flex", alignItems: "center", gap: "4px" }}>
                <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" /><circle cx="12" cy="7" r="4" /></svg>
                Lead:
              </span>
              <strong id="lab-active-case-lead" style={{ color: "#0f172a" }}>
                {caseItem.investigator_name}
              </strong>
            </div>

            <div id="lab-my-role-container" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: "0.72rem" }}>
              <span style={{ color: "#64748b" }}>My Status:</span>
              <span id="lab-my-role-badge" style={{ background: "rgba(56, 189, 248, 0.15)", color: "#0284c7", border: "1px solid rgba(56, 189, 248, 0.3)", padding: "1px 6px", borderRadius: "4px", fontWeight: 700, fontSize: "0.7rem" }}>
                Lead Investigator
              </span>
            </div>
          </div>

          {/* Team Management & Chat Assistant Buttons */}
          <div style={{ marginTop: "0.75rem", display: "flex", flexDirection: "column", gap: "0.45rem" }}>
            <button
              type="button"
              id="btn-lab-manage-team"
              onClick={() => setIsTeamModalOpen(true)}
              style={{
                width: "100%",
                background: "#0284c7",
                color: "#ffffff",
                border: "1px solid #38bdf8",
                padding: "0.45rem 0.75rem",
                borderRadius: "8px",
                fontSize: "0.75rem",
                fontWeight: 700,
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                gap: "6px",
                boxShadow: "0 2px 8px rgba(2, 132, 199, 0.25)"
              }}
            >
              <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" /><path d="M23 21v-2a4 4 0 0 0-3-3.87" /><path d="M16 3.13a4 4 0 0 1 0 7.75" /></svg>
              <span>Manage Team &amp; Access</span>
            </button>

            <button
              type="button"
              id="btn-lab-open-chat"
              onClick={() => setIsChatOpen(true)}
              style={{
                width: "100%",
                background: "linear-gradient(135deg, rgba(56, 189, 248, 0.15) 0%, rgba(14, 165, 233, 0.25) 100%)",
                color: "#38bdf8",
                border: "1px solid rgba(56, 189, 248, 0.4)",
                padding: "0.45rem 0.75rem",
                borderRadius: "8px",
                fontSize: "0.75rem",
                fontWeight: 700,
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                gap: "6px"
              }}
            >
              <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" /></svg>
              <span>Ask Sherlock AI (G-RAG)</span>
            </button>
          </div>
        </div>

        {/* 7 In-Case Workstation Tabs */}
        <nav className="lab-workstations-menu">
          <div className="lab-menu-label">CASE WORKSTATIONS</div>

          <button
            type="button"
            className={`lab-nav-item ${activeTab === "evidence" ? "active" : ""}`}
            onClick={() => handleSelectTab("evidence")}
          >
            <span className="lab-nav-icon"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="18" height="18" rx="2" /><line x1="9" y1="3" x2="9" y2="21" /></svg></span>
            <div className="lab-nav-text">
              <span className="lab-nav-title">Evidence Vault</span>
              <span className="lab-nav-sub">Ingestion &amp; Vaulting</span>
            </div>
          </button>

          <button
            type="button"
            className={`lab-nav-item ${activeTab === "extraction" ? "active" : ""}`}
            onClick={() => handleSelectTab("extraction")}
          >
            <span className="lab-nav-icon"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" /></svg></span>
            <div className="lab-nav-text">
              <span className="lab-nav-title">Artifact Extraction</span>
              <span className="lab-nav-sub">Plugin Triage &amp; Parsers</span>
            </div>
          </button>

          <button
            type="button"
            className={`lab-nav-item ${activeTab === "analysis" ? "active" : ""}`}
            onClick={() => handleSelectTab("analysis")}
          >
            <span className="lab-nav-icon"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12" /></svg></span>
            <div className="lab-nav-text">
              <span className="lab-nav-title">Agent Analysis</span>
              <span className="lab-nav-sub">Multi-Agent Telemetry</span>
            </div>
          </button>

          <button
            type="button"
            className={`lab-nav-item ${activeTab === "sis" ? "active" : ""}`}
            onClick={() => handleSelectTab("sis")}
          >
            <span className="lab-nav-icon"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="12 2 2 7 12 12 22 7 12 2" /><polyline points="2 17 12 22 22 17" /><polyline points="2 12 17 22 12" /></svg></span>
            <div className="lab-nav-text">
              <span className="lab-nav-title">SIS Timeline</span>
              <span className="lab-nav-sub">Attack Reconstruction</span>
            </div>
          </button>

          <button
            type="button"
            className={`lab-nav-item ${activeTab === "outputs" ? "active" : ""}`}
            onClick={() => handleSelectTab("outputs")}
          >
            <span className="lab-nav-icon"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /></svg></span>
            <div className="lab-nav-text">
              <span className="lab-nav-title">Outputs &amp; Sign-off</span>
              <span className="lab-nav-sub">Court Report Approval</span>
            </div>
          </button>

          <button
            type="button"
            className={`lab-nav-item ${activeTab === "graph" ? "active" : ""}`}
            onClick={() => handleSelectTab("graph")}
          >
            <span className="lab-nav-icon"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="18" cy="5" r="3" /><circle cx="6" cy="12" r="3" /><circle cx="18" cy="19" r="3" /><line x1="8.59" y1="13.51" x2="15.42" y2="17.49" /><line x1="15.41" y1="6.51" x2="8.59" y2="10.49" /></svg></span>
            <div className="lab-nav-text">
              <span className="lab-nav-title">Graph &amp; DB Explorer</span>
              <span className="lab-nav-sub">Entities &amp; Vector RAG</span>
            </div>
          </button>

          <button
            type="button"
            className={`lab-nav-item ${activeTab === "xai" ? "active" : ""}`}
            onClick={() => handleSelectTab("xai")}
          >
            <span className="lab-nav-icon"><Sparkles className="w-4 h-4 text-purple-400" /></span>
            <div className="lab-nav-text">
              <span className="lab-nav-title">Explainable AI (xAI)</span>
              <span className="lab-nav-sub">Feature Attribution &amp; Law</span>
            </div>
          </button>
        </nav>
      </aside>

      {/* Right: Workstation Sandbox Workbench */}
      <main className="lab-sandbox-workbench flex-1 p-6" id="lab-sandbox-workbench">
        <ErrorBoundary fallbackTitle={`Workstation Exception (${activeTab})`}>
          {activeTab === "evidence" && (
            <EvidenceVaultWorkstation
              caseItem={caseItem}
              evidenceList={evidenceList}
              onUploadEvidence={onUploadEvidence}
              onLockVault={onLockVault}
              onUnlockVault={onUnlockVault}
              onProceedToExtraction={() => handleSelectTab("extraction")}
              isLoading={isLoading}
            />
          )}

          {activeTab === "extraction" && (
            <ArtifactExtractionWorkstation
              caseId={caseItem.case_id}
              manifest={manifest}
              artifactsData={artifactsData}
              onTriggerExtraction={onTriggerExtraction}
              onProceedToAnalysis={() => handleSelectTab("analysis")}
              onExplainXAI={handleOpenExplainModal}
              isLoading={isLoading}
            />
          )}

          {activeTab === "analysis" && (
            <MultiAgentAnalysisWorkstation
              findings={findings}
              onRunAnalysis={onRunAnalysis}
              onProceedToTimeline={() => handleSelectTab("sis")}
              onExplainXAI={handleOpenExplainModal}
              isAnalyzing={isAnalyzing}
              activeTier={tierStatus?.active_tier || "Tier 3: Rule-based Engine"}
              evidenceCount={evidenceList.length}
            />
          )}

          {activeTab === "sis" && (
            <SISTimelineWorkstation
              sisState={sisState}
              onReviewSubmit={onReviewSubmit}
              isLoading={isLoading}
              onNavigateToVault={() => handleSelectTab("evidence")}
              onUnlockVault={onUnlockVault}
            />
          )}

          {activeTab === "outputs" && (
            (sisState?.review_gate?.status === "APPROVED" || sisState?.status === "APPROVED_LOCKED" || sisState?.status === "APPROVED") ? (
              <CourtReportWorkstation
                caseItem={caseItem}
                sisState={sisState}
                reportData={reportData}
                artifactsData={artifactsData}
                onDownloadJson={onDownloadReportJson}
                onExplainXAI={handleOpenExplainModal}
              />
            ) : (
              <div className="forensic-card p-10 text-center max-w-2xl mx-auto my-12 space-y-6 border border-amber-500/40 bg-dark-950/80 shadow-2xl rounded-2xl animate-fadeIn">
                <div className="w-16 h-16 rounded-2xl bg-amber-500/10 border border-amber-500/30 text-amber-400 flex items-center justify-center mx-auto shadow-inner shadow-amber-500/20">
                  <Lock className="w-8 h-8" />
                </div>

                <div className="space-y-2">
                  <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-400 text-xs font-mono font-bold">
                    <span>HTTP 423 LOCKED</span>
                    <span>•</span>
                    <span>AWAITING COMPULSORY INVESTIGATOR REVIEW</span>
                  </div>
                  <h2 className="text-xl font-black font-display text-white">
                    Court Deliverables &amp; Report Enclave Locked
                  </h2>
                  <p className="text-xs text-slate-300 max-w-lg mx-auto leading-relaxed">
                    Under ISO/IEC 27037 standards and the H-MACFR framework, official court deliverables cannot be generated until an authorized examiner certifies the candidate Systematic Investigation Summary (SIS). Review the findings and attack milestones to confirm or reject with examiner notes.
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-dark-900 border border-slate-800 text-xs text-slate-400 font-mono space-y-1">
                  <div>Current Pre-SIS Gate Status: <strong className="text-amber-400">{sisState?.review_gate?.status || "PENDING"}</strong></div>
                  <div>Authorized Examiner: <strong className="text-slate-200">{caseItem.investigator_name}</strong></div>
                </div>

                <div className="pt-2">
                  <button
                    type="button"
                    onClick={() => handleSelectTab("sis")}
                    className="px-6 py-2.5 bg-gradient-to-r from-amber-600 to-amber-500 hover:from-amber-500 hover:to-amber-400 text-slate-950 font-black text-xs rounded-xl shadow-lg shadow-amber-600/30 transition flex items-center gap-2 mx-auto cursor-pointer"
                  >
                    <span>Go to Workstation 4 (SIS Timeline &amp; Review) &rarr;</span>
                  </button>
                </div>
              </div>
            )
          )}

          {activeTab === "graph" && (
            <GraphExplorerWorkstation
              caseItem={caseItem}
              sisState={sisState}
              onSyncToTimeline={() => handleSelectTab("sis")}
            />
          )}

          {activeTab === "xai" && (
            <XAIWorkstation
              caseItem={caseItem}
              findings={findings}
              sisState={sisState}
              onOpenExplainModal={handleOpenExplainModal}
            />
          )}
        </ErrorBoundary>
      </main>

      {/* Floating Sherlock G-RAG AI Assistant Quick Pill */}
      <button
        type="button"
        id="btn-floating-sherlock-chat"
        onClick={() => setIsChatOpen(true)}
        style={{
          position: "fixed",
          bottom: "24px",
          right: "24px",
          zIndex: 90,
          background: "linear-gradient(135deg, #0284c7 0%, #0369a1 100%)",
          color: "#ffffff",
          border: "1px solid rgba(56, 189, 248, 0.4)",
          padding: "0.6rem 1.15rem",
          borderRadius: "30px",
          fontWeight: 700,
          fontSize: "0.82rem",
          cursor: "pointer",
          display: "flex",
          alignItems: "center",
          gap: "8px",
          boxShadow: "0 8px 25px rgba(2, 132, 199, 0.45), 0 0 15px rgba(56, 189, 248, 0.25)",
          transition: "transform 0.15s ease"
        }}
        onMouseEnter={(e) => (e.currentTarget.style.transform = "translateY(-2px)")}
        onMouseLeave={(e) => (e.currentTarget.style.transform = "translateY(0)")}
        title="Open Sherlock G-RAG Forensic Assistant"
      >
        <span
          style={{
            display: "inline-block",
            width: "8px",
            height: "8px",
            borderRadius: "50%",
            background: "#34d399",
            boxShadow: "0 0 8px #34d399"
          }}
        />
        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2.5">
          <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
        </svg>
        <span>Ask Sherlock AI</span>
      </button>

      {/* Forensic Chatbot Modal */}
      {isChatOpen && (
        <ForensicChatbotModal
          isOpen={isChatOpen}
          onClose={() => setIsChatOpen(false)}
          caseItem={caseItem}
          onNavigateToWorkstation={(tab) => handleSelectTab(tab as any)}
          onExplainXAI={handleOpenExplainModal}
        />
      )}

      {/* Manage Team & Access Modal */}
      {isTeamModalOpen && (
        <ManageTeamModal
          isOpen={isTeamModalOpen}
          onClose={() => setIsTeamModalOpen(false)}
          caseItem={caseItem}
        />
      )}

      {/* Universal 4-Part xAI Explanatory Audit Trace Drawer / Modal */}
      <ExplainXAIModal
        isOpen={isExplainModalOpen}
        onClose={() => setIsExplainModalOpen(false)}
        targetItem={explainModalItem}
        itemType={explainModalType}
      />
    </section>
  );
};
