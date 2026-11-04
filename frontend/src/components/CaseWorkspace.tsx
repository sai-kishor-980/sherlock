import React, { useState, useEffect } from "react";
import { Shield, FolderTree, Cpu, GitCommit, Scale, ArrowLeft } from "lucide-react";
import type { Case, Evidence, DomainFinding, SISState, InferenceTierStatus } from "../types/forensic";
import { api } from "../services/api";
import { EvidenceVaultWorkstation } from "./workstations/EvidenceVaultWorkstation";
import { ArtifactExtractionWorkstation } from "./workstations/ArtifactExtractionWorkstation";
import { MultiAgentAnalysisWorkstation } from "./workstations/MultiAgentAnalysisWorkstation";
import { SISTimelineWorkstation } from "./workstations/SISTimelineWorkstation";
import { CourtReportWorkstation } from "./workstations/CourtReportWorkstation";

interface CaseWorkspaceProps {
  caseItem: Case;
  onBack: () => void;
  tierStatus: InferenceTierStatus | null;
}

export type WorkstationTab = "vault" | "extraction" | "analysis" | "timeline" | "report";

export const CaseWorkspace: React.FC<CaseWorkspaceProps> = ({
  caseItem,
  onBack,
  tierStatus
}) => {
  const [activeTab, setActiveTab] = useState<WorkstationTab>("analysis");
  const [evidenceList, setEvidenceList] = useState<Evidence[]>([]);
  const [manifest, setManifest] = useState<any>(null);
  const [findings, setFindings] = useState<DomainFinding[]>([]);
  const [sisState, setSisState] = useState<SISState | null>(null);
  const [reportData, setReportData] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  // Load all case assets
  const loadCaseData = async () => {
    setIsLoading(true);
    try {
      const [evList, mfest, fndgs, sis, rpt] = await Promise.all([
        api.getEvidence(caseItem.case_id).catch(() => []),
        api.getManifest(caseItem.case_id).catch(() => null),
        api.getFindings(caseItem.case_id).catch(() => []),
        api.getSIS(caseItem.case_id).catch(() => null),
        api.getReport(caseItem.case_id).catch(() => null)
      ]);
      setEvidenceList(evList);
      setManifest(mfest);
      setFindings(fndgs);
      setSisState(sis);
      setReportData(rpt);
    } catch (err) {
      console.error("Error loading case data:", err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadCaseData();
  }, [caseItem.case_id]);

  // Actions
  const handleUploadEvidence = async (file: File) => {
    await api.uploadEvidence(caseItem.case_id, file);
    await loadCaseData();
  };

  const handleLockVault = async () => {
    await api.lockVault(caseItem.case_id);
    await loadCaseData();
  };

  const handleUnlockVault = async (reason: string) => {
    await api.unlockVault(caseItem.case_id, reason);
    await loadCaseData();
  };

  const handleTriggerExtraction = async () => {
    setIsLoading(true);
    try {
      await api.triggerExtraction(caseItem.case_id);
      await loadCaseData();
    } finally {
      setIsLoading(false);
    }
  };

  const handleRunAnalysis = async () => {
    setIsAnalyzing(true);
    try {
      await api.runAnalysis(caseItem.case_id);
      await loadCaseData();
    } catch (err: any) {
      alert(err.message || "Analysis error");
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleReviewSubmit = async (action: "APPROVE" | "REJECT_REANALYZE", notes: string) => {
    await api.reviewSIS(caseItem.case_id, action, notes);
    await loadCaseData();
  };

  const handleDownloadReportJson = async () => {
    try {
      const r = await api.getReport(caseItem.case_id);
      const blob = new Blob([JSON.stringify(r, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `SherlockAI_Report_${caseItem.case_id}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: any) {
      alert(err.message || "Failed to download report");
    }
  };

  const tabs: Array<{ id: WorkstationTab; label: string; icon: any }> = [
    { id: "vault", label: "1. Evidence Vault", icon: Shield },
    { id: "extraction", label: "2. Artifact Extraction", icon: FolderTree },
    { id: "analysis", label: "3. Multi-Agent Analysis", icon: Cpu },
    { id: "timeline", label: "4. SIS Timeline", icon: GitCommit },
    { id: "report", label: "5. Court Report", icon: Scale },
  ];

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6 animate-fadeIn">
      {/* Top Breadcrumb & Case Context Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="p-2 rounded-xl bg-dark-850 hover:bg-slate-800 border border-slate-700/80 text-slate-400 hover:text-slate-100 transition"
            title="Return to Cases Dashboard"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs px-2 py-0.5 rounded bg-dark-800 text-cyan-400 border border-slate-700">
                {caseItem.case_id}
              </span>
              <h1 className="text-xl font-bold font-display text-white">
                {caseItem.case_name}
              </h1>
            </div>
            <span className="text-xs text-slate-400 mt-0.5 block">
              Lead: <strong className="text-slate-200">{caseItem.investigator_name}</strong> &bull; Priority: {caseItem.priority}
            </span>
          </div>
        </div>

        {/* 5 Workstation Switcher Buttons */}
        <div className="flex items-center gap-1.5 p-1 bg-dark-850 rounded-xl border border-slate-800 overflow-x-auto">
          {tabs.map((t) => {
            const Icon = t.icon;
            const isActive = activeTab === t.id;
            return (
              <button
                key={t.id}
                onClick={() => setActiveTab(t.id)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition whitespace-nowrap ${
                  isActive
                    ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm"
                    : "text-slate-400 hover:text-slate-200 hover:bg-dark-900"
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? "text-cyan-400" : "text-slate-500"}`} />
                <span>{t.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Active Workstation Mount */}
      <div>
        {activeTab === "vault" && (
          <EvidenceVaultWorkstation
            caseItem={caseItem}
            evidenceList={evidenceList}
            onUploadEvidence={handleUploadEvidence}
            onLockVault={handleLockVault}
            onUnlockVault={handleUnlockVault}
            onProceedToExtraction={() => setActiveTab("extraction")}
            isLoading={isLoading}
          />
        )}

        {activeTab === "extraction" && (
          <ArtifactExtractionWorkstation
            caseId={caseItem.case_id}
            manifest={manifest}
            onTriggerExtraction={handleTriggerExtraction}
            onProceedToAnalysis={() => setActiveTab("analysis")}
            isLoading={isLoading}
          />
        )}

        {activeTab === "analysis" && (
          <MultiAgentAnalysisWorkstation
            findings={findings}
            onRunAnalysis={handleRunAnalysis}
            onProceedToTimeline={() => setActiveTab("timeline")}
            isAnalyzing={isAnalyzing}
            activeTier={tierStatus?.active_tier || "Tier 3: Rule-based Engine"}
            evidenceCount={evidenceList.length}
          />
        )}

        {activeTab === "timeline" && (
          <SISTimelineWorkstation
            sisState={sisState}
            onReviewSubmit={handleReviewSubmit}
            isLoading={isLoading}
          />
        )}

        {activeTab === "report" && (
          <CourtReportWorkstation
            caseItem={caseItem}
            sisState={sisState}
            reportData={reportData}
            onDownloadJson={handleDownloadReportJson}
          />
        )}
      </div>
    </div>
  );
};
