import React from "react";
import type { Case, Evidence, InferenceTierStatus } from "../types/forensic";
import type { WorkspaceTab } from "./WorkspaceHeader";

interface WorkspaceMainProps {
  activeTab: WorkspaceTab;
  cases: Case[];
  activeCase: Case | null;
  onSelectCase?: (c: Case) => void;
  onOpenCaseInLab: (c: Case) => void;
  onOpenCreateModal: () => void;
  tierStatus: InferenceTierStatus | null;
  evidenceList: Evidence[];
}

export const WorkspaceMain: React.FC<WorkspaceMainProps> = ({
  activeTab,
  cases,
  activeCase,
  onSelectCase: _onSelectCase,
  onOpenCaseInLab,
  onOpenCreateModal,
  tierStatus,
  evidenceList
}) => {
  const activeCasesCount = cases.filter((c) => c.status !== "Closed").length;

  return (
    <main id="workspace-main" style={{ display: "block", marginLeft: "240px", padding: "1.5rem 2rem", minHeight: "100vh" }}>
      {/* Modern Sleek Command Center Hero Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-6 pb-4 border-b border-slate-800">
        <div>
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-bold uppercase tracking-wider mb-2">
            <span className="w-2 h-2 rounded-full bg-blue-500 animate-pulse"></span>
            Enterprise Digital Forensics
          </div>
          <h1 className="text-2xl font-black font-display text-white tracking-tight">
            Sherlock AI Forensic Command Center
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Hierarchical Multi-Agent Cognitive Forensic Reconstruction Framework • Select any case below to enter its isolated Forensic Lab.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={onOpenCreateModal}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold rounded-lg shadow-md hover:shadow-cyan-500/20 transition flex items-center gap-2 cursor-pointer"
          >
            <span>+</span>
            <span>New Case File</span>
          </button>
        </div>
      </div>

      {/* 1. Command Center / Home Tab */}
      {activeTab === "home" && (
        <div className="space-y-6">
          {/* Top 4 Metrics Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="card p-4 bg-dark-850 border border-slate-800 rounded-xl">
              <div className="text-xs text-slate-400 font-semibold mb-1">TOTAL CASE FILES</div>
              <div className="text-2xl font-black font-mono text-cyan-400">{cases.length}</div>
              <div className="text-[11px] text-slate-500 mt-1">Registered investigation repositories</div>
            </div>

            <div className="card p-4 bg-dark-850 border border-slate-800 rounded-xl">
              <div className="text-xs text-slate-400 font-semibold mb-1">ACTIVE INVESTIGATIONS</div>
              <div className="text-2xl font-black font-mono text-emerald-400">{activeCasesCount}</div>
              <div className="text-[11px] text-slate-500 mt-1">Currently open with active chains</div>
            </div>

            <div className="card p-4 bg-dark-850 border border-slate-800 rounded-xl">
              <div className="text-xs text-slate-400 font-semibold mb-1">EVIDENTIARY ARTIFACTS</div>
              <div className="text-2xl font-black font-mono text-indigo-400">{evidenceList.length}</div>
              <div className="text-[11px] text-slate-500 mt-1">SHA-256 multi-pass verified</div>
            </div>

            <div className="card p-4 bg-dark-850 border border-slate-800 rounded-xl">
              <div className="text-xs text-slate-400 font-semibold mb-1">ACTIVE INFERENCE TIER</div>
              <div className="text-sm font-bold text-amber-400 truncate mt-1">
                {tierStatus?.active_tier || "Tier 3: Rule-based Engine"}
              </div>
              <div className="text-[11px] text-slate-500 mt-1">{tierStatus?.mode || "Deterministic NIST Fallback"}</div>
            </div>
          </div>

          {/* Recent Cases Table */}
          <div className="card bg-dark-850 border border-slate-800 rounded-xl overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
              <h2 className="text-sm font-bold text-slate-200">Investigation Case Repository</h2>
              <span className="text-xs text-slate-400">{cases.length} Total</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-dark-900 border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px]">
                  <tr>
                    <th className="py-3 px-4">Case ID</th>
                    <th className="py-3 px-4">Case Title</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4">Priority</th>
                    <th className="py-3 px-4">Lead Investigator</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {cases.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-slate-500">
                        No forensic cases created yet. Click "+ New Case File" to begin an investigation.
                      </td>
                    </tr>
                  ) : (
                    cases.map((c) => (
                      <tr
                        key={c.case_id}
                        onClick={() => onOpenCaseInLab(c)}
                        className={`hover:bg-slate-800/40 cursor-pointer transition ${
                          activeCase?.case_id === c.case_id ? "bg-cyan-500/10" : ""
                        }`}
                      >
                        <td className="py-3 px-4 font-mono font-semibold text-cyan-400">{c.case_id}</td>
                        <td className="py-3 px-4 font-semibold text-slate-200">{c.case_name}</td>
                        <td className="py-3 px-4">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              c.status === "Active"
                                ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/25"
                                : "bg-slate-800 text-slate-400"
                            }`}
                          >
                            {c.status}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              c.priority === "Critical"
                                ? "bg-rose-500/10 text-rose-400 border border-rose-500/25"
                                : c.priority === "High"
                                ? "bg-amber-500/10 text-amber-400 border border-amber-500/25"
                                : "bg-slate-800 text-slate-300"
                            }`}
                          >
                            {c.priority}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-slate-400">{c.investigator_name || "investigator1"}</td>
                        <td className="py-3 px-4 text-right">
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              onOpenCaseInLab(c);
                            }}
                            className="px-2.5 py-1 bg-dark-800 hover:bg-slate-700 text-cyan-300 border border-cyan-800/50 rounded font-semibold text-[11px] transition cursor-pointer"
                          >
                            Open in Lab &rarr;
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* 2. My Cases Tab */}
      {activeTab === "cases" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-bold text-white">All Investigation Repositories</h2>
            <button
              onClick={onOpenCreateModal}
              className="px-3.5 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold rounded-lg transition cursor-pointer"
            >
              + Create Case
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {cases.map((c) => (
              <div
                key={c.case_id}
                onClick={() => onOpenCaseInLab(c)}
                className={`p-4 rounded-xl border bg-dark-850 cursor-pointer transition hover:border-slate-700 ${
                  activeCase?.case_id === c.case_id ? "border-cyan-500 shadow-lg shadow-cyan-500/10" : "border-slate-800"
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-xs text-cyan-400 font-bold">{c.case_id}</span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-dark-900 border border-slate-700 text-slate-300">
                    {c.priority}
                  </span>
                </div>
                <h3 className="text-sm font-bold text-slate-100 mb-1">{c.case_name}</h3>
                <p className="text-xs text-slate-400 line-clamp-2 mb-3">{c.description || "No description provided."}</p>
                <div className="flex items-center justify-between text-[11px] text-slate-500 border-t border-slate-800/80 pt-2">
                  <span>Vault: {c.vault_status || "OPEN"}</span>
                  <span className="text-cyan-400 font-semibold">Enter Forensic Lab &rarr;</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </main>
  );
};
