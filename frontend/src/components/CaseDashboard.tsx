import React, { useState } from "react";
import { FolderPlus, Search, ShieldAlert, Lock, Unlock, ArrowRight, ShieldCheck, Clock, FileArchive } from "lucide-react";
import type { Case, PriorityLevel } from "../types/forensic";

interface CaseDashboardProps {
  cases: Case[];
  onSelectCase: (caseItem: Case) => void;
  onOpenCreateModal: () => void;
  isLoading: boolean;
}

export const CaseDashboard: React.FC<CaseDashboardProps> = ({
  cases,
  onSelectCase,
  onOpenCreateModal,
  isLoading
}) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [priorityFilter, setPriorityFilter] = useState<string>("ALL");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");

  const filteredCases = cases.filter((c) => {
    const matchesSearch =
      c.case_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      c.case_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      c.investigator_name.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesPriority = priorityFilter === "ALL" || c.priority === priorityFilter;
    const matchesStatus = statusFilter === "ALL" || c.status === statusFilter;
    return matchesSearch && matchesPriority && matchesStatus;
  });

  const activeCount = cases.filter((c) => c.status === "Active").length;
  const criticalCount = cases.filter((c) => c.priority === "Critical").length;
  const lockedCount = cases.filter((c) => c.vault_status === "LOCKED").length;

  const getPriorityBadge = (priority: PriorityLevel) => {
    switch (priority) {
      case "Critical":
        return <span className="forensic-badge-rose">Critical P1</span>;
      case "High":
        return <span className="forensic-badge-amber">High P2</span>;
      case "Medium":
        return <span className="forensic-badge-cyan">Medium P3</span>;
      case "Low":
        return <span className="forensic-badge-emerald">Low P4</span>;
      default:
        return <span className="forensic-badge-indigo">{priority}</span>;
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8 animate-fadeIn">
      {/* Top Banner / Metrics */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold font-display text-white tracking-tight">
            Forensic Investigation Cases
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Enterprise case management, ISO/IEC 27037 evidence vault, and multi-agent autonomous triage
          </p>
        </div>
        <button
          onClick={onOpenCreateModal}
          className="flex items-center gap-2 px-4 py-2.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold text-xs rounded-xl shadow-lg shadow-cyan-600/25 transition active:scale-95"
        >
          <FolderPlus className="w-4 h-4" />
          <span>New Case File</span>
        </button>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="forensic-card p-5 flex items-center justify-between">
          <div>
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Cases</span>
            <div className="text-3xl font-extrabold text-cyan-400 font-display mt-1">{activeCount}</div>
            <span className="text-[11px] text-slate-500 mt-0.5 block">Under Investigation</span>
          </div>
          <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
            <Clock className="w-6 h-6" />
          </div>
        </div>

        <div className="forensic-card p-5 flex items-center justify-between">
          <div>
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Critical Threat P1</span>
            <div className="text-3xl font-extrabold text-rose-400 font-display mt-1">{criticalCount}</div>
            <span className="text-[11px] text-slate-500 mt-0.5 block">Immediate Intervention</span>
          </div>
          <div className="w-12 h-12 rounded-xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400">
            <ShieldAlert className="w-6 h-6" />
          </div>
        </div>

        <div className="forensic-card p-5 flex items-center justify-between">
          <div>
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Vault Sealed &amp; Sealed</span>
            <div className="text-3xl font-extrabold text-emerald-400 font-display mt-1">{lockedCount}</div>
            <span className="text-[11px] text-slate-500 mt-0.5 block">Court Chain-of-Custody</span>
          </div>
          <div className="w-12 h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <ShieldCheck className="w-6 h-6" />
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="forensic-card p-4 flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search by case title, case ID, or investigator..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-dark-900 border border-slate-700/80 rounded-xl pl-9 pr-4 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 transition font-sans"
          />
        </div>

        <div className="flex gap-2 flex-wrap">
          <select
            value={priorityFilter}
            onChange={(e) => setPriorityFilter(e.target.value)}
            className="bg-dark-900 border border-slate-700/80 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 transition font-sans"
          >
            <option value="ALL">All Priorities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-dark-900 border border-slate-700/80 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 transition font-sans"
          >
            <option value="ALL">All Statuses</option>
            <option value="Active">Active</option>
            <option value="Closed">Closed</option>
          </select>
        </div>
      </div>

      {/* Case Grid */}
      {isLoading ? (
        <div className="text-center py-16 text-slate-400 text-sm">
          Loading investigation case files...
        </div>
      ) : filteredCases.length === 0 ? (
        <div className="forensic-card p-12 text-center">
          <FileArchive className="w-12 h-12 text-slate-600 mx-auto mb-3" />
          <h3 className="text-base font-bold text-slate-200">No Cases Found</h3>
          <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
            {searchTerm ? "No cases match your active search filters." : "No investigation cases registered yet. Initialize your first case to begin."}
          </p>
          <button
            onClick={onOpenCreateModal}
            className="mt-4 px-4 py-2 bg-dark-800 hover:bg-slate-700 border border-slate-700 rounded-lg text-xs font-semibold text-slate-200 transition"
          >
            + Create New Case
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {filteredCases.map((c) => (
            <div
              key={c.case_id}
              onClick={() => onSelectCase(c)}
              className="forensic-card p-5 flex flex-col justify-between group cursor-pointer hover:border-cyan-500/50 hover:bg-dark-800/80 transition-all hover:-translate-y-1"
            >
              <div>
                {/* Top Row: Case ID & Priority */}
                <div className="flex items-center justify-between gap-2 mb-3">
                  <span className="font-mono text-xs px-2 py-0.5 rounded bg-dark-900 text-slate-300 border border-slate-800">
                    {c.case_id}
                  </span>
                  {getPriorityBadge(c.priority)}
                </div>

                {/* Case Name */}
                <h3 className="text-base font-bold text-white group-hover:text-cyan-300 transition line-clamp-1 mb-1.5">
                  {c.case_name}
                </h3>

                {/* Description */}
                <p className="text-xs text-slate-400 line-clamp-2 mb-4 leading-relaxed">
                  {c.description || "No incident scope provided."}
                </p>
              </div>

              {/* Bottom Metadata */}
              <div className="pt-3.5 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
                <div className="flex items-center gap-1.5">
                  {c.vault_status === "LOCKED" ? (
                    <span className="flex items-center gap-1 text-emerald-400 text-[11px] font-semibold">
                      <Lock className="w-3.5 h-3.5" />
                      <span>Vault Sealed</span>
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 text-slate-500 text-[11px]">
                      <Unlock className="w-3.5 h-3.5" />
                      <span>Vault Open</span>
                    </span>
                  )}
                </div>

                <div className="flex items-center gap-1 text-cyan-400 font-semibold group-hover:translate-x-1 transition">
                  <span>Enter Lab</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
