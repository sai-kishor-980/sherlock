import React, { useState } from "react";
import { FolderTree, Play, CheckCircle2, FileJson, ArrowRight, X, Copy, Check, Table2, Layers } from "lucide-react";
import { ArtifactExplorerTable } from "./ArtifactExplorerTable";

interface ArtifactExtractionWorkstationProps {
  caseId: string;
  manifest: any;
  artifactsData?: any;
  onTriggerExtraction: () => Promise<void>;
  onProceedToAnalysis: () => void;
  onExplainXAI?: (item: any, type: string) => void;
  isLoading: boolean;
}

export const ArtifactExtractionWorkstation: React.FC<ArtifactExtractionWorkstationProps> = ({
  manifest,
  artifactsData,
  onTriggerExtraction,
  onProceedToAnalysis,
  onExplainXAI,
  isLoading
}) => {
  const [selectedFile, setSelectedFile] = useState<{ domain: string; name: string } | null>(null);
  const [copied, setCopied] = useState(false);
  const [viewMode, setViewMode] = useState<"table" | "hierarchy">("table");

  const activeAgents = manifest?.active_agents || {};
  const totalArtifacts = manifest?.total_artifacts_extracted || 0;
  const hasExtracted = totalArtifacts > 0 || (artifactsData?.summary?.total_artifacts ?? 0) > 0;

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Top Banner */}
      <div className="forensic-card p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold font-display text-white flex items-center gap-2">
            <FolderTree className="w-5 h-5 text-cyan-400" />
            Artifact Extraction &amp; Contract Normalization
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Volatile memory parsing, filesystem Prefetch triage, EVTX parsing, and registry hive extraction into standard schemas
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={onTriggerExtraction}
            disabled={isLoading}
            className="px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold text-xs rounded-xl shadow-lg shadow-cyan-600/25 transition disabled:opacity-50 flex items-center gap-2"
          >
            <Play className={`w-3.5 h-3.5 fill-current ${isLoading ? "animate-spin" : ""}`} />
            <span>{isLoading ? "Executing Parsers..." : "Execute Extractors"}</span>
          </button>

          {hasExtracted && (
            <button
              onClick={onProceedToAnalysis}
              className="px-4 py-2 bg-dark-800 hover:bg-slate-700 border border-slate-700 text-xs font-semibold text-slate-200 rounded-xl transition flex items-center gap-1.5"
            >
              <span>Multi-Agent Analysis</span>
              <ArrowRight className="w-3.5 h-3.5 text-cyan-400" />
            </button>
          )}
        </div>
      </div>

      {/* Manifest Overview Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="forensic-card p-4">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Total JSON Contracts</span>
          <div className="text-2xl font-bold font-display text-cyan-400 mt-1">{totalArtifacts}</div>
        </div>

        <div className="forensic-card p-4">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Active Domain Agents</span>
          <div className="text-2xl font-bold font-display text-emerald-400 mt-1">
            {Object.keys(activeAgents).length} / 5
          </div>
        </div>

        <div className="forensic-card p-4">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Extraction State</span>
          <div className="text-sm font-bold font-display text-slate-200 mt-2 flex items-center gap-1.5">
            {hasExtracted ? (
              <span className="text-emerald-400 flex items-center gap-1">
                <CheckCircle2 className="w-4 h-4" /> Ready for Triage
              </span>
            ) : (
              <span className="text-slate-400">Pending Execution</span>
            )}
          </div>
        </div>

        <div className="forensic-card p-4">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Contract Validation</span>
          <div className="text-sm font-bold font-display text-cyan-400 mt-2">
            Strict Schema Enforced
          </div>
        </div>
      </div>

      {/* View Switcher: Categorized Artifact Explorer vs File Hierarchy */}
      <div className="forensic-card overflow-hidden">
        <div className="px-5 py-3 border-b border-slate-800 bg-dark-850 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-bold text-slate-200">
              {viewMode === "table" ? "5-Domain Forensic Artifact Explorer" : "Extracted Artifact Hierarchy (extracted_artifacts/)"}
            </h3>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-500/30 text-cyan-300">
              {artifactsData?.summary?.total_artifacts ?? totalArtifacts} Parsed
            </span>
          </div>

          <div className="flex items-center gap-1.5 bg-dark-900 p-1 rounded-lg border border-slate-800">
            <button
              type="button"
              onClick={() => setViewMode("table")}
              className={`px-3 py-1 rounded text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer ${viewMode === "table" ? "bg-cyan-600 text-white shadow-sm" : "text-slate-400 hover:text-slate-200"
                }`}
            >
              <Table2 className="w-3.5 h-3.5" />
              <span>Categorized Tables</span>
            </button>
            <button
              type="button"
              onClick={() => setViewMode("hierarchy")}
              className={`px-3 py-1 rounded text-xs font-semibold flex items-center gap-1.5 transition cursor-pointer ${viewMode === "hierarchy" ? "bg-cyan-600 text-white shadow-sm" : "text-slate-400 hover:text-slate-200"
                }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Raw Contracts</span>
            </button>
          </div>
        </div>

        <div className="p-5">
          {viewMode === "table" ? (
            <ArtifactExplorerTable
              data={artifactsData}
              onExplainXAI={onExplainXAI}
            />
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {["network", "memory", "disk", "logs", "registry"].map((domain) => {
                const agentInfo = activeAgents[domain];
                const files = agentInfo?.files || [];
                const hasFiles = files.length > 0;

                return (
                  <div
                    key={domain}
                    className={`p-4 rounded-xl border transition ${hasFiles ? "bg-dark-800/80 border-slate-700/80" : "bg-dark-900/40 border-slate-800/60 opacity-60"
                      }`}
                  >
                    <div className="flex items-center justify-between mb-2.5">
                      <span className="text-xs font-bold text-slate-100 uppercase tracking-wider flex items-center gap-1.5">
                        <span className="w-2 h-2 rounded-full bg-cyan-400" />
                        {domain} Domain
                      </span>
                      <span className={`text-[11px] font-mono px-2 py-0.5 rounded ${hasFiles ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20" : "bg-slate-800 text-slate-500"
                        }`}>
                        {files.length} contracts
                      </span>
                    </div>

                    {hasFiles ? (
                      <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                        {files.map((file: any) => {
                          const fname = typeof file === "string" ? file : (file.filename || file.name || "contract.json");
                          const fsize = typeof file === "object" ? file.size_formatted : null;
                          return (
                            <button
                              key={fname}
                              onClick={() => setSelectedFile({ domain, name: fname })}
                              className="w-full text-left px-2.5 py-1.5 rounded-lg bg-dark-900/80 hover:bg-slate-750 border border-slate-800 text-slate-300 hover:text-cyan-300 font-mono text-[11px] flex items-center justify-between transition cursor-pointer"
                            >
                              <span className="truncate">{fname}</span>
                              <span className="text-[10px] text-slate-500">{fsize || "JSON"}</span>
                            </button>
                          );
                        })}
                      </div>
                    ) : (
                      <div className="text-xs text-slate-500 italic py-4 text-center">
                        No artifacts extracted for this domain
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Contract Preview Modal */}
      {selectedFile && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
          <div className="relative w-full max-w-2xl bg-dark-900 border border-slate-700 rounded-xl p-5 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <FileJson className="w-5 h-5 text-cyan-400" />
                <span className="text-sm font-bold text-slate-100 font-mono">
                  extracted_artifacts/{selectedFile.domain}/{selectedFile.name}
                </span>
              </div>
              <button
                onClick={() => setSelectedFile(null)}
                className="p-1 rounded text-slate-400 hover:text-slate-200"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="my-4 p-3 rounded-lg bg-dark-950 border border-slate-800 font-mono text-xs text-cyan-300 max-h-80 overflow-y-auto">
              <pre>{JSON.stringify({ domain: selectedFile.domain, contract: selectedFile.name, status: "NORM_VALIDATED" }, null, 2)}</pre>
            </div>

            <div className="flex justify-end gap-2">
              <button
                onClick={() => handleCopy(selectedFile.name)}
                className="px-3 py-1.5 bg-dark-800 text-slate-300 text-xs rounded-lg flex items-center gap-1.5"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? "Copied" : "Copy Path"}</span>
              </button>
              <button
                onClick={() => setSelectedFile(null)}
                className="px-3.5 py-1.5 bg-slate-800 text-slate-200 text-xs font-semibold rounded-lg"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
