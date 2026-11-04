import React, { useState } from "react";
import { UploadCloud, Lock, Unlock, FileText, CheckCircle2, Shield, AlertCircle, ArrowRight, Clock } from "lucide-react";
import type { Case, Evidence } from "../../types/forensic";

export function formatFileSize(bytes?: number): string {
  if (bytes === undefined || bytes === null || isNaN(bytes)) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function renderStatusBadge(statusStr?: string) {
  const norm = (statusStr || "VALIDATED").toUpperCase();
  if (norm === "EXTRACTED") {
    return (
      <span className="forensic-badge-cyan flex items-center gap-1">
        <CheckCircle2 className="w-3 h-3 text-cyan-400" />
        <span>Extracted &amp; Sealed</span>
      </span>
    );
  }
  if (norm === "VALIDATED" || norm === "SEALED" || norm === "VERIFIED" || norm === "UPLOADED") {
    return (
      <span className="forensic-badge-emerald flex items-center gap-1">
        <CheckCircle2 className="w-3 h-3 text-emerald-400" />
        <span>Sealed &amp; Verified</span>
      </span>
    );
  }
  if (norm === "PENDING_VALIDATION" || norm === "PENDING" || norm === "VALIDATING") {
    return (
      <span className="forensic-badge-amber flex items-center gap-1">
        <Clock className="w-3 h-3 text-amber-400" />
        <span>Pending Validation</span>
      </span>
    );
  }
  return (
    <span className="forensic-badge-rose flex items-center gap-1">
      <AlertCircle className="w-3 h-3 text-rose-400" />
      <span>Integrity Violation</span>
    </span>
  );
}

interface EvidenceVaultWorkstationProps {
  caseItem: Case;
  evidenceList: Evidence[];
  onUploadEvidence: (file: File, category?: string) => Promise<void>;
  onLockVault: () => Promise<void>;
  onUnlockVault: (reason: string) => Promise<void>;
  onProceedToExtraction: () => void;
  isLoading: boolean;
}

export const EvidenceVaultWorkstation: React.FC<EvidenceVaultWorkstationProps> = ({
  caseItem,
  evidenceList,
  onUploadEvidence,
  onLockVault,
  onUnlockVault,
  onProceedToExtraction,
  isLoading: _isLoading
}) => {
  const [dragOver, setDragOver] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string>("auto");
  const [isUploading, setIsUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [unlockReason, setUnlockReason] = useState("");
  const [showUnlockModal, setShowUnlockModal] = useState(false);

  const isVaultLocked = caseItem.vault_status === "LOCKED";

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (isVaultLocked) return;
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setSelectedFile(e.dataTransfer.files[0]);
    }
  };

  const handleUploadSubmit = async () => {
    if (!selectedFile) return;
    setIsUploading(true);
    setUploadError(null);
    try {
      await onUploadEvidence(selectedFile, selectedCategory === "auto" ? undefined : selectedCategory);
      setSelectedFile(null);
      setSelectedCategory("auto");
    } catch (err: any) {
      setUploadError(err.message || "Upload failed");
    } finally {
      setIsUploading(false);
    }
  };

  const handleUnlockSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!unlockReason.trim()) return;
    try {
      await onUnlockVault(unlockReason.trim());
      setShowUnlockModal(false);
      setUnlockReason("");
    } catch (err: any) {
      alert(err.message || "Failed to unlock vault");
    }
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Top Banner */}
      <div className="forensic-card p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold font-display text-white flex items-center gap-2">
            <Shield className="w-5 h-5 text-emerald-400" />
            ISO/IEC 27037 Cryptographic Evidence Vault
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Write-blocked evidentiary enclave with automated SHA-256 multi-pass hashing and HMAC validation
          </p>
        </div>

        <div className="flex items-center gap-3">
          {isVaultLocked ? (
            <div className="flex items-center gap-2">
              <span className="forensic-badge-emerald">
                <Lock className="w-3.5 h-3.5" />
                <span>Vault Sealed (Read-Only)</span>
              </span>
              <button
                onClick={() => setShowUnlockModal(true)}
                className="px-3 py-1.5 bg-dark-800 hover:bg-slate-700 border border-slate-700 text-amber-300 text-xs font-semibold rounded-lg transition flex items-center gap-1.5"
              >
                <Unlock className="w-3.5 h-3.5" />
                <span>Reopen Vault</span>
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <span className="forensic-badge-amber">
                <Unlock className="w-3.5 h-3.5" />
                <span>Vault Open (Ingestion Active)</span>
              </span>
              <button
                onClick={onLockVault}
                disabled={evidenceList.length === 0}
                className="px-3.5 py-1.5 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white text-xs font-bold rounded-lg shadow-lg shadow-emerald-600/20 transition disabled:opacity-50 flex items-center gap-1.5"
              >
                <Lock className="w-3.5 h-3.5" />
                <span>Lock Vault &amp; Seal</span>
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Upload Zone (Only when vault is open) */}
      {!isVaultLocked && (
        <div className="forensic-card p-6">
          <div
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
            className={`border-2 border-dashed rounded-xl p-8 text-center transition cursor-pointer ${
              dragOver ? "border-cyan-400 bg-cyan-950/20" : "border-slate-700 hover:border-slate-600 bg-dark-900/50"
            }`}
            onClick={() => document.getElementById("evidence-file-input")?.click()}
          >
            <input
              id="evidence-file-input"
              type="file"
              className="hidden"
              onChange={(e) => {
                if (e.target.files && e.target.files[0]) {
                  setSelectedFile(e.target.files[0]);
                }
              }}
            />
            <UploadCloud className="w-10 h-10 text-cyan-400 mx-auto mb-2" />
            <h3 className="text-sm font-bold text-slate-200">
              Drag &amp; drop forensic artifact files here, or <span className="text-cyan-400 underline">browse</span>
            </h3>
            <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">
              Supported artifacts: PCAP, PCAPNG, EVTX, E01, RAW Memory Dumps, SAM/SYSTEM Registry Hives, Prefetch (.pf)
            </p>

            {selectedFile && (
              <div className="mt-4 inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyan-950/40 border border-cyan-500/30 text-cyan-300 text-xs font-mono">
                <FileText className="w-4 h-4" />
                <span>{selectedFile.name} ({formatFileSize(selectedFile.size)})</span>
              </div>
            )}
          </div>

          {uploadError && (
            <div className="mt-3 p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
              <AlertCircle className="w-4 h-4" />
              <span>{uploadError}</span>
            </div>
          )}

          {selectedFile && (
            <div className="mt-4 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-dark-900/90 p-3.5 rounded-xl border border-slate-800">
              <div className="flex items-center gap-2">
                <label htmlFor="evidence-domain-select" className="text-xs font-semibold text-slate-400 whitespace-nowrap">
                  Target Domain / Category:
                </label>
                <select
                  id="evidence-domain-select"
                  value={selectedCategory}
                  onChange={(e) => setSelectedCategory(e.target.value)}
                  className="bg-dark-800 border border-slate-700 text-slate-200 text-xs rounded-lg px-3 py-1.5 focus:border-cyan-500 focus:outline-none"
                >
                  <option value="auto">Auto-detect from Extension</option>
                  <option value="Volatile Memory">Volatile Memory (RAM dump / .raw / .vmem)</option>
                  <option value="Network PCAP">Network PCAP (.pcap / .pcapng)</option>
                  <option value="Filesystem Disk">Filesystem Disk Image (.E01 / .dd / .raw)</option>
                  <option value="Windows Event Logs">Windows Event Logs (.evtx)</option>
                  <option value="Windows Registry Hive">Windows Registry Hive (SAM / SYSTEM / SOFTWARE)</option>
                </select>
              </div>

              <button
                onClick={handleUploadSubmit}
                disabled={isUploading}
                className="px-5 py-2 bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs rounded-lg transition disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {isUploading ? "Hashing &amp; Ingesting..." : "Ingest into Sealed Vault &rarr;"}
              </button>
            </div>
          )}
        </div>
      )}

      {/* Ingested Evidence Table */}
      <div className="forensic-card overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-800 bg-dark-850 flex items-center justify-between">
          <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
            <span>Preserved Evidence Artifacts</span>
            <span className="text-xs px-2 py-0.5 rounded-full bg-dark-900 border border-slate-700 text-cyan-400 font-mono">
              {evidenceList.length} Items
            </span>
          </h3>

          <button
            onClick={onProceedToExtraction}
            disabled={evidenceList.length === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-dark-800 hover:bg-slate-700 border border-slate-700 text-xs font-semibold text-slate-200 rounded-lg transition disabled:opacity-40"
          >
            <span>Proceed to Extraction</span>
            <ArrowRight className="w-3.5 h-3.5 text-cyan-400" />
          </button>
        </div>

        {evidenceList.length === 0 ? (
          <div className="p-8 text-center text-slate-500 text-xs">
            No evidence artifacts ingested yet. Upload files to calculate cryptographic signatures and begin.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-dark-900/80 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3">Artifact Filename</th>
                  <th className="px-4 py-3">Domain / Type</th>
                  <th className="px-4 py-3">File Size</th>
                  <th className="px-4 py-3">SHA-256 Digest</th>
                  <th className="px-4 py-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {evidenceList.map((ev) => {
                  const displayName = ev.name || (ev as any).original_filename || (ev as any).Filename || "Forensic Artifact";
                  const displaySize = formatFileSize(ev.file_size ?? (ev as any).size ?? (ev as any).FileSize);
                  const displayHash = ev.sha256_hash || (ev as any).file_hash || (ev as any).FileHash || "Hash Calculation Pending";
                  const displayStatus = ev.status || (ev as any).Status || "VALIDATED";

                  return (
                    <tr key={ev.evidence_id || (ev as any).EvidenceID || displayName} className="hover:bg-dark-800/40 transition">
                      <td className="px-4 py-3 font-semibold text-slate-100 flex items-center gap-2">
                        <FileText className="w-4 h-4 text-cyan-400 shrink-0" />
                        <span className="truncate max-w-xs" title={displayName}>{displayName}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="font-mono px-2 py-0.5 rounded bg-dark-900 text-slate-300 border border-slate-800">
                          {ev.type || (ev as any).Category || "Forensic Stream"}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-slate-400 font-mono">
                        {displaySize}
                      </td>
                      <td className="px-4 py-3 font-mono text-[11px] text-slate-400 truncate max-w-xs" title={displayHash}>
                        {displayHash}
                      </td>
                      <td className="px-4 py-3">
                        {renderStatusBadge(displayStatus)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Unlock Reason Modal */}
      {showUnlockModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
          <div className="w-full max-w-md bg-dark-900 border border-slate-700 rounded-xl p-5 shadow-2xl">
            <h3 className="text-sm font-bold text-slate-100 mb-1">Reopen Evidence Vault</h3>
            <p className="text-xs text-slate-400 mb-3">
              Mandatory audit requirement: provide an investigative rationale for reopening the vault (e.g. INSUFFICIENT_EVIDENCE flagged by domain agents).
            </p>
            <form onSubmit={handleUnlockSubmit} className="space-y-3">
              <textarea
                required
                rows={3}
                placeholder="Rationale for reopening vault..."
                value={unlockReason}
                onChange={(e) => setUnlockReason(e.target.value)}
                className="w-full bg-dark-800 border border-slate-700 rounded-lg p-2.5 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
              />
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowUnlockModal(false)}
                  className="px-3 py-1.5 bg-dark-800 text-slate-300 text-xs rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3.5 py-1.5 bg-amber-600 hover:bg-amber-500 text-white font-bold text-xs rounded-lg transition"
                >
                  Confirm Reopen
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
