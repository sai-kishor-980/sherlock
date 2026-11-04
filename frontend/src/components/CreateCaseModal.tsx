import React, { useState } from "react";
import { FolderPlus, X } from "lucide-react";
import type { PriorityLevel } from "../types/forensic";

interface CreateCaseModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (data: {
    case_name: string;
    investigator_name: string;
    description: string;
    priority: PriorityLevel;
  }) => Promise<void>;
  defaultInvestigator: string;
}

export const CreateCaseModal: React.FC<CreateCaseModalProps> = ({
  isOpen,
  onClose,
  onSubmit,
  defaultInvestigator
}) => {
  const [caseName, setCaseName] = useState("");
  const [investigator, setInvestigator] = useState(defaultInvestigator || "investigator1");
  const [description, setDescription] = useState("");
  const [priority, setPriority] = useState<PriorityLevel>("High");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!caseName.trim()) {
      setError("Please provide a case name or incident reference.");
      return;
    }
    setIsLoading(true);
    setError(null);
    try {
      await onSubmit({
        case_name: caseName.trim(),
        investigator_name: investigator.trim(),
        description: description.trim(),
        priority
      });
      onClose();
    } catch (err: any) {
      setError(err.message || "Failed to create case");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
      <div className="relative w-full max-w-lg bg-dark-900 border border-slate-700/80 rounded-2xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-dark-850">
          <div className="flex items-center gap-2.5">
            <FolderPlus className="w-5 h-5 text-cyan-400" />
            <h2 className="text-lg font-bold font-display text-slate-100">Initialize Forensic Investigation Case</h2>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {error && (
            <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">
              {error}
            </div>
          )}

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wider">
              Case Title / Incident Reference <span className="text-rose-400">*</span>
            </label>
            <input
              type="text"
              required
              placeholder="e.g. Memory Injection Incident & Lateral Movement"
              value={caseName}
              onChange={(e) => setCaseName(e.target.value)}
              className="w-full bg-dark-800 border border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 transition font-sans"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wider">
                Lead Investigator <span className="text-rose-400">*</span>
              </label>
              <input
                type="text"
                required
                value={investigator}
                onChange={(e) => setInvestigator(e.target.value)}
                className="w-full bg-dark-800 border border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 transition font-sans"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wider">
                Priority Level
              </label>
              <select
                value={priority}
                onChange={(e) => setPriority(e.target.value as PriorityLevel)}
                className="w-full bg-dark-800 border border-slate-700/80 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-cyan-500 transition font-sans"
              >
                <option value="Critical">Critical (P1)</option>
                <option value="High">High (P2)</option>
                <option value="Medium">Medium (P3)</option>
                <option value="Low">Low (P4)</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wider">
              Incident Scope / Description
            </label>
            <textarea
              rows={3}
              placeholder="Summary of compromised systems, suspicious telemetry, or investigative scope..."
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full bg-dark-800 border border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 transition font-sans resize-none"
            />
          </div>

          <div className="pt-2 flex justify-end gap-2.5">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 bg-dark-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-lg transition"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isLoading}
              className="px-5 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-bold rounded-lg shadow-lg shadow-cyan-600/25 transition disabled:opacity-50"
            >
              {isLoading ? "Initializing..." : "Create Case File &rarr;"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
