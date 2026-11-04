import React, { useState } from "react";
import { Cpu, Server, ShieldCheck, CheckCircle2, XCircle, RefreshCw, X } from "lucide-react";
import type { InferenceTierStatus } from "../types/forensic";
import { api } from "../services/api";

interface AISettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  status: InferenceTierStatus | null;
  onStatusUpdated: () => void;
}

export const AISettingsModal: React.FC<AISettingsModalProps> = ({
  isOpen,
  onClose,
  status,
  onStatusUpdated
}) => {
  const [remoteUrl, setRemoteUrl] = useState(status?.remote_service?.url || "");
  const [isUpdating, setIsUpdating] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; msg: string } | null>(null);

  if (!isOpen) return null;

  const handleSaveUrl = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsUpdating(true);
    setTestResult(null);
    try {
      await api.setRemoteInferenceUrl(remoteUrl.trim());
      onStatusUpdated();
      setTestResult({ ok: true, msg: "Inference endpoint saved and verified successfully!" });
    } catch (err: any) {
      setTestResult({ ok: false, msg: err.message || "Failed to connect to endpoint" });
    } finally {
      setIsUpdating(false);
    }
  };

  const isLocalActive = status?.active_tier?.includes("Tier 1");
  const isRemoteActive = status?.active_tier?.includes("Tier 2");
  const isRuleActive = status?.active_tier?.includes("Tier 3");

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-fadeIn">
      <div className="relative w-full max-w-2xl bg-dark-900 border border-slate-700/80 rounded-2xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-dark-850">
          <div className="flex items-center gap-2.5">
            <Cpu className="w-5 h-5 text-cyan-400" />
            <h2 className="text-lg font-bold font-display text-slate-100">AI Inference Service &amp; Hardware Diagnostics</h2>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-6 max-h-[80vh] overflow-y-auto">
          {/* Active Hierarchy Summary Banner */}
          <div className="p-4 rounded-xl bg-dark-800/80 border border-slate-700/60 flex items-center justify-between">
            <div>
              <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">Current Execution Mode</span>
              <div className="text-base font-bold text-slate-100 mt-0.5 flex items-center gap-2">
                <span className={`w-2.5 h-2.5 rounded-full ${status?.is_connected ? "bg-emerald-400 animate-pulse" : "bg-amber-400"}`} />
                {status?.active_tier || "Tier 3: Rule-based Engine"}
              </div>
              <span className="text-xs text-slate-400">Device: {status?.active_device}</span>
            </div>
            <div className={`px-3 py-1.5 rounded-lg text-xs font-bold uppercase tracking-wider border ${
              status?.is_connected
                ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                : "bg-amber-500/10 text-amber-400 border-amber-500/30"
            }`}>
              {status?.service_status || "Unavailable"}
            </div>
          </div>

          {/* Tier 1 Card: Local CUDA GPU */}
          <div className={`p-4 rounded-xl border transition ${
            isLocalActive ? "border-cyan-500/50 bg-cyan-950/20 shadow-lg" : "border-slate-800 bg-dark-850"
          }`}>
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-2.5">
                <div className={`p-2 rounded-lg ${status?.local_hardware.gpu_eligible ? "bg-emerald-500/15 text-emerald-400" : "bg-slate-800 text-slate-400"}`}>
                  <Cpu className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                    Tier 1: Local Onboard CUDA GPU
                    {isLocalActive && <span className="text-[10px] bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 px-2 py-0.5 rounded font-mono uppercase">Active</span>}
                  </h3>
                  <p className="text-xs text-slate-400">Direct in-memory Qwen 4-bit neural inference on host hardware</p>
                </div>
              </div>
              <span className={`text-xs font-semibold px-2 py-0.5 rounded ${
                status?.local_hardware.gpu_eligible ? "text-emerald-400 bg-emerald-500/10" : "text-slate-400 bg-slate-800"
              }`}>
                {status?.local_hardware.cuda_available ? (status?.local_hardware.gpu_eligible ? "Eligible (>=6GB)" : "VRAM < 6GB") : "No CUDA GPU"}
              </span>
            </div>

            <div className="mt-3 grid grid-cols-2 gap-2 text-xs font-mono bg-dark-900/60 p-2.5 rounded-lg border border-slate-800/80">
              <div>
                <span className="text-slate-500">Device: </span>
                <span className="text-slate-300">{status?.local_hardware.device_name || "None detected"}</span>
              </div>
              <div>
                <span className="text-slate-500">VRAM: </span>
                <span className="text-slate-300">{status?.local_hardware.total_vram_gb ? `${status.local_hardware.total_vram_gb} GB` : "0.0 GB"}</span>
              </div>
            </div>
            <p className="mt-2 text-[11px] text-slate-400 italic">
              Note: Requires minimum 6.0 GB VRAM to load 7B 4-bit weights without CUDA Out-Of-Memory errors.
            </p>
          </div>

          {/* Tier 2 Card: Remote AI GPU Service */}
          <div className={`p-4 rounded-xl border transition ${
            isRemoteActive ? "border-cyan-500/50 bg-cyan-950/20 shadow-lg" : "border-slate-800 bg-dark-850"
          }`}>
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-2.5">
                <div className={`p-2 rounded-lg ${status?.remote_service.reachable ? "bg-cyan-500/15 text-cyan-400" : "bg-slate-800 text-slate-400"}`}>
                  <Server className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                    Tier 2: Remote GPU Inference Bridge
                    {isRemoteActive && <span className="text-[10px] bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 px-2 py-0.5 rounded font-mono uppercase">Active</span>}
                  </h3>
                  <p className="text-xs text-slate-400">High-throughput accelerated endpoint (Tesla T4 / Colab / Dedicated Node)</p>
                </div>
              </div>
              <span className={`text-xs font-semibold px-2 py-0.5 rounded ${
                status?.remote_service.reachable ? "text-emerald-400 bg-emerald-500/10" : "text-amber-400 bg-amber-500/10"
              }`}>
                {status?.remote_service.reachable ? "Connected" : "Disconnected"}
              </span>
            </div>

            <form onSubmit={handleSaveUrl} className="mt-3 space-y-2">
              <label className="text-xs font-medium text-slate-300 block">Endpoint URL</label>
              <div className="flex gap-2">
                <input
                  type="url"
                  placeholder="https://...trycloudflare.com or http://localhost:8000"
                  value={remoteUrl}
                  onChange={(e) => setRemoteUrl(e.target.value)}
                  className="flex-1 bg-dark-900 border border-slate-700/80 rounded-lg px-3 py-1.5 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 transition font-mono"
                />
                <button
                  type="submit"
                  disabled={isUpdating}
                  className="px-3.5 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs rounded-lg transition flex items-center gap-1.5 disabled:opacity-50"
                >
                  {isUpdating ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : "Save &amp; Test"}
                </button>
              </div>
            </form>

            {testResult && (
              <div className={`mt-2 p-2 rounded-lg text-xs flex items-center gap-2 ${
                testResult.ok ? "bg-emerald-500/10 text-emerald-300 border border-emerald-500/30" : "bg-rose-500/10 text-rose-300 border border-rose-500/30"
              }`}>
                {testResult.ok ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <XCircle className="w-4 h-4 text-rose-400" />}
                {testResult.msg}
              </div>
            )}
          </div>

          {/* Tier 3 Card: Deterministic Heuristic Engine */}
          <div className={`p-4 rounded-xl border transition ${
            isRuleActive ? "border-amber-500/50 bg-amber-950/15" : "border-slate-800 bg-dark-850"
          }`}>
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-lg bg-amber-500/15 text-amber-400">
                <ShieldCheck className="w-5 h-5" />
              </div>
              <div className="flex-1">
                <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                  Tier 3: Deterministic Rule-Based Forensic Engine
                  {isRuleActive && <span className="text-[10px] bg-amber-500/20 text-amber-300 border border-amber-500/40 px-2 py-0.5 rounded font-mono uppercase">Active Fallback</span>}
                </h3>
                <p className="text-xs text-slate-400">Guaranteed sovereign offline baseline grounded in NIST SP 800-86 and MITRE ATT&amp;CK</p>
              </div>
              <span className="text-xs font-semibold px-2 py-0.5 rounded text-emerald-400 bg-emerald-500/10">Always Available</span>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 border-t border-slate-800 bg-dark-850 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition"
          >
            Close Diagnostics
          </button>
        </div>
      </div>
    </div>
  );
};
