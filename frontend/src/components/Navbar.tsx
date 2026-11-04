import React from "react";
import { Shield, ChevronRight, User, LogOut, Settings2 } from "lucide-react";
import type { InferenceTierStatus, Case } from "../types/forensic";

interface NavbarProps {
  status: InferenceTierStatus | null;
  onOpenAISettings: () => void;
  activeCase: Case | null;
  onBackToCases: () => void;
  user: any;
  onLogout: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  status,
  onOpenAISettings,
  activeCase,
  onBackToCases,
  user,
  onLogout
}) => {
  const isAiConnected = status?.is_connected;

  return (
    <header className="sticky top-0 z-40 w-full bg-dark-900/95 border-b border-slate-800/80 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Left: Brand & Case Breadcrumb */}
        <div className="flex items-center gap-3">
          <div 
            onClick={onBackToCases} 
            className="flex items-center gap-2.5 cursor-pointer group"
          >
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 group-hover:scale-105 transition">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <span className="text-lg font-bold font-display tracking-tight text-white flex items-center gap-1.5">
                Sherlock <span className="text-cyan-400">AI</span>
              </span>
              <span className="hidden sm:block text-[10px] text-slate-400 tracking-wider uppercase font-semibold">
                Autonomous Forensic Lab
              </span>
            </div>
          </div>

          {activeCase && (
            <div className="hidden md:flex items-center gap-2 pl-4 border-l border-slate-800 text-xs">
              <button 
                onClick={onBackToCases}
                className="text-slate-400 hover:text-slate-200 transition"
              >
                Cases
              </button>
              <ChevronRight className="w-3.5 h-3.5 text-slate-600" />
              <span className="font-semibold text-slate-200 truncate max-w-[200px]" title={activeCase.case_name}>
                {activeCase.case_name}
              </span>
              <span className="font-mono text-[11px] px-1.5 py-0.5 rounded bg-dark-800 text-cyan-400 border border-slate-700">
                {activeCase.case_id}
              </span>
            </div>
          )}
        </div>

        {/* Right: Persistent 3-Tier AI Status Badge & User Info */}
        <div className="flex items-center gap-3">
          {/* 3-Tier AI Inference Status Pill */}
          <button
            onClick={onOpenAISettings}
            className={`group relative flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium border transition-all ${
              isAiConnected
                ? "bg-emerald-950/30 text-emerald-300 border-emerald-500/30 hover:border-emerald-400 hover:bg-emerald-900/40"
                : "bg-amber-950/30 text-amber-300 border-amber-500/30 hover:border-amber-400 hover:bg-amber-900/40"
            }`}
            title="Click to inspect GPU hardware diagnostics and configure endpoints"
          >
            <span className="relative flex h-2 w-2">
              <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                isAiConnected ? "bg-emerald-400" : "bg-amber-400"
              }`} />
              <span className={`relative inline-flex rounded-full h-2 w-2 ${
                isAiConnected ? "bg-emerald-500" : "bg-amber-500"
              }`} />
            </span>
            <span className="font-semibold">
              {isAiConnected ? "AI Inference: Connected" : "Model Service: Unavailable"}
            </span>
            <span className="hidden lg:inline text-[10px] px-1.5 py-0.5 rounded bg-dark-900/80 border border-slate-700/60 font-mono text-slate-300">
              {status?.active_tier?.split(":")[0] || "Tier 3"}
            </span>
            <Settings2 className="w-3.5 h-3.5 text-slate-400 group-hover:text-slate-200 transition" />
          </button>

          {/* User Profile Pill */}
          <div className="hidden sm:flex items-center gap-2 pl-2 border-l border-slate-800 text-xs">
            <div className="w-7 h-7 rounded-lg bg-dark-800 border border-slate-700 flex items-center justify-center text-slate-300 font-bold">
              <User className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="flex flex-col text-left">
              <span className="font-semibold text-slate-200 text-[11px] leading-tight">
                {user?.username || "Investigator"}
              </span>
              <span className="text-[10px] text-slate-500 uppercase font-mono tracking-wider">
                {user?.role || "Examiner"}
              </span>
            </div>
          </div>

          {/* Sign Out Button */}
          <button
            onClick={onLogout}
            className="p-2 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-rose-950/30 border border-transparent hover:border-rose-500/30 transition"
            title="Sign Out"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  );
};
