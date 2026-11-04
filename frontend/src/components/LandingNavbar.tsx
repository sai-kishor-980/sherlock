import React from "react";
import type { InferenceTierStatus } from "../types/forensic";

interface LandingNavbarProps {
  onOpenLogin: () => void;
  status: InferenceTierStatus | null;
  onOpenAISettings: () => void;
}

export const LandingNavbar: React.FC<LandingNavbarProps> = ({
  onOpenLogin,
  status,
  onOpenAISettings
}) => {
  const scrollTo = (id: string) => {
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ behavior: "smooth" });
    }
  };

  const isAIActive = status?.analysis_mode === "AI-assisted";

  return (
    <header id="landing-navbar" className="landing-header" style={{ display: "flex" }}>
      <div className="landing-nav-container">
        <div className="landing-logo-block cursor-pointer" onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}>
          <span className="landing-logo-text">Sherlock AI</span>
        </div>

        <nav className="landing-nav-links">
          <button type="button" className="nav-tab-btn active" onClick={() => scrollTo("landing-hero")}>Home</button>
          <button type="button" className="nav-tab-btn" onClick={() => scrollTo("landing-preservation")}>Preservation Vault</button>
          <button type="button" className="nav-tab-btn" onClick={() => scrollTo("landing-multi-agent")}>5 Domain Agents</button>
          <button type="button" className="nav-tab-btn" onClick={() => scrollTo("landing-colab-bridge")}>Colab GPU Bridge</button>
          <button type="button" className="nav-tab-btn" onClick={() => scrollTo("landing-architecture")}>6 Pipeline Zones</button>
          <button type="button" className="nav-tab-btn" onClick={() => scrollTo("landing-custody")}>Court Report</button>
        </nav>

        <div className="landing-nav-actions">
          {/* 3-Tier Status Indicator */}
          <button
            type="button"
            onClick={onOpenAISettings}
            className={`hidden md:inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold border transition cursor-pointer ${
              isAIActive
                ? "bg-cyan-500/10 border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20"
                : "bg-amber-500/10 border-amber-500/30 text-amber-400 hover:bg-amber-500/20"
            }`}
            title="Configure GPU inference service"
          >
            <span className={`w-2 h-2 rounded-full ${isAIActive ? "bg-cyan-400 animate-pulse" : "bg-amber-400"}`} />
            <span>{status?.active_tier || "Tier 3: Rule-based Engine"}</span>
          </button>

          <button type="button" className="btn-text-link" id="btn-nav-login" onClick={onOpenLogin}>
            Sign in
          </button>
          <button type="button" className="btn btn-royal-blue" id="btn-nav-launch" onClick={onOpenLogin}>
            Explore
          </button>
        </div>
      </div>
    </header>
  );
};
