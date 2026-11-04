import React, { useState } from "react";
import type { InferenceTierStatus } from "../types/forensic";

export type WorkspaceTab = "home" | "cases";

interface WorkspaceHeaderProps {
  user: any;
  activeTab: WorkspaceTab;
  onTabChange: (tab: WorkspaceTab) => void;
  onLogout: () => void;
  onShowLanding: () => void;
  onOpenAISettings: () => void;
  tierStatus: InferenceTierStatus | null;
}

export const WorkspaceHeader: React.FC<WorkspaceHeaderProps> = ({
  user,
  activeTab,
  onTabChange,
  onLogout,
  onShowLanding,
  onOpenAISettings,
  tierStatus
}) => {
  const [collapsed, setCollapsed] = useState(false);

  const isAIActive = tierStatus?.analysis_mode === "AI-assisted";

  return (
    <header
      id="workspace-header"
      className={`vertical-sidebar-header ${collapsed ? "collapsed" : ""}`}
      style={{ display: "flex" }}
    >
      {/* Top Sherlock AI Brand Header */}
      <div
        className="sidebar-brand-header cursor-pointer text-left"
        style={{ padding: "1.1rem 1.25rem 0.6rem" }}
        onClick={onShowLanding}
        title="Return to Public Landing Page"
      >
        <span
          className="sidebar-brand-title font-extrabold whitespace-nowrap inline-block"
          style={{ fontSize: "1.15rem", color: "#0f172a", fontFamily: "'Outfit', sans-serif" }}
        >
          Sherlock <span style={{ color: "#1d4ed8" }}>AI</span>
        </span>
      </div>

      {/* Investigator Profile Card Badge */}
      <div
        className="sidebar-profile-card cursor-pointer"
        id="sidebar-profile-toggle-trigger"
        onClick={() => setCollapsed(!collapsed)}
        title="Toggle Sidebar"
      >
        <div className="sidebar-profile-avatar-box">
          <img src="images/sign.png" alt="Investigator Profile" className="sidebar-profile-img" />
        </div>
        {!collapsed && (
          <div className="sidebar-profile-info">
            <span id="user-display-name" className="sidebar-profile-name">
              {user?.username || "Investigator 01"}
            </span>
            <span id="user-role-badge" className="sidebar-profile-role">
              {(user?.role || "Investigator").toUpperCase()}
            </span>
          </div>
        )}
      </div>

      {/* 3-Tier Hardware Inference Status Badge */}
      <div style={{ padding: "0 1rem 0.5rem" }}>
        <button
          type="button"
          onClick={onOpenAISettings}
          className={`w-full py-1.5 px-2 rounded-lg text-[11px] font-semibold border flex items-center justify-center gap-1.5 transition cursor-pointer ${isAIActive
              ? "bg-cyan-500/10 border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20"
              : "bg-amber-500/10 border-amber-500/30 text-amber-400 hover:bg-amber-500/20"
            }`}
          title="Click to configure AI inference service"
        >
          <span className={`w-2 h-2 rounded-full ${isAIActive ? "bg-cyan-400 animate-pulse" : "bg-amber-400"}`} />
          {!collapsed && (
            <span className="truncate">{tierStatus?.active_tier || "Tier 3: Rule-based Engine"}</span>
          )}
        </button>
      </div>

      {/* Vertical Navigation Container */}
      <div className="sidebar-nav-container">
        <nav className="vertical-nav">
          <div className="sidebar-nav-group-label">{!collapsed ? "INVESTIGATION" : "•"}</div>

          <button
            className={`nav-tab ${activeTab === "home" ? "active" : ""}`}
            onClick={() => onTabChange("home")}
            title="Command Center"
          >
            <svg className="svg-icon" viewBox="0 0 24 24"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" /><polyline points="9 22 9 12 15 12 15 22" /></svg>
            {!collapsed && <span className="nav-tab-label">Command Center</span>}
          </button>

          <button
            className={`nav-tab ${activeTab === "cases" ? "active" : ""}`}
            onClick={() => onTabChange("cases")}
            title="My Cases"
          >
            <svg className="svg-icon" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="9" rx="1" /><rect x="14" y="3" width="7" height="5" rx="1" /><rect x="14" y="12" width="7" height="9" rx="1" /><rect x="3" y="16" width="7" height="5" rx="1" /></svg>
            {!collapsed && <span className="nav-tab-label">My Cases</span>}
          </button>
        </nav>
      </div>

      {/* Sidebar Bottom Footer: Sign Out & Ambient Fingerprint Watermark (hi8.png) */}
      <div className="sidebar-footer-minimalist">
        <button id="btn-logout" className="btn-signout-minimalist" onClick={onLogout} title="Sign Out of Sherlock AI">
          <svg className="svg-icon svg-icon-sm" viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" /><polyline points="16 17 21 12 16 7" /><line x1="21" y1="12" x2="9" y2="12" /></svg>
          {!collapsed && <span className="nav-tab-label">Sign Out</span>}
        </button>
        {/* Fingerprint Watermark */}
        <img src="images/hi8.png" alt="Fingerprint Watermark" className="sidebar-fp-watermark" />
      </div>
    </header>
  );
};
