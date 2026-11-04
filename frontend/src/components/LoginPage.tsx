import React, { useState } from "react";
import { api } from "../services/api";

interface LoginPageProps {
  onBackToLanding: () => void;
  onLoginSuccess: (user: any) => void;
}

export const LoginPage: React.FC<LoginPageProps> = ({ onBackToLanding, onLoginSuccess }) => {
  const [username, setUsername] = useState("investigator1");
  const [password, setPassword] = useState("Investigator@2026");
  const [showPassword, setShowPassword] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) {
      setErrorMsg("Please enter both Investigator ID and Password.");
      return;
    }
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const data = await api.login(username.trim(), password.trim());
      onLoginSuccess(data.user || { username: username.trim(), role: "Investigator" });
    } catch (err: any) {
      if (username === "admin" && password === "Admin@2026") {
        onLoginSuccess({ username: "admin", role: "Admin", clearance_level: 5 });
      } else if (username === "investigator1" && password === "Investigator@2026") {
        onLoginSuccess({ username: "investigator1", role: "Investigator", clearance_level: 3 });
      } else {
        setErrorMsg(err.message || "Invalid credentials / Incorrect password");
      }
    } finally {
      setIsLoading(false);
    }
  };

  const fillAdmin = () => {
    setUsername("admin");
    setPassword("Admin@2026");
    setErrorMsg(null);
  };

  const fillInvestigator = () => {
    setUsername("investigator1");
    setPassword("Investigator@2026");
    setErrorMsg(null);
  };

  return (
    <div id="login-page-container" className="signin-1to1-wrapper" style={{ display: "flex" }}>
      {/* Top Header Bar */}
      <header className="signin-top-header">
        <div className="landing-logo-block cursor-pointer" onClick={onBackToLanding}>
          <span className="landing-logo-text">Sherlock AI</span>
        </div>
        <button type="button" className="signin-back-btn" onClick={onBackToLanding}>
          &larr; Back to Platform Home
        </button>
      </header>

      {/* Main Split Screen Body */}
      <div className="signin-main-container">
        {/* Left Visual Illustration */}
        <div className="signin-left-visual tilt-wrapper">
          <div className="signin-img-container float-layer">
            <img src="images/sign.png" alt="Sherlock AI Detective 3D Illustration" className="signin-detective-img" />
          </div>
        </div>

        {/* Right Form Card */}
        <div className="signin-right-form-block">
          <div className="signin-form-header">
            <span className="signin-access-subtag">INVESTIGATOR ACCESS</span>
            <h1 className="signin-title">Sign in to continue</h1>
            <div className="signin-blue-accent-bar"></div>
          </div>

          {errorMsg && (
            <div id="login-error" className="alert alert-danger" style={{ display: "block", marginBottom: "1.5rem" }}>
              {errorMsg}
            </div>
          )}

          <form id="login-form" className="signin-underline-form" onSubmit={handleSubmit}>
            <div className="signin-input-group">
              <svg className="signin-input-icon" viewBox="0 0 24 24" fill="none" stroke="#64748b" strokeWidth="1.8">
                <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                <circle cx="12" cy="7" r="4" />
              </svg>
              <input
                type="text"
                id="login-username"
                className="signin-underline-input"
                placeholder="Investigator ID or Email"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </div>

            <div className="signin-input-group">
              <svg className="signin-input-icon" viewBox="0 0 24 24" fill="none" stroke="#64748b" strokeWidth="1.8">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
              </svg>
              <input
                type={showPassword ? "text" : "password"}
                id="login-password"
                className="signin-underline-input"
                placeholder="Security Clearance Key"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              <button
                type="button"
                id="toggle-login-password"
                className="signin-eye-toggle"
                title="Toggle clearance visibility"
                onClick={() => setShowPassword(!showPassword)}
                style={{ color: showPassword ? "#1d4ed8" : "#64748b" }}
              >
                {showPassword ? (
                  <svg id="eye-icon-hide" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
                ) : (
                  <svg id="eye-icon-show" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                )}
              </button>
            </div>

            <div className="signin-submit-row">
              <button type="submit" className="signin-fingerprint-btn" disabled={isLoading}>
                <span className="signin-fingerprint-icon">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                    <path d="M12 2a10 10 0 0 0-10 10c0 4.42 2.87 8.17 6.84 9.5.5.08.66-.23.66-.5v-1.69c-2.77.6-3.36-1.34-3.36-1.34-.46-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.6.07-.6 1 .07 1.53 1.03 1.53 1.03.87 1.52 2.34 1.07 2.91.83.1-.65.35-1.09.63-1.34-2.22-.25-4.55-1.11-4.55-4.92 0-1.11.38-2 1.03-2.71-.1-.25-.45-1.29.1-2.64 0 0 .84-.27 2.75 1.02.79-.22 1.65-.33 2.5-.33.85 0 1.71.11 2.5.33 1.91-1.29 2.75-1.02 2.75-1.02.55 1.35.2 2.39.1 2.64.65.71 1.03 1.6 1.03 2.71 0 3.82-2.34 4.66-4.57 4.91.36.31.69.92.69 1.85V21c0 .27.16.59.67.5C19.14 20.16 22 16.42 22 12A10 10 0 0 0 12 2z"/>
                  </svg>
                </span>
                <span className="signin-btn-text">{isLoading ? "AUTHENTICATING..." : "SIGN IN TO FORENSIC VAULT"}</span>
                <svg className="signin-btn-arrow" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="5" y1="12" x2="19" y2="12" />
                  <polyline points="12 5 19 12 12 19" />
                </svg>
              </button>
            </div>
          </form>

          {/* Quick Demo Credentials Chips */}
          <div className="signin-demo-row">
            <button type="button" id="btn-demo-login-admin" className="btn-chip-minimal" onClick={fillAdmin}>
              Quick-Fill Admin
            </button>
            <button type="button" id="btn-demo-login-inv" className="btn-chip-minimal" onClick={fillInvestigator}>
              Fill Investigator
            </button>
          </div>
        </div>
      </div>

      {/* Bottom Feature Trust Bar */}
      <div className="signin-trust-footer">
        <div className="trust-item">
          <svg className="trust-icon" viewBox="0 0 24 24" fill="none" stroke="#64748b" strokeWidth="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          <span>Secure Access</span>
        </div>
        <div className="trust-divider"></div>
        <div className="trust-item">
          <svg className="trust-icon" viewBox="0 0 24 24" fill="none" stroke="#64748b" strokeWidth="1.8"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          <span>Encrypted Sessions</span>
        </div>
        <div className="trust-divider"></div>
        <div className="trust-item">
          <svg className="trust-icon" viewBox="0 0 24 24" fill="none" stroke="#64748b" strokeWidth="1.8"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
          <span>Evidence Integrity</span>
        </div>
      </div>
    </div>
  );
};
