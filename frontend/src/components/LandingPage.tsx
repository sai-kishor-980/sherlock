import React from "react";

interface LandingPageProps {
  onOpenLogin: () => void;
}

export const LandingPage: React.FC<LandingPageProps> = ({ onOpenLogin }) => {
  return (
  <div id="landing-page-container" className="landing-wrapper">

    {/*  1. HERO SECTION  */}
    <section id="landing-hero" className="landing-hero-section">
      <div className="hero-content-grid">
        <div className="hero-left-text">
          <div className="hero-subtag" style={{ display: "inline-flex", alignItems: "center", gap: "0.5rem", background: "rgba(37, 99, 235, 0.1)", border: "1px solid rgba(37, 99, 235, 0.25)", color: "#2563eb", padding: "4px 12px", borderRadius: "9999px", fontWeight: "700", fontSize: "0.76rem", letterSpacing: "0.04em", marginBottom: "1.25rem" }}>
            <span>🛡️</span> AGENTIC SHERLOCK AI • TEAM G1266
          </div>

          <h1 className="hero-main-title" style={{ fontSize: "2.85rem", lineHeight: "1.15", fontWeight: "800", color: "#0f172a", marginBottom: "1rem" }}>
            A Hierarchical Cognitive <br />
            <span className="blue-highlight" style={{ color: "#2563eb" }}>Multi-Agent Framework</span><br />
            for Cyber Forensics.
          </h1>

          <p className="hero-description" style={{ fontSize: "1.05rem", lineHeight: "1.55", color: "#475569", maxWidth: "580px", marginBottom: "1.5rem" }}>
            Automated cyber attack reconstruction and cross-domain digital forensics. Powered by fine-tuned <strong>Qwen 3 / Qwen 2.5 LoRA</strong> intelligence, ISO/IEC 27037 cryptographic chain of custody, and human-in-the-loop validation.
          </p>

          {/*  Core Research Question Banner  */}
          <div style={{ background: "#f8fafc", borderLeft: "3px solid #2563eb", padding: "0.75rem 1rem", borderRadius: "0 6px 6px 0", marginBottom: "1.75rem", fontSize: "0.86rem", color: "#334155", fontStyle: "italic" }}>
            "Can AI assist human investigators in correlating scattered digital footprints and reconstructing the cyber attack sequence automatically?"
          </div>

          <div className="hero-cta-group" style={{ display: "flex", gap: "0.85rem", alignItems: "center", marginBottom: "1.5rem" }}>
            <button type="button" className="btn-royal-blue-hero" onClick={onOpenLogin}  style={{ padding: "0.75rem 1.6rem", fontWeight: "700", fontSize: "0.95rem", borderRadius: "8px" }}>
              Enter Forensic Lab &rarr;
            </button>
            <button type="button" className="btn-outline-hero" id="btn-hero-explore"  style={{ padding: "0.75rem 1.4rem", fontWeight: "600", fontSize: "0.95rem", borderRadius: "8px" }}>
              Explore 5 Agents
            </button>
          </div>

          {/*  Project Credentials Bar  */}
          <div style={{ display: "flex", flexWrap: "wrap", gap: "1rem", fontSize: "0.76rem", color: "#64748b", borderTop: "1px solid #e2e8f0", paddingTop: "1rem" }}>
            <div><strong>Mentor:</strong> Forensic AI Laboratory</div>
            <div>•</div>
            <div><strong>Architecture:</strong> Autonomous Multi-Agent Cognitive Framework</div>
            <div>•</div>
            <div><strong>Model:</strong> Qwen QLoRA Fine-Tuned</div>
          </div>
        </div>

        <div className="hero-right-visual">
          <div className="hero-landing-image-container">
            <img src="images/frontpage_img_clean.png" alt="Sherlock AI Multi-Agent Cognitive Framework" className="hero-landing-img" />
          </div>
        </div>
      </div>

      {/*  TRUST & BADGES BAR  */}
      <div className="landing-trust-bar">
        <span className="trust-label">ISO/IEC 27037 Standard Digital Forensics &amp; Cloud GPU Enclave</span>
        <div className="trust-badges-row">
          <span className="trust-badge">SHA-256 HMAC Sealed</span>
          <span className="trust-badge">5 Specialized Qwen Agents</span>
          <span className="trust-badge">Structured State (SIS)</span>
          <span className="trust-badge">Google Colab GPU Bridge</span>
          <span className="trust-badge">Air-Gapped Sovereign Ready</span>
        </div>
      </div>
    </section>

    {/*  2. LAYER 1 PRESERVATION VAULT SHOWCASE  */}
    <section id="landing-preservation" className="landing-feature-section preservation-landing-section">
      <div className="preservation-hero-grid">
        <div className="preservation-left-text">
          <div className="hero-subtag">- ZONE 1: EVIDENCE PRESERVATION</div>

          <h2 className="preservation-main-title">
            Cryptographic evidence<br />
            preservation <span className="blue-highlight">vault.</span>
          </h2>

          <p className="preservation-description">
            Real-time SHA-256 multi-pass hashing, write-blocked read-only evidentiary enclave, and verifiable chain-of-custody logging for legal court admissibility.
          </p>
        </div>

        <div className="preservation-right-visual">
          <div className="preservation-p1i1-container">
            <img src="images/p1i1.png" alt="Cryptographic Evidence Preservation Vault 3D" className="preservation-p1i1-img" />
          </div>
        </div>
      </div>

      {/*  BOTTOM 3-CARD FEATURE ROW  */}
      <div className="features-grid-3 preservation-cards-row">
        {/*  Card 1  */}
        <div className="feature-card-glass preservation-card">
          <div className="card-top-icon royal-blue">
            <svg className="svg-icon" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="10" y1="13" x2="14" y2="13"/><line x1="10" y1="17" x2="14" y2="17"/></svg>
          </div>
          <div className="card-visual-illustration">
            <img src="images/p1i2.png" alt="Multi-Pass Hash Digests" className="card-illus-img" />
          </div>
          <h3>SHA-256 Cryptographic Seal</h3>
          <p>Calculates streaming SHA-256 and SHA-1 digests at upload boundary with immutable chain of custody stamps.</p>
          <span className="card-arrow-link">&rarr;</span>
        </div>

        {/*  Card 2  */}
        <div className="feature-card-glass preservation-card">
          <div className="card-top-icon royal-blue">
            <svg className="svg-icon" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          </div>
          <div className="card-visual-illustration">
            <img src="images/p1i3.png" alt="Write-Blocked Vault" className="card-illus-img" />
          </div>
          <h3>Write-Blocked Read-Only Enclave</h3>
          <p>Read-only file permissions prevent inadvertent evidence tampering, preserving pristine bit-stream forensic images.</p>
          <span className="card-arrow-link">&rarr;</span>
        </div>

        {/*  Card 3  */}
        <div className="feature-card-glass preservation-card">
          <div className="card-top-icon royal-blue">
            <svg className="svg-icon" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
          </div>
          <div className="card-visual-illustration">
            <img src="images/p1i4.png" alt="Automated Quarantine" className="card-illus-img" />
          </div>
          <h3>Tamper-Evident Audit Ledger</h3>
          <p>Every read, export, or analysis operation is hashed into an append-only JSONL ledger for courtroom verification.</p>
          <span className="card-arrow-link">&rarr;</span>
        </div>
      </div>
    </section>

    {/*  3. MULTI-AGENT ANALYSIS SECTION: 5 SPECIALIZED AGENTS + SUPERVISOR  */}
    <section id="landing-multi-agent" className="landing-feature-section multi-agent-landing-section">
      <div className="landing-section-header multi-agent-header">
        <span className="feature-tag">- ZONE 2 &amp; 3: COGNITIVE AGENTIC INTELLIGENCE</span>
        <h2>5 Specialized Domain Agents<br /><span className="blue-highlight">Orchestrated by Qwen Supervisor.</span></h2>
        <p>Each domain agent operates its dedicated fine-tuned LoRA adapter, extracting standardized JSON contracts without intermediate carve noise.</p>
      </div>

      <div className="features-grid-3 agent-cards-grid" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(310px, 1fr))", gap: "1.25rem" }}>
        {/*  Supervisor Agent  */}
        <div className="feature-card-glass agent-card" style={{ border: "2px solid rgba(37, 99, 235, 0.4)", background: "linear-gradient(180deg, rgba(239, 246, 255, 0.6) 0%, #ffffff 100%)" }}>
          <div className="card-visual-illustration agent-card-illustration">
            <img src="images/p2i1.png" alt="Master Supervisor Agent" className="agent-illus-img" />
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
            <span className="agent-pill-tag" style={{ background: "#1d4ed8", color: "#ffffff" }}>Supervisor Orchestrator</span>
            <span style={{ fontSize: "0.72rem", fontWeight: "700", color: "#1d4ed8" }}>Base Cyber QLoRA</span>
          </div>
          <h3>Master Supervisor Agent</h3>
          <p>Evaluates evidence sufficiency, orchestrates the 5 specialized sub-agents, and fuses multi-domain clues into the <strong>Structured Investigation State (SIS)</strong>.</p>
        </div>

        {/*  Agent 1: Network Forensics Agent  */}
        <div className="feature-card-glass agent-card">
          <div className="card-visual-illustration agent-card-illustration">
            <img src="images/p2i2.png" alt="Network Forensics Agent" className="agent-illus-img" />
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
            <span className="agent-pill-tag" style={{ background: "#7c3aed", color: "#ffffff" }}>Network Agent</span>
            <span style={{ fontSize: "0.72rem", fontWeight: "700", color: "#7c3aed" }}>Network Forensics</span>
          </div>
          <h3>Network &amp; Traffic Agent</h3>
          <p>Extracts PCAP flows, DNS queries/responses, TCP/UDP sockets, browser history/cookies, and email message headers (Contract JSONs).</p>
        </div>

        {/*  Agent 2: Memory Analysis Agent  */}
        <div className="feature-card-glass agent-card">
          <div className="card-visual-illustration agent-card-illustration">
            <img src="images/p2i3.png" alt="Volatile RAM Dump Agent" className="agent-illus-img" />
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
            <span className="agent-pill-tag" style={{ background: "#1d4ed8", color: "#ffffff" }}>Memory Agent</span>
            <span style={{ fontSize: "0.72rem", fontWeight: "700", color: "#1d4ed8" }}>Memory Forensics</span>
          </div>
          <h3>Memory &amp; Process Agent</h3>
          <p>Powered by Volatility 3: uncovers hidden process trees, injected DLL modules, mutant handles, memory hollows, and in-memory malware indicators (Contract JSONs).</p>
        </div>

        {/*  Agent 3: Disk & Filesystem Agent  */}
        <div className="feature-card-glass agent-card">
          <div className="card-visual-illustration agent-card-illustration">
            <img src="images/p3i2.png" alt="Disk & File System Agent" className="agent-illus-img" />
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
            <span className="agent-pill-tag" style={{ background: "#059669", color: "#ffffff" }}>Disk Agent</span>
            <span style={{ fontSize: "0.72rem", fontWeight: "700", color: "#059669" }}>Disk Forensics</span>
          </div>
          <h3>Disk &amp; Execution Agent</h3>
          <p>Parses Master File Table ($MFT), Windows shortcut files (LNK), Prefetch execution logs (.pf), Recycle Bin metadata, and Jump Lists (Contract JSONs).</p>
        </div>

        {/*  Agent 4: Event Logs Agent  */}
        <div className="feature-card-glass agent-card">
          <div className="card-visual-illustration agent-card-illustration">
            <img src="images/p2i4.png" alt="Sysmon & Event Logs Agent" className="agent-illus-img" />
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
            <span className="agent-pill-tag" style={{ background: "#0891b2", color: "#ffffff" }}>Log Agent</span>
            <span style={{ fontSize: "0.72rem", fontWeight: "700", color: "#0891b2" }}>Logs Forensics</span>
          </div>
          <h3>Event Logs &amp; Telemetry</h3>
          <p>Audits Windows Security EVTX logs, Sysmon events (EID 1, 3, 7), PowerShell script block execution (EID 4104), and RDP logon/logoff trails (Contract JSONs).</p>
        </div>

        {/*  Agent 5: Windows Registry Agent  */}
        <div className="feature-card-glass agent-card">
          <div className="card-visual-illustration agent-card-illustration">
            <img src="images/p3i1.png" alt="Registry & Persistence Agent" className="agent-illus-img" />
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
            <span className="agent-pill-tag" style={{ background: "#d97706", color: "#ffffff" }}>Registry Agent</span>
            <span style={{ fontSize: "0.72rem", fontWeight: "700", color: "#d97706" }}>Registry Forensics</span>
          </div>
          <h3>Registry &amp; System Agent</h3>
          <p>Inspects SAM/SYSTEM/SOFTWARE hives: extracts installed software inventory, USB device insertion history, Run &amp; RunOnce persistence keys (Contract JSONs).</p>
        </div>
      </div>
    </section>

    {/*  4. GOOGLE COLAB CLOUD GPU BRIDGE INTERACTIVE PANEL  */}
    <section id="landing-colab-bridge" className="landing-feature-section" style={{ padding: "1.5rem 2rem 3rem 2rem" }}>
      <div style={{ background: "linear-gradient(135deg, #0f172a 0%, #1e293b 100%)", borderRadius: "14px", padding: "2.25rem 2.5rem", color: "#ffffff", border: "1px solid #334155", boxShadow: "0 12px 30px -5px rgba(0, 0, 0, 0.35)" }}>
        <div style={{ display: "flex", flexWrap: "wrap", justifyContent: "space-between", alignItems: "flex-start", gap: "1.5rem", marginBottom: "1.5rem" }}>
          <div style={{ maxWidth: "680px" }}>
            <div style={{ display: "inline-flex", alignItems: "center", gap: "0.5rem", background: "rgba(59, 130, 246, 0.2)", border: "1px solid rgba(59, 130, 246, 0.4)", color: "#93c5fd", padding: "4px 12px", borderRadius: "9999px", fontWeight: "700", fontSize: "0.74rem", marginBottom: "0.85rem" }}>
              <span>⚡</span> ZERO-GPU HARDWARE ACCELERATION • GOOGLE COLAB BRIDGE
            </div>
            <h3 style={{ fontSize: "1.65rem", fontWeight: "800", marginBottom: "0.5rem", color: "#ffffff" }}>Google Colab Cloud GPU Inference Bridge</h3>
            <p style={{ fontSize: "0.92rem", color: "#cbd5e1", lineHeight: "1.55", margin: "0" }}>
              No dedicated local GPU? Connect Sherlock AI to our free Google Colab notebook running <strong>Qwen2.5-7B-Instruct (4-bit QLoRA)</strong> on an NVIDIA T4 (15 GB VRAM) via a Cloudflare/ngrok tunnel. Sherlock AI seamlessly offloads LLM token generation, and automatically falls back to local air-gapped forensic evaluation if offline.
            </p>
          </div>
          <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: "0.5rem" }}>
            <div id="landing-colab-status-badge" style={{ display: "inline-flex", alignItems: "center", gap: "0.4rem", background: "rgba(16, 185, 129, 0.15)", border: "1px solid rgba(16, 185, 129, 0.4)", color: "#34d399", padding: "6px 14px", borderRadius: "9999px", fontWeight: "700", fontSize: "0.8rem" }}>
              <span style={{ fontSize: "0.9rem" }}>🟢</span> Local Air-Gapped Mode Active
            </div>
            <span style={{ fontSize: "0.74rem", color: "#94a3b8" }}>100% Functionality Guaranteed On All Devices</span>
          </div>
        </div>

        {/*  Interactive URL Input Row  */}
        <div style={{ background: "rgba(15, 23, 42, 0.6)", border: "1px solid rgba(148, 163, 184, 0.2)", borderRadius: "10px", padding: "1.25rem 1.5rem", display: "flex", flexWrap: "wrap", gap: "1rem", alignItems: "center", justifyContent: "space-between" }}>
          <div style={{ flex: "1", minWidth: "280px" }}>
            <label htmlFor="colab-endpoint-url-input" style={{ display: "block", fontSize: "0.76rem", fontWeight: "700", color: "#94a3b8", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "0.35rem" }}>Colab Tunnel URL (Cloudflare Quick Tunnel / ngrok)</label>
            <input type="text" id="colab-endpoint-url-input" placeholder="e.g. https://forensics-gpu-tunnel.trycloudflare.com" style={{ width: "100%", padding: "0.65rem 0.9rem", background: "#0f172a", border: "1px solid #334155", borderRadius: "6px", color: "#f1f5f9", fontSize: "0.85rem", fontFamily: "monospace" }} />
          </div>
          <div style={{ display: "flex", gap: "0.75rem", alignItems: "flex-end", marginTop: "1.2rem" }}>
            <button type="button" id="btn-colab-connect"  className="btn btn-royal-blue" style={{ padding: "0.65rem 1.3rem", fontWeight: "700", fontSize: "0.85rem" }}>
              Connect &amp; Test GPU
            </button>
            <button type="button"  className="btn btn-outline" style={{ borderColor: "#475569", color: "#cbd5e1", padding: "0.65rem 1rem", fontSize: "0.85rem" }}>
              Reset to Local
            </button>
          </div>
        </div>

        {/*  Footnote with link to notebook  */}
        <div style={{ marginTop: "1rem", display: "flex", flexWrap: "wrap", justifyContent: "space-between", alignItems: "center", fontSize: "0.78rem", color: "#94a3b8" }}>
          <div>📓 Turnkey Notebook: <code>sherf/docs/SherlockAI_Colab_Inference_Bridge.ipynb</code></div>
          <div style={{ color: "#60a5fa" }}>Run in Colab with 1 click &bull; Free T4 GPU &bull; Zero local compute load</div>
        </div>
      </div>
    </section>

    {/*  5. THE 6 ARCHITECTURAL ZONES (B.TECH PRESENTATION ALIGNED)  */}
    <section id="landing-architecture" className="landing-feature-section" style={{ padding: "1rem 2rem 3.5rem 2rem" }}>
      <div className="landing-section-header">
        <span className="feature-tag">- COMPLETE FORENSIC PIPELINE</span>
        <h2>6 Architectural Zones<br /><span className="blue-highlight">From Ingestion to ISO/IEC 27037 Court Deliverables.</span></h2>
        <p>A rigorous, closed-loop forensic reconstruction pipeline ensuring bit-stream chain of custody and human-verified attack narratives.</p>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "1.25rem" }}>
        {/*  Zone 1  */}
        <div className="feature-card-glass" style={{ borderTop: "3px solid #2563eb" }}>
          <div style={{ fontSize: "0.72rem", fontWeight: "800", color: "#2563eb", letterSpacing: "0.05em", marginBottom: "0.4rem" }}>ZONE 01 • INGESTION &amp; VAULT</div>
          <h3 style={{ marginBottom: "0.5rem", fontSize: "1.05rem" }}>Cryptographic Preservation</h3>
          <p style={{ fontSize: "0.85rem", color: "#64748b", lineHeight: "1.5" }}>Ingests PCAP, volatile RAM, disk images, and Windows event logs. Computes streaming SHA-256 and HMAC digests and locks bit-stream files under read-only write-blocking.</p>
        </div>

        {/*  Zone 2  */}
        <div className="feature-card-glass" style={{ borderTop: "3px solid #7c3aed" }}>
          <div style={{ fontSize: "0.72rem", fontWeight: "800", color: "#7c3aed", letterSpacing: "0.05em", marginBottom: "0.4rem" }}>ZONE 02 • MULTI-AGENT ENGINE</div>
          <h3 style={{ marginBottom: "0.5rem", fontSize: "1.05rem" }}>5 Specialized Domain Agents</h3>
          <p style={{ fontSize: "0.85rem", color: "#64748b", lineHeight: "1.5" }}>Network, Memory, Disk, Event Logs, and Windows Registry specialized agents extract standardized JSON contracts without intermediate carve clutter.</p>
        </div>

        {/*  Zone 3  */}
        <div className="feature-card-glass" style={{ borderTop: "3px solid #059669" }}>
          <div style={{ fontSize: "0.72rem", fontWeight: "800", color: "#059669", letterSpacing: "0.05em", marginBottom: "0.4rem" }}>ZONE 03 • SUFFICIENCY LOOP</div>
          <h3 style={{ marginBottom: "0.5rem", fontSize: "1.05rem" }}>Sufficiency Verification Loop</h3>
          <p style={{ fontSize: "0.85rem", color: "#64748b", lineHeight: "1.5" }}>Evaluates evidence completeness across correlated timelines. If key evidence is missing, the engine prompts the investigator for specific follow-up artifacts before proceeding.</p>
        </div>

        {/*  Zone 4  */}
        <div className="feature-card-glass" style={{ borderTop: "3px solid #0891b2" }}>
          <div style={{ fontSize: "0.72rem", fontWeight: "800", color: "#0891b2", letterSpacing: "0.05em", marginBottom: "0.4rem" }}>ZONE 04 • KNOWLEDGE LAYER</div>
          <h3 style={{ marginBottom: "0.5rem", fontSize: "1.05rem" }}>Knowledge Graph &amp; RAG</h3>
          <p style={{ fontSize: "0.85rem", color: "#64748b", lineHeight: "1.5" }}>Constructs dual knowledge representations: directional entity-event knowledge graph and high-dimensional semantic vector index for evidence-grounded threat modeling.</p>
        </div>

        {/*  Zone 5  */}
        <div className="feature-card-glass" style={{ borderTop: "3px solid #d97706" }}>
          <div style={{ fontSize: "0.72rem", fontWeight: "800", color: "#d97706", letterSpacing: "0.05em", marginBottom: "0.4rem" }}>ZONE 05 • STRUCTURED STATE</div>
          <h3 style={{ marginBottom: "0.5rem", fontSize: "1.05rem" }}>Structured State (SIS) &amp; Review</h3>
          <p style={{ fontSize: "0.85rem", color: "#64748b", lineHeight: "1.5" }}>Maintains the canonical Structured Investigation State. Forensic investigators review, accept, or reject hypotheses with a closed feedback loop back to the supervisor.</p>
        </div>

        {/*  Zone 6  */}
        <div className="feature-card-glass" style={{ borderTop: "3px solid #dc2626" }}>
          <div style={{ fontSize: "0.72rem", fontWeight: "800", color: "#dc2626", letterSpacing: "0.05em", marginBottom: "0.4rem" }}>ZONE 06 • COURT DELIVERABLES</div>
          <h3 style={{ marginBottom: "0.5rem", fontSize: "1.05rem" }}>ISO/IEC 27037 Court Outputs</h3>
          <p style={{ fontSize: "0.85rem", color: "#64748b", lineHeight: "1.5" }}>Produces four on-demand deliverables: Chronological Attack Timeline, MITRE ATT&amp;CK Attribution Matrix, Court-Ready ISO Forensic Report PDF/Print, and Case Chatbot.</p>
        </div>
      </div>
    </section>


    {/*  4. IMMUTABLE CHAIN OF CUSTODY SECTION  */}
    <section id="landing-custody" className="landing-feature-section custody-landing-section">
      {/*  TOP SPLIT HERO GRID  */}
      <div className="custody-hero-grid">
        <div className="custody-left-text">
          <div className="feature-tag">- LEGAL STANDARD</div>

          <h2 className="custody-main-title">
            Reconstruction &amp; court-ready<br />
            forensic <span className="blue-highlight">report.</span>
          </h2>

          <p className="custody-description">
            From bit-stream evidence ingestion to chronological attack reconstruction,<br />
            multi-source anomaly correlation, and court-admissible forensic reporting<br />
            with verified SHA-256 and HMAC digital signatures.
          </p>
        </div>

        <div className="custody-right-visual tilt-wrapper">
          <div className="custody-chain-container float-layer idle-floating-3d">
            <img src="images/chain.png" alt="Immutable Chain of Custody Orbit Diagram 3D" className="custody-chain-img tilt-3d-img" />
          </div>
        </div>
      </div>

      {/*  BOTTOM 3-CARD STEP ROW  */}
      <div className="custody-cards-grid">
        {/*  Card 1  */}
        <div className="custody-step-card tilt-wrapper">
          <div className="custody-card-top-row">
            <div className="custody-step-num">01</div>
          </div>
          <div className="card-visual-illustration custody-card-illustration float-layer idle-floating-3d">
            <img src="images/p3i1.png" alt="Evidence Upload & Hashing 3D" className="custody-illus-img tilt-3d-img" />
          </div>
          <h3>Evidence Upload &amp; Hashing</h3>
          <p>Calculates multi-pass SHA-256 and HMAC cryptographic digests, generating an immutable chain of custody bound to investigator credentials.</p>
          <span className="card-arrow-link">&rarr;</span>
        </div>

        {/*  Card 2  */}
        <div className="custody-step-card tilt-wrapper">
          <div className="custody-card-top-row">
            <div className="custody-step-num">02</div>
          </div>
          <div className="card-visual-illustration custody-card-illustration float-layer idle-floating-3d">
            <img src="images/p3i2.png" alt="Forensic Artifact Extraction 3D" className="custody-illus-img tilt-3d-img" />
          </div>
          <h3>Artifact Extraction &amp; Synthesis</h3>
          <p>Dispatches RAM, PCAP, and Disk images to prot1-main extractors, generating structured process trees, network streams, and registry indicators.</p>
          <span className="card-arrow-link">&rarr;</span>
        </div>

        {/*  Card 3  */}
        <div className="custody-step-card tilt-wrapper">
          <div className="custody-card-top-row">
            <div className="custody-step-num">03</div>
          </div>
          <div className="card-visual-illustration custody-card-illustration float-layer idle-floating-3d">
            <img src="images/p3i3.png" alt="Verification Audit & Court Report 3D" className="custody-illus-img tilt-3d-img" />
          </div>
          <h3>Timeline &amp; Court Report</h3>
          <p>Reconstructs chronological attack milestones, maps MITRE ATT&amp;CK techniques, and compiles ISO/IEC 27037 court-admissible reports.</p>
          <span className="card-arrow-link">&rarr;</span>
        </div>
      </div>
    </section>

    {/*  FOOTER  */}
    <footer className="landing-footer">
      <div className="landing-footer-content">
        <div className="footer-left">
          <span className="footer-logo">Sherlock AI</span>
          <p className="footer-subtext">Hierarchical Multi-Agent Cognitive Forensic Reconstruction Framework</p>
        </div>
        <div className="footer-right">
          © 2026 Sherlock AI. All rights reserved. Enterprise Forensic Security Core.
        </div>
      </div>
    </footer>

  </div>



  );
};
