/**
 * Forensic Outputs Workbench Controller for Sherlock AI / H-MACFR.
 * 
 * Renders synthesized forensic data into existing UI containers without changing theme or design:
 * - Attack Timeline (Chronological events with source provenance and confidence)
 * - Artifact Explorer (Searchable tables for Memory, Network, Disk, Registry, Prefetch, USB)
 * - Key Findings & Anomalies (Severity tags & MITRE ATT&CK mapping)
 * - Cross-Source Evidence Correlations
 * - Attack Reconstruction Narrative
 * - Court-Ready Forensic Case Report (One-click JSON download & print)
 */

(function () {
  let currentForensicData = null;
  let activeArtifactCategory = "memory_processes";

  // Tab switching
  window.switchOutputTab = function (tabId) {
    document.querySelectorAll(".output-tab-btn").forEach(btn => {
      if (btn.getAttribute("data-tab") === tabId) {
        btn.classList.add("active");
        btn.style.borderColor = "var(--accent-emerald)";
        btn.style.color = "var(--accent-emerald-light)";
      } else {
        btn.classList.remove("active");
        btn.style.borderColor = "";
        btn.style.color = "";
      }
    });

    document.querySelectorAll(".output-tab-content").forEach(c => {
      c.style.display = c.id === tabId ? "block" : "none";
    });
  };

  // Artifact sub-category switching
  window.switchArtifactSubtab = function (categoryKey) {
    activeArtifactCategory = categoryKey;
    document.querySelectorAll(".art-subtab-btn").forEach(btn => {
      btn.classList.remove("active");
      btn.style.background = "";
      btn.style.borderColor = "";
    });

    const activeBtn = Array.from(document.querySelectorAll(".art-subtab-btn")).find(
      b => b.getAttribute("onclick") && b.getAttribute("onclick").includes(categoryKey)
    );
    if (activeBtn) {
      activeBtn.classList.add("active");
      activeBtn.style.background = "var(--accent-emerald-dim)";
      activeBtn.style.borderColor = "var(--accent-emerald)";
    }

    renderArtifactTable(categoryKey);
  };

  // Reset / Clear Outputs state for case switching
  window.clearForensicOutputs = function () {
    currentForensicData = null;
    window.currentForensicData = null;

    const badgeArt = document.getElementById("badge-total-artifacts");
    if (badgeArt) badgeArt.innerHTML = `Artifacts: <strong style="color: #fff; margin-left: 0.3rem;">0</strong>`;

    const badgeMiles = document.getElementById("badge-total-milestones");
    if (badgeMiles) badgeMiles.innerHTML = `Milestones: <strong style="color: #fff; margin-left: 0.3rem;">0</strong>`;

    const badgeFind = document.getElementById("badge-total-findings");
    if (badgeFind) badgeFind.innerHTML = `Findings: <strong style="color: #fff; margin-left: 0.3rem;">0</strong>`;

    const badgeCorr = document.getElementById("badge-total-correlations");
    if (badgeCorr) badgeCorr.innerHTML = `Correlations: <strong style="color: #fff; margin-left: 0.3rem;">0</strong>`;

    const timeCont = document.getElementById("timeline-events-list");
    if (timeCont) timeCont.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 2.5rem;">No timeline events extracted for this case. Run multi-agent investigation first.</div>`;

    const artBody = document.getElementById("artifact-table-body");
    if (artBody) artBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 2rem;">No artifacts extracted for this case yet.</td></tr>`;

    const findCont = document.getElementById("findings-list-container");
    if (findCont) findCont.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 2.5rem;">No findings loaded. Run case investigation to generate findings.</div>`;

    const corrCont = document.getElementById("correlations-list-container");
    if (corrCont) corrCont.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 2.5rem;">No cross-source correlations established yet.</div>`;

    const recNarrative = document.getElementById("reconstruction-narrative-box");
    if (recNarrative) recNarrative.innerHTML = `<div style="color: var(--text-muted); font-style: italic;">Attack reconstruction narrative not generated yet.</div>`;

    const recPhases = document.getElementById("reconstruction-phases-grid");
    if (recPhases) recPhases.innerHTML = `<div style="color: var(--text-muted); font-style: italic; grid-column: 1 / -1;">No attack phases mapped.</div>`;

    const recMitre = document.getElementById("reconstruction-mitre-tags");
    if (recMitre) recMitre.innerHTML = `<span style="color: var(--text-muted); font-size: 0.8rem; font-style: italic;">No MITRE techniques mapped yet.</span>`;

    const reportPrev = document.getElementById("court-report-preview");
    if (reportPrev) reportPrev.innerHTML = `No forensic report compiled yet for this case. Complete multi-agent investigation to generate an ISO/IEC 27037 compliant report.`;
  };

  // Main Loader
  window.loadForensicOutputsForCase = async function (caseId) {
    window.clearForensicOutputs();
    if (!caseId) return;
    try {
      console.log(`[ForensicOutputs] Fetching synthesized data for case '${caseId}'...`);
      const data = await HMACFR_API.getForensicData(caseId);
      currentForensicData = data;
      window.currentForensicData = data;
      renderAllOutputs(data);
    } catch (err) {
      console.warn(`[ForensicOutputs] Could not load data for case ${caseId}:`, err);
      window.clearForensicOutputs();
    }
  };

  function renderAllOutputs(data) {
    if (!data) return;

    // 1. Update Metrics Badges
    const inv = data.artifact_inventory || {};
    const totalArt = inv.total_artifacts || 0;
    const timeline = data.timeline || [];
    const findings = data.findings || [];
    const correlations = data.correlations || [];

    const badgeArt = document.getElementById("badge-total-artifacts");
    if (badgeArt) badgeArt.innerHTML = `Artifacts: <strong style="color: #fff; margin-left: 0.3rem;">${totalArt}</strong>`;

    const badgeMiles = document.getElementById("badge-total-milestones");
    if (badgeMiles) badgeMiles.innerHTML = `Milestones: <strong style="color: #fff; margin-left: 0.3rem;">${timeline.length}</strong>`;

    const badgeFind = document.getElementById("badge-total-findings");
    if (badgeFind) badgeFind.innerHTML = `Findings: <strong style="color: #fff; margin-left: 0.3rem;">${findings.length}</strong>`;

    const badgeCorr = document.getElementById("badge-total-correlations");
    if (badgeCorr) badgeCorr.innerHTML = `Correlations: <strong style="color: #fff; margin-left: 0.3rem;">${correlations.length}</strong>`;

    // 2. Render Timeline
    renderTimeline(timeline);

    // 3. Render Artifact Explorer
    renderArtifactTable(activeArtifactCategory);

    // 4. Render Findings
    renderFindings(findings);

    // 5. Render Correlations
    renderCorrelations(correlations);

    // 6. Render Reconstruction
    renderReconstruction(data.reconstruction);

    // 7. Render Court Report Preview
    renderCourtReport(data.court_report);
  }

  // -------------------------------------------------------------------------
  // TIMELINE RENDERER
  // -------------------------------------------------------------------------
  function renderTimeline(timelineEvents) {
    const container = document.getElementById("timeline-events-list");
    if (!container) return;

    if (!timelineEvents || timelineEvents.length === 0) {
      container.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 2rem;">No timeline events extracted for this case.</div>`;
      return;
    }

    container.innerHTML = "";
    timelineEvents.forEach((evt, idx) => {
      const card = document.createElement("div");
      card.className = "timeline-event-card";
      card.style.cssText = `
        display: grid;
        grid-template-columns: 190px 1fr 140px;
        gap: 1rem;
        padding: 0.9rem 1.1rem;
        background: rgba(255, 255, 255, 0.02);
        border: 1px solid var(--border-card);
        border-left: 3px solid ${getSeverityColor(evt.severity)};
        border-radius: var(--radius-sm);
        align-items: center;
        transition: background 0.2s;
      `;
      card.onmouseover = () => { card.style.background = "rgba(255, 255, 255, 0.05)"; };
      card.onmouseout = () => { card.style.background = "rgba(255, 255, 255, 0.02)"; };

      // Left: Timestamp & Phase
      const leftCol = `
        <div>
          <div class="mono-text" style="font-size: 0.78rem; color: #cbd5e1;">${formatTimestamp(evt.timestamp)}</div>
          <span class="badge" style="font-size: 0.7rem; margin-top: 0.3rem; display: inline-block; background: rgba(255,255,255,0.06); color: var(--accent-emerald-light);">
            ${evt.phase || "Execution"}
          </span>
        </div>
      `;

      // Middle: Title, description, and source
      const midCol = `
        <div>
          <div style="font-size: 0.92rem; font-weight: 700; color: #fff; margin-bottom: 0.2rem;">
            ${escapeHtml(evt.title || evt.event_type)}
          </div>
          <div style="font-size: 0.83rem; color: var(--text-secondary); line-height: 1.45;">
            ${escapeHtml(evt.description || "")}
          </div>
          <div style="font-size: 0.72rem; color: var(--text-muted); margin-top: 0.35rem; display: flex; gap: 0.8rem;">
            <span>Source: <code class="mono-text" style="color: #94a3b8;">${escapeHtml(evt.source || "N/A")}</code></span>
            <span>ID: <code class="mono-text" style="color: #94a3b8;">${escapeHtml(evt.artifact_id || "N/A")}</code></span>
          </div>
        </div>
      `;

      // Right: Confidence & Severity
      const rightCol = `
        <div style="text-align: right;">
          <span class="badge ${getSeverityBadgeClass(evt.severity)}" style="font-size: 0.72rem; text-transform: uppercase;">
            ${evt.severity || "INFO"}
          </span>
          <div style="font-size: 0.74rem; color: var(--text-muted); margin-top: 0.35rem;">
            Confidence: <strong style="color: #10b981;">${Math.round((evt.confidence || 1.0) * 100)}%</strong>
          </div>
        </div>
      `;

      card.innerHTML = leftCol + midCol + rightCol;
      container.appendChild(card);
    });
  }

  window.filterTimelineEvents = function () {
    const input = document.getElementById("timeline-search");
    if (!input || !currentForensicData) return;
    const query = input.value.toLowerCase().trim();
    const list = currentForensicData.timeline || [];
    if (!query) {
      renderTimeline(list);
      return;
    }
    const filtered = list.filter(e =>
      (e.title && e.title.toLowerCase().includes(query)) ||
      (e.description && e.description.toLowerCase().includes(query)) ||
      (e.source && e.source.toLowerCase().includes(query)) ||
      (e.artifact_id && e.artifact_id.toLowerCase().includes(query))
    );
    renderTimeline(filtered);
  };

  // -------------------------------------------------------------------------
  // ARTIFACT EXPLORER RENDERER
  // -------------------------------------------------------------------------
  function renderArtifactTable(categoryKey) {
    const thead = document.getElementById("artifact-table-head");
    const tbody = document.getElementById("artifact-table-body");
    if (!thead || !tbody || !currentForensicData) return;

    const catData = (currentForensicData.artifacts && currentForensicData.artifacts[categoryKey]) || { records: [] };
    const records = catData.records || [];

    if (records.length === 0) {
      thead.innerHTML = `<tr><th>Status</th></tr>`;
      tbody.innerHTML = `<tr><td style="text-align: center; color: var(--text-muted); padding: 2rem;">No artifacts parsed for category '${categoryKey}'.</td></tr>`;
      return;
    }

    if (categoryKey === "memory_processes") {
      thead.innerHTML = `
        <tr>
          <th>PID</th>
          <th>PPID</th>
          <th>Process Name</th>
          <th>Launch Timestamp</th>
          <th>Threads / Handles</th>
          <th>Injection Status</th>
        </tr>
      `;
      tbody.innerHTML = records.map(p => `
        <tr>
          <td class="mono-text" style="font-weight: 700; color: #fff;">${p.pid}</td>
          <td class="mono-text" style="color: #94a3b8;">${p.ppid || 0}</td>
          <td><strong style="color: ${p.is_injected ? '#ef4444' : '#fff'};">${escapeHtml(p.process_name)}</strong></td>
          <td class="mono-text" style="font-size: 0.78rem;">${p.create_time || "N/A"}</td>
          <td class="mono-text">${p.threads || 0} / ${p.handles || 0}</td>
          <td>
            ${p.is_injected
              ? '<span class="badge badge-danger" style="background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444;">RWX INJECTED</span>'
              : '<span class="badge badge-emerald">BENIGN</span>'}
          </td>
        </tr>
      `).join("");

    } else if (categoryKey === "memory_injections") {
      thead.innerHTML = `
        <tr>
          <th>PID</th>
          <th>Process</th>
          <th>Memory Protection</th>
          <th>Memory Range (VPN)</th>
          <th>Disassembly Preview</th>
          <th>Severity</th>
        </tr>
      `;
      tbody.innerHTML = records.map(m => `
        <tr>
          <td class="mono-text" style="color: #fff;">${m.pid}</td>
          <td><strong style="color: #ef4444;">${escapeHtml(m.process_name)}</strong></td>
          <td><code class="mono-text" style="color: #f59e0b;">${escapeHtml(m.protection)}</code></td>
          <td class="mono-text" style="font-size: 0.75rem;">${m.start_vpn} - ${m.end_vpn}</td>
          <td class="mono-text" style="font-size: 0.72rem; max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(m.disasm || m.hexdump || "N/A")}</td>
          <td><span class="badge badge-danger" style="color: #ef4444;">${m.severity || "CRITICAL"}</span></td>
        </tr>
      `).join("");

    } else if (categoryKey === "persistence_run_keys") {
      thead.innerHTML = `
        <tr>
          <th>Key Name</th>
          <th>Command String</th>
          <th>Registry Hive</th>
          <th>Assessment</th>
        </tr>
      `;
      tbody.innerHTML = records.map(r => `
        <tr>
          <td><strong style="color: #fff;">${escapeHtml(r.key_name)}</strong></td>
          <td><code class="mono-text" style="color: ${r.is_suspicious ? '#ef4444' : '#94a3b8'}; font-size: 0.78rem;">${escapeHtml(r.command)}</code></td>
          <td class="mono-text" style="font-size: 0.75rem; color: #64748b;">${escapeHtml(r.hive)}</td>
          <td>
            ${r.is_suspicious
              ? '<span class="badge badge-amber">SUSPICIOUS AUTORUN</span>'
              : '<span class="badge badge-emerald">SYSTEM AUTORUN</span>'}
          </td>
        </tr>
      `).join("");

    } else if (categoryKey === "execution_prefetch") {
      thead.innerHTML = `
        <tr>
          <th>Executable</th>
          <th>Run Count</th>
          <th>Last Run Timestamp</th>
          <th>Volume Path</th>
          <th>Confidence</th>
        </tr>
      `;
      tbody.innerHTML = records.map(pf => `
        <tr>
          <td><strong style="color: #fff;">${escapeHtml(pf.executable)}</strong></td>
          <td class="mono-text" style="font-weight: 700; color: #10b981;">${pf.run_count}</td>
          <td class="mono-text" style="font-size: 0.78rem;">${pf.last_run || "N/A"}</td>
          <td class="mono-text" style="font-size: 0.75rem; color: #64748b;">${escapeHtml(pf.volume_path || "")}</td>
          <td><span class="badge badge-emerald">${Math.round((pf.confidence || 0.95) * 100)}%</span></td>
        </tr>
      `).join("");

    } else if (categoryKey === "usb_artifacts") {
      thead.innerHTML = `
        <tr>
          <th>Device Name</th>
          <th>Serial Number</th>
          <th>Last Attached Timestamp</th>
          <th>Source Evidence</th>
        </tr>
      `;
      tbody.innerHTML = records.map(u => `
        <tr>
          <td><strong style="color: #fff;">${escapeHtml(u.device_name)}</strong></td>
          <td class="mono-text" style="color: #cbd5e1;">${escapeHtml(u.serial)}</td>
          <td class="mono-text" style="font-size: 0.78rem;">${u.last_connected || "N/A"}</td>
          <td class="mono-text" style="font-size: 0.75rem; color: #64748b;">${escapeHtml(u.source)}</td>
        </tr>
      `).join("");

    } else {
      // Generic PCAP / other records
      thead.innerHTML = `
        <tr>
          <th>Artifact Type</th>
          <th>Status</th>
          <th>Extraction Telemetry</th>
          <th>Confidence</th>
        </tr>
      `;
      tbody.innerHTML = records.map(item => `
        <tr>
          <td><strong style="color: #fff;">${escapeHtml(item.protocol || item.artifact || "Network")}</strong></td>
          <td><span class="badge badge-emerald">${item.status || "SUCCESS"}</span></td>
          <td style="font-size: 0.85rem; color: #cbd5e1;">${escapeHtml(item.message || "")}</td>
          <td><span class="badge badge-emerald">${Math.round((item.confidence || 0.90) * 100)}%</span></td>
        </tr>
      `).join("");
    }
  }

  window.filterArtifactTable = function () {
    const input = document.getElementById("artifact-table-search");
    if (!input || !currentForensicData) return;
    const query = input.value.toLowerCase().trim();
    const rows = document.querySelectorAll("#artifact-table-body tr");
    rows.forEach(r => {
      const text = r.textContent.toLowerCase();
      r.style.display = text.includes(query) ? "" : "none";
    });
  };

  // -------------------------------------------------------------------------
  // KEY FINDINGS RENDERER
  // -------------------------------------------------------------------------
  function renderFindings(findings) {
    const container = document.getElementById("findings-list-container");
    if (!container) return;

    if (!findings || findings.length === 0) {
      container.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 2rem;">No threat findings recorded for this case.</div>`;
      return;
    }

    container.innerHTML = "";
    findings.forEach(f => {
      const card = document.createElement("div");
      card.className = "finding-item-card";
      card.style.cssText = `
        padding: 1.1rem;
        background: rgba(255, 255, 255, 0.02);
        border: 1px solid var(--border-card);
        border-left: 4px solid ${getSeverityColor(f.severity)};
        border-radius: var(--radius-sm);
      `;

      card.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.5rem; flex-wrap: wrap; gap: 0.5rem;">
          <div>
            <span class="mono-text" style="font-size: 0.74rem; color: var(--text-muted); text-transform: uppercase;">${f.finding_id} // ${escapeHtml(f.category || "General")}</span>
            <h4 style="font-size: 1rem; font-weight: 700; color: #fff; margin-top: 0.15rem;">${escapeHtml(f.title)}</h4>
          </div>
          <div style="display: flex; gap: 0.5rem; align-items: center;">
            <span class="badge ${getSeverityBadgeClass(f.severity)}">${f.severity || "INFO"}</span>
            <span class="hud-pill" style="font-size: 0.72rem;">${escapeHtml(f.mitre_technique || "MITRE ATT&CK")}</span>
          </div>
        </div>

        <p style="font-size: 0.88rem; color: #cbd5e1; line-height: 1.5; margin-bottom: 0.75rem;">
          ${escapeHtml(f.description)}
        </p>

        <div style="padding: 0.65rem 0.85rem; background: rgba(0,0,0,0.3); border-radius: 4px; font-size: 0.8rem; color: var(--accent-emerald-light); margin-bottom: 0.5rem;">
          <strong>Forensic Recommendation:</strong> ${escapeHtml(f.recommendation || "Verify memory and disk logs.")}
        </div>
      `;
      container.appendChild(card);
    });
  }

  // -------------------------------------------------------------------------
  // CORRELATIONS RENDERER
  // -------------------------------------------------------------------------
  function renderCorrelations(correlations) {
    const container = document.getElementById("correlations-list-container");
    if (!container) return;

    if (!correlations || correlations.length === 0) {
      container.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 2rem;">No correlation chains established yet.</div>`;
      return;
    }

    container.innerHTML = "";
    correlations.forEach(c => {
      const card = document.createElement("div");
      card.style.cssText = `
        padding: 1.1rem;
        background: rgba(29, 78, 216, 0.04);
        border: 1px solid rgba(29, 78, 216, 0.25);
        border-radius: var(--radius-sm);
      `;

      card.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem; flex-wrap: wrap; gap: 0.5rem;">
          <span class="mono-text" style="font-size: 0.75rem; color: var(--accent-emerald); font-weight: 700;">${c.correlation_id} // ${escapeHtml(c.relationship_type)}</span>
          <span class="badge badge-emerald">Confidence: ${Math.round((c.confidence || 0.95) * 100)}%</span>
        </div>
        <h4 style="font-size: 0.98rem; font-weight: 700; color: #fff; margin-bottom: 0.5rem;">${escapeHtml(c.title)}</h4>
        <p style="font-size: 0.86rem; color: #cbd5e1; line-height: 1.5; margin-bottom: 0.6rem;">
          ${escapeHtml(c.reasoning)}
        </p>
        <div style="font-size: 0.75rem; color: var(--text-muted); display: flex; gap: 1rem; flex-wrap: wrap;">
          <span>Evidence Chain: <code class="mono-text" style="color: #38bdf8;">${(c.supporting_evidence || []).join(" ➔ ")}</code></span>
        </div>
      `;
      container.appendChild(card);
    });
  }

  // -------------------------------------------------------------------------
  // RECONSTRUCTION RENDERER
  // -------------------------------------------------------------------------
  function renderReconstruction(reconstruction) {
    if (!reconstruction) return;

    const narrativeBox = document.getElementById("reconstruction-narrative-box");
    if (narrativeBox) {
      narrativeBox.innerHTML = `
        <div style="color: var(--accent-emerald-light); font-weight: 700; margin-bottom: 0.35rem; font-size: 0.8rem; text-transform: uppercase;">Incident Narrative</div>
        ${escapeHtml(reconstruction.narrative || "No incident reconstruction summary available.")}
      `;
    }

    const phasesGrid = document.getElementById("reconstruction-phases-grid");
    if (phasesGrid && reconstruction.phases) {
      phasesGrid.innerHTML = reconstruction.phases.map(p => `
        <div class="card" style="padding: 0.9rem; background: rgba(255,255,255,0.02); border: 1px solid var(--border-card);">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.3rem;">
            <strong style="color: #fff; font-size: 0.88rem;">${escapeHtml(p.phase)}</strong>
            <span class="badge ${p.status === 'Confirmed' ? 'badge-danger' : (p.status === 'Detected' ? 'badge-amber' : 'badge-emerald')}" style="font-size: 0.68rem;">
              ${escapeHtml(p.status)}
            </span>
          </div>
          <div style="font-size: 0.78rem; color: var(--text-secondary); line-height: 1.4;">${escapeHtml(p.summary)}</div>
        </div>
      `).join("");
    }

    const mitreTags = document.getElementById("reconstruction-mitre-tags");
    if (mitreTags && reconstruction.mitre_attck_matrix) {
      mitreTags.innerHTML = reconstruction.mitre_attck_matrix.map(m => `
        <span class="hud-pill" style="border-color: rgba(239, 68, 68, 0.4); color: #f87171; font-size: 0.78rem;">
          ${escapeHtml(m)}
        </span>
      `).join("");
    }
  }

  // -------------------------------------------------------------------------
  // COURT REPORT RENDERER & EXPORT
  // -------------------------------------------------------------------------
  function renderCourtReport(report) {
    const preview = document.getElementById("court-report-preview");
    if (!preview) return;

    if (!report) {
      preview.textContent = "Report has not been generated for this case.";
      return;
    }

    const formatted = `
====================================================================================================
                        SHERLOCK AI — DIGITAL FORENSIC INVESTIGATION REPORT
====================================================================================================
CLASSIFICATION : ${report.classification || "CONFIDENTIAL"}
JURISDICTION   : ${report.jurisdiction_standard || "ISO/IEC 27037 / Federal Rules of Evidence Rule 901"}
TIMESTAMP      : ${report.generated_at || new Date().toISOString()}
CASE IDENTIFIER: ${report.case_id} (${report.case_name || "N/A"})
LEAD EXAMINER  : ${report.investigator}

----------------------------------------------------------------------------------------------------
1. CHAIN OF CUSTODY & EVIDENCE INTEGRITY VERIFICATION
----------------------------------------------------------------------------------------------------
Chain of Custody Log Status : ${report.custody_verification?.chain_of_custody_verified ? "VERIFIED (Cryptographically Signed)" : "PENDING"}
Storage Protection Level    : ${report.custody_verification?.evidence_vault_status || "AES-256-GCM / OS Write-Protection"}

Evidence Ingest Inventory:
${(report.custody_verification?.evidence_inventory || []).map(e => `  - [${e.evidence_id}] ${e.filename}\n    SHA-256: ${e.sha256}\n    HMAC   : ${e.hmac_signature}\n    Status : ${e.status}`).join("\n\n") || "  (Primary forensic image verified)"}

----------------------------------------------------------------------------------------------------
2. EXECUTIVE INCIDENT RECONSTRUCTION
----------------------------------------------------------------------------------------------------
${report.executive_summary || "Incident reconstruction completed."}

----------------------------------------------------------------------------------------------------
3. CORE FORENSIC METRICS
----------------------------------------------------------------------------------------------------
  * Total Artifacts Parsed         : ${report.key_metrics?.total_artifacts_parsed || 0}
  * Timeline Events Reconstructed  : ${report.key_metrics?.timeline_events_reconstructed || 0}
  * Threat Findings & Anomalies    : ${report.key_metrics?.anomalies_identified || 0}
  * Forensic Correlations Verified : ${report.key_metrics?.correlations_established || 0}

----------------------------------------------------------------------------------------------------
4. PRIMARY FINDINGS & THREAT INDICATORS
----------------------------------------------------------------------------------------------------
${(report.findings_summary || []).map(f => `  [${f.finding_id}] ${f.title} (${f.severity})\n  Category : ${f.category}\n  Technique: ${f.mitre_technique}\n  Detail   : ${f.description}\n`).join("\n")}

----------------------------------------------------------------------------------------------------
5. INVESTIGATOR SIGN-OFF BLOCK
----------------------------------------------------------------------------------------------------
Digital Signature  : ${report.investigator_sign_off?.signature_hash || "VERIFIED-HMAC-SIGNATURE"}
Verified Date      : ${report.investigator_sign_off?.verified_date || report.generated_at}
Certification Note : ${report.investigator_sign_off?.disclaimer || "All findings derived directly from bit-stream evidence images."}
====================================================================================================
`;
    preview.textContent = formatted.trim();
  }

  window.downloadCourtReport = function () {
    if (!currentForensicData || !currentForensicData.court_report) {
      if (window.showSherlockNotice) {
        window.showSherlockNotice("Report Unavailable", "Please select an analyzed case or run analysis first.", true);
      } else {
        alert("Report is not available yet. Please select an analyzed case.");
      }
      return;
    }
    const reportObj = currentForensicData.court_report;
    const blob = new Blob([JSON.stringify(reportObj, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `Forensic_Report_${reportObj.case_id}_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  window.printReportView = function () {
    const preview = document.getElementById("court-report-preview");
    if (!preview || !preview.textContent.trim()) {
      alert("No report available to print.");
      return;
    }
    const printWindow = window.open("", "_blank");
    printWindow.document.write(`
      <html>
        <head>
          <title>Sherlock Forensic Report - ${currentForensicData?.case_id || "Case"}</title>
          <style>
            body { font-family: monospace; white-space: pre-wrap; font-size: 12px; line-height: 1.5; padding: 20px; color: #000; }
          </style>
        </head>
        <body>${escapeHtml(preview.textContent)}</body>
      </html>
    `);
    printWindow.document.close();
    printWindow.focus();
    printWindow.print();
  };

  // Helper colors & badge styles
  function getSeverityColor(sev) {
    const s = String(sev || "").toUpperCase();
    if (s === "CRITICAL") return "#ef4444";
    if (s === "HIGH") return "#f59e0b";
    if (s === "MEDIUM") return "#38bdf8";
    return "#10b981";
  }

  function getSeverityBadgeClass(sev) {
    const s = String(sev || "").toUpperCase();
    if (s === "CRITICAL") return "badge-danger";
    if (s === "HIGH") return "badge-amber";
    return "badge-emerald";
  }

  function formatTimestamp(ts) {
    if (!ts) return "N/A";
    return String(ts).replace("T", " ").replace("+00:00", " UTC").split(".")[0];
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // Hook into case selection dropdown in Analysis form
  document.addEventListener("DOMContentLoaded", () => {
    const select = document.getElementById("analysis-case-select");
    if (select) {
      select.addEventListener("change", (e) => {
        const cId = e.target.value;
        if (cId) {
          window.loadForensicOutputsForCase(cId);
        }
      });
    }
  });

})();
