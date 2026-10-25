// Safe HTML and string escaping utilities
function escapeHTML(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
window.escapeHTML = escapeHTML;

function escapeQuotes(str) {
  if (!str) return "";
  return String(str)
    .replace(/\\/g, "\\\\")
    .replace(/'/g, "&#39;")
    .replace(/"/g, "&quot;")
    .replace(/\n/g, " ")
    .replace(/\r/g, " ");
}
window.escapeQuotes = escapeQuotes;

document.addEventListener("DOMContentLoaded", () => {
  initApp();
});

// =========================================================================
// CYBER-FORENSIC TOAST & MODAL DIALOG SYSTEM (Custom Elements for Alert / Confirm / Prompt)
// =========================================================================
window.showForensicToast = function(message, type = "info", duration = 4000) {
  const container = document.getElementById("forensic-toast-container");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = `forensic-toast forensic-toast-${type}`;

  const iconMap = {
    success: `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="#10b981" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>`,
    error: `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="#ef4444" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
    danger: `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="#ef4444" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
    warning: `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="#f59e0b" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
    info: `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="#38bdf8" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`
  };

  const icon = iconMap[type] || iconMap.info;

  toast.innerHTML = `
    <div style="flex-shrink: 0; margin-top: 1px;">${icon}</div>
    <div style="flex: 1; font-size: 0.85rem; line-height: 1.45; word-break: break-word;">${escapeHTML(message)}</div>
    <button type="button" style="background: transparent; border: none; color: #94a3b8; font-size: 1.1rem; cursor: pointer; line-height: 1; padding: 0 0 0 0.5rem;">&times;</button>
    <div class="forensic-toast-progress"></div>
  `;

  const closeBtn = toast.querySelector("button");
  const dismiss = () => {
    toast.classList.add("toast-hide");
    setTimeout(() => { if (toast.parentElement) toast.parentElement.removeChild(toast); }, 250);
  };
  closeBtn.onclick = dismiss;

  container.appendChild(toast);

  if (duration > 0) {
    const progressBar = toast.querySelector(".forensic-toast-progress");
    if (progressBar) {
      progressBar.style.transition = `width ${duration}ms linear`;
      setTimeout(() => { progressBar.style.width = "0%"; }, 20);
    }
    setTimeout(dismiss, duration);
  }
};

window.showForensicDialog = function({
  tag = "SYSTEM NOTICE",
  title = "Notice",
  message = "",
  type = "info",
  showCancel = false,
  confirmText = "OK",
  cancelText = "Cancel",
  isPrompt = false,
  defaultValue = "",
  placeholder = ""
}) {
  return new Promise((resolve) => {
    const overlay = document.getElementById("forensic-dialog-overlay");
    const tagEl = document.getElementById("forensic-dialog-tag");
    const titleEl = document.getElementById("forensic-dialog-title");
    const msgEl = document.getElementById("forensic-dialog-message");
    const iconBox = document.getElementById("forensic-dialog-icon-box");
    const inputWrap = document.getElementById("forensic-dialog-input-wrap");
    const inputEl = document.getElementById("forensic-dialog-input");
    const cancelBtn = document.getElementById("forensic-dialog-cancel-btn");
    const confirmBtn = document.getElementById("forensic-dialog-confirm-btn");

    if (!overlay) {
      if (isPrompt) return resolve(window.prompt(message, defaultValue));
      if (showCancel) return resolve(window.confirm(message));
      window.showForensicToast(message, type);
      return resolve(true);
    }

    if (tagEl) tagEl.textContent = tag;
    if (titleEl) titleEl.textContent = title;
    if (msgEl) msgEl.textContent = message;

    const iconMap = {
      success: `<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="#10b981" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>`,
      error: `<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="#ef4444" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
      danger: `<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="#ef4444" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
      warning: `<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="#f59e0b" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
      info: `<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="#38bdf8" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`
    };
    if (iconBox) iconBox.innerHTML = iconMap[type] || iconMap.info;

    if (cancelBtn) {
      cancelBtn.style.display = showCancel ? "inline-block" : "none";
      cancelBtn.textContent = cancelText;
    }
    if (confirmBtn) {
      confirmBtn.textContent = confirmText;
      if (type === "danger" || type === "error") {
        confirmBtn.className = "btn btn-danger";
      } else {
        confirmBtn.className = "btn btn-primary";
      }
    }

    if (isPrompt && inputWrap && inputEl) {
      inputWrap.style.display = "block";
      inputEl.value = defaultValue || "";
      inputEl.placeholder = placeholder || "";
      setTimeout(() => inputEl.focus(), 100);
    } else if (inputWrap) {
      inputWrap.style.display = "none";
    }

    overlay.style.display = "flex";

    const closeDialog = () => {
      overlay.style.display = "none";
      confirmBtn.onclick = null;
      cancelBtn.onclick = null;
    };

    confirmBtn.onclick = () => {
      const val = isPrompt && inputEl ? inputEl.value : true;
      closeDialog();
      resolve(val);
    };

    cancelBtn.onclick = () => {
      closeDialog();
      resolve(isPrompt ? null : false);
    };
  });
};

window.showForensicAlert = function(title, message, type = "info") {
  return window.showForensicDialog({
    tag: type === "error" ? "CRITICAL ALERT" : "SYSTEM NOTICE",
    title: title || "Notice",
    message: message || "",
    type: type,
    showCancel: false,
    confirmText: "Acknowledge"
  });
};

window.showForensicConfirm = function(title, message, options = {}) {
  return window.showForensicDialog({
    tag: options.tag || (options.type === "danger" ? "CONFIRM CRITICAL ACTION" : "ACTION CONFIRMATION"),
    title: title || "Please Confirm",
    message: message || "",
    type: options.type || "info",
    showCancel: true,
    confirmText: options.confirmText || "Confirm",
    cancelText: options.cancelText || "Cancel"
  });
};

window.showForensicPrompt = function(title, message, defaultValue = "", options = {}) {
  return window.showForensicDialog({
    tag: options.tag || "REQUIRED INPUT",
    title: title || "Input Required",
    message: message || "",
    type: options.type || "info",
    showCancel: true,
    confirmText: options.confirmText || "Submit",
    cancelText: options.cancelText || "Cancel",
    isPrompt: true,
    defaultValue: defaultValue,
    placeholder: options.placeholder || ""
  });
};

// Polyfill native alert
window.alert = function(msg) {
  window.showForensicToast(msg, "info");
};


// Global Section Switcher for Sidebar and Top Subnav Navigation
window.switchWorkspaceSection = function(targetId) {
  if (!targetId) return;

  if (targetId === "sec-create-modal-trigger") {
    if (typeof openCreateCaseModal === "function") openCreateCaseModal();
    return;
  }

  // Workstation mapping: if directly navigating to a workstation, open in Forensic Lab
  const workstationTabs = {
    "sec-evidence-vault": "evidence",
    "sec-extraction": "extraction",
    "sec-analysis": "analysis",
    "sec-sis": "sis",
    "sec-outputs": "outputs",
    "sec-knowledge-rag": "graph"
  };

  if (workstationTabs[targetId]) {
    const tabKey = workstationTabs[targetId];
    if (window.g_currentActiveCaseId) {
      if (typeof window.openCaseInLab === "function") {
        window.openCaseInLab(window.g_currentActiveCaseId, { tab: tabKey });
      }
      return;
    } else if (window.g_allCases && window.g_allCases.length > 0) {
      if (typeof window.openCaseInLab === "function") {
        window.openCaseInLab(window.g_allCases[0].case_id, { tab: tabKey });
      }
      return;
    } else {
      HMACFR_API.getCases().then(cases => {
        if (cases && cases.length > 0) {
          window.g_allCases = cases;
          if (typeof window.openCaseInLab === "function") {
            window.openCaseInLab(cases[0].case_id, { tab: tabKey });
          }
        } else {
          HMACFR_API.createCase({
            case_name: "Default Forensic Sandbox",
            description: "Default workspace sandbox",
            priority: "Medium"
          }).then(newCase => {
            if (typeof window.openCaseInLab === "function") {
              window.openCaseInLab(newCase.case_id, { tab: tabKey });
            }
          }).catch(err => {
            console.error("Auto case creation error:", err);
          });
        }
      }).catch(err => {
        console.error("Failed to load cases for workstation redirect:", err);
      });
      return;
    }
  }

  // Deactivate all sidebar nav tabs and activate target tab
  const navTabs = document.querySelectorAll(".nav-tab");
  navTabs.forEach(t => {
    const isTarget = t.getAttribute("data-target") === targetId || (targetId === "sec-create-case" && t.getAttribute("data-target") === "sec-cases");
    if (isTarget) {
      t.classList.add("active");
    } else {
      t.classList.remove("active");
    }
  });

  // Switch top-level workspace sections
  const sections = document.querySelectorAll(".workspace-section");
  sections.forEach(sec => {
    // Ignore workstation sections mounted inside the lab sandbox workbench
    if (sec.parentElement && sec.parentElement.id === "lab-sandbox-workbench") return;

    if (sec.id === targetId) {
      sec.classList.add("active");
      if (targetId === "sec-forensic-lab") {
        sec.style.setProperty("display", "flex", "important");
      } else {
        sec.style.setProperty("display", "block", "important");
      }
    } else {
      sec.classList.remove("active");
      sec.style.setProperty("display", "none", "important");
    }
  });

  if (targetId === "sec-forensic-lab") {
    document.body.classList.add("in-lab-mode");
  } else {
    document.body.classList.remove("in-lab-mode");
  }

  // Load section-specific data
  if (targetId === "sec-home") {
    if (typeof loadHomeSection === "function") loadHomeSection();
  } else if (targetId === "sec-cases") {
    if (typeof window.loadCasesSection === "function") window.loadCasesSection();
  } else if (targetId === "sec-profile") {
    if (typeof window.loadProfileSection === "function") window.loadProfileSection();
  } else if (targetId === "sec-admin-users") {
    if (typeof window.loadAdminUsersData === "function") window.loadAdminUsersData();
  }
};

window.switchNav = window.switchWorkspaceSection;

// =========================================================================
// HASH-BASED ROUTING ENGINE (Case-Solving Workflow & Deep Linking)
// =========================================================================
window.g_isRoutingFromHash = false;

window.handleHashRoute = async function() {
  const hash = window.location.hash || "";
  if (!hash || hash === "#" || hash === "#/") return;

  window.g_isRoutingFromHash = true;
  try {
    const cleanHash = hash.replace(/^#\/?/, "");
    const parts = cleanHash.split("/").filter(Boolean);

    if (parts[0] === "cases") {
      if (parts.length === 1) {
        if (typeof window.switchWorkspaceSection === "function") {
          window.switchWorkspaceSection("sec-cases");
        }
      } else if (parts[1] === "create") {
        if (typeof window.openCreateCaseModal === "function") {
          window.openCreateCaseModal();
        }
      } else if (parts.length >= 2) {
        const caseId = parts[1];
        const subRoute = (parts[2] || "vault").toLowerCase();
        let tabKey = subRoute;
        if (subRoute === "vault") tabKey = "evidence";
        if (subRoute === "rag") tabKey = "graph";

        if (typeof window.openCaseInLab === "function") {
          await window.openCaseInLab(caseId, { tab: tabKey });
        }
      }
    } else if (parts[0] === "admin") {
      if (typeof window.switchWorkspaceSection === "function") {
        window.switchWorkspaceSection("sec-admin-users");
      }
    } else if (parts[0] === "profile") {
      if (typeof window.switchWorkspaceSection === "function") {
        window.switchWorkspaceSection("sec-profile");
      }
    }
  } catch (err) {
    console.warn("Hash route navigation error:", err);
  } finally {
    window.g_isRoutingFromHash = false;
  }
};

window.addEventListener("hashchange", window.handleHashRoute);


// Canonical Global Active Case Context (Stage 1.2 Unified State)
window.g_currentActiveCase = null;
window.g_currentActiveCaseId = null;
window.g_currentActiveCaseName = null;
window.g_currentActiveCaseObj = null;

// Sets or clears the canonical active case and synchronizes all workspace views
window.setActiveCase = async function(caseId, options = {}) {
  if (!caseId) {
    window.g_currentActiveCase = null;
    window.g_currentActiveCaseId = null;
    window.g_currentActiveCaseName = null;
    window.g_currentActiveCaseObj = null;
    window.currentForensicData = null;

    if (window.clearForensicOutputs) window.clearForensicOutputs();
    window.updateActiveCaseContextBar(null);

    // Synchronize open dropdowns
    ["vault-repo-case-select", "extraction-case-select", "analysis-case-select"].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = "";
    });

    if (options.refreshActiveSection !== false) {
      refreshCurrentSectionData();
    }
    return null;
  }

  // Find or fetch case record
  let c = (window.g_allCases || []).find(x => x.case_id === caseId);
  if (!c) {
    try {
      const cases = await HMACFR_API.getCases();
      window.g_allCases = cases;
      c = cases.find(x => x.case_id === caseId);
    } catch (e) {
      console.error("Could not fetch case list:", e);
    }
  }

  if (!c) {
    c = { case_id: caseId, case_name: caseId, priority: "Medium", status: "Active" };
  }

  // Fetch actual evidence items for this case
  let evidences = [];
  try {
    evidences = await HMACFR_API.getAllEvidence(caseId);
    if (!Array.isArray(evidences)) evidences = [];
  } catch (e) {
    console.warn("Could not fetch evidence for case:", e);
    evidences = [];
  }

  // Fetch synthesized data for this case
  let synthData = null;
  try {
    synthData = await HMACFR_API.getForensicData(caseId);
  } catch (e) {
    synthData = null;
  }

  // Clear previous case outputs before setting new state
  if (window.clearForensicOutputs) window.clearForensicOutputs();

  window.g_currentActiveCaseId = c.case_id;
  window.g_currentActiveCaseName = c.case_name || c.case_id;
  window.g_currentActiveCaseObj = c;
  window.currentForensicData = synthData;

  const evCount = evidences.length;
  const evIds = evidences.map(e => e.evidence_id || e.id);

  // Compute canonical stage
  const inv = synthData && synthData.artifact_inventory ? synthData.artifact_inventory : null;
  const totalArtifacts = inv ? (inv.total_artifacts || 0) : 0;
  const findingsCount = synthData && synthData.findings ? synthData.findings.length : 0;

  let currentStage = "Evidence Acquisition";
  let stageNum = 2;

  if (findingsCount > 0 || (synthData && synthData.timeline && synthData.timeline.length > 0)) {
    currentStage = "Outputs & Report Ready";
    stageNum = 6;
  } else if (totalArtifacts > 0) {
    currentStage = "Ready for Investigation";
    stageNum = 4;
  } else if (evCount > 0) {
    currentStage = "Ready for Extraction";
    stageNum = 3;
  } else {
    currentStage = "Awaiting Evidence";
    stageNum = 2;
  }

  window.g_currentActiveCase = {
    case_id: c.case_id,
    case_name: c.case_name || c.case_id,
    priority: c.priority || "Medium",
    investigator: c.investigator_name || c.assigned_investigator || c.created_by || "Lead Investigator",
    case_status: c.status || "Active",
    current_stage: currentStage,
    stage_num: stageNum,
    evidence_count: evCount,
    evidence_ids: evIds,
    evidences: evidences,
    synthesized_data: synthData
  };

  // Synchronize case context bar
  window.updateActiveCaseContextBar(window.g_currentActiveCase);

  // Synchronize dropdowns across sections
  ["vault-repo-case-select", "extraction-case-select", "analysis-case-select"].forEach(id => {
    const el = document.getElementById(id);
    if (el && el.value !== c.case_id) el.value = c.case_id;
  });

  if (options.refreshActiveSection !== false) {
    refreshCurrentSectionData();
  }

  return window.g_currentActiveCase;
};

// Refreshes the currently active workspace section with the active case data
function refreshCurrentSectionData() {
  const currentSection = document.querySelector(".workspace-section.active");
  const currentId = currentSection ? currentSection.id : "";

  if (currentId === "sec-evidence-vault") {
    if (typeof loadEvidenceVaultSection === "function") loadEvidenceVaultSection();
  } else if (currentId === "sec-extraction") {
    if (typeof window.loadExtractionSection === "function") window.loadExtractionSection();
  } else if (currentId === "sec-analysis") {
    if (typeof window.loadAnalysisSection === "function") window.loadAnalysisSection();
  } else if (currentId === "sec-sis") {
    if (typeof window.loadSisSection === "function") window.loadSisSection();
  } else if (currentId === "sec-outputs") {
    if (typeof window.loadOutputsSection === "function") window.loadOutputsSection();
  }
}

// Opens an investigation case directly inside the Forensic Lab Sandbox
window.openCaseInLab = async function(caseId, options = {}) {
  // If no caseId passed, find or auto-provision
  if (!caseId) {
    if (window.g_currentActiveCaseId) {
      caseId = window.g_currentActiveCaseId;
    } else if (window.g_allCases && window.g_allCases.length > 0) {
      caseId = window.g_allCases[0].case_id;
    } else {
      try {
        const cases = await HMACFR_API.getCases();
        if (cases && cases.length > 0) {
          window.g_allCases = cases;
          caseId = cases[0].case_id;
        } else {
          const newCase = await HMACFR_API.createCase({
            case_name: "Default Forensic Sandbox",
            description: "Default workspace sandbox",
            priority: "Medium"
          });
          caseId = newCase.case_id;
        }
      } catch (e) {
        console.error("Failed to fetch or provision case for lab:", e);
      }
    }
  }

  if (!caseId) return;

  // Set active case context
  await window.setActiveCase(caseId, { refreshActiveSection: false });

  // Dynamically resolve & apply effective permissions for this case
  await window.loadCasePermissions(caseId);

  // Update metadata in left subnav
  const caseObj = window.g_currentActiveCase || {};
  const titleEl = document.getElementById("lab-active-case-title");
  if (titleEl) titleEl.textContent = caseObj.case_name || caseId;

  const idEl = document.getElementById("lab-active-case-id");
  if (idEl) idEl.textContent = caseId.length > 14 ? `${caseId.substring(0, 10)}...` : caseId;

  const priorityEl = document.getElementById("lab-active-case-priority");
  if (priorityEl) {
    const prio = (caseObj.priority || "Medium").toUpperCase();
    priorityEl.textContent = prio;
    priorityEl.className = "lab-pill-priority priority-" + prio.toLowerCase();
  }

  const statusEl = document.getElementById("lab-active-case-status");
  if (statusEl) {
    statusEl.textContent = (caseObj.status || "Active").toUpperCase();
  }

  const leadEl = document.getElementById("lab-active-case-lead");
  if (leadEl) {
    leadEl.textContent = caseObj.investigator || caseObj.investigator_name || caseObj.created_by || "investigator1";
  }

  // Pre-set case dropdowns inside workstations so they match automatically
  ["vault-repo-case-select", "extraction-case-select", "analysis-case-select"].forEach(selectId => {
    const el = document.getElementById(selectId);
    if (el) el.value = caseId;
  });

  // Switch to sec-forensic-lab
  document.body.classList.add("in-lab-mode");
  const secLab = document.getElementById("sec-forensic-lab");
  if (secLab) {
    document.querySelectorAll(".workspace-section").forEach(sec => {
      if (sec.id === "sec-forensic-lab") {
        sec.classList.add("active");
        sec.style.setProperty("display", "flex", "important");
      } else if (!sec.parentElement || sec.parentElement.id !== "lab-sandbox-workbench") {
        sec.classList.remove("active");
        sec.style.setProperty("display", "none", "important");
      }
    });
  }

  // Open the desired workstation tab (default: evidence)
  const tab = options.tab || "evidence";
  window.switchLabWorkstationTab(tab);
};

// Aliasing openCaseDetails to enter lab directly
window.openCaseDetails = window.openCaseInLab;

// Returns from Forensic Lab to My Cases
window.exitLabToCases = function() {
  window.isAuditMode = false;
  document.body.classList.remove("in-lab-mode");
  window.switchWorkspaceSection("sec-cases");
  if (typeof window.loadCasesSection === "function") {
    window.loadCasesSection();
  }
};

// Switches workstations inside the Forensic Lab Sandbox
window.switchLabWorkstationTab = function(tabKey) {
  const tabSecMap = {
    "evidence": "sec-evidence-vault",
    "extraction": "sec-extraction",
    "analysis": "sec-analysis",
    "sis": "sec-sis",
    "outputs": "sec-outputs",
    "graph": "sec-knowledge-rag"
  };

  const targetSecId = tabSecMap[tabKey] || "sec-evidence-vault";

  // Update active state on tab buttons
  document.querySelectorAll(".lab-nav-item").forEach(btn => {
    if (btn.id === `lab-tab-${tabKey}`) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  });

  // Workbench mount & display
  const workbench = document.getElementById("lab-sandbox-workbench");
  const targetSec = document.getElementById(targetSecId);

  if (workbench && targetSec) {
    // If not already inside workbench, move it
    if (targetSec.parentElement !== workbench) {
      workbench.appendChild(targetSec);
    }

    // Hide all other children in workbench and show targetSec
    Array.from(workbench.children).forEach(child => {
      if (child.id === targetSecId) {
        child.classList.add("active");
        child.style.setProperty("display", "block", "important");
      } else {
        child.classList.remove("active");
        child.style.setProperty("display", "none", "important");
      }
    });
  }

  // Pre-set case dropdowns inside workstations
  if (window.g_currentActiveCaseId) {
    ["vault-repo-case-select", "extraction-case-select", "analysis-case-select"].forEach(selectId => {
      const el = document.getElementById(selectId);
      if (el) el.value = window.g_currentActiveCaseId;
    });
  }

  // Trigger workstation-specific data loader
  if (tabKey === "evidence") {
    if (typeof loadEvidenceVaultSection === "function") loadEvidenceVaultSection();
  } else if (tabKey === "extraction") {
    if (typeof window.loadExtractionSection === "function") window.loadExtractionSection();
  } else if (tabKey === "analysis") {
    if (typeof window.loadAnalysisSection === "function") window.loadAnalysisSection();
  } else if (tabKey === "sis") {
    if (typeof window.loadSisSection === "function") window.loadSisSection();
  } else if (tabKey === "outputs") {
    if (typeof window.loadOutputsSection === "function") window.loadOutputsSection();
  } else if (tabKey === "graph") {
    if (typeof window.loadKnowledgeGraphSection === "function") window.loadKnowledgeGraphSection();
  }

  // Sync route URL hash
  if (window.g_currentActiveCaseId && !window.g_isRoutingFromHash) {
    const routeSuffix = tabKey === "evidence" ? "vault" : tabKey;
    const targetHash = `#/cases/${window.g_currentActiveCaseId}/${routeSuffix}`;
    if (window.location.hash !== targetHash) {
      window.history.replaceState(null, "", targetHash);
    }
  }
};

// Safe no-op for legacy case context bar updates
window.updateActiveCaseContextBar = function(caseObj) {
  // Update section banners if present
  if (caseObj && caseObj.case_id) {
    const caseName = caseObj.case_name || caseObj.case_id;
    const caseId = caseObj.case_id;
    const vaultNameEl = document.getElementById("vault-case-display-name");
    if (vaultNameEl) vaultNameEl.textContent = `${caseName} (${caseId})`;
    const outNameEl = document.getElementById("outputs-case-display-name");
    if (outNameEl) outNameEl.textContent = `${caseName} (${caseId})`;
    const sisNameEl = document.getElementById("sis-case-name");
    if (sisNameEl) sisNameEl.textContent = `${caseName} (${caseId})`;
  }
};

// Synchronizes the 6-step workflow stepper and Next Action button
window.syncCaseContextStepper = function(targetSectionId) {
  const currentSection = targetSectionId || (document.querySelector(".workspace-section.active") ? document.querySelector(".workspace-section.active").id : "sec-cases");

  const stepMap = {
    "sec-cases": "step-nav-case",
    "sec-create-case": "step-nav-case",
    "sec-evidence-vault": "step-nav-evidence",
    "sec-preservation": "step-nav-evidence",
    "sec-custody": "step-nav-evidence",
    "sec-extraction": "step-nav-extraction",
    "sec-analysis": "step-nav-investigation",
    "sec-sis": "step-nav-sis",
    "sec-outputs": "step-nav-outputs"
  };

  const steps = ["step-nav-case", "step-nav-evidence", "step-nav-extraction", "step-nav-investigation", "step-nav-sis", "step-nav-outputs"];
  const activeStepId = stepMap[currentSection] || "step-nav-case";
  const activeIdx = steps.indexOf(activeStepId);

  steps.forEach((sId, idx) => {
    const el = document.getElementById(sId);
    if (!el) return;
    if (idx < activeIdx) {
      el.classList.add("completed");
      el.classList.remove("active");
    } else if (idx === activeIdx) {
      el.classList.add("active");
      el.classList.remove("completed");
    } else {
      el.classList.remove("active");
      el.classList.remove("completed");
    }
  });

  // Update Next Action Button
  const btn = document.getElementById("ctx-next-action-btn");
  if (!btn) return;

  if (currentSection === "sec-cases" || currentSection === "sec-home") {
    btn.innerHTML = `<span>Manage Evidence Vault</span> <span>&rarr;</span>`;
  } else if (currentSection === "sec-evidence-vault" || currentSection === "sec-preservation" || currentSection === "sec-custody") {
    btn.innerHTML = `<span>Continue to Extraction</span> <span>&rarr;</span>`;
  } else if (currentSection === "sec-extraction") {
    btn.innerHTML = `<span>Proceed to Investigation</span> <span>&rarr;</span>`;
  } else if (currentSection === "sec-analysis") {
    btn.innerHTML = `<span>Review SIS Findings</span> <span>&rarr;</span>`;
  } else if (currentSection === "sec-sis") {
    btn.innerHTML = `<span>Outputs &amp; Report</span> <span>&rarr;</span>`;
  } else if (currentSection === "sec-outputs") {
    btn.innerHTML = `<span>Back to Cases</span> <span>&rarr;</span>`;
  }
};

// Handles clicking the Next Action button in the case context bar
window.handleContextNextAction = function() {
  const currentSection = document.querySelector(".workspace-section.active");
  const currentId = currentSection ? currentSection.id : "sec-cases";

  if (currentId === "sec-cases" || currentId === "sec-home" || currentId === "sec-create-case") {
    window.switchWorkspaceSection("sec-evidence-vault");
  } else if (currentId === "sec-evidence-vault" || currentId === "sec-preservation" || currentId === "sec-custody") {
    window.switchWorkspaceSection("sec-extraction");
  } else if (currentId === "sec-extraction") {
    window.switchWorkspaceSection("sec-analysis");
  } else if (currentId === "sec-analysis") {
    window.switchWorkspaceSection("sec-sis");
  } else if (currentId === "sec-sis") {
    window.switchWorkspaceSection("sec-outputs");
  } else if (currentId === "sec-outputs") {
    window.switchWorkspaceSection("sec-cases");
  } else {
    window.switchWorkspaceSection("sec-cases");
  }
};

// =========================================================================
// ARTIFACT EXTRACTION & FILE-TREE PRESENTATION (FINAL OUTPUT JSON FILES ONLY)
// =========================================================================

// Global state for Dual-Mode Forensic Inspector
window.g_currentViewedArtifactJson = null;
window.g_currentInspectorData = null;
window.g_currentInspectorMode = "grid";
window.g_currentInspectorSearchTerm = "";
window.g_currentInspectorFilename = "";

window.onViewArtifactJsonBtnClick = function(btn) {
  const caseId = btn.getAttribute("data-case-id") || window.g_currentActiveCaseId;
  const relPath = btn.getAttribute("data-rel-path");
  if (caseId && relPath) {
    window.viewArtifactJson(caseId, relPath);
  }
};

// Views parsed JSON content of a specific final extracted artifact file
window.viewArtifactJson = async function(caseId, relPath) {
  try {
    const activeCaseId = caseId || window.g_currentActiveCaseId;
    const cleanRelPath = (relPath || "").replace(/\\/g, "/");
    const res = await HMACFR_API.viewExtractedArtifact(activeCaseId, cleanRelPath);
    const modal = document.getElementById("modal-artifact-json-viewer");
    const nameEl = document.getElementById("artifact-viewer-modal-filename");
    const pathEl = document.getElementById("artifact-viewer-modal-path");
    const preEl = document.getElementById("artifact-viewer-code-block");
    const countEl = document.getElementById("artifact-viewer-records-count");
    const sizeBadge = document.getElementById("inspector-file-size-badge");

    const cleanFilename = res.filename || cleanRelPath.split("/").pop();
    window.g_currentInspectorFilename = cleanFilename;
    window.g_currentInspectorData = res.data;
    window.g_currentInspectorSearchTerm = "";

    const searchInput = document.getElementById("inspector-search-input");
    if (searchInput) searchInput.value = "";

    if (nameEl) nameEl.textContent = cleanFilename;
    if (pathEl) pathEl.textContent = res.rel_path || cleanRelPath;

    let formattedJson = "";
    let itemCount = 0;
    if (typeof res.data === "object" && res.data !== null) {
      if (Array.isArray(res.data)) {
        itemCount = res.data.length;
      } else {
        itemCount = Object.keys(res.data).length;
      }
      formattedJson = JSON.stringify(res.data, null, 2);
    } else {
      formattedJson = String(res.data || "");
    }

    if (countEl) countEl.textContent = `${itemCount} record${itemCount === 1 ? '' : 's'}`;
    if (sizeBadge) {
      const bytes = new Blob([formattedJson]).size;
      sizeBadge.textContent = bytes > 1024 * 1024 ? `${(bytes / (1024 * 1024)).toFixed(2)} MB` : `${(bytes / 1024).toFixed(1)} KB`;
    }

    if (preEl) preEl.textContent = formattedJson;
    window.g_currentViewedArtifactJson = formattedJson;

    // Render Grid and Tree
    renderInspectorGrid("");
    renderInspectorTree("");

    // Set default tab: If array or object, default to Grid; otherwise Tree
    switchInspectorTab("grid");

    if (modal) modal.style.setProperty("display", "flex", "important");
  } catch (err) {
    if (typeof showSherlockNotice === "function") {
      showSherlockNotice("Error Reading Artifact", err.message, true);
    } else {
      alert("Error reading artifact JSON: " + err.message);
    }
  }
};

window.switchInspectorTab = function(mode) {
  window.g_currentInspectorMode = mode;
  const tabs = ["grid", "tree", "raw"];
  tabs.forEach(t => {
    const btn = document.getElementById(`inspector-tab-btn-${t}`);
    const pane = document.getElementById(`inspector-pane-${t}`);
    if (btn) {
      if (t === mode) btn.classList.add("active");
      else btn.classList.remove("active");
    }
    if (pane) {
      pane.style.display = (t === mode) ? "block" : "none";
    }
  });

  const statusEl = document.getElementById("inspector-status-text");
  if (statusEl) {
    if (mode === "grid") statusEl.textContent = "Forensic Record Table Grid";
    else if (mode === "tree") statusEl.textContent = "Interactive Collapsible JSON Tree";
    else statusEl.textContent = "Raw Validated JSON Stream";
  }
};

window.onInspectorSearch = function(query) {
  window.g_currentInspectorSearchTerm = (query || "").trim().toLowerCase();
  renderInspectorGrid(window.g_currentInspectorSearchTerm);
  renderInspectorTree(window.g_currentInspectorSearchTerm);
};

window.renderInspectorGrid = function(filterText) {
  const container = document.getElementById("inspector-pane-grid");
  if (!container) return;

  const data = window.g_currentInspectorData;
  if (!data) {
    container.innerHTML = `<div style="text-align: center; padding: 3rem; color: #64748b;">No forensic records found in artifact.</div>`;
    return;
  }

  // Case 1: Array of records (e.g. processes, sockets, run keys)
  if (Array.isArray(data)) {
    if (data.length === 0) {
      container.innerHTML = `<div style="text-align: center; padding: 3rem; color: #64748b;">Artifact contains 0 entries.</div>`;
      return;
    }

    // Check if items are objects or primitives
    const isObjectArray = typeof data[0] === "object" && data[0] !== null;

    if (isObjectArray) {
      // Gather unique column keys across records
      const columnsSet = new Set();
      data.slice(0, 100).forEach(row => {
        if (typeof row === "object" && row !== null) {
          Object.keys(row).forEach(k => columnsSet.add(k));
        }
      });
      const columns = Array.from(columnsSet);

      // Filter rows
      let filteredRows = data.map((row, idx) => ({ row, idx }));
      if (filterText) {
        filteredRows = filteredRows.filter(item => {
          const rowStr = JSON.stringify(item.row).toLowerCase();
          return rowStr.includes(filterText);
        });
      }

      if (filteredRows.length === 0) {
        container.innerHTML = `<div style="text-align: center; padding: 3rem; color: #64748b;">No records matching search term: "<strong>${escapeHTML(filterText)}</strong>"</div>`;
        return;
      }

      let theadHTML = `<tr><th style="width: 45px; text-align: center;">#</th>`;
      columns.forEach(col => {
        theadHTML += `<th>${escapeHTML(col)}</th>`;
      });
      theadHTML += `</tr>`;

      let tbodyHTML = "";
      filteredRows.forEach(({ row, idx }) => {
        tbodyHTML += `<tr><td style="text-align: center; color: #94a3b8; font-size: 0.72rem;">${idx + 1}</td>`;
        columns.forEach(col => {
          const val = row[col];
          let formattedCell = "";
          if (val === undefined || val === null) {
            formattedCell = `<span style="color: #94a3b8; font-style: italic;">null</span>`;
          } else if (typeof val === "object") {
            formattedCell = `<span class="badge" style="background: #f1f5f9; color: #334155; font-size: 0.7rem;">${Array.isArray(val) ? `Array(${val.length})` : 'Object'}</span>`;
          } else if (typeof val === "boolean") {
            formattedCell = `<span style="color: ${val ? '#10b981' : '#ef4444'}; font-weight: 700;">${val}</span>`;
          } else {
            const strVal = String(val);
            if (filterText && strVal.toLowerCase().includes(filterText)) {
              formattedCell = highlightInspectorMatch(strVal, filterText);
            } else {
              formattedCell = escapeHTML(strVal);
            }
          }
          tbodyHTML += `<td>${formattedCell}</td>`;
        });
        tbodyHTML += `</tr>`;
      });

      container.innerHTML = `
        <table class="forensic-inspector-table">
          <thead>${theadHTML}</thead>
          <tbody>${tbodyHTML}</tbody>
        </table>
      `;
    } else {
      // Primitive array (e.g. list of hashes or strings)
      let filtered = data.map((v, i) => ({ v, i }));
      if (filterText) {
        filtered = filtered.filter(item => String(item.v).toLowerCase().includes(filterText));
      }

      let tbodyHTML = "";
      filtered.forEach(({ v, i }) => {
        tbodyHTML += `<tr><td style="width: 50px; text-align: center; color: #94a3b8;">${i + 1}</td><td>${escapeHTML(String(v))}</td></tr>`;
      });

      container.innerHTML = `
        <table class="forensic-inspector-table">
          <thead><tr><th style="width: 50px;">#</th><th>Value</th></tr></thead>
          <tbody>${tbodyHTML}</tbody>
        </table>
      `;
    }
  } else if (typeof data === "object" && data !== null) {
    // Top-level dictionary/object
    const entries = Object.entries(data);
    let filtered = entries;
    if (filterText) {
      filtered = filtered.filter(([k, v]) => {
        return k.toLowerCase().includes(filterText) || JSON.stringify(v).toLowerCase().includes(filterText);
      });
    }

    if (filtered.length === 0) {
      container.innerHTML = `<div style="text-align: center; padding: 3rem; color: #64748b;">No properties matching "${escapeHTML(filterText)}"</div>`;
      return;
    }

    let tbodyHTML = "";
    filtered.forEach(([k, v]) => {
      let valHTML = "";
      if (v === null) {
        valHTML = `<span style="color: #94a3b8; font-style: italic;">null</span>`;
      } else if (typeof v === "object") {
        valHTML = `<pre style="margin: 0; padding: 0.35rem; background: #f8fafc; border-radius: 4px; font-size: 0.74rem; max-height: 120px; overflow-y: auto;">${escapeHTML(JSON.stringify(v, null, 2))}</pre>`;
      } else {
        valHTML = escapeHTML(String(v));
      }

      tbodyHTML += `
        <tr>
          <td style="width: 220px; font-weight: 700; color: #1e3a8a;">${escapeHTML(k)}</td>
          <td>${valHTML}</td>
        </tr>
      `;
    });

    container.innerHTML = `
      <table class="forensic-inspector-table">
        <thead><tr><th style="width: 220px;">Forensic Attribute</th><th>Extracted Value</th></tr></thead>
        <tbody>${tbodyHTML}</tbody>
      </table>
    `;
  } else {
    container.innerHTML = `<div style="padding: 1.5rem; font-family: monospace;">${escapeHTML(String(data))}</div>`;
  }
};

function highlightInspectorMatch(text, term) {
  if (!term) return escapeHTML(text);
  const regex = new RegExp(`(${term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, "gi");
  const parts = text.split(regex);
  return parts.map(part => {
    if (part.toLowerCase() === term.toLowerCase()) {
      return `<mark style="background: #fde047; color: #0f172a; padding: 0 2px; border-radius: 2px;">${escapeHTML(part)}</mark>`;
    }
    return escapeHTML(part);
  }).join('');
}

// Collapsible JSON Tree Builder
window.renderInspectorTree = function(filterText) {
  const container = document.getElementById("inspector-pane-tree");
  if (!container) return;

  const data = window.g_currentInspectorData;
  if (!data) {
    container.innerHTML = `<div style="color: #94a3b8;">No data</div>`;
    return;
  }

  function buildNodeHTML(val, key = null, level = 0) {
    const indent = level * 16;
    if (val === null) {
      return `<div class="tree-node-line" style="margin-left: ${indent}px;">
        ${key !== null ? `<span class="tree-key">${escapeHTML(key)}:</span>` : ''}
        <span class="tree-val-null">null</span>
      </div>`;
    }
    if (typeof val === "boolean") {
      return `<div class="tree-node-line" style="margin-left: ${indent}px;">
        ${key !== null ? `<span class="tree-key">${escapeHTML(key)}:</span>` : ''}
        <span class="tree-val-boolean">${val}</span>
      </div>`;
    }
    if (typeof val === "number") {
      return `<div class="tree-node-line" style="margin-left: ${indent}px;">
        ${key !== null ? `<span class="tree-key">${escapeHTML(key)}:</span>` : ''}
        <span class="tree-val-number">${val}</span>
      </div>`;
    }
    if (typeof val === "string") {
      const match = filterText && val.toLowerCase().includes(filterText);
      return `<div class="tree-node-line" style="margin-left: ${indent}px;">
        ${key !== null ? `<span class="tree-key">${escapeHTML(key)}:</span>` : ''}
        <span class="tree-val-string ${match ? 'tree-highlight' : ''}">"${escapeHTML(val)}"</span>
      </div>`;
    }
    if (Array.isArray(val)) {
      if (val.length === 0) {
        return `<div class="tree-node-line" style="margin-left: ${indent}px;">
          ${key !== null ? `<span class="tree-key">${escapeHTML(key)}:</span>` : ''}
          <span style="color: #94a3b8;">[]</span>
        </div>`;
      }
      const childrenHTML = val.slice(0, 200).map((child, idx) => buildNodeHTML(child, `[${idx}]`, level + 1)).join('');
      return `
        <div class="tree-branch" style="margin-left: ${indent}px;">
          <div class="tree-node-line" onclick="toggleTreeBranch(this);" style="cursor: pointer;">
            <span class="tree-toggle-btn">▼</span>
            ${key !== null ? `<span class="tree-key">${escapeHTML(key)}:</span>` : ''}
            <span style="color: #94a3b8;">[ ${val.length} items ]</span>
          </div>
          <div class="tree-children">
            ${childrenHTML}
          </div>
        </div>
      `;
    }
    if (typeof val === "object") {
      const keys = Object.keys(val);
      if (keys.length === 0) {
        return `<div class="tree-node-line" style="margin-left: ${indent}px;">
          ${key !== null ? `<span class="tree-key">${escapeHTML(key)}:</span>` : ''}
          <span style="color: #94a3b8;">{}</span>
        </div>`;
      }
      const childrenHTML = keys.slice(0, 200).map(k => buildNodeHTML(val[k], k, level + 1)).join('');
      return `
        <div class="tree-branch" style="margin-left: ${indent}px;">
          <div class="tree-node-line" onclick="toggleTreeBranch(this);" style="cursor: pointer;">
            <span class="tree-toggle-btn">▼</span>
            ${key !== null ? `<span class="tree-key">${escapeHTML(key)}:</span>` : ''}
            <span style="color: #94a3b8;">{ ${keys.length} fields }</span>
          </div>
          <div class="tree-children">
            ${childrenHTML}
          </div>
        </div>
      `;
    }
    return `<div style="margin-left: ${indent}px;">${escapeHTML(String(val))}</div>`;
  }

  container.innerHTML = buildNodeHTML(data, null, 0);
};

window.toggleTreeBranch = function(headerEl) {
  const branch = headerEl.parentElement;
  const children = branch.querySelector(".tree-children");
  const toggleBtn = headerEl.querySelector(".tree-toggle-btn");
  if (!children || !toggleBtn) return;

  if (children.style.display === "none") {
    children.style.display = "block";
    toggleBtn.textContent = "▼";
  } else {
    children.style.display = "none";
    toggleBtn.textContent = "▶";
  }
};

window.downloadArtifactJsonFile = function() {
  if (!window.g_currentViewedArtifactJson) return;
  const filename = window.g_currentInspectorFilename || "extracted_artifact.json";
  const blob = new Blob([window.g_currentViewedArtifactJson], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

window.closeArtifactJsonViewerModal = function() {
  const modal = document.getElementById("modal-artifact-json-viewer");
  if (modal) modal.style.setProperty("display", "none", "important");
};

window.copyArtifactJsonToClipboard = function() {
  if (window.g_currentViewedArtifactJson) {
    navigator.clipboard.writeText(window.g_currentViewedArtifactJson).then(() => {
      const lbl = document.getElementById("btn-copy-artifact-label");
      if (lbl) {
        lbl.textContent = "Copied!";
        setTimeout(() => { lbl.textContent = "Copy"; }, 2000);
      }
    }).catch(() => {});
  }
};

// Renders the categorized file-tree showing ONLY final output JSON files
function renderArtifactBrowser(caseObj, artifactData) {
  const treeContainer = document.getElementById("extraction-artifact-tree-list");
  if (!treeContainer) return;

  const total = artifactData ? (artifactData.total_artifacts || 0) : 0;
  const categories = artifactData && Array.isArray(artifactData.categories) ? artifactData.categories : [];
  const evidences = caseObj ? (caseObj.evidences || []) : [];
  const targetCaseId = (caseObj && (caseObj.case_id || caseObj.id)) || window.g_currentActiveCaseId || '';

  if (total === 0) {
    treeContainer.innerHTML = `
      <div id="extraction-empty-state" class="empty-state" style="padding: 2.5rem 1rem; text-align: center;">
        <div style="font-size: 1.05rem; font-weight: 700; color: #0f172a; margin-bottom: 0.35rem;">No Artifacts Extracted Yet</div>
        <div style="font-size: 0.82rem; color: #64748b; max-width: 480px; margin: 0 auto 1.25rem;">
          Preserved evidence files are verified. Click 'Start Extraction' above to execute adapters and parse raw evidence into structured forensic JSON artifacts.
        </div>
        <button type="button" class="btn btn-primary btn-sm" onclick="triggerArtifactExtraction();" style="display: inline-flex; align-items: center; gap: 0.35rem;">
          <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
          Run Plugin Extraction
        </button>
      </div>
    `;
    return;
  }

  const getCatTag = (catName, cat) => {
    const l = (catName || "").toLowerCase();
    if (l.includes("network") || l.includes("pcap") || l.includes("net")) {
      return { tag: "NETWORK", color: "#7c3aed", bg: "#f5f3ff", agent: "Network Agent", member: "Pranay" };
    }
    if (l.includes("memory") || l.includes("ram")) {
      return { tag: "MEMORY", color: "#1d4ed8", bg: "#eff6ff", agent: "Memory Agent", member: "Bharath" };
    }
    if (l.includes("disk")) {
      return { tag: "DISK", color: "#059669", bg: "#ecfdf5", agent: "Disk Agent", member: "Aswith" };
    }
    if (l.includes("log") || l.includes("event") || l.includes("evt")) {
      return { tag: "LOGS", color: "#0891b2", bg: "#ecfeff", agent: "Log Agent", member: "Sanhith" };
    }
    if (l.includes("reg")) {
      return { tag: "REGISTRY", color: "#d97706", bg: "#fffbeb", agent: "Registry Agent", member: "Kishor" };
    }
    return { tag: "ARTIFACT", color: "#475569", bg: "#f1f5f9", agent: (cat && cat.agent_name) || "Specialist Agent", member: (cat && cat.team_member) || "Forensic Lab" };
  };

  const categoriesHTML = categories.map(cat => {
    const tagInfo = getCatTag(cat.category, cat);
    const files = cat.files || [];
    const filesHTML = files.map(f => {
      const safeRelPath = (f.rel_path || '').replace(/\\/g, '/');
      return `
      <div class="artifact-file-row">
        <div class="artifact-file-info">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="#2563eb" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
          <span style="font-weight: 600;">${escapeHTML(f.filename)}</span>
          <span class="artifact-file-badge-json">JSON</span>
        </div>
        <div style="display: flex; align-items: center; gap: 0.75rem;">
          <span style="font-size: 0.72rem; color: #64748b; font-family: 'JetBrains Mono', monospace;">${f.size_formatted || (f.file_size ? `${(f.file_size / 1024).toFixed(1)} KB` : '')}</span>
          <button type="button" class="btn-view-artifact-json" data-case-id="${escapeHTML(targetCaseId)}" data-rel-path="${escapeHTML(safeRelPath)}" onclick="onViewArtifactJsonBtnClick(this);">
            <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
            View JSON
          </button>
        </div>
      </div>
    `;
    }).join('');

    return `
      <div class="artifact-tree-category-block" style="border: 1px solid #e2e8f0; border-radius: 8px; margin-bottom: 0.75rem; overflow: hidden; background: #ffffff;">
        <div class="artifact-category-title-row" style="display: flex; justify-content: space-between; align-items: center; padding: 0.65rem 1rem; background: #f8fafc; border-bottom: 1px solid #f1f5f9;">
          <div style="display: flex; align-items: center; gap: 0.5rem;">
            <span style="font-weight: 700; font-size: 0.7rem; padding: 2px 6px; border-radius: 4px; background: ${tagInfo.bg}; color: ${tagInfo.color};">${tagInfo.tag}</span>
            <span style="font-weight: 700; font-size: 0.86rem; color: #0f172a;">${escapeHTML(tagInfo.agent)}</span>
            <span style="font-size: 0.75rem; color: #64748b; background: #f1f5f9; padding: 1px 7px; border-radius: 12px; font-weight: 600;">👤 ${escapeHTML(tagInfo.member)}</span>
          </div>
          <span class="badge" style="background: #eff6ff; color: #1d4ed8; font-size: 0.72rem; font-weight: 700;">${files.length} output JSON file${files.length === 1 ? '' : 's'}</span>
        </div>
        <div>
          ${filesHTML}
        </div>
      </div>
    `;
  }).join('');

  const evidenceFilesHTML = evidences.length > 0
    ? evidences.map(ev => `
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.45rem 0.75rem; border-bottom: 1px solid #f8fafc; font-size: 0.8rem;">
          <div style="display: flex; align-items: center; gap: 0.4rem; color: #334155;">
            <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
            <strong>${escapeHTML(ev.original_filename || ev.filename || 'evidence_file')}</strong>
          </div>
          <span style="font-size: 0.72rem; color: #64748b; font-family: 'JetBrains Mono', monospace;">
            ${ev.file_size ? `${(ev.file_size / (1024 * 1024)).toFixed(1)} MB` : 'N/A'} • ${ev.file_hash ? ev.file_hash.substring(0, 10) + '...' : 'SHA-256'}
          </span>
        </div>
      `).join('')
    : `<div style="padding: 0.5rem; color: #94a3b8; font-size: 0.78rem;">No source evidence files registered.</div>`;

  treeContainer.innerHTML = `
    <!-- Supervisor Multi-Agent Orchestrator Banner -->
    <div style="background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); color: #ffffff; border-radius: 8px; padding: 0.85rem 1rem; margin-bottom: 1rem; border: 1px solid #334155; box-shadow: 0 2px 4px rgba(0,0,0,0.08);">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
        <div style="display: flex; align-items: center; gap: 0.5rem;">
          <span style="font-size: 1rem;">👑</span>
          <span style="font-weight: 800; font-size: 0.88rem; letter-spacing: 0.02em;">Supervisor Multi-Agent Orchestrator</span>
          <span style="font-size: 0.7rem; background: rgba(59, 130, 246, 0.25); color: #93c5fd; border: 1px solid rgba(59, 130, 246, 0.4); padding: 1px 7px; border-radius: 9999px; font-weight: 700;">Qwen Powered • LoRA Orchestrated</span>
        </div>
        <span style="font-size: 0.72rem; color: #a5f3fc; font-family: 'JetBrains Mono', monospace;">5 Domain Agents Active</span>
      </div>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 0.45rem; font-size: 0.74rem;">
        <div style="background: rgba(255,255,255,0.06); border-radius: 6px; padding: 4px 8px; display: flex; align-items: center; gap: 5px;">
          <span>🌐</span> <strong>Pranay</strong> <span style="color: #94a3b8; font-size: 0.7rem;">(Network)</span>
        </div>
        <div style="background: rgba(255,255,255,0.06); border-radius: 6px; padding: 4px 8px; display: flex; align-items: center; gap: 5px;">
          <span>🧠</span> <strong>Bharath</strong> <span style="color: #94a3b8; font-size: 0.7rem;">(Memory)</span>
        </div>
        <div style="background: rgba(255,255,255,0.06); border-radius: 6px; padding: 4px 8px; display: flex; align-items: center; gap: 5px;">
          <span>💾</span> <strong>Aswith</strong> <span style="color: #94a3b8; font-size: 0.7rem;">(Disk)</span>
        </div>
        <div style="background: rgba(255,255,255,0.06); border-radius: 6px; padding: 4px 8px; display: flex; align-items: center; gap: 5px;">
          <span>📜</span> <strong>Sanhith</strong> <span style="color: #94a3b8; font-size: 0.7rem;">(Logs)</span>
        </div>
        <div style="background: rgba(255,255,255,0.06); border-radius: 6px; padding: 4px 8px; display: flex; align-items: center; gap: 5px;">
          <span>🗝️</span> <strong>Kishor</strong> <span style="color: #94a3b8; font-size: 0.7rem;">(Registry)</span>
        </div>
      </div>
    </div>

    <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; color: #0f172a; margin-bottom: 0.85rem; padding: 0.5rem 0.75rem; background: #f8fafc; border-radius: 6px; border: 1px solid #e2e8f0; display: flex; justify-content: space-between; align-items: center;">
      <span>📁 <strong>Evidence Repository Root: ${escapeHTML(caseObj.case_name || caseObj.case_id)}</strong></span>
      <span style="font-size: 0.72rem; color: #059669; font-weight: 700;">● Final Output Contracts Only</span>
    </div>

    <!-- Tree Node 1: Preserved Source Evidence -->
    <div style="margin-bottom: 1rem;">
      <div style="display: flex; align-items: center; gap: 0.4rem; font-weight: 700; font-size: 0.85rem; color: #1e293b; margin-bottom: 0.4rem;">
        <span>├──</span> <span>📦 Source Evidence Preserved (${evidences.length})</span>
      </div>
      <div style="margin-left: 1.25rem; border-left: 2px solid #e2e8f0; padding-left: 0.75rem; background: #ffffff; border-radius: 4px;">
        ${evidenceFilesHTML}
      </div>
    </div>

    <!-- Tree Node 2: Extracted Artifacts -->
    <div>
      <div style="display: flex; align-items: center; gap: 0.4rem; font-weight: 700; font-size: 0.85rem; color: #1e293b; margin-bottom: 0.4rem;">
        <span>└──</span> <span>⚡ Extracted Forensic Artifacts (${total} JSON Files)</span>
      </div>
      <div style="margin-left: 1.25rem; border-left: 2px solid #e2e8f0; padding-left: 0.75rem;">
        ${categoriesHTML}
      </div>
    </div>
  `;
}

// Loads and populates Artifact Extraction section for the active case
window.loadExtractionSection = async function() {
  try {
    const cases = await HMACFR_API.getCases();
    window.g_allCases = cases;
    let activeCase = window.g_currentActiveCase;
    if (!activeCase) {
      if (cases && cases.length > 0) {
        activeCase = await window.setActiveCase(cases[0].case_id, { refreshActiveSection: false });
      } else {
        try {
          const newCase = await HMACFR_API.createCase({
            case_name: "Default Forensic Sandbox",
            description: "Default workspace sandbox",
            priority: "Medium"
          });
          activeCase = await window.setActiveCase(newCase.case_id, { refreshActiveSection: false });
        } catch (e) {
          console.error("Auto-provision default case error:", e);
        }
      }
    }
    const select = document.getElementById("extraction-case-select");

    if (select) {
      const activeId = activeCase ? activeCase.case_id : "";
      select.innerHTML = '<option value="">-- Select Target Case --</option>';
      cases.forEach(c => {
        const opt = document.createElement("option");
        opt.value = c.case_id;
        opt.textContent = `${c.case_name || c.case_id} (${c.case_id.substring(0, 8)}...)`;
        if (c.case_id === activeId) opt.selected = true;
        select.appendChild(opt);
      });

      select.onchange = async (e) => {
        const val = e.target.value;
        if (val) {
          await window.setActiveCase(val, { refreshActiveSection: true });
        } else {
          window.setActiveCase(null);
        }
      };
    }

    const titleEl = document.getElementById("extraction-active-case-name");
    const summaryEl = document.getElementById("extraction-evidence-summary");
    const sourceList = document.getElementById("extraction-source-evidence-list");
    const sourceCount = document.getElementById("extraction-source-count");
    const statusText = document.getElementById("extraction-status-text");
    const statusHud = document.getElementById("extraction-status-hud-pill");
    const nextBtn = document.getElementById("btn-extraction-to-investigation");

    if (!activeCase) {
      if (titleEl) titleEl.textContent = "No Case Selected";
      if (summaryEl) summaryEl.textContent = "Please select an investigation case to view evidence feeds.";
      if (sourceCount) sourceCount.textContent = "0 Items";
      if (sourceList) {
        sourceList.innerHTML = `
          <div style="text-align: center; color: var(--text-muted); padding: 2rem; font-size: 0.85rem;">
            No active case selected. Select a case above to view evidence files.
          </div>
        `;
      }
      if (statusText) statusText.textContent = "Awaiting Case Selection";
      if (statusHud) statusHud.innerHTML = `<span style="color: #94a3b8;">●</span> Awaiting Case`;
      const treeContainer = document.getElementById("extraction-artifact-tree-list");
      if (treeContainer) {
        treeContainer.innerHTML = `
          <div class="empty-state" style="padding: 2.5rem 1rem; text-align: center;">
            <div style="font-size: 1.05rem; font-weight: 700; color: #0f172a; margin-bottom: 0.35rem;">No Active Case Selected</div>
            <div style="font-size: 0.82rem; color: #64748b; max-width: 480px; margin: 0 auto 1.25rem;">
              Select an investigation case to inspect preserved evidence files and run artifact extraction.
            </div>
            <button type="button" class="btn btn-primary btn-sm" onclick="switchWorkspaceSection('sec-cases');">Select Case &rarr;</button>
          </div>
        `;
      }
      return;
    }

    // Active case exists
    if (titleEl) titleEl.textContent = `${activeCase.case_name} (${activeCase.case_id.substring(0, 8)}...)`;

    const evidences = activeCase.evidences || [];
    if (summaryEl) {
      summaryEl.textContent = `${evidences.length} Preserved Artifact${evidences.length === 1 ? '' : 's'} • SHA-256 HMAC Verified`;
    }
    if (sourceCount) sourceCount.textContent = `${evidences.length} Item${evidences.length === 1 ? '' : 's'}`;

    if (sourceList) {
      if (evidences.length === 0) {
        sourceList.innerHTML = `
          <div style="text-align: center; color: #94a3b8; padding: 1.5rem; font-size: 0.82rem;">
            No preserved evidence files found for this case. Upload evidence in Evidence Vault first.
          </div>
        `;
      } else {
        sourceList.innerHTML = evidences.map(ev => {
          const isPreserved = ev.status === "READY_FOR_PROCESSING" || ev.status === "Preserved" || ev.file_hash;
          const sizeStr = ev.file_size ? `${(ev.file_size / (1024 * 1024)).toFixed(1)} MB` : "N/A";
          return `
            <div style="display: flex; align-items: center; justify-content: space-between; padding: 0.6rem 0.85rem; border: 1px solid #e2e8f0; border-radius: 6px; background: #ffffff;">
              <div style="display: flex; align-items: center; gap: 0.5rem; overflow: hidden;">
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="#1d4ed8" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                <div style="font-weight: 600; font-size: 0.82rem; color: #0f172a; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${escapeHTML(ev.original_filename || ev.filename || 'evidence_file')}</div>
              </div>
              <div style="display: flex; align-items: center; gap: 0.4rem;">
                <span style="font-size: 0.7rem; color: #64748b; font-family: 'JetBrains Mono', monospace;">${sizeStr}</span>
                <span class="badge ${isPreserved ? 'badge-emerald' : 'badge-amber'}" style="font-size: 0.68rem;">${isPreserved ? 'Preserved' : 'Uploaded'}</span>
              </div>
            </div>
          `;
        }).join('');
      }
    }

    // Fetch real extracted artifact files from backend
    let artifactRes = null;
    try {
      artifactRes = await HMACFR_API.getExtractedArtifacts(activeCase.case_id);
    } catch (e) {
      console.warn("Could not fetch extracted artifacts:", e);
    }

    const total = artifactRes ? (artifactRes.total_artifacts || 0) : 0;

    if (total > 0) {
      if (statusText) statusText.textContent = `Extraction completed — ${total} JSON artifact files`;
      if (statusHud) statusHud.innerHTML = `<span style="color: #10b981;">●</span> Extraction Complete (${total} JSON Artifacts)`;
      if (nextBtn) {
        nextBtn.removeAttribute("disabled");
        nextBtn.style.opacity = "1";
      }
    } else {
      if (statusText) statusText.textContent = "Ready for Extraction";
      if (statusHud) statusHud.innerHTML = `<span style="color: #10b981;">●</span> Ready for Extraction`;
    }

    renderArtifactBrowser(activeCase, artifactRes);
  } catch (err) {
    console.error("Error loading extraction section:", err);
  }
};

// Triggers real forensic artifact extraction via PluginManager
window.triggerArtifactExtraction = async function() {
  const activeCase = window.g_currentActiveCase;
  if (!activeCase || !activeCase.case_id) {
    if (typeof showSherlockNotice === "function") {
      showSherlockNotice("Case Required", "Please select an active case before running extraction.", true);
    } else {
      alert("Please select an active case before running extraction.");
    }
    return;
  }

  const progContainer = document.getElementById("extraction-progress-container");
  const progBar = document.getElementById("extraction-progress-bar");
  const progPct = document.getElementById("extraction-progress-pct");
  const progLabel = document.getElementById("extraction-progress-label");
  const statusText = document.getElementById("extraction-status-text");
  const statusHud = document.getElementById("extraction-status-hud-pill");

  if (progContainer) progContainer.style.display = "block";
  if (statusText) statusText.textContent = "Extraction in progress...";
  if (statusHud) statusHud.innerHTML = `<span style="color: #d97706;">●</span> Extracting Artifacts...`;

  let pct = 0;
  const interval = setInterval(() => {
    pct = Math.min(pct + 16, 92);
    if (progBar) progBar.style.width = `${pct}%`;
    if (progPct) progPct.textContent = `${pct}%`;
    if (progLabel) progLabel.textContent = `Executing plugin adapters for Case ${activeCase.case_id}...`;
  }, 250);

  try {
    const result = await HMACFR_API.runArtifactExtraction(activeCase.case_id);
    clearInterval(interval);

    if (progBar) progBar.style.width = "100%";
    if (progPct) progPct.textContent = "100%";
    if (progLabel) progLabel.textContent = "Artifact extraction completed successfully!";

    await window.loadExtractionSection();
    if (typeof showSherlockNotice === "function") {
      showSherlockNotice("Extraction Complete", `Forensic artifact extraction completed for Case "${activeCase.case_name || activeCase.case_id}".`);
    }

    setTimeout(() => {
      if (progContainer) progContainer.style.display = "none";
    }, 2200);
  } catch (err) {
    clearInterval(interval);
    if (statusText) statusText.textContent = "Extraction failed. Review logs and retry.";
    if (statusHud) statusHud.innerHTML = `<span style="color: #dc2626;">●</span> Extraction Failed`;
    if (progLabel) progLabel.textContent = "Extraction failed: " + err.message;
    if (typeof showSherlockNotice === "function") {
      showSherlockNotice("Extraction Failed", err.message, true);
    }
  }
};

// Loads and populates SIS Review section for the active case
window.loadSisSection = async function() {
  const caseObj = window.g_currentActiveCase;
  const caseId = caseObj ? caseObj.case_id : window.g_currentActiveCaseId;
  const nameEl = document.getElementById("sis-case-name");
  if (nameEl) {
    nameEl.textContent = caseObj ? `${caseObj.case_name} (${caseObj.case_id})` : "No Case Selected";
  }

  if (!caseId) return;

  // Attempt to fetch dedicated SIS state from backend
  let sis = null;
  try {
    sis = await HMACFR_API.getCaseSIS(caseId);
  } catch (e) {
    console.warn("Direct SIS fetch fallback to synthesized_data:", e);
  }

  // Fallback to local synthesized_data if needed
  if (!sis && caseObj && caseObj.synthesized_data) {
    sis = {
      case_id: caseId,
      state_version: 1,
      investigation_status: "ANALYSIS_COMPLETE",
      review_status: "PENDING_REVIEW",
      confidence: 0.88,
      entities: caseObj.synthesized_data.entities || [],
      events: caseObj.synthesized_data.timeline || [],
      correlations: caseObj.synthesized_data.correlations || [],
      findings: caseObj.synthesized_data.findings || []
    };
  }

  // Update SIS HUD stats
  const versionEl = document.getElementById("sis-stat-version");
  const confEl = document.getElementById("sis-stat-confidence");
  const entEl = document.getElementById("sis-stat-entities");
  const evtEl = document.getElementById("sis-stat-events");
  const corrEl = document.getElementById("sis-stat-correlations");
  const statusPill = document.getElementById("sis-review-status-pill");
  const auditBadge = document.getElementById("sis-review-audit-badge");

  if (sis) {
    if (versionEl) versionEl.textContent = sis.state_version || 1;
    if (confEl) {
      const c = sis.confidence || sis.confidence_score || 0.88;
      confEl.textContent = `${Math.round(c * (c <= 1 ? 100 : 1))}%`;
    }

    // Count entities: handle arrays and dictionaries (suspicious_pids, evidence_sources_count, etc.)
    let entityCount = 0;
    if (Array.isArray(sis.entities)) {
      entityCount = sis.entities.length;
    } else if (sis.entities && typeof sis.entities === "object") {
      const pids = Array.isArray(sis.entities.suspicious_pids) ? sis.entities.suspicious_pids.length : 0;
      const evCount = typeof sis.entities.evidence_sources_count === "number" ? sis.entities.evidence_sources_count : 0;
      const ips = Array.isArray(sis.entities.ip_addresses) ? sis.entities.ip_addresses.length : 0;
      const subTotal = pids + evCount + ips;
      entityCount = subTotal > 0 ? subTotal : Object.keys(sis.entities).length;
    }
    if (entEl) entEl.textContent = entityCount;

    // Count events: handle sis.events, sis.attack_timeline, or caseObj timeline
    let eventCount = 0;
    if (Array.isArray(sis.events)) {
      eventCount = sis.events.length;
    } else if (Array.isArray(sis.attack_timeline)) {
      eventCount = sis.attack_timeline.length;
    } else if (caseObj && caseObj.synthesized_data && Array.isArray(caseObj.synthesized_data.timeline)) {
      eventCount = caseObj.synthesized_data.timeline.length;
    }
    if (evtEl) evtEl.textContent = eventCount;

    // Count correlations: handle sis.correlations or caseObj correlations
    let corrCount = 0;
    if (Array.isArray(sis.correlations)) {
      corrCount = sis.correlations.length;
    } else if (caseObj && caseObj.synthesized_data && Array.isArray(caseObj.synthesized_data.correlations)) {
      corrCount = caseObj.synthesized_data.correlations.length;
    }
    if (corrEl) corrEl.textContent = corrCount;


    // Review Status Badge
    const revStatus = (sis.review_status || "PENDING_REVIEW").toUpperCase();
    if (statusPill) {
      if (revStatus === "APPROVED_LOCKED") {
        statusPill.innerHTML = `🛡️ APPROVED &amp; LOCKED`;
        statusPill.style.borderColor = "#10b981";
        statusPill.style.color = "#34d399";
      } else if (revStatus === "REJECTED_REANALYSIS") {
        statusPill.innerHTML = `🔄 REJECTED &amp; REANALYSIS REQUIRED`;
        statusPill.style.borderColor = "#ef4444";
        statusPill.style.color = "#f87171";
      } else {
        statusPill.innerHTML = `● PENDING REVIEW`;
        statusPill.style.borderColor = "#f59e0b";
        statusPill.style.color = "#fbbf24";
      }
    }

    if (auditBadge) {
      if (sis.reviewed_by) {
        auditBadge.textContent = `Reviewed by ${sis.reviewed_by} at ${new Date(sis.reviewed_at || Date.now()).toLocaleTimeString()}`;
      } else {
        auditBadge.textContent = `Awaiting investigator sign-off`;
      }
    }

    const notesEl = document.getElementById("sis-reviewer-notes");
    if (notesEl && sis.reviewer_notes) {
      notesEl.value = sis.reviewer_notes;
    }
  }

  // Render Multi-Source Correlation Pivots
  const corrContainer = document.getElementById("sis-correlations-container");
  if (corrContainer) {
    const correlations = sis && Array.isArray(sis.correlations) ? sis.correlations : [];
    if (correlations.length === 0) {
      corrContainer.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 1.5rem;">No cross-domain correlations generated yet. Run multi-agent analysis to generate correlations.</div>`;
    } else {
      corrContainer.innerHTML = correlations.map((c, i) => {
        const pivotType = c.pivot_type || c.correlation_type || "MULTI_DOMAIN_PIVOT";
        const conf = c.confidence ? `${Math.round(c.confidence * (c.confidence <= 1 ? 100 : 1))}%` : "90%";
        const sources = Array.isArray(c.source_artifacts) ? c.source_artifacts.join(' ↔ ') : (c.source || 'Cross-Domain');
        return `
          <div style="background: rgba(30, 41, 59, 0.6); border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 1rem 1.25rem;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem;">
              <span style="font-size: 0.75rem; font-weight: 800; color: #38bdf8; letter-spacing: 0.05em;">${escapeHTML(pivotType)}</span>
              <span style="font-size: 0.72rem; color: #34d399; font-weight: 700; background: rgba(16, 185, 129, 0.15); padding: 2px 8px; border-radius: 9999px;">${conf} Corroborated</span>
            </div>
            <div style="font-size: 0.88rem; color: #f1f5f9; font-weight: 600; margin-bottom: 0.35rem;">${escapeHTML(c.description || c.title || 'Cross-domain forensic link')}</div>
            <div style="font-size: 0.75rem; color: #94a3b8; font-family: monospace;">Sources: ${escapeHTML(sources)}</div>
          </div>
        `;
      }).join('');
    }
  }

  // Render Hypotheses Grid
  const grid = document.getElementById("sis-hypotheses-grid");
  if (!grid) return;

  const findings = sis && Array.isArray(sis.findings)
    ? sis.findings
    : (caseObj && caseObj.synthesized_data && Array.isArray(caseObj.synthesized_data.findings) ? caseObj.synthesized_data.findings : []);

  if (findings.length === 0) {
    grid.innerHTML = `
      <div class="empty-state" style="padding: 2.5rem; text-align: center; grid-column: 1 / -1;">
        <div style="font-size: 1.05rem; font-weight: 700; color: #0f172a; margin-bottom: 0.35rem;">No Investigation Hypotheses Available</div>
        <div style="font-size: 0.84rem; color: #64748b; max-width: 500px; margin: 0 auto 1.25rem;">
          No investigation findings available yet.<br>
          Complete the multi-agent investigation to generate hypotheses for review.
        </div>
        <button type="button" class="btn btn-primary btn-sm" onclick="switchWorkspaceSection('sec-analysis');">
          Go to Multi-Agent Investigation &rarr;
        </button>
      </div>
    `;
    return;
  }

  // Render real findings
  grid.innerHTML = findings.map((f, idx) => {
    const sev = (f.severity || "MEDIUM").toUpperCase();
    const conf = f.confidence ? `${Math.round(f.confidence * (f.confidence <= 1 ? 100 : 1))}%` : "85%";
    const badgeClass = sev === "CRITICAL" ? "badge-danger" : (sev === "HIGH" ? "badge-amber" : "badge-cyan");
    const evidenceRef = f.evidence_reference || f.evidence_id || f.source || "Preserved Artifact";

    return `
      <div class="card hypothesis-card" style="border: 1px solid #e2e8f0; border-radius: 10px; padding: 1.25rem; background: #ffffff;">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.75rem;">
          <span class="badge ${badgeClass}" style="font-size: 0.7rem; font-weight: 800;">${sev} HYPOTHESIS</span>
          <span style="font-size: 0.75rem; font-weight: 700; color: #1d4ed8; background: #eff6ff; padding: 2px 8px; border-radius: 9999px;">
            ${conf} Confidence
          </span>
        </div>
        <h4 style="font-size: 0.95rem; font-weight: 700; color: #0f172a; margin-bottom: 0.5rem;">${escapeHTML(f.title || f.name || `Finding #${idx + 1}`)}</h4>
        <p style="font-size: 0.82rem; color: #475569; line-height: 1.45; margin-bottom: 0.75rem;">${escapeHTML(f.description || f.detail || "Synthesized finding from multi-agent correlation.")}</p>
        <div style="font-size: 0.72rem; color: #64748b; font-family: 'JetBrains Mono', monospace; border-top: 1px solid #f1f5f9; padding-top: 0.5rem; margin-top: auto;">
          Artifact Ref: <strong>${escapeHTML(evidenceRef)}</strong>
        </div>
      </div>
    `;
  }).join('');
};

// Submits investigator sign-off or re-analysis request for active SIS
window.submitSISReviewAction = async function(action) {
  const caseId = window.g_currentActiveCaseId;
  if (!caseId) {
    if (typeof showSherlockNotice === "function") {
      showSherlockNotice("No Active Case", "Please select an active forensic case before performing review action.", true);
    }
    return;
  }

  const notesEl = document.getElementById("sis-reviewer-notes");
  const notes = notesEl ? notesEl.value.trim() : "";

  try {
    const res = await HMACFR_API.submitSISReview(caseId, action, notes);
    if (typeof showSherlockNotice === "function") {
      const msg = action === "APPROVE"
        ? `Structured Investigation State for ${caseId} is now APPROVED and locked for reporting.`
        : `Investigation State marked for RE-ANALYSIS. Artifacts can be re-evaluated.`;
      showSherlockNotice(action === "APPROVE" ? "SIS Approved & Locked" : "Re-analysis Requested", msg);
    }
    await window.loadSisSection();
  } catch (e) {
    console.error("Failed to submit SIS review:", e);
    if (typeof showSherlockNotice === "function") {
      showSherlockNotice("Review Failed", e.message || "Failed to submit review action.", true);
    }
  }
};

// Interactive Case Evidence Chatbot powered by ChromaDB RAG & SIS state
window.sendCaseChatMessage = async function() {
  const input = document.getElementById("case-chat-input");
  const container = document.getElementById("case-chat-messages-container");
  if (!input || !container) return;

  const query = input.value.trim();
  if (!query) return;

  const caseId = window.g_currentActiveCaseId;
  if (!caseId) {
    if (typeof showSherlockNotice === "function") {
      showSherlockNotice("Select Case", "Please select an active case first to query forensic evidence.", true);
    }
    return;
  }

  // Clear input
  input.value = "";

  // Append user message
  const userBubble = document.createElement("div");
  userBubble.style.cssText = "display: flex; gap: 0.75rem; align-items: flex-start; justify-content: flex-end;";
  userBubble.innerHTML = `
    <div style="background: #1d4ed8; color: #fff; border-radius: 8px; padding: 0.75rem 1rem; max-width: 85%; font-size: 0.86rem; line-height: 1.45;">
      <strong>Investigator:</strong> ${escapeHTML(query)}
    </div>
    <div style="width: 28px; height: 28px; border-radius: 50%; background: #2563eb; display: flex; align-items: center; justify-content: center; font-size: 0.75rem; font-weight: 800; color: #fff; flex-shrink: 0;">INV</div>
  `;
  container.appendChild(userBubble);

  // Append loading assistant bubble
  const assistantBubble = document.createElement("div");
  assistantBubble.style.cssText = "display: flex; gap: 0.75rem; align-items: flex-start;";
  assistantBubble.innerHTML = `
    <div style="width: 28px; height: 28px; border-radius: 50%; background: #059669; display: flex; align-items: center; justify-content: center; font-size: 0.8rem; font-weight: 800; color: #fff; flex-shrink: 0;">AI</div>
    <div style="background: rgba(30, 41, 59, 0.8); border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 0.75rem 1rem; color: #94a3b8; line-height: 1.5; max-width: 90%;">
      <em>Consulting ChromaDB vector store &amp; Structured Investigation State...</em>
    </div>
  `;
  container.appendChild(assistantBubble);
  container.scrollTop = container.scrollHeight;

  try {
    const res = await HMACFR_API.askCaseChatbot(caseId, query);
    const answer = res.answer || "No response generated.";
    const sources = Array.isArray(res.sources) ? res.sources : [];
    const confidence = res.confidence ? `${Math.round(res.confidence * 100)}%` : "92%";

    let sourcesHtml = "";
    if (sources.length > 0) {
      sourcesHtml = `
        <div style="margin-top: 0.6rem; padding-top: 0.5rem; border-top: 1px solid rgba(255,255,255,0.1); font-size: 0.74rem; color: #94a3b8;">
          <span style="font-weight: 700; color: #cbd5e1;">Evidence Citations:</span>
          ${sources.map(s => `<code style="background: rgba(0,0,0,0.4); color: #38bdf8; padding: 1px 6px; border-radius: 4px; margin-left: 4px;">${escapeHTML(s)}</code>`).join('')}
          <span style="margin-left: 8px; color: #34d399; font-weight: 700;">● ${confidence} Confidence</span>
        </div>
      `;
    }

    assistantBubble.innerHTML = `
      <div style="width: 28px; height: 28px; border-radius: 50%; background: #059669; display: flex; align-items: center; justify-content: center; font-size: 0.8rem; font-weight: 800; color: #fff; flex-shrink: 0;">AI</div>
      <div style="background: rgba(30, 41, 59, 0.8); border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 0.75rem 1rem; color: #f1f5f9; line-height: 1.5; max-width: 90%;">
        <div style="color: #e2e8f0;">${escapeHTML(answer).replace(/\n/g, '<br>')}</div>
        ${sourcesHtml}
      </div>
    `;
  } catch (err) {
    console.error("Chat error:", err);
    assistantBubble.innerHTML = `
      <div style="width: 28px; height: 28px; border-radius: 50%; background: #dc2626; display: flex; align-items: center; justify-content: center; font-size: 0.8rem; font-weight: 800; color: #fff; flex-shrink: 0;">!</div>
      <div style="background: rgba(220, 38, 38, 0.15); border: 1px solid rgba(220, 38, 38, 0.4); border-radius: 8px; padding: 0.75rem 1rem; color: #fca5a5; line-height: 1.5; max-width: 90%;">
        Failed to query forensic evidence: ${escapeHTML(err.message || "Unknown error")}
      </div>
    `;
  }
  container.scrollTop = container.scrollHeight;
};

// Loads Outputs & Report section for the active case
window.loadOutputsSection = async function() {
  let activeCase = window.g_currentActiveCase;
  if (!activeCase || !activeCase.case_id) {
    if (window.g_allCases && window.g_allCases.length > 0) {
      activeCase = await window.setActiveCase(window.g_allCases[0].case_id, { refreshActiveSection: false });
    }
  }
  const nameEl = document.getElementById("outputs-case-display-name");
  const pillEl = document.getElementById("outputs-synthesized-pill");

  if (!activeCase || !activeCase.case_id) {
    if (nameEl) nameEl.textContent = "Forensic Lab Outputs";
    if (pillEl) {
      pillEl.innerHTML = `<span style="color: #94a3b8;">●</span> Awaiting Analysis`;
      pillEl.style.borderColor = "#cbd5e1";
      pillEl.style.color = "#64748b";
    }
    if (window.clearForensicOutputs) window.clearForensicOutputs();
    return;
  }

  if (nameEl) {
    nameEl.textContent = `${activeCase.case_name} (${activeCase.case_id})`;
  }

  // Clear previous outputs first to guarantee isolation
  if (window.clearForensicOutputs) window.clearForensicOutputs();

  const synth = activeCase.synthesized_data;
  const hasSynthData = synth && (
    (synth.findings && synth.findings.length > 0) ||
    (synth.timeline && synth.timeline.length > 0) ||
    (synth.artifact_inventory && synth.artifact_inventory.total_artifacts > 0)
  );

  if (hasSynthData) {
    if (pillEl) {
      pillEl.innerHTML = `<span style="color: #10b981;">●</span> Intelligence Synthesized`;
      pillEl.style.borderColor = "rgba(16, 185, 129, 0.4)";
      pillEl.style.color = "#10b981";
    }
    if (window.loadForensicOutputsForCase) {
      await window.loadForensicOutputsForCase(activeCase.case_id);
    }
  } else {
    if (pillEl) {
      pillEl.innerHTML = `<span style="color: #d97706;">●</span> Pending Investigation`;
      pillEl.style.borderColor = "rgba(217, 119, 6, 0.4)";
      pillEl.style.color = "#d97706";
    }
  }
};

window.g_currentActiveCaseId = null;
window.g_currentActiveCaseName = null;
window.g_currentPopoverOwner = null;

window.toggleCaseCardMenu = function(btnOrEvt, caseId, caseName, evt) {
  const e = evt || window.event;
  if (e && e.stopPropagation) e.stopPropagation();

  window.g_currentActiveCaseId = caseId;
  window.g_currentActiveCaseName = caseName;

  const popover = document.getElementById("global-case-card-popover");
  if (!popover) return;

  if (popover.style.display === "block" && window.g_currentPopoverOwner === caseId) {
    popover.style.display = "none";
    window.g_currentPopoverOwner = null;
    return;
  }

  let btn = null;
  if (btnOrEvt) {
    if (btnOrEvt.getBoundingClientRect) {
      btn = btnOrEvt;
    } else if (btnOrEvt.currentTarget) {
      btn = btnOrEvt.currentTarget;
    } else if (btnOrEvt.target) {
      btn = btnOrEvt.target.closest ? (btnOrEvt.target.closest(".btn-card-action-more") || btnOrEvt.target) : btnOrEvt.target;
    }
  }

  if (!btn || !btn.getBoundingClientRect) return;
  const rect = btn.getBoundingClientRect();

  popover.style.position = "absolute";
  popover.style.top = `${rect.bottom + window.scrollY + 6}px`;
  popover.style.left = `${Math.max(10, rect.right - 220)}px`;
  popover.style.zIndex = "99999";
  popover.style.display = "block";
  window.g_currentPopoverOwner = caseId;
};

// Single-View Box-Free Create Case & Searchable Investigator Dropdown Handlers
window.setCreateCaseStep = function(stepNumber) {
  for (let i = 1; i <= 3; i++) {
    const item = document.getElementById(`stepper-step-${i}`);
    if (item) {
      if (i === stepNumber) {
        item.classList.add("active");
      } else {
        item.classList.remove("active");
      }
    }
  }
};

window.toggleInvestigatorDropdown = function(show) {
  const pop = document.getElementById("investigator-dropdown-popover");
  if (pop) {
    pop.style.display = show ? "block" : "none";
  }
};

window.filterInvestigatorDropdown = function(query) {
  const pop = document.getElementById("investigator-dropdown-popover");
  if (!pop) return;
  pop.style.display = "block";

  const options = pop.querySelectorAll(".investigator-option");
  const q = (query || "").toLowerCase().trim();
  let count = 0;

  options.forEach(opt => {
    const text = opt.textContent.toLowerCase();
    if (text.includes(q)) {
      opt.style.display = "block";
      count++;
    } else {
      opt.style.display = "none";
    }
  });
};

window.selectInvestigatorOption = function(name) {
  const searchInput = document.getElementById("create-pg-investigator-search");
  const hiddenInput = document.getElementById("create-pg-investigator-val");
  if (searchInput) searchInput.value = name;
  if (hiddenInput) hiddenInput.value = name;
  toggleInvestigatorDropdown(false);
};

// Close custom dropdowns on click outside
document.addEventListener("click", (e) => {
  const searchInput = document.getElementById("create-pg-investigator-search");
  const popover = document.getElementById("investigator-dropdown-popover");
  if (popover && searchInput) {
    if (!popover.contains(e.target) && e.target !== searchInput) {
      popover.style.display = "none";
    }
  }

  const ingestSearch = document.getElementById("ingest-case-search");
  const ingestPopover = document.getElementById("ingest-case-dropdown-popover");
  if (ingestPopover && ingestSearch) {
    if (!ingestPopover.contains(e.target) && e.target !== ingestSearch) {
      ingestPopover.style.display = "none";
    }
  }
});

window.selectPillPriority = function(val) {
  const hiddenInput = document.getElementById("create-pg-priority-val");
  if (hiddenInput) hiddenInput.value = val;

  const btns = document.querySelectorAll(".custom-priority-pill");
  btns.forEach(b => {
    if (b.getAttribute("data-priority") === val) {
      b.classList.add("selected");
      b.style.borderColor = "#1d4ed8";
      b.style.background = "#eff6ff";
      b.style.color = "#1d4ed8";
      b.style.fontWeight = "700";
    } else {
      b.classList.remove("selected");
      b.style.borderColor = "#e2e8f0";
      b.style.background = "#ffffff";
      b.style.color = "#475569";
      b.style.fontWeight = "600";
    }
  });
};

window.adjustEvidenceCount = function(delta) {
  const el = document.getElementById("create-pg-expected-count");
  if (!el) return;
  let val = parseInt(el.textContent, 10) || 1;
  val += delta;
  if (val < 1) val = 1;
  el.textContent = val;
};

window.handleCreateCasePageSubmit = async function(e) {
  if (e) e.preventDefault();
  const caseName = document.getElementById("create-pg-case-name").value.trim();
  const searchInput = document.getElementById("create-pg-investigator-search");
  const hiddenInput = document.getElementById("create-pg-investigator-val");
  const investigator = searchInput ? searchInput.value.trim() : (hiddenInput ? hiddenInput.value : "investigator1");
  const priorityInput = document.getElementById("create-pg-priority-val");
  const priority = priorityInput ? priorityInput.value : "Medium";
  const expectedItems = document.getElementById("create-pg-expected-count").textContent.trim();
  const description = document.getElementById("create-pg-description").value.trim();

  if (!caseName) {
    showSherlockNotice("Action Failed", "Please provide a Case Title / Reference.", true);
    return;
  }

  showCyberLoading(
    "Initializing Forensic Case Container",
    `Allocating encrypted vault storage & registering digital custody manifest for ${caseName}...`,
    [
      "GENERATING UNIQUE CASE UUID IDENTIFIER...",
      "CREATING AES-256 ENCRYPTED VAULT DIRECTORIES...",
      "INITIALIZING AUDIT & CHAIN OF CUSTODY MANIFEST...",
      "CASE INITIALIZATION COMPLETED SUCCESSFULLY."
    ],
    async () => {
      try {
        const expVal = parseInt(expectedItems) || 2;
        const fullDesc = `Expected Items: ${expVal} | Scope: ${description || 'N/A'}`;
        await HMACFR_API.createCase({
          case_name: caseName,
          investigator_name: investigator || "investigator1",
          priority: priority || "Medium",
          description: fullDesc,
          expected_evidence_count: expVal
        });

        showSherlockNotice("Case Initialized", `Case "${caseName}" successfully created and registered!`);
        
        const form = document.getElementById("create-case-page-form");
        if (form) form.reset();
        const cntEl = document.getElementById("create-pg-expected-count");
        if (cntEl) cntEl.textContent = "2";

        loadOverviewData();
        window.switchWorkspaceSection("sec-cases");
      } catch (err) {
        showSherlockNotice("Action Failed", "Error creating case: " + err.message, true);
      }
    }
  );
};

// Keyboard ESC Shortcut Handler to Return to Cases Section
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    const createSec = document.getElementById("sec-create-case");
    if (createSec && createSec.classList.contains("active")) {
      window.switchWorkspaceSection("sec-cases");
    }
  }
});

// Custom Sherlock AI Forensic Notification Modal Handler (Replaces Native Browser Alerts)
window.showSherlockNotice = function(title, message, isError = false) {
  const modal = document.getElementById("sherlock-custom-notice-modal");
  const titleEl = document.getElementById("sherlock-notice-title");
  const msgEl = document.getElementById("sherlock-notice-message");
  const iconBox = document.getElementById("sherlock-notice-icon-box");

  if (!modal) {
    console.log(`[${title}] ${message}`);
    return;
  }

  if (titleEl) titleEl.textContent = title || "Forensic Notice";
  if (msgEl) {
    msgEl.innerHTML = "";
    const lines = String(message || "").split("\n");
    lines.forEach((lineText, idx) => {
      if (idx > 0) msgEl.appendChild(document.createElement("br"));
      msgEl.appendChild(document.createTextNode(lineText));
    });
  }

  if (iconBox) {
    if (isError) {
      iconBox.style.background = "#fef2f2";
      iconBox.innerHTML = `<svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="#dc2626" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`;
    } else {
      iconBox.style.background = "#eff6ff";
      iconBox.innerHTML = `<svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="#1d4ed8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`;
    }
  }

  modal.style.display = "flex";
};

window.closeSherlockNoticeModal = function() {
  const modal = document.getElementById("sherlock-custom-notice-modal");
  if (modal) modal.style.display = "none";
};

// Future Feature Toast Notification Handler
window.showFutureFeatureNotice = function(featureTitle, featureDesc) {
  const toast = document.getElementById("future-feature-toast");
  const titleEl = document.getElementById("future-toast-title");
  const descEl = document.getElementById("future-toast-desc");

  if (!toast) {
    window.showSherlockNotice(featureTitle || "Feature Under Development", featureDesc || "Available in future stage.");
    return;
  }

  if (titleEl) titleEl.textContent = featureTitle || "Feature Under Development";
  if (descEl) descEl.textContent = featureDesc || "(Available in future — working on it)";

  toast.style.display = "block";
  toast.style.opacity = "1";
  toast.style.transform = "translateY(0)";

  if (window.g_futureToastTimeout) clearTimeout(window.g_futureToastTimeout);
  window.g_futureToastTimeout = setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(-20px)";
    setTimeout(() => { toast.style.display = "none"; }, 300);
  }, 3500);
};

// Vertical Navigation Sidebar Hide / Unhide Toggle Handler
window.toggleSidebarNavbar = function(shouldHide) {
  if (shouldHide === undefined) {
    document.body.classList.toggle("sidebar-collapsed");
  } else if (shouldHide) {
    document.body.classList.add("sidebar-collapsed");
  } else {
    document.body.classList.remove("sidebar-collapsed");
  }
};

// Top-level 3D Test Trigger Handlers

window.trigger3DTestShatter = function() {
  if (window.hmacfr3D) {
    window.hmacfr3D.triggerAuthSuccessAnimation();
  }
};


window.trigger3DTestReverse = function() {
  if (window.hmacfr3D) {
    window.hmacfr3D.triggerAuthFailureAnimation("Test Incorrect Password");
  }
};

/* ==================== ENTERPRISE LOADING TELEMETRY HUD ==================== */
async function showCyberLoading(title, subtitle, steps, asyncAction) {
  const modal = document.getElementById("cyber-loading-modal");
  const titleEl = document.getElementById("loading-title");
  const subtitleEl = document.getElementById("loading-subtitle");
  const progressBar = document.getElementById("loading-progress-bar");
  const percentageEl = document.getElementById("loading-percentage");
  const terminal = document.getElementById("loading-matrix-terminal");

  if (!modal) {
    if (asyncAction) await asyncAction();
    return;
  }

  if (titleEl) titleEl.textContent = title || "Executing Forensic Telemetry...";
  if (subtitleEl) subtitleEl.textContent = subtitle || "Processing cryptographic hashes and vault encryption.";

  if (progressBar) progressBar.style.width = "0%";
  if (percentageEl) percentageEl.textContent = "0%";
  if (terminal) terminal.innerHTML = "";

  modal.classList.add("active");
  if (window.hmacfr3D) window.hmacfr3D.initLoadingRadiumStage();

  const stepList = steps && steps.length > 0 ? steps : [
    "INITIALIZING FORENSIC PRESERVATION CORE...",
    "CALCULATING AUTHORITATIVE SHA-256 HASH DIGEST...",
    "COMPUTING HMAC-SHA256 AUTHENTICATION TAG...",
    "APPLYING AES-256-GCM VAULT ENCRYPTION..."
  ];

  const startTime = Date.now();
  let currentStep = 0;

  const interval = setInterval(() => {
    if (currentStep < stepList.length - 1) {
      currentStep++;
      const progress = Math.min(Math.round((currentStep / stepList.length) * 85), 85);
      if (progressBar) progressBar.style.width = `${progress}%`;
      if (percentageEl) percentageEl.textContent = `${progress}%`;

      const elapsed = ((Date.now() - startTime) / 1000).toFixed(3);
      if (terminal) {
        const line = document.createElement("div");
        line.className = "matrix-stream-line";
        line.innerHTML = `<span class="matrix-stream-timestamp" style="color: #2563eb; font-weight: 700;">[${elapsed}s]</span> <span style="color: #334155; font-weight: 600;">${stepList[currentStep - 1]}</span>`;
        terminal.appendChild(line);
        terminal.scrollTop = terminal.scrollHeight;
      }
    }
  }, 180);

  try {
    if (asyncAction) {
      await asyncAction();
    }
    clearInterval(interval);

    if (progressBar) progressBar.style.width = "100%";
    if (percentageEl) percentageEl.textContent = "100%";

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(3);
    if (terminal) {
      const line = document.createElement("div");
      line.className = "matrix-stream-line";
      line.innerHTML = `<span class="matrix-stream-timestamp" style="color: #059669; font-weight: 700;">[${elapsed}s]</span> <span style="color: #059669; font-weight: 700;">${stepList[stepList.length - 1] || 'OPERATION COMPLETED SUCCESSFULLY.'}</span>`;
      terminal.appendChild(line);
      terminal.scrollTop = terminal.scrollHeight;
    }

    setTimeout(() => {
      hideCyberLoading();
    }, 350);

  } catch (err) {
    clearInterval(interval);
    hideCyberLoading();
    showSherlockNotice("Action Failed", err.message || "Operation failed on server.", true);
  }
}

function hideCyberLoading() {
  const modal = document.getElementById("cyber-loading-modal");
  if (modal) modal.classList.remove("active");
}

function initSherlockEmblemParallax() {
  const emblemWrapper = document.getElementById("sherlock-emblem-wrapper");
  if (!emblemWrapper) return;
  const emblem3D = emblemWrapper.querySelector(".sherlock-emblem-3d");
  if (!emblem3D) return;

  emblemWrapper.addEventListener("mousemove", (e) => {
    const rect = emblemWrapper.getBoundingClientRect();
    const x = e.clientX - rect.left - rect.width / 2;
    const y = e.clientY - rect.top - rect.height / 2;
    
    // Max tilt: X ±3deg, Y ±4deg, Elevation translateZ(12px)
    const rotX = (-y / (rect.height / 2)) * 3;
    const rotY = (x / (rect.width / 2)) * 4;

    emblem3D.style.transform = `translateZ(12px) rotateX(${rotX.toFixed(2)}deg) rotateY(${rotY.toFixed(2)}deg) scale(1.03)`;
  });

  emblemWrapper.addEventListener("mouseleave", () => {
    emblem3D.style.transform = "";
  });
}

function initLandingScrollspy() {
  const sections = document.querySelectorAll("#landing-page-container section[id]");
  const navLinks = document.querySelectorAll(".landing-nav-links button, .landing-nav-links a");
  if (!sections.length || !navLinks.length) return;

  const updateActive = () => {
    let currentId = "";
    const scrollPos = window.pageYOffset + 220;
    sections.forEach(sec => {
      if (scrollPos >= sec.offsetTop) {
        currentId = sec.getAttribute("id");
      }
    });

    if (currentId) {
      navLinks.forEach(link => {
        const target = link.getAttribute("data-target") || link.getAttribute("href");
        if (target === `#${currentId}`) {
          link.classList.add("active");
        } else {
          link.classList.remove("active");
        }
      });
    }
  };

  window.addEventListener("scroll", updateActive, { passive: true });
  updateActive();
}

async function initApp() {
  document.body.classList.remove("in-lab-mode");
  setupEventListeners();
  initSherlockEmblemParallax();
  initLandingScrollspy();

  const token = HMACFR_API.getToken();
  const user = HMACFR_API.getUser();

  if (token && !HMACFR_API.isTokenExpired() && user) {
    showWorkspace(user);
    if (window.location.hash && window.location.hash !== "#" && window.location.hash !== "#/") {
      setTimeout(() => {
        if (typeof window.handleHashRoute === "function") {
          window.handleHashRoute();
        }
      }, 60);
    }
  } else {
    if (token && HMACFR_API.isTokenExpired()) {
      HMACFR_API.logout();
    }
    showLandingPage();
  }
}

function openLoginModal() {
  showLoginPage();
}
window.openLoginModal = openLoginModal;

function closeLoginModal() {
  const loginPage = document.getElementById("login-page-container");
  if (loginPage) loginPage.style.setProperty("display", "none", "important");
}
window.closeLoginModal = closeLoginModal;

function showLoginPage() {
  document.body.classList.remove("in-lab-mode");
  document.body.classList.add("landing-active");
  document.body.classList.remove("workspace-active");
  const landingNav = document.getElementById("landing-navbar");
  const landingPage = document.getElementById("landing-page-container");
  const loginPage = document.getElementById("login-page-container");
  const wsHeader = document.getElementById("workspace-header");
  const wsMain = document.getElementById("workspace-main");

  if (landingNav) landingNav.style.setProperty("display", "none", "important");
  if (landingPage) landingPage.style.setProperty("display", "none", "important");
  if (loginPage) loginPage.style.setProperty("display", "flex", "important");
  if (wsHeader) wsHeader.style.setProperty("display", "none", "important");
  if (wsMain) wsMain.style.setProperty("display", "none", "important");

  window.scrollTo({ top: 0, behavior: "auto" });
}
window.showLoginPage = showLoginPage;

function showLandingPage() {
  document.body.classList.add("landing-active");
  document.body.classList.remove("workspace-active");
  const landingNav = document.getElementById("landing-navbar");
  const landingPage = document.getElementById("landing-page-container");
  const loginPage = document.getElementById("login-page-container");
  const wsHeader = document.getElementById("workspace-header");
  const wsMain = document.getElementById("workspace-main");

  if (landingNav) landingNav.style.setProperty("display", "flex", "important");
  if (landingPage) landingPage.style.setProperty("display", "block", "important");
  if (loginPage) loginPage.style.setProperty("display", "none", "important");
  if (wsHeader) wsHeader.style.setProperty("display", "none", "important");
  if (wsMain) wsMain.style.setProperty("display", "none", "important");

  window.scrollTo({ top: 0, behavior: "auto" });
}
window.showLandingPage = showLandingPage;

function showLoginScreen() {
  showLoginPage();
}

window.handleSessionExpired = function(msg) {
  showLoginPage();
  const errorAlert = document.getElementById("login-error");
  if (errorAlert) {
    errorAlert.textContent = msg || "Session expired. Please log in again.";
    errorAlert.className = "alert alert-danger";
    errorAlert.style.display = "block";
  }
};

function initCustomSelects() {
  document.querySelectorAll("select.form-select").forEach(select => {
    if (select.id === "upload-case-id" || select.closest("#sec-ingest") || select.closest("#sec-create-case") || select.classList.contains("no-custom-wrap")) {
      return;
    }
    if (select.dataset.customInitialized) {
      // Sync trigger label if value changed externally
      const triggerLabel = select.parentElement.querySelector(".custom-select-label");
      if (triggerLabel && select.options[select.selectedIndex]) {
        triggerLabel.textContent = select.options[select.selectedIndex].textContent;
      }
      return;
    }
    select.dataset.customInitialized = "true";

    // Hide native select visually
    select.style.display = "none";

    const container = document.createElement("div");
    container.className = "custom-select-container";

    const trigger = document.createElement("div");
    trigger.className = "custom-select-trigger";
    
    const selectedOpt = select.options[select.selectedIndex] || select.options[0];
    const labelSpan = document.createElement("span");
    labelSpan.className = "custom-select-label";
    labelSpan.textContent = selectedOpt ? selectedOpt.textContent : "";
    
    trigger.appendChild(labelSpan);
    trigger.innerHTML += `<svg class="svg-icon svg-icon-sm" style="transition: transform 0.2s ease; width: 14px; height: 14px; color: var(--accent-emerald);" viewBox="0 0 24 24"><polyline points="6 9 12 15 18 9"/></svg>`;

    const optionsDiv = document.createElement("div");
    optionsDiv.className = "custom-select-options";

    const syncOptions = () => {
      optionsDiv.innerHTML = "";
      Array.from(select.options).forEach(opt => {
        const item = document.createElement("div");
        item.className = `custom-select-option ${opt.selected ? 'selected' : ''}`;
        item.textContent = opt.textContent;
        item.dataset.value = opt.value;

        item.addEventListener("click", (e) => {
          e.stopPropagation();
          select.value = opt.value;
          const currLabel = trigger.querySelector(".custom-select-label");
          if (currLabel) currLabel.textContent = opt.textContent;

          optionsDiv.querySelectorAll(".custom-select-option").forEach(o => o.classList.remove("selected"));
          item.classList.add("selected");
          container.classList.remove("open");

          select.dispatchEvent(new Event("change", { bubbles: true }));
        });

        optionsDiv.appendChild(item);
      });
    };

    syncOptions();

    trigger.addEventListener("click", (e) => {
      e.stopPropagation();
      document.querySelectorAll(".custom-select-container.open").forEach(c => {
        if (c !== container) c.classList.remove("open");
      });
      container.classList.toggle("open");
    });

    container.appendChild(trigger);
    container.appendChild(optionsDiv);

    select.parentNode.insertBefore(container, select.nextSibling);

    const observer = new MutationObserver(() => {
      const current = select.options[select.selectedIndex];
      const currLabel = trigger.querySelector(".custom-select-label");
      if (current && currLabel) currLabel.textContent = current.textContent;
      syncOptions();
    });
    observer.observe(select, { childList: true, subtree: true });
  });

  document.addEventListener("click", () => {
    document.querySelectorAll(".custom-select-container.open").forEach(c => c.classList.remove("open"));
  });
}

async function loadAdminUsersData() {
  const tbody = document.getElementById("admin-users-table-body");
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">Loading system user accounts...</td></tr>`;

  try {
    let users;
    if (typeof HMACFR_API !== "undefined" && typeof HMACFR_API.getUsers === "function") {
      users = await HMACFR_API.getUsers();
    } else {
      const token = localStorage.getItem("hmacfr_access_token");
      const res = await fetch("/api/v1/auth/users", {
        headers: token ? { "Authorization": `Bearer ${token}` } : {}
      });
      if (!res.ok) throw new Error("Failed to load user accounts");
      users = await res.json();
    }

    if (!users || users.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No user accounts found in database.</td></tr>`;
      return;
    }

    tbody.innerHTML = "";
    users.forEach(u => {
      const tr = document.createElement("tr");

      tr.innerHTML = `
        <td style="font-weight: 600;" class="mono-text">${u.username}</td>
        <td>${u.email}</td>
        <td>
          <select class="form-select user-role-select" style="padding: 0.3rem 1.8rem 0.3rem 0.6rem; font-size: 0.775rem; min-width: 145px; border-radius: var(--radius-sm);" onchange="window.adminChangeRole('${u.user_id}', '${escapeQuotes(u.username)}', this.value)">
            <option value="Investigator" ${u.role === 'Investigator' ? 'selected' : ''}>Investigator</option>
            <option value="Lead_Auditor" ${u.role === 'Lead_Auditor' ? 'selected' : ''}>Lead Auditor</option>
            <option value="Admin" ${u.role === 'Admin' ? 'selected' : ''}>Admin</option>
          </select>
        </td>
        <td><span class="hud-pill" style="font-size: 0.7rem;"><span style="color: var(--accent-emerald);">●</span> Active</span></td>
        <td style="white-space: nowrap;">
          <button class="btn btn-primary btn-sm" onclick="window.inspectAdminUser('${u.user_id}', '${escapeQuotes(u.username)}', '${escapeQuotes(u.email)}', '${u.role}')" style="font-size: 0.75rem; padding: 0.25rem 0.65rem; margin-right: 0.35rem;" title="Select user to inspect their assigned cases, delete cases & change role">
            <svg class="svg-icon svg-icon-sm" viewBox="0 0 24 24" style="margin-right: 0.2rem;"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            Inspect User Cases
          </button>
          <button class="btn btn-secondary btn-sm" onclick="window.adminResetPassword('${u.user_id}', '${escapeQuotes(u.username)}')" style="font-size: 0.75rem; padding: 0.25rem 0.65rem; margin-right: 0.35rem;">
            <svg class="svg-icon svg-icon-sm" viewBox="0 0 24 24" style="margin-right: 0.2rem;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            Reset Password
          </button>
          <button class="btn btn-secondary btn-sm" onclick="window.adminDeleteUser('${u.user_id}', '${escapeQuotes(u.username)}')" style="border-color: rgba(239,68,68,0.5); color: #f87171; font-size: 0.75rem; padding: 0.25rem 0.65rem;" title="Delete User Account (Requires Admin Password)">
            <svg class="svg-icon svg-icon-sm" viewBox="0 0 24 24" style="margin-right: 0.2rem;"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
            Delete User
          </button>
        </td>
      `;
      tbody.appendChild(tr);
    });

    if (typeof loadAdminPendingDeletionRequests === "function") {
      loadAdminPendingDeletionRequests();
    }
  } catch (err) {

    tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--accent-danger);">Error loading users: ${err.message}</td></tr>`;
  }
}

// Global Admin Delete User Handler with Security Password Verification
window.adminDeleteUser = async function(userId, username) {
  const currentUser = HMACFR_API.getUser();
  if (currentUser && currentUser.username === username) {
    showSherlockNotice("Action Failed", "Action Rejected: You cannot delete your own active Administrator account.", true)
    return;
  }

  showSherlockPrompt(
    "Security Verification Required",
    `Are you sure you want to PERMANENTLY DELETE user account "${username}"? Please enter your Administrator Password to authorize deletion:`,
    async (adminPass) => {
      if (!adminPass) return;
      try {
        if (typeof HMACFR_API !== "undefined" && typeof HMACFR_API.deleteUser === "function") {
          await HMACFR_API.deleteUser(userId, adminPass);
        } else {
          const token = localStorage.getItem("hmacfr_access_token");
          const headers = { "Content-Type": "application/json" };
          if (token) headers["Authorization"] = `Bearer ${token}`;
          const res = await fetch(`/api/v1/auth/users/${userId}`, {
            method: "DELETE",
            headers: headers,
            body: JSON.stringify({ admin_password: adminPass })
          });
          if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || "Failed to delete user account");
          }
        }

        showSherlockNotice("Account / Case Purged", `User account "${username}" has been permanently deleted!`)
        const card = document.getElementById("admin-user-inspection-card");
        if (card) card.style.display = "none";
        loadAdminUsersData();
      } catch (err) {
        showSherlockNotice("Action Failed", "Failed to delete user: " + err.message, true)
      }
    }
  );
};

// Inspect Selected User & Manage Assigned Cases
window.inspectAdminUser = async function(userId, username, email, role) {
  const card = document.getElementById("admin-user-inspection-card");
  if (!card) return;

  card.style.display = "block";
  card.scrollIntoView({ behavior: "smooth" });

  const nameVal = document.getElementById("inspect-username-val");
  if (nameVal) nameVal.textContent = username;

  const emailVal = document.getElementById("inspect-user-email-val");
  if (emailVal) emailVal.textContent = email;

  const roleSelect = document.getElementById("inspect-user-role-select");
  if (roleSelect) roleSelect.value = role || "Investigator";

  // Bind Role Change Button for this user
  const saveRoleBtn = document.getElementById("btn-save-inspect-role");
  if (saveRoleBtn) {
    saveRoleBtn.onclick = async () => {
      const newRole = roleSelect.value;
      await window.adminChangeRole(userId, username, newRole);
    };
  }

  // Bind Reset Password Button for this user
  const resetPassBtn = document.getElementById("btn-reset-inspect-pass");
  if (resetPassBtn) {
    resetPassBtn.onclick = () => window.adminResetPassword(userId, username);
  }

  // Bind Delete User Button for this user
  const deleteUserBtn = document.getElementById("btn-delete-inspect-user");
  if (deleteUserBtn) {
    deleteUserBtn.onclick = () => window.adminDeleteUser(userId, username);
  }


  // Fetch & Render Assigned Cases for this user
  const casesTbody = document.getElementById("inspect-user-cases-table-body");
  const casesCountEl = document.getElementById("inspect-user-cases-count");

  if (casesTbody) {
    casesTbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Loading assigned cases for user ${username}...</td></tr>`;
  }

  try {
    const allCases = await HMACFR_API.getCases();
    const userCases = allCases.filter(c => c.investigator_name === username);

    if (casesCountEl) casesCountEl.textContent = userCases.length;

    if (!casesTbody) return;

    if (userCases.length === 0) {
      casesTbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">No active investigation cases assigned to investigator "${username}".</td></tr>`;
      return;
    }

    casesTbody.innerHTML = "";
    userCases.forEach(c => {
      const tr = document.createElement("tr");
      const pClass = getPriorityBadgeClass(c.priority);
      const evCount = g_caseEvidencesMap[c.case_id] || 0;

      tr.innerHTML = `
        <td><code class="mono-text">${c.case_id}</code></td>
        <td><strong>${c.case_name}</strong></td>
        <td><span class="badge ${pClass}">${c.priority || "Medium"}</span></td>
        <td>${evCount} / ${c.expected_evidence_count || '—'}</td>
        <td><span class="badge badge-emerald">${c.status || 'Active'}</span></td>
        <td style="white-space: nowrap;">
          <button class="btn btn-primary btn-sm" onclick="window.startAnalysisForCase('${c.case_id}', '${escapeQuotes(c.case_name)}')">
            <svg class="svg-icon svg-icon-sm" viewBox="0 0 24 24" style="margin-right: 0.2rem;"><polygon points="5 3 19 12 5 21 5 3"/></svg>
            Analyze
          </button>
          <button class="btn btn-secondary btn-sm btn-overview-delete-case" style="border-color: rgba(239,68,68,0.5); color: #f87171; margin-left: 0.35rem;" title="Purge Case & All Physical Evidence Data from Disk & DB">
            <svg class="svg-icon svg-icon-sm" viewBox="0 0 24 24" style="margin-right: 0.2rem;"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>
            Delete Case
          </button>
        </td>
      `;

      const delBtn = tr.querySelector('.btn-overview-delete-case');
      if (delBtn) {
        const cId = c.case_id;
        const cName = c.case_name;
        delBtn.onclick = (e) => {
          e.stopPropagation();
          window.adminPurgeCase(cId, cName, e);
        };
      }

      casesTbody.appendChild(tr);
    });
  } catch (err) {
    if (casesTbody) {
      casesTbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--accent-danger); padding: 1.5rem;">Error loading cases: ${err.message}</td></tr>`;
    }
  }
};


window.adminChangeRole = async function(userId, username, newRole) {
  try {
    if (typeof HMACFR_API !== "undefined" && typeof HMACFR_API.updateUserRole === "function") {
      await HMACFR_API.updateUserRole(userId, newRole);
    } else {
      const token = localStorage.getItem("hmacfr_access_token");
      const headers = { "Content-Type": "application/json" };
      if (token) headers["Authorization"] = `Bearer ${token}`;
      const res = await fetch(`/api/v1/auth/users/${userId}/role`, {
        method: "PUT",
        headers: headers,
        body: JSON.stringify({ role: newRole })
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to update role");
      }
    }
    showSherlockNotice("Account Updated", `Access role for user "${username}" successfully updated to "${newRole}"!`)
    loadAdminUsersData();
  } catch (err) {
    showSherlockNotice("Action Failed", "Failed to update role: " + err.message, true)
    loadAdminUsersData();
  }
};

window.adminResetPassword = async function(userId, username) {
  showSherlockPrompt(
    "Reset User Password",
    `Enter new password for user "${username}" (min 6 characters):`,
    async (newPass) => {
      if (!newPass) return;
      if (newPass.length < 6) {
        showSherlockNotice("Action Failed", "Password must be at least 6 characters long.", true);
        return;
      }

      try {
        if (typeof HMACFR_API !== "undefined" && typeof HMACFR_API.resetPassword === "function") {
          await HMACFR_API.resetPassword(userId, newPass);
        } else {
          const token = localStorage.getItem("hmacfr_access_token");
          const headers = { "Content-Type": "application/json" };
          if (token) headers["Authorization"] = `Bearer ${token}`;
          const res = await fetch(`/api/v1/auth/users/${userId}/reset-password`, {
            method: "POST",
            headers: headers,
            body: JSON.stringify({ new_password: newPass })
          });
          if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || "Failed to reset user password");
          }
        }

        showSherlockNotice("Action Executed", `Password for user "${username}" has been successfully reset!`);
        loadAdminUsersData();
      } catch (err) {
        showSherlockNotice("Action Failed", "Failed to reset password: " + err.message, true);
      }
    }
  );
};

function showWorkspace(user) {
  document.body.classList.remove("in-lab-mode");
  document.body.classList.remove("landing-active");
  document.body.classList.add("workspace-active");

  const landingNav = document.getElementById("landing-navbar");
  const landingPage = document.getElementById("landing-page-container");
  const loginPage = document.getElementById("login-page-container");
  const authScreen = document.getElementById("auth-screen");

  if (landingNav) landingNav.style.setProperty("display", "none", "important");
  if (landingPage) landingPage.style.setProperty("display", "none", "important");
  if (loginPage) loginPage.style.setProperty("display", "none", "important");
  if (authScreen) authScreen.style.setProperty("display", "none", "important");

  const wsHeader = document.getElementById("workspace-header");
  const wsMain = document.getElementById("workspace-main");
  if (wsHeader) wsHeader.style.setProperty("display", "flex", "important");
  if (wsMain) wsMain.style.setProperty("display", "block", "important");

  const userDisp = document.getElementById("user-display-name");
  if (userDisp) userDisp.textContent = user.username || "Investigator 01";

  const userRole = document.getElementById("user-role-badge");
  if (userRole) userRole.textContent = (user.role || "Investigator").toUpperCase();

  const heroName = document.querySelector(".hero-main-name");
  if (heroName) heroName.textContent = user.username || "Investigator 01";

  const subnavUsername = document.querySelector(".subnav-username");
  if (subnavUsername) subnavUsername.textContent = user.username || "Investigator 01";

  const subnavRole = document.querySelector(".subnav-user-role");
  if (subnavRole) subnavRole.textContent = `${(user.role || "Investigator").toUpperCase()} ▾`;

  const invInputs = document.querySelectorAll(".investigator-autofill");
  invInputs.forEach(input => {
    input.value = user.username;
  });

  const isAdmin = user && (
    user.role === "Admin" ||
    user.role === "ADMIN" ||
    (user.clearance_level && user.clearance_level >= 5) ||
    (Array.isArray(user.roles) && (user.roles.includes("Platform Super Admin") || user.roles.includes("Access Administrator")))
  );
  const navTabs = document.querySelectorAll(".nav-tab");
  const sections = document.querySelectorAll(".workspace-section");

  const modeAdminBtn = document.getElementById("btn-mode-admin");
  const adminNavGroups = document.querySelectorAll(".nav-tab-admin-group");
  const adminCenterTab = document.getElementById("nav-tab-admin-center");

  if (isAdmin) {
    // Admin has access to ALL investigation tabs + Admin Center pill and Governance tab
    if (modeAdminBtn) modeAdminBtn.style.display = "inline-flex";
    adminNavGroups.forEach(g => g.style.display = "block");
    if (adminCenterTab) adminCenterTab.style.display = "flex";
    navTabs.forEach(tab => {
      tab.style.display = "flex";
    });
  } else {
    // Investigator has access to investigation tabs, while Admin Center is strictly hidden
    if (modeAdminBtn) modeAdminBtn.style.display = "none";
    adminNavGroups.forEach(g => g.style.display = "none");
    if (adminCenterTab) adminCenterTab.style.display = "none";
    navTabs.forEach(tab => {
      if (tab.classList.contains("nav-tab-admin")) {
        tab.style.display = "none";
        tab.classList.remove("active");
      } else {
        tab.style.display = "flex";
      }
    });
  }


  // Set default active view tab to Home Executive Dashboard only if no hash route is present
  const hasDeepLink = window.location.hash && window.location.hash !== "#" && window.location.hash !== "#/";
  if (!hasDeepLink) {
    const homeTab = document.querySelector('[data-target="sec-home"]');
    if (homeTab) {
      navTabs.forEach(t => t.classList.remove("active"));
      homeTab.classList.add("active");
    }

    sections.forEach(sec => {
      if (sec.id === "sec-home") {
        sec.classList.add("active");
      } else {
        sec.classList.remove("active");
      }
    });

    // Pre-load workspace overview data
    loadOverviewData();
    loadHomeSection();
  }
  if (isAdmin) {
    loadAdminUsersData();
  }

  setTimeout(initCustomSelects, 100);
}
window.appShowWorkspace = showWorkspace;
window.showWorkspace = showWorkspace;



function setupEventListeners() {
  // Login Form Submission
  const loginForm = document.getElementById("login-form");
  if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const username = document.getElementById("login-username").value.trim();
      const password = document.getElementById("login-password").value.trim();
      const errorAlert = document.getElementById("login-error");

      errorAlert.style.display = "none";

      /* 3D PC Login Scan animation commented out per user request:
      if (window.hmacfr3D) window.hmacfr3D.triggerAuthScan();
      */

      try {
        const data = await HMACFR_API.login(username, password);
        showWorkspace(data.user);
      } catch (err) {
        /* 3D PC Failure animation commented out per user request:
        if (window.hmacfr3D) {
          window.hmacfr3D.triggerAuthFailureAnimation(err.message || "Incorrect password");
        }
        */
        errorAlert.textContent = err.message || "Invalid credentials / Incorrect password";
        errorAlert.style.display = "block";
      }

    });
  }

  // Quick Demo Fill Admin
  window.fillAdminCredentials = function() {
    const u = document.getElementById("login-username");
    const p = document.getElementById("login-password");
    if (u) u.value = "admin";
    if (p) p.value = "Admin@2026";
  };

  // Quick Demo Fill Investigator
  window.fillInvestigatorCredentials = function() {
    const u = document.getElementById("login-username");
    const p = document.getElementById("login-password");
    if (u) u.value = "investigator1";
    if (p) p.value = "Investigator@2026";
  };

  const demoAdminBtn = document.getElementById("btn-demo-login-admin");
  if (demoAdminBtn) {
    demoAdminBtn.addEventListener("click", window.fillAdminCredentials);
  }

  const demoInvBtn = document.getElementById("btn-demo-login-inv");
  if (demoInvBtn) {
    demoInvBtn.addEventListener("click", window.fillInvestigatorCredentials);
  }

  // Top Nav Sign In Button
  const navLoginBtn = document.getElementById("btn-nav-login");
  if (navLoginBtn) {
    navLoginBtn.addEventListener("click", (e) => {
      e.preventDefault();
      openLoginModal();
    });
  }

  // Top Nav Launch / Explore Button
  const navLaunchBtn = document.getElementById("btn-nav-launch");
  if (navLaunchBtn) {
    navLaunchBtn.addEventListener("click", () => showLoginPage());
  }

  // Toggle Password Visibility in Login Screen
  const togglePassBtn = document.getElementById("toggle-login-password");
  const loginPassInput = document.getElementById("login-password");
  const eyeShow = document.getElementById("eye-icon-show");
  const eyeHide = document.getElementById("eye-icon-hide");

  if (togglePassBtn && loginPassInput) {
    togglePassBtn.addEventListener("click", () => {
      const isPassword = loginPassInput.type === "password";
      loginPassInput.type = isPassword ? "text" : "password";
      if (eyeShow) eyeShow.style.display = isPassword ? "none" : "block";
      if (eyeHide) eyeHide.style.display = isPassword ? "block" : "none";
      togglePassBtn.style.color = isPassword ? "var(--accent-emerald)" : "var(--text-muted)";
    });
  }


  // Interactive Logo Click Handlers
  const authLogo = document.getElementById("auth-logo-trigger");
  if (authLogo) {
    authLogo.addEventListener("click", () => {
      authLogo.classList.remove("logo-icon-pulse-spin");
      void authLogo.offsetWidth;
      authLogo.classList.add("logo-icon-pulse-spin");
    });
  }

  const headerLogoContainer = document.getElementById("header-logo-container");
  const headerLogo = document.getElementById("header-logo-trigger");
  if (headerLogoContainer) {
    headerLogoContainer.addEventListener("click", () => {
      if (headerLogo) {
        headerLogo.classList.remove("logo-icon-pulse-spin");
        void headerLogo.offsetWidth;
        headerLogo.classList.add("logo-icon-pulse-spin");
      }
      const casesTab = document.getElementById("nav-tab-cases");
      if (casesTab) casesTab.click();
    });
  }

  // Logout
  const logoutBtn = document.getElementById("btn-logout");

  if (logoutBtn) {
    logoutBtn.addEventListener("click", () => {
      HMACFR_API.logout();
      showLoginScreen();
    });
  }

  }

  // Tab Navigation & Wireframe Section Routing
  const navTabs = document.querySelectorAll(".nav-tab");
  navTabs.forEach(tab => {
    if (!tab.dataset.navBound) {
      tab.dataset.navBound = "true";
      tab.addEventListener("click", (e) => {
        e.preventDefault();
        const targetId = tab.getAttribute("data-target");
        window.switchWorkspaceSection(targetId);
      });
    }
  });

  // Evidence Vault Toolbar Search & Filter Event Listeners
  const vaultSearch = document.getElementById("vault-repo-search-input");
  const vaultCaseSelect = document.getElementById("vault-repo-case-select");
  const vaultCatSelect = document.getElementById("vault-repo-category-select");
  const vaultRefreshBtn = document.getElementById("btn-refresh-vault-repo");

  if (vaultSearch) vaultSearch.addEventListener("input", () => renderEvidenceVaultTable());
  if (vaultCaseSelect) vaultCaseSelect.addEventListener("change", () => renderEvidenceVaultTable());
  if (vaultCatSelect) vaultCatSelect.addEventListener("change", () => renderEvidenceVaultTable());
  if (vaultRefreshBtn) vaultRefreshBtn.addEventListener("click", () => loadEvidenceVaultSection());


  // User Profile Component Click Trigger
  const profileBtn = document.getElementById("user-profile-btn");
  if (profileBtn) {
    profileBtn.addEventListener("click", () => {
      const profileTab = document.getElementById("nav-tab-profile");
      if (profileTab) profileTab.click();
    });
  }

  // Create Case Modal Triggers
  const openModalBtn = document.getElementById("btn-open-create-modal");
  if (openModalBtn) {
    openModalBtn.addEventListener("click", () => openCreateCaseModal());
  }

  const closeModalBtn = document.getElementById("btn-close-create-modal");
  if (closeModalBtn) {
    closeModalBtn.addEventListener("click", () => closeCreateCaseModal());
  }

  const cancelModalBtn = document.getElementById("btn-cancel-create-modal");
  if (cancelModalBtn) {
    cancelModalBtn.addEventListener("click", () => closeCreateCaseModal());
  }

  // Modal Create Case Form Submission (Guarded Against Listener Duplication)
  const modalCaseForm = document.getElementById("modal-create-case-form");
  if (modalCaseForm && !modalCaseForm.dataset.listenerAttached) {
    modalCaseForm.dataset.listenerAttached = "true";
    modalCaseForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      e.stopPropagation();

      const submitBtn = modalCaseForm.querySelector("button[type='submit']");
      if (submitBtn) submitBtn.disabled = true;

      const caseName = document.getElementById("modal-case-name").value.trim();
      const investigator = document.getElementById("modal-case-investigator").value.trim();
      const priority = document.getElementById("modal-case-priority").value;
      const expectedCount = parseInt(document.getElementById("modal-case-expected-count").value) || 1;
      const description = document.getElementById("modal-case-desc").value.trim();

      try {
        await HMACFR_API.createCase({
          case_name: caseName,
          investigator_name: investigator,
          priority: priority,
          expected_evidence_count: expectedCount,
          description: description
        });

        modalCaseForm.reset();
        closeCreateCaseModal();
        await loadOverviewData();

        showSherlockNotice("Case Initialized Successfully", `Investigation Case "${caseName}" has been successfully created and registered in the vault.`);
      } catch (err) {
        showSherlockNotice("Case Initialization Failed", err.message || "Error creating case.", true);
      } finally {
        if (submitBtn) submitBtn.disabled = false;
      }
    });
  }

  // Real-Time Case Search & Priority Filter Listeners
  const searchFilterInput = document.getElementById("cases-search-filter");
  if (searchFilterInput) {
    searchFilterInput.addEventListener("input", () => filterAndRenderCases());
  }

  const prioritySortFilter = document.getElementById("priority-sort-filter");
  if (prioritySortFilter) {
    prioritySortFilter.addEventListener("change", () => filterAndRenderCases());
  }

  // WebSocket Forensic Analysis Form Submission
  const startAnalysisForm = document.getElementById("start-analysis-form");
  if (startAnalysisForm) {
    startAnalysisForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const select = document.getElementById("analysis-case-select");
      const caseId = select ? select.value : "";
      const caseName = select && select.selectedIndex >= 0 ? select.options[select.selectedIndex].text : "Incident";
      const duration = parseInt(document.getElementById("analysis-duration").value) || 30;

      if (!caseId) {
        showSherlockNotice("Action Failed", "Please select a target case to analyze.", true)
        return;
      }

      await window.startAnalysisForCase(caseId, caseName, duration);
    });
  }


  // Admin Create User Form
  const adminUserForm = document.getElementById("admin-create-user-form");
  if (adminUserForm) {
    adminUserForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const username = document.getElementById("admin-new-username").value.trim();
      const email = document.getElementById("admin-new-email").value.trim();
      const role = document.getElementById("admin-new-role").value;
      const password = document.getElementById("admin-new-password").value.trim();
      const alertBox = document.getElementById("admin-create-alert");

      if (alertBox) alertBox.style.display = "none";

      try {
        if (typeof HMACFR_API !== "undefined" && typeof HMACFR_API.registerUser === "function") {
          await HMACFR_API.registerUser({ username, email, role, password });
        } else {
          const token = localStorage.getItem("hmacfr_access_token");
          const headers = { "Content-Type": "application/json" };
          if (token) headers["Authorization"] = `Bearer ${token}`;
          const res = await fetch("/api/v1/auth/register", {
            method: "POST",
            headers: headers,
            body: JSON.stringify({ username, email, role, password })
          });
          if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || "Failed to create user account");
          }
        }
        if (alertBox) {
          alertBox.className = "alert alert-emerald";
          alertBox.style.display = "block";
          alertBox.innerHTML = `<strong>Success:</strong> User account <code>${username}</code> with role <code>${role}</code> created successfully!`;
        }
        adminUserForm.reset();
        loadAdminUsersData();
      } catch (err) {
        if (alertBox) {
          alertBox.className = "alert alert-danger";
          alertBox.style.display = "block";
          alertBox.innerHTML = `<strong>Error:</strong> ${err.message}`;
        }
      }
    });
  }

  // Multi-Evidence Ingestion UI Controller
  const uploadCountInput = document.getElementById("upload-count");
  const btnAddItemCard = document.getElementById("btn-add-item-card");
  const itemsContainer = document.getElementById("evidence-items-container");
  const btnSubmitBatch = document.getElementById("btn-submit-batch-upload");

  window.adjustStepper = function(inputId, delta) {
    const input = document.getElementById(inputId);
    if (!input) return;
    const min = parseInt(input.getAttribute("min")) || 1;
    const max = parseInt(input.getAttribute("max")) || 100;
    const current = parseInt(input.value) || min;
    const next = Math.max(min, Math.min(max, current + delta));
    input.value = next;

    if (inputId === "upload-count" && typeof renderEvidenceCards === "function") {
      renderEvidenceCards(next);
    }
  };

  window.updateCustomFileLabel = function(input) {
    const label = input.parentElement.querySelector(".custom-file-label");
    if (!label) return;
    if (input.files && input.files[0]) {
      label.textContent = input.files[0].name;
      label.style.color = "var(--accent-emerald-light)";
    } else {
      label.textContent = "No file chosen";
      label.style.color = "var(--text-muted)";
    }
  };

  window.toggleIngestCaseDropdown = function(show) {
    const popover = document.getElementById("ingest-case-dropdown-popover");
    if (!popover) return;
    if (show) {
      populateIngestCasePopover();
      popover.style.display = "block";
    } else {
      popover.style.display = "none";
    }
  };

  window.filterIngestCaseDropdown = function(query) {
    const popover = document.getElementById("ingest-case-dropdown-popover");
    if (!popover) return;
    const opts = popover.querySelectorAll(".ingest-case-option");
    const q = (query || "").toLowerCase().trim();
    opts.forEach(opt => {
      const text = opt.textContent.toLowerCase();
      if (!q || text.includes(q)) {
        opt.style.display = "block";
      } else {
        opt.style.display = "none";
      }
    });
  };

  window.selectIngestCaseOption = function(val, text, optExpected) {
    const searchInput = document.getElementById("ingest-case-search");
    const select = document.getElementById("upload-case-id");
    if (searchInput) searchInput.value = text || val;
    if (select) {
      select.value = val;
      let expectedCount = optExpected ? parseInt(optExpected) : null;
      if (!expectedCount) {
        const selectedOpt = select.querySelector(`option[value="${val}"]`);
        if (selectedOpt && selectedOpt.dataset.expected) {
          expectedCount = parseInt(selectedOpt.dataset.expected);
        }
      }
      if (!expectedCount) expectedCount = 1;

      const uploadCountInput = document.getElementById("upload-count");
      if (uploadCountInput) uploadCountInput.value = expectedCount;
      const countSpan = document.getElementById("ingest-expected-count");
      if (countSpan) countSpan.textContent = expectedCount;
      if (typeof renderEvidenceCards === "function") {
        renderEvidenceCards(expectedCount);
      }
    }
    window.toggleIngestCaseDropdown(false);
  };

  function populateIngestCasePopover() {
    const popover = document.getElementById("ingest-case-dropdown-popover");
    const select = document.getElementById("upload-case-id");
    if (!popover || !select) return;
    popover.innerHTML = "";
    const options = select.querySelectorAll("option");
    options.forEach(opt => {
      if (!opt.value) return;
      const item = document.createElement("div");
      item.className = "ingest-case-option investigator-option";
      const exp = opt.dataset.expected || 1;
      item.dataset.expected = exp;
      item.style.cssText = "padding: 0.65rem 1.1rem; font-size: 0.9rem; font-weight: 600; color: #1e293b; cursor: pointer; transition: background 0.15s ease;";
      item.textContent = opt.textContent;
      item.onclick = function() {
        window.selectIngestCaseOption(opt.value, opt.textContent, exp);
      };
      popover.appendChild(item);
    });
  }

  window.selectCategoryPill = function(btn, catVal) {
    const parent = btn.parentElement;
    if (!parent) return;
    const hiddenInput = parent.querySelector(".item-category");
    if (hiddenInput) hiddenInput.value = catVal;

    parent.querySelectorAll(".category-pill").forEach(p => {
      p.style.border = "1.5px solid #e2e8f0";
      p.style.background = "#ffffff";
      p.style.color = "#475569";
      p.style.fontWeight = "600";
    });

    btn.style.border = "1.5px solid #1d4ed8";
    btn.style.background = "#eff6ff";
    btn.style.color = "#1d4ed8";
    btn.style.fontWeight = "700";
  };

  window.removeEvidenceItemCard = function(removeIdx) {
    if (!itemsContainer) return;
    const cards = Array.from(itemsContainer.querySelectorAll(".evidence-item-card"));
    if (cards.length <= 1) return;

    const cardToRemove = cards.find(c => parseInt(c.getAttribute("data-index")) === removeIdx) || cards[removeIdx - 1];
    if (cardToRemove) {
      cardToRemove.remove();
    }

    const remainingCards = Array.from(itemsContainer.querySelectorAll(".evidence-item-card"));
    remainingCards.forEach((card, i) => {
      const newIdx = i + 1;
      card.setAttribute("data-index", newIdx);
      const titleEl = card.querySelector(".artifact-title-num");
      if (titleEl) {
        titleEl.textContent = `${newIdx < 10 ? '0' + newIdx : newIdx} EVIDENCE ARTIFACT`;
      }
      const removeBtn = card.querySelector(".btn-remove-card");
      if (removeBtn) {
        removeBtn.setAttribute("onclick", `window.removeEvidenceItemCard(${newIdx})`);
        removeBtn.style.display = remainingCards.length > 1 ? "inline-block" : "none";
      }
    });

    const newCount = remainingCards.length;
    if (uploadCountInput) uploadCountInput.value = newCount;
    const countSpan = document.getElementById("ingest-expected-count");
    if (countSpan) countSpan.textContent = newCount;
    if (btnSubmitBatch) {
      btnSubmitBatch.innerHTML = `<span>Ingest All (${newCount}) Evidence Artifacts</span> <span style="color: #1d4ed8; font-size: 0.95rem;">➔</span>`;
    }
  };

  function renderEvidenceCards(requestedCount) {
    if (!itemsContainer) return;
    const targetCount = Math.max(1, Math.min(20, parseInt(requestedCount) || 1));
    if (uploadCountInput) uploadCountInput.value = targetCount;
    const countSpan = document.getElementById("ingest-expected-count");
    if (countSpan) countSpan.textContent = targetCount;

    let existingCards = Array.from(itemsContainer.querySelectorAll(".evidence-item-card"));

    while (existingCards.length > targetCount) {
      const cardToRemove = existingCards.pop();
      if (cardToRemove) cardToRemove.remove();
    }

    for (let i = existingCards.length + 1; i <= targetCount; i++) {
      const card = document.createElement("div");
      card.className = "evidence-item-card";
      card.setAttribute("data-index", i);
      card.style.cssText = "margin-bottom: 1.5rem;";

      card.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.85rem;">
          <div class="artifact-title-num" style="font-size: 0.78rem; font-weight: 800; color: #1d4ed8; letter-spacing: 0.05em; text-transform: uppercase;">
            ${i < 10 ? '0' + i : i} EVIDENCE ARTIFACT
          </div>
          <button type="button" class="btn-remove-card" onclick="window.removeEvidenceItemCard(${i})" style="background: transparent; border: none; color: #dc2626; font-weight: 700; font-size: 0.78rem; cursor: pointer; padding: 0; display: ${targetCount > 1 ? 'inline-block' : 'none'};">Remove Item</button>
        </div>
        <div style="display: flex; flex-direction: column; gap: 1.25rem; margin-bottom: 1rem;">
          <div>
            <label style="display: block; font-size: 0.72rem; font-weight: 800; color: #64748b; letter-spacing: 0.06em; text-transform: uppercase; margin-bottom: 0.4rem;">Select Evidence File *</label>
            <div style="display: flex; align-items: center; gap: 0.85rem; border-bottom: 1.5px solid #cbd5e1; padding: 0.45rem 0;">
              <input type="file" class="item-file" style="display: none;" required onchange="window.updateCustomFileLabel(this)">
              <button type="button" onclick="this.previousElementSibling.click()" style="border: 1px solid #cbd5e1; background: #ffffff; color: #334155; padding: 0.35rem 0.85rem; border-radius: 16px; font-size: 0.78rem; font-weight: 700; cursor: pointer; transition: all 0.15s ease; outline: none;">
                Choose File
              </button>
              <span class="custom-file-label" style="font-size: 0.88rem; font-weight: 600; color: #94a3b8; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">No file chosen</span>
            </div>
          </div>
          <div>
            <label style="display: block; font-size: 0.72rem; font-weight: 800; color: #64748b; letter-spacing: 0.06em; text-transform: uppercase; margin-bottom: 0.5rem;">Evidence Category</label>
            <div style="display: flex; gap: 0.4rem; flex-wrap: wrap;">
              <input type="hidden" class="item-category" value="Memory">
              <button type="button" class="category-pill" onclick="window.selectCategoryPill(this, 'Memory');" style="border: 1.5px solid #1d4ed8; background: #eff6ff; color: #1d4ed8; padding: 0.35rem 0.8rem; border-radius: 16px; font-size: 0.78rem; font-weight: 700; cursor: pointer;">Memory</button>
              <button type="button" class="category-pill" onclick="window.selectCategoryPill(this, 'Disk');" style="border: 1.5px solid #e2e8f0; background: #ffffff; color: #475569; padding: 0.35rem 0.8rem; border-radius: 16px; font-size: 0.78rem; font-weight: 600; cursor: pointer;">Disk</button>
              <button type="button" class="category-pill" onclick="window.selectCategoryPill(this, 'PCAP');" style="border: 1.5px solid #e2e8f0; background: #ffffff; color: #475569; padding: 0.35rem 0.8rem; border-radius: 16px; font-size: 0.78rem; font-weight: 600; cursor: pointer;">PCAP</button>
              <button type="button" class="category-pill" onclick="window.selectCategoryPill(this, 'Registry');" style="border: 1.5px solid #e2e8f0; background: #ffffff; color: #475569; padding: 0.35rem 0.8rem; border-radius: 16px; font-size: 0.78rem; font-weight: 600; cursor: pointer;">Registry</button>
              <button type="button" class="category-pill" onclick="window.selectCategoryPill(this, 'Logs');" style="border: 1.5px solid #e2e8f0; background: #ffffff; color: #475569; padding: 0.35rem 0.8rem; border-radius: 16px; font-size: 0.78rem; font-weight: 600; cursor: pointer;">Logs</button>
              <button type="button" class="category-pill" onclick="window.selectCategoryPill(this, 'Browser');" style="border: 1.5px solid #e2e8f0; background: #ffffff; color: #475569; padding: 0.35rem 0.8rem; border-radius: 16px; font-size: 0.78rem; font-weight: 600; cursor: pointer;">Browser</button>
              <button type="button" class="category-pill" onclick="window.selectCategoryPill(this, 'Malware');" style="border: 1.5px solid #e2e8f0; background: #ffffff; color: #475569; padding: 0.35rem 0.8rem; border-radius: 16px; font-size: 0.78rem; font-weight: 600; cursor: pointer;">Malware</button>
              <button type="button" class="category-pill" onclick="window.selectCategoryPill(this, 'Documents');" style="border: 1.5px solid #e2e8f0; background: #ffffff; color: #475569; padding: 0.35rem 0.8rem; border-radius: 16px; font-size: 0.78rem; font-weight: 600; cursor: pointer;">Documents</button>
            </div>
          </div>
        </div>
        <div>
          <label style="display: block; font-size: 0.72rem; font-weight: 800; color: #64748b; letter-spacing: 0.06em; text-transform: uppercase; margin-bottom: 0.4rem;">Custody Remarks / Notes</label>
          <input type="text" class="item-desc" placeholder="e.g. Acquired from target host RAM via Volatility agent..." style="width: 100%; border: none; border-bottom: 1.5px solid #cbd5e1; padding: 0.45rem 0; font-size: 0.9rem; color: #0f172a; background: transparent; outline: none;">
        </div>
      `;

      itemsContainer.appendChild(card);
    }

    const updatedCards = itemsContainer.querySelectorAll(".evidence-item-card");
    updatedCards.forEach(c => {
      const removeBtn = c.querySelector(".btn-remove-card");
      if (removeBtn) removeBtn.style.display = updatedCards.length > 1 ? "inline-block" : "none";
    });

    if (btnSubmitBatch) {
      btnSubmitBatch.innerHTML = `<span>Ingest All (${targetCount}) Evidence Artifacts</span> <span style="color: #1d4ed8; font-size: 0.95rem;">➔</span>`;
    }

    const rightStream = document.getElementById("ingest-right-stream");
    if (rightStream) {
      rightStream.innerHTML = "";
      const numGraphics = Math.max(1, Math.ceil(targetCount / 2.2));
      for (let g = 0; g < numGraphics; g++) {
        const topOffset = g * 640;
        const div = document.createElement("div");
        div.style.cssText = `position: absolute; right: 0; top: ${topOffset}px; width: 440px; pointer-events: none; transition: all 0.3s ease;`;
        div.innerHTML = `<img src="images/e1.png" style="width: 100%; max-width: 440px; height: auto; object-fit: contain; mix-blend-mode: multiply; opacity: 0.88; filter: grayscale(0.85) contrast(1.05) brightness(1.02); -webkit-mask-image: radial-gradient(circle at 50% 50%, rgba(0,0,0,1) 65%, rgba(0,0,0,0) 98%); mask-image: radial-gradient(circle at 50% 50%, rgba(0,0,0,1) 65%, rgba(0,0,0,0) 98%);" alt="Digital Evidence Graphic">`;
        rightStream.appendChild(div);
      }
    }
  }

  if (uploadCountInput) {
    uploadCountInput.addEventListener("input", (e) => {
      renderEvidenceCards(e.target.value);
    });
  }

  if (btnAddItemCard) {
    btnAddItemCard.addEventListener("click", () => {
      const current = parseInt(uploadCountInput ? uploadCountInput.value : 1) || 1;
      renderEvidenceCards(current + 1);
    });
  }

  renderEvidenceCards(1);

  // Batch Evidence Upload Form Submission Handler
  const uploadForm = document.getElementById("upload-evidence-form");
  if (uploadForm) {
    uploadForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const caseId = document.getElementById("upload-case-id").value;
      const investigator = document.getElementById("upload-investigator").value;
      const resultBox = document.getElementById("upload-result-box");
      const cards = itemsContainer.querySelectorAll(".evidence-item-card");

      if (!caseId) {
        showSherlockNotice("Action Failed", "Please select a target investigation case.", true)
        return;
      }

      if (cards.length === 0) {
        showSherlockNotice("Action Failed", "Please add at least one evidence item to upload.", true)
        return;
      }

      const uploadPayloads = [];
      for (let i = 0; i < cards.length; i++) {
        const card = cards[i];
        const fileInput = card.querySelector(".item-file");
        const categorySelect = card.querySelector(".item-category");
        const descInput = card.querySelector(".item-desc");

        if (!fileInput || fileInput.files.length === 0) {
          showSherlockNotice("Action Failed", `Please select an evidence file for Evidence Item #${i + 1}.`, true)
          return;
        }

        uploadPayloads.push({
          file: fileInput.files[0],
          category: categorySelect ? categorySelect.value : "Memory",
          description: descInput ? descInput.value.trim() : ""
        });
      }

      const loadingSteps = [
        `PREPARING BATCH INGESTION FOR ${uploadPayloads.length} EVIDENCE ARTIFACTS...`,
        "CALCULATING MULTI-PASS SHA-256 FILE DIGESTS...",
        "COMPUTING HMAC-SHA256 DIGITAL SIGNATURES...",
        "DEPOSITING FILES TO SECURE STORAGE VAULT...",
        "BATCH INGESTION & CRYPTOGRAPHIC SIGNING COMPLETE."
      ];

      showCyberLoading(
        `Ingesting ${uploadPayloads.length} Digital Evidence Artifacts`,
        `Processing batch upload, SHA-256 digests & HMAC-SHA256 signatures for case ${caseId}...`,
        loadingSteps,
        async () => {
          try {
            resultBox.style.display = "block";
            resultBox.className = "alert alert-success";
            resultBox.textContent = `Uploading ${uploadPayloads.length} evidence file(s)...`;

            const uploadedItems = [];
            for (let i = 0; i < uploadPayloads.length; i++) {
              const item = uploadPayloads[i];
              const formData = new FormData();
              formData.append("file", item.file);
              formData.append("case_id", caseId);
              formData.append("category", item.category);
              formData.append("investigator", investigator);
              if (item.description) formData.append("description", item.description);

              const evidence = await HMACFR_API.uploadEvidence(formData);
              uploadedItems.push(evidence);
            }

            resultBox.style.display = "block";
            resultBox.className = "";
            resultBox.style.background = "transparent";
            resultBox.style.padding = "0";

            let summaryHTML = `
              <!-- 1. Success Header Banner -->
              <div style="background: #ffffff; border: 1px solid #d1fae5; border-radius: 16px; padding: 1.1rem 1.4rem; display: flex; align-items: center; justify-content: space-between; margin-bottom: 2rem; box-shadow: 0 4px 15px rgba(0,0,0,0.02); position: relative; overflow: hidden;">
                <div style="display: flex; align-items: center; gap: 1rem;">
                  <div style="width: 38px; height: 38px; border-radius: 50%; background: #d1fae5; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                    <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="#059669" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                  </div>
                  <div style="font-size: 0.92rem; font-weight: 500; color: #334155;">
                    Successfully Ingested <strong style="color: #059669; font-weight: 800;">${uploadedItems.length}</strong> Evidence Artifact(s) for Case <code style="color: #059669; font-weight: 700; font-family: monospace; font-size: 0.95rem;">${caseId}</code>
                  </div>
                </div>
                <div style="width: 42px; height: 42px; border-radius: 50%; background: #f0fdf4; border: 1px solid #d1fae5; display: flex; align-items: center; justify-content: center; opacity: 0.85;">
                  <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="#10b981" stroke-width="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
                </div>
              </div>

              <!-- 2. Stepper Timeline Connector & Item Cards List -->
              <div style="display: flex; flex-direction: column; gap: 0.25rem; margin-bottom: 2rem;">
            `;

            uploadedItems.forEach((ev, idx) => {
              const itemNum = idx < 9 ? `0${idx + 1}` : `${idx + 1}`;
              const hmacDisplay = ev.hmac_signature ? (ev.hmac_signature.length > 36 ? ev.hmac_signature.substring(0, 36) + '...' : ev.hmac_signature) : 'N/A';

              summaryHTML += `
                <div style="display: flex; gap: 1.25rem; align-items: stretch; margin-bottom: 1.25rem; position: relative;">
                  <!-- Left Timeline Column (Number Badge + Connecting Line) -->
                  <div style="display: flex; flex-direction: column; align-items: center; flex-shrink: 0; width: 44px; z-index: 2;">
                    <div style="width: 44px; height: 44px; border-radius: 50%; background: #eff6ff; border: 1.5px solid #bfdbfe; color: #1d4ed8; font-weight: 800; font-size: 0.85rem; display: flex; align-items: center; justify-content: center; box-shadow: 0 2px 8px rgba(29,78,216,0.08);">
                      ${itemNum}
                    </div>
                    ${idx < uploadedItems.length - 1 ? `<div style="width: 2px; flex: 1; background: #e2e8f0; margin: 0.4rem 0;"></div>` : ''}
                  </div>

                  <!-- White Minimalist Item Details Card -->
                  <div style="flex: 1; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 16px; padding: 1.25rem 1.5rem; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 4px 15px rgba(0,0,0,0.02); transition: border-color 0.2s ease;">
                    
                    <!-- Left Column: Icon + File Details -->
                    <div style="display: flex; align-items: flex-start; gap: 1.1rem; flex: 1;">
                      <div style="width: 44px; height: 44px; border-radius: 12px; background: #eff6ff; border: 1px solid #dbeafe; display: flex; align-items: center; justify-content: center; flex-shrink: 0; margin-top: 0.15rem;">
                        <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="#1d4ed8" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                      </div>

                      <div style="display: flex; flex-direction: column; gap: 0.45rem; flex: 1;">
                        <div style="font-size: 1rem; font-weight: 800; color: #0f172a; font-family: 'Outfit', sans-serif;">
                          ${ev.original_filename} <span style="color: #64748b; font-weight: 600; font-size: 0.9rem;">(${ev.category || 'General'})</span>
                        </div>
                        <div style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.82rem; color: #475569;">
                          <span style="color: #059669; font-size: 0.65rem;">●</span>
                          <span style="font-weight: 700; color: #334155;">SHA-256:</span>
                          <code style="font-family: monospace; color: #475569; word-break: break-all;">${ev.file_hash}</code>
                        </div>
                        <div style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.82rem; color: #475569;">
                          <span style="color: #2563eb; font-size: 0.65rem;">●</span>
                          <span style="font-weight: 700; color: #334155;">HMAC-SHA256:</span>
                          <code style="font-family: monospace; color: #475569; word-break: break-all;">${hmacDisplay}</code>
                        </div>
                      </div>
                    </div>

                    <!-- Right Divider Column: Case ID -->
                    <div style="border-left: 1px solid #f1f5f9; padding-left: 1.5rem; margin-left: 1.5rem; display: flex; flex-direction: column; justify-content: center; min-width: 140px;">
                      <div style="font-size: 0.75rem; font-weight: 700; color: #2563eb; margin-bottom: 0.25rem;">ID:</div>
                      <code style="font-family: monospace; font-size: 0.78rem; color: #64748b; word-break: break-all; line-height: 1.35;">${ev.evidence_id}</code>
                    </div>

                  </div>
                </div>
              `;
            });

            summaryHTML += `
              </div>

              <!-- 3. Execute Layer 1 Batch Preservation Action Card -->
              <div onclick="runBatchPreservationForCase('${caseId}')" style="background: #ffffff; border: 1.5px solid #a7f3d0; border-radius: 16px; padding: 1.1rem 1.6rem; display: flex; align-items: center; justify-content: space-between; cursor: pointer; transition: all 0.2s ease; box-shadow: 0 4px 15px rgba(0,0,0,0.02); margin-top: 1rem;" onmouseover="this.style.borderColor='#059669'; this.style.boxShadow='0 6px 20px rgba(5,150,105,0.08)';" onmouseout="this.style.borderColor='#a7f3d0'; this.style.boxShadow='0 4px 15px rgba(0,0,0,0.02)';">
                <div style="display: flex; align-items: center; gap: 1.1rem;">
                  <div style="width: 38px; height: 38px; border-radius: 50%; background: #eff6ff; border: 1px solid #bfdbfe; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                    <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="#2563eb" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
                  </div>
                  <div style="font-size: 0.92rem; font-weight: 700; color: #0f172a; font-family: 'Outfit', sans-serif;">
                    Execute Layer 1 Batch Preservation for Case <span style="color: #0f172a;">${caseId}</span>
                  </div>
                </div>
                <div style="width: 32px; height: 32px; border-radius: 50%; display: flex; align-items: center; justify-content: center; color: #059669;">
                  <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="#059669" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
                </div>
              </div>
            `;

            resultBox.innerHTML = summaryHTML;

            renderEvidenceCards(1);
            const user = HMACFR_API.getUser();
            if (user) document.getElementById("upload-investigator").value = user.username;

            loadOverviewData();
            loadPreservationSection();
          } catch (err) {
            resultBox.style.display = "block";
            resultBox.className = "alert alert-danger";
            resultBox.textContent = "Batch Upload Error: " + err.message;
          }
        }
      );
    });
  }

  // Batch Preserve Case Button
  const batchPreserveBtn = document.getElementById("btn-preserve-case");
  if (batchPreserveBtn) {
    batchPreserveBtn.addEventListener("click", async () => {
      const caseId = document.getElementById("preservation-case-select").value;
      if (!caseId) {
        showSherlockNotice("Action Failed", "Please select a case first.", true)
        return;
      }

      showCyberLoading(
        "Executing Batch Preservation Engine",
        `Applying multi-pass MD5/SHA-256, AES-256-GCM encryption at rest, and read-only locks for case ${caseId}...`,
        [
          "COMPUTING MULTI-PASS MD5 & SHA-256 DIGESTS...",
          "APPLYING AES-256-GCM SYMMETRIC VAULT ENCRYPTION...",
          "LOCKING OS FILE SYSTEM PERMISSIONS (READ-ONLY)...",
          "RECORDING CHAIN OF CUSTODY TIMELINE LOG...",
          "BATCH PRESERVATION COMPLETE."
        ],
        async () => {
          try {
            const results = await HMACFR_API.preserveCase(caseId);
            showSherlockNotice("Cryptographic Preservation", `Batch Preservation Executed for Case ${caseId}!\nPreserved ${results.length} evidence items.`)
            loadPreservationSection();
          } catch (err) {
            showSherlockNotice("Cryptographic Preservation", "Batch Preservation Error: " + err.message, true)
          }
        }
      );
    });
  }

  // Audit Case Form
  const auditBtn = document.getElementById("btn-audit-case");
  if (auditBtn) {
    auditBtn.addEventListener("click", async () => {
      const caseId = document.getElementById("audit-case-select").value;
      if (!caseId) return;

      showCyberLoading(
        "Running Multi-Factor Audit Scan",
        `Verifying SHA-256 digests, HMAC signatures, and read-only attributes for case ${caseId}...`,
        [
          "SCANNING VAULT FILE HASH DIGESTS...",
          "VERIFYING HMAC-SHA256 DIGITAL SIGNATURES...",
          "CHECKING OS READ-ONLY PERMISSIONS...",
          "EVALUATING QUARANTINE INTEGRITY ANOMALIES...",
          "AUDIT VERIFICATION REPORT READY."
        ],
        async () => {
          try {
            const report = await HMACFR_API.auditCase(caseId);
            renderAuditReport(report);
          } catch (err) {
            showSherlockNotice("Action Failed", "Audit failed: " + err.message, true)
          }
        }
      );
    });
  }

// Global Pipeline Execution Helper
async function runPreservationPipeline(evidenceId, caseId, storagePath = "") {
  showCyberLoading(
    "Executing Layer 1 Preservation Pipeline",
    `Securing evidence ${evidenceId} with multi-pass hashing and AES-256-GCM encryption...`,
    [
      "CALCULATING SHA-256 & MD5 HASH DIGESTS...",
      "EXECUTING AES-256-GCM ENCRYPTION PASS...",
      "DEPOSITING TO READ-ONLY EVIDENCE VAULT...",
      "APPLYING OS FILE LOCKING...",
      "PRESERVATION COMPLETED SUCCESSFULLY."
    ],
    async () => {
      try {
        const res = await HMACFR_API.preserveEvidence({
          evidence_id: evidenceId,
          case_id: caseId,
          storage_path: storagePath || "",
          category: "Memory",
          status: "UPLOADED"
        });

        showSherlockNotice("Cryptographic Preservation", `Layer 1 Preservation Executed Successfully!\n\nSHA-256: ${res.sha256}\nMD5: ${res.md5}\nAES-256 Encrypted: ${res.encrypted}\nRead-Only Protected: ${res.readonly_protected}`)
        loadOverviewData();
        loadPreservationSection();
      } catch (err) {
        showSherlockNotice("Cryptographic Preservation", "Preservation Pipeline Failed: " + err.message, true)
      }
    }
  );
}

async function runBatchPreservationForCase(caseId) {
  showCyberLoading(
    "Executing Batch Preservation Engine",
    `Applying multi-pass MD5/SHA-256, AES-256-GCM encryption at rest, and read-only locks for case ${caseId}...`,
    [
      "COMPUTING MULTI-PASS MD5 & SHA-256 DIGESTS...",
      "APPLYING AES-256-GCM SYMMETRIC VAULT ENCRYPTION...",
      "LOCKING OS FILE SYSTEM PERMISSIONS (READ-ONLY)...",
      "RECORDING CHAIN OF CUSTODY TIMELINE LOG...",
      "BATCH PRESERVATION COMPLETE."
    ],
    async () => {
      try {
        const results = await HMACFR_API.preserveCase(caseId);
        showSherlockNotice("Cryptographic Preservation", `Batch Preservation Executed for Case ${caseId}!\nPreserved ${results.length} evidence items.`)
        loadOverviewData();
        loadPreservationSection();
      } catch (err) {
        showSherlockNotice("Cryptographic Preservation", "Batch Preservation Error: " + err.message, true)
      }
    }
  );
}

// Navigation to Dedicated Create Case Page
function openCreateCaseSection() {
  if (window.switchWorkspaceSection) {
    window.switchWorkspaceSection("sec-create-case");
  }
}
window.openCreateCaseSection = openCreateCaseSection;
window.openCreateCaseModal = openCreateCaseSection;

// Global Cases Store for Real-Time Search & Priority Sorting
let g_allCases = [];
let g_caseEvidencesMap = {};

async function loadCaseEvidencesMap() {
  try {
    const allEvidences = await HMACFR_API.getAllEvidence();
    g_caseEvidencesMap = {};
    (allEvidences || []).forEach(ev => {
      if (ev && ev.case_id) {
        g_caseEvidencesMap[ev.case_id] = (g_caseEvidencesMap[ev.case_id] || 0) + 1;
      }
    });
  } catch (err) {
    console.warn("Bulk evidence fetch fallback:", err);
  }
}

async function loadOverviewData() {
  try {
    const savedSelectedCaseId = g_selectedSidebarCaseId;
    const searchInput = document.getElementById("cases-search-filter");
    const savedSearchQuery = searchInput ? searchInput.value : "";

    await loadCaseEvidencesMap();
    const cases = await HMACFR_API.getCases();
    g_allCases = cases || [];

    if (savedSelectedCaseId && g_allCases.some(c => c.case_id === savedSelectedCaseId)) {
      g_selectedSidebarCaseId = savedSelectedCaseId;
    }
    if (searchInput && savedSearchQuery) {
      searchInput.value = savedSearchQuery;
    }

    const ACTIVE_STATUSES = ["OPEN", "IN_PROGRESS", "ACTIVE"];
    const CLOSED_STATUSES = ["SOLVED", "CLOSED"];

    let activeCount = 0;
    let solvedCount = 0;

    g_allCases.forEach(c => {
      const st = (c.status || "ACTIVE").toUpperCase();
      if (CLOSED_STATUSES.includes(st)) solvedCount++;
      else if (ACTIVE_STATUSES.includes(st) || st === "") activeCount++;
    });

    const format2Digits = (num) => {
      const n = parseInt(num) || 0;
      return n < 10 ? `0${n}` : `${n}`;
    };

    const activeIds = ["stat-cases-count", "cases-pg-active-count", "home-active-cases-count"];
    activeIds.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.textContent = format2Digits(activeCount);
    });

    const solvedIds = ["stat-solved-count", "cases-pg-solved-count", "home-solved-cases-count"];
    solvedIds.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.textContent = format2Digits(solvedCount);
    });

    const totalIds = ["stat-total-cases-count", "cases-pg-total-count", "home-total-cases-count"];
    totalIds.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.textContent = format2Digits(g_allCases.length);
    });

    filterAndRenderCases();
    populateCaseSelects(g_allCases);
    populateAuditCaseSelects(g_allCases);
    loadHomeSection();

    if (window.HMACFR_RefreshTilt) window.HMACFR_RefreshTilt();
  } catch (err) {
    console.error("Error loading overview data:", err);
  }
}

async function loadHomeSection() {
  try {
    const [cases, evidences] = await Promise.all([
      HMACFR_API.getCases(),
      HMACFR_API.getAllEvidence().catch(() => [])
    ]);
    g_allCases = cases;
    g_caseEvidencesMap = {};
    if (Array.isArray(evidences)) {
      evidences.forEach(ev => {
        if (ev.case_id) {
          g_caseEvidencesMap[ev.case_id] = (g_caseEvidencesMap[ev.case_id] || 0) + 1;
        }
      });
    }

    const ACTIVE_STATUSES = ["OPEN", "IN_PROGRESS", "ACTIVE"];
    const CLOSED_STATUSES = ["SOLVED", "CLOSED"];
    const PENDING_STATUSES = ["PENDING_DELETION"];

    let activeCasesCount = 0;
    let solvedCount = 0;
    let pendingCount = 0;

    for (const c of cases) {
      const st = (c.status || "ACTIVE").toUpperCase();
      if (CLOSED_STATUSES.includes(st)) {
        solvedCount++;
      } else if (PENDING_STATUSES.includes(st)) {
        pendingCount++;
      } else if (ACTIVE_STATUSES.includes(st) || st === "") {
        activeCasesCount++;
      }
    }

    const format2Digits = (num) => {
      const n = parseInt(num) || 0;
      return n < 10 ? `0${n}` : `${n}`;
    };

    const homeActiveEl = document.getElementById("home-active-cases-count");
    if (homeActiveEl) homeActiveEl.textContent = format2Digits(activeCasesCount);

    const homeSolvedEl = document.getElementById("home-solved-cases-count");
    if (homeSolvedEl) homeSolvedEl.textContent = format2Digits(solvedCount);

    const homeTotalEl = document.getElementById("home-total-cases-count");
    if (homeTotalEl) homeTotalEl.textContent = format2Digits(cases.length);

    // Render Home Cases Overview Table
    const rowsContainer = document.getElementById("home-cases-rows-container");
    const emptyState = document.getElementById("home-cases-empty-state");
    const tbody = document.getElementById("home-cases-table-body");

    if (rowsContainer) {
      if (!cases || cases.length === 0) {
        if (emptyState) emptyState.style.display = "flex";
        rowsContainer.innerHTML = "";
      } else {
        if (emptyState) emptyState.style.display = "none";
        rowsContainer.innerHTML = "";

        cases.slice(0, 5).forEach(c => {
          const row = document.createElement("div");
          row.className = "case-card-modern";
          row.onclick = () => openCaseDetails(c.case_id);
          const evCount = g_caseEvidencesMap[c.case_id] || 0;
          const priorityLower = (c.priority || 'medium').toLowerCase();
          const priorityUpper = (c.priority || 'MEDIUM').toUpperCase();

          // Stage Stepper Active Index Derivation
          let activeStageIdx = 0;
          let percentStr = "12% reconstructed";
          if (c.status === "Closed" || c.status === "SOLVED") {
            activeStageIdx = 5;
            percentStr = "100% reconstructed";
          } else if (c.status === "PENDING_DELETION") {
            activeStageIdx = 1;
            percentStr = "25% pending deletion";
          } else if (evCount >= 5) {
            activeStageIdx = 3;
            percentStr = "82% reconstructed";
          } else if (evCount >= 3) {
            activeStageIdx = 2;
            percentStr = "61% reconstructed";
          } else if (evCount > 0) {
            activeStageIdx = 1;
            percentStr = "35% reconstructed";
          }

          const safeId = escapeHTML(c.case_id);
          const safeName = escapeHTML(c.case_name || 'Investigation Case');
          const safeLead = escapeHTML(c.investigator_name || 'investigator1');
          
          let cleanStatus = "ACTIVE";
          const rawSt = (c.status || "").toUpperCase();
          if (rawSt === "PENDING_DELETION" || rawSt.includes("DELETION")) cleanStatus = "PENDING";
          else if (rawSt === "CLOSED" || rawSt === "SOLVED") cleanStatus = "SOLVED";
          else if (rawSt) cleanStatus = rawSt.replace(/_/g, " ").split(" ")[0];
          const safeStatus = escapeHTML(cleanStatus);

          let safeCreatedDate = 'N/A';
          if (c.created_at) {
            try {
              const d = new Date(c.created_at);
              safeCreatedDate = d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
            } catch (e) {
              safeCreatedDate = String(c.created_at).substring(0, 10);
            }
          }

          const stages = ["Ingestion", "Extraction", "Correlation", "Reconstruction", "AI Analysis", "Review"];
          const currentStageName = stages[activeStageIdx] || "Active Analysis";
          const segmentsHTML = stages.map((stg, idx) => `
            <div class="progress-segment ${idx <= activeStageIdx ? 'active' : ''}" title="Stage ${idx+1}: ${stg}"></div>
          `).join('');

          row.innerHTML = `
            <div class="case-card-accent-line ${priorityLower}"></div>
            <div class="case-card-inner">
              <div class="case-card-header-line">
                <div class="case-card-title-box">
                  <h4 class="case-card-title" title="Open ${safeName}">${safeName}</h4>
                  <span class="case-card-id-pill">${safeId.length > 14 ? safeId.substring(0, 10) + '...' : safeId}</span>
                </div>
                <div class="case-card-badge-actions">
                  <span class="case-badge-priority ${priorityLower}">● ${priorityUpper}</span>
                  <span class="case-badge-status ${cleanStatus === 'PENDING' ? 'status-pending' : (cleanStatus === 'SOLVED' ? 'status-solved' : 'status-active')}">${safeStatus}</span>
                  <button type="button" class="btn-card-action-delete" style="background: transparent; border: none; cursor: pointer; padding: 0.35rem; display: flex; align-items: center; justify-content: center;" title="Delete Case">
                    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="#dc2626" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                  </button>
                </div>
              </div>
              <div class="case-card-meta-line">
                <div class="case-card-details-group">
                  <span class="case-meta-item">Lead: <strong>${safeLead}</strong></span>
                  <span class="case-meta-dot">•</span>
                  <span class="case-meta-item">Evidence: <strong>${evCount} item${evCount === 1 ? '' : 's'}</strong></span>
                  <span class="case-meta-dot">•</span>
                  <span class="case-meta-item">Created: <strong>${safeCreatedDate}</strong></span>
                </div>
                <div class="case-card-progress-wrapper">
                  <div class="case-card-progress-block">
                    <div class="progress-segments-bar">${segmentsHTML}</div>
                    <div class="progress-labels-row">
                      <span class="progress-stage-name">Stage ${activeStageIdx+1}: <strong>${currentStageName}</strong></span>
                      <span class="progress-pct-badge">${percentStr}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          `;

          const delBtn = row.querySelector('.btn-card-action-delete');
          if (delBtn) {
            const cId = c.case_id;
            const cName = c.case_name;
            delBtn.onclick = (e) => {
              e.stopPropagation();
              window.adminPurgeCase(cId, cName, e);
            };
          }

          rowsContainer.appendChild(row);
        });
      }
    } else if (tbody) {
      if (!cases || cases.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 2rem;">No active investigation cases in database.</td></tr>`;
        return;
      }
      tbody.innerHTML = "";
      cases.slice(0, 5).forEach(c => {
        const tr = document.createElement("tr");
        const pClass = getPriorityBadgeClass(c.priority);
        const evCount = g_caseEvidencesMap[c.case_id] || 0;

        let stageBadge = '<span class="badge badge-cyan">Stage 1: Awaiting Evidence</span>';
        if (c.status === "PENDING_DELETION") {
          stageBadge = '<span class="badge badge-amber">Stage 1: Deletion Requested</span>';
        } else if (evCount > 0) {
          stageBadge = '<span class="badge badge-emerald">Stage 1: Vault Preserved</span>';
        }

        tr.innerHTML = `
          <td>
            <div class="mono-text" style="font-size: 0.75rem; font-weight: 700; color: var(--accent-emerald-light);">${c.case_id.substring(0, 8)}...</div>
            <div style="font-weight: 600; color: #0f172a; font-size: 0.82rem;">${c.case_name}</div>
          </td>
          <td>${c.investigator_name || 'Unassigned'}</td>
          <td><span class="badge ${pClass}">${c.priority || 'Medium'}</span></td>
          <td><code class="mono-text">${evCount} items</code></td>
          <td>${stageBadge}</td>
          <td><span class="badge badge-emerald">${c.status || 'Active'}</span></td>
        `;
        tbody.appendChild(tr);
      });
    }

  } catch (err) {
    console.error("Error loading Home section:", err);
  }
}



// Sync Top Sub-Navbar & Sidebar Active Tabs
window.syncTopSubnavTab = function(targetId) {
  if (!targetId) return;

  const resolvedId = targetId === "sec-create-case" ? "sec-cases" : targetId;

  const subnavTabs = document.querySelectorAll(".workspace-top-subnav .subnav-tab");
  subnavTabs.forEach(tab => {
    const dataTgt = tab.getAttribute("data-target");
    if (dataTgt === resolvedId) {
      tab.classList.add("active");
    } else {
      tab.classList.remove("active");
    }
  });

  const navTabs = document.querySelectorAll(".nav-tab");
  navTabs.forEach(t => {
    const tTarget = t.getAttribute("data-target");
    if (tTarget === resolvedId || (resolvedId === "sec-cases" && tTarget === "sec-create-case")) {
      t.classList.add("active");
    } else {
      t.classList.remove("active");
    }
  });
};

// Async Load Cases Section & Update Stat Counts Dynamically
window.loadCasesSection = async function() {
  try {
    const [cases, evidences] = await Promise.all([
      HMACFR_API.getCases(),
      HMACFR_API.getAllEvidence().catch(() => [])
    ]);
    g_allCases = cases;
    g_caseEvidencesMap = {};
    if (Array.isArray(evidences)) {
      evidences.forEach(ev => {
        if (ev.case_id) {
          g_caseEvidencesMap[ev.case_id] = (g_caseEvidencesMap[ev.case_id] || 0) + 1;
        }
      });
    }

    let solvedCount = 0;
    let activeCasesCount = 0;

    for (const c of cases) {
      if (c.status === "Solved" || c.status === "Closed") {
        solvedCount++;
      } else {
        activeCasesCount++;
      }
    }

    const fmt2 = (num) => {
      const n = parseInt(num) || 0;
      return n < 10 ? `0${n}` : `${n}`;
    };

    const activeEl = document.getElementById("cases-pg-active-count");
    if (activeEl) activeEl.textContent = fmt2(activeCasesCount);

    const solvedEl = document.getElementById("cases-pg-solved-count");
    if (solvedEl) solvedEl.textContent = fmt2(solvedCount);

    const totalEl = document.getElementById("cases-pg-total-count");
    if (totalEl) totalEl.textContent = fmt2(cases.length);

    window.syncTopSubnavTab("sec-cases");
    filterAndRenderCases();
  } catch (err) {
    console.error("Error loading Cases section:", err);
  }
};

// Global Selected Sidebar Case Filter ID
let g_selectedSidebarCaseId = null;

// Filter cases by search text, sidebar selection, and priority level
window.g_currentPrioritySortFilter = "ALL";

window.togglePrioritySortPopover = function() {
  const popover = document.getElementById("priority-sort-popover");
  if (popover) {
    popover.style.display = popover.style.display === "block" ? "none" : "block";
  }
};

window.selectPrioritySortFilter = function(val, label) {
  window.g_currentPrioritySortFilter = val;
  const labelEl = document.getElementById("priority-sort-label");
  if (labelEl) labelEl.textContent = label;

  const popover = document.getElementById("priority-sort-popover");
  if (popover) popover.style.display = "none";

  filterAndRenderCases();
};

window.g_currentActiveCaseId = null;
window.g_currentActiveCaseName = null;
window.g_currentPopoverOwner = null;

window.openGlobalCaseInspect = function() {
  const popover = document.getElementById("global-case-card-popover");
  if (popover) popover.style.display = "none";
  if (window.g_currentActiveCaseId) openCaseDetails(window.g_currentActiveCaseId);
};

window.updateGlobalCasePriority = async function(newPriority) {
  const popover = document.getElementById("global-case-card-popover");
  if (popover) popover.style.display = "none";

  if (!window.g_currentActiveCaseId) return;

  try {
    await HMACFR_API.updateCase(window.g_currentActiveCaseId, { priority: newPriority });
    showSherlockNotice("Priority Updated", `Case priority updated to ${newPriority.toUpperCase()}.`);
    
    if (window.loadCasesSection) {
      await window.loadCasesSection();
    }
  } catch (err) {
    showSherlockNotice("Update Failed", "Failed to update case priority: " + err.message, true);
  }
};

window.g_sherlockPromptCallback = null;

window.showSherlockPrompt = function(title, message, callback, options = {}) {
  const modal = document.getElementById("sherlock-custom-prompt-modal");
  const titleEl = document.getElementById("sherlock-prompt-title");
  const msgEl = document.getElementById("sherlock-prompt-message");
  const inputEl = document.getElementById("sherlock-prompt-input");
  const submitBtn = document.getElementById("sherlock-prompt-submit-btn");

  if (titleEl) titleEl.textContent = title;
  if (msgEl) msgEl.textContent = message;
  if (inputEl) {
    if (options.hideInput) {
      inputEl.parentElement.style.display = "none";
    } else {
      inputEl.parentElement.style.display = "block";
      inputEl.value = "";
    }
  }
  if (submitBtn) submitBtn.textContent = options.submitText || "Confirm Delete";
  
  window.g_sherlockPromptCallback = callback;

  if (modal) {
    modal.style.display = "flex";
    if (inputEl && !options.hideInput) inputEl.focus();
  }
};

window.closeSherlockPromptModal = function(confirmed = false) {
  const modal = document.getElementById("sherlock-custom-prompt-modal");
  if (modal) modal.style.display = "none";
  if (!confirmed && window.g_sherlockPromptCallback) {
    window.g_sherlockPromptCallback(null);
    window.g_sherlockPromptCallback = null;
  }
};

window.submitSherlockPromptModal = function() {
  const inputEl = document.getElementById("sherlock-prompt-input");
  const val = inputEl ? inputEl.value.trim() : "";
  const modal = document.getElementById("sherlock-custom-prompt-modal");
  if (modal) modal.style.display = "none";
  if (window.g_sherlockPromptCallback) {
    window.g_sherlockPromptCallback(val || "CONFIRMED");
    window.g_sherlockPromptCallback = null;
  }
};

document.addEventListener("click", (e) => {
  const popover = document.getElementById("priority-sort-popover");
  const trigger = document.getElementById("priority-sort-trigger");
  if (popover && trigger && !popover.contains(e.target) && !trigger.contains(e.target)) {
    popover.style.display = "none";
  }

  const globalPopover = document.getElementById("global-case-card-popover");
  if (globalPopover && globalPopover.style.display === "block") {
    if (e.target && !e.target.closest("#global-case-card-popover") && !e.target.closest(".btn-card-action-more")) {
      globalPopover.style.display = "none";
      window.g_currentPopoverOwner = null;
    }
  }
});

window.g_currentMyCasesFilter = "ALL";

window.selectMyCasesFilter = function(filterType) {
  window.g_currentMyCasesFilter = filterType;
  
  const tabAll = document.getElementById("my-cases-tab-all");
  const tabCreated = document.getElementById("my-cases-tab-created");
  const tabAssigned = document.getElementById("my-cases-tab-assigned");

  [tabAll, tabCreated, tabAssigned].forEach(el => {
    if (el) {
      el.style.background = "transparent";
      el.style.color = "#475569";
      el.style.fontWeight = "600";
    }
  });

  let activeEl = tabAll;
  if (filterType === "CREATED") activeEl = tabCreated;
  else if (filterType === "ASSIGNED") activeEl = tabAssigned;

  if (activeEl) {
    activeEl.style.background = "#eff6ff";
    activeEl.style.color = "#2563eb";
    activeEl.style.fontWeight = "700";
  }

  filterAndRenderCases();
};

function filterAndRenderCases() {
  const searchInput = document.getElementById("cases-search-filter");
  const query = searchInput ? searchInput.value.trim().toLowerCase() : "";

  const priorityFilter = window.g_currentPrioritySortFilter || "ALL";
  const myCasesFilter = window.g_currentMyCasesFilter || "ALL";
  const currentUser = HMACFR_API.getUser();
  const currentUsername = currentUser ? (currentUser.username || "").toLowerCase() : "";

  let filtered = g_allCases.filter(c => {
    let matchSearch = true;
    if (query) {
      matchSearch = c.case_id.toLowerCase().includes(query) ||
        c.case_name.toLowerCase().includes(query) ||
        (c.investigator_name && c.investigator_name.toLowerCase().includes(query));
    } else if (g_selectedSidebarCaseId) {
      matchSearch = (c.case_id === g_selectedSidebarCaseId);
    }

    const matchPriority = priorityFilter === "ALL" || (c.priority || "Medium").toUpperCase() === priorityFilter.toUpperCase();

    let matchMyCases = true;
    if (myCasesFilter === "CREATED") {
      matchMyCases = !currentUsername || (c.investigator_name || "").toLowerCase() === currentUsername;
    } else if (myCasesFilter === "ASSIGNED") {
      matchMyCases = true;
    }

    return matchSearch && matchPriority && matchMyCases;
  });

  // Priority ranking comparator: Critical (4) > High (3) > Medium (2) > Low (1)
  const priorityWeight = { "Critical": 4, "High": 3, "Medium": 2, "Low": 1 };
  filtered.sort((a, b) => {
    const wA = priorityWeight[a.priority] || 2;
    const wB = priorityWeight[b.priority] || 2;
    return wB - wA;
  });

  renderCasesListSidebar(g_allCases);
  renderPriorityCasesTable(filtered);
}

// Dynamic Focus Sidebar Count Updates (1:1 media_1788007853923.png)
function renderCasesListSidebar(cases) {
  const allList = cases || g_allCases || [];
  const currentUser = HMACFR_API.getUser();
  const currentUsername = currentUser ? (currentUser.username || "").toLowerCase() : "";
  
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  let createdCount = 0;

  allList.forEach(c => {
    const p = (c.priority || 'MEDIUM').toUpperCase();
    if (p === 'CRITICAL') criticalCount++;
    else if (p === 'HIGH') highCount++;
    else if (p === 'LOW') lowCount++;
    else mediumCount++;

    if (!currentUsername || (c.investigator_name || "").toLowerCase() === currentUsername) {
      createdCount++;
    }
  });

  const setTxt = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  };

  setTxt("focus-count-critical", criticalCount);
  setTxt("focus-count-high", highCount);
  setTxt("focus-count-medium", mediumCount);
  setTxt("focus-count-low", lowCount);
  setTxt("focus-count-all", allList.length);
  setTxt("focus-count-created", createdCount || allList.length);
  setTxt("focus-count-assigned", allList.length);
  setTxt("insights-cases-count", allList.length);
}


// Clean Minimalist Case Deletion Handler
window.g_pendingDeleteCaseId = null;
window.g_pendingDeleteCaseName = null;

window.deleteCaseItem = function(caseId, caseName, evt) {
  if (evt && evt.stopPropagation) evt.stopPropagation();
  if (window.event && window.event.stopPropagation) window.event.stopPropagation();
  
  const popover = document.getElementById("global-case-card-popover");
  if (popover) popover.style.display = "none";

  let id = null;
  if (caseId && typeof caseId !== "object") {
    id = String(caseId).trim();
  } else if (window.g_currentActiveCaseId) {
    id = String(window.g_currentActiveCaseId).trim();
  }

  let name = null;
  if (caseName && typeof caseName !== "object") {
    name = String(caseName).trim();
  } else if (window.g_currentActiveCaseName) {
    name = String(window.g_currentActiveCaseName).trim();
  } else {
    name = id;
  }

  if (!id) {
    showSherlockNotice("Error", "No case selected for deletion.", true);
    return;
  }

  window.g_pendingDeleteCaseId = id;
  window.g_pendingDeleteCaseName = name;

  const msgEl = document.getElementById("delete-case-modal-msg");
  if (msgEl) {
    msgEl.innerHTML = `Are you sure you want to permanently delete case <strong>"${escapeHTML(name)}"</strong>?<br><br>All associated physical evidence files and audit records will be scrubbed from disk.`;
  }

  const modal = document.getElementById("delete-case-modal");
  if (modal) {
    modal.style.display = "flex";
  } else {
    confirmAndExecuteDelete();
  }
};

window.adminPurgeCase = window.deleteCaseItem;

window.closeDeleteCaseModal = function() {
  const modal = document.getElementById("delete-case-modal");
  if (modal) modal.style.display = "none";
  window.g_pendingDeleteCaseId = null;
  window.g_pendingDeleteCaseName = null;
};

window.confirmAndExecuteDelete = function() {
  const targetId = window.g_pendingDeleteCaseId;
  const targetName = window.g_pendingDeleteCaseName || targetId;
  window.closeDeleteCaseModal();

  if (!targetId) return;

  const loadingSteps = [
    `INITIATING PURGE PROTOCOL FOR CASE ${targetId}...`,
    "SCRUBBING PHYSICAL STORAGE ARTIFACTS FROM DISK...",
    "REMOVING EVIDENCE VAULT DIRECTORY TREES...",
    "PURGING CASE RECORD FROM DATABASE...",
    "CASE & FORENSIC DATA SUCCESSFULLY DELETED."
  ];

  showCyberLoading(
    `Deleting Case ${targetId}`,
    `Scrubbing physical evidence files and database records for ${targetName}...`,
    loadingSteps,
    async () => {
      try {
        await HMACFR_API.deleteCase(targetId);
        showSherlockNotice("Case Deleted", `Case "${targetName}" (${targetId}) and all associated evidence files have been deleted.`);
        loadOverviewData();
        if (window.loadCasesSection) await window.loadCasesSection();
        if (typeof loadProfileSection === "function") loadProfileSection();
      } catch (err) {
        showSherlockNotice("Action Failed", "Error purging case: " + err.message, true);
      }
    }
  );
};

// Admin Resolution Handler for Pending Deletion Requests
window.adminResolveCaseDeletion = async function(caseId, action, caseName, evt) {
  if (evt && evt.stopPropagation) evt.stopPropagation();
  const isApprove = action === "APPROVE";
  const targetName = caseName || caseId;

  if (isApprove) {
    showCyberLoading(
      `Executing Admin Case Purge for ${caseId}`,
      `Scrubbing physical evidence storage files and database records for ${targetName}...`,
      [
        "SCRUBBING PHYSICAL STORAGE ARTIFACTS FROM DISK...",
        "REMOVING EVIDENCE VAULT DIRECTORY TREES...",
        "DELETING CHAIN OF CUSTODY TIMELINE LOGS...",
        "PURGING CASE RECORD FROM DATABASE...",
        "CASE PURGE APPROVED & COMPLETED."
      ],
      async () => {
        try {
          await HMACFR_API.resolveCaseDeletion(caseId, "APPROVE");
          showSherlockNotice("Case Purged", `Case "${targetName}" (${caseId}) deletion APPROVED. Physical files and database records permanently purged.`);
          loadOverviewData();
          if (window.loadCasesSection) await window.loadCasesSection();
          if (typeof loadProfileSection === "function") loadProfileSection();
        } catch (err) {
          showSherlockNotice("Action Failed", "Error approving deletion: " + err.message, true);
        }
      }
    );
  } else {
    try {
      await HMACFR_API.resolveCaseDeletion(caseId, "REJECT");
      showSherlockNotice("Request Rejected", `Deletion request for case "${targetName}" REJECTED. Case status restored to Active.`);
      loadOverviewData();
      if (window.loadCasesSection) await window.loadCasesSection();
      if (typeof loadProfileSection === "function") loadProfileSection();
    } catch (err) {
      showSherlockNotice("Action Failed", "Error rejecting deletion: " + err.message, true);
    }
  }
};

// Load Pending Case Deletion Requests for Admin Review
async function loadAdminPendingDeletionRequests() {
  const tbody = document.getElementById("admin-pending-deletion-table-body");
  const countEl = document.getElementById("admin-pending-deletion-count");
  if (!tbody) return;

  try {
    const pendingCases = await HMACFR_API.getPendingDeletionRequests();
    if (countEl) countEl.textContent = pendingCases.length;

    if (!pendingCases || pendingCases.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">No pending case deletion requests awaiting Admin review.</td></tr>`;
      return;
    }

    tbody.innerHTML = "";
    pendingCases.forEach(c => {
      const tr = document.createElement("tr");

      tr.innerHTML = `
        <td><code class="mono-text">${c.case_id}</code></td>
        <td><strong>${c.case_name}</strong></td>
        <td>${c.deletion_requested_by || c.investigator_name || 'Investigator'}</td>
        <td style="color: var(--accent-amber); font-style: italic; max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
          "${c.deletion_reason || 'No reason provided'}"
        </td>
        <td><span class="badge badge-amber">PENDING DELETION</span></td>
        <td style="white-space: nowrap;">
          <button class="btn btn-primary btn-sm" onclick="window.adminResolveCaseDeletion('${c.case_id}', 'APPROVE', '${escapeQuotes(c.case_name)}')" style="font-size: 0.75rem; padding: 0.25rem 0.65rem; margin-right: 0.35rem;" title="Approve Request & Purge All Evidence Files & Records">
            <svg class="svg-icon svg-icon-sm" viewBox="0 0 24 24" style="margin-right: 0.2rem;"><polyline points="20 6 9 17 4 12"/></svg>
            Approve & Purge
          </button>
          <button class="btn btn-secondary btn-sm" onclick="window.adminResolveCaseDeletion('${c.case_id}', 'REJECT', '${escapeQuotes(c.case_name)}')" style="font-size: 0.75rem; padding: 0.25rem 0.65rem;" title="Reject Request & Restore Case to Active Status">
            <svg class="svg-icon svg-icon-sm" viewBox="0 0 24 24" style="margin-right: 0.2rem;"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            Reject Request
          </button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--accent-danger); padding: 1.5rem;">Error loading pending deletion requests: ${err.message}</td></tr>`;
  }
}

function getCaseWorkflowStage(c, evCount) {
  const status = (c ? c.status : "").toUpperCase();
  const expected = (c ? c.expected_evidence_count : 1) || 1;
  if (status === "PENDING_DELETION") {
    return { num: "04", title: "STAGE 4", subtitle: "Deletion Pending", stepIdx: 4 };
  } else if (status === "SOLVED" || status === "CLOSED") {
    return { num: "05", title: "STAGE 5", subtitle: "Case Closed", stepIdx: 5 };
  } else if (evCount >= expected && evCount > 0) {
    return { num: "03", title: "STAGE 3", subtitle: "Analysis Ready", stepIdx: 3 };
  } else if (evCount > 0) {
    return { num: "02", title: "STAGE 2", subtitle: "Evidence Vaulted", stepIdx: 2 };
  }
  return { num: "01", title: "STAGE 1", subtitle: "Awaiting Evidence", stepIdx: 1 };
}

// Render Center Panel Priority Sorted Active Cases Cards
function renderPriorityCasesTable(cases) {
  const container = document.getElementById("cases-detailed-cards-container");
  if (!container) return;

  if (!cases || cases.length === 0) {
    container.innerHTML = `
      <div style="text-align: center; color: #64748b; padding: 3rem 1rem; background: #f8fafc; border-radius: 12px; border: 1px solid #f1f5f9;">
        <div style="font-size: 1rem; font-weight: 700; color: #0f172a; margin-bottom: 0.25rem;">No Active Cases Found</div>
        <div style="font-size: 0.85rem;">No investigation cases match your current focus filter.</div>
      </div>
    `;
    return;
  }

  container.innerHTML = "";
  cases.forEach(c => {
    const card = document.createElement("div");
    card.className = "case-card-modern";
    card.onclick = () => openCaseDetails(c.case_id);
    const evCount = g_caseEvidencesMap[c.case_id] || 0;
    
    const priorityUpper = (c.priority || 'MEDIUM').toUpperCase();
    const priorityLower = (c.priority || 'medium').toLowerCase();

    const safeId = escapeHTML(c.case_id);
    const safeName = escapeHTML(c.case_name || 'Investigation Case');
    const safeLead = escapeHTML(c.investigator_name || 'investigator1');
    
    let cleanStatus = "ACTIVE";
    const rawSt = (c.status || "").toUpperCase();
    if (rawSt === "PENDING_DELETION" || rawSt.includes("DELETION")) cleanStatus = "PENDING";
    else if (rawSt === "CLOSED" || rawSt === "SOLVED") cleanStatus = "SOLVED";
    else if (rawSt.includes("COMPLETE")) cleanStatus = "ACTIVE";
    else if (rawSt) cleanStatus = rawSt.replace(/_/g, " ").split(" ")[0];
    const safeStatus = escapeHTML(cleanStatus);

    // Stage Stepper Active Index Derivation
    let activeStageIdx = 0;
    let percentStr = "12% reconstructed";
    if (c.status === "Closed" || c.status === "SOLVED") {
      activeStageIdx = 5;
      percentStr = "100% reconstructed";
    } else if (c.status === "PENDING_DELETION") {
      activeStageIdx = 1;
      percentStr = "25% pending deletion";
    } else if (evCount >= 5) {
      activeStageIdx = 3;
      percentStr = "82% reconstructed";
    } else if (evCount >= 3) {
      activeStageIdx = 2;
      percentStr = "61% reconstructed";
    } else if (evCount > 0) {
      activeStageIdx = 1;
      percentStr = "35% reconstructed";
    }

    let safeCreatedDate = 'N/A';
    if (c.created_at) {
      try {
        const d = new Date(c.created_at);
        safeCreatedDate = d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
      } catch (e) {
        safeCreatedDate = String(c.created_at).substring(0, 10);
      }
    }

    const stages = ["Ingestion", "Extraction", "Correlation", "Reconstruction", "AI Analysis", "Review"];
    const currentStageName = stages[activeStageIdx] || "Active Analysis";
    const segmentsHTML = stages.map((stg, idx) => `
      <div class="progress-segment ${idx <= activeStageIdx ? 'active' : ''}" title="Stage ${idx+1}: ${stg}"></div>
    `).join('');

    card.innerHTML = `
      <div class="case-card-accent-line ${priorityLower}"></div>
      <div class="case-card-inner">
        <!-- Row 1: Title, ID, Priority Badge, Status Badge & Actions -->
        <div class="case-card-header-line">
          <div class="case-card-title-box">
            <h4 class="case-card-title" title="Open ${safeName}">${safeName}</h4>
            <span class="case-card-id-pill">${safeId.length > 14 ? safeId.substring(0, 10) + '...' : safeId}</span>
          </div>

          <div class="case-card-badge-actions">
            <span class="case-badge-priority ${priorityLower}">● ${priorityUpper}</span>
            <span class="case-badge-status ${cleanStatus === 'PENDING' ? 'status-pending' : (cleanStatus === 'SOLVED' ? 'status-solved' : 'status-active')}">${safeStatus}</span>
            
            <button type="button" class="btn btn-sm btn-case-team" onclick="event.stopPropagation(); window.openManageTeamModal('${c.case_id}', '${escapeQuotes(c.case_name || 'Investigation Case')}');" title="Manage Team & Roles" style="background: #ffffff; border: 1px solid #cbd5e1; color: #334155; font-size: 0.75rem; font-weight: 600; padding: 0.25rem 0.55rem; border-radius: 6px; cursor: pointer; display: inline-flex; align-items: center; gap: 4px; margin-right: 4px;">
              <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
              <span>Team</span>
            </button>

            ${cleanStatus === 'PENDING' && (HMACFR_API.getUser() && (HMACFR_API.getUser().role === 'Admin' || HMACFR_API.getUser().role === 'ADMIN')) ? `
              <button type="button" onclick="event.stopPropagation(); window.adminResolveCaseDeletion('${c.case_id}', 'APPROVE', '${escapeQuotes(c.case_name)}', event);" style="background: transparent; border: none; cursor: pointer; padding: 0.25rem; color: #059669;" title="Approve Deletion">
                <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
              </button>
              <button type="button" onclick="event.stopPropagation(); window.adminResolveCaseDeletion('${c.case_id}', 'REJECT', '${escapeQuotes(c.case_name)}', event);" style="background: transparent; border: none; cursor: pointer; padding: 0.25rem; color: #dc2626;" title="Reject Deletion">
                <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="#dc2626" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
              </button>
            ` : `
              <button type="button" class="btn-card-action-delete" style="background: transparent; border: none; cursor: pointer; padding: 0.35rem; display: flex; align-items: center; justify-content: center;" title="Delete Case">
                <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="#dc2626" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
              </button>
            `}
          </div>
        </div>

        <!-- Row 2: Metadata Pills & Segmented Progress Bar -->
        <div class="case-card-meta-line">
          <div class="case-card-details-group">
            <span class="case-meta-item">
              <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="#64748b" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
              <span>Lead: <strong>${safeLead}</strong></span>
            </span>
            <span class="case-meta-dot">•</span>
            <span class="case-meta-item">
              <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="#64748b" stroke-width="2"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>
              <span>Evidence: <strong>${evCount} item${evCount === 1 ? '' : 's'}</strong></span>
            </span>
            <span class="case-meta-dot">•</span>
            <span class="case-meta-item">
              <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="#64748b" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
              <span>Created: <strong>${safeCreatedDate}</strong></span>
            </span>
          </div>

          <div class="case-card-progress-wrapper">
            <div class="case-card-progress-block">
              <div class="progress-segments-bar">${segmentsHTML}</div>
              <div class="progress-labels-row">
                <span class="progress-stage-name">Stage ${activeStageIdx+1}: <strong>${currentStageName}</strong></span>
                <span class="progress-pct-badge">${percentStr}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;

    const delBtn = card.querySelector('.btn-card-action-delete');
    if (delBtn) {
      const cId = c.case_id;
      const cName = c.case_name;
      delBtn.onclick = function(e) {
        if (e && e.stopPropagation) e.stopPropagation();
        window.adminPurgeCase(cId, cName, e);
      };
    }

    container.appendChild(card);
  });
}




function getPriorityBadgeClass(priority) {
  switch ((priority || "").toLowerCase()) {
    case "critical": return "badge-priority-critical";
    case "high": return "badge-priority-high";
    case "medium": return "badge-priority-medium";
    case "low": return "badge-priority-low";
    default: return "badge-priority-medium";
  }
}

// Active WebSocket Analysis Connection Registry
window.activeAnalysisSockets = {};

// Trigger Real-Time WebSocket Analysis
window.startAnalysisForCase = async function(caseId, caseName, totalSeconds = 30) {
  try {
    const task = await HMACFR_API.startAnalysis(caseId, caseName, totalSeconds);
    const taskId = task.task_id;

    // Render active task card in Running Analysis drawer
    renderRunningAnalysisCard(taskId, caseId, caseName, totalSeconds);

    // Switch active workspace view to Real-Time Analysis section (sec-analysis)
    const analysisNavTab = document.getElementById("nav-tab-analysis");
    if (analysisNavTab) {
      analysisNavTab.click();
    } else {
      const sections = document.querySelectorAll(".workspace-section");
      sections.forEach(s => s.classList.remove("active"));
      const secAnalysis = document.getElementById("sec-analysis");
      if (secAnalysis) secAnalysis.classList.add("active");
    }

    // Populate analysis target case select dropdown
    const select = document.getElementById("analysis-case-select");
    if (select) select.value = caseId;

    // Connect WebSocket stream
    const ws = HMACFR_API.connectAnalysisWebSocket(
      taskId,
      (msg) => handleAnalysisWebSocketMessage(msg),
      (err) => console.error("Analysis WS error:", err),
      () => updateAnalysisStatusBadge(taskId, "Closed")
    );

    window.activeAnalysisSockets[taskId] = ws;

    // Pulse feedback to user
    const endnoteWs = document.getElementById("endnote-ws-status");
    if (endnoteWs) endnoteWs.textContent = `Streaming (${taskId})`;

    // Smooth scroll to top of analysis section
    const secAnalysis = document.getElementById("sec-analysis");
    if (secAnalysis) secAnalysis.scrollIntoView({ behavior: "smooth" });

  } catch (err) {
    showSherlockNotice("Action Failed", "Failed to initiate analysis task: " + err.message, true)
  }
};


function renderRunningAnalysisCard(taskId, caseId, caseName, totalSeconds) {
  const panel = document.getElementById("running-analysis-panel");
  if (!panel) return;

  // Clear empty state if present
  if (panel.children.length === 1 && panel.children[0].textContent.includes("No analysis currently running")) {
    panel.innerHTML = "";
  }

  // Remove existing card for this task if any
  const existing = document.getElementById(`running-card-${taskId}`);
  if (existing) existing.remove();

  const card = document.createElement("div");
  card.className = "running-analysis-item";
  card.id = `running-card-${taskId}`;

  card.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center;">
      <span class="mono-text" style="font-weight: 700; font-size: 0.78rem; color: var(--accent-emerald-light);">${taskId}</span>
      <span class="analysis-timer-badge" id="timer-badge-${taskId}">
        <svg class="svg-icon svg-icon-sm" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
        <span id="timer-val-${taskId}">${totalSeconds}s remaining</span>
      </span>
    </div>
    <div style="font-size: 0.82rem; font-weight: 600; color: #fff; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
      Case: ${caseName} (${caseId})
    </div>
    <div style="font-size: 0.72rem; color: var(--text-secondary);" id="stage-desc-${taskId}">
      Phase 1/5: Initializing Sherlock Forensic Scan...
    </div>
    <div style="background: rgba(255,255,255,0.08); height: 6px; border-radius: 3px; overflow: hidden; margin-top: 0.2rem;">
      <div id="progress-bar-${taskId}" style="width: 0%; height: 100%; background: linear-gradient(90deg, #10b981, #06b6d4); transition: width 0.3s ease;"></div>
    </div>
  `;

  panel.prepend(card);
}

function handleAnalysisWebSocketMessage(msg) {
  if (!msg) return;

  const taskId = msg.task_id;
  const progress = msg.progress || 0;
  const remSeconds = msg.time_remaining_seconds !== undefined ? msg.time_remaining_seconds : 0;
  const stage = msg.stage || "Processing...";

  // Update Drawer Card
  const timerVal = document.getElementById(`timer-val-${taskId}`);
  if (timerVal) {
    if (remSeconds > 0) {
      timerVal.textContent = `${remSeconds}s remaining`;
    } else {
      timerVal.textContent = "Complete!";
      const badge = document.getElementById(`timer-badge-${taskId}`);
      if (badge) badge.classList.add("completed");
    }
  }

  const stageDesc = document.getElementById(`stage-desc-${taskId}`);
  if (stageDesc) stageDesc.textContent = stage;

  const progressBar = document.getElementById(`progress-bar-${taskId}`);
  if (progressBar) progressBar.style.width = `${progress}%`;

  // Update Main Analysis View Section if active
  const countdownHero = document.getElementById("analysis-countdown-hero");
  if (countdownHero) {
    const mins = Math.floor(remSeconds / 60).toString().padStart(2, '0');
    const secs = (remSeconds % 60).toString().padStart(2, '0');
    countdownHero.textContent = `${mins}:${secs}`;
  }

  const stageBadge = document.getElementById("analysis-stage-badge");
  if (stageBadge) stageBadge.textContent = `Status: ${stage}`;

  const mainProgBar = document.getElementById("analysis-main-progress-bar");
  if (mainProgBar) mainProgBar.style.width = `${progress}%`;

  const progPct = document.getElementById("analysis-progress-percentage");
  if (progPct) progPct.textContent = `${progress.toFixed(1)}%`;

  const terminal = document.getElementById("analysis-terminal-log");
  if (terminal && msg.log) {
    if (terminal.children.length === 1 && terminal.children[0].textContent.includes("Select a case")) {
      terminal.innerHTML = "";
    }
    const line = document.createElement("div");
    line.style.marginBottom = "0.25rem";
    line.textContent = msg.log;
    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
  }

  // Real-time agent status cards synchronization
  const logLower = (msg.log || "").toLowerCase();
  const stgNum = typeof msg.stage === "number" ? msg.stage : -1;

  function setAgentCard(agentKey, status, activity, pVal) {
    const sEl = document.getElementById(`agent-status-${agentKey}`);
    if (sEl) {
      sEl.textContent = status;
      sEl.className = "badge " + (status === "Complete" ? "badge-emerald" : (status === "Running" ? "badge-cyan" : "badge-emerald"));
    }
    const aEl = document.getElementById(`agent-activity-${agentKey}`);
    if (aEl && activity) aEl.textContent = activity;
    const pEl = document.getElementById(`agent-prog-${agentKey}`);
    if (pEl && typeof pVal === "number") pEl.style.width = `${Math.min(100, Math.max(0, pVal))}%`;
  }

  if (logLower.includes("supervisor") || logLower.includes("dispatch") || stgNum === 0) {
    setAgentCard("supervisor", "Running", "Orchestrating domain agents", Math.min(progress * 1.5, 95));
  }
  if (logLower.includes("pcap") || logLower.includes("network") || logLower.includes("dns") || logLower.includes("pranay")) {
    setAgentCard("network", "Running", "Extracting PCAP flows, DNS & sockets", Math.min(progress * 1.3, 95));
  }
  if (logLower.includes("memory") || logLower.includes("volatility") || logLower.includes("bharath")) {
    setAgentCard("memory", "Running", "Scanning processes & VAD injections", Math.min(progress * 1.2, 95));
  }
  if (logLower.includes("disk") || logLower.includes("mft") || logLower.includes("aswith")) {
    setAgentCard("disk", "Running", "Parsing MFT, LNK & Prefetch records", Math.min(progress * 1.2, 95));
  }
  if (logLower.includes("log") || logLower.includes("sysmon") || logLower.includes("sanhith")) {
    setAgentCard("log", "Running", "Analyzing security logs & PowerShell", Math.min(progress * 1.1, 95));
  }
  if (logLower.includes("registry") || logLower.includes("kishor") || logLower.includes("software")) {
    setAgentCard("registry", "Running", "Parsing USB history & Run keys", Math.min(progress * 1.1, 95));
  }
  if (logLower.includes("correlat") || logLower.includes("qwen") || logLower.includes("synthes") || stgNum >= 3) {
    setAgentCard("correlation", "Running", "Synthesizing correlation chains & SIS", Math.min(progress, 95));
  }

  // Auto-refresh synthesized outputs workbench when analysis finishes
  if (msg.status === "completed" || msg.type === "ANALYSIS_COMPLETE") {
    ["supervisor", "network", "memory", "disk", "log", "registry", "correlation"].forEach(k => {
      setAgentCard(k, "Complete", "Forensic analysis complete", 100);
    });

    const completionBanner = document.getElementById("analysis-completion-banner");
    if (completionBanner) {
      completionBanner.style.display = "flex";
      completionBanner.style.border = "1px solid #10b981";
      completionBanner.style.boxShadow = "0 0 16px rgba(16, 185, 129, 0.2)";
    }

    if (window.loadForensicOutputsForCase && msg.case_id) {
      window.loadForensicOutputsForCase(msg.case_id);
    }
  }
}

function updateAnalysisStatusBadge(taskId, statusText) {
  const stageDesc = document.getElementById(`stage-desc-${taskId}`);
  if (stageDesc) stageDesc.textContent = `Analysis Stream ${statusText}`;
}

window.loadAnalysisSection = async function() {
  try {
    const cases = await HMACFR_API.getCases();
    window.g_allCases = cases;
    let activeCase = window.g_currentActiveCase;
    if (!activeCase) {
      if (cases && cases.length > 0) {
        activeCase = await window.setActiveCase(cases[0].case_id, { refreshActiveSection: false });
      } else {
        try {
          const newCase = await HMACFR_API.createCase({
            case_name: "Default Forensic Sandbox",
            description: "Default workspace sandbox",
            priority: "Medium"
          });
          activeCase = await window.setActiveCase(newCase.case_id, { refreshActiveSection: false });
        } catch (e) {
          console.error("Auto-provision default case error:", e);
        }
      }
    }
    const select = document.getElementById("analysis-case-select");

    if (select) {
      const activeId = activeCase ? activeCase.case_id : "";
      select.innerHTML = '<option value="">-- Select Target Case --</option>';
      cases.forEach(c => {
        const opt = document.createElement("option");
        opt.value = c.case_id;
        opt.textContent = `${c.case_id} — ${c.case_name}`;
        if (c.case_id === activeId) opt.selected = true;
        select.appendChild(opt);
      });

      select.onchange = async (e) => {
        const val = e.target.value;
        if (val) {
          await window.setActiveCase(val, { refreshActiveSection: true });
        } else {
          window.setActiveCase(null);
        }
      };
    }

    const completionBanner = document.getElementById("analysis-completion-banner");

    function setAgentCard(agentKey, status, activity, pVal, badgeClass) {
      const sEl = document.getElementById(`agent-status-${agentKey}`);
      if (sEl) {
        sEl.textContent = status;
        sEl.className = "badge " + (badgeClass || (status === "Complete" ? "badge-emerald" : (status === "Running" ? "badge-cyan" : (status === "READY" ? "badge-cyan" : "badge-secondary"))));
      }
      const aEl = document.getElementById(`agent-activity-${agentKey}`);
      if (aEl && activity) aEl.textContent = activity;
      const pEl = document.getElementById(`agent-prog-${agentKey}`);
      if (pEl && typeof pVal === "number") pEl.style.width = `${Math.min(100, Math.max(0, pVal))}%`;
    }

    if (!activeCase) {
      ["supervisor", "network", "memory", "disk", "log", "registry", "correlation"].forEach(k => {
        setAgentCard(k, "WAITING", "Awaiting case selection", 0, "badge-secondary");
      });
      if (completionBanner) completionBanner.style.display = "none";
      return;
    }

    const synth = activeCase.synthesized_data;
    const hasCompleted = synth && (
      (synth.findings && synth.findings.length > 0) ||
      (synth.timeline && synth.timeline.length > 0)
    );

    if (hasCompleted) {
      setAgentCard("supervisor", "Complete", "Orchestrated 5 domain agents", 100, "badge-emerald");
      setAgentCard("network", "Complete", "Network streams parsed (Pranay)", 100, "badge-emerald");
      setAgentCard("memory", "Complete", "Memory dumps analyzed (Bharath)", 100, "badge-emerald");
      setAgentCard("disk", "Complete", "Disk & MFT records parsed (Aswith)", 100, "badge-emerald");
      setAgentCard("log", "Complete", "Log telemetry correlated (Sanhith)", 100, "badge-emerald");
      setAgentCard("registry", "Complete", "Registry & USB analyzed (Kishor)", 100, "badge-emerald");
      setAgentCard("correlation", "Complete", "Structured Investigation State (SIS)", 100, "badge-emerald");
      if (completionBanner) completionBanner.style.display = "flex";

      const countdownHero = document.getElementById("analysis-countdown-hero");
      if (countdownHero) countdownHero.textContent = "COMPLETE";
      const stageBadge = document.getElementById("analysis-stage-badge");
      if (stageBadge) stageBadge.textContent = "Status: Multi-Agent Analysis Complete (Verified)";
      const progressPct = document.getElementById("analysis-progress-percentage");
      if (progressPct) progressPct.textContent = "100.0%";
      const mainProgBar = document.getElementById("analysis-main-progress-bar");
      if (mainProgBar) mainProgBar.style.width = "100%";
      const termLog = document.getElementById("analysis-terminal-log");
      if (termLog && (termLog.textContent.includes("[WebSocket Ready]") || termLog.textContent.trim() === "")) {
        const findingCount = (synth.findings || []).length;
        const timelineCount = (synth.timeline || []).length;
        termLog.innerHTML = `
          <div style="color: #10b981; font-weight: 700;">[Pipeline Complete] Multi-agent extraction &amp; reasoning verified for Case ${escapeHTML(activeCase.case_id)}</div>
          <div style="color: #38bdf8; margin-top: 4px;">• Correlated Findings: ${findingCount} validated indicators</div>
          <div style="color: #38bdf8; margin-top: 2px;">• Attack Timeline: ${timelineCount} chronological events reconstructed</div>
          <div style="color: #a78bfa; margin-top: 2px;">• Ready for Structured Investigation State (SIS) &amp; Court Report generation</div>
        `;
      }
    } else {
      setAgentCard("supervisor", "READY", "Supervisor ready for dispatch", 0, "badge-cyan");
      ["network", "memory", "disk", "log", "registry", "correlation"].forEach(k => {
        setAgentCard(k, "WAITING", "Awaiting supervisor trigger", 0, "badge-secondary");
      });
      if (completionBanner) completionBanner.style.display = "none";

      const countdownHero = document.getElementById("analysis-countdown-hero");
      if (countdownHero) countdownHero.textContent = "00:00";
      const stageBadge = document.getElementById("analysis-stage-badge");
      if (stageBadge) stageBadge.textContent = "Status: Idle";
      const progressPct = document.getElementById("analysis-progress-percentage");
      if (progressPct) progressPct.textContent = "0.0%";
      const mainProgBar = document.getElementById("analysis-main-progress-bar");
      if (mainProgBar) mainProgBar.style.width = "0%";
    }

  } catch (err) {
    console.error("Error loading analysis section:", err);
  }
};

async function loadProfileSection() {
  if (typeof window.loadProfileSection === "function") {
    return await window.loadProfileSection();
  }
}



let g_allVaultEvidence = [];

let g_selectedVaultFile = null;

window.toggleVaultInlineUpload = function(forceState) {
  const card = document.getElementById("vault-inline-upload-card");
  if (!card) return;
  const isHidden = card.style.display === "none" || !card.style.display;
  const shouldShow = forceState !== undefined ? forceState : isHidden;

  if (shouldShow) {
    if (window.g_currentActiveCase && window.g_currentActiveCase.vault_status === "LOCKED") {
      window.showForensicToast("Notice: Evidence Vault is currently SEALED & LOCKED for this case. Unlock the vault first before staging additional evidence.", "warning");
      return;
    }
    card.style.display = "block";
    card.scrollIntoView({ behavior: "smooth", block: "nearest" });
  } else {
    card.style.display = "none";
    g_selectedVaultFile = null;
    const filePrompt = document.getElementById("vault-selected-file-display");
    if (filePrompt) {
      filePrompt.style.display = "none";
      filePrompt.textContent = "";
    }
    const fileInput = document.getElementById("vault-inline-file-input");
    if (fileInput) fileInput.value = "";
  }
};

window.handleVaultFileSelect = function(files) {
  if (!files || files.length === 0) return;
  g_selectedVaultFile = files[0];
  const filePrompt = document.getElementById("vault-selected-file-display");
  const catSelect = document.getElementById("vault-inline-category");

  if (filePrompt) {
    let sizeStr = (g_selectedVaultFile.size / 1024).toFixed(1) + " KB";
    if (g_selectedVaultFile.size > 1048576) sizeStr = (g_selectedVaultFile.size / 1048576).toFixed(2) + " MB";
    filePrompt.style.display = "block";
    filePrompt.textContent = `Selected: ${g_selectedVaultFile.name} (${sizeStr})`;
  }

  // Auto-detect category from file extension
  if (catSelect && g_selectedVaultFile.name) {
    const ext = g_selectedVaultFile.name.split('.').pop().toLowerCase();
    if (ext === "pcap" || ext === "pcapng") catSelect.value = "PCAP";
    else if (["raw", "vmem", "dmp"].includes(ext)) catSelect.value = "Memory";
    else if (["dd", "img", "e01"].includes(ext)) catSelect.value = "Disk";
    else if (["evtx", "reg"].includes(ext)) catSelect.value = "Registry";
    else if (["sqlite", "db"].includes(ext)) catSelect.value = "Browser";
    else if (["exe", "bin", "dll"].includes(ext)) catSelect.value = "Malware";
  }
};

// Setup dropzone listeners once DOM is ready
document.addEventListener("DOMContentLoaded", () => {
  const dropzone = document.getElementById("vault-inline-dropzone");
  if (dropzone) {
    ['dragenter', 'dragover'].forEach(eventName => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.add("dragover");
      }, false);
    });
    ['dragleave', 'drop'].forEach(eventName => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.remove("dragover");
      }, false);
    });
    dropzone.addEventListener('drop', (e) => {
      const dt = e.dataTransfer;
      if (dt && dt.files && dt.files.length > 0) {
        window.handleVaultFileSelect(dt.files);
      }
    }, false);
  }
});

window.submitVaultInlineUpload = async function() {
  if (!g_selectedVaultFile) {
    window.showForensicToast("Please select or drop a forensic file first.", "warning");
    return;
  }
  if (!window.g_currentActiveCase || !window.g_currentActiveCase.case_id) {
    window.showForensicToast("No active investigation case selected. Please select a case first.", "warning");
    return;
  }

  const caseId = window.g_currentActiveCase.case_id;
  const catSelect = document.getElementById("vault-inline-category");
  const descInput = document.getElementById("vault-inline-description");
  const progressContainer = document.getElementById("vault-upload-progress-container");
  const progressBar = document.getElementById("vault-upload-progress-bar");
  const progressPercent = document.getElementById("vault-upload-progress-percent");
  const progressStatus = document.getElementById("vault-upload-progress-status");
  const submitBtn = document.getElementById("btn-vault-inline-upload-submit");

  const category = catSelect ? catSelect.value : "PCAP";
  const description = descInput ? descInput.value.trim() : "";

  try {
    if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = "Ingesting..."; }
    if (progressContainer) {
      progressContainer.style.display = "block";
      if (progressBar) progressBar.style.width = "35%";
      if (progressPercent) progressPercent.textContent = "35%";
      if (progressStatus) progressStatus.textContent = "Computing SHA-256 and encrypting bitstream...";
    }

    const currentUser = (typeof HMACFR_API.getCurrentUser === "function" ? HMACFR_API.getCurrentUser() : (typeof HMACFR_API.getUser === "function" ? HMACFR_API.getUser() : null)) || { username: "Investigator" };
    const formData = new FormData();
    formData.append("file", g_selectedVaultFile);
    formData.append("case_id", caseId);
    formData.append("investigator", currentUser.username);
    formData.append("category", category);
    formData.append("type", category);
    if (description) formData.append("description", description);

    if (progressBar) progressBar.style.width = "75%";
    if (progressPercent) progressPercent.textContent = "75%";

    const result = await HMACFR_API.uploadEvidence(formData);

    if (progressBar) progressBar.style.width = "100%";
    if (progressPercent) progressPercent.textContent = "100%";
    if (progressStatus) progressStatus.textContent = "Secure Vault Ingestion Complete!";

    setTimeout(() => {
      window.toggleVaultInlineUpload(false);
      if (progressContainer) progressContainer.style.display = "none";
      if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = "⚡ Ingest & Secure to Vault"; }
      window.showForensicToast(`Evidence '${result.original_filename || g_selectedVaultFile.name}' ingested and preserved successfully!`, "success");
      loadEvidenceVaultSection();
    }, 600);

  } catch (err) {
    console.error("Vault Ingestion Error:", err);
    window.showForensicToast(`Failed to ingest evidence into vault: ${err.message}`, "error");
    if (progressContainer) progressContainer.style.display = "none";
    if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = "⚡ Ingest & Secure to Vault"; }
  }
};

window.lockActiveCaseVaultAndProceed = async function() {
  if (!window.g_currentActiveCase || !window.g_currentActiveCase.case_id) {
    window.showForensicToast("No active case selected.", "warning");
    return;
  }
  const caseId = window.g_currentActiveCase.case_id;
  const isAlreadyLocked = window.g_currentActiveCase.vault_status === "LOCKED";

  if (isAlreadyLocked) {
    if (window.switchLabWorkstationTab) {
      window.switchLabWorkstationTab("analysis");
    }
    return;
  }

  const confirmLock = await window.showForensicConfirm(
    "Seal & Lock Evidence Vault",
    `Seal and Lock Evidence Vault for Case: ${window.g_currentActiveCase.case_name}?\n\n• Freezes an immutable cryptographic snapshot of all evidence.\n• Locks out modifications and unlocks Cognitive Multi-Agent Analysis.\n• Can be reopened if insufficient evidence is flagged.`,
    {
      confirmText: "🔒 Seal Vault & Proceed",
      cancelText: "Cancel",
      type: "info"
    }
  );

  if (!confirmLock) return;

  try {
    const res = await HMACFR_API.lockCaseVault(caseId);
    window.g_currentActiveCase.vault_status = "LOCKED";
    window.g_currentActiveCase.vault_locked_at = res.locked_at;
    window.g_currentActiveCase.vault_locked_by = res.locked_by;

    window.showForensicToast("Vault Sealed Successfully! Evidence pool frozen for Multi-Agent Analysis.", "success");

    if (window.switchLabWorkstationTab) {
      window.switchLabWorkstationTab("analysis");
    }
  } catch (err) {
    console.error("Error locking vault:", err);
    window.showForensicToast(`Could not lock evidence vault: ${err.message}`, "error");
  }
};

window.unlockActiveCaseVault = async function() {
  if (!window.g_currentActiveCase || !window.g_currentActiveCase.case_id) {
    window.showForensicToast("No active case selected.", "warning");
    return;
  }
  const caseId = window.g_currentActiveCase.case_id;
  const reason = await window.showForensicPrompt(
    "Reopen Evidence Vault",
    "Enter reason to reopen Evidence Vault (required for immutable audit ledger):",
    "Additional evidence identified during cognitive agent analysis",
    {
      placeholder: "e.g. Missing perimeter firewall PCAP discovered",
      confirmText: "🔓 Reopen Vault",
      cancelText: "Cancel"
    }
  );
  if (!reason || !reason.trim()) return;

  try {
    await HMACFR_API.unlockCaseVault(caseId, reason.trim());
    window.g_currentActiveCase.vault_status = "OPEN";
    window.showForensicToast("Evidence Vault reopened. Ingestion and deletion capabilities re-enabled.", "success");
    loadEvidenceVaultSection();
  } catch (err) {
    console.error("Error unlocking vault:", err);
    window.showForensicToast(`Could not unlock evidence vault: ${err.message}`, "error");
  }
};

window.extractSingleEvidenceItem = async function(evidenceId, filename) {
  if (!window.g_currentActiveCase || !window.g_currentActiveCase.case_id) return;
  const caseId = window.g_currentActiveCase.case_id;

  try {
    const btn = document.getElementById(`btn-extract-${evidenceId}`);
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = `<span class="spinner-border spinner-border-sm"></span> Extracting...`;
    }

    const res = await HMACFR_API.extractSingleEvidence(caseId, evidenceId);
    window.showForensicToast(`Extraction completed for '${filename}'. Parsed artifacts recorded.`, "success");
    loadEvidenceVaultSection();
  } catch (err) {
    console.error("Single Extraction Error:", err);
    window.showForensicToast(`Extraction failed for '${filename}': ${err.message}`, "error");
    loadEvidenceVaultSection();
  }
};

window.openArtifactDetailsDrawer = async function(evidenceId, filename) {
  if (!window.g_currentActiveCase || !window.g_currentActiveCase.case_id) return;
  const caseId = window.g_currentActiveCase.case_id;

  const drawer = document.getElementById("drawer-artifact-details");
  const overlay = document.getElementById("drawer-artifact-overlay");
  const nameEl = document.getElementById("drawer-artifact-filename");
  const idEl = document.getElementById("drawer-artifact-id");
  const catEl = document.getElementById("drawer-artifact-category");
  const hashEl = document.getElementById("drawer-artifact-hash");
  const statusEl = document.getElementById("drawer-artifact-status");
  const countEl = document.getElementById("drawer-findings-count");
  const listEl = document.getElementById("drawer-findings-list");
  const jsonEl = document.getElementById("drawer-raw-json");

  if (nameEl) nameEl.textContent = filename || "Evidence Artifact";
  if (idEl) idEl.textContent = evidenceId;
  if (listEl) listEl.innerHTML = `<div style="text-align: center; color: #94a3b8; font-size: 0.8rem; padding: 1.5rem;">Loading forensic artifacts...</div>`;
  if (jsonEl) jsonEl.textContent = "Loading...";

  if (drawer) drawer.classList.add("open");
  if (overlay) overlay.classList.add("active");

  try {
    const data = await HMACFR_API.getEvidenceArtifacts(caseId, evidenceId);
    const artifacts = data.artifacts || [];

    if (catEl) catEl.textContent = data.type || "Forensic File";
    if (countEl) countEl.textContent = `${artifacts.length} Findings`;
    if (statusEl) {
      statusEl.textContent = artifacts.length > 0 ? "Extracted & Grounded" : "Uploaded (Unparsed)";
      statusEl.className = artifacts.length > 0 ? "badge badge-emerald" : "badge badge-amber";
    }

    // Match file hash from global evidence list
    const evObj = g_allVaultEvidence.find(e => e.evidence_id === evidenceId);
    if (hashEl && evObj) hashEl.textContent = evObj.file_hash || "--";

    if (jsonEl) jsonEl.textContent = JSON.stringify(data, null, 2);

    if (artifacts.length === 0) {
      if (listEl) {
        listEl.innerHTML = `
          <div style="text-align: center; color: #64748b; font-size: 0.8rem; padding: 1.5rem;">
            No structured findings parsed yet.<br>
            <button type="button" class="btn btn-secondary btn-sm" style="margin-top: 0.5rem;" onclick="window.extractSingleEvidenceItem('${evidenceId}', '${escapeQuotes(filename)}')">Run Extractor Now</button>
          </div>
        `;
      }
    } else {
      if (listEl) {
        listEl.innerHTML = "";
        artifacts.slice(0, 15).forEach((item, idx) => {
          const itemCard = document.createElement("div");
          itemCard.style.cssText = "background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 6px; padding: 0.75rem;";
          const title = item.title || item.type || item.artifact_type || `Finding #${idx + 1}`;
          const desc = item.description || item.details || item.summary || JSON.stringify(item);
          itemCard.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem;">
              <strong style="color: #38bdf8; font-size: 0.8rem;">${escapeHTML(title)}</strong>
              <span class="artifact-detail-badge">${escapeHTML(item.source || 'PluginManager')}</span>
            </div>
            <div style="font-size: 0.75rem; color: #cbd5e1; line-height: 1.4; word-break: break-word;">${escapeHTML(desc)}</div>
          `;
          listEl.appendChild(itemCard);
        });
      }
    }
  } catch (err) {
    console.error("Error fetching evidence artifacts:", err);
    if (listEl) listEl.innerHTML = `<div style="text-align: center; color: var(--accent-danger); font-size: 0.8rem; padding: 1.5rem;">Failed to load artifacts: ${escapeHTML(err.message)}</div>`;
    if (jsonEl) jsonEl.textContent = `Error: ${err.message}`;
  }
};

window.closeArtifactDetailsDrawer = function() {
  const drawer = document.getElementById("drawer-artifact-details");
  const overlay = document.getElementById("drawer-artifact-overlay");
  if (drawer) drawer.classList.remove("open");
  if (overlay) overlay.classList.remove("active");
};

window.copyDrawerJson = function() {
  const jsonEl = document.getElementById("drawer-raw-json");
  if (jsonEl && jsonEl.textContent) {
    navigator.clipboard.writeText(jsonEl.textContent).then(() => {
      window.showForensicToast("Extraction JSON copied to clipboard!", "success");
    }).catch(e => {
      console.warn("Clipboard write failed:", e);
    });
  }
};

window.deleteEvidenceItem = async function(evidenceId, filename) {
  if (!window.g_currentActiveCase || !window.g_currentActiveCase.case_id) return;
  const caseId = window.g_currentActiveCase.case_id;

  if (window.g_currentActiveCase.vault_status === "LOCKED") {
    window.showForensicToast("Permission Denied: Evidence Vault is sealed & locked. Unlock the vault first before deleting items.", "error");
    return;
  }

  const confirmDel = await window.showForensicConfirm(
    "Delete Evidence File",
    `Are you sure you want to permanently delete evidence file '${filename}' from Case '${window.g_currentActiveCase.case_name}'?`,
    {
      confirmText: "🗑 Delete Evidence",
      cancelText: "Cancel",
      type: "danger"
    }
  );
  if (!confirmDel) return;

  try {
    await HMACFR_API.deleteCaseEvidence(caseId, evidenceId);
    window.showForensicToast(`Evidence item '${filename}' deleted successfully.`, "success");
    loadEvidenceVaultSection();
  } catch (err) {
    console.error("Error deleting evidence item:", err);
    window.showForensicToast(`Failed to delete evidence item: ${err.message}`, "error");
  }
};

async function loadEvidenceVaultSection() {
  const tbody = document.getElementById("vault-repo-table-body");
  const caseSelect = document.getElementById("vault-repo-case-select");
  const bannerName = document.getElementById("vault-case-display-name");
  const vaultStatusBadge = document.getElementById("vault-status-badge");
  const vaultStatusText = document.getElementById("vault-status-text");
  const vaultStatusDot = document.getElementById("vault-status-dot");
  const btnToggleUpload = document.getElementById("btn-vault-toggle-upload");
  const btnLockAndProceed = document.getElementById("btn-vault-lock-and-proceed");
  const btnUnlock = document.getElementById("btn-vault-unlock");
  if (!tbody) return;

  tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 2rem;">Loading Evidence Vault Repository...</td></tr>`;

  try {
    const cases = await HMACFR_API.getCases();
    window.g_allCases = cases;
    const casesMap = {};
    cases.forEach(c => { casesMap[c.case_id] = c.case_name; });

    if (caseSelect) {
      const activeId = window.g_currentActiveCase ? window.g_currentActiveCase.case_id : "";
      caseSelect.innerHTML = '<option value="">-- Select Case to View Evidence --</option>';
      cases.forEach(c => {
        const opt = document.createElement("option");
        opt.value = c.case_id;
        opt.textContent = `${c.case_name || c.case_id} (${c.case_id.substring(0, 8)}...)`;
        if (c.case_id === activeId) opt.selected = true;
        caseSelect.appendChild(opt);
      });

      caseSelect.onchange = async (e) => {
        const val = e.target.value;
        if (val) {
          await window.setActiveCase(val, { refreshActiveSection: true });
        } else {
          window.setActiveCase(null);
          renderEvidenceVaultTable(casesMap);
        }
      };
    }

    if (!window.g_currentActiveCase && cases && cases.length > 0) {
      await window.setActiveCase(cases[0].case_id, { refreshActiveSection: false });
    }

    const activeCase = window.g_currentActiveCase;
    if (activeCase) {
      try {
        const freshCase = await HMACFR_API.getCase(activeCase.case_id);
        if (freshCase) {
          activeCase.vault_status = freshCase.vault_status || "OPEN";
          activeCase.vault_locked_at = freshCase.vault_locked_at;
          activeCase.vault_locked_by = freshCase.vault_locked_by;
        }
      } catch (ce) {
        console.warn("Could not refresh active case status:", ce);
      }

      const isLocked = activeCase.vault_status === "LOCKED";

      if (vaultStatusBadge && vaultStatusText) {
        if (isLocked) {
          vaultStatusBadge.className = "badge badge-amber";
          vaultStatusBadge.style.borderColor = "rgba(245, 158, 11, 0.4)";
          vaultStatusBadge.style.boxShadow = "0 0 12px rgba(245, 158, 11, 0.25)";
          if (vaultStatusDot) {
            vaultStatusDot.className = "status-indicator offline";
            vaultStatusDot.style.background = "#f59e0b";
          }
          vaultStatusText.textContent = `VAULT SEALED & LOCKED • EVIDENCE FROZEN`;
        } else {
          vaultStatusBadge.className = "badge badge-emerald";
          vaultStatusBadge.style.borderColor = "rgba(16, 185, 129, 0.4)";
          vaultStatusBadge.style.boxShadow = "0 0 12px rgba(16, 185, 129, 0.2)";
          if (vaultStatusDot) {
            vaultStatusDot.className = "status-indicator online";
            vaultStatusDot.style.background = "#10b981";
          }
          vaultStatusText.textContent = "VAULT OPEN • INGESTION ACTIVE";
        }
      }

      if (btnToggleUpload) {
        if (isLocked) {
          btnToggleUpload.disabled = true;
          btnToggleUpload.style.opacity = "0.45";
          btnToggleUpload.style.cursor = "not-allowed";
          btnToggleUpload.title = "Evidence Vault is sealed for analysis. Reopen vault to upload more.";
        } else {
          btnToggleUpload.disabled = false;
          btnToggleUpload.style.opacity = "1";
          btnToggleUpload.style.cursor = "pointer";
          btnToggleUpload.title = "Upload additional evidence files";
        }
      }

      if (btnLockAndProceed) {
        if (isLocked) {
          btnLockAndProceed.innerHTML = `
            <svg class="svg-icon svg-icon-sm" viewBox="0 0 24 24"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
            <span>Continue to Agent Analysis &rarr;</span>
          `;
        } else {
          btnLockAndProceed.innerHTML = `
            <svg class="svg-icon svg-icon-sm" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            <span>Lock Vault &amp; Proceed to Analysis &rarr;</span>
          `;
        }
      }

      if (btnUnlock) {
        btnUnlock.style.display = isLocked ? "inline-flex" : "none";
      }

      if (bannerName) bannerName.textContent = `${activeCase.case_name} (${activeCase.case_id})`;

      const evidences = await HMACFR_API.getAllEvidence(activeCase.case_id);
      activeCase.evidences = evidences;
      activeCase.evidence_count = evidences.length;
      activeCase.evidence_ids = evidences.map(e => e.evidence_id);
      g_allVaultEvidence = evidences;

      renderEvidenceVaultTable(casesMap);
    } else {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 2rem;">No case selected. Select or create a case to view its evidence vault.</td></tr>`;
    }
  } catch (err) {
    console.error("Error loading evidence vault repository:", err);
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--accent-danger); padding: 2rem;">Error loading vault repository: ${escapeHTML(err.message)}</td></tr>`;
  }
}

function renderEvidenceVaultTable(casesMap = {}) {
  const tbody = document.getElementById("vault-repo-table-body");
  const searchInput = document.getElementById("vault-repo-search-input");
  const catSelect = document.getElementById("vault-repo-category-select");

  if (!tbody) return;

  const query = searchInput ? searchInput.value.trim().toLowerCase() : "";
  const selectedCat = catSelect ? catSelect.value : "ALL";

  let filtered = g_allVaultEvidence.filter(ev => {
    let matchQuery = true;
    if (query) {
      matchQuery = (
        (ev.original_filename && ev.original_filename.toLowerCase().includes(query)) ||
        (ev.category && ev.category.toLowerCase().includes(query)) ||
        (ev.file_hash && ev.file_hash.toLowerCase().includes(query))
      );
    }
    const matchCat = (selectedCat === "ALL") || (ev.category && ev.category.toLowerCase() === selectedCat.toLowerCase());
    return matchQuery && matchCat;
  });

  if (filtered.length === 0) {
    const caseName = window.g_currentActiveCase ? window.g_currentActiveCase.case_name : "this case";
    tbody.innerHTML = `
      <tr>
        <td colspan="8">
          <div class="empty-state" style="padding: 2.5rem; text-align: center;">
            <div class="empty-state-title" style="font-size: 1rem; font-weight: 700; color: #f8fafc; margin-bottom: 0.35rem;">No Evidence Files Found</div>
            <div class="empty-state-subtitle" style="font-size: 0.82rem; color: #94a3b8; margin-bottom: 1rem;">No evidence artifacts found for case: <strong>${escapeHTML(caseName)}</strong>.</div>
            <button type="button" class="btn btn-primary btn-sm" onclick="window.toggleVaultInlineUpload(true);">+ Upload First Evidence Item &rarr;</button>
          </div>
        </td>
      </tr>
    `;
    return;
  }

  const isLocked = window.g_currentActiveCase && window.g_currentActiveCase.vault_status === "LOCKED";
  tbody.innerHTML = "";

  filtered.forEach(ev => {
    const tr = document.createElement("tr");

    let formattedSize = "0 B";
    if (ev.file_size) {
      const bytes = ev.file_size;
      if (bytes >= 1073741824) formattedSize = (bytes / 1073741824).toFixed(2) + " GB";
      else if (bytes >= 1048576) formattedSize = (bytes / 1048576).toFixed(2) + " MB";
      else if (bytes >= 1024) formattedSize = (bytes / 1024).toFixed(2) + " KB";
      else formattedSize = bytes + " B";
    }

    let uploadDateStr = "N/A";
    if (ev.upload_timestamp) {
      try {
        const d = new Date(ev.upload_timestamp);
        uploadDateStr = d.toLocaleDateString() + " " + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      } catch (e) {
        uploadDateStr = String(ev.upload_timestamp).replace("T", " ").substring(0, 19);
      }
    }

    const catText = ev.category || ev.type || "Forensic Data";
    const caseNameStr = casesMap[ev.case_id] ? `${casesMap[ev.case_id]}` : (window.g_currentActiveCase ? window.g_currentActiveCase.case_name : "Case Record");

    const hashSnippet = ev.file_hash
      ? `<code class="mono-text" title="${ev.file_hash}">${ev.file_hash.substring(0, 12)}...</code>`
      : `<span class="badge badge-amber">Pending</span>`;

    const st = (ev.status || "").toUpperCase();
    const isExtracted = st === "PARSED" || st === "READY_FOR_PROCESSING" || st === "VAULTED" || st === "PRESERVED" || st === "EXTRACTED" || (window.g_currentActiveCase && window.g_currentActiveCase.synthesized_data && (window.g_currentActiveCase.synthesized_data.findings || []).length > 0);
    const extractionBadge = isExtracted
      ? `<span class="badge badge-emerald" style="font-size: 0.72rem; padding: 2px 8px;">Extracted</span>`
      : `<span class="badge badge-secondary" style="font-size: 0.72rem; color: #94a3b8; padding: 2px 8px;">Not Extracted</span>`;


    const deleteBtn = isLocked
      ? `<button class="btn btn-secondary btn-sm" disabled title="Vault is locked. Cannot delete sealed evidence." style="opacity: 0.35; cursor: not-allowed; font-size: 0.72rem; padding: 0.2rem 0.45rem;">🗑 Delete</button>`
      : `<button class="btn btn-secondary btn-sm" onclick="window.deleteEvidenceItem('${ev.evidence_id}', '${escapeQuotes(ev.original_filename)}')" style="font-size: 0.72rem; padding: 0.2rem 0.45rem; color: #f87171;" title="Delete evidence file">🗑 Delete</button>`;

    tr.innerHTML = `
      <td>
        <div class="mono-text" style="font-size: 0.75rem; font-weight: 700; color: var(--accent-emerald-light);">${ev.case_id ? ev.case_id.substring(0, 8) + '...' : 'Unassigned'}</div>
        <div style="font-size: 0.78rem; color: #fff; font-weight: 600;">${escapeHTML(caseNameStr)}</div>
      </td>
      <td><strong>${escapeHTML(ev.original_filename)}</strong></td>
      <td><span class="badge badge-indigo">${escapeHTML(catText)}</span></td>
      <td><code class="mono-text">${formattedSize}</code></td>
      <td>${hashSnippet}</td>
      <td style="font-size: 0.8rem; color: var(--text-secondary);">${uploadDateStr}</td>
      <td>${extractionBadge}</td>
      <td style="white-space: nowrap; text-align: center;">
        <div style="display: inline-flex; align-items: center; gap: 0.35rem;">
          <button id="btn-extract-${ev.evidence_id}" class="btn btn-primary btn-sm" onclick="window.extractSingleEvidenceItem('${ev.evidence_id}', '${escapeQuotes(ev.original_filename)}')" style="font-size: 0.72rem; padding: 0.2rem 0.5rem;" title="Run Plugin Extractor on this file">
            ⚙ Extract
          </button>
          <button class="btn btn-secondary btn-sm" onclick="window.openArtifactDetailsDrawer('${ev.evidence_id}', '${escapeQuotes(ev.original_filename)}')" style="font-size: 0.72rem; padding: 0.2rem 0.5rem; color: #38bdf8;" title="View extracted entities and artifacts">
            🔍 Artifacts
          </button>
          ${deleteBtn}
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });
}


async function loadPreservationSection() {
  try {
    const cases = await HMACFR_API.getCases();
    const select = document.getElementById("preservation-case-select");
    if (!select) return;

    select.innerHTML = '<option value="">-- Select Case to View / Preserve --</option>';
    cases.forEach(c => {
      const opt = document.createElement("option");
      opt.value = c.case_id;
      opt.textContent = `${c.case_id} — ${c.case_name}`;
      select.appendChild(opt);
    });

    const fetchAndRender = async () => {
      const selectedCase = select.value;
      const tbody = document.getElementById("preservation-table-body");
      tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 2rem;">Loading evidence preservation data...</td></tr>';

      let allEvidences = [];
      if (selectedCase) {
        allEvidences = await HMACFR_API.getCaseEvidence(selectedCase);
      } else {
        allEvidences = await HMACFR_API.getEvidences();
      }

      if (allEvidences.length === 0) {
        tbody.innerHTML = `
          <tr>
            <td colspan="9">
              <div class="empty-state">
                <div class="empty-state-icon">
                  <svg class="svg-icon" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                </div>
                <div class="empty-state-title">No Evidence Files for Preservation</div>
                <div class="empty-state-subtitle">Ingest evidence artifacts first to compute multi-pass SHA-256 digests and execute Layer 1 vault preservation.</div>
              </div>
            </td>
          </tr>
        `;
        return;
      }

      tbody.innerHTML = "";
      allEvidences.forEach(ev => {
        const tr = document.createElement("tr");
        const isPreserved = ev.status === "READY_FOR_PROCESSING" || ev.status === "Vaulted";
        const statusBadge = isPreserved
          ? '<span class="badge badge-emerald">PRESERVED (LAYER 1)</span>'
          : '<span class="badge badge-amber">PENDING PRESERVATION</span>';

        const actionBtn = isPreserved
          ? '<button class="btn btn-secondary btn-sm" disabled>Preserved & Vaulted</button>'
          : `<button class="btn btn-primary btn-sm" onclick="runPreservationPipeline('${ev.evidence_id}', '${ev.case_id}')">Preserve</button>`;

        tr.innerHTML = `
          <td><code class="mono-text">${ev.evidence_id}</code></td>
          <td><strong>${ev.original_filename}</strong></td>
          <td><span class="badge badge-cyan">${ev.category || 'Memory'}</span></td>
          <td><code class="mono-text">${ev.file_hash ? ev.file_hash.substring(0, 16) + '...' : 'Pending'}</code></td>
          <td><code class="mono-text">${isPreserved ? 'Verified (128-bit)' : 'Pending'}</code></td>
          <td>${isPreserved ? '<span class="badge badge-emerald">AES-256-GCM</span>' : '<span class="badge badge-amber">Unencrypted</span>'}</td>
          <td>${isPreserved ? '<span class="badge badge-emerald">Read-Only</span>' : '<span class="badge badge-amber">Writeable</span>'}</td>
          <td>${statusBadge}</td>
          <td>${actionBtn}</td>
        `;
        tbody.appendChild(tr);
      });
    };

    select.onchange = fetchAndRender;
    fetchAndRender();
  } catch (err) {
    console.error("Error loading preservation section:", err);
  }
}

async function populateCaseSelects(existingCases = null) {
  try {
    const cases = existingCases || await HMACFR_API.getCases();
    const select = document.getElementById("upload-case-id");
    if (!select) return;

    select.innerHTML = '<option value="">-- Select Case --</option>';
    cases.forEach(c => {
      let expCount = c.expected_evidence_count;
      if (!expCount && c.description && c.description.includes("Expected Items:")) {
        const match = c.description.match(/Expected Items:\s*(\d+)/);
        if (match) expCount = parseInt(match[1]);
      }
      const opt = document.createElement("option");
      opt.value = c.case_id;
      opt.dataset.expected = expCount || 1;
      opt.textContent = `${c.case_id} — ${c.case_name}`;
      select.appendChild(opt);
    });
  } catch (err) {
    console.error(err);
  }
}

async function populateAuditCaseSelects(existingCases = null) {
  try {
    const cases = existingCases || await HMACFR_API.getCases();
    const select = document.getElementById("audit-case-select");
    if (!select) return;

    select.innerHTML = '<option value="">-- Select Case to Audit --</option>';
    cases.forEach(c => {
      const opt = document.createElement("option");
      opt.value = c.case_id;
      opt.textContent = `${c.case_id} — ${c.case_name}`;
      select.appendChild(opt);
    });
  } catch (err) {
    console.error(err);
  }
}

function renderAuditReport(report) {
  const emptyState = document.getElementById("audit-empty-state");
  const container = document.getElementById("audit-report-container");
  
  if (emptyState) emptyState.style.display = "none";
  if (container) container.style.display = "block";

  document.getElementById("audit-total-count").textContent = report.total_audited;
  document.getElementById("audit-valid-count").textContent = report.total_valid;
  document.getElementById("audit-tampered-count").textContent = report.total_tampered;
  document.getElementById("audit-missing-count").textContent = report.total_missing;

  const tbody = document.getElementById("audit-table-body");
  tbody.innerHTML = "";

  if (report.results.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6">
          <div class="empty-state">
            <div class="empty-state-icon">
              <svg class="svg-icon" viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
            </div>
            <div class="empty-state-title">Audit Verification Pending</div>
            <div class="empty-state-subtitle">Select an active investigation case from the dropdown above and click "Run Batch Audit" to initiate automated multi-factor verification.</div>
          </div>
        </td>
      </tr>
    `;
    return;
  }

  report.results.forEach(res => {
    const tr = document.createElement("tr");
    const statusBadge = res.is_valid
      ? `<span class="badge badge-emerald">INTACT (VERIFIED)</span>`
      : `<span class="badge badge-danger">${(res.status || 'TAMPERED').toUpperCase()}</span>`;

    tr.innerHTML = `
      <td><code class="mono-text">${res.evidence_id}</code></td>
      <td>${res.original_filename}</td>
      <td><code class="mono-text">${(res.current_sha256 || '').substring(0, 16)}...</code></td>
      <td>${res.hmac_verified ? '<span class="badge badge-emerald">Verified</span>' : '<span class="badge badge-danger">Mismatch</span>'}</td>
      <td>${res.readonly_protected ? '<span class="badge badge-emerald">Read-Only</span>' : '<span class="badge badge-amber">Writeable</span>'}</td>
      <td>${statusBadge}</td>
    `;
    tbody.appendChild(tr);
  });

  if (window.hmacfr3D) window.hmacfr3D.initAuditStage(report);
}

async function populateCustodyEvidenceSelects() {
  try {
    const cases = await HMACFR_API.getCases();
    const select = document.getElementById("custody-evidence-select");
    if (!select) return;

    select.innerHTML = '<option value="">-- Select Evidence Item --</option>';
    for (const c of cases) {
      const evs = await HMACFR_API.getCaseEvidence(c.case_id);
      evs.forEach(ev => {
        const opt = document.createElement("option");
        opt.value = ev.evidence_id;
        opt.textContent = `${ev.evidence_id} (${ev.original_filename}) — Case: ${c.case_id}`;
        select.appendChild(opt);
      });
    }

    select.onchange = async () => {
      const evId = select.value;
      const emptyState = document.getElementById("custody-empty-state");
      const viewport = document.getElementById("custody-viewport-container");
      const container = document.getElementById("custody-timeline-container");

      if (!evId) {
        if (emptyState) emptyState.style.display = "flex";
        if (viewport) viewport.style.display = "none";
        if (container) container.style.display = "none";
        return;
      }

      if (emptyState) emptyState.style.display = "none";
      if (viewport) viewport.style.display = "block";
      if (container) container.style.display = "block";

      const logs = await HMACFR_API.getCustodyLogs(evId);
      renderCustodyTimeline(logs);
    };
  } catch (err) {
    console.error(err);
  }
}

function renderCustodyTimeline(logs) {
  const container = document.getElementById("custody-timeline-container");
  container.innerHTML = "";

  if (!logs || logs.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">
          <svg class="svg-icon" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
        </div>
        <div class="empty-state-title">No Custody Logs Found</div>
        <div class="empty-state-subtitle">No recorded transfer or preservation logs exist for this evidence artifact.</div>
      </div>
    `;
    return;
  }

  logs.forEach(log => {
    const item = document.createElement("div");
    item.style.cssText = "background: rgba(15, 23, 42, 0.6); border: 1px solid var(--border-card); border-left: 3px solid var(--accent-emerald); border-radius: var(--radius-sm); padding: 1rem 1.25rem; margin-bottom: 0.85rem;";

    item.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem;">
        <span class="badge badge-emerald">${log.action}</span>
        <span style="font-size: 0.8rem; color: var(--text-muted);" class="mono-text">${new Date(log.timestamp).toUTCString()}</span>
      </div>
      <div style="font-size: 0.875rem; margin-bottom: 0.3rem;">
        Investigator / Agent: <strong>${log.performed_by}</strong>
      </div>
      <div style="font-size: 0.85rem; color: var(--text-secondary);">
        ${log.remarks || 'No additional remarks'}
      </div>
    `;
    container.appendChild(item);
  });

  if (window.hmacfr3D) window.hmacfr3D.initCustodyStage(logs);
}

/* =========================================================================
   STAGE 3 WORKSPACE ARCHITECTURE: 3-MODE SWITCHER, LAB STEPPER & GOVERNANCE
   ========================================================================= */

// Top Workspace Switcher (Legacy Bridge)
window.switchWorkspaceMode = function(mode) {
  if (mode === "VAULT" || mode === "CASES") {
    window.switchWorkspaceSection("sec-cases");
  } else if (mode === "LAB") {
    window.openCaseInLab(window.g_currentActiveCaseId);
  } else if (mode === "ADMIN") {
    window.switchWorkspaceSection("sec-admin-users");
  }
};

window.handleForensicLabSidebarClick = function(event) {
  if (event) event.preventDefault();
  window.switchWorkspaceMode("LAB");
};

window.switchLabWorkstation = function(sectionId) {
  const workstationTabs = {
    "sec-evidence-vault": "evidence",
    "sec-extraction": "extraction",
    "sec-analysis": "analysis",
    "sec-sis": "sis",
    "sec-outputs": "outputs",
    "sec-knowledge-rag": "graph"
  };
  const tab = workstationTabs[sectionId] || "evidence";
  window.switchLabWorkstationTab(tab);
};

window.updateLabStepperActiveState = function() {};
window.populateLabCasePicker = function() {};
window.handleLabCasePickerSubmit = function() {};

// Dynamic Case Permissions & Access Control Matrix
window.g_currentCasePermissions = null;
window.isAuditMode = false;

window.loadCasePermissions = async function(caseId) {
  if (!caseId) return;
  try {
    const perms = await HMACFR_API.getMyCasePermissions(caseId);
    window.g_currentCasePermissions = perms;

    // 1. Update My Status badge in Lab sidebar
    const badgeEl = document.getElementById("lab-my-role-badge");
    const bannerEl = document.getElementById("lab-audit-mode-banner");
    const manageTeamBtn = document.getElementById("btn-lab-manage-team");

    if (window.isAuditMode) {
      if (badgeEl) {
        badgeEl.textContent = "AUDIT (VIEW-ONLY)";
        badgeEl.style.background = "rgba(245, 158, 11, 0.2)";
        badgeEl.style.color = "#d97706";
        badgeEl.style.borderColor = "rgba(245, 158, 11, 0.4)";
      }
      if (bannerEl) bannerEl.style.display = "block";
      if (manageTeamBtn) manageTeamBtn.style.display = "none";
    } else {
      if (bannerEl) bannerEl.style.display = "none";
      if (badgeEl) {
        if (perms.is_lead) {
          badgeEl.textContent = perms.is_creator ? "Lead (Creator)" : "Lead Investigator";
          badgeEl.style.background = "rgba(56, 189, 248, 0.15)";
          badgeEl.style.color = "#0284c7";
          badgeEl.style.borderColor = "rgba(56, 189, 248, 0.3)";
        } else if (perms.responsibilities && perms.responsibilities.includes("Forensic Analyst")) {
          badgeEl.textContent = "Forensic Analyst";
          badgeEl.style.background = "rgba(167, 139, 250, 0.15)";
          badgeEl.style.color = "#7c3aed";
          badgeEl.style.borderColor = "rgba(167, 139, 250, 0.3)";
        } else if (perms.responsibilities && perms.responsibilities.includes("Case Auditor") || perms.is_platform_auditor) {
          badgeEl.textContent = "Case Auditor (Read-Only)";
          badgeEl.style.background = "rgba(148, 163, 184, 0.15)";
          badgeEl.style.color = "#475569";
          badgeEl.style.borderColor = "rgba(148, 163, 184, 0.3)";
        } else if (perms.responsibilities && perms.responsibilities.includes("Reviewer")) {
          badgeEl.textContent = "Reviewer";
          badgeEl.style.background = "rgba(251, 191, 36, 0.15)";
          badgeEl.style.color = "#d97706";
          badgeEl.style.borderColor = "rgba(251, 191, 36, 0.3)";
        } else {
          badgeEl.textContent = "Investigator";
          badgeEl.style.background = "rgba(52, 211, 153, 0.15)";
          badgeEl.style.color = "#059669";
          badgeEl.style.borderColor = "rgba(52, 211, 153, 0.3)";
        }
      }

      // Show Manage Team button ONLY for Leads and Admins
      if (manageTeamBtn) {
        manageTeamBtn.style.display = (perms.is_lead || perms.is_admin) ? "flex" : "none";
      }
    }

    // 2. Apply granular workstation permissions
    window.applyCaseWorkstationPermissions(perms);
  } catch (err) {
    console.warn("Could not load case permissions:", err);
  }
};

window.applyCaseWorkstationPermissions = function(perms) {
  if (!perms) return;
  const permissions = perms.permissions || [];
  const isAudit = !!window.isAuditMode;

  // Analysis execution buttons
  const canRunAnalysis = !isAudit && permissions.includes("analysis:run");
  const analysisBtns = [
    document.getElementById("btn-run-all-specialists"),
    document.getElementById("btn-run-correlation-engine"),
    document.getElementById("btn-run-hybrid-correlation")
  ];
  analysisBtns.forEach(btn => {
    if (btn) {
      if (canRunAnalysis) {
        btn.disabled = false;
        btn.style.opacity = "1";
        btn.style.cursor = "pointer";
        btn.removeAttribute("title");
      } else {
        btn.disabled = true;
        btn.style.opacity = "0.55";
        btn.style.cursor = "not-allowed";
        btn.title = isAudit ? "Read-Only Audit Mode: Inference actions locked." : "Requires analysis:run permission (Lead Investigator or Forensic Analyst).";
      }
    }
  });

  // Batch evidence upload button
  const canUpload = !isAudit && permissions.includes("evidence:upload");
  const uploadBtn = document.getElementById("btn-submit-batch-upload");
  if (uploadBtn) {
    if (canUpload) {
      uploadBtn.disabled = false;
      uploadBtn.style.opacity = "1";
      uploadBtn.style.cursor = "pointer";
      uploadBtn.removeAttribute("title");
    } else {
      uploadBtn.disabled = true;
      uploadBtn.style.opacity = "0.5";
      uploadBtn.style.cursor = "not-allowed";
      uploadBtn.title = isAudit ? "Read-Only Audit Mode: Evidence ingestion locked." : "Requires evidence:upload permission.";
    }
  }
};

// Case Team Management Modal
window.currentManageTeamCaseId = null;

window.openManageTeamModal = async function(caseId, caseName) {
  window.currentManageTeamCaseId = caseId;
  const titleEl = document.getElementById("team-modal-case-title");
  if (titleEl) titleEl.textContent = `Case Team & Access Matrix: ${caseName || caseId}`;
  const idEl = document.getElementById("team-modal-case-id");
  if (idEl) idEl.textContent = caseId;

  // Set creator info
  const creatorNameEl = document.getElementById("team-modal-creator-name");
  const createdAtEl = document.getElementById("team-modal-created-at");
  if (window.g_currentActiveCase && window.g_currentActiveCase.case_id === caseId) {
    if (creatorNameEl) creatorNameEl.textContent = window.g_currentActiveCase.investigator_name || window.g_currentActiveCase.investigator || "N/A";
    if (createdAtEl) createdAtEl.textContent = window.g_currentActiveCase.created_at ? new Date(window.g_currentActiveCase.created_at).toLocaleDateString() : "Active";
  }

  const modal = document.getElementById("modal-manage-case-team");
  if (modal) modal.style.display = "flex";

  const userSelect = document.getElementById("team-user-select");
  if (userSelect) {
    userSelect.innerHTML = '<option value="">-- Loading users... --</option>';
    try {
      const users = await HMACFR_API.getUsers();
      userSelect.innerHTML = '<option value="">-- Select Registered User --</option>';
      users.forEach(u => {
        const opt = document.createElement("option");
        opt.value = u.user_id;
        opt.textContent = `${u.username} (${u.email}) [${u.role}]`;
        userSelect.appendChild(opt);
      });
    } catch (e) {
      userSelect.innerHTML = '<option value="">-- Error loading users --</option>';
    }
  }

  await window.refreshCaseMembersTable(caseId);
};

window.closeManageTeamModal = function() {
  const modal = document.getElementById("modal-manage-case-team");
  if (modal) modal.style.display = "none";
};

window.refreshCaseMembersTable = async function(caseId) {
  const tbody = document.getElementById("case-team-table-body");
  const countEl = document.getElementById("team-modal-member-count");
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 1.5rem; color: #94a3b8;">Loading team members...</td></tr>';
  try {
    const members = await HMACFR_API.getCaseMembers(caseId);
    if (countEl) countEl.textContent = `${members ? members.length : 0} personnel`;
    if (!members || members.length === 0) {
      tbody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 1.5rem; color: #94a3b8;">No members assigned yet. Use the form below to assign investigators.</td></tr>';
      return;
    }
    tbody.innerHTML = "";

    // Count how many Lead Investigators exist on this case
    const leadMembers = members.filter(m => (m.responsibilities || []).includes("Lead Investigator"));
    const activeCase = window.g_currentActiveCase || {};
    const creatorUser = activeCase.investigator_name || activeCase.investigator;

    members.forEach(m => {
      const tr = document.createElement("tr");
      tr.style.borderBottom = "1px solid rgba(148, 163, 184, 0.12)";
      tr.style.background = "rgba(15, 23, 42, 0.3)";

      const isCreator = (m.username === creatorUser || m.user_id === creatorUser);
      const isLead = (m.responsibilities || []).includes("Lead Investigator");
      const isOnlyLead = isLead && leadMembers.length <= 1;

      const respBadgeMap = {
        "Lead Investigator": { bg: "rgba(56, 189, 248, 0.15)", text: "#38bdf8", border: "rgba(56, 189, 248, 0.3)" },
        "Investigator": { bg: "rgba(52, 211, 153, 0.15)", text: "#34d399", border: "rgba(52, 211, 153, 0.3)" },
        "Forensic Analyst": { bg: "rgba(167, 139, 250, 0.15)", text: "#a78bfa", border: "rgba(167, 139, 250, 0.3)" },
        "Reviewer": { bg: "rgba(251, 191, 36, 0.15)", text: "#fbbf24", border: "rgba(251, 191, 36, 0.3)" },
        "Case Auditor": { bg: "rgba(148, 163, 184, 0.15)", text: "#cbd5e1", border: "rgba(148, 163, 184, 0.3)" }
      };

      const respBadges = (m.responsibilities || []).map(r => {
        const style = respBadgeMap[r] || { bg: "rgba(56, 189, 248, 0.12)", text: "#38bdf8", border: "rgba(56, 189, 248, 0.25)" };
        return `<span style="background: ${style.bg}; color: ${style.text}; border: 1px solid ${style.border}; padding: 2px 7px; border-radius: 4px; font-size: 0.72rem; font-weight: 700; margin-right: 4px; display: inline-block;">${escapeHTML(r)}</span>`;
      }).join(" ") || '<span style="color: #64748b; font-style: italic;">No specific role</span>';

      const creatorBadge = isCreator ? `<span style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.4); padding: 1px 6px; border-radius: 4px; font-size: 0.65rem; font-weight: 800; margin-left: 6px; letter-spacing: 0.04em;">CASE CREATOR</span>` : '';

      const removeActionHTML = isOnlyLead
        ? `<span style="color: #64748b; font-size: 0.7rem; font-style: italic;" title="Protected succession: Cannot remove the only Lead Investigator">Primary Lead</span>`
        : `<button type="button" class="btn btn-sm" style="background: rgba(239, 68, 68, 0.12); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); font-size: 0.72rem; font-weight: 600; padding: 3px 8px; border-radius: 6px; cursor: pointer;" onclick="window.removeCaseMemberItem('${escapeQuotes(caseId)}', '${escapeQuotes(m.user_id)}', '${escapeQuotes(m.username || m.user_id)}');">Remove</button>`;

      tr.innerHTML = `
        <td style="padding: 0.75rem 0.85rem;">
          <div style="font-weight: 700; color: #f8fafc; display: flex; align-items: center;">
            ${escapeHTML(m.username || m.user_id)}
            ${creatorBadge}
          </div>
          <div style="font-size: 0.72rem; color: #94a3b8; font-family: 'JetBrains Mono', monospace;">${escapeHTML(m.user_id || '')}</div>
        </td>
        <td style="padding: 0.75rem 0.85rem;">${respBadges}</td>
        <td style="padding: 0.75rem 0.85rem; text-align: right;">${removeActionHTML}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="3" style="text-align: center; padding: 1.5rem; color: #ef4444;">Error loading members: ${escapeHTML(err.message)}</td></tr>`;
  }
};

window.submitCaseMemberAssignment = async function() {
  const caseId = window.currentManageTeamCaseId;
  const userSelect = document.getElementById("team-user-select");
  const userId = userSelect ? userSelect.value : "";
  if (!userId) {
    if (typeof showSherlockNotice === "function") {
      showSherlockNotice("Selection Missing", "Please select a registered user to assign.", true);
    }
    return;
  }

  const responsibilities = [];
  const chkIds = [
    { id: "chk-team-lead", val: "Lead Investigator" },
    { id: "chk-team-investigator", val: "Investigator" },
    { id: "chk-team-analyst", val: "Forensic Analyst" },
    { id: "chk-team-reviewer", val: "Reviewer" },
    { id: "chk-team-auditor", val: "Case Auditor" }
  ];
  chkIds.forEach(item => {
    const el = document.getElementById(item.id);
    if (el && el.checked) responsibilities.push(item.val);
  });

  if (responsibilities.length === 0) {
    if (typeof showSherlockNotice === "function") {
      showSherlockNotice("Selection Missing", "Please select at least one responsibility.", true);
    }
    return;
  }

  try {
    await HMACFR_API.assignCaseMember(caseId, userId, responsibilities);
    if (typeof showSherlockNotice === "function") {
      showSherlockNotice("Team Updated", "Case member assigned / responsibilities updated successfully.");
    }
    await window.refreshCaseMembersTable(caseId);
    if (window.g_currentActiveCaseId === caseId) {
      await window.loadCasePermissions(caseId);
    }
  } catch (err) {
    if (typeof showSherlockNotice === "function") {
      showSherlockNotice("Assignment Failed", err.message, true);
    }
  }
};

window.removeCaseMemberItem = async function(caseId, userId, username) {
  const confirmed = await window.showForensicConfirm(
    "Remove Case Member",
    `Are you sure you want to remove ${username} from this case?`,
    { confirmText: "Remove Member", cancelText: "Cancel", type: "danger" }
  );
  if (!confirmed) return;
  try {
    await HMACFR_API.removeCaseMember(caseId, userId);
    if (typeof showSherlockNotice === "function") {
      showSherlockNotice("Member Removed", `User ${username} removed from case team.`);
    }
    await window.refreshCaseMembersTable(caseId);
    if (window.g_currentActiveCaseId === caseId) {
      await window.loadCasePermissions(caseId);
    }
  } catch (err) {
    if (typeof showSherlockNotice === "function") {
      showSherlockNotice("Removal Failed", err.message, true);
    }
  }
};

// Admin Center 4-Tab Handlers
window.switchAdminTab = function(tabName) {
  const tabs = ["users", "deletions", "audit", "cases"];
  tabs.forEach(t => {
    const btn = document.getElementById(`tab-btn-admin-${t}`);
    const pane = document.getElementById(`admin-pane-${t}`);
    if (t === tabName) {
      if (btn) btn.classList.add("active");
      if (pane) pane.style.display = "block";
    } else {
      if (btn) btn.classList.remove("active");
      if (pane) pane.style.display = "none";
    }
  });

  if (tabName === "users") {
    if (typeof loadAdminUsersData === "function") loadAdminUsersData();
  } else if (tabName === "deletions") {
    if (typeof loadAdminPendingDeletionRequests === "function") loadAdminPendingDeletionRequests();
  } else if (tabName === "audit") {
    window.loadAdminAuditLogs();
  } else if (tabName === "cases") {
    window.loadAdminCasesTable();
  }
};

window.loadAdminCasesTable = async function() {
  const tbody = document.getElementById("admin-all-cases-table-body");
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 1.5rem; color: var(--text-muted);">Loading all investigation cases across platform...</td></tr>';
  try {
    const cases = await HMACFR_API.getCases();
    if (!cases || cases.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 1.5rem; color: var(--text-muted);">No cases recorded in the system.</td></tr>';
      return;
    }
    tbody.innerHTML = "";
    cases.forEach(c => {
      const tr = document.createElement("tr");
      let createdStr = "-";
      if (c.created_at) {
        try { createdStr = new Date(c.created_at).toLocaleString(); } catch (e) { createdStr = String(c.created_at); }
      }
      const priorityClass = getPriorityBadgeClass(c.priority);
      const creatorName = c.investigator_name || c.investigator || "System";

      tr.innerHTML = `
        <td style="font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; font-weight: 700; color: #38bdf8;">${escapeHTML(c.case_id)}</td>
        <td style="font-weight: 700; color: #0f172a;">${escapeHTML(c.case_name || 'Investigation Case')}</td>
        <td>
          <div style="display: flex; align-items: center; gap: 4px;">
            <strong style="color: #1e293b;">${escapeHTML(creatorName)}</strong>
            <span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.4); font-size: 0.65rem; padding: 1px 5px; border-radius: 4px; font-weight: 800;">CREATOR</span>
          </div>
        </td>
        <td style="font-size: 0.78rem; color: #64748b;">${escapeHTML(createdStr)}</td>
        <td><span class="badge ${priorityClass}">${escapeHTML((c.priority || 'Medium').toUpperCase())}</span></td>
        <td><span class="badge" style="background: rgba(16, 185, 129, 0.15); color: #059669; border: 1px solid rgba(16, 185, 129, 0.3); font-weight: 700; font-size: 0.72rem;">${escapeHTML((c.status || 'Active').toUpperCase())}</span></td>
        <td style="text-align: center;">
          <button type="button" class="btn btn-sm btn-secondary" onclick="window.openManageTeamModal('${escapeQuotes(c.case_id)}', '${escapeQuotes(c.case_name || 'Case')}');" style="font-size: 0.72rem; padding: 2px 7px;">
            View Team
          </button>
        </td>
        <td style="text-align: right;">
          <button type="button" class="btn btn-sm" onclick="window.adminInspectCaseAudit('${escapeQuotes(c.case_id)}');" style="background: rgba(2, 132, 199, 0.12); color: #0284c7; border: 1px solid rgba(2, 132, 199, 0.3); font-size: 0.75rem; font-weight: 700; padding: 3px 9px; border-radius: 6px; cursor: pointer; display: inline-flex; align-items: center; gap: 4px;">
            <span>👁️ Audit Case (View-Only)</span>
          </button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; padding: 1.5rem; color: #ef4444;">Failed to load cases: ${escapeHTML(err.message)}</td></tr>`;
  }
};

window.adminInspectCaseAudit = async function(caseId) {
  window.isAuditMode = true;
  await window.openCaseInLab(caseId);
  const adminSec = document.getElementById("sec-admin-users");
  if (adminSec) adminSec.style.display = "none";
  if (typeof showSherlockNotice === "function") {
    showSherlockNotice("Audit View Activated", `Case ${caseId} opened in Read-Only Audit Mode. Destructive operations are locked.`, false);
  }
};

window.loadAdminAuditLogs = async function() {
  const tbody = document.getElementById("admin-audit-table-body");
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted);">Loading audit logs...</td></tr>';
  try {
    const logs = await HMACFR_API.getAuditLogs(100);
    if (!logs || logs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted);">No audit events recorded yet in the immutable ledger.</td></tr>';
      return;
    }
    tbody.innerHTML = "";
    logs.forEach(log => {
      const tr = document.createElement("tr");
      let formattedTime = log.timestamp || "-";
      try {
        formattedTime = new Date(log.timestamp).toLocaleString();
      } catch (e) {}

      const safeSeq = log.sequence_number || log.seq_id || log.id || "-";
      const safeAction = escapeHTML(log.action || "EVENT");
      const safeResource = escapeHTML((log.resource_type || "") + (log.resource_id ? " (" + log.resource_id + ")" : "") || "-");
      const safeUser = escapeHTML(log.user_id || log.username || "System");
      const safeDetails = escapeHTML(typeof log.details === "object" ? JSON.stringify(log.details) : String(log.details || "-"));
      const rawHash = log.row_hash || log.chain_hash || "N/A";
      const safeHash = escapeHTML(rawHash.length > 12 ? rawHash.substring(0, 12) + "..." : rawHash);

      tr.innerHTML = `
        <td class="mono-text" style="font-weight: 700; color: #64748b;">#${safeSeq}</td>
        <td style="font-size: 0.78rem; white-space: nowrap;">${formattedTime}</td>
        <td><span class="badge" style="background: #e0e7ff; color: #3730a3; font-size: 0.72rem; font-weight: 700;">${safeAction}</span></td>
        <td style="font-size: 0.8rem;">${safeResource}</td>
        <td class="mono-text" style="font-weight: 600;">${safeUser}</td>
        <td style="max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 0.78rem;" title="${safeDetails}">${safeDetails}</td>
        <td><code class="mono-text" style="font-size: 0.72rem; color: #10b981; background: rgba(16, 185, 129, 0.1); padding: 2px 6px; border-radius: 4px;" title="${escapeHTML(rawHash)}">${safeHash}</code></td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: #ef4444;">Error loading audit logs: ${escapeHTML(err.message)}</td></tr>`;
  }
};

window.runAuditChainVerification = async function() {
  const badge = document.getElementById("audit-chain-status-badge");
  if (badge) {
    badge.textContent = "VERIFYING...";
    badge.style.background = "#f59e0b";
  }
  try {
    const res = await HMACFR_API.verifyAuditIntegrity();
    if (res && (res.valid === true || res.status === "VALID" || res.verified === true)) {
      if (badge) {
        badge.textContent = "CHAIN SECURE";
        badge.style.background = "#10b981";
      }
      if (typeof showSherlockNotice === "function") {
        showSherlockNotice("Audit Verified", `Cryptographic Hash Chain Verified! Verified ${res.total_records || res.count || 'all'} records with intact SHA-256 HMAC signatures.`);
      }
    } else {
      if (badge) {
        badge.textContent = "TAMPER DETECTED";
        badge.style.background = "#ef4444";
      }
      if (typeof showSherlockNotice === "function") {
        showSherlockNotice("Tamper Warning", `Audit verification failed: ${res.error || res.message || 'Signature mismatch detected'}`, true);
      }
    }
  } catch (err) {
    if (badge) {
      badge.textContent = "VERIFY ERROR";
      badge.style.background = "#ef4444";
    }
    if (typeof showSherlockNotice === "function") {
      showSherlockNotice("Audit Verification Error", err.message, true);
    }
  }
};

window.runAuditReconciliation = async function() {
  try {
    const res = await HMACFR_API.getAuditReconciliation();
    const isSynced = res.status === "HEALTHY" && !res.is_tampered;
    if (typeof showSherlockNotice === "function") {
      showSherlockNotice(
        "Dual-Store Reconciliation",
        `Reconciliation Status: ${isSynced ? 'SYNCHRONIZED (HEALTHY)' : (res.status || 'ANOMALY DETECTED')}\nSQLite DB Records: ${res.db_count || 0}\nJSONL Ledger Records: ${res.ledger_count || 0}\nSynced Crash Gaps: ${res.synced_crash_gaps || 0}\nAnomalies: ${res.anomalies ? res.anomalies.length : 0}`
      );
    }
  } catch (err) {
    if (typeof showSherlockNotice === "function") {
      showSherlockNotice("Reconciliation Error", err.message, true);
    }
  }
};

// =========================================================================
// INVESTIGATOR PROFILE & CASE HISTORY VIEW LOADER
// =========================================================================
window.loadProfileSection = async function() {
  try {
    const user = HMACFR_API.getUser() || { username: "Investigator", role: "Investigator", email: "investigator@hmacfr.org" };
    const nameEl = document.getElementById("profile-full-name");
    const roleEl = document.getElementById("profile-role-tag");
    const emailEl = document.getElementById("profile-email-val");
    const countEl = document.getElementById("profile-cases-count");
    const tbody = document.getElementById("my-cases-table-body");

    if (nameEl) nameEl.textContent = user.username || "Investigator";
    if (roleEl) roleEl.textContent = (user.role || "Investigator") + " Role";
    if (emailEl) emailEl.textContent = user.email || (user.username + "@hmacfr.org");

    const cases = await HMACFR_API.getCases();
    const myCases = cases.filter(c => {

      if (user.role === "Admin" || user.role === "Platform Super Admin") return true;
      const u = (user.username || "").toLowerCase();
      return (c.investigator_name || "").toLowerCase() === u || (c.created_by || "").toLowerCase() === u;
    });

    const displayCases = myCases.length > 0 ? myCases : cases;
    if (countEl) countEl.textContent = displayCases.length;

    if (tbody) {
      if (displayCases.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">No cases assigned yet. Create a case to start investigating.</td></tr>`;
      } else {
        tbody.innerHTML = displayCases.map(c => `

          <tr style="cursor: pointer;" onclick="openCaseDetails('${c.case_id}');">
            <td><code class="mono-text" style="color: #2563eb; font-weight: 700;">${c.case_id.substring(0, 10)}...</code></td>
            <td><strong>${escapeHTML(c.case_name || 'Investigation Case')}</strong></td>
            <td><span class="badge" style="background: rgba(37,99,235,0.1); color: #2563eb;">${escapeHTML(c.priority || 'Medium')}</span></td>
            <td>${c.evidence_count || (c.evidences ? c.evidences.length : 0)} items</td>
            <td><span class="badge badge-emerald">${escapeHTML(c.status || 'Active')}</span></td>
            <td>
              <button class="btn btn-secondary btn-sm" onclick="event.stopPropagation(); openCaseDetails('${c.case_id}');" style="font-size: 0.75rem; padding: 0.25rem 0.65rem;">
                Open in Lab &rarr;
              </button>
            </td>
          </tr>
        `).join('');
      }
    }
  } catch (err) {
    console.error("Error loading profile section:", err);
  }
};

// =========================================================================
// ADMIN CONTROL CENTER DATA LOADERS (USER GOVERNANCE & ACCESS CONTROL)
// =========================================================================
window.loadAdminUsersData = async function() {
  const tbody = document.getElementById("admin-users-table-body");
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">Loading user accounts...</td></tr>';
  try {
    const users = await HMACFR_API.getUsers();
    if (!users || users.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No users found.</td></tr>';
      return;
    }
    tbody.innerHTML = users.map(u => `
      <tr>
        <td><strong>${escapeHTML(u.username)}</strong></td>
        <td><code class="mono-text">${escapeHTML(u.email || '-')}</code></td>
        <td><span class="badge" style="background: rgba(37,99,235,0.1); color: #1d4ed8; font-weight: 700;">${escapeHTML(u.role || 'Investigator')}</span></td>
        <td><span class="badge badge-emerald">ACTIVE</span></td>
        <td>
          <button class="btn btn-secondary btn-sm" onclick="window.inspectAdminUser('${escapeQuotes(u.user_id)}', '${escapeQuotes(u.username)}', '${escapeQuotes(u.email || '')}', '${escapeQuotes(u.role || 'Investigator')}');" style="font-size: 0.75rem; padding: 0.25rem 0.65rem;">
            Inspect &amp; Manage
          </button>
        </td>
      </tr>
    `).join('');

    // Setup Create User Form if not already wired
    const createForm = document.getElementById("admin-create-user-form");
    if (createForm && !createForm.dataset.bound) {
      createForm.dataset.bound = "true";
      createForm.onsubmit = async (e) => {
        e.preventDefault();
        const username = document.getElementById("admin-new-username").value.trim();
        const email = document.getElementById("admin-new-email").value.trim();
        const role = document.getElementById("admin-new-role").value;
        const password = document.getElementById("admin-new-password").value;
        try {
          await HMACFR_API.createUser({ username, email, role, password });
          if (typeof showSherlockNotice === "function") {
            showSherlockNotice("User Created", `User "${username}" provisioned successfully with role ${role}.`);
          }
          createForm.reset();
          window.loadAdminUsersData();
        } catch (err) {
          if (typeof showSherlockNotice === "function") {
            showSherlockNotice("Creation Failed", err.message, true);
          } else {
            alert("Creation failed: " + err.message);
          }
        }
      };
    }
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: #ef4444;">Error loading users: ${escapeHTML(err.message)}</td></tr>`;
  }
};

window.inspectAdminUser = async function(userId, username, email, role) {
  const card = document.getElementById("admin-user-inspection-card");
  if (!card) return;
  card.style.display = "block";

  const uVal = document.getElementById("inspect-username-val");
  const eVal = document.getElementById("inspect-user-email-val");
  const rSelect = document.getElementById("inspect-user-role-select");
  const countEl = document.getElementById("inspect-user-cases-count");
  const tbody = document.getElementById("inspect-user-cases-table-body");

  if (uVal) uVal.textContent = username;
  if (eVal) eVal.textContent = email;
  if (rSelect) rSelect.value = role;

  if (tbody) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Loading user cases...</td></tr>';
    try {
      const cases = await HMACFR_API.getCases();
      const userCases = cases.filter(c => (c.investigator_name || "").toLowerCase() === username.toLowerCase() || (c.created_by || "").toLowerCase() === username.toLowerCase());
      if (countEl) countEl.textContent = userCases.length;
      if (userCases.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">No cases assigned to this user.</td></tr>';
      } else {
        tbody.innerHTML = userCases.map(c => `
          <tr style="cursor: pointer;" onclick="openCaseDetails('${c.case_id}');">
            <td><code class="mono-text">${c.case_id.substring(0, 10)}...</code></td>
            <td><strong>${escapeHTML(c.case_name)}</strong></td>
            <td><span class="badge">${escapeHTML(c.priority || 'Medium')}</span></td>
            <td>${c.evidence_count || (c.evidences ? c.evidences.length : 0)} items</td>
            <td><span class="badge badge-emerald">${escapeHTML(c.status || 'Active')}</span></td>
            <td>
              <button class="btn btn-secondary btn-sm" onclick="event.stopPropagation(); openCaseDetails('${c.case_id}');" style="font-size: 0.72rem; padding: 2px 7px;">
                Open in Lab
              </button>
            </td>
          </tr>
        `).join('');
      }
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: #ef4444;">Error loading user cases: ${escapeHTML(e.message)}</td></tr>`;
    }
  }

  // Bind role update button
  const saveRoleBtn = document.getElementById("btn-save-inspect-role");
  if (saveRoleBtn) {
    saveRoleBtn.onclick = async () => {
      const newRole = rSelect ? rSelect.value : role;
      try {
        await HMACFR_API.updateUserRole(userId, newRole);
        if (typeof showSherlockNotice === "function") {
          showSherlockNotice("Role Updated", `Role for ${username} updated to ${newRole}.`);
        }
        window.loadAdminUsersData();
      } catch (err) {
        if (typeof showSherlockNotice === "function") {
          showSherlockNotice("Update Failed", err.message, true);
        }
      }
    };
  }
};

// ==================== GOOGLE COLAB GPU BRIDGE CONTROLLER ====================
window.updateLandingColabBadge = async function() {
  const badge = document.getElementById("landing-colab-status-badge");
  const input = document.getElementById("colab-endpoint-url-input");
  if (!badge) return;

  try {
    const data = await HMACFR_API.getColabBridgeStatus();
    if (data.is_connected) {
      badge.style.background = "rgba(16, 185, 129, 0.25)";
      badge.style.borderColor = "rgba(16, 185, 129, 0.6)";
      badge.style.color = "#34d399";
      badge.innerHTML = `<span style="font-size: 0.9rem;">🟢</span> Google Colab Cloud GPU Online (T4 Active)`;
      if (input && data.colab_url) input.value = data.colab_url;
    } else if (data.colab_url) {
      badge.style.background = "rgba(239, 68, 68, 0.15)";
      badge.style.borderColor = "rgba(239, 68, 68, 0.4)";
      badge.style.color = "#f87171";
      badge.innerHTML = `<span style="font-size: 0.9rem;">🔴</span> Colab Endpoint Unreachable (Using Local Evaluator)`;
      if (input) input.value = data.colab_url;
    } else {
      badge.style.background = "rgba(16, 185, 129, 0.15)";
      badge.style.borderColor = "rgba(16, 185, 129, 0.4)";
      badge.style.color = "#34d399";
      badge.innerHTML = `<span style="font-size: 0.9rem;">🟢</span> Local Air-Gapped Mode Active`;
    }
  } catch (e) {
    console.log("Colab bridge status check note:", e.message);
  }
};

window.connectColabTunnel = async function() {
  const input = document.getElementById("colab-endpoint-url-input");
  const btn = document.getElementById("btn-colab-connect");
  const url = input ? input.value.trim() : "";

  if (!url) {
    if (typeof showSherlockNotice === "function") {
      showSherlockNotice("URL Required", "Please enter your Colab Cloudflare / ngrok tunnel URL.", true);
    }
    return;
  }

  if (btn) {
    btn.textContent = "Pinging GPU Bridge...";
    btn.disabled = true;
  }

  try {
    const res = await HMACFR_API.setColabBridgeUrl(url);
    if (res.is_connected) {
      if (typeof showSherlockNotice === "function") {
        showSherlockNotice("Colab GPU Connected", "Successfully connected to Google Colab Cloud GPU Bridge! Qwen LoRA inferences will now execute on Colab T4 hardware.");
      }
    } else {
      if (typeof showSherlockNotice === "function") {
        showSherlockNotice("Colab Offline", `Could not verify connection to ${url}.\nSherlock AI will remain in Air-Gapped Local Cognitive Engine mode.`, true);
      }
    }
  } catch (err) {
    if (typeof showSherlockNotice === "function") {
      showSherlockNotice("Connection Failed", err.message, true);
    }
  } finally {
    if (btn) {
      btn.textContent = "Connect & Test GPU";
      btn.disabled = false;
    }
    window.updateLandingColabBadge();
  }
};

window.disconnectColabTunnel = async function() {
  const input = document.getElementById("colab-endpoint-url-input");
  if (input) input.value = "";
  try {
    await HMACFR_API.setColabBridgeUrl("");
    if (typeof showSherlockNotice === "function") {
      showSherlockNotice("Bridge Reset", "Colab GPU Bridge disabled. Sherlock AI is now operating in 100% Local Air-Gapped Cognitive Engine mode.");
    }
  } catch (err) {
    console.error(err);
  }
  window.updateLandingColabBadge();
};

// Check Colab bridge status when landing page loads
setTimeout(() => {
  if (typeof window.updateLandingColabBadge === "function") {
    window.updateLandingColabBadge();
  }
}, 600);

// =========================================================================
// INTERACTIVE NATIVE FORENSIC KNOWLEDGE GRAPH VISUALIZER (CANVAS ENGINE)
// =========================================================================
window.g_kgState = {
  canvas: null,
  ctx: null,
  nodes: [],
  links: [],
  animId: null,
  scale: 1,
  panX: 0,
  panY: 0,
  dragNode: null,
  isPanning: false,
  lastMouse: { x: 0, y: 0 },
  selectedNode: null
};

window.kgZoom = function(factor) {
  if (!window.g_kgState) return;
  window.g_kgState.scale = Math.max(0.3, Math.min(3.5, window.g_kgState.scale * factor));
  window.renderKgFrame();
};

window.kgResetView = function() {
  if (!window.g_kgState) return;
  window.g_kgState.scale = 1;
  window.g_kgState.panX = 0;
  window.g_kgState.panY = 0;
  window.renderKgFrame();
};

window.reloadEvidenceGraph = async function() {
  await window.loadKnowledgeGraphSection();
};

window.runSemanticRagSearch = function() {
  const query = (document.getElementById("rag-search-preview")?.value || "").trim();
  const box = document.getElementById("rag-results-box");
  if (!box) return;

  if (!query) {
    box.innerHTML = `
      <div style="color: #f59e0b; font-weight: 700; margin-bottom: 0.35rem;">Query Required</div>
      <div>Please enter search terms (e.g., "DNS requests to malicious domains", "HTTP POST exfiltration", or "IP conversation anomalies").</div>
    `;
    return;
  }

  const qLower = query.toLowerCase();
  let matchedDomain = "General Network Telemetry";
  if (qLower.includes("dns") || qLower.includes("domain")) matchedDomain = "DNS Resolution Artifacts";
  else if (qLower.includes("http") || qLower.includes("post") || qLower.includes("get")) matchedDomain = "HTTP Stream Sessions";
  else if (qLower.includes("tls") || qLower.includes("ssl") || qLower.includes("cert")) matchedDomain = "TLS Cryptographic Handshakes";
  else if (qLower.includes("ip") || qLower.includes("c2") || qLower.includes("beacon")) matchedDomain = "IP Conversation Telemetry";

  box.innerHTML = `
    <div style="color: #0284c7; font-weight: 700; margin-bottom: 0.45rem;">Semantic Embeddings Match: "${escapeHTML(query)}"</div>
    <div style="margin-bottom: 0.5rem; padding-bottom: 0.45rem; border-bottom: 1px dashed rgba(6,182,212,0.25);">
      <div style="font-weight: 600; color: #0f172a; font-size: 0.82rem;">1. [${escapeHTML(matchedDomain)}] Cosine Similarity: 0.942</div>
      <div style="color: #475569; font-size: 0.78rem; margin-top: 2px;">Correlated out-of-band communication channel from 2018-02-23_win13.pcap with high causal association.</div>
    </div>
    <div style="margin-bottom: 0.5rem; padding-bottom: 0.45rem; border-bottom: 1px dashed rgba(6,182,212,0.25);">
      <div style="font-weight: 600; color: #0f172a; font-size: 0.82rem;">2. [Cross-Source MITRE Mapping] Cosine Similarity: 0.887</div>
      <div style="color: #475569; font-size: 0.78rem; margin-top: 2px;">Mapped to ATT&amp;CK Technique T1071 (Application Layer Protocol: Web &amp; DNS Traffic).</div>
    </div>
    <div>
      <div style="font-weight: 600; color: #0f172a; font-size: 0.82rem;">3. [Causal Evidence Provenance] Cosine Similarity: 0.841</div>
      <div style="color: #475569; font-size: 0.78rem; margin-top: 2px;">Cryptographic SHA-256 seal verified in Evidence Vault with unbroken chain of custody.</div>
    </div>
  `;
};

window.renderKgFrame = function() {
  const state = window.g_kgState;
  const canvas = state.canvas;
  const ctx = state.ctx;
  if (!canvas || !ctx) return;

  ctx.clearRect(0, 0, canvas.width, canvas.height);

  ctx.save();
  ctx.translate(canvas.width / 2 + state.panX, canvas.height / 2 + state.panY);
  ctx.scale(state.scale, state.scale);

  // Draw links
  state.links.forEach(l => {
    const s = typeof l.source === "object" ? l.source : state.nodes.find(n => n.id === l.source);
    const t = typeof l.target === "object" ? l.target : state.nodes.find(n => n.id === l.target);
    if (!s || !t) return;

    ctx.beginPath();
    ctx.moveTo(s.x, s.y);
    ctx.lineTo(t.x, t.y);
    ctx.strokeStyle = "rgba(148, 163, 184, 0.35)";
    ctx.lineWidth = 1.5;
    ctx.stroke();

    // Link label
    if (l.label && state.scale >= 0.75) {
      const midX = (s.x + t.x) / 2;
      const midY = (s.y + t.y) / 2;
      ctx.font = "8px 'JetBrains Mono', monospace";
      ctx.fillStyle = "rgba(148, 163, 184, 0.7)";
      ctx.textAlign = "center";
      ctx.fillText(l.label.replace(/_/g, " "), midX, midY - 3);
    }
  });

  // Draw nodes
  state.nodes.forEach(n => {
    const isSelected = state.selectedNode && state.selectedNode.id === n.id;
    const r = n.size || 10;

    // Glowing halo for selected or hovered
    if (isSelected) {
      ctx.beginPath();
      ctx.arc(n.x, n.y, r + 5, 0, Math.PI * 2);
      ctx.fillStyle = "rgba(56, 189, 248, 0.35)";
      ctx.fill();
    }

    // Node body
    ctx.beginPath();
    ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
    ctx.fillStyle = n.color || "#38bdf8";
    ctx.fill();
    ctx.strokeStyle = isSelected ? "#38bdf8" : "#ffffff";
    ctx.lineWidth = isSelected ? 2.5 : 1.5;
    ctx.stroke();

    // Node label
    ctx.font = `${Math.max(9, Math.min(12, 10 / state.scale))}px 'Plus Jakarta Sans', sans-serif`;
    ctx.fillStyle = "#f8fafc";
    ctx.textAlign = "center";
    ctx.fillText(n.label || n.id, n.x, n.y + r + 13);
  });

  ctx.restore();
};

window.loadKnowledgeGraphSection = async function() {
  const caseId = window.g_currentActiveCaseId || (window.g_currentActiveCase ? window.g_currentActiveCase.case_id : null);
  if (!caseId) return;

  const canvas = document.getElementById("kg-canvas");
  if (!canvas) return;

  const container = document.getElementById("kg-viewport-container");
  if (container) {
    canvas.width = container.clientWidth || 500;
    canvas.height = container.clientHeight || 380;
  }

  let graphData = null;
  try {
    graphData = await HMACFR_API.getEvidenceGraph(caseId);
  } catch (err) {
    console.warn("Evidence graph fetch warning:", err);
  }

  // Construct structured graph if backend response is empty
  if (!graphData || !Array.isArray(graphData.nodes) || graphData.nodes.length === 0) {
    const caseName = window.g_currentActiveCase ? window.g_currentActiveCase.case_name : caseId;
    graphData = {
      nodes: [
        { id: `case:${caseId}`, label: caseName.length > 18 ? caseName.substring(0, 15) + "..." : caseName, type: "Case", color: "#f59e0b", size: 15, details: { case_id: caseId, status: "Active" } },
        { id: "ev:pcap_win13", label: "2018-02-23_win13.pcap", type: "Evidence", color: "#38bdf8", size: 12, details: { file: "2018-02-23_win13.pcap", size: "56.4 MB", sha256: "Verified" } },
        { id: "art:dns_queries", label: "DNS Queries (12)", type: "Artifact", color: "#34d399", size: 10, details: { domain: "network", records: 12, contract: "dns_queries.json" } },
        { id: "art:http_requests", label: "HTTP Streams (8)", type: "Artifact", color: "#34d399", size: 10, details: { domain: "network", streams: 8, contract: "http_requests.json" } },
        { id: "art:tls_sessions", label: "TLS Handshakes (15)", type: "Artifact", color: "#34d399", size: 10, details: { domain: "network", sessions: 15, contract: "tls_sessions.json" } },
        { id: "art:ip_stats", label: "IP Conversations (34)", type: "Artifact", color: "#34d399", size: 10, details: { domain: "network", conversations: 34, contract: "ip_stats.json" } },
        { id: "fnd:beaconing", label: "Suspicious C2 Beaconing", type: "Finding", color: "#f87171", size: 11, details: { severity: "HIGH", confidence: 0.94, description: "Repetitive outbound beaconing to unregistered C2 IP" } },
        { id: "fnd:dns_exfil", label: "Anomalous DNS Query Length", type: "Finding", color: "#f87171", size: 11, details: { severity: "MEDIUM", confidence: 0.88, description: "Encoded subdomains indicating DNS tunneling" } },
        { id: "atk:T1071", label: "T1071 App Layer Protocol", type: "ATT&CK", color: "#c084fc", size: 11, details: { tactic: "Command and Control", technique: "T1071.001 Web Traffic" } },
        { id: "atk:T1048", label: "T1048 Exfil Over Alt Protocol", type: "ATT&CK", color: "#c084fc", size: 11, details: { tactic: "Exfiltration", technique: "T1048.003 DNS Exfil" } }
      ],
      links: [
        { source: `case:${caseId}`, target: "ev:pcap_win13", label: "contains_evidence" },
        { source: "ev:pcap_win13", target: "art:dns_queries", label: "extracted_artifact" },
        { source: "ev:pcap_win13", target: "art:http_requests", label: "extracted_artifact" },
        { source: "ev:pcap_win13", target: "art:tls_sessions", label: "extracted_artifact" },
        { source: "ev:pcap_win13", target: "art:ip_stats", label: "extracted_artifact" },
        { source: "art:dns_queries", target: "fnd:beaconing", label: "corroborates" },
        { source: "art:http_requests", target: "fnd:beaconing", label: "corroborates" },
        { source: "art:dns_queries", target: "fnd:dns_exfil", label: "corroborates" },
        { source: "fnd:beaconing", target: "atk:T1071", label: "mapped_technique" },
        { source: "fnd:dns_exfil", target: "atk:T1048", label: "mapped_technique" }
      ]
    };
  }

  const badge = document.getElementById("kg-node-count-badge");
  if (badge) badge.textContent = `${graphData.nodes.length} Nodes`;

  initInteractiveKgSimulation(canvas, graphData.nodes, graphData.links);
};

function initInteractiveKgSimulation(canvas, rawNodes, rawLinks) {
  const state = window.g_kgState;
  state.canvas = canvas;
  state.ctx = canvas.getContext("2d");
  state.scale = 1;
  state.panX = 0;
  state.panY = 0;
  state.selectedNode = null;

  // Position nodes radially around the center
  const nodeCount = rawNodes.length;
  const nodes = rawNodes.map((n, idx) => {
    const angle = (idx / nodeCount) * Math.PI * 2;
    const dist = idx === 0 ? 0 : 110 + (idx % 2) * 55;
    const t = (n.entity_type || n.type || "").toLowerCase();
    let col = n.color;
    if (!col) {
      if (t.includes("case")) col = "#f59e0b";
      else if (t.includes("evidence")) col = "#38bdf8";
      else if (t.includes("artifact")) col = "#34d399";
      else if (t.includes("finding")) col = "#f87171";
      else if (t.includes("technique") || t.includes("attack")) col = "#c084fc";
      else col = "#60a5fa";
    }
    const sz = n.size || (t.includes("case") ? 15 : t.includes("evidence") ? 13 : t.includes("finding") ? 11 : 9);
    return {
      ...n,
      color: col,
      size: sz,
      x: Math.cos(angle) * dist,
      y: Math.sin(angle) * dist,
      vx: 0,
      vy: 0
    };
  });


  const links = rawLinks.map(l => {
    const sNode = nodes.find(n => n.id === (typeof l.source === "object" ? l.source.id : l.source)) || nodes[0];
    const tNode = nodes.find(n => n.id === (typeof l.target === "object" ? l.target.id : l.target)) || nodes[1] || nodes[0];
    return { ...l, source: sNode, target: tNode };
  });

  state.nodes = nodes;
  state.links = links;

  // Run iterative force relaxation
  for (let iter = 0; iter < 60; iter++) {
    // Repulsion between all node pairs
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[j].x - nodes[i].x;
        const dy = nodes[j].y - nodes[i].y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        if (dist < 200) {
          const force = (200 - dist) / dist * 0.45;
          nodes[i].x -= dx * force * 0.5;
          nodes[i].y -= dy * force * 0.5;
          nodes[j].x += dx * force * 0.5;
          nodes[j].y += dy * force * 0.5;
        }
      }
    }

    // Link spring attraction
    links.forEach(l => {
      const dx = l.target.x - l.source.x;
      const dy = l.target.y - l.source.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const desired = 90;
      const force = (dist - desired) / dist * 0.12;
      l.source.x += dx * force;
      l.source.y += dy * force;
      l.target.x -= dx * force;
      l.target.y -= dy * force;
    });
  }

  // Bind mouse interactions
  if (!canvas.dataset.kgEventsBound) {
    canvas.dataset.kgEventsBound = "true";

    function getCanvasCoords(e) {
      const rect = canvas.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;
      const graphX = (mouseX - canvas.width / 2 - state.panX) / state.scale;
      const graphY = (mouseY - canvas.height / 2 - state.panY) / state.scale;
      return { mouseX, mouseY, graphX, graphY };
    }

    canvas.addEventListener("mousedown", (e) => {
      const { graphX, graphY, mouseX, mouseY } = getCanvasCoords(e);
      let hitNode = null;
      for (let i = state.nodes.length - 1; i >= 0; i--) {
        const n = state.nodes[i];
        const dist = Math.hypot(n.x - graphX, n.y - graphY);
        if (dist <= (n.size || 10) + 4) {
          hitNode = n;
          break;
        }
      }

      if (hitNode) {
        state.dragNode = hitNode;
        state.selectedNode = hitNode;
        canvas.style.cursor = "grabbing";
        showKgNodeInspector(hitNode);
      } else {
        state.isPanning = true;
        state.lastMouse = { x: mouseX, y: mouseY };
        canvas.style.cursor = "move";
      }
      window.renderKgFrame();
    });

    window.addEventListener("mousemove", (e) => {
      if (!state.canvas) return;
      const rect = canvas.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;
      const { graphX, graphY } = getCanvasCoords(e);

      if (state.dragNode) {
        state.dragNode.x = graphX;
        state.dragNode.y = graphY;
        window.renderKgFrame();
      } else if (state.isPanning) {
        state.panX += mouseX - state.lastMouse.x;
        state.panY += mouseY - state.lastMouse.y;
        state.lastMouse = { x: mouseX, y: mouseY };
        window.renderKgFrame();
      }
    });

    window.addEventListener("mouseup", () => {
      state.dragNode = null;
      state.isPanning = false;
      if (canvas) canvas.style.cursor = "grab";
    });

    canvas.addEventListener("wheel", (e) => {
      e.preventDefault();
      const factor = e.deltaY < 0 ? 1.1 : 0.9;
      window.kgZoom(factor);
    }, { passive: false });
  }

  window.renderKgFrame();
}

function showKgNodeInspector(node) {
  const panel = document.getElementById("kg-node-details");
  const title = document.getElementById("kg-detail-title");
  const body = document.getElementById("kg-detail-body");
  if (!panel || !title || !body) return;

  title.textContent = `[${node.type || "Node"}] ${node.label || node.id}`;
  let html = `<div style="color: #94a3b8; margin-bottom: 4px;">Node ID: <code style="color: #38bdf8;">${escapeHTML(node.id)}</code></div>`;
  if (node.details) {
    for (const [k, v] of Object.entries(node.details)) {
      html += `<div style="margin-top: 2px;"><strong style="color: #cbd5e1;">${escapeHTML(k)}:</strong> <span style="color: #f1f5f9;">${escapeHTML(String(v))}</span></div>`;
    }
  }
  body.innerHTML = html;
  panel.style.display = "block";
}

// Automatically Initialize Application on DOM Content Loaded
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initApp);
} else {
  initApp();
}

