document.addEventListener("DOMContentLoaded", () => {
  initApp();
});

// Global Section Switcher for Sidebar and Top Subnav Navigation
window.switchWorkspaceSection = function(targetId) {
  if (!targetId) return;

  if (targetId === "sec-create-modal-trigger") {
    if (typeof openCreateCaseModal === "function") openCreateCaseModal();
    return;
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

  // Hide all workspace sections and show the target section with !important
  const sections = document.querySelectorAll(".workspace-section");
  sections.forEach(sec => {
    if (sec.id === targetId) {
      sec.classList.add("active");
      sec.style.setProperty("display", "block", "important");
    } else {
      sec.classList.remove("active");
      sec.style.setProperty("display", "none", "important");
    }
  });

  // Sync top subnav active underline tab
  if (window.syncTopSubnavTab) {
    if (targetId === "sec-create-case") {
      window.syncTopSubnavTab("sec-cases");
    } else {
      window.syncTopSubnavTab(targetId);
    }
  }

  // Load section-specific data
  if (targetId === "sec-home") {
    if (typeof loadHomeSection === "function") loadHomeSection();
  } else if (targetId === "sec-cases") {
    if (typeof window.loadCasesSection === "function") window.loadCasesSection();
  } else if (targetId === "sec-evidence-vault") {
    if (typeof loadEvidenceVaultSection === "function") loadEvidenceVaultSection();
  } else if (targetId === "sec-preservation") {
    if (typeof loadPreservationSection === "function") loadPreservationSection();
  } else if (targetId === "sec-custody") {
    if (typeof populateCustodyEvidenceSelects === "function") populateCustodyEvidenceSelects();
  } else if (targetId === "sec-analysis") {
    if (typeof loadAnalysisSection === "function") loadAnalysisSection();
  } else if (targetId === "sec-profile") {
    if (typeof loadProfileSection === "function") loadProfileSection();
  } else if (targetId === "sec-admin-users") {
    if (typeof loadAdminUsersData === "function") loadAdminUsersData();
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
  setupEventListeners();
  initSherlockEmblemParallax();
  initLandingScrollspy();

  const token = HMACFR_API.getToken();
  const user = HMACFR_API.getUser();

  if (token || user) {
    const sessionUser = user || { username: "investigator1", role: "Investigator", clearance_level: 3 };
    if (!user) HMACFR_API.setUser(sessionUser);
    if (!token) HMACFR_API.setToken("dev_session_token");

    showWorkspace(sessionUser);
  } else {
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

  const isAdmin = user && (user.role === "Admin" || user.role === "ADMIN" || (user.clearance_level && user.clearance_level >= 5));
  const navTabs = document.querySelectorAll(".nav-tab");
  const sections = document.querySelectorAll(".workspace-section");

  if (isAdmin) {
    // Admin has access to ALL investigation tabs + Admin Users Governance tab
    navTabs.forEach(tab => {
      tab.style.display = "flex";
    });
  } else {
    // Investigator has access to all investigation tabs, while Admin Users tab is hidden
    navTabs.forEach(tab => {
      if (tab.classList.contains("nav-tab-admin")) {
        tab.style.display = "none";
        tab.classList.remove("active");
      } else {
        tab.style.display = "flex";
      }
    });
  }


  // Set default active view tab to Home Executive Dashboard
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
    const cases = g_allCases.length > 0 ? g_allCases : await HMACFR_API.getCases();
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
          row.className = "timeline-case-card-row";
          const evCount = g_caseEvidencesMap[c.case_id] || 0;
          const priorityLower = (c.priority || 'medium').toLowerCase();

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

          const stages = ["Acquire", "Extract", "Correlate", "Reconstruct", "AI Analysis", "Review"];
          const stepperDotsHTML = stages.map((stg, idx) => `
            <div class="stepper-dot-item ${idx <= activeStageIdx ? 'active' : ''}">
              <span class="stepper-dot"></span>
              <span class="stepper-label">${stg}</span>
            </div>
          `).join('');

          row.innerHTML = `
            <span class="timeline-node-dot"></span>
            
            <!-- Col 1: Case Title (top) & Case ID (bottom) -->
            <div class="case-card-info-col">
              <div class="case-card-id" onclick="openCaseDetails('${c.case_id}')" title="Inspect Case ${escapeHTML(c.case_name || c.case_id)}">${escapeHTML(c.case_name || 'Investigation Case')}</div>
              <div class="case-card-title">${escapeHTML(c.case_id.substring(0, 8))}...</div>
            </div>

            <!-- Col 2: Priority & Dynamic Evidence Count -->
            <div class="case-card-priority-col">
              <span class="case-card-priority-tag ${priorityLower}">${escapeHTML(c.priority || 'MEDIUM')}</span>
              <span class="case-card-artifacts-count">${evCount} evidence</span>
            </div>

            <!-- Col 3: Horizontal 6-Stage Stepper -->
            <div class="case-card-stepper-col">
              <div class="stepper-horizontal-track">
                <div class="stepper-connecting-line"></div>
                <div class="stepper-dots-group">
                  ${stepperDotsHTML}
                </div>
              </div>
            </div>

            <!-- Col 4: Status & Progress % -->
            <div class="case-card-status-col">
              <span class="case-card-status-text ${c.status === 'PENDING_DELETION' ? 'pending' : ''}">${c.status === 'PENDING_DELETION' ? 'PENDING' : 'ACTIVE'}</span>
              <span class="case-card-percent-text">${percentStr}</span>
            </div>

            <!-- Col 5: Direct Red Delete Trash Action Icon -->
            <div style="display: flex; justify-content: flex-end;">
              <button type="button" class="btn-card-action-delete" style="background: transparent; border: none; cursor: pointer; padding: 0.35rem; display: flex; align-items: center; justify-content: center; transition: opacity 0.15s ease;" onmouseover="this.style.opacity='0.75';" onmouseout="this.style.opacity='1.0';" title="Delete Case">
                <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="#dc2626" stroke-width="2" style="pointer-events: none;"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
              </button>
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
    const cases = await HMACFR_API.getCases();
    g_allCases = cases;
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
    card.className = "active-case-dashboard-card";
    const evCount = g_caseEvidencesMap[c.case_id] || 0;
    
    const priorityUpper = (c.priority || 'MEDIUM').toUpperCase();
    let accentColor = "#2563eb";
    if (priorityUpper === "CRITICAL") accentColor = "#dc2626";
    else if (priorityUpper === "HIGH") accentColor = "#d97706";
    else if (priorityUpper === "LOW") accentColor = "#16a34a";

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

    const stages = ["Acquire", "Extract", "Correlate", "Reconstruct", "AI Analysis", "Review"];
    const stepperDotsHTML = stages.map((stg, idx) => `
      <div class="stepper-dot-item ${idx <= activeStageIdx ? 'active' : ''}">
        <span class="stepper-dot"></span>
        <span class="stepper-label">${stg}</span>
      </div>
    `).join('');

    card.innerHTML = `
      <div class="case-card-accent-bar" style="background: ${accentColor};"></div>

      <!-- Col 1: Case ID & Title -->
      <div style="display: flex; flex-direction: column; overflow: hidden; border-right: 1px solid #f1f5f9; padding-right: 0.75rem;">
        <span style="font-size: 0.62rem; font-weight: 700; color: #94a3b8; letter-spacing: 0.08em;">CASE ID</span>
        <span style="font-size: 0.9rem; font-weight: 800; color: #0f172a; cursor: pointer; font-family: 'Plus Jakarta Sans', sans-serif; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" onclick="openCaseDetails('${c.case_id}')" title="Inspect ${safeId}">${safeName}</span>
        <span style="font-size: 0.75rem; color: #64748b;">${safeId.substring(0, 8)}...</span>
      </div>

      <!-- Col 2: Lead & Created -->
      <div style="display: flex; flex-direction: column; gap: 0.25rem; border-right: 1px solid #f1f5f9; padding-right: 0.75rem;">
        <div>
          <span style="font-size: 0.62rem; font-weight: 700; color: #94a3b8; letter-spacing: 0.08em; display: block;">LEAD</span>
          <div style="font-size: 0.78rem; color: #334155; font-weight: 600; display: flex; align-items: center; gap: 0.25rem; margin-top: 1px; white-space: nowrap;">
            <svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="#64748b" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
            <span>${safeLead}</span>
          </div>
        </div>
        <div>
          <span style="font-size: 0.62rem; font-weight: 700; color: #94a3b8; letter-spacing: 0.08em; display: block;">CREATED</span>
          <span style="font-size: 0.72rem; color: #64748b; white-space: nowrap;">25 Aug 2025</span>
        </div>
      </div>

      <!-- Col 3: Priority & Evidence -->
      <div style="display: flex; flex-direction: column; gap: 0.25rem; border-right: 1px solid #f1f5f9; padding-right: 0.75rem;">
        <div>
          <span style="font-size: 0.62rem; font-weight: 700; color: #94a3b8; letter-spacing: 0.08em; display: block;">PRIORITY</span>
          <span style="font-size: 0.72rem; font-weight: 800; color: ${accentColor}; text-transform: uppercase; white-space: nowrap;">● ${priorityUpper}</span>
        </div>
        <div>
          <span style="font-size: 0.62rem; font-weight: 700; color: #94a3b8; letter-spacing: 0.08em; display: block;">EVIDENCE</span>
          <div style="font-size: 0.78rem; color: #475569; font-weight: 600; display: flex; align-items: center; gap: 0.25rem; margin-top: 1px; white-space: nowrap;">
            <svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="#64748b" stroke-width="2"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>
            <span>${evCount} items</span>
          </div>
        </div>
      </div>

      <!-- Col 4: Investigation Stage Stepper -->
      <div style="border-right: 1px solid #f1f5f9; padding-right: 0.75rem; width: 100%;">
        <span style="font-size: 0.62rem; font-weight: 700; color: #94a3b8; letter-spacing: 0.08em; display: block; margin-bottom: 0.35rem;">INVESTIGATION STAGE</span>
        <div class="stepper-horizontal-track">
          <div class="stepper-connecting-line"></div>
          <div class="stepper-dots-group">
            ${stepperDotsHTML}
          </div>
        </div>
      </div>

      <!-- Col 5: Progress % -->
      <div style="border-right: 1px solid #f1f5f9; padding-right: 0.75rem;">
        <span style="font-size: 0.62rem; font-weight: 700; color: #94a3b8; letter-spacing: 0.08em; display: block;">PROGRESS</span>
        <span style="font-size: 0.88rem; font-weight: 800; color: #2563eb; white-space: nowrap;">${percentStr.split(' ')[0]}</span>
        <span style="font-size: 0.68rem; color: #64748b; display: block; white-space: nowrap;">reconstructed</span>
      </div>

      <!-- Col 6: Status & Actions -->
      <div style="display: flex; align-items: center; justify-content: space-between; gap: 0.35rem; width: 100%;">
        <div>
          <span style="font-size: 0.62rem; font-weight: 700; color: #94a3b8; letter-spacing: 0.08em; display: block;">STATUS</span>
          <span style="font-size: 0.8rem; font-weight: 800; color: ${cleanStatus === 'PENDING' ? '#d97706' : '#2563eb'}; letter-spacing: 0.05em; display: inline-block; border-bottom: 2px solid ${cleanStatus === 'PENDING' ? '#d97706' : '#2563eb'}; padding-bottom: 1px; white-space: nowrap;">${safeStatus}</span>
        </div>
        <div style="display: flex; align-items: center; gap: 0.25rem;">
          ${cleanStatus === 'PENDING' && (HMACFR_API.getUser() && (HMACFR_API.getUser().role === 'Admin' || HMACFR_API.getUser().role === 'ADMIN')) ? `
            <button type="button" onclick="window.adminResolveCaseDeletion('${c.case_id}', 'APPROVE', '${escapeQuotes(c.case_name)}', event);" style="background: transparent; border: none; cursor: pointer; padding: 0.25rem; color: #059669; display: flex; align-items: center; justify-content: center;" title="Approve Case Deletion (Purge)">
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="#059669" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
            </button>
            <button type="button" onclick="window.adminResolveCaseDeletion('${c.case_id}', 'REJECT', '${escapeQuotes(c.case_name)}', event);" style="background: transparent; border: none; cursor: pointer; padding: 0.25rem; color: #dc2626; display: flex; align-items: center; justify-content: center;" title="Reject Case Deletion (Restore Active)">
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="#dc2626" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            </button>
          ` : `
            <button type="button" class="btn-card-action-delete" onclick="window.adminPurgeCase('${c.case_id}', '${escapeQuotes(c.case_name)}', event);" style="background: transparent; border: none; cursor: pointer; padding: 0.35rem; display: flex; align-items: center; justify-content: center; transition: opacity 0.15s ease;" onmouseover="this.style.opacity='0.75';" onmouseout="this.style.opacity='1.0';" title="Delete Case">
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="#dc2626" stroke-width="2" style="pointer-events: none;"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
            </button>
          `}
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

window.escapeHTML = function(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};

function escapeQuotes(str) {
  if (!str) return "";
  return String(str)
    .replace(/\\/g, "\\\\")
    .replace(/'/g, "&#39;")
    .replace(/"/g, "&quot;")
    .replace(/\n/g, " ")
    .replace(/\r/g, " ");
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
}

function updateAnalysisStatusBadge(taskId, statusText) {
  const stageDesc = document.getElementById(`stage-desc-${taskId}`);
  if (stageDesc) stageDesc.textContent = `Analysis Stream ${statusText}`;
}

async function loadAnalysisSection() {
  try {
    const cases = await HMACFR_API.getCases();
    const select = document.getElementById("analysis-case-select");
    if (!select) return;

    const currentVal = select.value;
    select.innerHTML = '<option value="">-- Select Target Case --</option>';
    cases.forEach(c => {
      const opt = document.createElement("option");
      opt.value = c.case_id;
      opt.textContent = `${c.case_id} — ${c.case_name}`;
      if (c.case_id === currentVal) opt.selected = true;
      select.appendChild(opt);
    });
  } catch (err) {
    console.error(err);
  }
}

async function loadProfileSection() {
  const user = HMACFR_API.getUser() || { username: "Investigator", role: "Investigator" };

  const nameEl = document.getElementById("profile-full-name");
  if (nameEl) nameEl.textContent = user.username;

  const roleEl = document.getElementById("profile-role-tag");
  if (roleEl) roleEl.textContent = user.role || "Investigator Role";

  const emailEl = document.getElementById("profile-email-val");
  if (emailEl) emailEl.textContent = user.email || `${user.username.toLowerCase()}@hmacfr.org`;

  try {
    const cases = await HMACFR_API.getCases();
    const userCases = cases.filter(c => !user.username || c.investigator_name === user.username || user.role === "Admin");

    const casesCountEl = document.getElementById("profile-cases-count");
    if (casesCountEl) casesCountEl.textContent = userCases.length;

    const tbody = document.getElementById("my-cases-table-body");
    if (!tbody) return;

    if (userCases.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">No case history recorded for this investigator.</td></tr>`;
      return;
    }

    tbody.innerHTML = "";
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
          <button class="btn btn-secondary btn-sm" onclick="window.startAnalysisForCase('${c.case_id}', '${escapeQuotes(c.case_name)}')">
            Analyze
          </button>
          <button class="btn btn-secondary btn-sm btn-profile-delete-case" style="border-color: rgba(239,68,68,0.5); color: #f87171; margin-left: 0.35rem;" title="Permanently Purge Case & All Evidence Data">
            Delete
          </button>
        </td>
      `;

      const delBtn = tr.querySelector('.btn-profile-delete-case');
      if (delBtn) {
        const cId = c.case_id;
        const cName = c.case_name;
        delBtn.onclick = (e) => {
          e.stopPropagation();
          window.adminPurgeCase(cId, cName, e);
        };
      }

      tbody.appendChild(tr);
    });


  } catch (err) {
    console.error("Error loading profile case history:", err);
  }
}


let g_allVaultEvidence = [];

async function loadEvidenceVaultSection() {
  const tbody = document.getElementById("vault-repo-table-body");
  const countEl = document.getElementById("vault-repo-total-count");
  const caseSelect = document.getElementById("vault-repo-case-select");
  if (!tbody) return;

  tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 2rem;">Loading Evidence Vault Repository...</td></tr>`;

  try {
    // 1. Fetch cases to populate Case Filter Dropdown
    const cases = await HMACFR_API.getCases();
    const casesMap = {};
    if (caseSelect) {
      const currentCase = caseSelect.value;
      caseSelect.innerHTML = '<option value="">-- All Investigation Cases --</option>';
      cases.forEach(c => {
        casesMap[c.case_id] = c.case_name;
        const opt = document.createElement("option");
        opt.value = c.case_id;
        opt.textContent = `${c.case_id.substring(0, 8)}... (${c.case_name})`;
        if (c.case_id === currentCase) opt.selected = true;
        caseSelect.appendChild(opt);
      });
    } else {
      cases.forEach(c => { casesMap[c.case_id] = c.case_name; });
    }

    // 2. Fetch all evidence items from backend
    g_allVaultEvidence = await HMACFR_API.getAllEvidence();
    if (countEl) countEl.textContent = g_allVaultEvidence.length;

    renderEvidenceVaultTable(casesMap);
  } catch (err) {
    console.error("Error loading evidence vault repository:", err);
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--accent-danger); padding: 2rem;">Error loading vault repository: ${err.message}</td></tr>`;
  }
}

function renderEvidenceVaultTable(casesMap = {}) {
  const tbody = document.getElementById("vault-repo-table-body");
  const searchInput = document.getElementById("vault-repo-search-input");
  const caseSelect = document.getElementById("vault-repo-case-select");
  const catSelect = document.getElementById("vault-repo-category-select");

  if (!tbody) return;

  const query = searchInput ? searchInput.value.trim().toLowerCase() : "";
  const selectedCase = caseSelect ? caseSelect.value : "";
  const selectedCat = catSelect ? catSelect.value : "ALL";

  let filtered = g_allVaultEvidence.filter(ev => {
    let matchQuery = true;
    if (query) {
      matchQuery = (
        (ev.original_filename && ev.original_filename.toLowerCase().includes(query)) ||
        (ev.case_id && ev.case_id.toLowerCase().includes(query)) ||
        (ev.category && ev.category.toLowerCase().includes(query)) ||
        (ev.file_hash && ev.file_hash.toLowerCase().includes(query))
      );
    }

    const matchCase = !selectedCase || (ev.case_id === selectedCase);
    const matchCat = (selectedCat === "ALL") || (ev.category && ev.category.toLowerCase() === selectedCat.toLowerCase());

    return matchQuery && matchCase && matchCat;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8">
          <div class="empty-state" style="padding: 2rem;">
            <div class="empty-state-title">No Matching Evidence Artifacts</div>
            <div class="empty-state-subtitle">No digital evidence artifacts match the current search or filter criteria.</div>
          </div>
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = "";
  filtered.forEach(ev => {
    const tr = document.createElement("tr");

    // Format file size
    let formattedSize = "0 B";
    if (ev.file_size) {
      const bytes = ev.file_size;
      if (bytes >= 1073741824) formattedSize = (bytes / 1073741824).toFixed(2) + " GB";
      else if (bytes >= 1048576) formattedSize = (bytes / 1048576).toFixed(2) + " MB";
      else if (bytes >= 1024) formattedSize = (bytes / 1024).toFixed(2) + " KB";
      else formattedSize = bytes + " B";
    }

    // Format Date Uploaded
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
    const caseNameStr = casesMap[ev.case_id] ? `${casesMap[ev.case_id]}` : "Case Record";

    const hashSnippet = ev.file_hash
      ? `<code class="mono-text" title="${ev.file_hash}">${ev.file_hash.substring(0, 14)}...</code>`
      : `<span class="badge badge-amber">Pending</span>`;

    const isPreserved = ev.status === "READY_FOR_PROCESSING" || ev.status === "Vaulted" || ev.status === "Preserved";
    const statusBadge = isPreserved
      ? `<span class="badge badge-emerald">Preserved &amp; Encrypted</span>`
      : `<span class="badge badge-cyan">Uploaded (${ev.status || 'Active'})</span>`;

    tr.innerHTML = `
      <td>
        <div class="mono-text" style="font-size: 0.75rem; font-weight: 700; color: var(--accent-emerald-light);">${ev.case_id ? ev.case_id.substring(0, 8) + '...' : 'Unassigned'}</div>
        <div style="font-size: 0.78rem; color: #fff; font-weight: 600;">${caseNameStr}</div>
      </td>
      <td><strong>${ev.original_filename}</strong></td>
      <td><span class="badge badge-indigo">${catText}</span></td>
      <td><code class="mono-text">${formattedSize}</code></td>
      <td>${hashSnippet}</td>
      <td style="font-size: 0.8rem; color: var(--text-secondary);">${uploadDateStr}</td>
      <td>${statusBadge}</td>
      <td style="white-space: nowrap;">
        <button class="btn btn-secondary btn-sm" onclick="window.inspectEvidenceVaultItem('${ev.evidence_id}', '${escapeQuotes(ev.original_filename)}', '${ev.case_id}')" style="font-size: 0.75rem; padding: 0.25rem 0.5rem;" title="Run Integrity Audit on Evidence Item">
          Audit Item
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

window.inspectEvidenceVaultItem = function(evidenceId, filename, caseId) {
  if (caseId) window.g_selectedSidebarCaseId = caseId;
  window.g_currentSelectedAuditEvidenceId = evidenceId;

  if (window.switchWorkspaceSection) {
    window.switchWorkspaceSection("sec-audit");
  }

  setTimeout(() => {
    const auditCaseSelect = document.getElementById("audit-case-select");
    if (auditCaseSelect && caseId) {
      auditCaseSelect.value = caseId;
    }
    const btn = document.getElementById("btn-audit-case");
    if (btn) btn.click();
  }, 150);
};


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

// Automatically Initialize Application on DOM Content Loaded
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initApp);
} else {
  initApp();
}
