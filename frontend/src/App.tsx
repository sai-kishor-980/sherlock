import { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { ThreeBackground } from "./components/ThreeBackground";
import { LandingNavbar } from "./components/LandingNavbar";
import { LandingPage } from "./components/LandingPage";
import { LoginPage } from "./components/LoginPage";
import { WorkspaceHeader, type WorkspaceTab } from "./components/WorkspaceHeader";
import { WorkspaceMain } from "./components/WorkspaceMain";
import { ForensicLabWorkspace, type LabWorkstationTab } from "./components/ForensicLabWorkspace";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { AISettingsModal } from "./components/AISettingsModal";
import { CreateCaseModal } from "./components/CreateCaseModal";
import { api } from "./services/api";
import type { Case, Evidence, DomainFinding, SISState, InferenceTierStatus } from "./types/forensic";

export type ViewMode = "landing" | "login" | "workspace";

export function App() {
  const navigate = useNavigate();
  const location = useLocation();

  const [viewMode, setViewMode] = useState<ViewMode>("landing");
  const [activeTab, setActiveTab] = useState<WorkspaceTab>("home");
  const [activeLabTab, setActiveLabTab] = useState<LabWorkstationTab>("evidence");
  const [cases, setCases] = useState<Case[]>([]);
  const [activeCase, setActiveCase] = useState<Case | null>(null);
  const [inLabMode, setInLabMode] = useState(false);
  const [activeLabCase, setActiveLabCase] = useState<Case | null>(null);
  const [inferenceStatus, setInferenceStatus] = useState<InferenceTierStatus | null>(null);
  const [user, setUser] = useState<any>(api.getUser() || { username: "investigator1", role: "Investigator" });

  // Workspace case assets state
  const [evidenceList, setEvidenceList] = useState<Evidence[]>([]);
  const [manifest, setManifest] = useState<any>(null);
  const [findings, setFindings] = useState<DomainFinding[]>([]);
  const [sisState, setSisState] = useState<SISState | null>(null);
  const [reportData, setReportData] = useState<any>(null);
  const [artifactsData, setArtifactsData] = useState<any>(null);

  // Loading & Modals
  const [isLoading, setIsLoading] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isAISettingsOpen, setIsAISettingsOpen] = useState(false);
  const [isCreateCaseOpen, setIsCreateCaseOpen] = useState(false);

  // Sync body classes with original theme
  useEffect(() => {
    if (viewMode === "workspace") {
      document.body.classList.remove("landing-active");
      document.body.classList.add("workspace-active");
      if (inLabMode) {
        document.body.classList.add("in-lab-mode");
      } else {
        document.body.classList.remove("in-lab-mode");
      }
    } else {
      document.body.classList.add("landing-active");
      document.body.classList.remove("workspace-active");
      document.body.classList.remove("in-lab-mode");
    }
  }, [viewMode, inLabMode]);

  // Load cases from backend
  const fetchCases = async () => {
    try {
      const data = await api.getCases();
      setCases(data);
      if (data.length > 0 && !activeCase) {
        setActiveCase(data[0]);
      }
      return data;
    } catch (err) {
      console.warn("Could not load cases:", err);
      return [];
    }
  };

  // Check 3-Tier Hardware Inference Status
  const fetchInferenceStatus = async () => {
    try {
      const data = await api.getInferenceStatus();
      setInferenceStatus(data);
    } catch (err) {
      console.warn("Could not probe inference status:", err);
    }
  };

  // Load specific case assets (vault, findings, sis, report, artifacts)
  const loadCaseData = async (caseId: string) => {
    setIsLoading(true);
    try {
      const [evList, mfest, fndgs, sis, rpt, arts] = await Promise.all([
        api.getEvidence(caseId).catch(() => []),
        api.getManifest(caseId).catch(() => null),
        api.getFindings(caseId).catch(() => []),
        api.getSIS(caseId).catch(() => null),
        api.getReport(caseId).catch(() => null),
        api.getArtifacts(caseId).catch(() => null)
      ]);
      setEvidenceList(evList);
      setManifest(mfest);
      setFindings(fndgs);
      setSisState(sis);
      setReportData(rpt);
      setArtifactsData(arts);
    } catch (err) {
      console.error("Error loading case data:", err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    const initSession = async () => {
      if (!api.getToken()) {
        try {
          await api.login("investigator1", "Investigator@2026");
          setUser(api.getUser() || { username: "investigator1", role: "Investigator" });
        } catch (e) {
          console.warn("Initial session check:", e);
        }
      }
      await fetchCases();
      await fetchInferenceStatus();
    };

    initSession();

    // Check inference tier every 15 seconds
    const interval = setInterval(fetchInferenceStatus, 15000);
    return () => clearInterval(interval);
  }, []);

  // Sync route with application state
  useEffect(() => {
    const path = location.pathname;

    // 1. Scoped Forensic Lab Route: /cases/:caseId/lab or /cases/:caseId/lab/:workstation
    const labMatch = path.match(/^\/cases\/([^/]+)\/lab(?:\/([^/]+))?/);
    if (labMatch) {
      const caseIdFromUrl = labMatch[1];
      const rawWs = labMatch[2] || "vault";
      const wsTab: LabWorkstationTab = (rawWs === "vault" ? "evidence" : rawWs) as LabWorkstationTab;

      setViewMode("workspace");
      setInLabMode(true);
      setActiveLabTab(wsTab);

      const foundCase = cases.find((c) => c.case_id === caseIdFromUrl);
      if (foundCase) {
        setActiveCase(foundCase);
        setActiveLabCase(foundCase);
      } else {
        setActiveLabCase((prev) =>
          prev?.case_id === caseIdFromUrl
            ? prev
            : ({
                case_id: caseIdFromUrl,
                case_name: `Case ${caseIdFromUrl}`,
                investigator_name: user?.username || "investigator1",
                priority: "High",
                status: "Active",
                created_at: new Date().toISOString()
              } as Case)
        );
      }
      return;
    }

    // 2. Cases List: /cases
    if (path === "/cases") {
      setViewMode("workspace");
      setInLabMode(false);
      setActiveTab("cases");
      return;
    }

    // 3. Command Center: /home
    if (path === "/home") {
      setViewMode("workspace");
      setInLabMode(false);
      setActiveTab("home");
      return;
    }

    // 4. Sign In: /login
    if (path === "/login") {
      setViewMode("login");
      return;
    }

    // 5. Landing / Root: / or /ui or /ui/
    if (path === "/" || path === "/ui" || path === "/ui/") {
      if (!api.getToken()) {
        setViewMode("landing");
      } else {
        setViewMode("workspace");
        setInLabMode(false);
        setActiveTab("home");
      }
    }
  }, [location.pathname, cases]);

  // Load case assets when activeCase or activeLabCase changes
  useEffect(() => {
    const targetId = activeLabCase?.case_id || activeCase?.case_id;
    if (targetId) {
      loadCaseData(targetId);
    }
  }, [activeLabCase?.case_id, activeCase?.case_id]);

  // User Actions
  const handleLoginSuccess = (loggedInUser: any) => {
    setUser(loggedInUser);
    setViewMode("workspace");
    setActiveTab("home");
    setInLabMode(false);
    navigate("/home");
    fetchCases();
  };

  const handleLogout = () => {
    api.logout();
    setUser(null);
    setViewMode("landing");
    setInLabMode(false);
    navigate("/");
  };

  const handleCreateCase = async (newCaseData: any) => {
    const created = await api.createCase(newCaseData);
    await fetchCases();
    setActiveCase(created);
    setActiveLabCase(created);
    setInLabMode(true);
    navigate(`/cases/${created.case_id}/lab/vault`);
  };

  const handleUploadEvidence = async (file: File, category?: string) => {
    const cid = activeLabCase?.case_id || activeCase?.case_id;
    if (!cid) return;
    await api.uploadEvidence(cid, file, category);
    await loadCaseData(cid);
  };

  const handleLockVault = async () => {
    const cid = activeLabCase?.case_id || activeCase?.case_id;
    if (!cid) return;
    await api.lockVault(cid);
    await loadCaseData(cid);
  };

  const handleUnlockVault = async (reason: string) => {
    const cid = activeLabCase?.case_id || activeCase?.case_id;
    if (!cid) return;
    await api.unlockVault(cid, reason);
    await loadCaseData(cid);
  };

  const handleTriggerExtraction = async () => {
    const cid = activeLabCase?.case_id || activeCase?.case_id;
    if (!cid) return;
    setIsLoading(true);
    try {
      await api.triggerExtraction(cid);
      await loadCaseData(cid);
    } finally {
      setIsLoading(false);
    }
  };

  const handleRunAnalysis = async () => {
    const cid = activeLabCase?.case_id || activeCase?.case_id;
    if (!cid) return;
    setIsAnalyzing(true);
    try {
      const res = await api.runAnalysis(cid);
      const taskId = res?.task_id;
      if (taskId) {
        let attempts = 0;
        const maxAttempts = 35;
        while (attempts < maxAttempts) {
          await new Promise((resolve) => setTimeout(resolve, 1000));
          attempts++;
          const taskStatus = await api.getAnalysisTask(taskId).catch(() => null);
          if (taskStatus && (taskStatus.status === "completed" || taskStatus.status === "failed")) {
            break;
          }
        }
      }
      await loadCaseData(cid);
    } catch (err: any) {
      alert(err.message || "Analysis error");
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleReviewSubmit = async (action: "APPROVE" | "REJECT_REANALYZE", notes: string) => {
    const cid = activeLabCase?.case_id || activeCase?.case_id;
    if (!cid) return;
    await api.reviewSIS(cid, action, notes);
    await loadCaseData(cid);
  };

  const handleDownloadReportJson = () => {
    if (!reportData && !sisState) return;
    const blob = new Blob([JSON.stringify(reportData || sisState, null, 2)], {
      type: "application/json"
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `Sherlock_Report_${activeLabCase?.case_id || activeCase?.case_id || "Export"}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const currentLabCase = activeLabCase || activeCase;

  return (
    <>
      {/* 3D WebGL Ambient Background Canvas */}
      <ThreeBackground />

      {/* 1. Public Landing Page View */}
      {viewMode === "landing" && (
        <>
          <LandingNavbar
            onOpenLogin={() => {
              setViewMode("login");
              navigate("/login");
            }}
            status={inferenceStatus}
            onOpenAISettings={() => setIsAISettingsOpen(true)}
          />
          <LandingPage onOpenLogin={() => {
            setViewMode("login");
            navigate("/login");
          }} />
        </>
      )}

      {/* 2. Full-Page Sign In View */}
      {viewMode === "login" && (
        <LoginPage
          onBackToLanding={() => {
            setViewMode("landing");
            navigate("/");
          }}
          onLoginSuccess={handleLoginSuccess}
        />
      )}

      {/* 3. Investigation Workspace View */}
      {viewMode === "workspace" && (
        <div className="flex">
          {inLabMode && currentLabCase ? (
            <ErrorBoundary fallbackTitle="Forensic Lab Workspace Exception">
              <ForensicLabWorkspace
                caseItem={currentLabCase}
                onExitLab={() => {
                  setInLabMode(false);
                  setActiveLabCase(null);
                  navigate("/cases");
                }}
                tierStatus={inferenceStatus}
                evidenceList={evidenceList}
                findings={findings}
                sisState={sisState}
                reportData={reportData}
                artifactsData={artifactsData}
                manifest={manifest}
                isAnalyzing={isAnalyzing}
                isLoading={isLoading}
                initialTab={activeLabTab}
                onTabChange={(tab) => {
                  setActiveLabTab(tab);
                  const pathTab = tab === "evidence" ? "vault" : tab;
                  navigate(`/cases/${currentLabCase.case_id}/lab/${pathTab}`);
                }}
                onUploadEvidence={handleUploadEvidence}
                onLockVault={handleLockVault}
                onUnlockVault={handleUnlockVault}
                onTriggerExtraction={handleTriggerExtraction}
                onRunAnalysis={handleRunAnalysis}
                onReviewSubmit={handleReviewSubmit}
                onDownloadReportJson={handleDownloadReportJson}
              />
            </ErrorBoundary>
          ) : (
            <>
              <WorkspaceHeader
                user={user}
                activeTab={activeTab}
                onTabChange={(tab) => {
                  setActiveTab(tab);
                  navigate(tab === "home" ? "/home" : "/cases");
                }}
                onLogout={handleLogout}
                onShowLanding={() => {
                  setViewMode("landing");
                  navigate("/");
                }}
                onOpenAISettings={() => setIsAISettingsOpen(true)}
                tierStatus={inferenceStatus}
              />
              <WorkspaceMain
                activeTab={activeTab}
                cases={cases}
                activeCase={activeCase}
                onSelectCase={(c) => {
                  setActiveCase(c);
                  setActiveLabCase(c);
                  setInLabMode(true);
                  navigate(`/cases/${c.case_id}/lab/vault`);
                }}
                onOpenCaseInLab={(c) => {
                  setActiveCase(c);
                  setActiveLabCase(c);
                  setInLabMode(true);
                  navigate(`/cases/${c.case_id}/lab/vault`);
                }}
                onOpenCreateModal={() => setIsCreateCaseOpen(true)}
                tierStatus={inferenceStatus}
                evidenceList={evidenceList}
              />
            </>
          )}
        </div>
      )}

      {/* AI GPU Inference Settings Modal */}
      {isAISettingsOpen && (
        <AISettingsModal
          isOpen={isAISettingsOpen}
          onClose={() => setIsAISettingsOpen(false)}
          status={inferenceStatus}
          onStatusUpdated={fetchInferenceStatus}
        />
      )}

      {/* Create New Case Modal */}
      {isCreateCaseOpen && (
        <CreateCaseModal
          isOpen={isCreateCaseOpen}
          onClose={() => setIsCreateCaseOpen(false)}
          onSubmit={handleCreateCase}
          defaultInvestigator={user?.username || "investigator1"}
        />
      )}
    </>
  );
}

export default App;
