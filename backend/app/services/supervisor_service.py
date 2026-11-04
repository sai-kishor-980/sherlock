"""
Supervisor Service & Multi-Agent Orchestrator for Agentic Sherlock AI.

Orchestrates the Specialized Forensic Domain Agents:
- Network Forensics Agent (network)
- Memory Analysis Agent (memory)
- Disk & Filesystem Agent (disk)
- Event Logs Agent (logs)
- Windows Registry Agent (registry)
- Email & Communication Agent (email)

Enforces strict output JSON contracts in:
  output/cases/<case_id>/extracted_artifacts/<domain>/<contract_file>.json
Hides raw buffers and ensures only genuine tool-produced JSON contracts are stored.
Coordinates with ModelAdapterService for domain-specific Qwen LoRA reasoning.
"""

import os
import json
import shutil
import datetime
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional

from app.core.logger import log_app_event, log_error_event
from app.services.model_adapter_service import ModelAdapterService

BACKEND_DIR = Path(__file__).resolve().parents[2]
OUTPUT_CASES_DIR = BACKEND_DIR / "output" / "cases"

# Exact Contract Specifications per Technical Agent
AGENT_CONTRACTS = {
    "network": {
        "agent_name": "Network Forensics Agent",
        "domain": "network",
        "role": "Network Packet & Protocol Specialist",
        "description": "PCAP packet metadata, DNS resolutions, IP/port traffic flows, and protocol summaries",
        "expected_files": [
            "network_summary.json",
            "dns_analysis.json",
            "network_connections.json"
        ]
    },
    "memory": {
        "agent_name": "Memory Analysis Agent",
        "domain": "memory",
        "role": "Volatile Memory & Kernel Specialist",
        "description": "Volatile RAM, processes, trees, loaded modules, handles, services/persistence, and malware indicators",
        "expected_files": [
            "processes.json",
            "modules.json",
            "handles.json",
            "memory_analysis.json",
            "memory_summary.json",
            "execution.json",
            "system.json",
            "services_persistence.json",
            "network.json",
            "users_security.json",
            "threat_hunting.json"
        ]
    },
    "disk": {
        "agent_name": "Disk & Filesystem Agent",
        "domain": "disk",
        "role": "Filesystem & Disk Artifact Specialist",
        "description": "Master File Table (MFT), Filesystem Inventory, Deleted Files, LNK shortcut files, Prefetch execution records, Recycle Bin metadata, and Jump Lists",
        "expected_files": [
            "filesystem_inventory.json",
            "deleted_files.json",
            "disk_summary.json",
            "mft_analysis.json",
            "mft_summary.json",
            "lnk_analysis.json",
            "lnk_summary.json",
            "prefetch_analysis.json",
            "prefetch_summary.json",
            "recyclebin_analysis.json",
            "recyclebin_summary.json",
            "jumplist_automatic.json",
            "jumplist_custom.json",
            "jumplist_summary.json"
        ]
    },
    "logs": {
        "agent_name": "Event Logs Agent",
        "domain": "logs",
        "role": "Windows Event & Sysmon Specialist",
        "description": "Windows Security Event Logs, Sysmon, process creation, PowerShell activity, logon/logoff, RDP sessions, and service installations",
        "expected_files": [
            "security_logons.json",
            "process_creations.json",
            "services_installed.json",
            "powershell_activity.json",
            "rdp_sessions.json",
            "eventlogs_summary.json"
        ]
    },
    "registry": {
        "agent_name": "Windows Registry Agent",
        "domain": "registry",
        "role": "Registry Hive & Configuration Specialist",
        "description": "Installed software, USB device history, Run/RunOnce keys, RecentDocs, persistence keys, and parser error diagnostics",
        "expected_files": [
            "installed_software.json",
            "usb_devices.json",
            "run_keys.json",
            "recent_files.json",
            "registry_summary.json",
            "registry_errors.json"
        ]
    },
    "email": {
        "agent_name": "Email & Communication Agent",
        "domain": "email",
        "role": "Email Archive & Message Specialist",
        "description": "Email archive extraction (.zip, .eml, .msg, .mbox), attachments, and communications telemetry",
        "expected_files": [
            "email_messages.json",
            "email_attachments.json",
            "email_summary.json"
        ]
    }
}


class SupervisorService:
    """
    Central Supervisor Orchestration Engine.
    Coordinates evidence dispatch, tool execution, output contract normalization,
    and handoff to domain Qwen LoRA reasoning models.
    """

    @classmethod
    def get_case_output_dir(cls, case_id: str) -> Path:
        target = OUTPUT_CASES_DIR / case_id
        target.mkdir(parents=True, exist_ok=True)
        return target

    @classmethod
    def get_domain_output_dir(cls, case_id: str, domain: str) -> Path:
        domain_dir = cls.get_case_output_dir(case_id) / "extracted_artifacts" / domain
        domain_dir.mkdir(parents=True, exist_ok=True)
        return domain_dir

    @classmethod
    def classify_evidence_to_domain(cls, evidence_type: str, file_name: str) -> str:
        """
        Maps evidence type or file extension to the responsible Domain Agent.
        """
        t = (evidence_type or "").lower()
        fn = (file_name or "").lower()

        # Email Domain: .eml, .msg, .mbox, takeout zip, or email type
        if t in ["email", "eml", "msg", "mbox"] or fn.endswith((".eml", ".msg", ".mbox")) or ("takeout" in fn and fn.endswith(".zip")):
            return "email"

        # Network Domain: PCAP, PCAPNG
        if t in ["pcap", "pcapng", "network"] or fn.endswith((".pcap", ".pcapng")):
            return "network"

        # Memory Domain: RAM, DMP, VMEM, MEM
        if t in ["memory", "ram", "mem", "vmem", "dmp"] or fn.endswith((".raw", ".mem", ".dmp", ".vmem")):
            return "memory"

        # Log Domain: EVTX, Sysmon, EventLog
        if t in ["eventlog", "logs", "evtx", "sysmon"] or fn.endswith(".evtx") or "event" in fn or "sysmon" in fn:
            return "logs"

        # Registry Domain: REG, HIVES (SAM, SYSTEM, SOFTWARE, NTUSER.DAT)
        if t in ["registry", "reg", "hive"] or fn.endswith(".reg") or fn in ["sam", "system", "software", "ntuser.dat", "security"]:
            return "registry"

        # Disk Domain: MFT, LNK, Prefetch, JumpLists, Recycle Bin, Disk Images
        if t in ["disk", "mft", "lnk", "prefetch", "jumplist", "recyclebin"] or fn.endswith((".e01", ".ex01", ".dd", ".img", ".001", ".pf", ".lnk")) or "$mft" in fn or "$recycle" in fn or "destinations-ms" in fn:
            return "disk"

        # Default fallback to disk
        return "disk"

    @classmethod
    def orchestrate_case_extraction(cls, case_id: str, evidence_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Dispatches all evidence items for a case to their respective domain agents.
        Executes parsers, normalizes final JSON contracts into extracted_artifacts/<domain>/,
        and generates the supervisor orchestration manifest.
        """
        log_app_event(f"[Supervisor] Orchestrating artifact extraction for Case {case_id} across specialized domain agents...")
        case_dir = cls.get_case_output_dir(case_id)
        extracted_root = case_dir / "extracted_artifacts"
        extracted_root.mkdir(parents=True, exist_ok=True)

        # 1. Group evidence by responsible domain agent
        domain_workloads: Dict[str, List[Dict[str, Any]]] = {
            domain: [] for domain in AGENT_CONTRACTS.keys()
        }

        for ev in evidence_list:
            domain = cls.classify_evidence_to_domain(ev.get("type", ""), ev.get("name", "") or ev.get("path", ""))
            if domain in domain_workloads:
                domain_workloads[domain].append(ev)
            else:
                domain_workloads["disk"].append(ev)

        # 2. Run plugin extraction for registered evidence items via PluginManager
        pm_results = {}
        try:
            from artifact_extraction.plugin_manager.manager import PluginManager
            pm = PluginManager(case_id=case_id)
            pm_case = pm.create_case(case_id)
            registered = []
            for ev in evidence_list:
                p = ev.get("path")
                if p and os.path.exists(p):
                    registered.append({
                        "path": p,
                        "type": ev.get("type"),
                        "name": ev.get("name", Path(p).name),
                        "evidence_id": ev.get("evidence_id")
                    })
            if registered:
                pm.register_evidence(pm_case, registered)
                pm_results = pm.execute_case(pm_case)
        except Exception as ex:
            log_error_event(f"[Supervisor] Note during PluginManager invocation: {ex}")

        # 3. Synchronize genuine outputs into agent contract JSON files (Strictly NO dummy placeholders)
        agent_summaries = {}
        for domain, contract_info in AGENT_CONTRACTS.items():
            agent_summary = cls._normalize_domain_artifacts(case_id, domain, contract_info, domain_workloads[domain])
            agent_summaries[domain] = agent_summary

        # Filter only active domains (domains with genuine extracted files or diagnostic records)
        active_domains = {d: s for d, s in agent_summaries.items() if s["extracted_count"] > 0 or s.get("has_errors")}

        # 4. Generate Supervisor Manifest with Fault-Tolerant Status
        manifest = {
            "orchestrator": "Supervisor Multi-Agent (Qwen Powered)",
            "case_id": case_id,
            "orchestration_timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "active_agents": {
                domain: {
                    "agent": info["agent_name"],
                    "role": info["role"],
                    "extracted_count": agent_summaries[domain]["extracted_count"],
                    "status": (
                        "COMPLETED" if agent_summaries[domain]["extracted_count"] > 0 and not agent_summaries[domain].get("has_errors")
                        else ("PARTIALLY_EXTRACTED" if agent_summaries[domain]["extracted_count"] > 0 or agent_summaries[domain].get("has_errors")
                        else "INACTIVE")
                    ),
                    "files": agent_summaries[domain]["files"],
                    "errors": agent_summaries[domain].get("error_details", [])
                }
                for domain, info in AGENT_CONTRACTS.items()
                if agent_summaries[domain]["extracted_count"] > 0 or len(domain_workloads[domain]) > 0
            },
            "total_artifacts_extracted": sum(s["extracted_count"] for s in agent_summaries.values())
        }

        manifest_file = case_dir / "supervisor_manifest.json"
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        # Authoritatively transition SQLite Evidence records to 'EXTRACTED'
        try:
            from app.db.connection import SessionLocal
            from app.db.models.evidence import Evidence
            with SessionLocal() as db:
                ev_items = db.query(Evidence).filter(Evidence.case_id == case_id).all()
                for ev in ev_items:
                    ev.status = "EXTRACTED"
                db.commit()
                log_app_event(f"[Supervisor] Successfully updated {len(ev_items)} evidence records to 'EXTRACTED' for Case {case_id}")
        except Exception as db_err:
            log_app_event(f"[Supervisor] Note updating evidence status in DB: {db_err}")

        log_app_event(f"[Supervisor] Orchestration finished for Case {case_id}: {manifest['total_artifacts_extracted']} genuine JSON artifacts verified.")
        log_app_event(f"[Supervisor] Domain agents must be executed via execute_domain_analyses() before SIS synthesis.")
        return manifest

    @classmethod
    def _normalize_domain_artifacts(
        cls,
        case_id: str,
        domain: str,
        contract_info: Dict[str, Any],
        workload: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Normalizes genuine tool outputs for a specific domain agent.
        Collects real extracted files and places them into extracted_artifacts/<domain>/.
        Strictly does NOT generate fake or empty baseline contracts.
        """
        case_dir = cls.get_case_output_dir(case_id)
        domain_dir = cls.get_domain_output_dir(case_id, domain)
        expected_files = set(contract_info.get("expected_files", []))

        # Sources to look for extracted data strictly for this domain
        domain_search_map = {
            "network": ["network", "pcap", "pcap_analysis"],
            "memory": ["memory", "memory/plugins"],
            "disk": ["disk", "disk/analyzed", "disk/filesystem", "prefetch_analysis", "lnk_analysis"],
            "logs": ["logs", "eventlog_analysis"],
            "registry": ["registry", "registry_analysis"],
            "email": ["email"]
        }

        domain_subdirs = domain_search_map.get(domain, [domain])
        candidate_search_dirs = [domain_dir]
        for sub in domain_subdirs:
            p = case_dir / sub
            if p.exists() and p.resolve() != domain_dir.resolve():
                candidate_search_dirs.append(p)

        extracted_files = []
        seen_filenames = set()

        for cdir in candidate_search_dirs:
            if not cdir.exists() or not cdir.is_dir():
                continue
            for item in sorted(os.listdir(cdir)):
                if not item.lower().endswith(".json"):
                    continue
                if item.startswith("temp_") or item.startswith(".") or item in ["case_summary.json", "supervisor_manifest.json"]:
                    continue
                # Strictly enforce that only expected contract files for THIS domain are collected
                if expected_files and item not in expected_files:
                    continue
                if item in seen_filenames:
                    continue

                source_fpath = cdir / item
                if not source_fpath.is_file():
                    continue

                target_fpath = domain_dir / item
                # Copy into domain_dir if found in candidate subfolder
                try:
                    if source_fpath.resolve() != target_fpath.resolve():
                        shutil.copy2(source_fpath, target_fpath)
                except Exception:
                    pass

                if target_fpath.exists() and target_fpath.is_file():
                    try:
                        size = os.path.getsize(target_fpath)
                        if size > 0:
                            seen_filenames.add(item)
                            extracted_files.append({
                                "filename": item,
                                "rel_path": f"extracted_artifacts/{domain}/{item}",
                                "file_size": size,
                                "size_formatted": f"{(size / 1024):.1f} KB" if size > 1024 else f"{size} B",
                                "status": "EXTRACTED"
                            })
                    except Exception:
                        pass

        # Inspect for parser diagnostic error files (Decision 3)
        error_details = []
        for cdir in candidate_search_dirs:
            if not cdir.exists() or not cdir.is_dir():
                continue
            for err_file in cdir.glob("*_errors.json"):
                try:
                    with open(err_file, "r", encoding="utf-8") as ef:
                        err_content = json.load(ef)
                        if err_content:
                            error_details.append({
                                "error_file": err_file.name,
                                "count": len(err_content) if isinstance(err_content, list) else 1,
                                "details": err_content[:5] if isinstance(err_content, list) else err_content
                            })
                except Exception:
                    pass

        return {
            "domain": domain,
            "agent_name": contract_info["agent_name"],
            "role": contract_info["role"],
            "extracted_count": len(extracted_files),
            "files": extracted_files,
            "has_errors": len(error_details) > 0,
            "error_details": error_details
        }

    @classmethod
    def get_case_artifacts_tree(cls, case_id: str) -> Dict[str, Any]:
        """
        Returns the finalized forensic artifact tree grouped by Agent domain.
        Strictly excludes domains with 0 artifacts and temporary dump files.
        """
        case_dir = cls.get_case_output_dir(case_id)
        extracted_root = case_dir / "extracted_artifacts"

        categories = []
        total_artifacts = 0

        # Scan each Domain Agent
        for domain, info in AGENT_CONTRACTS.items():
            domain_dir = extracted_root / domain
            files = []

            dirs_to_check = [domain_dir]
            legacy_dir = case_dir / domain
            if legacy_dir.exists() and legacy_dir.is_dir():
                dirs_to_check.append(legacy_dir)
            if domain == "disk" and (case_dir / "disk" / "analyzed").exists():
                dirs_to_check.append(case_dir / "disk" / "analyzed")
            if domain == "network" and (case_dir / "pcap").exists():
                dirs_to_check.append(case_dir / "pcap")

            seen_filenames = set()
            for d in dirs_to_check:
                if d.exists() and d.is_dir():
                    for item in sorted(os.listdir(d)):
                        item_path = d / item
                        if item_path.is_file() and item.lower().endswith(".json"):
                            if item.startswith("temp_") or item.startswith(".") or item in ["case_summary.json", "supervisor_manifest.json"]:
                                continue
                            if item in seen_filenames:
                                continue
                            seen_filenames.add(item)
                            size_bytes = os.path.getsize(item_path)
                            if size_bytes > 0:
                                rel_path = str(item_path.relative_to(case_dir)).replace("\\", "/")
                                files.append({
                                    "filename": item,
                                    "rel_path": rel_path,
                                    "file_size": size_bytes,
                                    "size_formatted": f"{(size_bytes / 1024):.1f} KB" if size_bytes > 1024 else f"{size_bytes} B",
                                    "domain": domain,
                                    "agent": info["agent_name"],
                                    "role": info["role"]
                                })

            # ONLY include category if it actually contains extracted files!
            if files:
                files.sort(key=lambda x: x["filename"])
                total_artifacts += len(files)
                categories.append({
                    "category": domain,
                    "agent_name": info["agent_name"],
                    "role": info["role"],
                    "description": info["description"],
                    "artifact_count": len(files),
                    "files": files
                })

        summary_data = {}
        manifest_path = case_dir / "supervisor_manifest.json"
        if manifest_path.exists():
            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    summary_data = json.load(f)
            except Exception:
                pass

        return {
            "case_id": case_id,
            "total_artifacts": total_artifacts,
            "categories": categories,
            "summary": summary_data,
            "status": "READY" if total_artifacts > 0 else "EMPTY"
        }

    @classmethod
    def execute_domain_analyses(cls, case_id: str) -> List[Dict[str, Any]]:
        """
        Dispatches all extracted domain artifacts for a case to the 5 specialized domain agents.
        Executes ModelAdapterService cognitive analysis with observation accounting.
        Emits explicit examination-status records for missing domains (INSUFFICIENT_EVIDENCE, confidence 0.0).
        Enforces the Mandatory Five-Agent Completion Barrier via AgentBarrierService.
        """
        from app.services.agent_barrier_service import AgentBarrierService, REQUIRED_DOMAINS

        case_dir = cls.get_case_output_dir(case_id)
        extracted_root = case_dir / "extracted_artifacts"
        findings_dir = case_dir / "findings"
        findings_dir.mkdir(parents=True, exist_ok=True)

        # Execution ID for this investigation run — all domain outcomes are
        # associated with this ID so stale results from previous runs cannot
        # authorize a new synthesis.
        execution_id = str(uuid.uuid4())

        all_findings = []

        domain_priority_contracts = {
            "network": ["network_connections.json", "dns_analysis.json", "network_summary.json"],
            "memory": ["threat_hunting.json", "processes.json", "memory_summary.json"],
            "disk": ["prefetch_analysis.json", "deleted_files.json", "mft_analysis.json", "disk_summary.json"],
            "logs": ["eventlogs_summary.json", "security_logons.json", "powershell_activity.json"],
            "registry": ["registry_summary.json", "run_keys.json", "usb_devices.json"],
            "email": ["email_summary.json", "email_messages.json"]
        }

        # Dispatch across all 5 mandatory domains
        for domain in REQUIRED_DOMAINS:
            domain_dir = extracted_root / domain
            contract_names = domain_priority_contracts.get(domain, [])
            dispatched_for_domain = 0

            if domain_dir.exists() and domain_dir.is_dir():
                for c_name in contract_names:
                    c_path = domain_dir / c_name
                    if c_path.exists() and c_path.is_file() and os.path.getsize(c_path) > 0:
                        try:
                            with open(c_path, "r", encoding="utf-8") as f:
                                content = json.load(f)

                            log_app_event(f"[Supervisor] Dispatching {domain}/{c_name} to {domain.capitalize()} Agent...")
                            finding = ModelAdapterService.analyze_domain_evidence(
                                domain=domain,
                                evidence_type=c_name.replace(".json", "").replace("_", " ").title(),
                                evidence_content=content
                            )
                            finding["case_id"] = case_id
                            finding["source_artifact"] = f"extracted_artifacts/{domain}/{c_name}"
                            all_findings.append(finding)
                            dispatched_for_domain += 1
                        except Exception as err:
                            log_error_event(f"[Supervisor] Error analyzing {domain}/{c_name}: {err}")

            # If no evidentiary contracts were dispatched for this domain, emit explicit examination status record
            if dispatched_for_domain == 0:
                log_app_event(f"[Supervisor] Evidentiary absence in {domain} domain. Emitting explicit INSUFFICIENT_EVIDENCE record.")
                status_finding = ModelAdapterService.analyze_domain_evidence(
                    domain=domain,
                    evidence_type=f"{domain.capitalize()} Forensics (Absence Record)",
                    evidence_content=None
                )
                status_finding["case_id"] = case_id
                status_finding["source_artifact"] = f"extracted_artifacts/{domain}/"
                all_findings.append(status_finding)

        # Evaluate Five-Domain Completion Barrier
        barrier_ok, barrier_details = AgentBarrierService.evaluate_five_agent_barrier(case_id, all_findings, execution_id=execution_id)
        log_app_event(f"[Supervisor] Five-Agent Barrier evaluation for Case {case_id}: satisfied={barrier_ok}")

        try:
            with open(findings_dir / "all_findings.json", "w", encoding="utf-8") as f:
                json.dump(all_findings, f, indent=2, default=str)
            log_app_event(f"[Supervisor] Generated and saved {len(all_findings)} agent findings for Case {case_id}")
        except Exception as we:
            log_error_event(f"[Supervisor] Note saving findings: {we}")

        return all_findings, barrier_ok, barrier_details

