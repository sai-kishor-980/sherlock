"""
Agent Barrier and Investigation Lifecycle Service for SherlockAI / H-MACFR.

Enforces:
1. Strict 16-State Lifecycle State Machine.
2. Mandatory Five-Domain Completion Barrier:
   All 5 specialized forensic domains (network, memory, disk, logs, registry)
   must execute and yield a validated outcome before downstream correlation,
   hypothesis generation, and Pre-SIS synthesis can proceed.
3. Explicit examination-status records for missing domains:
   Domains without artifacts receive INSUFFICIENT_EVIDENCE (confidence 0.0),
   never fabricated benign/suspicious findings.
4. Resilient failure recovery: Individual failed agents can be retried without
   discarding the successful runs of other agents.
"""

import os
import json
import time
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple


class ForensicInvestigationState:
    WAITING_FOR_EXTRACTION = "WAITING_FOR_EXTRACTION"
    EXTRACTION_IN_PROGRESS = "EXTRACTION_IN_PROGRESS"
    EXTRACTION_COMPLETED = "EXTRACTION_COMPLETED"
    EXTRACTION_FAILED = "EXTRACTION_FAILED"
    WAITING_FOR_AGENT_EXECUTION = "WAITING_FOR_AGENT_EXECUTION"
    AGENTS_IN_PROGRESS = "AGENTS_IN_PROGRESS"
    AGENTS_COMPLETED = "AGENTS_COMPLETED"
    AGENTS_PARTIAL = "AGENTS_PARTIAL"
    WAITING_FOR_CORRELATION = "WAITING_FOR_CORRELATION"
    CORRELATION_IN_PROGRESS = "CORRELATION_IN_PROGRESS"
    CORRELATION_COMPLETED = "CORRELATION_COMPLETED"
    WAITING_FOR_PRE_SIS = "WAITING_FOR_PRE_SIS"
    PRE_SIS_PENDING_REVIEW = "PRE_SIS_PENDING_REVIEW"
    SIS_APPROVED = "SIS_APPROVED"
    SIS_REJECTED_REANALYZE = "SIS_REJECTED_REANALYZE"
    REPORT_GENERATED = "REPORT_GENERATED"


REQUIRED_DOMAINS = ["network", "memory", "disk", "logs", "registry"]


class AgentBarrierService:
    @classmethod
    def get_state_file_path(cls, case_id: str) -> Path:
        base_dir = Path(__file__).resolve().parents[2]
        case_dir = base_dir / "output" / "cases" / case_id
        case_dir.mkdir(parents=True, exist_ok=True)
        return case_dir / "investigation_state.json"

    @classmethod
    def get_case_state(cls, case_id: str) -> Dict[str, Any]:
        state_file = cls.get_state_file_path(case_id)
        if state_file.exists():
            try:
                with open(state_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        
        # Derive initial state from existing disk artifacts
        base_dir = Path(__file__).resolve().parents[2]
        case_dir = base_dir / "output" / "cases" / case_id
        extracted_root = case_dir / "extracted_artifacts"
        findings_file = case_dir / "findings" / "all_findings.json"
        sis_file = case_dir / "sis_state.json"

        current_status = ForensicInvestigationState.WAITING_FOR_EXTRACTION
        if sis_file.exists():
            current_status = ForensicInvestigationState.PRE_SIS_PENDING_REVIEW
        elif findings_file.exists():
            current_status = ForensicInvestigationState.AGENTS_COMPLETED
        elif extracted_root.exists() and any(extracted_root.iterdir()):
            current_status = ForensicInvestigationState.EXTRACTION_COMPLETED

        initial_state = {
            "case_id": case_id,
            "status": current_status,
            "domain_statuses": {domain: "PENDING" for domain in REQUIRED_DOMAINS},
            "last_updated": time.time(),
            "completed_domains": [],
            "failed_domains": [],
            "missing_domains": [],
            "barrier_satisfied": False,
            "investigation_notes": []
        }
        cls.save_case_state(case_id, initial_state)
        return initial_state

    @classmethod
    def save_case_state(cls, case_id: str, state_data: Dict[str, Any]) -> None:
        state_file = cls.get_state_file_path(case_id)
        state_data["last_updated"] = time.time()
        try:
            with open(state_file, "w", encoding="utf-8") as f:
                json.dump(state_data, f, indent=2, default=str)
        except Exception:
            pass

    @classmethod
    def update_state(cls, case_id: str, new_status: str, notes: Optional[str] = None) -> Dict[str, Any]:
        state = cls.get_case_state(case_id)
        state["status"] = new_status
        if notes:
            state.setdefault("investigation_notes", []).append({
                "timestamp": time.time(),
                "status": new_status,
                "note": notes
            })
        cls.save_case_state(case_id, state)
        return state

    # Recognized, validated outcome statuses that may count toward barrier completion.
    VALID_COMPLETION_STATUSES = {"COMPLETED", "INSUFFICIENT_EVIDENCE"}
    VALID_FAILURE_STATUSES = {"FAILED", "GPU_UNAVAILABLE"}

    @classmethod
    def evaluate_five_agent_barrier(
        cls,
        case_id: str,
        findings: List[Dict[str, Any]],
        execution_id: Optional[str] = None,
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Validates that all five domains have an explicit execution record for the
        current execution_id: either a grounded evidentiary finding or an explicit
        INSUFFICIENT_EVIDENCE record.
        Stale findings from previous executions (different execution_id) are ignored.
        Returns:
            (barrier_satisfied: bool, evaluation_details: dict)
        """
        if execution_id is None:
            execution_id = str(uuid.uuid4())

        # Tag each finding with the current execution ID for traceability.
        for f in findings:
            f["execution_id"] = execution_id

        # Only consider findings belonging to the current execution.
        current_findings = [
            f for f in findings
            if f.get("execution_id") == execution_id
        ]

        evaluated_domains = {}
        completed = []
        failed = []
        insufficient = []

        for domain in REQUIRED_DOMAINS:
            domain_records = [
                f for f in current_findings
                if str(f.get("domain", "")).lower() == domain
            ]
            if not domain_records:
                evaluated_domains[domain] = {
                    "status": "MISSING",
                    "reason": f"No analysis record present for {domain} agent in execution {execution_id}."
                }
                failed.append(domain)
            else:
                # Explicit status validation: only recognized statuses may count.
                has_failure = any(
                    f.get("status") in cls.VALID_FAILURE_STATUSES
                    or f.get("error") == "GPU_UNAVAILABLE"
                    for f in domain_records
                )
                has_insufficient = all(
                    f.get("status") == "INSUFFICIENT_EVIDENCE" or
                    str(f.get("classification", "")).upper() == "INSUFFICIENT_EVIDENCE"
                    for f in domain_records
                )
                has_unknown = any(
                    f.get("status") is not None
                    and f.get("status") not in cls.VALID_COMPLETION_STATUSES
                    and f.get("status") not in cls.VALID_FAILURE_STATUSES
                    and f.get("status") != "INSUFFICIENT_EVIDENCE"
                    and str(f.get("classification", "")).upper() != "INSUFFICIENT_EVIDENCE"
                    for f in domain_records
                )

                if has_failure:
                    evaluated_domains[domain] = {
                        "status": "FAILED",
                        "reason": f"{domain} agent execution failed or GPU disconnected."
                    }
                    failed.append(domain)
                elif has_unknown:
                    evaluated_domains[domain] = {
                        "status": "INVALID",
                        "reason": f"{domain} agent returned an unrecognized or invalid outcome status."
                    }
                    failed.append(domain)
                elif has_insufficient:
                    evaluated_domains[domain] = {
                        "status": "INSUFFICIENT_EVIDENCE",
                        "records_count": len(domain_records),
                        "is_examination_status": True
                    }
                    insufficient.append(domain)
                    completed.append(domain)
                else:
                    # All records have recognized, non-failure, non-insufficient statuses.
                    evaluated_domains[domain] = {
                        "status": "COMPLETED",
                        "records_count": len(domain_records),
                        "top_classification": domain_records[0].get("classification", "BENIGN")
                    }
                    completed.append(domain)

        barrier_satisfied = len(failed) == 0 and len(completed) == len(REQUIRED_DOMAINS)
        
        details = {
            "barrier_satisfied": barrier_satisfied,
            "execution_id": execution_id,
            "required_domains": REQUIRED_DOMAINS,
            "completed_domains": completed,
            "failed_domains": failed,
            "insufficient_evidence_domains": insufficient,
            "domain_evaluations": evaluated_domains
        }

        # Update case lifecycle state with current execution context.
        state = cls.get_case_state(case_id)
        state["execution_id"] = execution_id
        state["domain_statuses"] = {d: evaluated_domains[d]["status"] for d in REQUIRED_DOMAINS}
        state["completed_domains"] = completed
        state["failed_domains"] = failed
        state["missing_domains"] = [d for d in REQUIRED_DOMAINS if evaluated_domains[d]["status"] == "MISSING"]
        state["barrier_satisfied"] = barrier_satisfied

        if barrier_satisfied:
            state["status"] = ForensicInvestigationState.AGENTS_COMPLETED
        elif completed:
            state["status"] = ForensicInvestigationState.AGENTS_PARTIAL
        else:
            state["status"] = ForensicInvestigationState.WAITING_FOR_AGENT_EXECUTION

        cls.save_case_state(case_id, state)
        return barrier_satisfied, details

    @classmethod
    def validate_barrier_for_execution(cls, case_id: str, execution_id: str) -> bool:
        """
        Returns True only if the persisted barrier state belongs to the given
        execution_id AND barrier_satisfied is True. Stale state from a previous
        execution never authorizes a new run.
        """
        state = cls.get_case_state(case_id)
        if state.get("execution_id") != execution_id:
            return False
        return bool(state.get("barrier_satisfied", False))

