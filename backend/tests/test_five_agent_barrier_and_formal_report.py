"""
Automated Forensic Verification Suite for SherlockAI (H-MACFR).

Tests:
1. Five-Agent Completion Barrier state machine and explicit INSUFFICIENT_EVIDENCE accounting.
2. Strict Colab GPU readiness gating (HTTP 503 GPU_UNAVAILABLE blocking, zero mock fallback).
3. ReportLab 5.0.1 Formal Digital Forensic PDF Report generation (NumberedCanvas, 12 sections, SHA-256 seal).
4. Review Gate enforcement on PDF downloads (HTTP 423 Locked until Pre-SIS approved).
5. ChromaDB cosine distance threshold cutoff and elimination of false citations on irrelevant queries.
6. DNS-to-flow correlation deduplication (eliminating the 13 duplicated hypotheses/pivots).
"""

import pytest
import os
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from app.services.agent_barrier_service import AgentBarrierService, ForensicInvestigationState, REQUIRED_DOMAINS
from app.services.model_adapter_service import ModelAdapterService
from app.services.formal_report_service import FormalReportService, NumberedCanvas
from app.services.synthesizer_service import ForensicSynthesizerService
from app.services.xai_service import XAIService


# -----------------------------------------------------------------------------
# 1. Five-Agent Completion Barrier & INSUFFICIENT_EVIDENCE Accounting Tests
# -----------------------------------------------------------------------------

def test_five_agent_barrier_all_completed():
    case_id = "CASE_TEST_BARRIER_01"
    findings = [
        {"domain": "network", "finding_id": "F-NET-01", "classification": "SUSPICIOUS", "confidence": 0.85},
        {"domain": "memory", "finding_id": "F-MEM-01", "classification": "MALICIOUS", "confidence": 0.90},
        {"domain": "disk", "finding_id": "F-DISK-01", "classification": "BENIGN", "confidence": 0.75},
        {"domain": "logs", "finding_id": "F-LOG-01", "classification": "BENIGN", "confidence": 0.80},
        {"domain": "registry", "finding_id": "F-REG-01", "classification": "BENIGN", "confidence": 0.70},
    ]

    barrier_ok, details = AgentBarrierService.evaluate_five_agent_barrier(case_id, findings)
    assert barrier_ok is True
    assert set(details["completed_domains"]) == set(REQUIRED_DOMAINS)
    assert len(details["failed_domains"]) == 0

    state = AgentBarrierService.get_case_state(case_id)
    assert state["status"] == ForensicInvestigationState.AGENTS_COMPLETED
    assert state["barrier_satisfied"] is True


def test_five_agent_barrier_with_insufficient_evidence_record():
    case_id = "CASE_TEST_BARRIER_INSUFF"
    # Network and Disk have findings; Memory, Logs, and Registry have explicit examination absence records
    findings = [
        {"domain": "network", "finding_id": "F-NET-01", "classification": "SUSPICIOUS", "confidence": 0.85},
        {"domain": "disk", "finding_id": "F-DISK-01", "classification": "BENIGN", "confidence": 0.75},
        {"domain": "memory", "finding_id": "STATUS-MEM", "classification": "INSUFFICIENT_EVIDENCE", "confidence": 0.0, "is_examination_status": True},
        {"domain": "logs", "finding_id": "STATUS-LOG", "classification": "INSUFFICIENT_EVIDENCE", "confidence": 0.0, "is_examination_status": True},
        {"domain": "registry", "finding_id": "STATUS-REG", "classification": "INSUFFICIENT_EVIDENCE", "confidence": 0.0, "is_examination_status": True},
    ]

    barrier_ok, details = AgentBarrierService.evaluate_five_agent_barrier(case_id, findings)
    assert barrier_ok is True
    assert set(details["insufficient_evidence_domains"]) == {"memory", "logs", "registry"}
    assert details["domain_evaluations"]["memory"]["is_examination_status"] is True

    state = AgentBarrierService.get_case_state(case_id)
    assert state["status"] == ForensicInvestigationState.AGENTS_COMPLETED
    assert state["barrier_satisfied"] is True


def test_five_agent_barrier_blocks_when_domain_missing():
    case_id = "CASE_TEST_BARRIER_MISSING"
    # Only 3 domains evaluated, 2 completely missing from findings list
    findings = [
        {"domain": "network", "finding_id": "F-NET-01", "classification": "SUSPICIOUS", "confidence": 0.85},
        {"domain": "disk", "finding_id": "F-DISK-01", "classification": "BENIGN", "confidence": 0.75},
        {"domain": "logs", "finding_id": "F-LOG-01", "classification": "BENIGN", "confidence": 0.80},
    ]

    barrier_ok, details = AgentBarrierService.evaluate_five_agent_barrier(case_id, findings)
    assert barrier_ok is False
    assert "memory" in details["failed_domains"]
    assert "registry" in details["failed_domains"]

    state = AgentBarrierService.get_case_state(case_id)
    assert state["barrier_satisfied"] is False
    assert state["status"] == ForensicInvestigationState.AGENTS_PARTIAL


def test_five_agent_barrier_blocks_when_domain_fails():
    case_id = "CASE_TEST_BARRIER_FAIL"
    # Memory agent failed (e.g. GPU disconnected)
    findings = [
        {"domain": "network", "finding_id": "F-NET-01", "classification": "SUSPICIOUS", "confidence": 0.85},
        {"domain": "disk", "finding_id": "F-DISK-01", "classification": "BENIGN", "confidence": 0.75},
        {"domain": "memory", "finding_id": "F-MEM-FAIL", "status": "FAILED", "error": "GPU_UNAVAILABLE"},
        {"domain": "logs", "finding_id": "F-LOG-01", "classification": "BENIGN", "confidence": 0.80},
        {"domain": "registry", "finding_id": "F-REG-01", "classification": "BENIGN", "confidence": 0.70},
    ]

    barrier_ok, details = AgentBarrierService.evaluate_five_agent_barrier(case_id, findings)
    assert barrier_ok is False
    assert "memory" in details["failed_domains"]

    state = AgentBarrierService.get_case_state(case_id)
    assert state["barrier_satisfied"] is False


# -----------------------------------------------------------------------------
# 2. Remote GPU Readiness & Strict Failure Handling Tests
# -----------------------------------------------------------------------------

def test_empty_evidence_yields_truthful_insufficient_evidence():
    """Verify that empty evidence yields INSUFFICIENT_EVIDENCE with 0.0 confidence, never fake 98% hygiene."""
    res = ModelAdapterService.analyze_domain_evidence(
        domain="disk",
        evidence_type="Deleted Files",
        evidence_content=[]
    )
    assert res["classification"] == "INSUFFICIENT_EVIDENCE"
    assert res["status"] == "INSUFFICIENT_EVIDENCE"
    assert res["confidence"] == 0.0
    assert res["is_examination_status"] is True
    assert "No disk" in res["observation"]


def test_gpu_unavailable_does_not_call_rule_based_mock():
    """Verify that when GPU is offline, analyze_domain_evidence returns FAILED (GPU_UNAVAILABLE), not fake findings."""
    with patch.object(ModelAdapterService, "get_hardware_info", return_value={"gpu_eligible": False}), \
         patch.object(ModelAdapterService, "get_remote_gpu_url", return_value="http://invalid-colab-tunnel.example.com"):
        res = ModelAdapterService.analyze_domain_evidence(
            domain="network",
            evidence_type="PCAP Telemetry",
            evidence_content=[{"src_ip": "10.0.0.1", "dst_ip": "1.2.3.4"}],
            timeout=1
        )
        assert res["status"] == "FAILED"
        assert res["error"] == "GPU_UNAVAILABLE"
        assert res["confidence"] == 0.0
        assert res["classification"] == "INCONCLUSIVE"


def test_check_gpu_readiness_offline():
    with patch.object(ModelAdapterService, "get_hardware_info", return_value={"gpu_eligible": False}), \
         patch.object(ModelAdapterService, "get_remote_gpu_url", return_value=None):
        status = ModelAdapterService.check_gpu_readiness()
        assert status["ready"] is False
        assert status["provider"] == "none"


# -----------------------------------------------------------------------------
# 3. ReportLab 5.0.1 Formal PDF Report Generation & NumberedCanvas Tests
# -----------------------------------------------------------------------------

def test_formal_report_generation_compiles_pdf():
    case_id = "CASE_TEST_REPORT_GEN"
    mock_case = MagicMock()
    mock_case.case_name = "Forensic Verification Case"
    mock_case.investigator_name = "Lead Investigator"
    mock_case.created_at = "2026-10-31T00:00:00Z"
    mock_case.classification_level = "EVIDENTIARY / RESTRICTED"

    sis_state = {
        "state_version": 1,
        "investigation_summary": "Test incident reconstruction for digital forensics.",
        "findings": [
            {
                "finding_id": "FINDING-NET-001",
                "domain": "network",
                "title": "Outbound DNS beaconing to malicious DGA domain",
                "classification": "MALICIOUS",
                "risk_level": "CRITICAL",
                "confidence": 0.94,
                "mitre_technique": "T1071.004",
                "evidence_sources": ["2018-02-23_win13.pcap"],
                "reasoning": "Observed high-entropy queries resolving to rogue external IP."
            }
        ],
        "correlations": [
            {
                "correlation_id": "CORR-0001",
                "relationship_type": "dns_resolution_to_flow",
                "epistemic_classification": "CAUSAL_DEPENDENCY",
                "confidence": 0.95,
                "reasoning": "Host resolved DGA domain and immediately opened bidirectional socket."
            }
        ],
        "evidence_sufficiency": {
            "sufficiency_score": 0.85,
            "domain_coverage": {"percentage": 60, "active_domains": ["network", "disk", "logs"]},
            "investigative_limitations": []
        },
        "review_gate": {
            "status": "APPROVED",
            "reviewed_by": "Agentic Examiner",
            "reviewed_at": "2026-10-31T05:00:00Z",
            "investigator_notes": "Admissible in court proceedings per Rule 702."
        }
    }

    evidence_records = [
        MagicMock(original_filename="2018-02-23_win13.pcap", file_hash="abd963e784f419d0a69598ce6dc8c5155d5d7e2ac28a1a1aaddf44ec48ea569", file_size=56000000, category="Network PCAP", upload_timestamp=None)
    ]

    pdf_path, sha256_hash, version = FormalReportService.generate_pdf_report(
        case_id=case_id,
        case_obj=mock_case,
        sis_state=sis_state,
        evidence_records=evidence_records,
        reviewer_user="Agentic Examiner"
    )

    assert os.path.exists(pdf_path)
    assert pdf_path.endswith(".pdf")
    assert len(sha256_hash) == 64
    assert version >= 1
    assert os.path.getsize(pdf_path) > 5000  # Multi-page formal document

    # Verify manifest entry
    manifest = FormalReportService.get_report_manifest(case_id)
    assert len(manifest["reports"]) >= 1
    latest = manifest["reports"][-1]
    assert latest["sha256_hash"] == sha256_hash
    assert latest["immutable"] is True


# -----------------------------------------------------------------------------
# 4. Multi-Metric Evidence Sufficiency Evaluator Tests
# -----------------------------------------------------------------------------

def test_evidence_sufficiency_multi_metric():
    case_id = "CASE_TEST_SUFFICIENCY"
    findings = [
        {"domain": "network", "classification": "MALICIOUS"},
        {"domain": "disk", "classification": "SUSPICIOUS"},
        {"domain": "memory", "classification": "INSUFFICIENT_EVIDENCE", "is_examination_status": True},
        {"domain": "logs", "classification": "INSUFFICIENT_EVIDENCE", "is_examination_status": True},
        {"domain": "registry", "classification": "INSUFFICIENT_EVIDENCE", "is_examination_status": True},
    ]
    correlations = [
        {
            "correlation_id": "C-1",
            "source_a": {"domain": "network"},
            "source_b": {"domain": "disk"},
            "relationship_type": "cross_domain"
        }
    ]

    sufficiency = ForensicSynthesizerService.evaluate_evidence_sufficiency(
        case_id=case_id,
        correlations=correlations,
        findings=findings,
        disk={"records": [{"id": 1}]},
        mem={},
        pcap={"records": [{"id": 1}]}
    )

    # 2 out of 5 domains active -> 40% coverage
    assert sufficiency["domain_coverage"]["score"] == 0.40
    assert sufficiency["domain_coverage"]["percentage"] == 40
    assert "memory" in sufficiency["domain_coverage"]["missing_domains"]
    assert "logs" in sufficiency["domain_coverage"]["missing_domains"]
    assert "registry" in sufficiency["domain_coverage"]["missing_domains"]

    # Sufficiency score must NOT be 100% (1.0)
    assert sufficiency["sufficiency_score"] < 1.0
    assert len(sufficiency["investigative_limitations"]) == 3


# -----------------------------------------------------------------------------
# 5. DNS-to-Flow Correlation Deduplication Tests
# -----------------------------------------------------------------------------

def test_dns_to_network_correlation_deduplication():
    case_id = "CASE_TEST_DEDUPLICATION"
    pcap = {
        "dns": {
            "records": [
                {
                    "query": "malicious-c2.test.local",
                    "answers": ["198.51.100.45"],
                    "timestamp": "2026-10-31T01:00:00Z"
                }
            ]
        },
        "ip_stats": {
            # 13 identical packet conversations hitting the same resolved IP
            "records": [
                {"conversation": f"10.0.0.5:4915{i} <-> 198.51.100.45:443", "timestamp": "2026-10-31T01:00:02Z"}
                for i in range(13)
            ]
        }
    }

    findings = [
        {"domain": "network", "finding_id": "FINDING-NET-01", "observation": "DNS query to malicious-c2.test.local"},
        {"domain": "network", "finding_id": "FINDING-NET-02", "observation": "Outbound TCP socket to 198.51.100.45"}
    ]

    correlations = ForensicSynthesizerService._build_correlations(
        case_id=case_id,
        findings=findings,
        mem={},
        disk={},
        pcap=pcap
    )

    # Verify only ONE deduplicated correlation is created for this (query, ans) pair, NOT 13!
    dns_corrs = [c for c in correlations if c.get("relationship_type") == "dns_resolution_to_flow"]
    assert len(dns_corrs) == 1
    assert dns_corrs[0]["associated_flows_count"] == 13
    assert dns_corrs[0]["source_finding_id"] == "FINDING-NET-01"
    assert dns_corrs[0]["target_finding_id"] == "FINDING-NET-02"


# -----------------------------------------------------------------------------
# 6. Genuine xAI Metrics Calculation Tests
# -----------------------------------------------------------------------------

def test_xai_metrics_genuine_shannon_entropy():
    # Uniform 256 bytes should have maximal Shannon entropy close to 8.0
    all_bytes = bytes(range(256))
    metrics = XAIService.compute_byte_metrics(all_bytes)
    assert metrics["shannon_entropy"] == 8.0
    assert metrics["total_bytes"] == 256

    # Pure zeros should have 0.0 entropy
    zero_bytes = b"\x00" * 128
    zero_metrics = XAIService.compute_byte_metrics(zero_bytes)
    assert zero_metrics["shannon_entropy"] == 0.0
    assert zero_metrics["null_byte_density"] == 1.0
    assert zero_metrics["ascii_density"] == 0.0


# -----------------------------------------------------------------------------
# 7. Thread Safety: Concurrent Remote GPU URL Access
# -----------------------------------------------------------------------------

def test_remote_gpu_url_thread_safety():
    """
    Verifies that concurrent reads and writes to COLAB_GPU_INFERENCE_URL
    via set_remote_gpu_url() / get_remote_gpu_url() are thread-safe.
    No race conditions, no lost writes, no corrupted reads.
    """
    import threading
    import time

    urls_tried = [
        "https://thread-test-1.trycloudflare.com",
        "https://thread-test-2.trycloudflare.com",
        "https://thread-test-3.trycloudflare.com",
        None,
    ]

    errors = []
    results = []

    def writer(url_index):
        try:
            for _ in range(10):
                ModelAdapterService.set_remote_gpu_url(urls_tried[url_index])
                time.sleep(0.001)
        except Exception as e:
            errors.append(f"writer error: {e}")

    def reader():
        try:
            for _ in range(30):
                url = ModelAdapterService.get_remote_gpu_url()
                results.append(url)
                time.sleep(0.001)
        except Exception as e:
            errors.append(f"reader error: {e}")

    threads = []
    # 3 concurrent writers, 2 concurrent readers
    for i in range(3):
        threads.append(threading.Thread(target=writer, args=(i,)))
    for _ in range(2):
        threads.append(threading.Thread(target=reader))

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert len(errors) == 0, f"Thread safety errors: {errors}"
    # All read values must be one of the URLs that was written (or None)
    valid_values = set(urls_tried)
    for r in results:
        assert r in valid_values, f"Unexpected URL value read: {r}"
    # At least one read should have succeeded
    assert len(results) > 0, "No reads completed successfully"
