"""
Regression test suite for Neo4j Knowledge Graph Integration,
4-Class Epistemic Classification, Evidence Sufficiency Gap Routing,
Pre-SIS Lifecycle, and Domain LoRA Output Normalization.
"""

import os
import json
import pytest
from pathlib import Path

from app.services.neo4j_service import Neo4jService
from app.services.synthesizer_service import (
    ForensicSynthesizerService,
    CorrelationEpistemicClass
)
from app.services.model_adapter_service import ModelAdapterService
from app.services.graph_service import EvidenceGraphService


def test_neo4j_offline_resilience_and_cypher_export(tmp_path):
    """
    Verifies that Neo4jService gracefully handles offline status
    and generates valid standalone Cypher export statements.
    """
    status = Neo4jService.test_connection()
    assert status["status"] in ["ONLINE", "OFFLINE"]
    assert "7687" in status["uri"] or "bolt" in status["uri"]

    case_id = "TEST-NEO4J-001"
    evidence = [
        {"evidence_id": "EV-01", "name": "disk.raw", "type": "DISK", "sha256": "abcdef123456"}
    ]
    artifacts = [
        {
            "artifact_id": "ART-01",
            "domain": "memory",
            "category": "process",
            "timestamp": "2026-10-23T12:00:00Z",
            "confidence": 0.95,
            "description": "Suspicious injected process"
        },
        {
            "artifact_id": "ART-02",
            "domain": "disk",
            "category": "prefetch",
            "timestamp": "2026-10-23T12:05:00Z",
            "confidence": 0.85,
            "description": "Prefetch execution record"
        }
    ]
    correlations = [
        {
            "source_id": "ART-01",
            "target_id": "ART-02",
            "relationship_type": "persistence_to_execution",
            "epistemic_classification": CorrelationEpistemicClass.CAUSAL_DEPENDENCY,
            "confidence": 0.85,
            "uncertainty_score": 0.15,
            "reasoning": "Direct causal chain from persistence to execution"
        }
    ]
    techniques = [
        {"technique_id": "T1547.001", "name": "Registry Run Keys", "tactic": "Persistence", "artifact_id": "ART-02"}
    ]

    cypher_script = Neo4jService.generate_cypher_export(
        case_id=case_id,
        case_name="Test Neo4j Case",
        evidence_list=evidence,
        artifacts=artifacts,
        correlations=correlations,
        techniques=techniques
    )

    assert "MERGE (c:Case {case_id: 'TEST-NEO4J-001'})" in cypher_script
    assert "MERGE (e:Evidence {evidence_id: 'EV-01'})" in cypher_script
    assert "MERGE (a:Artifact {artifact_id: 'ART-01'})" in cypher_script
    assert ":CAUSAL_DEPENDENCY" in cypher_script
    assert "T1547.001" in cypher_script

    # Verify sync_case_graph creates neo4j_export.cypher file
    res = Neo4jService.sync_case_graph(
        case_id=case_id,
        case_name="Test Case",
        evidence_list=evidence,
        artifacts=artifacts,
        correlations=correlations,
        techniques=techniques,
        output_dir=tmp_path
    )

    export_file = tmp_path / "neo4j_export.cypher"
    assert export_file.exists()
    assert export_file.stat().st_size > 0
    assert res["neo4j_status"] in ["ONLINE", "OFFLINE_EXPORT_READY"]


def test_4class_epistemic_classification_and_uncertainty():
    """
    Verifies that synthesizer outputs adhere to the 4 epistemic buckets:
    CAUSAL_DEPENDENCY, CORRELATIONAL_ASSOCIATION, COINCIDENTAL_NOISE, AMBIGUOUS_UNKNOWN.
    Also verifies uncertainty score = 1.0 - confidence.
    """
    case_id = "DISK_2"
    synthesized = ForensicSynthesizerService.synthesize_case(case_id)
    correlations = synthesized.get("correlations", [])

    assert len(correlations) > 0

    valid_classes = {
        CorrelationEpistemicClass.CAUSAL_DEPENDENCY,
        CorrelationEpistemicClass.CORRELATIONAL_ASSOCIATION,
        CorrelationEpistemicClass.COINCIDENTAL_NOISE,
        CorrelationEpistemicClass.AMBIGUOUS_UNKNOWN
    }

    for c in correlations:
        epistemic = c.get("epistemic_classification")
        assert epistemic in valid_classes, f"Unexpected epistemic classification: {epistemic}"

        conf = c.get("confidence", 0.0)
        uncertainty = c.get("uncertainty_score")
        assert uncertainty is not None
        assert abs(uncertainty - round(1.0 - conf, 3)) < 1e-4

        grounded = c.get("grounded_evidence")
        assert isinstance(grounded, list)
        assert len(grounded) > 0


def test_evidence_sufficiency_evaluation_and_gap_routing():
    """
    Verifies that evaluate_evidence_sufficiency identifies gaps and emits
    targeted recommendations for UploadService.
    """
    correlations = [
        {
            "correlation_id": "CORR-001",
            "relationship_type": "process_injection_chain",
            "source_a": {"artifact_id": "PID-9999", "entity": "evil_parent.exe"}
        }
    ]
    findings = []
    disk = {"services_installed": [{"service_name": "TestSvc", "image_path": "C:\\drivers\\bad.sys"}]}
    mem = {"processes": {"plugins": {"windows.pslist": [{"PID": 100}]}}}  # PID 9999 is missing!
    pcap = {"dns": {"records": [{"query": "bad.com"}]}}  # Network flow is missing!

    sufficiency = ForensicSynthesizerService.evaluate_evidence_sufficiency(
        case_id="TEST-SUFF",
        correlations=correlations,
        findings=findings,
        disk=disk,
        mem=mem,
        pcap=pcap
    )

    assert sufficiency["sufficiency_score"] < 1.0
    assert sufficiency["total_gaps"] >= 2

    gap_types = [g["gap_type"] for g in sufficiency["detected_gaps"]]
    assert "MISSING_PARENT_PROCESS_TELEMETRY" in gap_types
    assert "MISSING_PCAP_PACKET_FLOWS" in gap_types

    # Recommendations must target UploadService
    recs = sufficiency["upload_engine_recommendations"]
    assert len(recs) >= 2
    for r in recs:
        assert r["target_engine"] == "UploadService"


def test_pre_sis_generation_and_review_gate(tmp_path):
    """
    Verifies that _build_pre_sis_state outputs pre_sis_state.json with PENDING_INVESTIGATOR_REVIEW,
    and review_pre_sis properly promotes to APPROVED_LOCKED.
    """
    case_id = "Bharath_TES1"
    synthesized = ForensicSynthesizerService.synthesize_case(case_id)

    pre_sis = synthesized.get("pre_sis_state")
    assert pre_sis is not None
    assert pre_sis["investigation_status"] == "PRE_SIS_CANDIDATE"
    assert pre_sis["review_gate"]["status"] == "PENDING_INVESTIGATOR_REVIEW"

    case_dir = ForensicSynthesizerService.get_case_output_dir(case_id)
    pre_sis_file = case_dir / "pre_sis_state.json"
    assert pre_sis_file.exists()

    # Approve Pre-SIS gate
    approved = ForensicSynthesizerService.review_pre_sis(
        case_id=case_id,
        action="APPROVE",
        reviewer="Lead Investigator Smith",
        notes="All candidate causal links corroborated."
    )

    assert approved["investigation_status"] == "APPROVED_LOCKED"
    assert approved["review_gate"]["status"] == "APPROVED"
    assert approved["review_gate"]["reviewed_by"] == "Lead Investigator Smith"

    # Verify official sis_state.json is now promoted and locked
    sis_file = case_dir / "sis_state.json"
    assert sis_file.exists()
    with open(sis_file, "r", encoding="utf-8") as sf:
        sis_data = json.load(sf)
    assert sis_data["investigation_status"] == "APPROVED_LOCKED"


def test_model_adapter_output_normalization():
    """
    Verifies that ModelAdapterService.normalize_agent_output validates and standardizes
    both dictionary and natural language string outputs into the AgentFinding contract.
    """
    # Test dictionary input
    raw_dict = {
        "classification": "malicious",
        "risk_level": "critical",
        "reasoning": "Detected Cobalt Strike beacon network communication pattern.",
        "key_evidence": ["Periodic C2 beaconing on port 443"]
    }
    norm1 = ModelAdapterService.normalize_agent_output(raw_dict, domain="network", evidence_type="pcap")
    assert norm1["domain"] == "network"
    assert norm1["classification"] == "MALICIOUS"
    assert norm1["risk_level"] == "CRITICAL"
    assert norm1["contract_validated"] is True

    # Test free-text LLM generation string input
    raw_text = (
        "1. Classification: Suspicious Activity\n"
        "2. Risk level: High\n"
        "3. Reasoning: Unhosted svchost.exe process was observed executing from non-system path.\n"
        "4. Key evidence:\n"
        "- Suspicious parent PID 1234\n"
        "- Image path in AppData"
    )
    norm2 = ModelAdapterService.normalize_agent_output(raw_text, domain="memory", evidence_type="process")
    assert norm2["domain"] == "memory"
    assert norm2["classification"] == "SUSPICIOUS"
    assert norm2["risk_level"] == "HIGH"
    assert "Unhosted svchost.exe" in norm2["reasoning"]
    assert len(norm2["key_evidence"]) == 2
    assert norm2["contract_validated"] is True
