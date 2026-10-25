"""
Sprint 2 Automated Regression Tests — Threat Knowledge and Evidence Graph.
Tests:
1. MITRE ATT&CK STIX 2.1 ingestion, source metadata provenance, and ChromaDB persistence.
2. Ingestion idempotency (duplicate prevention on reruns).
3. Vector similarity search and tactic filtering.
4. Evidence Graph construction with typed nodes and relationship natures.
5. Evidence Graph serialization and reloading.
6. End-to-end evidentiary trace: source artifact -> observation -> finding -> ATT&CK mapping.
7. Graceful error handling for missing evidence/cases.
"""

import os
import json
import pytest
from pathlib import Path

from app.services.knowledge_service import KnowledgeService
from app.services.graph_service import EvidenceGraphService


@pytest.fixture(scope="module")
def sample_case_id():
    # Use existing verified test case
    return "CASE_ALL5_F1A5D2"


def test_mitre_attack_source_metadata():
    """
    Verifies that official MITRE ATT&CK STIX 2.1 source metadata is preserved with SHA-256 digest.
    """
    meta = KnowledgeService.get_source_metadata()
    assert "source_url" in meta
    assert "retrieval_date" in meta
    assert "sha256_hash" in meta
    assert meta["stix_version"] == "2.1"
    assert meta["attack_version"] == "20.0"
    assert meta["total_stix_objects"] > 20000


def test_mitre_attack_ingestion_and_idempotence():
    """
    Verifies that ATT&CK ingestion into ChromaDB is 100% idempotent and prevents duplicates.
    """
    # First check / ingestion
    stats1 = KnowledgeService.ingest_mitre_attack()
    count1 = stats1["collection_count"]
    assert count1 >= 700

    # Rerun ingestion (must not increase count)
    stats2 = KnowledgeService.ingest_mitre_attack()
    count2 = stats2["collection_count"]
    assert count1 == count2, f"Idempotence failed: count changed from {count1} to {count2}"


def test_mitre_vector_search_and_exact_lookup():
    """
    Verifies semantic vector search and exact technique ID lookup.
    """
    # 1. Semantic search for Process Injection
    results = KnowledgeService.search_techniques("reflective memory injection into remote process", n_results=3)
    assert len(results) > 0
    top_hit = results[0]
    assert "T1055" in top_hit["technique_id"] or "T1620" in top_hit["technique_id"]
    assert top_hit["similarity_score"] > 0.40

    # 2. Exact lookup
    t1055 = KnowledgeService.get_technique_by_id("T1055")
    assert t1055 is not None
    assert t1055["name"] == "Process Injection"
    assert "defense-evasion" in t1055["tactics"] or "privilege-escalation" in t1055["tactics"]
    assert t1055["stix_id"].startswith("attack-pattern--")


def test_evidence_graph_construction(sample_case_id):
    """
    Verifies Evidence Graph construction with explicit entity types and edge relationship natures.
    """
    G = EvidenceGraphService.build_case_evidence_graph(sample_case_id)
    assert G.number_of_nodes() > 20
    assert G.number_of_edges() > 20

    metrics = EvidenceGraphService.get_graph_metrics(G)
    nodes_by_type = metrics["node_distribution"]

    # Verify all distinct entity types exist
    assert "case" in nodes_by_type
    assert "evidence" in nodes_by_type
    assert "artifact" in nodes_by_type
    assert "process" in nodes_by_type
    assert "finding" in nodes_by_type
    assert "mitre_technique" in nodes_by_type

    # Verify edge natures
    natures = metrics["nature_distribution"]
    assert "OBSERVED_FACT" in natures
    assert "CORROBORATED_HYPOTHESIS" in natures
    assert "ATTACK_MAPPING" in natures


def test_evidence_graph_persistence_and_reload(sample_case_id, tmp_path):
    """
    Verifies graph JSON serialization and lossless reload.
    """
    G = EvidenceGraphService.build_case_evidence_graph(sample_case_id)
    saved_path = EvidenceGraphService.save_graph(G, sample_case_id)
    assert saved_path.exists()

    reloaded_G = EvidenceGraphService.load_graph(sample_case_id)
    assert reloaded_G is not None
    assert reloaded_G.number_of_nodes() == G.number_of_nodes()
    assert reloaded_G.number_of_edges() == G.number_of_edges()


def test_technique_provenance_trace(sample_case_id):
    """
    Demonstrates a complete evidentiary trace:
    ATT&CK Technique (T1055) -> Finding -> Process Observation -> Artifact -> Raw Evidence.
    """
    G = EvidenceGraphService.build_case_evidence_graph(sample_case_id)
    traces = EvidenceGraphService.trace_technique_provenance(G, "T1055")
    assert len(traces) > 0, "No provenance trace found for T1055"

    sample_trace = traces[0]
    assert sample_trace["technique"]["technique_id"] == "T1055"
    assert sample_trace["mapping_edge"]["relationship"] == "MAPPED_TO_TECHNIQUE"
    assert sample_trace["mapping_edge"]["nature"] == "ATTACK_MAPPING"
    assert "finding" in sample_trace
    assert sample_trace["observation"]["entity_type"] == "process"
    assert len(sample_trace["supporting_artifacts"]) > 0


def test_missing_evidence_safe_handling():
    """
    Verifies that requesting a graph for a non-existent case fails gracefully.
    """
    non_existent_id = "CASE_NON_EXISTENT_999999"
    G = EvidenceGraphService.build_case_evidence_graph(non_existent_id)
    assert G.number_of_nodes() >= 1  # Only the root case node
    traces = EvidenceGraphService.trace_technique_provenance(G, "T1055")
    assert traces == []
