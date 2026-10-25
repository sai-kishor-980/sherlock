"""
Unit & Integration Test Suite for Explainable Multi-Agent Correlation Engine.
Tests all 6 correlation rules, epistemic classification, timeline building, and graph output.
"""

import pytest
from app.services.correlation_engine import (
    ExplainableCorrelationEngine,
    CorrelationEpistemicClass,
    TypedEntityExtractor
)


def test_rule_1_process_lineage():
    findings = [
        {
            "finding_id": "F-LOG-01",
            "agent": "logs",
            "observation": "Process creation recorded for powershell.exe with PID 4120",
            "entities": [{"executable": "powershell.exe", "pid": "4120"}],
            "timeline": {"timestamp_utc": "2026-09-15T08:24:45Z"}
        },
        {
            "finding_id": "F-MEM-01",
            "agent": "memory",
            "observation": "Memory inspection found injected thread in PID 4120 (powershell.exe)",
            "entities": [{"executable": "powershell.exe", "pid": "4120"}],
            "timeline": {"timestamp_utc": "2026-09-15T08:25:00Z"}
        }
    ]
    res = ExplainableCorrelationEngine.correlate_case_findings(findings, case_id="TEST-CASE")
    edges = res["correlation_edges"]
    assert len(edges) >= 1
    edge = edges[0]
    assert edge["rule_id"] == "RULE-PROC-01"
    assert edge["epistemic_class"] == CorrelationEpistemicClass.CAUSAL_DEPENDENCY
    assert edge["confidence"] == 0.98


def test_rule_2_persistence_to_execution():
    findings = [
        {
            "finding_id": "F-REG-01",
            "agent": "registry",
            "artifact_type": "Registry Run Key",
            "observation": "Persistence key for update_svc.exe",
            "entities": [{"executable": "C:\\Windows\\Temp\\update_svc.exe"}],
            "timeline": {"timestamp_utc": "2026-09-15T08:23:00Z"}
        },
        {
            "finding_id": "F-DISK-01",
            "agent": "disk",
            "artifact_type": "Windows Prefetch",
            "observation": "Prefetch execution recorded for update_svc.exe with 5 runs",
            "entities": [{"executable": "update_svc.exe"}],
            "timeline": {"timestamp_utc": "2026-09-15T08:23:30Z"}
        }
    ]
    res = ExplainableCorrelationEngine.correlate_case_findings(findings, case_id="TEST-CASE")
    edges = [e for e in res["correlation_edges"] if e["rule_id"] == "RULE-PERSIST-01"]
    assert len(edges) == 1
    assert edges[0]["epistemic_class"] == CorrelationEpistemicClass.CAUSAL_DEPENDENCY
    assert "update_svc.exe" in edges[0]["reasoning"]


def test_rule_4_network_to_process():
    findings = [
        {
            "finding_id": "F-NET-01",
            "agent": "network",
            "observation": "DNS beaconing to evil-c2.org (185.220.101.5)",
            "entities": [{"domain": "evil-c2.org", "ip": "185.220.101.5"}],
            "timeline": {"timestamp_utc": "2026-09-15T08:25:00Z"}
        },
        {
            "finding_id": "F-LOG-01",
            "agent": "logs",
            "observation": "PowerShell command downloading payload from 185.220.101.5",
            "entities": [{"executable": "powershell.exe", "ip": "185.220.101.5"}],
            "timeline": {"timestamp_utc": "2026-09-15T08:24:45Z"}
        }
    ]
    res = ExplainableCorrelationEngine.correlate_case_findings(findings, case_id="TEST-CASE")
    edges = [e for e in res["correlation_edges"] if e["rule_id"] == "RULE-NET-01"]
    assert len(edges) == 1
    assert edges[0]["epistemic_class"] == CorrelationEpistemicClass.CAUSAL_DEPENDENCY
    assert "185.220.101.5" in str(edges[0]["matched_entities"])


def test_rule_6_temporal_sequence_coincidental_noise():
    """Events close in time but with zero shared entities must be classified as COINCIDENTAL_NOISE."""
    findings = [
        {
            "finding_id": "F-DISK-BENIGN",
            "agent": "disk",
            "observation": "Benign print driver executed: printui.exe",
            "entities": [{"executable": "printui.exe"}],
            "timeline": {"timestamp_utc": "2026-09-15T08:20:00Z"}
        },
        {
            "finding_id": "F-NET-UNKNOWN",
            "agent": "network",
            "observation": "Unrelated NTP time synchronization packet to pool.ntp.org",
            "entities": [{"domain": "pool.ntp.org", "ip": "192.168.1.1"}],
            "timeline": {"timestamp_utc": "2026-09-15T08:20:10Z"}
        }
    ]
    res = ExplainableCorrelationEngine.correlate_case_findings(findings, case_id="TEST-CASE")
    edges = [e for e in res["correlation_edges"] if e["rule_id"] == "RULE-TIME-01"]
    assert len(edges) == 1
    # Zero entity overlap -> flagged as COINCIDENTAL_NOISE
    assert edges[0]["epistemic_class"] == CorrelationEpistemicClass.COINCIDENTAL_NOISE
    assert edges[0]["confidence"] <= 0.50


def test_full_graph_and_narrative_generation():
    findings = [
        {
            "finding_id": "F-REG-01",
            "agent": "registry",
            "entities": [{"executable": "beacon.exe"}],
            "observation": "Run key persistence for beacon.exe",
            "timeline": {"timestamp_utc": "2026-09-15T08:20:00Z"}
        },
        {
            "finding_id": "F-DISK-01",
            "agent": "disk",
            "entities": [{"executable": "beacon.exe"}],
            "observation": "Prefetch execution for beacon.exe",
            "timeline": {"timestamp_utc": "2026-09-15T08:21:00Z"}
        },
        {
            "finding_id": "F-NET-01",
            "agent": "network",
            "entities": [{"ip": "10.0.0.1"}],
            "observation": "C2 socket opened",
            "timeline": {"timestamp_utc": "2026-09-15T08:22:00Z"}
        }
    ]
    res = ExplainableCorrelationEngine.correlate_case_findings(findings, case_id="CASE_E2E")
    assert res["evidence_graph"]["total_nodes"] == 3
    assert len(res["unified_timeline"]) == 3
    assert "beacon.exe" in res["incident_narrative"]
