"""
SherlockAI — Correlation Engine Phase 1 Validation & Regression Test Suite.

Covers the 8 mandatory validation areas:
1. Process identity and PID reuse / inverted timestamps.
2. Registry persistence and executable correlation (ordered vs inverted).
3. DNS resolution and network-flow association (ordered vs inverted).
4. USB device presence versus evidence of data transfer (coincidental noise).
5. Missing, conflicting, and inverted timestamps in timeline reconstruction.
6. Duplicate evidence and repeated findings suppression (grouping by PID).
7. Missing source entities and unresolved graph edge diagnostics (no fabricated nodes).
8. Preservation of source provenance, target timestamps, and uncertainty.
"""

import json
import pytest
import datetime
from pathlib import Path
import networkx as nx

from app.services.synthesizer_service import ForensicSynthesizerService
from app.services.graph_service import EvidenceGraphService


# =============================================================================
# SYNTHETIC FIXTURES (Clearly labeled as synthetic for deterministic testing)
# =============================================================================

@pytest.fixture
def synthetic_base_case():
    return {
        "case_id": "SYNTHETIC_PHASE1_TEST_CASE",
        "findings": [],
        "mem": {},
        "disk": {},
        "pcap": {}
    }


# =============================================================================
# TEST 1: Process Identity and PID Reuse
# =============================================================================

def test_rule1_pid_reuse_inverted_timestamps(synthetic_base_case):
    """
    Validation Area 1: In Windows process lineage, a parent process MUST exist
    before its child (child CreateTime >= parent CreateTime).
    If child CreateTime precedes parent CreateTime (delta_sec < 0), this indicates
    PID reuse or conflicting system clock logs.
    The engine must NOT assume causality; it must flag ANOMALOUS_INVERTED_TIMESTAMPS,
    downgrade epistemic nature to AMBIGUOUS_ASSOCIATION, and cap confidence at <= 0.40.
    """
    case_id = synthetic_base_case["case_id"]

    # Inverted timestamps: child (PID 2000) was created at 10:00:00, but parent (PID 1000) was created at 10:15:00
    mem_inverted = {
        "processes": {
            "plugins": {
                "windows.pslist": [
                    {
                        "PID": 1000,
                        "PPID": 500,
                        "ImageFileName": "svchost.exe",
                        "CreateTime": "2026-10-23T10:15:00Z",
                        "Threads": 8
                    },
                    {
                        "PID": 2000,
                        "PPID": 1000,
                        "ImageFileName": "malware.exe",
                        "CreateTime": "2026-10-23T10:00:00Z",
                        "Threads": 2
                    }
                ]
            }
        },
        "threat_hunting": {
            "plugins": {
                "windows.malfind": [
                    {
                        "PID": 2000,
                        "Process": "malware.exe",
                        "Protection": "PAGE_EXECUTE_READWRITE",
                        "Start VPN": "0x400000"
                    }
                ]
            }
        }
    }

    correlations = ForensicSynthesizerService._build_correlations(
        case_id=case_id,
        findings=[],
        mem=mem_inverted,
        disk={},
        pcap={}
    )

    assert len(correlations) == 1
    corr = correlations[0]
    assert corr["relationship_type"] == "process_injection_chain"
    assert corr["temporal_status"] == "ANOMALOUS_INVERTED_TIMESTAMPS"
    assert corr["temporal_delta_seconds"] == -900.0  # Child 15 mins prior to parent
    assert corr["correlation_nature"] == "AMBIGUOUS_ASSOCIATION"
    assert corr["confidence"] <= 0.40
    assert "probable PID reuse" in corr["confidence_justification"]


def test_rule1_ordered_parent_child_chronology(synthetic_base_case):
    """
    Validation Area 1 (Positive): When parent was created before child,
    temporal status is CHRONOLOGICALLY_ORDERED and confidence is maintained.
    """
    case_id = synthetic_base_case["case_id"]

    mem_ordered = {
        "processes": {
            "plugins": {
                "windows.pslist": [
                    {
                        "PID": 1000,
                        "PPID": 500,
                        "ImageFileName": "explorer.exe",
                        "CreateTime": "2026-10-23T09:00:00Z",
                        "Threads": 16
                    },
                    {
                        "PID": 2000,
                        "PPID": 1000,
                        "ImageFileName": "cmd.exe",
                        "CreateTime": "2026-10-23T09:05:00Z",
                        "Threads": 2
                    }
                ]
            }
        },
        "threat_hunting": {
            "plugins": {
                "windows.malfind": [
                    {
                        "PID": 2000,
                        "Process": "cmd.exe",
                        "Protection": "PAGE_EXECUTE_READWRITE",
                        "Start VPN": "0x500000"
                    }
                ]
            }
        }
    }

    correlations = ForensicSynthesizerService._build_correlations(
        case_id=case_id,
        findings=[],
        mem=mem_ordered,
        disk={},
        pcap={}
    )

    assert len(correlations) == 1
    corr = correlations[0]
    assert corr["temporal_status"] == "CHRONOLOGICALLY_ORDERED"
    assert corr["temporal_delta_seconds"] == 300.0
    assert corr["correlation_nature"] == "CORROBORATED_HYPOTHESIS"
    assert corr["confidence"] >= 0.80


# =============================================================================
# TEST 2: Registry Persistence and Executable Correlation
# =============================================================================

def test_rule2_persistence_precedes_execution(synthetic_base_case):
    """
    Validation Area 2 (Positive): Registry Run key was written at 10:00:00,
    and Prefetch recorded execution at 10:02:00.
    Chronology confirms persistence preceded execution.
    """
    case_id = synthetic_base_case["case_id"]

    disk_data = {
        "run_keys": [
            {
                "name": "UpdaterService",
                "command": "C:\\Windows\\Temp\\update.exe -run",
                "last_write_time": "2026-10-23T10:00:00Z"
            }
        ],
        "prefetch_analysis": [
            {
                "executable_name": "update.exe",
                "last_run_time": "2026-10-23T10:02:00Z",
                "run_count": 1
            }
        ]
    }

    correlations = ForensicSynthesizerService._build_correlations(
        case_id=case_id,
        findings=[],
        mem={},
        disk=disk_data,
        pcap={}
    )

    assert len(correlations) == 1
    corr = correlations[0]
    assert corr["relationship_type"] == "persistence_to_execution"
    assert corr["temporal_status"] == "CHRONOLOGICALLY_ORDERED"
    assert corr["temporal_delta_seconds"] == 120.0
    assert corr["correlation_nature"] == "CORROBORATED_HYPOTHESIS"
    assert corr["confidence"] == 0.85


def test_rule2_inverted_prefetch_precedes_persistence(synthetic_base_case):
    """
    Validation Area 2 (Inverted): If Prefetch records execution at 08:00:00,
    but Registry Run key was not created until 10:00:00, the Run key persistence
    cannot have caused the 08:00:00 execution.
    Must flag ANOMALOUS_PREFETCH_PRECEDES_PERSISTENCE and downgrade to AMBIGUOUS_ASSOCIATION (0.35).
    """
    case_id = synthetic_base_case["case_id"]

    disk_data = {
        "run_keys": [
            {
                "name": "BackdoorRunKey",
                "command": "C:\\Temp\\malware.exe",
                "last_write_time": "2026-10-23T10:00:00Z"
            }
        ],
        "prefetch_analysis": [
            {
                "executable_name": "malware.exe",
                "last_run_time": "2026-10-23T08:00:00Z",
                "run_count": 3
            }
        ]
    }

    correlations = ForensicSynthesizerService._build_correlations(
        case_id=case_id,
        findings=[],
        mem={},
        disk=disk_data,
        pcap={}
    )

    assert len(correlations) == 1
    corr = correlations[0]
    assert corr["temporal_status"] == "ANOMALOUS_PREFETCH_PRECEDES_PERSISTENCE"
    assert corr["temporal_delta_seconds"] == -7200.0  # 2 hours prior
    assert corr["correlation_nature"] == "AMBIGUOUS_ASSOCIATION"
    assert corr["confidence"] == 0.35


# =============================================================================
# TEST 3: DNS Resolution and Network-Flow Association
# =============================================================================

def test_rule3_dns_precedes_network_flow(synthetic_base_case):
    """
    Validation Area 3 (Positive): DNS lookup resolves evil-c2.com to 198.51.100.99
    at 12:00:00, followed by TCP handshake with 198.51.100.99 at 12:00:01.
    Strict sequence + identical IP confirms DETERMINISTIC_GROUNDED (0.95).
    """
    case_id = synthetic_base_case["case_id"]

    pcap_data = {
        "dns": {
            "records": [
                {
                    "query": "evil-c2.com",
                    "answers": ["198.51.100.99"],
                    "timestamp": "2026-10-23T12:00:00Z",
                    "suspicious_dga": True
                }
            ]
        },
        "ip_stats": {
            "records": [
                {
                    "conversation": "192.168.1.100:49215 <-> 198.51.100.99:443",
                    "start_time": "2026-10-23T12:00:01Z",
                    "packets": 12
                }
            ]
        }
    }

    correlations = ForensicSynthesizerService._build_correlations(
        case_id=case_id,
        findings=[],
        mem={},
        disk={},
        pcap=pcap_data
    )

    assert len(correlations) == 1
    corr = correlations[0]
    assert corr["relationship_type"] == "dns_resolution_to_flow"
    assert corr["temporal_status"] == "CHRONOLOGICALLY_ORDERED"
    assert corr["temporal_delta_seconds"] == 1.0
    assert corr["correlation_nature"] == "DETERMINISTIC_GROUNDED"
    assert corr["confidence"] == 0.95


def test_rule3_flow_precedes_dns_anomaly(synthetic_base_case):
    """
    Validation Area 3 (Inverted): Outbound traffic occurred at 11:50:00, but DNS lookup
    for that IP was only logged at 12:00:00.
    The prior flow could not have been triggered by the subsequent DNS query.
    Must flag ANOMALOUS_FLOW_PRECEDED_DNS and downgrade to AMBIGUOUS_ASSOCIATION (0.45).
    """
    case_id = synthetic_base_case["case_id"]

    pcap_data = {
        "dns": {
            "records": [
                {
                    "query": "late-dns.com",
                    "answers": ["203.0.113.50"],
                    "timestamp": "2026-10-23T12:00:00Z"
                }
            ]
        },
        "ip_stats": {
            "records": [
                {
                    "conversation": "192.168.1.50:50123 <-> 203.0.113.50:80",
                    "start_time": "2026-10-23T11:50:00Z"
                }
            ]
        }
    }

    correlations = ForensicSynthesizerService._build_correlations(
        case_id=case_id,
        findings=[],
        mem={},
        disk={},
        pcap=pcap_data
    )

    assert len(correlations) == 1
    corr = correlations[0]
    assert corr["temporal_status"] == "ANOMALOUS_FLOW_PRECEDED_DNS"
    assert corr["temporal_delta_seconds"] == -600.0
    assert corr["correlation_nature"] == "AMBIGUOUS_ASSOCIATION"
    assert corr["confidence"] == 0.45


# =============================================================================
# TEST 4: USB Device Presence vs Data Transfer
# =============================================================================

def test_rule4_usb_presence_is_coincidental_noise(synthetic_base_case):
    """
    Validation Area 4: Removable USB device registration in registry (USBSTOR)
    without volume path or shellbag link must be classified as COINCIDENTAL_NOISE (0.15).
    It must NOT claim data exfiltration or malware launch.
    """
    case_id = synthetic_base_case["case_id"]

    disk_data = {
        "usb_devices": [
            {
                "device_name": "SanDisk Ultra USB 3.0",
                "serial_number": "4C531001331122114123",
                "last_connected": "2026-10-23T14:00:00Z",
                "values": {"FriendlyName": "SanDisk Ultra USB"}
            }
        ],
        "prefetch_analysis": [
            {
                "executable_name": "CALC.EXE",
                "last_run_time": "2026-10-23T14:05:00Z",
                "run_count": 5
            }
        ]
    }

    correlations = ForensicSynthesizerService._build_correlations(
        case_id=case_id,
        findings=[],
        mem={},
        disk=disk_data,
        pcap={}
    )

    assert len(correlations) == 1
    corr = correlations[0]
    assert corr["relationship_type"] == "usb_insertion_to_execution"
    assert corr["correlation_nature"] == "COINCIDENTAL_NOISE"
    assert corr["confidence"] == 0.15
    assert corr["temporal_status"] == "CIRCUMSTANTIAL_UNLINKED_PATH"
    # Ensure it dynamically used CALC.EXE and not hardcoded VMWARETRAY
    assert corr["source_b"]["artifact_id"] == "PREFETCH-CALC.EXE"
    assert "CALC.EXE" in corr["source_b"]["entity"]


# =============================================================================
# TEST 5: Missing, Conflicting, and Inverted Timestamps
# =============================================================================

def test_missing_timestamps_preservation_in_timeline(synthetic_base_case):
    """
    Validation Area 5: When an artifact has NO timestamp, the engine must NEVER
    substitute current workstation time (utcnow).
    The timestamp must remain None, flagged with UNAVAILABLE and UNRECORDED,
    and placed at the end of the chronological timeline.
    """
    case_id = synthetic_base_case["case_id"]

    disk_missing = {
        "prefetch_analysis": [
            {
                "executable_name": "unknown_tool.exe",
                "last_run_time": None,
                "run_count": 1
            }
        ],
        "usb_devices": [
            {
                "device_name": "Generic USB",
                "serial_number": "UNKNOWN_SER",
                "last_connected": None
            }
        ]
    }

    timeline = ForensicSynthesizerService._build_timeline(
        case_id=case_id,
        mem={},
        disk=disk_missing,
        pcap={}
    )

    assert len(timeline) == 2
    for event in timeline:
        assert event["timestamp"] is None or event["timestamp"] == "None"
        assert event["timestamp_quality"] == "UNAVAILABLE"
        assert event["timestamp_source"] == "UNRECORDED"


# =============================================================================
# TEST 6: Duplicate Evidence and Repeated Findings Suppression
# =============================================================================

def test_duplicate_malfind_findings_grouped_by_pid(synthetic_base_case):
    """
    Validation Area 6: In volatile memory analysis, multiple RWX allocations
    belonging to the same PID must be grouped into a single finding and a single
    correlation chain, rather than inflating finding counts.
    """
    case_id = synthetic_base_case["case_id"]

    mem_multi_vad = {
        "processes": {
            "plugins": {
                "windows.pslist": [
                    {
                        "PID": 4000,
                        "PPID": 1000,
                        "ImageFileName": "winlogon.exe",
                        "CreateTime": "2026-10-23T06:00:00Z"
                    }
                ]
            }
        },
        "threat_hunting": {
            "plugins": {
                "windows.malfind": [
                    {"PID": 4000, "Process": "winlogon.exe", "Protection": "PAGE_EXECUTE_READWRITE", "Start VPN": "0x100000"},
                    {"PID": 4000, "Process": "winlogon.exe", "Protection": "PAGE_EXECUTE_READWRITE", "Start VPN": "0x200000"},
                    {"PID": 4000, "Process": "winlogon.exe", "Protection": "PAGE_EXECUTE_READWRITE", "Start VPN": "0x300000"}
                ]
            }
        }
    }

    findings = ForensicSynthesizerService._build_findings(
        case_id=case_id,
        mem=mem_multi_vad,
        disk={},
        pcap={}
    )

    # Exactly 1 finding for winlogon.exe, noting 3 VAD allocations
    malfind_findings = [f for f in findings if "Suspicious Executable Memory Allocation" in f["title"]]
    assert len(malfind_findings) == 1
    assert "detected 3 unbacked executable memory allocation(s)" in malfind_findings[0]["description"]

    # Exactly 1 correlation chain for winlogon.exe
    correlations = ForensicSynthesizerService._build_correlations(
        case_id=case_id,
        findings=findings,
        mem=mem_multi_vad,
        disk={},
        pcap={}
    )
    assert len(correlations) == 1
    assert correlations[0]["source_b"]["vad_allocations_count"] == 3


# =============================================================================
# TEST 7: Missing Source Entities and Unresolved Graph Edges
# =============================================================================

def test_unresolved_graph_edge_diagnostics_without_fabrication(tmp_path):
    """
    Validation Area 7: If a correlation references a node that does NOT exist
    in evidence (e.g. PPID 9999 was not in the memory dump pslist), the Evidence
    Graph builder MUST NOT create a fabricated node to make the edge connect.
    Instead, it must emit a diagnostic in G.graph['unresolved_correlation_edges']
    and report it in get_graph_metrics.
    """
    # Create synthetic case output structure
    case_id = "SYNTHETIC_UNRESOLVED_TEST"
    base_cases = Path(ForensicSynthesizerService.get_case_output_dir(case_id))
    base_cases.mkdir(parents=True, exist_ok=True)

    extracted_dir = base_cases / "extracted_artifacts"
    extracted_dir.mkdir(parents=True, exist_ok=True)
    (extracted_dir / "memory").mkdir(exist_ok=True)

    # Pslist only has child PID 5000, parent PID 9999 is missing from dump
    pslist_content = {
        "plugins": {
            "windows.pslist": [
                {
                    "PID": 5000,
                    "PPID": 9999,
                    "ImageFileName": "orphan.exe",
                    "CreateTime": "2026-10-23T05:00:00Z"
                }
            ]
        }
    }
    with open(extracted_dir / "memory" / "processes.json", "w", encoding="utf-8") as f:
        json.dump(pslist_content, f)

    report_content = {
        "case_id": case_id,
        "findings": [],
        "artifacts": {
            "memory_processes": {
                "records": [
                    {"pid": 5000, "ppid": 9999, "process_name": "orphan.exe", "create_time": "2026-10-23T05:00:00Z"}
                ]
            }
        },
        "correlations": [
            {
                "correlation_id": "CORR-ORPHAN-01",
                "relationship_type": "process_injection_chain",
                "correlation_nature": "CORROBORATED_HYPOTHESIS",
                "confidence": 0.80,
                "source_a": {"domain": "memory", "artifact_id": "PID-9999", "entity": "Unknown"},
                "source_b": {"domain": "memory", "artifact_id": "PID-5000", "entity": "orphan.exe"}
            }
        ]
    }
    with open(base_cases / "synthesized_report.json", "w", encoding="utf-8") as f:
        json.dump(report_content, f)

    # Build evidence graph
    G = EvidenceGraphService.build_case_evidence_graph(case_id)

    # Assert no fabricated node was created for PID 9999
    assert f"process:{case_id}:9999" not in G

    # Assert diagnostic was emitted
    metrics = EvidenceGraphService.get_graph_metrics(G)
    assert metrics["unresolved_correlation_edges_count"] == 1
    diag = metrics["unresolved_correlation_edges"][0]
    assert diag["correlation_id"] == "CORR-ORPHAN-01"
    assert "source_a: PID-9999" in diag["unresolved_reasons"][0]
    assert "Correlation edge dropped from active graph" in diag["diagnostic"]


# =============================================================================
# TEST 8: Preservation of Source Provenance and Uncertainty
# =============================================================================

def test_source_provenance_and_uncertainty_preservation(synthetic_base_case):
    """
    Validation Area 8: Target host timestamps from 2012 must be preserved faithfully,
    and analysis runtime must be separated into analysis_timestamp.
    Correlation records must expose temporal_delta_seconds and temporal_status.
    """
    case_id = synthetic_base_case["case_id"]

    mem_2012 = {
        "threat_hunting": {
            "generated_at": "2026-09-18T14:40:22Z",
            "plugins": {
                "windows.malfind": [
                    {
                        "PID": 1234,
                        "Process": "winlogon.exe",
                        "Protection": "PAGE_EXECUTE_READWRITE",
                        "Offset": 1048576
                    }
                ]
            }
        },
        "processes": {
            "plugins": {
                "windows.pslist": [
                    {
                        "PID": 1234,
                        "PPID": 400,
                        "ImageFileName": "winlogon.exe",
                        "CreateTime": "2012-07-22T17:34:01Z",
                        "Threads": 4
                    }
                ]
            }
        }
    }

    timeline = ForensicSynthesizerService._build_timeline(
        case_id=case_id,
        mem=mem_2012,
        disk={},
        pcap={}
    )

    inj_event = next(e for e in timeline if e["event_type"] == "Code Injection")
    # Must preserve the 2012 target host process creation time, NOT 2026!
    assert inj_event["timestamp"] == "2012-07-22T17:34:01Z"
    assert inj_event["timestamp_quality"] == "APPROXIMATE_HOST_PROCESS_LIFETIME"
    assert inj_event["analysis_timestamp"] == "2026-09-18T14:40:22Z"


# =============================================================================
# PHASE 2A AUDIT TESTS: Graph Semantics, is_causal Flag & Diagnostic Integrity
# =============================================================================

def test_graph_edge_is_causal_and_artifact_id_integrity():
    """
    Phase 2A Audit Test:
    1. Verifies that correlation edges store explicit 'is_causal' booleans (False for coincidental noise).
    2. Verifies that correlation edges preserve 'source_artifact_id' and 'target_artifact_id'.
    3. Verifies that CORR-0003 remains unhallucinated in diagnostics for CASE_ALL5_F1A5D2.
    4. Verifies exact node and edge count accounting.
    """
    case_id = "CASE_ALL5_F1A5D2"
    G = EvidenceGraphService.build_case_evidence_graph(case_id)

    # 1. Inspect USB coincidental noise edge
    usb_edge = None
    for u, v, d in G.edges(data=True):
        if d.get("relationship_type") == "USB_INSERTION_TO_EXECUTION":
            usb_edge = d
            break

    assert usb_edge is not None
    assert usb_edge["nature"] == "COINCIDENTAL_NOISE"
    assert usb_edge["is_causal"] is False  # Must explicitly mark coincidental noise as non-causal
    assert usb_edge["confidence"] == 0.15
    assert "source_artifact_id" in usb_edge
    assert "target_artifact_id" in usb_edge

    # 2. Inspect Process Injection causal hypothesis edge
    proc_edge = None
    for u, v, d in G.edges(data=True):
        if d.get("relationship_type") == "PROCESS_INJECTION_CHAIN":
            proc_edge = d
            break

    assert proc_edge is not None
    assert proc_edge["nature"] == "CORROBORATED_HYPOTHESIS"
    assert proc_edge["is_causal"] is True  # Causal hypothesis flagged as causal candidate
    assert proc_edge["confidence"] >= 0.80

    # 3. Verify CORR-0003 unresolved diagnostic
    metrics = EvidenceGraphService.get_graph_metrics(G)
    assert metrics["unresolved_correlation_edges_count"] == 1
    unres = metrics["unresolved_correlation_edges"][0]
    assert unres["correlation_id"] == "CORR-0003"
    assert "PID-1464" in unres["unresolved_reasons"][0]

    # 4. Verify exact node count equals sum of distribution
    total_nodes = metrics["total_nodes"]
    node_dist = metrics["node_distribution"]
    assert total_nodes == sum(node_dist.values())
    assert total_nodes == 79

    # 5. Verify exact edge count equals sum of distribution
    total_edges = metrics["total_edges"]
    rel_dist = metrics["relationship_distribution"]
    assert total_edges == sum(rel_dist.values())
    assert total_edges == 94

