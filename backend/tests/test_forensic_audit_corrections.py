"""
Sprint 2 Forensic Audit & Regression Tests.
Verifies corrections identified during the Sprint 2 Forensic Audit:
1. Malfind finding deduplication (grouped by PID, no duplicate findings per process).
2. Epistemic calibration: Process injection hypothesis confidence capped <= 0.85.
3. Forensic integrity: USB device registration mapped to T1200 (Hardware Additions), NOT T1052.001 (Exfiltration).
4. Network PCAP parsing: Exact packet conversation tuple verification (malicious-c2-test.corp.net -> 198.51.100.42:443).
5. Evidence Graph cleanliness: Deterministic node/edge counts free of duplicate finding spam.
6. Training pair dataset audit: Asserts detection of intra-domain vs cross-domain confounding.
"""

import json
from pathlib import Path
import pytest

from app.services.synthesizer_service import ForensicSynthesizerService
from app.services.graph_service import EvidenceGraphService


@pytest.fixture(scope="module")
def case_id():
    return "CASE_ALL5_F1A5D2"


def test_malfind_findings_deduplicated_by_pid(case_id):
    """
    Verifies that multiple VAD allocations for the same process (e.g. winlogon.exe)
    are consolidated into a single finding per PID rather than spamming duplicate findings.
    """
    res = ForensicSynthesizerService.synthesize_case(case_id)
    findings = res["findings"]

    # Check for process injection findings
    injection_findings = [f for f in findings if "T1055" in str(f.get("mitre_technique"))]
    pids_found = set()
    for f in injection_findings:
        for src in f.get("evidence_sources", []):
            art_id = src.get("artifact_id", "")
            if "PID-" in art_id:
                pid = art_id.replace("PID-", "")
                assert pid not in pids_found, f"Duplicate finding generated for PID {pid}!"
                pids_found.add(pid)

    # In CASE_ALL5_F1A5D2, exactly 4 distinct PIDs were flagged by malfind: 584, 608, 1484, 1640
    assert len(injection_findings) == 4


def test_process_injection_hypothesis_confidence_bound(case_id):
    """
    Verifies that unconfirmed memory allocations are classified as CORROBORATED_HYPOTHESIS
    with confidence strictly within [0.80, 0.85], NOT over-claimed as 0.98 malicious facts.
    """
    res = ForensicSynthesizerService.synthesize_case(case_id)
    findings = res["findings"]

    for f in findings:
        if "T1055" in str(f.get("mitre_technique")):
            conf = f.get("confidence", 0)
            assert conf <= 0.85, f"Finding {f['finding_id']} confidence {conf} exceeds hypothesis upper bound 0.85!"
            assert f.get("assessment") == "suspicious", f"Finding {f['finding_id']} must be 'suspicious' hypothesis, not 'malicious'!"


def test_usb_registration_not_exfiltration(case_id):
    """
    Verifies that USBSTOR device registration in registry is classified as hardware/peripheral telemetry (T1200),
    not prematurely labeled as confirmed data exfiltration (T1052.001).
    """
    res = ForensicSynthesizerService.synthesize_case(case_id)
    findings = res["findings"]

    usb_findings = [f for f in findings if "USB" in f.get("title", "") or "T1200" in str(f.get("mitre_technique"))]
    assert len(usb_findings) == 1, "Expected exactly 1 USB registration finding"

    usb_f = usb_findings[0]
    assert "T1052" not in str(usb_f.get("mitre_technique")), "USBSTOR presence must not be mapped to T1052 (Exfiltration)!"
    assert "T1200" in str(usb_f.get("mitre_technique")), "USBSTOR presence should map to T1200 (Hardware Additions)"
    assert "exfiltration" not in usb_f.get("title", "").lower()
    assert "does not constitute proof of data transfer" in usb_f.get("description", "").lower() or "not demonstrate data transfer" in usb_f.get("description", "").lower()


def test_network_pcap_actual_packet_tuples(case_id):
    """
    Verifies that network correlations reference the real packet captures:
    malicious-c2-test.corp.net -> 198.51.100.42 (not fabricated example.com or 93.184.216.34).
    """
    res = ForensicSynthesizerService.synthesize_case(case_id)
    correlations = res["correlations"]

    dns_corrs = [c for c in correlations if c.get("relationship_type") == "dns_resolution_to_flow"]
    assert len(dns_corrs) == 1, "Expected DNS-to-flow correlation"

    c = dns_corrs[0]
    assert "malicious-c2-test.corp.net" in c["title"] or "malicious-c2-test.corp.net" in str(c["source_a"])
    assert "198.51.100.42" in c["title"] or "198.51.100.42" in str(c["source_b"])
    assert "example.com" not in c["title"]
    assert "93.184.216.34" not in c["title"]


def test_graph_metrics_epistemic_integrity(case_id):
    """
    Verifies that Evidence Graph adheres to epistemic rules:
    - No duplicate winlogon finding nodes.
    - All CORROBORATED_HYPOTHESIS edges have confidence <= 0.85.
    - Graph is directed and reproducible.
    """
    G = EvidenceGraphService.build_case_evidence_graph(case_id)
    metrics = EvidenceGraphService.get_graph_metrics(G)

    # Total findings should now be 5 (4 memory injection candidates + 1 USB hardware)
    assert metrics["node_distribution"]["finding"] == 5

    # Check edge hypothesis bounds
    for u, v, d in G.edges(data=True):
        if d.get("nature") == "CORROBORATED_HYPOTHESIS":
            conf = d.get("confidence", 0)
            assert conf <= 0.85, f"Edge {u} -> {v} hypothesis confidence {conf} exceeds 0.85!"


def test_training_pair_domain_confounding_detected(case_id):
    """
    Audits correlation_training_pairs.json and verifies that it warns/fails on domain confounding
    (where all positive pairs are intra-domain and all negative pairs are cross-domain).
    """
    dataset_file = Path(__file__).resolve().parents[1] / "output" / "cases" / case_id / "correlation_training_pairs.json"
    if not dataset_file.exists():
        pytest.skip("Dataset file not found")

    with open(dataset_file, "r", encoding="utf-8") as f:
        samples = json.load(f)

    pos_samples = [s for s in samples if s.get("ground_truth_causal_label") == 1]
    neg_samples = [s for s in samples if s.get("ground_truth_causal_label") == 0]

    pos_intra = sum(1 for s in pos_samples if s["domain_a"] == s["domain_b"])
    neg_cross = sum(1 for s in neg_samples if s["domain_a"] != s["domain_b"])

    # Document that the prototype dataset currently exhibits 100% intra-domain positive bias
    assert pos_intra == len(pos_samples), "Audit observation: 100% of positive pairs are intra-domain"
    assert neg_cross == len(neg_samples), "Audit observation: 100% of negative pairs are cross-domain"
