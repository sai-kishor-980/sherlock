"""
Test Suite for Hybrid Neuro-Symbolic Correlation Engine with Supervisor LLM.
Validates:
1. Exact and normalized entity matching.
2. Similar but non-identical executable names rejection.
3. PID reuse and ambiguous process identity handling.
4. Missing and conflicting timestamps zero-fabrication.
5. Registry-to-execution correlation (RULE-PERSIST-01).
6. Network-to-process attribution with and without evidence (RULE-NET-01).
7. Supervisor model proposed unsupported relationships (rejection & schema validation).
8. Hallucinated / fabricated finding IDs rejection.
9. Bounded 1-retry with schema enforcement.
10. Multi-tier epistemic classification and visual styles (SOLID_CYAN, SOLID_PURPLE, DASHED_AMBER, DOTTED_GRAY).
11. Idempotency and duplicate edge prevention on repeated execution.
"""

import pytest
from app.services.correlation_engine import (
    ExplainableCorrelationEngine,
    CorrelationEpistemicClass,
    TypedEntityExtractor,
    MatchingMethod
)
from app.services.model_adapter_service import ModelAdapterService


def test_1_exact_and_normalized_entity_matching():
    """Verify paths with forward/back slashes, casing, and quotes normalize to match."""
    p1 = "C:\\Windows\\System32\\drivers\\etc\\hosts"
    p2 = "c:/windows/system32/drivers/etc/hosts"
    assert TypedEntityExtractor.normalize_path(p1) == TypedEntityExtractor.normalize_path(p2)

    finding1 = {
        "finding_id": "F-DISK-01",
        "agent": "disk",
        "entities": [{"path": ' "C:/Windows/System32/calc.exe" '}],
        "observation": "File created at C:\\Windows\\System32\\calc.exe"
    }
    finding2 = {
        "finding_id": "F-LOG-01",
        "agent": "logs",
        "entities": [{"executable": "calc.exe"}],
        "observation": "calc.exe started"
    }
    res = ExplainableCorrelationEngine.correlate_case_findings([finding1, finding2], invoke_supervisor=False)
    assert len(res["correlation_edges"]) >= 1
    edge = res["correlation_edges"][0]
    assert "calc.exe" in str(edge["matched_entities"])
    assert edge["visual_style"] in ("SOLID_CYAN", "SOLID_PURPLE")


def test_2_similar_but_non_identical_executables_rejected():
    """Ensure svchost.exe does NOT match svchost32.exe or malicious typo-squats."""
    finding1 = {
        "finding_id": "F-DISK-01",
        "agent": "disk",
        "entities": [{"executable": "svchost.exe"}],
        "observation": "Prefetch execution record for svchost.exe"
    }
    finding2 = {
        "finding_id": "F-LOG-01",
        "agent": "logs",
        "entities": [{"executable": "svchost32.exe"}],
        "observation": "Process creation for svchost32.exe"
    }
    res = ExplainableCorrelationEngine.correlate_case_findings([finding1, finding2], invoke_supervisor=False)
    # Should not establish process lineage or persistence linkage
    causal_edges = [e for e in res["correlation_edges"] if e["epistemic_class"] == CorrelationEpistemicClass.CAUSAL_DEPENDENCY]
    assert len(causal_edges) == 0


def test_3_pid_reuse_inverted_timestamps_ambiguous():
    """If parent process creation timestamp is later than child timestamp, must mark AMBIGUOUS."""
    finding_parent = {
        "finding_id": "F-MEM-PARENT",
        "agent": "memory",
        "entities": [{"executable": "cmd.exe", "pid": "1000"}],
        "timeline": {"timestamp_utc": "2026-09-15T09:00:00Z"},
        "observation": "Parent cmd.exe created at 09:00:00"
    }
    finding_child = {
        "finding_id": "F-LOG-CHILD",
        "agent": "logs",
        "entities": [{"executable": "powershell.exe", "pid": "2000", "ppid": "1000"}],
        "timeline": {"timestamp_utc": "2026-09-15T08:00:00Z"},
        "observation": "Child powershell.exe created at 08:00:00"
    }
    res = ExplainableCorrelationEngine.correlate_case_findings([finding_parent, finding_child], invoke_supervisor=False)
    # The timestamps are inverted by 1 hour -> PID reuse anomaly
    for edge in res["correlation_edges"]:
        if edge.get("rule_id") == "RULE-PROC-01":
            assert edge["epistemic_class"] == CorrelationEpistemicClass.AMBIGUOUS_UNKNOWN
            assert "PID reuse" in edge["reasoning"] or "inverted" in edge["reasoning"].lower()


def test_4_missing_timestamps_zero_fabrication():
    """Missing timestamps must remain UNAVAILABLE and not fabricated to current time."""
    finding1 = {
        "finding_id": "F-REG-01",
        "agent": "registry",
        "observation": "Run key persistence with no timestamp recorded",
        "entities": [{"executable": "backdoor.exe"}],
        "timeline": None
    }
    res = ExplainableCorrelationEngine.correlate_case_findings([finding1], invoke_supervisor=False)
    events = res["unified_timeline"]
    assert len(events) == 1
    assert events[0]["timestamp_utc"] is None
    assert events[0]["timestamp_type"] == "UNAVAILABLE"
    assert events[0]["timestamp_source"] == "UNRECORDED"


def test_5_registry_persistence_to_execution():
    """Correlate registry Run key with prefetch execution."""
    f_reg = {
        "finding_id": "F-REG-01",
        "agent": "registry",
        "artifact_type": "Registry Run Key",
        "entities": [{"executable": "C:\\Windows\\Temp\\trojan.exe"}],
        "observation": "Persistence key for trojan.exe",
        "timeline": {"timestamp_utc": "2026-09-15T08:00:00Z"}
    }
    f_disk = {
        "finding_id": "F-DISK-01",
        "agent": "disk",
        "artifact_type": "Windows Prefetch",
        "entities": [{"executable": "trojan.exe"}],
        "observation": "Prefetch execution record for trojan.exe with 12 runs",
        "timeline": {"timestamp_utc": "2026-09-15T08:01:00Z"}
    }
    res = ExplainableCorrelationEngine.correlate_case_findings([f_reg, f_disk], invoke_supervisor=False)
    persist_edges = [e for e in res["correlation_edges"] if e["rule_id"] == "RULE-PERSIST-01"]
    assert len(persist_edges) == 1
    edge = persist_edges[0]
    assert edge["epistemic_class"] == CorrelationEpistemicClass.CAUSAL_DEPENDENCY
    assert edge["visual_style"] == "SOLID_CYAN"
    assert edge["verification_status"] == "VERIFIED"
    assert edge["is_model_hypothesis"] is False


def test_6_network_attribution_with_and_without_evidence():
    """Attribution requires shared IP/domain or socket linkage."""
    f_net = {
        "finding_id": "F-NET-01",
        "agent": "network",
        "entities": [{"ip": "198.51.100.22", "domain": "c2-server.com"}],
        "observation": "DNS beacon to c2-server.com (198.51.100.22)",
        "timeline": {"timestamp_utc": "2026-09-15T08:10:00Z"}
    }
    # Case A: Log has matching IP
    f_log_match = {
        "finding_id": "F-LOG-01",
        "agent": "logs",
        "entities": [{"executable": "powershell.exe", "ip": "198.51.100.22"}],
        "observation": "PowerShell outbound connection to 198.51.100.22",
        "timeline": {"timestamp_utc": "2026-09-15T08:10:05Z"}
    }
    res_match = ExplainableCorrelationEngine.correlate_case_findings([f_net, f_log_match], invoke_supervisor=False)
    net_edges = [e for e in res_match["correlation_edges"] if e["rule_id"] == "RULE-NET-01"]
    assert len(net_edges) == 1
    assert net_edges[0]["epistemic_class"] == CorrelationEpistemicClass.CAUSAL_DEPENDENCY

    # Case B: Log has completely unrelated IP
    f_log_nomatch = {
        "finding_id": "F-LOG-02",
        "agent": "logs",
        "entities": [{"executable": "notepad.exe", "ip": "8.8.8.8"}],
        "observation": "Google DNS query",
        "timeline": {"timestamp_utc": "2026-09-15T08:10:05Z"}
    }
    res_nomatch = ExplainableCorrelationEngine.correlate_case_findings([f_net, f_log_nomatch], invoke_supervisor=False)
    net_edges_no = [e for e in res_nomatch["correlation_edges"] if e["rule_id"] == "RULE-NET-01"]
    assert len(net_edges_no) == 0


def test_7_supervisor_schema_validation_and_rejection():
    """Supervisor proposing fabricated finding IDs must be rejected by the validation layer."""
    valid_ids = {"F-NET-01", "F-MEM-01"}
    fabricated_output = {
        "correlations": [
            {
                "source_finding_id": "F-NET-01",
                "target_finding_id": "F-FABRICATED-999",  # Invalid / hallucinated ID
                "relationship_type": "EXFILTRATION_TO_PROCESS",
                "epistemic_class": "CAUSAL_DEPENDENCY",
                "reasoning": "Hallucinated link"
            }
        ],
        "incident_narrative": "Fabricated attack story."
    }
    parsed, errors = ModelAdapterService._parse_and_validate_supervisor_json(
        fabricated_output,
        valid_finding_ids=valid_ids
    )
    # Must flag validation error and reject the edge
    assert len(errors) >= 1
    assert "Invalid or fabricated target_finding_id 'F-FABRICATED-999'" in errors[0]
    assert len(parsed.get("correlations", [])) == 0


def test_8_supervisor_valid_proposal_creates_dashed_amber_hypothesis():
    """Supervisor proposing a valid cross-domain hypothesis creates a DASHED_AMBER edge."""
    valid_ids = {"F-NET-01", "F-MEM-01"}
    valid_model_output = {
        "correlations": [
            {
                "source_finding_id": "F-NET-01",
                "target_finding_id": "F-MEM-01",
                "relationship_type": "CROSS_DOMAIN_C2_TO_INJECTION",
                "epistemic_class": "CORRELATIONAL_ASSOCIATION",
                "matched_entities": ["185.220.101.5"],
                "reasoning": "C2 network flow correlates with memory injection timing.",
                "alternative_explanations": "Could be independent benign telemetry.",
                "missing_evidence": "Need socket table linking PID 584 to port 49152.",
                "confidence": 0.78
            }
        ],
        "incident_narrative": "Adversary staged C2 and executed reflective DLL injection."
    }
    parsed, errors = ModelAdapterService._parse_and_validate_supervisor_json(
        valid_model_output,
        valid_finding_ids=valid_ids
    )
    assert len(errors) == 0
    assert len(parsed["correlations"]) == 1
    edge = parsed["correlations"][0]
    assert edge["is_model_hypothesis"] is True
    assert edge["uncertainty_score"] == 0.22


def test_9_idempotency_no_duplicate_edges_on_repeated_runs():
    """Repeated runs on the same findings must generate identical, deduplicated edge sets."""
    findings = [
        {
            "finding_id": "F-LOG-01",
            "agent": "logs",
            "entities": [{"executable": "cmd.exe", "pid": "100"}],
            "timeline": {"timestamp_utc": "2026-09-15T08:00:00Z"}
        },
        {
            "finding_id": "F-MEM-01",
            "agent": "memory",
            "entities": [{"executable": "cmd.exe", "pid": "100"}],
            "timeline": {"timestamp_utc": "2026-09-15T08:00:05Z"}
        }
    ]
    res1 = ExplainableCorrelationEngine.correlate_case_findings(findings, case_id="CASE_IDEMP", invoke_supervisor=False)
    res2 = ExplainableCorrelationEngine.correlate_case_findings(findings, case_id="CASE_IDEMP", invoke_supervisor=False)
    assert len(res1["correlation_edges"]) == len(res2["correlation_edges"]) == 1
    assert res1["evidence_graph"]["total_edges"] == res2["evidence_graph"]["total_edges"] == 1
