"""
SherlockAI — Regression Test Suite for Correlation Pipeline Evaluation & Targeted Fixes.

Covers:
1. End-to-end evaluation harness execution against audited pilot dataset.
2. Nested evidence discovery for Standalone Artifact Test (JW01).
3. SCM Service persistence correlation (Event ID 7045 -> driver binaries).
4. Whole-token executable boundary matching preventing substring false-positives.
5. Direct process-to-VAD memory injection correlation.
6. Strict segregation of ambiguous pairs from binary precision/recall scoring.
"""

from pathlib import Path
import pytest

from app.services.synthesizer_service import ForensicSynthesizerService
from app.cli.evaluate_correlation_pipeline import CorrelationEvaluator, match_correlation_to_pair

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "correlation_datasets"
PILOT_DATASET = FIXTURES_DIR / "pilot_phase1c2_audited_expanded_dataset.json"


def test_pipeline_reproducible_evaluation_metrics():
    """
    Verifies that the correlation pipeline achieves expected performance on the audited dataset:
    - 23 total samples processed
    - Exactly 9 ambiguous samples excluded from binary metrics
    - 14 binary evaluated samples (5 positives, 9 negatives)
    - Zero false positives (Precision = 1.0)
    - Zero false negatives (Recall = 1.0)
    """
    assert PILOT_DATASET.exists(), f"Missing dataset fixture: {PILOT_DATASET}"
    
    result = CorrelationEvaluator.evaluate(PILOT_DATASET)
    summary = result["summary"]
    
    assert summary["total_samples"] == 23
    assert summary["ambiguous_excluded"] == 9
    assert summary["evaluated_binary_samples"] == 14
    assert summary["true_positives"] == 5
    assert summary["false_positives"] == 0
    assert summary["true_negatives"] == 9
    assert summary["false_negatives"] == 0
    assert summary["precision"] == 1.0
    assert summary["recall"] == 1.0
    assert summary["f1_score"] == 1.0


def test_nested_evidence_discovery_standalone_artifact_test():
    """
    Regression Test for Defect 1:
    Previously, _ingest_disk failed to discover artifacts nested under evidence/EVD-001/disk/,
    resulting in 0 ingested artifacts and 0 generated correlations.
    Verifies that nested discovery discovers disk artifacts and generates correlations.
    """
    res = ForensicSynthesizerService.synthesize_case("Standalone Artifact Test")
    
    # Check that disk ingestion discovered artifacts
    inv = res.get("artifact_inventory", {})
    assert inv.get("total_artifacts", 0) > 0, "Failed to discover nested evidence artifacts"
    
    # Check that correlations were generated
    corrs = res.get("correlations", [])
    assert len(corrs) > 0, "Standalone Artifact Test should generate correlations after nested discovery fix"


def test_scm_service_persistence_correlation_in_disk2():
    """
    Regression Test for Defect 2:
    Verifies that Service Control Manager Event ID 7045 creates persistence-to-execution
    correlations for HdAudio.sys and e1i63x64.sys in DISK_2, while cross-service mismatches
    are not falsely generated.
    """
    res = ForensicSynthesizerService.synthesize_case("DISK_2")
    corrs = res.get("correlations", [])
    
    scm_corrs = [c for c in corrs if c.get("relationship_type") == "persistence_to_execution" and "Service" in c.get("title", "")]
    assert len(scm_corrs) >= 2, "Expected SCM service persistence correlations in DISK_2"
    
    hdaudio_corr = next((c for c in scm_corrs if "HdAudio.sys" in c.get("title", "")), None)
    assert hdaudio_corr is not None, "Missing HdAudio.sys SCM correlation"
    assert hdaudio_corr["source_a"]["domain"] == "logs"
    assert hdaudio_corr["source_b"]["domain"] == "disk"
    assert hdaudio_corr["confidence"] >= 0.80
    
    e1i_corr = next((c for c in scm_corrs if "e1i63x64.sys" in c.get("title", "")), None)
    assert e1i_corr is not None, "Missing e1i63x64.sys SCM correlation"
    assert e1i_corr["source_a"]["domain"] == "logs"
    assert e1i_corr["source_b"]["domain"] == "disk"


def test_token_boundary_persistence_matching_rejects_substring_collision():
    """
    Regression Test for Defect 3:
    In the previous implementation, `if exe and exe in cmd:` caused loose substring collisions,
    e.g., prefetch `at.exe` or `date.exe` would falsely correlate with `update.exe`.
    Verifies that token-level boundary matching rejects substring collisions.
    """
    # Synthetic disk with update.exe in Run key
    synthetic_disk = {
        "run_keys": [
            {
                "name": "SoftwareUpdater",
                "command": "C:\\Program Files\\App\\update.exe --silent",
                "last_write_time": "2020-01-01T12:00:00Z"
            }
        ],
        "prefetch_analysis": [
            {
                "executable_name": "date.exe",
                "last_run_time": "2020-01-01T12:05:00Z",
                "run_count": 1
            },
            {
                "executable_name": "at.exe",
                "last_run_time": "2020-01-01T12:05:00Z",
                "run_count": 1
            },
            {
                "executable_name": "update.exe",
                "last_run_time": "2020-01-01T12:05:00Z",
                "run_count": 5
            }
        ]
    }
    
    corrs = ForensicSynthesizerService._build_correlations(
        case_id="TEST_CASE",
        findings=[],
        mem={},
        disk=synthetic_disk,
        pcap={}
    )
    
    persist_corrs = [c for c in corrs if c.get("relationship_type") == "persistence_to_execution"]
    
    # Must contain update.exe
    assert any(c.get("source_b", {}).get("entity") == "update.exe" for c in persist_corrs), "update.exe should match"
    
    # Must NOT contain date.exe or at.exe
    assert not any(c.get("source_b", {}).get("entity") == "date.exe" for c in persist_corrs), "date.exe substring false-positive must be rejected"
    assert not any(c.get("source_b", {}).get("entity") == "at.exe" for c in persist_corrs), "at.exe substring false-positive must be rejected"


def test_process_injection_correlation_groups_malfind():
    """
    Verifies that unbacked RWX VAD allocations from Volatility malfind generate
    a corroborated process injection chain linking parent and injected child process with VAD count.
    """
    synthetic_mem = {
        "threat_hunting": {
            "plugins": {
                "windows.malfind": [
                    {
                        "PID": 1640,
                        "Process": "reader_sl.exe",
                        "Start VPN": 3997696,
                        "Protection": "PAGE_EXECUTE_READWRITE"
                    }
                ]
            }
        },
        "processes": {
            "plugins": {
                "windows.pslist": [
                    {
                        "PID": 1640,
                        "PPID": 1484,
                        "ImageFileName": "reader_sl.exe",
                        "CreateTime": "2012-07-22T02:43:01Z"
                    },
                    {
                        "PID": 1484,
                        "PPID": 1464,
                        "ImageFileName": "explorer.exe",
                        "CreateTime": "2012-07-22T02:42:32Z"
                    }
                ]
            }
        }
    }
    
    corrs = ForensicSynthesizerService._build_correlations(
        case_id="TEST_CASE",
        findings=[],
        mem=synthetic_mem,
        disk={},
        pcap={}
    )
    
    injection_corrs = [c for c in corrs if "injection" in c.get("relationship_type", "")]
    assert len(injection_corrs) == 1, "Expected single deduplicated process injection correlation"
    assert injection_corrs[0]["source_a"]["artifact_id"] == "PID-1484"
    assert injection_corrs[0]["source_b"]["artifact_id"] == "PID-1640"
    assert injection_corrs[0]["source_b"]["vad_allocations_count"] == 1
    assert injection_corrs[0]["confidence"] == 0.80


def test_ambiguous_pairs_excluded_from_binary_metrics():
    """
    Verifies that pairs labeled AMBIGUOUS_UNRESOLVED are not penalized as False Positives or False Negatives.
    """
    result = CorrelationEvaluator.evaluate(PILOT_DATASET)
    
    jw_case = result["cases"]["PILOT_CASE_JW01"]
    amb_pairs = [p for p in jw_case["pairs"] if p["ground_truth_label"] == "AMBIGUOUS_UNRESOLVED"]
    
    assert len(amb_pairs) == 7
    for p in amb_pairs:
        assert p["evaluation_status"] == "EXCLUDED_AMBIGUOUS"
