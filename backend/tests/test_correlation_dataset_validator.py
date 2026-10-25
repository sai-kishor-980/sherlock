"""
Regression and Quality Gate Tests for Correlation Learning Dataset Schema & Validator (Phase 1A).

Tests:
1. Valid positive, negative, and ambiguous example structures
2. Missing timestamps represented honestly vs dishonestly
3. Missing provenance accounting
4. Invalid and contradictory labels
5. Duplicate sample IDs and duplicate artifact pairs
6. Domain-label confounding detection
7. Investigation-level split leakage detection
8. Empty and malformed datasets
9. CLI exit codes and diagnostic output
10. Separation of structural validity from training readiness
"""

import sys
import json
import subprocess
from pathlib import Path
import pytest
from pydantic import ValidationError

from app.db.schemas.correlation_dataset import (
    CORRELATION_SCHEMA_VERSION,
    CorrelationSample,
    DatasetArtifact,
    DatasetAnnotation,
    DatasetTemporalContext,
    EpistemicLabel,
    RelationshipType,
    ArtifactDomain,
    TimestampQuality,
    TemporalOrderStatus,
    DatasetSplit
)
from app.services.correlation_validator_service import (
    CorrelationDatasetValidator,
    DatasetValidationResult
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "correlation_datasets"


def test_valid_dev_fixture_passes_structural_validation():
    """
    Verifies that the small synthetic development fixture passes 100% of structural checks
    including positive, negative, and ambiguous examples with honest timestamps.
    """
    fixture_path = FIXTURES_DIR / "synthetic_valid_dev_fixture.json"
    assert fixture_path.exists(), f"Missing fixture: {fixture_path}"

    result = CorrelationDatasetValidator.validate(fixture_path)
    assert result.is_structurally_valid is True, f"Structural validation failed: {result.structural_errors}"
    assert result.total_records_processed == 5
    assert result.valid_record_count == 5
    assert len(result.structural_errors) == 0
    assert len(result.duplicate_sample_ids) == 0
    assert len(result.duplicate_artifact_pairs) == 0
    assert len(result.split_investigation_leakage) == 0

    # Verify distribution breakdown
    assert result.label_distribution["VERIFIED_POSITIVE"] == 2
    assert result.label_distribution["VERIFIED_NEGATIVE"] == 2
    assert result.label_distribution["AMBIGUOUS_UNRESOLVED"] == 1


def test_valid_dev_fixture_fails_training_readiness_honestly():
    """
    Crucial requirement: A small development fixture must be structurally valid
    WITHOUT pretending to be training-ready (due to scale N < 2500, K < 15).
    """
    fixture_path = FIXTURES_DIR / "synthetic_valid_dev_fixture.json"
    result = CorrelationDatasetValidator.validate(fixture_path)

    # Must NOT pass research training readiness
    assert result.is_training_ready is False
    gates = result.training_readiness_gates
    assert gates["Gate 1: Minimum Scale"]["status"] == "FAIL"
    assert "requires >= 2,500 pairs" in gates["Gate 1: Minimum Scale"]["diagnostic"]
    assert gates["Gate 2: Case Diversity"]["status"] == "FAIL"
    assert "risks memorizing" in gates["Gate 2: Case Diversity"]["diagnostic"]


def test_honest_missing_timestamp_representation():
    """
    Ensures missing timestamps are represented honestly (None / UNRECORDED)
    and fails if a missing timestamp claims to be EXACT_ORIGIN.
    """
    # Honest representation passes
    art_honest = DatasetArtifact(
        artifact_id="VAD-0x01",
        domain=ArtifactDomain.MEMORY,
        artifact_type="vad_memory",
        timestamp=None,
        timestamp_quality=TimestampQuality.UNRECORDED
    )
    assert art_honest.timestamp is None
    assert art_honest.timestamp_quality == TimestampQuality.UNRECORDED

    # Dishonest representation (timestamp=None but claiming EXACT_ORIGIN) fails
    with pytest.raises(ValidationError) as exc_info:
        DatasetArtifact(
            artifact_id="VAD-0x02",
            domain=ArtifactDomain.MEMORY,
            artifact_type="vad_memory",
            timestamp=None,
            timestamp_quality=TimestampQuality.EXACT_ORIGIN
        )
    assert "Missing timestamps must be declared as UNRECORDED or UNAVAILABLE" in str(exc_info.value)


def test_contradictory_labels_rejected():
    """
    Validates rejection of:
    - VERIFIED_POSITIVE with causal label 0
    - AMBIGUOUS_UNRESOLVED with binary label (1 or 0)
    - VERIFIED_POSITIVE with COINCIDENTAL_NOISE
    """
    # 1. VERIFIED_POSITIVE with label 0
    with pytest.raises(ValidationError) as exc1:
        DatasetAnnotation(
            epistemic_label=EpistemicLabel.VERIFIED_POSITIVE,
            ground_truth_causal_label=0,
            relationship_type=RelationshipType.PARENT_CHILD_PROCESS,
            label_rationale="Contradictory positive label test",
            annotation_source="TEST",
            annotator_ids=["EX_1"]
        )
    assert "VERIFIED_POSITIVE examples must have ground_truth_causal_label == 1" in str(exc1.value)

    # 2. AMBIGUOUS_UNRESOLVED with binary label 1
    with pytest.raises(ValidationError) as exc2:
        DatasetAnnotation(
            epistemic_label=EpistemicLabel.AMBIGUOUS_UNRESOLVED,
            ground_truth_causal_label=1,
            relationship_type=RelationshipType.PROCESS_INJECTION,
            label_rationale="Contradictory ambiguous label test",
            annotation_source="TEST",
            annotator_ids=["EX_1"]
        )
    assert "AMBIGUOUS_UNRESOLVED examples must have ground_truth_causal_label == None" in str(exc2.value)

    # 3. VERIFIED_POSITIVE with COINCIDENTAL_NOISE
    with pytest.raises(ValidationError) as exc3:
        DatasetAnnotation(
            epistemic_label=EpistemicLabel.VERIFIED_POSITIVE,
            ground_truth_causal_label=1,
            relationship_type=RelationshipType.COINCIDENTAL_NOISE,
            label_rationale="Contradictory positive coincidental noise test",
            annotation_source="TEST",
            annotator_ids=["EX_1"]
        )
    assert "cannot have relationship_type == COINCIDENTAL_NOISE" in str(exc3.value)


def test_duplicate_sample_ids_and_artifact_pairs():
    """
    Verifies detection of duplicate sample IDs and duplicate artifact pairs within the same case.
    """
    fixture_path = FIXTURES_DIR / "synthetic_duplicate_pairs.json"
    result = CorrelationDatasetValidator.validate(fixture_path)

    assert result.is_structurally_valid is False
    assert len(result.duplicate_artifact_pairs) >= 1
    assert any("Duplicate pair detected" in err["message"] for err in result.structural_errors)


def test_investigation_split_leakage_detected():
    """
    Ensures that splitting artifact pairs from the same case across TRAIN and TEST
    is caught and flagged as critical leakage.
    """
    fixture_path = FIXTURES_DIR / "synthetic_leakage_dataset.json"
    result = CorrelationDatasetValidator.validate(fixture_path)

    assert result.is_structurally_valid is False
    assert len(result.split_investigation_leakage) == 1
    assert result.split_investigation_leakage[0]["investigation_id"] == "SYNTH_CASE_LEAKED"
    assert any("Data leakage error" in err["message"] for err in result.structural_errors)


def test_domain_confounding_detected():
    """
    Verifies that the validator catches fatal domain confounding where 100% of positives
    are intra-domain and 100% of negatives are cross-domain.
    """
    fixture_path = FIXTURES_DIR / "synthetic_confounded_dataset.json"
    result = CorrelationDatasetValidator.validate(fixture_path)

    assert result.fatal_domain_confounding_detected is True
    assert "100% of positive pairs are intra-domain" in result.domain_confounding_details
    gate4 = result.training_readiness_gates["Gate 4: Domain Balance (No Confounding)"]
    assert gate4["status"] == "FAIL"


def test_empty_and_malformed_datasets():
    """
    Tests handling of 0-byte files, non-array JSON roots, and malformed syntax.
    """
    # 1. Non-existent file
    res1 = CorrelationDatasetValidator.validate("non_existent_path.json")
    assert res1.is_structurally_valid is False
    assert any("File does not exist" in e["message"] for e in res1.structural_errors)

    # 2. Empty list
    res2 = CorrelationDatasetValidator.validate([])
    assert res2.is_structurally_valid is False
    assert any("0 records" in e["message"] for e in res2.structural_errors)

    # 3. Invalid schema fixture
    fixture_path = FIXTURES_DIR / "synthetic_invalid_schema.json"
    res3 = CorrelationDatasetValidator.validate(fixture_path)
    assert res3.is_structurally_valid is False
    assert len(res3.structural_errors) > 0


def test_cli_exit_codes_and_diagnostics():
    """
    Verifies CLI invocation exit codes:
    - Exit 0: Structurally valid file (without --check-readiness)
    - Exit 2: Structurally valid file when --check-readiness fails on small fixture
    - Exit 1: Structurally invalid file
    """
    cli_script = Path(__file__).resolve().parents[1] / "app" / "cli" / "validate_correlation_dataset.py"
    backend_dir = Path(__file__).resolve().parents[1]

    # Test A: Valid dev fixture without readiness -> Exit 0
    valid_fixture = FIXTURES_DIR / "synthetic_valid_dev_fixture.json"
    proc_a = subprocess.run(
        [sys.executable, str(cli_script), str(valid_fixture)],
        cwd=str(backend_dir),
        capture_output=True,
        text=True
    )
    assert proc_a.returncode == 0, f"CLI stdout:\n{proc_a.stdout}\nstderr:\n{proc_a.stderr}"
    assert "SHERLOCKAI / H-MACFR — CORRELATION DATASET VALIDATION REPORT" in proc_a.stdout
    assert "Structural Status:        PASS" in proc_a.stdout

    # Test B: Valid dev fixture WITH --check-readiness -> Exit 2 (not training-ready)
    proc_b = subprocess.run(
        [sys.executable, str(cli_script), str(valid_fixture), "--check-readiness"],
        cwd=str(backend_dir),
        capture_output=True,
        text=True
    )
    assert proc_b.returncode == 2, f"Expected code 2, got {proc_b.returncode}"
    assert "TRAINING READINESS GATES FAILED" in proc_b.stderr

    # Test C: Structurally invalid fixture -> Exit 1
    invalid_fixture = FIXTURES_DIR / "synthetic_invalid_schema.json"
    proc_c = subprocess.run(
        [sys.executable, str(cli_script), str(invalid_fixture)],
        cwd=str(backend_dir),
        capture_output=True,
        text=True
    )
    assert proc_c.returncode == 1, f"Expected code 1, got {proc_c.returncode}"
    assert "STRUCTURAL VALIDATION FAILED" in proc_c.stderr


def test_reversed_noise_duplicate_detected():
    """
    Asserts that symmetric coincidental noise pairs (A, B) and (B, A) are detected as duplicate pairs.
    """
    fixture_path = FIXTURES_DIR / "synthetic_reversed_noise_duplicate.json"
    result = CorrelationDatasetValidator.validate(fixture_path)

    assert result.is_structurally_valid is False
    assert len(result.duplicate_artifact_pairs) == 1
    assert result.duplicate_artifact_pairs[0]["directionality"] == "UNDIRECTED_SYMMETRIC"
    assert any("Duplicate pair detected (symmetric)" in e["message"] for e in result.structural_errors)


def test_cyclic_directed_relationship_detected():
    """
    Asserts that cyclic positive directed causality (A -> B and B -> A as PARENT_CHILD) is caught as a physical impossibility.
    """
    fixture_path = FIXTURES_DIR / "synthetic_cyclic_directed_relationship.json"
    result = CorrelationDatasetValidator.validate(fixture_path)

    assert result.is_structurally_valid is False
    assert len(result.cyclic_directed_relationships) == 1
    assert any("Cyclic / inverted directed causality error" in e["message"] for e in result.structural_errors)


def test_contradictory_pair_labels_detected():
    """
    Asserts that contradictory positive vs negative labels for the exact same artifact pair are detected.
    """
    fixture_path = FIXTURES_DIR / "synthetic_contradictory_pair_labels.json"
    result = CorrelationDatasetValidator.validate(fixture_path)

    assert result.is_structurally_valid is False
    assert len(result.contradictory_label_conflicts) == 1
    assert any("Contradictory label conflict" in e["message"] for e in result.structural_errors)


def test_disputed_annotator_gate_fails_consensus():
    """
    Asserts that multiple annotator IDs do NOT pass Gate 7 if adjudication_status is DISPUTED.
    """
    fixture_path = FIXTURES_DIR / "synthetic_disputed_annotator_gate.json"
    result = CorrelationDatasetValidator.validate(fixture_path)

    gate7 = result.training_readiness_gates["Gate 7: Annotation Consensus & Quality"]
    assert gate7["status"] == "FAIL"
    assert "1 unresolved disputed label(s)" in gate7["diagnostic"]


def test_inconsistent_temporal_delta_rejected():
    """
    Asserts that a mismatch between ISO timestamp difference and delta_seconds is rejected by schema validator.
    """
    fixture_path = FIXTURES_DIR / "synthetic_inconsistent_delta.json"
    result = CorrelationDatasetValidator.validate(fixture_path)

    assert result.is_structurally_valid is False
    assert any("inconsistent temporal delta" in e["message"] for e in result.structural_errors)


def test_invalid_timestamp_format_rejected():
    """
    Asserts that invalid non-ISO-8601 timestamps (e.g. month 99) are rejected by schema validator.
    """
    fixture_path = FIXTURES_DIR / "synthetic_invalid_timestamp_format.json"
    result = CorrelationDatasetValidator.validate(fixture_path)

    assert result.is_structurally_valid is False
    assert any("invalid ISO-8601 timestamp" in e["message"] for e in result.structural_errors)


def test_cross_case_evidence_leakage_detected():
    """
    Asserts that the exact same artifact pair copied across different cases in different splits (TRAIN vs TEST) is caught.
    """
    fixture_path = FIXTURES_DIR / "synthetic_cross_case_leakage.json"
    result = CorrelationDatasetValidator.validate(fixture_path)

    assert result.is_structurally_valid is False
    assert len(result.cross_split_evidence_leakage) == 1
    assert any("Cross-split duplicate evidence leakage" in e["message"] for e in result.structural_errors)


def test_jsonl_dataset_streaming_load(tmp_path):
    """
    Verifies that .jsonl datasets stream and validate properly.
    """
    jsonl_file = tmp_path / "stream_test.jsonl"
    with open(FIXTURES_DIR / "synthetic_valid_dev_fixture.json") as f:
        records = json.load(f)

    with open(jsonl_file, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    result = CorrelationDatasetValidator.validate(jsonl_file)
    assert result.is_structurally_valid is True
    assert result.total_records_processed == len(records)


def test_valid_reversed_assertion_passes():
    """
    Asserts that reversing the direction of a directed relationship with opposite labels
    (e.g. A spawned B is POSITIVE, but B spawned A is NEGATIVE) is forensically valid and non-contradictory.
    """
    samples = [
        {
            "sample_id": "REV-001",
            "investigation_id": "CASE_REV_TEST",
            "schema_version": "1.0.0",
            "source_artifact": {
                "artifact_id": "PID-10",
                "domain": "memory",
                "artifact_type": "process",
                "timestamp": "2026-09-20T08:00:00Z",
                "timestamp_quality": "EXACT_ORIGIN"
            },
            "target_artifact": {
                "artifact_id": "PID-20",
                "domain": "memory",
                "artifact_type": "process",
                "timestamp": "2026-09-20T08:00:10Z",
                "timestamp_quality": "EXACT_ORIGIN"
            },
            "temporal_context": {
                "delta_seconds": 10.0,
                "temporal_order": "SOURCE_PRECEDES_TARGET"
            },
            "annotation": {
                "epistemic_label": "VERIFIED_POSITIVE",
                "ground_truth_causal_label": 1,
                "relationship_type": "PARENT_CHILD_PROCESS",
                "label_rationale": "PID 10 (explorer) legitimately spawned PID 20 (cmd).",
                "annotation_source": "TEST",
                "annotator_ids": ["EX_1"]
            }
        },
        {
            "sample_id": "REV-002",
            "investigation_id": "CASE_REV_TEST",
            "schema_version": "1.0.0",
            "source_artifact": {
                "artifact_id": "PID-20",
                "domain": "memory",
                "artifact_type": "process",
                "timestamp": "2026-09-20T08:00:10Z",
                "timestamp_quality": "EXACT_ORIGIN"
            },
            "target_artifact": {
                "artifact_id": "PID-10",
                "domain": "memory",
                "artifact_type": "process",
                "timestamp": "2026-09-20T08:00:00Z",
                "timestamp_quality": "EXACT_ORIGIN"
            },
            "temporal_context": {
                "delta_seconds": -10.0,
                "temporal_order": "TARGET_PRECEDES_SOURCE"
            },
            "annotation": {
                "epistemic_label": "VERIFIED_NEGATIVE",
                "ground_truth_causal_label": 0,
                "relationship_type": "PARENT_CHILD_PROCESS",
                "label_rationale": "PID 20 (cmd) did NOT spawn PID 10 (explorer). Valid negative mining.",
                "annotation_source": "TEST",
                "annotator_ids": ["EX_1"]
            }
        }
    ]

    result = CorrelationDatasetValidator.validate(samples)
    assert result.is_structurally_valid is True, f"Errors: {result.structural_errors}"
    assert len(result.duplicate_artifact_pairs) == 0
    assert len(result.contradictory_label_conflicts) == 0
    assert len(result.cyclic_directed_relationships) == 0


def test_generic_id_similarity_across_splits_is_warning_not_error():
    """
    Asserts that cases in different splits with common generic artifact IDs (like PID-100)
    WITHOUT matching cryptographic storage hashes are treated as warnings/diagnostics, not fatal errors.
    """
    samples = [
        {
            "sample_id": "SPLIT-GEN-01",
            "investigation_id": "CASE_HOST_A",
            "schema_version": "1.0.0",
            "source_artifact": {
                "artifact_id": "PID-100",
                "domain": "memory",
                "artifact_type": "process",
                "timestamp_quality": "UNRECORDED"
            },
            "target_artifact": {
                "artifact_id": "PID-200",
                "domain": "memory",
                "artifact_type": "process",
                "timestamp_quality": "UNRECORDED"
            },
            "temporal_context": { "temporal_order": "UNKNOWN" },
            "annotation": {
                "epistemic_label": "VERIFIED_POSITIVE",
                "ground_truth_causal_label": 1,
                "relationship_type": "PARENT_CHILD_PROCESS",
                "label_rationale": "Generic PID on Host A in TRAIN split.",
                "annotation_source": "TEST",
                "annotator_ids": ["EX_1"]
            },
            "split": "TRAIN"
        },
        {
            "sample_id": "SPLIT-GEN-02",
            "investigation_id": "CASE_HOST_B",
            "schema_version": "1.0.0",
            "source_artifact": {
                "artifact_id": "PID-100",
                "domain": "memory",
                "artifact_type": "process",
                "timestamp_quality": "UNRECORDED"
            },
            "target_artifact": {
                "artifact_id": "PID-200",
                "domain": "memory",
                "artifact_type": "process",
                "timestamp_quality": "UNRECORDED"
            },
            "temporal_context": { "temporal_order": "UNKNOWN" },
            "annotation": {
                "epistemic_label": "VERIFIED_POSITIVE",
                "ground_truth_causal_label": 1,
                "relationship_type": "PARENT_CHILD_PROCESS",
                "label_rationale": "Generic PID on Host B in TEST split.",
                "annotation_source": "TEST",
                "annotator_ids": ["EX_1"]
            },
            "split": "TEST"
        }
    ]

    result = CorrelationDatasetValidator.validate(samples)
    # Must NOT fail structural validity
    assert result.is_structurally_valid is True
    # Must record suspicious similarity diagnostic
    assert len(result.suspicious_id_similarity_diagnostics) == 1
    assert any("Suspicious generic ID similarity" in w["message"] for w in result.structural_warnings)


def test_timezone_naive_and_aware_mismatch_rejected():
    """
    Asserts that mixing timezone-aware (Z) and timezone-naive timestamps raises a validation error.
    """
    raw_sample = {
        "sample_id": "TZ-ERR-001",
        "investigation_id": "CASE_TZ",
        "schema_version": "1.0.0",
        "source_artifact": {
            "artifact_id": "ART-1",
            "domain": "memory",
            "artifact_type": "process",
            "timestamp": "2026-09-20T08:00:00Z",
            "timestamp_quality": "EXACT_ORIGIN"
        },
        "target_artifact": {
            "artifact_id": "ART-2",
            "domain": "memory",
            "artifact_type": "process",
            "timestamp": "2026-09-20T08:00:10",
            "timestamp_quality": "EXACT_ORIGIN"
        },
        "temporal_context": {
            "delta_seconds": 10.0,
            "temporal_order": "SOURCE_PRECEDES_TARGET"
        },
        "annotation": {
            "epistemic_label": "VERIFIED_POSITIVE",
            "ground_truth_causal_label": 1,
            "relationship_type": "PARENT_CHILD_PROCESS",
            "label_rationale": "Testing timezone consistency validation.",
            "annotation_source": "TEST",
            "annotator_ids": ["EX_1"]
        }
    }
    with pytest.raises(ValidationError) as exc:
        CorrelationSample.model_validate(raw_sample)
    assert "mixed timezone-aware and timezone-naive" in str(exc.value)


def test_forward_causal_temporal_inversion_rejected():
    """
    Asserts that a forward causal positive relationship (like PARENT_CHILD_PROCESS)
    where target event is timestamped before source on the exact same host is rejected.
    """
    raw_sample = {
        "sample_id": "CAUSAL-ERR-001",
        "investigation_id": "CASE_CAUSAL",
        "schema_version": "1.0.0",
        "source_artifact": {
            "artifact_id": "ART-PARENT",
            "domain": "memory",
            "artifact_type": "process",
            "timestamp": "2026-09-20T08:00:15Z",
            "timestamp_quality": "EXACT_ORIGIN"
        },
        "target_artifact": {
            "artifact_id": "ART-CHILD",
            "domain": "memory",
            "artifact_type": "process",
            "timestamp": "2026-09-20T08:00:00Z",
            "timestamp_quality": "EXACT_ORIGIN"
        },
        "temporal_context": {
            "delta_seconds": -15.0,
            "temporal_order": "TARGET_PRECEDES_SOURCE",
            "clock_skew_risk": "NONE_SAME_SYSTEM"
        },
        "annotation": {
            "epistemic_label": "VERIFIED_POSITIVE",
            "ground_truth_causal_label": 1,
            "relationship_type": "PARENT_CHILD_PROCESS",
            "label_rationale": "Child process claiming to be born before parent on same host.",
            "annotation_source": "TEST",
            "annotator_ids": ["EX_1"]
        }
    }
    with pytest.raises(ValidationError) as exc:
        CorrelationSample.model_validate(raw_sample)
    assert "violates forward causal validity" in str(exc.value)


def test_partial_domain_confounding_diagnostics():
    """
    Asserts that partial domain confounding (>90% positive in a domain transition) triggers a diagnostic warning.
    """
    samples = []
    # 9 positive samples and 1 negative sample for memory -> network
    for i in range(9):
        samples.append({
            "sample_id": f"PART-POS-{i}",
            "investigation_id": f"CASE_{i}",
            "schema_version": "1.0.0",
            "source_artifact": { "artifact_id": f"P-{i}", "domain": "memory", "artifact_type": "process", "timestamp_quality": "UNRECORDED" },
            "target_artifact": { "artifact_id": f"N-{i}", "domain": "network", "artifact_type": "flow", "timestamp_quality": "UNRECORDED" },
            "temporal_context": { "temporal_order": "UNKNOWN" },
            "annotation": {
                "epistemic_label": "VERIFIED_POSITIVE",
                "ground_truth_causal_label": 1,
                "relationship_type": "EXECUTION_TO_NETWORK_FLOW",
                "label_rationale": "Valid execution to network connection.",
                "annotation_source": "EMULATION_LOG",
                "annotator_ids": ["EMU_1"]
            }
        })
    samples.append({
        "sample_id": "PART-NEG-0",
        "investigation_id": "CASE_99",
        "schema_version": "1.0.0",
        "source_artifact": { "artifact_id": "P-99", "domain": "memory", "artifact_type": "process", "timestamp_quality": "UNRECORDED" },
        "target_artifact": { "artifact_id": "N-99", "domain": "network", "artifact_type": "flow", "timestamp_quality": "UNRECORDED" },
        "temporal_context": { "temporal_order": "UNKNOWN" },
        "annotation": {
            "epistemic_label": "VERIFIED_NEGATIVE",
            "ground_truth_causal_label": 0,
            "relationship_type": "COINCIDENTAL_NOISE",
            "label_rationale": "Coincidental network flow.",
            "annotation_source": "EMULATION_LOG",
            "annotator_ids": ["EMU_1"]
        }
    })

    result = CorrelationDatasetValidator.validate(samples)
    assert len(result.partial_domain_confounding_warnings) >= 1
    assert any("Transition 'memory -> network' is 90.0% positive" in w for w in result.partial_domain_confounding_warnings)
    assert "memory -> network" in result.domain_pair_contingency
    assert result.domain_pair_contingency["memory -> network"]["TOTAL"] == 10


def test_pilot_phase1c2_audited_dataset_structural_validation():
    """
    Verifies that the audited & expanded pilot dataset (23 pairs across 3 independent cases)
    passes full structural validation, exhibits zero duplicate pairs, zero case leakage,
    and fails training readiness honestly.
    """
    fixture_path = FIXTURES_DIR / "pilot_phase1c2_audited_expanded_dataset.json"
    assert fixture_path.exists(), f"Missing fixture: {fixture_path}"

    result = CorrelationDatasetValidator.validate(fixture_path)
    assert result.is_structurally_valid is True, f"Structural validation failed: {result.structural_errors}"
    assert result.total_records_processed == 23
    assert result.valid_record_count == 23
    assert len(result.structural_errors) == 0
    assert len(result.duplicate_sample_ids) == 0
    assert len(result.duplicate_artifact_pairs) == 0
    assert len(result.split_investigation_leakage) == 0

    # Verify that readiness gates fail honestly (since n=23 < 2500, cases=3 < 15)
    assert result.is_training_ready is False
    assert result.training_readiness_gates["Gate 1: Minimum Scale"]["status"] == "FAIL"
    assert result.training_readiness_gates["Gate 2: Case Diversity"]["status"] == "FAIL"
    # Gate 6 (uncertainty representation >= 5%) passes because ambiguous pairs are honestly labeled
    assert result.training_readiness_gates["Gate 6: Ambiguous / Uncertainty Representation"]["status"] == "PASS"

