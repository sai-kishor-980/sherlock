# SherlockAI / H-MACFR — Correlation Learning Phase 1A: Dataset Schema, Validator, and Quality Gates Report

**Phase:** Phase 1A (Dataset Schema, Validator, and Quality Gates)  
**Date:** 2026-10-23  
**Framework:** H-MACFR (Hierarchical Multi-Agent Cyber Forensic Reconstruction)  
**Status:** COMPLETE & VERIFIED (64/64 Backend Tests Passed)  
**Deliverable File:** `CORRELATION_DATASET_PHASE1A_REPORT.md`

---

## 1. Executive Summary

In adherence to [`CORRELATION_TRAINING_PLAN.md`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/CORRELATION_TRAINING_PLAN.md), Phase 1A establishes the foundational dataset infrastructure required to represent, audit, and validate forensic artifact pairs before collecting the multi-case training corpus.

No machine learning models were trained, no existing correlation engine rules were modified, and no synthetic fixtures were falsely claimed as real forensic evidence.

### Key Milestones Achieved
1. **Versioned Dataset Schema (`1.0.0`):** Defined strongly-typed Pydantic schemas in [`app/db/schemas/correlation_dataset.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/db/schemas/correlation_dataset.py) supporting three-way epistemic labels (`VERIFIED_POSITIVE`, `VERIFIED_NEGATIVE`, `AMBIGUOUS_UNRESOLVED`), honest missing-timestamp handling, provenance tracking, and strict internal consistency constraints.
2. **Independent Two-Report Validation Engine:** Implemented [`CorrelationDatasetValidator`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/correlation_validator_service.py) with clean separation between:
   - **Report A (Structural Validity):** Syntactic validity, internal field consistency, duplicate pair detection, and investigation-level split leakage.
   - **Report B (Training Readiness):** Automated audit against the 7 research gates from [`CORRELATION_TRAINING_PLAN.md`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/CORRELATION_TRAINING_PLAN.md) (scale $\ge 2,500$, case diversity $\ge 15$, class balance, domain confounding check, relationship coverage, and inter-rater consensus).
3. **Reusable Validation CLI:** Built [`app/cli/validate_correlation_dataset.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/cli/validate_correlation_dataset.py) returning exit code `0` for structural validity, exit code `1` for structural failures, and exit code `2` when `--check-readiness` flags unready datasets.
4. **Synthetic Test Fixtures:** Created 5 focused unit fixtures in [`tests/fixtures/correlation_datasets/`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/tests/fixtures/correlation_datasets/) demonstrating valid structures, duplicate pairs, contradictory labels, domain confounding, and split leakage. All fixtures are explicitly flagged with `synthetic_fixture: true`.
5. **Comprehensive Automated Test Suite:** Implemented [`tests/test_correlation_dataset_validator.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/tests/test_correlation_dataset_validator.py). Full backend test suite passed: **64 passed, 0 failed in 108.92s**.

---

## 2. Inventory of Changed and Created Files

| File Path | Operation | Purpose |
| :--- | :--- | :--- |
| [`sherf/backend/app/db/schemas/correlation_dataset.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/db/schemas/correlation_dataset.py) | **CREATED** | Core Pydantic v2 data models, enums (`EpistemicLabel`, `RelationshipType`, `ArtifactDomain`, `TemporalOrderStatus`, `TimestampQuality`, `ClockSkewRisk`, `DatasetSplit`, `AdjudicationStatus`), and validators. |
| [`sherf/backend/app/db/schemas/__init__.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/db/schemas/__init__.py) | **MODIFIED** | Imported and exported correlation dataset schemas and constants in package `__all__`. |
| [`sherf/backend/app/services/correlation_validator_service.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/correlation_validator_service.py) | **CREATED** | Reusable validator engine producing distinct Structural Validity and Training Readiness reports, leakage detection, and domain confounding audits. |
| [`sherf/backend/app/cli/validate_correlation_dataset.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/cli/validate_correlation_dataset.py) | **CREATED** | Standalone CLI entrypoint supporting `--check-readiness`, `--json`, and distinct exit codes (0, 1, 2). |
| [`sherf/backend/tests/fixtures/correlation_datasets/synthetic_valid_dev_fixture.json`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/tests/fixtures/correlation_datasets/synthetic_valid_dev_fixture.json) | **CREATED** | 5-sample synthetic fixture containing positive, negative, and ambiguous examples with honest missing timestamps. |
| [`sherf/backend/tests/fixtures/correlation_datasets/synthetic_invalid_schema.json`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/tests/fixtures/correlation_datasets/synthetic_invalid_schema.json) | **CREATED** | Fixture with missing required fields, invalid domains, and malformed labels. |
| [`sherf/backend/tests/fixtures/correlation_datasets/synthetic_duplicate_pairs.json`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/tests/fixtures/correlation_datasets/synthetic_duplicate_pairs.json) | **CREATED** | Fixture with duplicate sample IDs and duplicate artifact pairs within the same case. |
| [`sherf/backend/tests/fixtures/correlation_datasets/synthetic_contradictory_labels.json`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/tests/fixtures/correlation_datasets/synthetic_contradictory_labels.json) | **CREATED** | Fixture asserting rejection of `VERIFIED_POSITIVE` with binary label 0. |
| [`sherf/backend/tests/fixtures/correlation_datasets/synthetic_leakage_dataset.json`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/tests/fixtures/correlation_datasets/synthetic_leakage_dataset.json) | **CREATED** | Fixture asserting rejection of same investigation partitioned across `TRAIN` and `TEST`. |
| [`sherf/backend/tests/fixtures/correlation_datasets/synthetic_confounded_dataset.json`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/tests/fixtures/correlation_datasets/synthetic_confounded_dataset.json) | **CREATED** | Fixture asserting detection of 100% domain confounding. |
| [`sherf/backend/tests/test_correlation_dataset_validator.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/tests/test_correlation_dataset_validator.py) | **CREATED** | 9 comprehensive automated tests for schema validation, CLI exit codes, and quality gates. |
| [`CORRELATION_DATASET_PHASE1A_REPORT.md`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/CORRELATION_DATASET_PHASE1A_REPORT.md) | **CREATED** | Phase 1A comprehensive audit and verification deliverable. |

---

## 3. Schema Architecture Decisions

### 3.1 Versioning and Field Immutability
- **`schema_version: "1.0.0"`**: Included on every sample record. Any future breaking revisions to the taxonomy or feature layout will increment the minor or major version.
- **Extra Fields Forbidden (`extra="forbid"`)**: Enforced across sub-models (`DatasetArtifact`, `DatasetAnnotation`, `DatasetTemporalContext`, `EvidenceProvenance`) to prevent silent field typos or unrecognized heuristic clutter.

### 3.2 Epistemic Label Rigor (Three-Way Partition)
The schema enforces three mutually exclusive labels:
1. `VERIFIED_POSITIVE`: Must have `ground_truth_causal_label == 1`. Cannot be assigned `RelationshipType.COINCIDENTAL_NOISE`.
2. `VERIFIED_NEGATIVE`: Must have `ground_truth_causal_label == 0`.
3. `AMBIGUOUS_UNRESOLVED`: Must have `ground_truth_causal_label == None`.
   - **Rationale:** Forcing an ambiguous pair (e.g. unknown process creation time in RAM, inverted timestamps from clock skew) into a binary $0$ or $1$ introduces label noise and ruins probability calibration.

### 3.3 Honest Missing-Timestamp Modeling
In digital forensics, raw telemetry often genuinely lacks timestamps (e.g. unbacked VAD allocation in volatile RAM, deleted registry key slack, raw TCP fragments without initial handshake).
- If `timestamp is None`, `timestamp_quality` must be set to `TimestampQuality.UNRECORDED` or `TimestampQuality.UNAVAILABLE`.
- If a record has `timestamp is None` but claims `timestamp_quality == EXACT_ORIGIN`, the validator raises an immediate schema error.

### 3.4 Strict Non-Leakage Group Splitting
- Split metadata is explicitly tracked per record: `TRAIN`, `VALIDATION`, `TEST`, or `UNASSIGNED`.
- The validator tracks `investigation_id -> Set[DatasetSplit]`. If any investigation appears in more than one split, the dataset fails structural validation with a `Data leakage error`.

---

## 4. Separation of Structural Validity from Training Readiness

A central requirement of Phase 1A was ensuring that a small, clean development fixture can be validated structurally without weakening the research readiness standards established in [`CORRELATION_TRAINING_PLAN.md`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/CORRELATION_TRAINING_PLAN.md).

### Comparison Matrix

| Property | Report A: Structural Validity | Report B: Research Training Readiness |
| :--- | :--- | :--- |
| **Objective** | Ensure records are syntactically valid and internally non-contradictory. | Ensure the corpus is statistically sound, unconfounded, and ready for model training. |
| **Minimum Sample Count ($N$)** | $\ge 1$ record | $\ge 2,500$ annotated pairs |
| **Minimum Case Diversity ($K$)** | $\ge 1$ investigation | $\ge 15$ independent investigations |
| **Domain Confounding Check** | Informational warning if present | **Hard Failure** (Gate 4 fails if 100% confounded) |
| **Class Balance Check** | Informational distribution counter | **Hard Failure** (Gate 3 fails if outside 35%–55% pos) |
| **Split Leakage Check** | **Hard Failure** (Exit code 1) | **Hard Failure** |
| **Small Dev Fixture Result** | **PASS** | **FAIL (Expected: Not Training Ready)** |
| **CLI Exit Code Behavior** | Fails with exit code `1` | Fails with exit code `2` only when `--check-readiness` is passed |

---

## 5. Verification Commands and Test Execution

### 5.1 CLI Execution Against Synthetic Fixtures

#### 1. Valid Development Fixture (Structural Check Only):
```bash
python -m app.cli.validate_correlation_dataset tests/fixtures/correlation_datasets/synthetic_valid_dev_fixture.json
```
**Output:**
```
================================================================================
 SHERLOCKAI / H-MACFR — CORRELATION DATASET VALIDATION REPORT
================================================================================
 Total Records Processed: 5
 Valid Structural Records: 5
 Structural Status:        PASS
 Training Readiness Status: NOT READY (Expected for Dev/Fixtures)
--------------------------------------------------------------------------------
 [SECTION A] STRUCTURAL VALIDITY REPORT
  [OK] Dataset is structurally valid and internally consistent.
--------------------------------------------------------------------------------
 [SECTION B] FORENSIC DISTRIBUTIONS & STATISTICS
  Investigations (Cases): 2 unique case(s)
    - SYNTH_CASE_ALPHA: 4 pair(s)
    - SYNTH_CASE_BETA: 1 pair(s)
  Epistemic Labels: {'VERIFIED_POSITIVE': 2, 'VERIFIED_NEGATIVE': 2, 'AMBIGUOUS_UNRESOLVED': 1}
  Binary Causal Labels: {'POSITIVE (1)': 2, 'NEGATIVE (0)': 2, 'AMBIGUOUS (null)': 1}
  Relationship Types: {'PARENT_CHILD_PROCESS': 1, 'PERSISTENCE_TO_EXECUTION': 1, 'COINCIDENTAL_NOISE': 2, 'PROCESS_INJECTION': 1}
--------------------------------------------------------------------------------
 [SECTION C] RESEARCH TRAINING READINESS GATES
  (Evaluates compliance with CORRELATION_TRAINING_PLAN.md criteria)
  - Gate 1: Minimum Scale: [FAIL] (Target: >= 2,500 pairs | Measured: 5 pairs)
      Diagnostic: Corpus has 5 pairs; requires >= 2,500 pairs for supervised training.
  - Gate 2: Case Diversity: [FAIL] (Target: >= 15 independent investigations | Measured: 2 investigations)
      Diagnostic: Only 2 case(s) present. Model risks memorizing specific environment topology.
================================================================================
[RESULT] VALIDATION SUCCESSFUL. Exit code 0.
```

#### 2. Valid Development Fixture with `--check-readiness`:
```bash
python -m app.cli.validate_correlation_dataset tests/fixtures/correlation_datasets/synthetic_valid_dev_fixture.json --check-readiness
```
**Exit Code:** `2`  
**Stderr:** `[RESULT] TRAINING READINESS GATES FAILED (Structurally valid, but not research-ready). Exit code 2.`

#### 3. Structurally Invalid Fixture:
```bash
python -m app.cli.validate_correlation_dataset tests/fixtures/correlation_datasets/synthetic_invalid_schema.json
```
**Exit Code:** `1`  
**Stderr:** `[RESULT] STRUCTURAL VALIDATION FAILED. Exit code 1.`

---

### 5.2 Automated Pytest Suite Results

Executed the newly created unit tests:
```bash
pytest tests/test_correlation_dataset_validator.py
```
**Result:** `9 passed, 1 warning in 1.23s`

Executed the complete backend regression test suite:
```bash
pytest tests/
```
**Result:** `64 passed, 327 warnings in 108.92s`

```
tests\test_correlation_dataset_validator.py .........                    [ 14%]
tests\test_correlation_phase1_validation.py ............                 [ 32%]
tests\test_encryption.py .                                               [ 34%]
tests\test_events.py .                                                   [ 35%]
tests\test_forensic_audit_corrections.py ......                          [ 45%]
tests\test_hashing.py .                                                  [ 46%]
tests\test_permissions.py .                                              [ 48%]
tests\test_preservation.py ....                                          [ 54%]
tests\test_sis_and_chatbot.py ...                                        [ 59%]
tests\test_sprint2_knowledge_and_graph.py .......                        [ 70%]
tests\test_stage2_authorization.py .........                             [ 84%]
tests\test_stage3_workspace_api.py .....                                 [ 92%]
tests\test_storage.py ..                                                 [ 95%]
tests\test_upload.py .                                                   [ 96%]
tests\test_verification.py ..                                            [100%]
================ 64 passed, 327 warnings in 108.92s (0:01:48) =================
```

---

## 6. Audit Classification: Facts, Assumptions, and Limitations

| Statement / Finding | Classification | Evidence / Basis |
| :--- | :--- | :--- |
| Versioned schema enforces three-way labels | **Verified Fact** | Inspected [`correlation_dataset.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/db/schemas/correlation_dataset.py). Pydantic validators reject ambiguous examples with binary labels. |
| CLI accurately distinguishes validity from readiness | **Verified Fact** | Verified by `test_cli_exit_codes_and_diagnostics` (Exit 0 on structural pass, Exit 2 on readiness fail with `--check-readiness`, Exit 1 on structural fail). |
| Cross-split investigation leakage is caught | **Verified Fact** | Verified by `test_investigation_split_leakage_detected` on `synthetic_leakage_dataset.json`. |
| Domain confounding is detected | **Verified Fact** | Verified by `test_domain_confounding_detected` on `synthetic_confounded_dataset.json`. |
| Production readiness requires $\ge 2,500$ pairs across $\ge 15$ cases | **Rule Baseline** | Defined as minimum research criteria in [`CORRELATION_TRAINING_PLAN.md`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/CORRELATION_TRAINING_PLAN.md). |
| Existing synthetic fixtures do not represent real-world accuracy | **Verified Fact** | All test fixtures are synthetic unit tests marked with `synthetic_fixture: true`. No machine learning generalization claims are made. |

---

## 7. Remaining Limitations and Next Steps (Phase 1B Readiness)

### Limitations in Current Phase
1. **Corpus Not Yet Collected:** The validator and schema are fully operational, but the multi-case training corpus ($N \ge 2,500$, $K \ge 15$) has not yet been acquired or annotated.
2. **Inter-Rater Reliability Score Pending Corpus:** The validator checks annotator count per record (`len(annotator_ids) >= 2`), but empirical Cohen's Kappa calculation requires the multi-examiner corpus from Phase 1B.
3. **Correlation Engine Unaltered:** The production rule engine in `synthesizer_service.py` remains active and untouched; no model training has occurred.

### Next Steps (Phase 1B & Beyond)
- **Phase 1B:** Acquire multi-case forensic datasets from public DFIR challenge benchmarks (NIST CFReDS, CyberDefenders) and Caldera/Atomic Red Team automated attack emulations.
- **Phase 1C:** Execute the two-examiner annotation protocol to produce `correlation_corpus_v1.json`, validating it through the CLI until all 7 training readiness gates pass.
- **Phase 2:** Train the baseline tabular LightGBM model surrounded by the deterministic forensic safety envelope.

---
*End of Correlation Learning Phase 1A Report — SherlockAI.*
