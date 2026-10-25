# SherlockAI Correlation Learning — Phase 1B / 1B.1: Validator Audit and Dataset Collection Readiness Report

**Phase:** Phase 1B & Phase 1B.1 (Validator Audit, Defect Resolution, Gaps Closure, and Collection Readiness)  
**Date:** 2026-10-23  
**Framework:** H-MACFR (Hierarchical Multi-Agent Cyber Forensic Reconstruction)  
**Status:** COMPLETE & VERIFIED (77/77 Backend Tests Passed, 22/22 Validator Suite Passed)  
**Deliverable File:** `CORRELATION_DATASET_PHASE1B_AUDIT.md`

---

## 1. Executive Summary

Following [`CORRELATION_DATASET_PHASE1A_REPORT.md`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/CORRELATION_DATASET_PHASE1A_REPORT.md) and [`CORRELATION_TRAINING_PLAN.md`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/CORRELATION_TRAINING_PLAN.md), Phase 1B and Phase 1B.1 conducted an adversarial technical audit and gap-closure cycle on the dataset schema, validation engine, CLI, and test fixtures.

We did not assume that report claims or passing unit tests equated to real-world forensic validity. Instead, we subjected the implementation to adversarial failure modes, identified edge-case gaps, remediated all confirmed defects, added targeted regression tests, verified CLI execution across all fixtures in both structural and readiness modes, and established the operational collection guide for acquiring multi-case forensic data.

### Key Milestones Delivered in Phase 1B / 1B.1:
1. **Relationship Identity and Directionality Formalization:**
   - Distinguished duplicate records, contradictory labels for the same assertion, impossible causal cycles, and valid reversed assertions.
   - Encoded relationship-aware assertion keys: directed assertions track $(A \to B, rel)$, while undirected assertions (`COINCIDENTAL_NOISE`) track $\{A, B\}$.
   - Reversing a directed relationship with an opposite label (e.g. $A \to B$ is `PARENT_CHILD_PROCESS` `VERIFIED_POSITIVE`, while $B \to A$ is `PARENT_CHILD_PROCESS` `VERIFIED_NEGATIVE`) is recognized as valid negative hard mining and passes cleanly.
   - Pair-level contradictions between positive causal relationships and `COINCIDENTAL_NOISE` are strictly caught.
2. **Cross-Case Leakage vs Identifier Similarity:**
   - Distinguished confirmed physical evidence leakage (via cryptographic SHA-256 entity hashes or storage hashes with record locators) from innocent generic identifier collisions (e.g. two separate Windows cases both containing `PID-1048` and `PID-2048`).
   - Confirmed evidence collisions across splits fail structural validation; generic local ID collisions across splits generate diagnostic warnings without failing valid cases.
3. **Timestamp Semantics and Forward Causal Feasibility:**
   - Integrated strict ISO-8601 parsing with microsecond precision and UTC timezone normalization (`parse_iso_timestamp`).
   - Prevented mixing timezone-aware (e.g. `...Z`) and timezone-naive timestamps.
   - Enforced configurable mathematical delta consistency: $|\Delta t_{\text{recorded}} - (t_2 - t_1)| \le \text{tolerance}$ (`TIMESTAMP_DELTA_TOLERANCE_SECONDS = 1.0`).
   - Enforced forward causal temporal feasibility: for positive forward causal relationships (`PARENT_CHILD_PROCESS`, `PERSISTENCE_TO_EXECUTION`, `DOWNLOAD_TO_EXECUTION`, `LOGON_TO_PRIVILEGE_USE`, `CREDENTIAL_ACCESS_TO_AUTH`, `EXECUTION_TO_NETWORK_FLOW`) with exact origin timestamps on the same system without clock skew, a target event occurring before the source event is rejected.
4. **Domain Confounding & Transition Contingency:**
   - Built a 2D source-target domain transition contingency table reporting positive, negative, and ambiguous counts for every domain pair.
   - Implemented automated partial domain confounding diagnostics flagging any domain transition with $\ge 90\%$ or $\le 10\%$ positive rates ($N \ge 5$).
   - Guarded against bidirectional extreme confounding (100% positive intra / 100% negative cross, or 100% positive cross / 100% negative intra).
5. **Annotation Quality & Adjudication Pathways:**
   - Strictly separated three valid ground-truth pathways: Automated Emulation Logs (`EMULATION_LOG`), Multi-Annotator Consensus (`CONSENSUS_VERIFIED`, $\ge 2$ annotators), and Multi-Annotator Arbitration (`ARBITRATED`, $\ge 2$ annotators).
   - Ensured that single-reviewer opinions and unreviewed samples cannot satisfy Gate 7, and any unresolved disputed sample (`DISPUTED`) immediately fails Gate 7.
6. **Fixture Discrepancy Resolution:**
   - Clarified the count discrepancy: Phase 1A documented 5 samples in [`synthetic_valid_dev_fixture.json`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/tests/fixtures/correlation_datasets/synthetic_valid_dev_fixture.json), whereas the initial Phase 1B summary table mistakenly cited 14 samples due to a drafting typo. The actual file contains exactly **5 samples** (2 positive, 2 negative, 1 ambiguous). This has been rectified and verified across all reports and CLI runs.

---

## 2. Findings Ranked by Severity

| ID | Severity | Category | Description | Root Cause | Remediation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **F-01** | **CRITICAL** | Integrity / False-Pass | **Contradictory labels for identical evidence pairs passed.** A sample claiming $(A, B)$ is causal was not cross-referenced against a sample claiming $(A, B)$ is coincidental noise. | Directed pairs and undirected noise were partitioned into separate dictionaries, preventing cross-relationship contradiction checks. | Unified pair-level tracking for causal positives vs noise. Assertion keying now checks contradictory labels for the same assertion and cross-concept conflicts between causal links and coincidental noise. |
| **F-02** | **HIGH** | Forensic Rigor / False-Pass | **Cyclic directed causality passed.** Mutually causal pairs ($A \to B$ and $B \to A$ both with label 1) passed structural validation. | Forward and reverse pairs were stored under separate directional keys without mutual cycle checking. | Added canonical cycle detector checking whether both forward and reverse directed edges claim positive causal lineage. |
| **F-03** | **HIGH** | Gate Reliability / False-Pass | **Gate 7 (Consensus) counted disputed annotations.** Merely supplying 2 annotator ID strings satisfied the gate even when `adjudication_status == "DISPUTED"`. | Gate logic checked `len(annotator_ids) >= 2 or status == CONSENSUS_VERIFIED` without excluding `DISPUTED`. | Gate 7 now strictly requires `len(annotator_ids) >= 2 AND adjudication_status in (CONSENSUS_VERIFIED, ARBITRATED)` or `EMULATION_LOG`. Rejects if any disputed records exist. |
| **F-04** | **MEDIUM** | Schema Consistency | **Inconsistent temporal delta vs event timestamps.** Timestamps could differ by 10 seconds while `delta_seconds` claimed 5,000 seconds, and non-ISO strings passed. | Pydantic model only checked sign of `delta_seconds` against `temporal_order`, omitting delta calculation. | Added model validator computing `expected_delta = (t_b - t_a).total_seconds()` and enforcing $| \Delta t_{\text{recorded}} - \Delta t_{\text{expected}} | \le 1.0\text{s}$ alongside ISO-8601 parsing and forward causal ordering. |
| **F-05** | **MEDIUM** | Split Leakage | **Generic local artifact IDs falsely failed independent cases, while cross-case physical duplicates risked passing.** | Split leakage initially checked only local artifact ID strings without verifying whether cryptographic hashes or storage provenance matched. | Implemented `compute_artifact_evidence_fingerprint`. If cryptographic SHA-256 or storage provenance collides across splits, it is flagged as confirmed leakage. Generic ID name collisions across cases generate non-fatal diagnostic warnings. |
| **F-06** | **LOW** | Scalability | **Full-dataset memory buffering.** Multi-hundred-megabyte JSONL files risked OOM during ingestion. | Whole-file `f.read()` before parsing. | Implemented streaming JSONL line-by-line reading in `CorrelationDatasetValidator.load_dataset_file`. |

---

## 3. Directionality and Relationship Taxonomy

In [`app/db/schemas/correlation_dataset.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/db/schemas/correlation_dataset.py):

```
                                Relationship Taxonomy
                                          │
            ┌─────────────────────────────┴─────────────────────────────┐
            ▼                                                           ▼
   Undirected (Symmetric)                                     Strictly Directed
   • COINCIDENTAL_NOISE                                        • PARENT_CHILD_PROCESS
     - Direction is meaningless:                               • PROCESS_INJECTION
       (A, B) and (B, A) are identical duplicates.             • PERSISTENCE_TO_EXECUTION
     - Assertion key: {inv, min(A,B), max(A,B), NOISE}         • EXECUTION_TO_NETWORK_FLOW
                                                               • DNS_TO_NETWORK_FLOW
                                                               • LNK_TO_FILE_ACCESS
                                                               • DOWNLOAD_TO_EXECUTION
                                                               • LOGON_TO_PRIVILEGE_USE
                                                               • CREDENTIAL_ACCESS_TO_AUTH
                                                               - Direction defines causal arrow:
                                                                 (A -> B) != (B -> A)
```

### Directional Assertion Rules:
1. **Identical Assertion Duplicates:**
   - Sample 1: $A \xrightarrow{rel} B$ with label $L$
   - Sample 2: $A \xrightarrow{rel} B$ with label $L$
   - $\rightarrow$ **DUPLICATE_SAMPLE_PAIR** (Fatal error).
2. **Conflicting Labels for Same Assertion:**
   - Sample 1: $A \xrightarrow{rel} B$ with `VERIFIED_POSITIVE`
   - Sample 2: $A \xrightarrow{rel} B$ with `VERIFIED_NEGATIVE`
   - $\rightarrow$ **CONTRADICTORY_LABEL_CONFLICT** (Fatal error).
3. **Valid Reversed Assertions (Hard Negative Mining):**
   - Sample 1: $A \xrightarrow{PARENT\_CHILD} B$ with `VERIFIED_POSITIVE` ($A$ spawned $B$).
   - Sample 2: $B \xrightarrow{PARENT\_CHILD} A$ with `VERIFIED_NEGATIVE` ($B$ did not spawn $A$).
   - $\rightarrow$ **VALID & ACCEPTED** (Forensically true and non-contradictory).
4. **Impossible Causal Cycles:**
   - Sample 1: $A \xrightarrow{rel_1} B$ with `VERIFIED_POSITIVE`
   - Sample 2: $B \xrightarrow{rel_2} A$ with `VERIFIED_POSITIVE`
   - $\rightarrow$ **CYCLIC_RELATIONSHIP** (Fatal error: mutual positive causality).
5. **Causal vs Noise Conflict:**
   - Sample 1: $A \xrightarrow{rel} B$ with `VERIFIED_POSITIVE` (Causal relationship established).
   - Sample 2: $A \leftrightarrow B$ labeled as `COINCIDENTAL_NOISE` (Claiming pair is background noise).
   - $\rightarrow$ **CONTRADICTORY_LABEL_CONFLICT** (Fatal error).

---

## 4. Empirical Test and CLI Verification Results

### 4.1 CLI Execution Matrix Across All Synthetic Fixtures

All fixtures executed via [`app/cli/validate_correlation_dataset.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/cli/validate_correlation_dataset.py):

| Fixture File | Samples | CLI Mode | Exit Code | Diagnostic Message Logged | Status |
| :--- | :---: | :--- | :---: | :--- | :---: |
| `synthetic_valid_dev_fixture.json` | 5 | Structural | `0` | `Structural Status: PASS` (5 valid records, 0 errors, 0 warnings) | **PASS** |
| `synthetic_valid_dev_fixture.json` | 5 | `--check-readiness` | `2` | `Gate 1: Minimum Scale: [FAIL] (requires >= 2,500 pairs)` | **PASS** |
| `synthetic_invalid_schema.json` | 1 | Structural | `1` | `Input should be 'memory', 'disk', 'network'...` | **PASS** |
| `synthetic_duplicate_pairs.json` | 2 | Structural | `1` | `Duplicate pair detected (directed) in investigation 'SYNTH_CASE_DUP'` | **PASS** |
| `synthetic_reversed_noise_duplicate.json` | 2 | Structural | `1` | `Duplicate pair detected (symmetric) in investigation 'SYNTH_CASE_SYM'` | **PASS** |
| `synthetic_cyclic_directed_relationship.json` | 2 | Structural | `1` | `Cyclic / inverted directed causality error: Both PID-10 -> PID-20 and PID-20 -> PID-10 claim positive causal lineage` | **PASS** |
| `synthetic_contradictory_pair_labels.json` | 2 | Structural | `1` | `Contradictory label conflict: Evidence pair PID-500 <-> PID-600 has conflicting labels ['VERIFIED_NEGATIVE', 'VERIFIED_POSITIVE']` | **PASS** |
| `synthetic_disputed_annotator_gate.json` | 5 | `--check-readiness` | `2` | `Gate 7: Annotation Consensus & Quality: [FAIL] (1 unresolved disputed label(s))` | **PASS** |
| `synthetic_inconsistent_delta.json` | 1 | Structural | `1` | `inconsistent temporal delta: delta_seconds is 5000.00s, but timestamp difference is 10.00s` | **PASS** |
| `synthetic_invalid_timestamp_format.json` | 1 | Structural | `1` | `invalid ISO-8601 timestamp '2026-99-99 99:99:99'` | **PASS** |
| `synthetic_cross_case_leakage.json` | 2 | Structural | `1` | `Cross-split duplicate evidence leakage: Artifact pair with fingerprints ... appears across multiple splits: ['TEST', 'TRAIN']` | **PASS** |
| `synthetic_leakage_dataset.json` | 2 | Structural | `1` | `Data leakage error: Investigation 'SYNTH_CASE_LEAKED' is partitioned across multiple splits: ['TEST', 'TRAIN']` | **PASS** |
| `synthetic_confounded_dataset.json` | 4 | `--check-readiness` | `2` | `Gate 4: Domain Balance (No Confounding): [FAIL] (100% of positive pairs are intra-domain AND 100% of negative pairs are cross-domain)` | **PASS** |

### 4.2 Automated Regression Suite Results

Executed the expanded validator test suite:
```bash
pytest tests/test_correlation_dataset_validator.py
```
**Result:** **22 passed, 1 warning in 1.36s**

Executed the full backend regression suite:
```bash
pytest tests/
```
**Result:** **77 passed, 327 warnings in 72.98s (0:01:12)**  
Zero regressions across database, authorization, cryptographic custody, graph API, and existing correlation synthesizer rules.

---

## 5. Investigator Dataset Collection Guide (Operational Infrastructure Protocol)

Investigators collecting multi-case forensic data for the H-MACFR correlation engine must strictly adhere to this four-stage protocol.

### 5.1 Case Sourcing and Isolation
1. **Multi-Source Acquisition:** Source forensic cases across 3 complementary operational origins:
   - *Source A (Benchmark Challenges):* NIST CFReDS, CyberDefenders, Magnet CTF images.
   - *Source B (Adversarial Emulations):* Caldera and Atomic Red Team executions on virtualized enterprise endpoints with Sysmon/ETW and PCAP collection.
   - *Source C (Benign Baselines):* Clean workstation activity from developers, administrators, and office productivity profiles.
2. **Case Partitioning:**
   - Every case ($K$) must be assigned to exactly one split (`TRAIN`, `VALIDATION`, or `TEST`).
   - Group partitioning must be enforced (`GroupKFold` on `investigation_id`).
   - Never copy or re-extract artifacts between cases in different splits.

### 5.2 Negative Pair Generation (Controlled Negative Mining)
To avoid domain confounding and synthetic shortcuts:
1. **Hard Negatives:** Mine intra-domain candidate pairs that share temporal proximity but lack causal connection:
   - Concurrently executing independent background processes (e.g. `svchost.exe` and `OneDrive.exe`).
   - Network flows initiated by unrelated system processes during an attack window.
   - Independent registry modifications occurring around user logon.
2. **Reversed Directional Negatives:**
   - For every verified causal relationship $A \xrightarrow{rel} B$, record $B \xrightarrow{rel} A$ labeled as `VERIFIED_NEGATIVE` when reverse causality is physically false.
3. **Domain Balancing:**
   - Target $\approx 50\%$ cross-domain positive pairs and $\approx 50\%$ intra-domain negative pairs to satisfy Gate 4.

### 5.3 Provenance and Custody Recording
Every sample must preserve audit-trail provenance:
- `storage_hash`: SHA-256 hash of the parent raw disk image, memory dump, or PCAP file.
- `file_path`: Extraction JSON or SQLite path relative to the case directory.
- `record_locator`: Record line, offset, or primary database key.
- `extractor_name`: Exact extraction tool and version (e.g. `Volatility3 v2.5.0 windows.pslist`).

### 5.4 Adjudication Protocol
```
                       Candidate Artifact Pair
                                  │
                  Independent Review by 2 Examiners
                                  │
         ┌────────────────────────┴────────────────────────┐
         ▼                                                 ▼
      Agreement                                       Disagreement
         │                                                 │
Assign CONSENSUS_VERIFIED                      Senior Examiner Arbitration
Both Examiner IDs Recorded                                 │
                                              ┌────────────┴────────────┐
                                              ▼                         ▼
                                          Resolved                 Unresolved
                                     Assign ARBITRATED           Assign DISPUTED
                                   Rationale Documented       (Excluded from Model)
```

---

## 6. Audit Classification: Facts, Assumptions, and Limitations

| Statement / Finding | Classification | Verification Source / Technical Evidence |
| :--- | :--- | :--- |
| Validator distinguishes directionality and reverses noise duplicates | **Verified Fact** | Verified by `test_reversed_noise_duplicate_detected` on `synthetic_reversed_noise_duplicate.json`. |
| Cyclic directed causality is caught | **Verified Fact** | Verified by `test_cyclic_directed_relationship_detected` on `synthetic_cyclic_directed_relationship.json`. |
| Valid reversed assertions pass | **Verified Fact** | Verified by `test_valid_reversed_assertion_passes` in unit test suite. |
| Cross-case evidence leakage is caught via cryptographic fingerprints | **Verified Fact** | Verified by `test_cross_case_evidence_leakage_detected` on `synthetic_cross_case_leakage.json`. |
| Generic ID name collisions generate non-fatal warnings | **Verified Fact** | Verified by `test_generic_id_similarity_across_splits_is_warning_not_error`. |
| Forward causal temporal violations are rejected | **Verified Fact** | Verified by `test_forward_causal_temporal_inversion_rejected`. |
| Partial domain confounding is detected | **Verified Fact** | Verified by `test_partial_domain_confounding_diagnostics`. |
| Development fixture count is 5 records | **Verified Fact** | Verified by `len(json.load(open('synthetic_valid_dev_fixture.json')))` and CLI output (5 records). |
| Existing repository data cannot train a model | **Verified Fact** | Verified in Phase 0 audit: $N=10$, $K=1$, 100% domain confounded. |
| Production correlation engine remains untouched | **Verified Fact** | [`synthesizer_service.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/synthesizer_service.py) unmodified; all 77 tests pass. |

---

## 7. Strategic GO / NO-GO Decisions

### Decision A: Real Data Collection Across Independent Cases
$$\mathbf{DECISION: \quad GO}$$
- **Rationale:** The schema, Pydantic validation models, quality gate engine, CLI tool, and collection protocols are fully implemented, audited, and verified against all adversarial edge cases. The infrastructure is 100% ready to ingest, validate, and audit real multi-case forensic data.

### Decision B: Training a First Baseline Model
$$\mathbf{DECISION: \quad NO\text{-}GO}$$
- **Rationale:** Model training remains strictly blocked. The existing repository dataset (`CASE_ALL5_F1A5D2`) contains only 10 pairs from 1 case with 100% domain confounding. Supervised model training will only be authorized once a real multi-case corpus ($N \ge 2500$, $K \ge 15$) passes all 7 research readiness gates.

---
*End of Phase 1B / 1B.1 Validator Audit and Collection Readiness Report — SherlockAI.*
