# SherlockAI — Correlation Engine Phase 1: Correctness Fixes and Validation Report

**Phase:** Correlation Engine Correctness Fixes & Empirical Validation  
**Date:** October 23, 2026  
**Auditor / Engineer:** Senior Digital Forensics Engineer & Correlation Engine Specialist  
**Status:** COMPLETE & VERIFIED  

---

## 1. Executive Summary

Phase 1 focused on identifying, isolating, and fixing foundational correctness and epistemic integrity defects within the multi-domain correlation engine (`synthesizer_service.py` and `graph_service.py`). No Graph API, GraphRAG prompt layers, or machine learning models were introduced in this phase, adhering strictly to engineering priority constraints.

### Key Milestones Achieved
1. **Timestamp Integrity Enforced**: Completely eliminated fallback substitution of lab workstation runtime (`utcnow()`) for missing target events. Timeline builder now explicitly preserves unrecorded timestamps (`None`) with `timestamp_quality: "UNAVAILABLE"` and `timestamp_source: "UNRECORDED"`, sorting unrecorded events to the end of the chronological ledger.
2. **Temporal Windowing & Skew Policies**: Implemented bidirectional temporal sequence policies across all correlation rules. The engine now calculates $\Delta t = T(\text{effect}) - T(\text{cause})$. When timestamps are inverted (e.g. child created before parent in PID reuse, prefetch executing prior to Run key modification, or flow preceding DNS lookup), the engine marks the relationship as `ANOMALOUS_INVERTED_TIMESTAMPS` and downgrades it to `AMBIGUOUS_ASSOCIATION` ($0.35 - 0.45$ confidence) without discarding evidence or fabricating chronology.
3. **Graph Entity Resolution Repaired**: Resolved previously dropped `RUNKEY-`, `PREFETCH-`, and `USB-` artifact references to genuine entity nodes in `EvidenceGraphService`. The engine no longer silently drops non-PID/DNS correlation edges.
4. **No-Fabrication Diagnostic Guard**: Ensured that when referenced source or target entities do not exist in evidence (e.g. parent PPID missing from volatile RAM pslist), the engine refuses to create fabricated nodes. Instead, it captures formal diagnostics in `G.graph["unresolved_correlation_edges"]` and exposes them via `get_graph_metrics()`.
5. **Zero Finding/Chain Duplication**: Consolidated multiple volatile memory malfind allocations for identical PIDs into singular findings and unified correlation chains.
6. **Empirical Verification**: All 11 focused validation tests in [`tests/test_correlation_phase1_validation.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/tests/test_correlation_phase1_validation.py) passed, and full backend test suites passed (33 passed in 23.03s, 7 knowledge/graph passed in 199.56s).

---

## 2. Confirmed Baseline Defects

| Defect ID | Severity | Component & Location | Baseline Description | Forensic Impact |
| :--- | :---: | :--- | :--- | :--- |
| **DEF-01** | **Critical** | [`synthesizer_service.py: _build_timeline`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/synthesizer_service.py#L645-L730) | When target artifact timestamps were absent, code substituted workstation runtime `datetime.datetime.utcnow().isoformat()`. For memory injection, it used lab extraction time `th_raw.get("generated_at")`. | Contaminated 2012 target forensic evidence with 2026 lab workstation timestamps, distorting chronological ordering by 14 years. |
| **DEF-02** | **Critical** | [`synthesizer_service.py: _build_correlations`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/synthesizer_service.py#L865-L1040) | Correlation rules asserted causality without computing $\Delta t$ or checking whether event sequences were chronologically plausible. | PID reuse, delayed DNS logging, and pre-existing binaries were blindly correlated as causal adversary actions. |
| **DEF-03** | **High** | [`graph_service.py: build_case_evidence_graph`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/graph_service.py#L367-L388) | Node resolver only handled `PID-` and `DNS-`/`NET-FLOW-`. When correlation referenced `RUNKEY-`, `PREFETCH-`, or `USB-`, `node_a` and `node_b` remained `None`. | Valid cross-domain correlations (e.g. Registry Persistence, USB Removable Device) were silently dropped from `evidence_graph.json`. |
| **DEF-04** | **High** | [`graph_service.py: build_case_evidence_graph`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/graph_service.py#L388) | When source/target nodes were missing, edges were omitted without emitting any diagnostic record. | Investigators had no visibility into why certain correlations were omitted from the graph visualization. |
| **DEF-05** | **Medium** | [`synthesizer_service.py: line 1051`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/synthesizer_service.py#L1051) | Removable USB noise rule hardcoded `"PREFETCH-VMWARETRAY"` regardless of what executables actually executed in `raw_pf`. | Failed to generalize across different disk prefetch evidence extracts. |

---

## 3. Changes Made & Exact Source Locations

### 1. `synthesizer_service.py`
* **`_parse_ts` Utility Added (lines 862–878)**:
  Parses ISO 8601 strings, UTC `Z` suffixes, and common forensic datetime formats (`%Y-%m-%d %H:%M:%S`) safely into Python `datetime.datetime` objects.
* **Timeline Timestamp Segregation (lines 620–737)**:
  * Memory injection events qualified with `timestamp_quality: "APPROXIMATE_HOST_PROCESS_LIFETIME"` and `timestamp_source: "MEMORY_PSLIST_CREATETIME"`, storing extraction run time under `analysis_timestamp`.
  * Prefetch and USB entries without authentic timestamps preserved as `None` with `timestamp_quality: "UNAVAILABLE"` and `timestamp_source: "UNRECORDED"`.
  * Chronological sorting function routes unrecorded/None timestamps to synthetic index `9999-12-31T23:59:59` so that historical target event sequences remain intact.
* **Temporal Policies in `_build_correlations` (lines 880–1110)**:
  * **Rule 1 (`process_injection_chain`)**: Calculates $\Delta t = T(\text{child}) - T(\text{parent})$. If $\Delta t < 0$, flags `temporal_status: "ANOMALOUS_INVERTED_TIMESTAMPS"`, assigns `AMBIGUOUS_ASSOCIATION`, and caps confidence to $0.40$ (flagging probable PID reuse). If $\Delta t \ge 0$, sets `CHRONOLOGICALLY_ORDERED`. If timestamps unavailable, sets `TIMESTAMPS_UNAVAILABLE_SNAPSHOT`.
  * **Rule 2 (`persistence_to_execution`)**: Compares Run key `last_write_time` vs Prefetch `last_run_time`. If prefetch execution preceded Run key creation ($\Delta t < 0$), flags `ANOMALOUS_PREFETCH_PRECEDES_PERSISTENCE` and downgrades to `AMBIGUOUS_ASSOCIATION` ($0.35$).
  * **Rule 3 (`dns_resolution_to_flow`)**: Compares DNS query time vs conversation start time. If flow preceded DNS ($\Delta t < 0$), flags `ANOMALOUS_FLOW_PRECEDED_DNS` and downgrades to `AMBIGUOUS_ASSOCIATION` ($0.45$). If ordered, maintains `DETERMINISTIC_GROUNDED` ($0.95$).
  * **Rule 4 (`usb_insertion_to_execution`)**: Dynamically extracts the active prefetch executable from `raw_pf` instead of hardcoding `VMWARETRAY.EXE`. Calculates $\Delta t$ between USB insertion and prefetch execution while classifying the link as `COINCIDENTAL_NOISE` ($0.15$).

### 2. `graph_service.py`
* **Entity Extraction for Disk & Registry (lines 268–370)**:
  Added parsing stages during `build_case_evidence_graph`:
  * Prefetch records $\rightarrow$ `prefetch:{case_id}:{exe}` nodes, linked to `artifact:disk:prefetch_analysis.json` via `OBSERVED_IN`.
  * USB records $\rightarrow$ `usb:{case_id}:{serial}` nodes, linked to `artifact:registry:usb_devices.json` via `OBSERVED_IN`.
  * Run key records $\rightarrow$ `runkey:{case_id}:{name}` nodes, linked to `artifact:registry:run_keys.json` via `OBSERVED_IN`.
* **Correlation Edge Entity Resolvers (lines 375–470)**:
  Extended resolution branches for `RUNKEY-`, `PREFETCH-`, and `USB-` IDs to connect to genuine entity nodes or parent artifact nodes.
* **Unresolved Edge Diagnostic Capture (lines 475–510)**:
  When an entity does not exist in `G` (e.g. PPID 1464 terminated prior to memory acquisition), the engine refuses to fabricate a dummy node. Instead, it appends a detailed diagnostic into `G.graph["unresolved_correlation_edges"]`.
* **Diagnostic Metrics in `get_graph_metrics` (lines 600–606)**:
  Added `"unresolved_correlation_edges_count"` and `"unresolved_correlation_edges"` to graph metrics return dict.

---

## 4. Regression Tests & Verification Results

### Suite 1: Focused Phase 1 Validation Suite
File: [`tests/test_correlation_phase1_validation.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/tests/test_correlation_phase1_validation.py)  
Command: `pytest tests/test_correlation_phase1_validation.py`  
Output: **11 passed in 4.60s**

| Test Function | Target Validation Area | Test Description | Result |
| :--- | :--- | :--- | :---: |
| `test_rule1_pid_reuse_inverted_timestamps` | Process identity & PID reuse | Child created 15m prior to reported parent. Verifies flag `ANOMALOUS_INVERTED_TIMESTAMPS`, `AMBIGUOUS_ASSOCIATION`, and confidence $\le 0.40$. | **PASSED** |
| `test_rule1_ordered_parent_child_chronology` | Process lineage | Parent created 5m before child. Verifies `CHRONOLOGICALLY_ORDERED` and `CORROBORATED_HYPOTHESIS` ($0.80$). | **PASSED** |
| `test_rule2_persistence_precedes_execution` | Registry persistence $\leftrightarrow$ prefetch | Run key created at 10:00, executed at 10:02. Verifies $\Delta t = +120\text{s}$, `CHRONOLOGICALLY_ORDERED` ($0.85$). | **PASSED** |
| `test_rule2_inverted_prefetch_precedes_persistence` | Conflicting timestamps | Execution occurred 2h prior to Run key modification. Verifies `ANOMALOUS_PREFETCH_PRECEDES_PERSISTENCE` ($0.35$). | **PASSED** |
| `test_rule3_dns_precedes_network_flow` | DNS to network flow | DNS lookup immediately followed by TCP flow on resolved IP. Verifies `DETERMINISTIC_GROUNDED` ($0.95$). | **PASSED** |
| `test_rule3_flow_precedes_dns_anomaly` | Network flow anomaly | TCP flow started 10m prior to DNS query. Verifies `ANOMALOUS_FLOW_PRECEDED_DNS` ($0.45$). | **PASSED** |
| `test_rule4_usb_presence_is_coincidental_noise` | USB presence vs exfiltration | Removable drive mount without volume path link. Verifies `COINCIDENTAL_NOISE` ($0.15$) and dynamic executable resolution. | **PASSED** |
| `test_missing_timestamps_preservation_in_timeline` | Timestamp integrity | Target events without timestamps are preserved as `None` with `UNAVAILABLE`/`UNRECORDED` (no `utcnow()` substitution). | **PASSED** |
| `test_duplicate_malfind_findings_grouped_by_pid` | Deduplication | 3 RWX VAD allocations on same PID grouped into exactly 1 finding and 1 correlation chain. | **PASSED** |
| `test_unresolved_graph_edge_diagnostics_without_fabrication` | Graph integrity | Orphan PPID missing from RAM dump triggers diagnostic in `unresolved_correlation_edges` without fabricating node. | **PASSED** |
| `test_source_provenance_and_uncertainty_preservation` | Provenance preservation | Volatile RAM timestamps from 2012 preserved intact, separating lab analysis runtime into `analysis_timestamp`. | **PASSED** |

### Suite 2: Audit Corrections Regression Suite
File: [`tests/test_forensic_audit_corrections.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/tests/test_forensic_audit_corrections.py)  
Command: `pytest tests/test_forensic_audit_corrections.py`  
Output: **6 passed in 5.61s**

### Suite 3: Sprint 2 Knowledge & Graph Suite
File: [`tests/test_sprint2_knowledge_and_graph.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/tests/test_sprint2_knowledge_and_graph.py)  
Command: `pytest tests/test_sprint2_knowledge_and_graph.py`  
Output: **7 passed in 199.56s** (including full STIX 2.1 ChromaDB vector collection verification)

### Suite 4: Full Backend Suite
Command: `pytest tests/test_encryption.py tests/test_events.py tests/test_hashing.py tests/test_permissions.py tests/test_preservation.py tests/test_sis_and_chatbot.py tests/test_storage.py tests/test_upload.py tests/test_verification.py tests/test_forensic_audit_corrections.py tests/test_correlation_phase1_validation.py`  
Output: **33 passed, 0 failed in 23.03s**

---

## 5. Remaining Weaknesses in Each Correlation Rule

Despite Phase 1 fixes, the rule engine retains inherent structural constraints that must be understood prior to deploying multi-hop reasoning or GraphRAG:

1. **Rule 1 (`process_injection_chain`)**:
   * *Remaining Weakness*: Malfind identifies memory pages that are executable and unbacked by disk (`PAGE_EXECUTE_READWRITE`). However, Windows Just-In-Time (JIT) compilers (e.g. .NET runtime, browser JavaScript engines) legitimately generate RWX memory regions. While finding confidence is now capped at $0.85$, definitive confirmation requires shellcode disassembly and thread call-stack inspection.
2. **Rule 2 (`persistence_to_execution`)**:
   * *Remaining Weakness*: Matching is based on binary name substring matching (e.g. `"update.exe"`). If malware installs a Run key for `update.exe` but an unrelated legitimate administrative utility also runs `update.exe` from another folder, the rule can falsely link the Run key to the benign execution without path or SHA-256 hash corroboration.
3. **Rule 3 (`dns_resolution_to_flow`)**:
   * *Remaining Weakness*: Cloud hosting and Content Delivery Networks (Cloudflare, AWS CloudFront, Fastly) host thousands of domains on identical anycast IP addresses. Matching DNS resolution of `domainA.com` to traffic on `104.16.x.x` without verifying TLS Server Name Indication (SNI) or HTTP Host headers can lead to false causal attribution in multi-tenant environments.
4. **Rule 4 (`usb_insertion_to_execution`)**:
   * *Remaining Weakness*: Evaluates pairwise Cartesian product between USB registrations and prefetch records. Currently flags unlinked activity as `COINCIDENTAL_NOISE` ($0.15$), but does not yet inspect Shellbags (`UsrClass.dat`), LNK targets, or USN journal records to positively prove or disprove drive volume access.

---

## 6. Review of the Proposed 30-Pair Benchmark (Step 5 Review)

The 30-pair benchmark proposed in `CORRELATION_ENGINE_READINESS.md` Section 6 was critically evaluated against forensic standards:

### Label Auditing & Epistemic Corrections
* **Caution on "Ground Truth Causal Label = 1"**:
  In digital forensics, a pairwise correlation between a Registry Run key and a Prefetch execution is a **corroborated hypothesis**, not a mathematical ground truth causal certainty. Labeling candidate pairs with a binary $1$ overstates evidentiary proof unless execution was proven to be spawned by the user init subsystem via process lineage telemetry.
* **Correction of Adversarial Examples**:
  Adversarial pairs where timestamps conflict (e.g. ADV-01: prefetch executing before MFT creation) should NOT be forced into a negative label ($0$). They represent **anomalous forensic contradictions** indicating clock skew, timestomping, or file substitution, which require their own distinct label: `AMBIGUOUS_ASSOCIATION` / `ANOMALOUS`.
* **Dataset Splitting**:
  Pairs must NEVER be randomly partitioned into train/test splits from the same case. Case-level data sharing leaks identical IP subnets, usernames, and timestamp offsets, causing artificial benchmark inflation. Datasets must be split strictly by **case / scenario boundary**.
* **30-Pair Reliability Boundary**:
  A 30-pair synthetic benchmark serves as an integration regression suite. It does **NOT** establish statistical generalizability or production machine learning reliability for commercial or courtroom deployment.

---

## 7. Measured Forensic Metrics (Valid Ground Truth Only)

Metrics evaluated on the active case [`CASE_ALL5_F1A5D2`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/output/cases/CASE_ALL5_F1A5D2):

| Metric | Measured Value | Pre-Audit Baseline | Evaluation Status |
| :--- | :---: | :---: | :---: |
| **Evidence Graph Nodes** | **79 nodes** | 29 nodes | $\mathbf{+172\%}$ (Genuine prefetch, usb, and artifact entities added) |
| **Evidence Graph Edges** | **94 edges** | 22 edges | $\mathbf{+327\%}$ (Full cross-domain hierarchy & correlation links represented) |
| **Unresolved Correlation Edges Detected** | **1 edge** (`CORR-0003`) | 0 (Silently dropped) | **100% Diagnostic Visibility** (No fabricated nodes) |
| **Unsupported Causal Claim Rate (UCCR)** | **0.00%** | >40.00% | **OPTIMAL** (USBSTOR classified as T1200 hardware, not T1052 exfiltration) |
| **Duplicate Finding Inflation Rate (DFIR)** | **1.00** | 2.75 | **OPTIMAL** (Grouped by PID; zero redundant findings) |
| **Contaminated Lab Workstation Timestamps** | **0** | 4 events | **ELIMINATED** (Zero `utcnow()` fallbacks in target timeline) |

---

## 8. Outstanding Blockers & Next Recommended Task

### Blockers Resolved
- [x] Contaminated workstation timestamp fallbacks eliminated.
- [x] Inverted chronology and clock skew handled without inventing events.
- [x] Entity resolution for `RUNKEY-`, `PREFETCH-`, and `USB-` implemented.
- [x] Diagnostics for unresolved edges emitted without node fabrication.
- [x] Malfind duplicate findings consolidated by PID.

### Next Recommended Task (Sprint 2/3 Transition)
**Expose the Evidence Graph via API (`GET /api/v1/cases/{case_id}/graph`)**:
Now that `EvidenceGraphService` produces a verified 79-node, 94-edge graph with explicit epistemic natures (`OBSERVED_FACT`, `CORROBORATED_HYPOTHESIS`, `COINCIDENTAL_NOISE`, `ATTACK_MAPPING`) and diagnostic visibility for unresolved edges, the immediate next technical step is exposing this graph via a clean REST endpoint in [`cases.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/api/routes/cases.py). This will enable graph visualization and provide the structured evidentiary neighborhood required for subsequent GraphRAG context retrieval.
