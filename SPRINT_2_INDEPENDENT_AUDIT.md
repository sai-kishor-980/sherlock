# SherlockAI — Sprint 2 Forensic Audit Report
**Auditor Role:** Senior Digital Forensics Engineer, Software Auditor & Skeptical Research Reviewer  
**Audit Date:** 2026-10-23  
**Audit Target:** H-MACFR / SherlockAI Forensic Pipeline (Backend, Artifact Extractors, Correlation Engine, Graph & Knowledge Systems)  
**Status:** COMPLETE — 43/43 AUTOMATED TESTS PASSING

---

## Executive Summary

This independent forensic audit was conducted to verify whether the H-MACFR multi-domain correlation engine produces **evidence-grounded, technically valid forensic relationships**, or merely generates plausible-looking findings through heuristic rules.

### Core Audit Verdict
The underlying software architecture (evidence vaulting, SQLite chain-of-custody, STIX 2.1 vector ingestion, NetworkX graph serialization, and cross-domain contract interfaces) is **technically robust, modular, and functional**. However, previous project reports contained **unsubstantiated forensic assertions, synthetic narrative hallucinations, and premature AI/machine learning claims**:
1. **Zero Active Neural Inference Locally**: Despite packaging fine-tuned QLoRA/LoRA adapters, local inference does not execute PEFT models. When no remote GPU endpoint is specified, `ModelAdapterService` falls back to **hardcoded keyword substring matching** (`powershell`, `svchost`, `cmd.exe`).
2. **Finding Inflation & Duplicate Spam**: Prior to this audit, `_build_findings` generated 11 separate "CRITICAL malicious" findings for `winlogon.exe` simply because Volatility's `malfind` reported 11 VAD regions in that single process.
3. **Forensic Over-Claiming on Process Injection**: Memory allocations marked `PAGE_EXECUTE_READWRITE` were declared "confirmed malicious code injection" with confidence `0.98`, without checking for shellcode disassembly, MZ headers, or thread start execution contexts.
4. **Unsupported Exfiltration Claims**: USB device registrations in the registry (`USBSTOR`) were mapped directly to `T1052.001: Exfiltration to Removable Drive` with `0.88` confidence, despite zero telemetry demonstrating data transfer or file access.
5. **Narrative Discrepancy in Network Fixtures**: Previous report text cited `example.com` resolving to `93.184.216.34` over HTTP port 80. Physical packet inspection via Scapy proves the fixture `sample.pcap` has always contained `malicious-c2-test.corp.net` resolving to `198.51.100.42` over HTTPS port 443.
6. **Severe Domain Confounding in Dataset**: The 10-pair correlation dataset contained 100% intra-domain positive samples and 100% cross-domain negative samples, making it invalid for cross-domain machine learning training.

All 6 confirmed engineering and forensic defects have been **actively corrected in the codebase and locked in with automated regression tests** ([`test_forensic_audit_corrections.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/tests/test_forensic_audit_corrections.py)).

---

## 1. Implementation Classification Matrix

Each major subsystem was inspected against source code, unit tests, and case outputs:

| Component / Feature | Source Reference | Classification | Evidence & Operational Reality |
| :--- | :--- | :---: | :--- |
| **Evidence Vault & Preservation** | [`storage_service.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/storage_service.py), [`upload_service.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/upload_service.py) | **Implemented & Verified** | Files stored under `evidence_vault/{case_id}/{evidence_id}`, SHA-256 computed on raw bytes and logged in SQLite `chain_of_custody`. Verified in 6 preservation tests. |
| **MITRE ATT&CK STIX 2.1 Ingestion** | [`knowledge_service.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/knowledge_service.py) | **Implemented & Verified** | Ingests official STIX 2.1 JSON bundle (v20.0, 52.7 MB, SHA-256 `81113ba...`). Filters 227 revoked/deprecated objects; upserts 706 active techniques into persistent ChromaDB idempotently. |
| **Evidence Graph Engine** | [`graph_service.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/graph_service.py) | **Implemented & Verified** | NetworkX 3.5 `DiGraph` builds case graph linking Case, Evidence, Artifacts, Processes, Endpoints, Findings, and MITRE Techniques. Serializes losslessly to `evidence_graph.json`. |
| **Artifact Extractors (PCAP, Prefetch, LNK, Registry, EVTX)** | `artifact_extraction/` | **Implemented & Verified** | Parsers run on uploaded files. Scapy extracts DNS and conversations; yarp/python-registry extracts USBSTOR; python-evtx extracts logons. |
| **Cross-Domain Correlation Engine** | [`synthesizer_service.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/synthesizer_service.py) | **Implemented & Verified (Rule-Based)** | 100% deterministic Python heuristics. Links DNS $\rightarrow$ IP flows, PID parent-child chains, and Run keys $\rightarrow$ Prefetch. Zero learned ML inference. |
| **LoRA Domain Adapters Execution** | [`model_adapter_service.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/model_adapter_service.py) | **Partially Implemented** | Adapter weights exist in zip archives. However, local inference raises `NotImplementedError` and falls back to string keyword matching. Active inference requires Colab GPU bridge. |
| **Machine Learning Correlation Model** | `output/.../correlation_training_pairs.json` | **Prototype / Not Implemented** | Model is untrained. 10 synthetic/heuristic training pairs exist, but are confounded and unsuitable for production model fine-tuning. |
| **GraphRAG / LLM Agent Synthesis** | Prompt templates in `supervisor_service.py` | **Prototype / Partially Implemented** | Prompt templates exist for case synthesis; full RAG retrieval from ChromaDB + NetworkX neighborhood subgraph is deferred to Sprint 3. |

---

## 2. In-Depth Forensic Validity Findings

### Finding A: Memory & Process Injection (`csrss.exe` & `winlogon.exe`)
* **Severity:** **HIGH**
* **File & Function:** [`synthesizer_service.py: _build_findings`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/synthesizer_service.py#L729)
* **Observed Defect:**
  1. `threat_hunting.json` was copied from pre-extracted directory `Bharath_TES1/memory`, not extracted from a vaulted physical memory capture image.
  2. For `winlogon.exe` (PID 608), 11 identical findings (`FIND-0002` through `FIND-0012`) were generated, each claiming "Process Code Injection in 'winlogon.exe'" with `confidence: 0.98` and `assessment: malicious`.
  3. Inspection of the underlying data reveals that the 11 VAD regions contain mostly zero-byte buffers (`00 00 00... 25 00 25 00`), not executable assembly or shellcode.
  4. For `csrss.exe` (PID 584), the region has `Tag: Vad `, `PAGE_EXECUTE_READWRITE`, but lacks an MZ header or thread injection context. In Windows subsystem architecture, `csrss.exe` legitimately allocates shared memory.
* **Forensic Impact:** In an audit or court proceeding, labeling unbacked executable memory as 98% confirmed malicious code injection without disassembling the instructions or verifying thread execution is inadmissible conjecture.
* **Correction Applied:**
  - Grouped malfind entries by PID in `_build_findings`, collapsing 11 duplicate findings into 1 consolidated finding per process.
  - Reclassified finding title to *"Suspicious Executable Memory Allocation in '{proc}' (PID: {pid})"*.
  - Downgraded `assessment` to `"suspicious"` and calibrated `confidence` to `0.85` (within hypothesis bounds).
  - Added explicit forensic qualification that memory dump disassembly and thread start address verification are required to confirm injection.

### Finding B: Registry Persistence & Prefetch Correlation
* **Severity:** **MEDIUM**
* **File & Function:** [`synthesizer_service.py: _build_correlations`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/synthesizer_service.py#L899)
* **Observed Defect:**
  - In test case `CASE_ALL5_F1A5D2`, `extracted_artifacts/registry/run_keys.json` had **0 records**. The uploaded fixture was `SYSTEM` hive, which stores system services and drivers, while `Run` keys reside in `SOFTWARE` or `NTUSER.DAT`.
  - `prefetch_analysis.json` contained `VMWARETRAY.EXE` (run count 10).
  - Previous reports claimed that Registry Run key persistence was linked to Prefetch execution in this case. In reality, `run_keys` was empty, and no such correlation was generated.
* **Forensic Impact:** Registry configuration alone demonstrates only persistence configuration; actual execution requires independent corroboration (Prefetch, UserAssist, or Event ID 4688). Claiming a link when the registry hive contained 0 Run keys was inaccurate.
* **Correction Applied:** Verified rule logic requires non-empty inputs; documented that `SYSTEM` hive alone does not contain autorun persistence; preserved honest negative behavior in case reports.

### Finding C: Network Correlation & Packet Discrepancy
* **Severity:** **HIGH**
* **File & Function:** [`sample.pcap`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/sample_evidence/sample.pcap), [`PCAPMerger`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/artifact_extraction/pcap/merger.py), `SPRINT_2_VERIFICATION.md`
* **Observed Defect:**
  - The previous Sprint 2 verification report text claimed that `sample.pcap` was a capture of `example.com` resolving to `93.184.216.34` over HTTP port 80.
  - Physical inspection of the binary pcap via Scapy proves this was a narrative invention. The actual packets in `sample.pcap` are:
    * Packet 1: `192.168.1.100` $\rightarrow$ `8.8.8.8:53` UDP DNS query `malicious-c2-test.corp.net`
    * Packet 2: `8.8.8.8:53` $\rightarrow$ `192.168.1.100` UDP DNS answer `198.51.100.42`
    * Packets 3–6: `192.168.1.100:49152 <-> 198.51.100.42:443` TCP 3-way handshake + TLS payload (54 bytes).
* **Forensic Impact:** Reporting fictitious hostnames and ports undermines forensic chain of custody.
* **Correction Applied:**
  - Corrected all documentation and tests to reference the actual packet data: `malicious-c2-test.corp.net` resolving to `198.51.100.42:443`.
  - Added [`test_network_pcap_actual_packet_tuples`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/tests/test_forensic_audit_corrections.py#L86) verifying exact endpoints and ports.

### Finding D: USB Activity Misclassified as Exfiltration
* **Severity:** **HIGH**
* **File & Function:** [`synthesizer_service.py: _build_findings`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/synthesizer_service.py#L780)
* **Observed Defect:**
  - The registry extractor identified a USB storage device registration in `SYSTEM\ControlSet001\Enum\USBSTOR` (`CBM Flash Disk USB Device`).
  - `_build_findings` generated finding `FIND-0015` titled *"External USB Removable Media Activity Detected"*, categorized it under *"Initial Access / Exfiltration"*, and mapped it to **`T1052.001: Exfiltration to Removable Drive`** with confidence `0.88`.
* **Forensic Impact:** In forensic science, USBSTOR registry keys prove that a hardware device was connected or registered with Windows. It provides **zero evidence of data transfer or exfiltration**. Claiming `T1052.001` without file-level artifacts (Shellbags, RecentDocs, USN Journal) is a severe methodological violation.
* **Correction Applied:**
  - Renamed finding to *"Removable USB Storage Device Registration Detected"*.
  - Re-mapped technique to **`T1200: Hardware Additions`** (Peripheral Attachment).
  - Added explicit disclaimer: *"In digital forensics, registry device registration establishes physical connection history but does NOT constitute proof of data transfer or exfiltration without file-level access logs, Shellbags, or LNK file corroboration."*
  - Re-calibrated confidence to `0.85` and severity to `LOW`.

---

## 3. Confidence & Epistemic Boundaries Audit

### The Reality of "Confidence Scores"
The project specification describes:
* `DETERMINISTIC_GROUNDED`: $0.95 - 1.00$
* `CORROBORATED_HYPOTHESIS`: $0.80 - 0.90$
* `COINCIDENTAL_NOISE`: $< 0.20$

**Audit Finding:** None of the confidence numbers in the system represent statistically calibrated probabilities or machine learning posterior probabilities. They are **hardcoded heuristic weights**:
* `FIND-0001` had confidence `0.98` hardcoded in python source.
* In `graph_service.py`, `INDICATES_ANOMALY` edges inherited this `0.98` score, assigning confidence `0.98` to an edge explicitly typed as `CORROBORATED_HYPOTHESIS`, violating the stated $[0.80, 0.90]$ hypothesis boundary.

### Corrections Applied:
1. In [`synthesizer_service.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/synthesizer_service.py), all hypothesis findings are hard-capped at $\le 0.85$.
2. In [`graph_service.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/graph_service.py), edge creation enforces `min(f.get("confidence", 0.80), 0.85)` for `CORROBORATED_HYPOTHESIS` edges.
3. Every ATT&CK mapping edge carries an immutable disclaimer:
   > *"Technique mapping represents analytic taxonomy categorization; does not constitute definitive proof of adversary attack."*

---

## 4. Training Dataset & AI Claims Audit

### Inspection of `correlation_training_pairs.json`
The staged dataset contains 10 samples (5 positive, 5 negative):
* **Positive Samples (1–5):**
  - Sample 1: Memory PID-368 $\rightarrow$ Memory PID-584 (Intra-domain)
  - Sample 2: Memory PID-368 $\rightarrow$ Memory PID-608 (Intra-domain)
  - Sample 3: Memory PID-1464 $\rightarrow$ Memory PID-1484 (Intra-domain)
  - Sample 4: Memory PID-1484 $\rightarrow$ Memory PID-1640 (Intra-domain)
  - Sample 5: Network DNS $\rightarrow$ Network IP Flow (Intra-domain)
* **Negative Samples (6–10):**
  - Sample 6: Registry USB vs Disk Prefetch (Cross-domain)
  - Sample 7: Registry USB vs Disk Prefetch (Cross-domain)
  - Sample 8: Memory PID vs Network Socket (Cross-domain)
  - Sample 9: Memory PID vs Network Socket (Cross-domain)
  - Sample 10: Disk LNK vs Network Socket (Cross-domain)

### Audit Evaluation:
1. **Severe Domain Confounding**: 100% of positive pairs are intra-domain (`domain_a == domain_b`), and 100% of negative pairs are cross-domain (`domain_a != domain_b`). A machine learning model trained on this dataset would learn a trivial spurious feature (`domain_a == domain_b -> positive`), completely defeating cross-domain correlation.
2. **Synthetic / Manual Origin**: Labels were assigned deterministically by `test_all_five_adapters_e2e.py`, not derived from multi-host attack datasets or labeled by independent forensic examiners.
3. **Verdict**: **This dataset must NOT be used to train production models.** It is suitable only as a schema validation fixture.

---

## 5. Evidence Graph & ATT&CK Mapping Reproducibility

Following the audit corrections, `EvidenceGraphService.build_case_evidence_graph("CASE_ALL5_F1A5D2")` produces clean, reproducible metrics:

| Graph Metric | Pre-Audit (Inflated) | Post-Audit (Corrected) | Forensic Justification |
| :--- | :---: | :---: | :--- |
| **Total Nodes** | 86 | **76** | Deduplicated 11 winlogon findings down to 1 finding node. |
| **Finding Nodes** | 15 | **5** | Exactly 4 memory process candidates + 1 USB registration. |
| **Total Edges** | 108 | **89** | Redundant hypothesis and mapping edges eliminated. |
| **Observed Facts** | 76 | **76** | Direct provenance edges (vault, extraction, process tree) preserved. |
| **Corroborated Hypotheses** | 17 | **7** | Hypothesis edges capped $\le 0.85$, strictly bound. |
| **ATT&CK Mappings** | 15 | **5** | 1 mapping edge per deduplicated finding. |

---

## 6. List of Previous Claims That Must Be Corrected

1. **Claim:** *"All 5 fine-tuned LoRA neural adapters are actively running domain-specific cognitive inference locally."*  
   **Correction:** Local execution falls back to keyword substring matching in `_run_forensic_evaluator`. Live PEFT inference raises `NotImplementedError` unless connected to an external GPU bridge (`COLAB_GPU_INFERENCE_URL`).
2. **Claim:** *"CASE_ALL5_F1A5D2 confirmed 14 critical malicious process injections."*  
   **Correction:** 11 of the findings were duplicate allocations for PID 608 (`winlogon.exe`). The case contains exactly 4 candidate processes, which represent unconfirmed executable memory anomalies (`suspicious`), not confirmed malicious attacks.
3. **Claim:** *"External USB Removable Media Activity Detected demonstrates Initial Access / Exfiltration (T1052.001)."*  
   **Correction:** USBSTOR registry keys prove physical device registration only. It is classified under `T1200: Hardware Additions` with an explicit disclaimer that file transfer is not proven.
4. **Claim:** *"sample.pcap contains DNS query for example.com resolving to 93.184.216.34 over HTTP port 80."*  
   **Correction:** `sample.pcap` contains `malicious-c2-test.corp.net` resolving to `198.51.100.42` over HTTPS port 443.
5. **Claim:** *"The correlation engine has a calibrated, balanced 10-pair training dataset ready for GNN/ML fine-tuning."*  
   **Correction:** The 10 pairs have severe domain confounding (intra-domain positive vs cross-domain negative) and are schema validation fixtures, not a viable machine learning training set.
