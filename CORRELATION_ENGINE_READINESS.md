# SherlockAI / H-MACFR — Correlation Engine Readiness Audit & Plan

**Auditor Role:** Senior Digital Forensics Engineer, Correlation-Engine Developer & Skeptical Validation Reviewer  
**Audit Date:** 2026-10-23  
**Target Subsystem:** Forensic Correlation Engine, Synthesis Service, Evidence Graph, and AI Training Pipeline  
**Document Status:** FINAL AUDIT & ROADMAP (Planning Phase — No Code Modified)

---

## 1. Executive Verdict

### Readiness Determination: **NOT READY FOR PRODUCTION FORENSIC USE; CONDITIONALLY READY FOR CONTROLLED LAB PROTOTYPING ONLY**

| Operational Scope | Verdict | Forensic & Engineering Rationale |
| :--- | :---: | :--- |
| **Air-Gapped Case Triage & Vaulting** | **READY** | Cryptographic evidence vaulting, SHA-256 integrity hashing, SQLite chain-of-custody, and STIX 2.1 vector storage are fully functional and verified (43/43 tests passing). |
| **Deterministic Rule-Based Correlation** | **CONDITIONALLY READY** | Current rules operate on exact string/identifier matches (PID trees, DNS-to-IP flows). While basic logic functions, rules lack temporal delta boundaries, confuse forensic examination runtimes with target event timestamps, and silently drop registry/disk correlation edges in the graph. |
| **Machine Learning / GNN Correlation** | **NOT READY** | Zero active machine learning or neural inference exists in the local pipeline (`ModelAdapterService` falls back to keyword matching). The existing 10-pair dataset has 100% domain confounding and cannot support model training. |
| **Court-Defensible Causal Attribution** | **NOT READY** | The engine cannot yet defend multi-hop causal claims under adversarial cross-examination. It relies on heuristic leaps (e.g. unbacked VAD page = code injection; registry USBSTOR key = data exfiltration) without verifying prerequisite corroborating telemetry. |

---

## 2. Current Architecture & End-to-End Data Flow

The actual execution path of evidence through the correlation pipeline was mapped by tracing source files:

```
[Raw Physical Evidence]
  │  (SYSTEM hive, sample.pcap, Application.evtx, Prefetch, LNK, Volatility tables)
  ▼
1. INGESTION & VAULTING (storage_service.py, upload_service.py)
  │  - Files written to evidence_vault/{case_id}/{evidence_id}
  │  - SHA-256 computed on raw bytes; registered in SQLite `evidence` & `chain_of_custody`
  ▼
2. ARTIFACT EXTRACTION (artifact_extraction/plugin_manager/manager.py)
  │  - Domain extractors execute independently (Scapy for PCAP, yarp for Registry, python-evtx for Logs)
  │  - Emits domain JSON files to output/cases/{case_id}/extracted_artifacts/{domain}/
  ▼
3. ENTITY NORMALIZATION (synthesizer_service.py: _ingest_*)
  │  - Ingests memory/processes.json, threat_hunting.json, run_keys.json, usb_devices.json,
  │    dns_analysis.json, network_connections.json
  │  - Normalizes artifacts into categorized tables (_build_artifact_explorer)
  ▼
4. CORRELATION CANDIDATE GENERATION & RULE MATCHING (_build_correlations)
  │  - Rule 1: Malfind PID matches pslist PPID (Process Injection Chain)
  │  - Rule 2: Registry Run key command matches Prefetch executable name (Persistence to Execution)
  │  - Rule 3: DNS A-record answer IP matches TCP conversation string (DNS to Network Flow)
  │  - Rule 4: USB device registration evaluated against Prefetch (Demoted to Coincidental Noise)
  ▼
5. CONFIDENCE ASSIGNMENT & EPISTEMIC CLASSIFICATION (_build_correlations)
  │  - Hardcodes heuristic confidence (0.80, 0.85, 0.95, 0.15)
  │  - Assigns epistemic nature: OBSERVED_FACT, CORROBORATED_HYPOTHESIS, COINCIDENTAL_NOISE
  ▼
6. FINDING SYNTHESIS & DEDUPLICATION (_build_findings)
  │  - Synthesizes findings (FIND-0001 to FIND-0005)
  │  - Groups malfind allocations by PID (post-audit fix)
  │  - Maps finding titles to MITRE techniques (T1055, T1200, T1547.001)
  ▼
7. EVIDENCE GRAPH CONSTRUCTION (graph_service.py: build_case_evidence_graph)
  │  - Instantiates NetworkX DiGraph
  │  - Adds Case, Evidence, Artifact, Process, Endpoint, and Finding nodes
  │  - Injects correlation edges (Note: Entity resolution bug silently drops non-PID/DNS edges)
  │  - Queries ChromaDB (knowledge_service.py) for STIX 2.1 technique metadata nodes
  │  - Serializes graph losslessly to output/cases/{case_id}/evidence_graph.json
  ▼
8. REPORT & MANIFEST EXPORT (_build_court_report, _build_sis_state)
  │  - Emits synthesized_report.json, court_case_report.json, and supervisor_manifest.json
```

---

## 3. Rule Inventory & Validation Coverage

Every correlation rule currently implemented in [`synthesizer_service.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/synthesizer_service.py) was audited for technical rigor:

| Rule Name & ID | Source $\rightarrow$ Target | Required Identifiers & Matching Conditions | Temporal Assumptions & Delta ($\Delta t$) | Assigned Nature & Confidence | Known Failure Modes & Missing Safeguards | Validation Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: |
| **Rule 1: Process Injection Chain** (`process_injection_chain`) | `memory/threat_hunting.json` (malfind) $\rightarrow$ `memory/processes.json` (pslist) | `malfind.PID == pslist.PID`; resolves `pslist.PPID` to parent process image name. | **Zero temporal checks.** Assumes memory snapshot represents a single, static point in time. | `CORROBORATED_HYPOTHESIS`<br>Confidence: `0.80` (1 VAD) or `0.85` (>1 VAD) | **PID Reuse & Subsystem Buffers**: Does not verify thread start address, thread creation time, or presence of shellcode. In Windows, `csrss.exe` legitimately allocates RWX shared memory. | **Validated with Limitations** (Tested on static Volatility dump in `Bharath_TES1`). |
| **Rule 2: Persistence to Execution** (`persistence_to_execution`) | `registry/run_keys.json` $\rightarrow$ `disk/prefetch_analysis.json` | Substring match: `prefetch.executable_name.lower() in run_key.command.lower()`. | **Zero temporal checks.** Does not check whether Prefetch `last_run_time` occurred *after* Run key registry write timestamp (`LastWriteTime`). | `CORROBORATED_HYPOTHESIS`<br>Confidence: `0.85` | **Coincidental Naming & Hive Scope**: Substring match can falsely link `cmd.exe` in prefetch to unrelated maintenance scripts. **Silent Graph Drop**: `graph_service.py` lacks entity resolution for `RUNKEY-` and `PREFETCH-`, so this edge is omitted from the graph. | **Untested with Live Data** (`run_keys.json` was empty in `CASE_ALL5_F1A5D2` because uploaded hive was `SYSTEM`, not `SOFTWARE`). |
| **Rule 3: DNS Resolution to Outbound Flow** (`dns_resolution_to_flow`) | `network/dns_analysis.json` $\rightarrow$ `network/network_connections.json` | Substring match: `dns_answer_ip in conversation_string` (e.g. `"198.51.100.42" in "192.168.1.100 <-> 198.51.100.42"`). | **Zero temporal checks.** Assumes any DNS query in the PCAP caused any subsequent IP conversation with that IP in the same PCAP. | `DETERMINISTIC_GROUNDED`<br>Confidence: `0.95` | **Shared Hosting & CDNs**: Multiple domain names resolve to the same CDN/Cloudflare IP (e.g. `104.16.x.x`). Linking a query for Domain A to traffic for Domain B on the same IP is a false causal link without SNI/HTTP Host header verification. | **Validated on Synthetic Fixture** (`sample.pcap` contains 6 packets). |
| **Rule 4: USB Insertion to Execution Noise** (`usb_insertion_to_execution`) | `disk/usb_devices.json` $\rightarrow$ `disk/prefetch_analysis.json` | Pairwise Cartesian product between top 2 USB devices and prefetch executables. Checks if executable volume path is on fixed disk (`C:\`). | Evaluates temporal proximity as circumstantial only. | `COINCIDENTAL_NOISE`<br>Confidence: `0.15` | **Hardcoded Target**: Explicitly hardcodes `"PREFETCH-VMWARETRAY"` in line 1051. If another executable is parsed, the rule still references VMware Tray. **Silent Graph Drop**: Edge is not added to graph due to missing `USB-` node resolver. | **Validated on Staged Fixture**. |

---

## 4. Confirmed Defects vs. Suspected Defects

### Confirmed Defects (Verified via Code & Execution)
1. **Critical — Timestamp Inversion / Cross-Contamination**:
   * *Location:* [`synthesizer_service.py: _build_timeline`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/synthesizer_service.py#L645-L700)
   * *Evidence:* When artifact timestamps are missing, the code falls back to `datetime.datetime.utcnow().isoformat()`. For memory injection events, it uses `th_raw.get("generated_at")` (the time the Volatility script ran on the lab workstation in 2026), intermingling lab extraction times with target host event timestamps from years earlier.
2. **High — Correlation Edge Dropping in Evidence Graph**:
   * *Location:* [`graph_service.py: lines 367–388`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/graph_service.py#L367-L388)
   * *Evidence:* The resolver only checks for `PID-` and `DNS-`/`NET-FLOW-`. When `source_a` is `RUNKEY-` or `USB-` and `source_b` is `PREFETCH-`, `node_a` and `node_b` remain `None`. These edges are silently discarded, meaning persistence and coincidental noise links never appear in the NetworkX graph.
3. **High — Severe Domain Confounding in Dataset**:
   * *Location:* [`test_all_five_adapters_e2e.py: lines 287–354`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/test_all_five_adapters_e2e.py#L287-L354), `correlation_training_pairs.json`
   * *Evidence:* All 5 positive pairs are intra-domain (`memory` $\rightarrow$ `memory` or `network` $\rightarrow$ `network`), while all 5 negative pairs are cross-domain. A machine learning model trained on this will learn that cross-domain pairs are always non-causal.
4. **Medium — Hardcoded Target Entity in USB Noise Rule**:
   * *Location:* [`synthesizer_service.py: line 1051`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/synthesizer_service.py#L1051)
   * *Evidence:* The artifact ID is hardcoded to `"PREFETCH-VMWARETRAY"` regardless of what executables actually exist in `raw_pf`.

### Suspected / Latent Defects (Under Audit Investigation)
1. **High — PID Collision / Wrap-Around Vulnerability**:
   * Windows PIDs are reused rapidly (especially PIDs $< 1000$ like `csrss.exe` and `svchost.exe`). The correlation engine matches purely on `PID == target_pid` without asserting that process creation timestamps $\Delta t(\text{target}) < \Delta t(\text{parent})$ or verifying process GUIDs / EPROCESS addresses.
2. **Medium — CDN / Virtual Host Shared IP False Linkage**:
   * Rule 3 matches any DNS answer IP to any conversation containing that IP. In cloud hosting (AWS CloudFront, Cloudflare, Akamai), hundreds of unrelated domains share the same IP. Without verifying TLS Server Name Indication (SNI) or HTTP Host headers, Rule 3 will generate false positive attributions.

---

## 5. Criteria for Forensic Relationship Classification

To prevent cognitive bias, the correlation engine must enforce strict evidentiary thresholds:

```
                                    RELATIONSHIP TAXONOMY
                                               │
             ┌─────────────────────────────────┴─────────────────────────────────┐
             ▼                                                                   ▼
       OBSERVED FACT                                                        HYPOTHESIS
 (Direct Mathematical Binding)                                      (Contextual Inference)
             │                                                                   │
    ┌────────┴────────┐                                                 ┌────────┴────────┐
    ▼                 ▼                                                 ▼                 ▼
DETERMINISTIC      CHAIN OF                                       CORROBORATED      COINCIDENTAL
  GROUNDED         CUSTODY                                         HYPOTHESIS           NOISE
(e.g. TCP SYN     (e.g. SHA-256                                   (e.g. PPID tree     (e.g. Background
 matching DNS      vault hash)                                     + RWX VAD tag)      update during USB)
  answer IP)                                                                           
```

### 1. `DETERMINISTIC_GROUNDED` (Confidence: $0.95 - 1.00$)
* **Definition**: Physical, mathematical, or structural connection recorded in an immutable protocol or filesystem ledger.
* **Requirements**:
  1. Identical socket 5-tuple matching (Source IP, Source Port, Dest IP, Dest Port, Protocol) OR cryptographic hash match across domains.
  2. Strict temporal sequence: Event A timestamp $\le$ Event B timestamp, with $\Delta t \le 30$ seconds.
  3. No unverified intermediate proxies.

### 2. `CORROBORATED_HYPOTHESIS` (Confidence: $0.70 - 0.85$)
* **Definition**: Plausible causal inference supported by multiple independent, circumstantial forensic artifacts.
* **Requirements**:
  1. At least **two distinct forensic artifacts** corroborating the same entity (e.g. Registry Run key path matches Prefetch execution record AND Prefetch timestamp is greater than Registry `LastWriteTime`).
  2. Temporal plausibility window ($\Delta t \le \text{configured threshold}$, e.g. 1 hour).
  3. Contextual exclusion of known benign system behaviors (e.g. Windows Error Reporting, scheduled defragmentation).

### 3. `AMBIGUOUS_ASSOCIATION` (Confidence: $0.30 - 0.50$)
* **Definition**: Artifacts share an identifier or temporal proximity, but benign explanations are equally or more probable.
* **Requirements**: Entity name matches (e.g. `svchost.exe`), but binary paths, hashes, or parent PIDs cannot be confirmed.

### 4. `COINCIDENTAL_NOISE` (Confidence: $< 0.20$)
* **Definition**: Events occurring in temporal proximity that have no causal or operational connection.
* **Requirements**: Verified disjunction in volume, user account, network socket, or process tree (e.g. USB drive inserted on volume `E:\` while binary executes from `C:\Program Files`).

### 5. `UNSUPPORTED_CAUSAL_CLAIM` (Confidence: `0.00` — Rejected)
* **Definition**: Asserting a high-level attack step without prerequisite corroborating evidence (e.g. asserting Data Exfiltration based solely on a USBSTOR registry entry).

---

## 6. Controlled Validation Dataset Design

To replace the confounded 10-pair prototype, a 30-pair balanced validation benchmark must be constructed across 3 isolated forensic scenarios:

```
                VALIDATION BENCHMARK (30 Grounded Pairs)
                                    │
         ┌──────────────────────────┼──────────────────────────┐
         ▼                          ▼                          ▼
 SCENARIO 1: LATERAL         SCENARIO 2: PERSISTENCE    SCENARIO 3: DATA STAGING
   MOVEMENT & C2              & EXECUTION HIJACK          & EXFILTRATION
 (Network + Memory)            (Registry + Disk)          (USB + Event Logs)
  • 4 True Positive            • 3 True Positive          • 3 True Positive
  • 3 True Negative            • 3 True Negative          • 4 True Negative
  • 3 Adversarial/Edge         • 4 Adversarial/Edge       • 3 Adversarial/Edge
```

### 1. Positive Test Cases (Ground Truth Causal Label = 1)
* **POS-01 (Persistence to Execution)**: Registry Run key `HKLM\...\Run\Updater` pointing to `C:\Users\Public\update.exe` (Timestamp $T_0$) $\leftrightarrow$ Prefetch `UPDATE.EXE-4A82F10B.pf` with `last_run_time` $T_0 + 42\text{s}$.
* **POS-02 (C2 Communication)**: Memory active socket in `beacon.exe` bound to local port 49812 $\leftrightarrow$ PCAP TCP session `192.168.1.50:49812 <-> 203.0.113.15:443`.
* **POS-03 (Service Installation)**: Event Log 7045 (New Service Created: `WmdmPmSp`) $\leftrightarrow$ Registry `SYSTEM\ControlSet001\Services\WmdmPmSp` ImagePath.
* **POS-04 (Legitimate Child Process)**: Process `powershell.exe` (PID 4112) with PPID 1840 $\leftrightarrow$ Parent process `cmd.exe` (PID 1840) whose process create time precedes child create time.
* **POS-05 (Grounded DNS-to-Flow)**: PCAP DNS query `c2.attacker.com` resolving to `198.51.100.88` $\leftrightarrow$ Outbound HTTPS session to `198.51.100.88:443` initiated within 1.2 seconds.

### 2. Negative Distractor Cases (Ground Truth Causal Label = 0)
* **NEG-01 (Temporal Coincidence / USB vs System Process)**: Hardware USB device insertion timestamp $\leftrightarrow$ Background `SearchIndexer.exe` execution from `C:\Windows\System32`.
* **NEG-02 (Shared IP on CDN)**: PCAP DNS query for benign site `cdn.example.org` resolving to `104.16.20.1` $\leftrightarrow$ Outbound traffic to `104.16.20.1` occurring 20 minutes later with different HTTP host.
* **NEG-03 (Generic Process Name Homonym)**: Memory process `svchost.exe` (PID 892) on Machine A $\leftrightarrow$ Event Log 4688 for `svchost.exe` (PID 892) generated after system reboot (PID reused).
* **NEG-04 (LNK File to Fixed Volume vs USB Mount)**: LNK shortcut pointing to `C:\Users\Admin\Documents\report.docx` $\leftrightarrow$ Removable drive insertion on volume `F:\`.
* **NEG-05 (Unbacked Memory vs Network Traffic)**: Legitimate JIT buffer in `csrss.exe` $\leftrightarrow$ Background Windows Update NTP sync on port 123.

### 3. Adversarial & Edge Cases (Integrity Robustness)
* **ADV-01 (Clock Skew / Timestamp Inversion)**: Prefetch file execution timestamp is 3 hours *earlier* than the binary creation timestamp in `$MFT`. (Engine must flag `ANOMALOUS_TIMESTAMP_INVERSION` and reject causality).
* **ADV-02 (PID Wrap-Around Collision)**: Host terminates `malware.exe` (PID 1200) at 10:00:00; OS spawns benign `notepad.exe` (PID 1200) at 10:05:00. Network connection occurs at 10:06:00. (Engine must NOT link network connection to `malware.exe`).
* **ADV-03 (Missing Source Artifact)**: Finding references `artifact_id: PID-9999`, but PID 9999 is absent from `processes.json`. (Engine must handle gracefully without crashing or creating orphan edges).
* **ADV-04 (Duplicate Malfind Allocations)**: Process contains 25 unbacked pages. (Engine must emit exactly 1 finding and 1 correlation chain, not 25 duplicates).

---

## 7. Metrics & Formal Evaluation Methodology

To evaluate the correlation engine objectively, performance must be decoupled into **Rule Engine Quality**, **Confidence Calibration**, and **Graph Integrity**:

### 1. Classification Metrics
Let candidate artifact pairs be evaluated against ground truth labels:
* **True Positive (TP)**: Correctly predicted causal link between genuinely related artifacts.
* **False Positive (FP)**: Inferred causal link between unrelated artifacts (Type I Error / Hallucination).
* **True Negative (TN)**: Correctly rejected coincidental pair.
* **False Negative (FN)**: Missed genuine causal relationship (Type II Error / Blind Spot).

$$\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}}, \quad \text{Recall} = \frac{\text{TP}}{\text{TP} + \text{FN}}, \quad \text{FPR} = \frac{\text{FP}}{\text{FP} + \text{TN}}$$

### 2. Forensic Integrity Metrics (Project-Specific)
* **Unsupported Causal Claim Rate (UCCR)**:
  $$\text{UCCR} = \frac{\text{Findings with uncorroborated high-severity techniques (e.g. Exfiltration without file transfer)}}{\text{Total Generated Findings}}$$
  *Target:* $\mathbf{0.00\%}$
* **Duplicate Finding Inflation Rate (DFIR)**:
  $$\text{DFIR} = \frac{\text{Duplicate findings referencing same underlying entity}}{\text{Total Unique Root Entities}}$$
  *Target:* $\mathbf{1.00}$ (Exactly 1 finding per unique entity; pre-audit was $2.75$).
* **Provenance Completeness Ratio (PCR)**:
  $$\text{PCR} = \frac{\text{Graph edges with valid raw evidence vault hash \& extraction source}}{\text{Total Active Edges}}$$
  *Target:* $\mathbf{100.00\%}$

---

## 8. Prioritized Implementation Roadmap

```
PHASE 1 (Sprint 3 Core)     PHASE 2 (Sprint 3 Core)     PHASE 3 (Sprint 3.5)
┌──────────────────────┐    ┌──────────────────────┐    ┌──────────────────────┐
│  Graph Entity Bug    │───►│  Temporal Windowing  │───►│  Unconfounded        │
│  Fix & Graph API     │    │  & Provenance Guards │    │  Benchmark Dataset   │
└──────────────────────┘    └──────────────────────┘    └──────────────────────┘
           │                                                       │
           ▼                                                       ▼
┌──────────────────────┐                                ┌──────────────────────┐
│  GraphRAG Grounded   │                                │  Air-Gapped Local    │
│  LLM Context Layer   │                                │  Quantized Inference │
└──────────────────────┘                                └──────────────────────┘
```

### Task 1: Fix Graph Service Correlation Entity Resolution & Expose Graph API (Severity: HIGH)
* **Description**: Update [`graph_service.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/graph_service.py) to resolve `RUNKEY-`, `PREFETCH-`, and `USB-` artifact IDs so that persistence and noise correlation edges are not dropped. Implement `GET /api/v1/cases/{case_id}/graph`.
* **Dependencies**: None (Can proceed immediately).
* **Acceptance Criteria**: Correlation edges for `persistence_to_execution` appear in `evidence_graph.json`; API returns HTTP 200 with verified JSON graph.

### Task 2: Implement Temporal Windowing Engine ($\Delta t$ Enforcement) (Severity: HIGH)
* **Description**: Refactor `_build_correlations` to parse authentic artifact timestamps. Disallow correlations where $\text{Timestamp}(B) < \text{Timestamp}(A)$ or $\Delta t > \text{Threshold}$ (e.g. 1 hour for execution links). Remove laboratory extraction time fallback.
* **Dependencies**: Task 1.
* **Acceptance Criteria**: Passing regression test proving that inverted timestamps reject correlation.

### Task 3: Construct the 30-Pair Unconfounded Benchmark Dataset (Severity: MEDIUM)
* **Description**: Build a multi-scenario JSON benchmark containing authentic cross-domain positives and intra-domain negatives.
* **Dependencies**: Task 2.
* **Acceptance Criteria**: Automated test verifying zero domain confounding in benchmark.

### Task 4: GraphRAG Context Synthesis Layer (Severity: HIGH)
* **Description**: Connect ChromaDB STIX 2.1 vector retrieval and NetworkX subgraph neighborhoods into structured prompt templates for the local explanation agent.
* **Dependencies**: Task 1.
* **Acceptance Criteria**: RAG prompt incorporates verified graph edges and suppresses uncorroborated attack claims.

---

## 9. Go / No-Go Checklist for Sprint 3

| Checklist Item | Requirement | Current Status | Gate Status |
| :---: | :--- | :---: | :---: |
| **Gate 1** | Automated test suite passes 100% without regressions. | 43/43 Passing | **GO** |
| **Gate 2** | Malfind findings deduplicated by process PID. | Verified (1 finding per PID) | **GO** |
| **Gate 3** | Unbacked memory injection confidence capped $\le 0.85$ as hypothesis. | Verified in code & test | **GO** |
| **Gate 4** | USB device registration classified as `T1200`, not `T1052.001` exfiltration. | Verified in code & test | **GO** |
| **Gate 5** | Network correlation reflects actual Scapy PCAP bytes (`198.51.100.42:443`). | Verified in code & test | **GO** |
| **Gate 6** | Prohibit training ML model on confounded 10-pair prototype dataset. | Formally prohibited | **GO** |
| **Gate 7** | Fix entity resolution dropping `RUNKEY-` and `PREFETCH-` edges in graph. | Planned in Task 1 | **HOLD (Sprint 3 Prerequisite)** |
| **Gate 8** | Implement temporal windowing ($\Delta t$) before multi-hop correlation claims. | Planned in Task 2 | **HOLD (Sprint 3 Prerequisite)** |

---

## 10. Single Highest-Priority Next Action

**Update [`graph_service.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/graph_service.py) to resolve `RUNKEY-`, `PREFETCH-`, and `USB-` artifact IDs so correlation edges are not dropped, then implement `GET /api/v1/cases/{case_id}/graph` in [`cases.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/api/routes/cases.py).**

*Forensic Justification*: The rule engine already computes cross-domain links for persistence and coincidental noise, but because `graph_service.py` lacks entity resolvers for non-PID/DNS artifacts, those edges are silently omitted from the Evidence Graph. Fixing this entity resolution bug ensures the graph represents the complete, verified investigation state before the Sprint 3 GraphRAG layer is built on top of it.
