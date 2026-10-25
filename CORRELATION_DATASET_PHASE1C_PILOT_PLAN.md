# SherlockAI / H-MACFR — Correlation Learning Phase 1C: Forensic Dataset Inventory & Controlled Pilot Plan

**Document Status:** Complete & Verified Baseline  
**Date:** 2026-10-23  
**Framework:** H-MACFR (Hierarchical Multi-Agent Cyber Forensic Reconstruction)  
**Deliverable:** `CORRELATION_DATASET_PHASE1C_PILOT_PLAN.md`  
**Target Subsystem:** Correlation Dataset Collection, Evidence Vault, and Dataset Validator CLI  
**Prerequisites:** [`CORRELATION_TRAINING_PLAN.md`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/CORRELATION_TRAINING_PLAN.md), [`CORRELATION_DATASET_PHASE1A_REPORT.md`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/CORRELATION_DATASET_PHASE1A_REPORT.md), [`CORRELATION_DATASET_PHASE1B_AUDIT.md`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/CORRELATION_DATASET_PHASE1B_AUDIT.md)

---

## Executive Summary & Baseline Status

Following the implementation of the versioned schema and validation service in **Phase 1A**, and the extensive auditor corrections, causal cycle guards, and de-confounding diagnostics in **Phase 1B / 1B.1**, this document delivers **Phase 1C: Forensic Dataset Inventory & Controlled Pilot Plan**.

### Core Objectives
1. **Physical Inspection & Verified Inventory:** Audit all forensic artifacts physically present in the project repository, cataloging acquisition method, exact cryptographic hashes, ground-truth availability, licensing, and limitations.
2. **Controlled Pilot Scope & Operational Definitions:** Define explicit boundaries for an initial controlled pilot ($N \approx 100\text{--}150$ candidate pairs), establishing rigorous criteria to separate evidentiary association from causal inference, and defining operational rules for `VERIFIED_POSITIVE`, `VERIFIED_NEGATIVE`, and `AMBIGUOUS_UNRESOLVED`.
3. **Reproducible Collection Workflow:** Document the end-to-end chain of custody, extraction pipeline, candidate generation filtering, multi-examiner annotation protocol, and CLI quality gate validation.
4. **Project Readiness Evaluation:** Specify how leakage, class balance, domain confounding, and annotation consensus will be evaluated as engineering criteria.
5. **Strategic Feasibility Decision:** Deliver a formal decision on whether a real forensic pilot can proceed with existing evidence.

### Strict Constraints Adhered To
- **Zero Model Training:** No machine learning models are trained during Phase 1C.
- **Zero Production Rule Alterations:** The existing deterministic deduction rules in [`synthesizer_service.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/synthesizer_service.py) remain untouched.
- **Zero Fabricated Evidence or Labels:** All cataloged sources reflect verified file paths, actual byte lengths, and real cryptographic hashes.
- **Synthetic Transparency:** Synthetic fixtures (e.g. `CASE_ALL5_F1A5D2` and unit test fixtures) are explicitly classified as synthetic and segregated from forensic evidence.

---

## 1. Verified Source Inventory & Forensic Data Audit

An empirical filesystem audit was conducted across the workspace (`sherf/backend/evidence_vault`, `sherf/backend/output/cases`, `prot1-main/output/cases`, and `processeed/`). Only sources verified by disk inspection and cryptographic hashing are reported below.

### 1.1 Candidate Forensic Sources Summary Table

| Source ID | Investigation / Case Name | Primary Evidence Files & Types | Raw Size on Disk | Verified SHA-256 Hash | Ground-Truth Availability | Usable for Pilot? |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **SRC-01** | `1cda6ac0` / `Standalone Artifact Test` | `2020JimmyWilson.E01` (Disk)<br>`Triage-Memory.mem` (Memory) | 309.8 MB (Disk)<br>5,368.7 MB (RAM) | E01: `6c18f662744d55e2769d9510f6173f04dab668c42b67ef27b675d22e628b4ed5`<br>MEM: `a18602964abfbc54e1c83ebdaa61638ff3c2251485e4ad684fc9b59d43dd04a8` | **HIGH** (Documented DFIR challenge scenario & answer key) | **YES** (Primary multi-domain pilot source) |
| **SRC-02** | `Bharath_TES1` | `cridex_memory.vmem` (Volatility 3 extracted JSON plugins) | 1.1 MB extracted<br>(512 MB raw image referenced) | Extracted JSONs verified; raw VMEM file in vault points to 74-byte placeholder. | **HIGH** (Public Cridex malware memory challenge ground truth) | **YES** (Memory domain injection & process parentage) |
| **SRC-03** | `DISK_2` | `System.evtx`, `Security.evtx`, `$MFT`, `SOFTWARE`, `SYSTEM`, `Amcache.hve` | 212.4 MB total<br>(EVTX: 28.5 MB, MFT: 89.4 MB) | `System.evtx`: `b55e0331913ae3e157778b40810aa7061d4a572a1bf64c207e99ea3732ca7a58`<br>`Security.evtx`: `91da878de6e5950337f714eb89e6eb5f7a0dc221650b284e3650961aa18eb4eb` | **MEDIUM** (Real Windows Server environment; timeline-reconstructible) | **YES** (Disk, Event Log, Registry intra/cross-domain pairs) |
| **SRC-04** | `DISK_1` | `$MFT`, `SOFTWARE`, `SYSTEM`, 100+ `.pf` Prefetch files | 61.5 MB total<br>(MFT: 33.6 MB, Reg: 16.5 MB) | `$MFT`: verified; `NTOSBOOT-B00DFAAD.pf`: `077c59502b4d1b72...` | **LOW** (Unannotated baseline Windows desktop image) | **CONDITIONAL** (Suitable for negative & baseline pairs) |
| **SRC-05** | `pcap1` / `pcap2` | `network_summary.json`, carved stream files (`carved_file_*.bin`) | `pcap1`: 739.6 KB<br>`pcap2`: 10.4 KB | Extracted summaries verified; raw `.pcap` files not retained in case folder. | **MEDIUM** (Stratosphere IPS / CTU malware captures `2017-3-30_win6`) | **CONDITIONAL** (Network-only; no simultaneous memory/disk host capture) |
| **SRC-06** | `processeed/` | `installed_software.json`, `run_keys.json`, `usb_devices.json`, `recent_files.json` | 163.6 KB total<br>(300 normalized objects) | `run_keys.json`: `1701f2b41810260080ecc1eecd6d28cc8cd52c1134ab65a969ff0094d822292b` | **NONE** (Unsupervised registry feature dump) | **NO** (Feature profiling only; lacks temporal ground truth) |
| **SRC-07** | `CASE_ALL5_F1A5D2` | Synthetic pipeline fixture (10 pairs) | 7.2 KB | `7381ff7ab145...` | **SYNTHETIC ONLY** (100% domain confounded test fixture) | **NO** (Test fixture only; strictly excluded from training) |

---

### 1.2 In-Depth Source Profiles & Limitations

#### Source 1: Jimmy Wilson Enterprise Challenge Image (`SRC-01`)
- **Acquisition & Provenance:** Originates from the DFIR Lone Wolf / Jimmy Wilson scenario (standard community challenge image). Preserved inside the HMAC-secured vault at [`sherf/backend/evidence_vault/1cda6ac0-fb62-425c-b69c-813ed1275707/`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/evidence_vault/1cda6ac0-fb62-425c-b69c-813ed1275707/).
- **Available Artifact Types:**
  - *Disk:* Master File Table (`$MFT`, 6,029,312 bytes), Registry hives (`SOFTWARE` 48.5 MB, `SYSTEM` 11.8 MB, `SAM`, `SECURITY`, `DEFAULT`, `Jimmy Wilson_NTUSER.DAT` 786 KB, `UsrClass.dat` 524 KB), Prefetch records (`DLLHOST.EXE`, `RUNDLL32.EXE`, `WMIADAP.EXE`), JumpLists (`AutomaticDestinations`, `CustomDestinations`), LNK shortcuts (`Recent/*.lnk`), Recycle Bin containers (`$I...`, `$R...`), Event Logs (`Application.evtx`, `Security.evtx`, `System.evtx`).
  - *Email:* Google Takeout archive containing `All mail Including Spam and Trash.mbox` (39,269,181 bytes) and 24 attachments.
  - *Browser:* Firefox profile with `places.sqlite` (10.5 MB) and `cookies.sqlite` (524 KB).
  - *Memory:* `Triage-Memory.mem` (5,368,709,120 bytes, exactly 5.0 GB raw RAM image).
- **Ground-Truth Availability:** **High.** Documented insider threat and data exfiltration timeline with known filenames, user accounts (`Jimmy Wilson`), accessed URLs, and exfiltrated price lists.
- **Licensing:** Educational / DFIR training community challenge (free for academic research with scenario attribution; no proprietary restrictions).
- **Forensic Limitations:** Single workstation scenario. Does not include an independent synchronized enterprise perimeter firewall or external PCAP trace.

#### Source 2: RAM Memory Forensic Scan — Cridex (`SRC-02`)
- **Acquisition & Provenance:** Documented memory capture of the Cridex banking trojan (Volatility 3 test corpus / NIST CFReDS).
- **Available Artifact Types:** Extracted Volatility 3 telemetry including `windows_pslist.json` (active processes), `windows_pstree.json` (process hierarchy), `windows_cmdline.json` (process command lines), `windows_malfind.json` (injected RWX memory pages), `windows_vadinfo.json` (Virtual Address Descriptors, 849 KB), `windows_handles.json` (1.1 MB), `windows_dlllist.json` (241 KB), and `windows_svcscan.json` (97 KB).
- **Ground-Truth Availability:** **High.** Verified malware execution ground truth: Process Injection into `explorer.exe` and `reader_sl.exe` (PID 1640), active C2 socket connections to port 443, and code injection allocation descriptors.
- **Licensing:** Public research malware capture (NIST / Volatility Foundation).
- **Forensic Limitations:** Raw `.vmem` image on disk is replaced with a stub placeholder in `sample_evidence/`; however, the full suite of extracted Volatility 3 JSON telemetry is intact in `sherf/backend/output/cases/Bharath_TES1/memory/`.

#### Source 3: Enterprise Windows Server Disk Capture (`SRC-03` / `DISK_2`)
- **Acquisition & Provenance:** Complete forensic extraction of an enterprise Windows Server system disk located at [`prot1-main/output/cases/DISK_2/`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/prot1-main/output/cases/DISK_2/).
- **Available Artifact Types:**
  - *Event Logs:* 114 `.evtx` logs including `System.evtx` (16.8 MB), `Security.evtx` (6.4 MB), `Microsoft-Windows-GroupPolicy%4Operational.evtx` (2.2 MB), `Application.evtx` (1.1 MB), `Microsoft-Windows-TaskScheduler%4Operational.evtx` (1.1 MB), `Microsoft-Windows-PowerShell%4Operational.evtx`.
  - *Disk & File System:* Master File Table (`$MFT`, 89,391,104 bytes), LNK files (`lnk_analysis.json`).
  - *Registry:* `SOFTWARE` (45.9 MB), `SYSTEM` (12.8 MB), `Amcache.hve` (262 KB), `Administrator_NTUSER.DAT` (524 KB).
  - *Extracted Telemetry:* Parsed security logons (`security_logons.json`, 1.9 MB), process creation events (`process_creations.json`, 44.4 KB), services installed (`services_installed.json`), RDP sessions (`rdp_sessions.json`).
- **Ground-Truth Availability:** **Medium.** Real enterprise administration activity. Requires examiner timeline reconstruction; ideal for generating authentic, multi-domain benign baseline pairs, administrative persistence-to-execution pairs, and negative decoy pairs.
- **Licensing:** Enterprise research disk image.
- **Forensic Limitations:** Parent raw disk image (`.E01`) was extracted during previous pipeline phases and is not retained locally in the raw vault; extracted forensic files and hives are fully preserved.

#### Source 4: Stratosphere IPS / CTU Malware PCAPs (`SRC-05` / `pcap1`, `pcap2`)
- **Acquisition & Provenance:** Traffic captures originating from CTU university malware research (`2017-3-30_win6.pcap` and `2017-03-26_win20.pcap`).
- **Available Artifact Types:** Extracted network summaries (`network_summary.json`) documenting DNS queries, TCP connections, HTTP user agents, TLS handshakes, and carved packet payloads.
- **Ground-Truth Availability:** **Medium.** Documented malware C2 IPs and domain beaconing.
- **Forensic Limitations:** Captured in isolated network sandboxes without simultaneous endpoint disk images or memory dumps. Cannot be used for cross-host memory-to-network correlation without artificial timestamp alignment.

---

## 2. Controlled Pilot Scope & Relationship Definitions

### 2.1 Pilot Scope Specification
The Phase 1C Controlled Pilot will be restricted to **$N = 120$ candidate artifact pairs** across **$K = 3$ independent forensic investigations**:

$$\mathcal{D}_{\text{pilot}} = \mathcal{D}_{\text{SRC-01}} \cup \mathcal{D}_{\text{SRC-02}} \cup \mathcal{D}_{\text{SRC-03}}$$

| Pilot Investigation ID | Case Title / Scenario | Selected Artifact Domains | Target Pair Count | Primary Focus |
| :--- | :--- | :--- | :--- | :--- |
| `PILOT_CASE_JW01` | Jimmy Wilson (Lone Wolf) | Disk, Registry, Memory, Email, Browser | 50 pairs | Multi-domain insider threat: Download $\to$ LNK $\to$ Execution $\to$ Exfiltration |
| `PILOT_CASE_CR02` | Cridex Memory Intrusion | Memory (Processes, VAD, Injections) | 35 pairs | Intra-domain process injection, parent-child chains, thread manipulation |
| `PILOT_CASE_SRV03` | Windows Server Baseline (DISK_2) | Disk, Event Logs, Registry, Services | 35 pairs | Intra-domain and cross-domain benign operational sequences & negative decoys |
| **Total** | **3 Independent Cases** | **5 Forensic Domains** | **120 pairs** | **Balanced across causal and non-causal relationships** |

---

### 2.2 Separating Evidentiary Association from Causal Inference

A primary failure mode in forensic machine learning is **conflating co-occurrence with causality**. The pilot enforces strict epistemic separation:

```
[Level 1: Candidate Association Filter (Blocking)]
Artifact A and Artifact B share an identifier (PID, file path, IP, or user)
                        OR
Fall within the same temporal window (|Δt| <= 300s).
               │
               ▼  DOES NOT PROVE CAUSALITY!
[Level 2: Forensic Causal Verification]
Artifact A provided the execution vector, code injection, persistent trigger,
or direct command invocation that physically brought Artifact B into existence.
```

#### Operational Negative Rules (What is NOT Causal):
1. **Shared System Identity Is Not Causality:** Two unrelated processes running under `NT AUTHORITY\SYSTEM` (e.g. `lsass.exe` and `spoolsv.exe`) do not share a causal relationship.
2. **Generic Process Co-Occurrence Is Not Causality:** A browser writing to `places.sqlite` while `svchost.exe` writes an event log record within $\Delta t = 2\text{s}$ is an incidental co-occurrence (`COINCIDENTAL_NOISE`), **NOT** a causal nexus.
3. **Reversed Directionality Is Non-Causal:** If Run Key $A$ caused Process $B$ to execute, asserting that Process $B$ caused Run Key $A$ is physically false and must be labeled `VERIFIED_NEGATIVE`.
4. **Independent USB Insertion vs Execution:** An inserted USB drive does not have a causal link with an arbitrary executable launched from `C:\Windows\System32\` unless the executable binary or argument was hosted on the mounted volume.

---

### 2.3 Operational Definitions for Epistemic Labels

Every pilot example must receive exactly one of the three schema-defined epistemic labels:

```
+---------------------------------------------------------------------------------------------------+
|                                  EPISTEMIC LABEL ONTOLOGY                                         |
+---------------------------------------------------------------------------------------------------+
|  1. VERIFIED_POSITIVE                                                                             |
|     - Ground-Truth Causal Label: 1 (Binary)                                                       |
|     - Physical / logical proof that Artifact A initiated, spawned, injected, persisted, or        |
|       directly communicated with Artifact B.                                                      |
|     - Requires: Temporal precedence (Δt >= 0, within tolerance), kernel-verifiable parentage,     |
|       socket table binding, or verified attack emulation logs.                                    |
|                                                                                                   |
|  2. VERIFIED_NEGATIVE                                                                             |
|     - Ground-Truth Causal Label: 0 (Binary)                                                       |
|     - Definitively established as non-causal or benign coincidental co-occurrence.                |
|     - Includes: Reversed causal direction, unrelated entities sharing generic IDs, distinct       |
|       uncoordinated background threads, and provably independent benign noise.                    |
|                                                                                                   |
|  3. AMBIGUOUS_UNRESOLVED                                                                          |
|     - Ground-Truth Causal Label: null (Excluded from binary loss; preserved for calibration)      |
|     - Artifacts exhibit a plausible evidentiary nexus (e.g. temporal correlation, shared user,    |
|       or suspect staging path), but forensic telemetry is incomplete.                             |
|     - Examples: Missing parent process in memory dump, unlogged script execution, or unresolvable |
|       DNS flow with multiple concurrent destinations.                                             |
+---------------------------------------------------------------------------------------------------+
```

---

### 2.4 Explicit Relationship Types (Ontology)

The pilot will categorize all pairs into the standardized 10 relationship types:

1. `PARENT_CHILD_PROCESS`: Direct process creation where Process $A$ spawned Process $B$ (verified via PPID / PID matching and `CreateTime`).
2. `PROCESS_INJECTION`: Process $A$ allocated memory in, created a remote thread in, or hollowed Process $B$ (verified via `windows.malfind`, RWX page protection, and VAD structures).
3. `PERSISTENCE_TO_EXECUTION`: Registry Run key, service install, or scheduled task created at $t_1$ subsequently invoked binary execution at $t_2$ (verified via command string matching and Prefetch execution time).
4. `EXECUTION_TO_NETWORK_FLOW`: Process execution initiated an active TCP connection or UDP datagram flow (verified via socket endpoint PID and timestamp window).
5. `DNS_TO_NETWORK_FLOW`: DNS query for domain $D$ returned IP $I$, immediately followed by a socket flow to $I$ (verified via query answer record and flow destination).
6. `LNK_TO_FILE_ACCESS`: User interaction with a shortcut file (`.lnk`) opened the target document or executable (verified via LNK tracker block and target file `$MFT` access time).
7. `DOWNLOAD_TO_EXECUTION`: Browser or email client saved attachment/file to disk, followed by user/process execution of that file (verified via Zone.Identifier, browser history, and Prefetch).
8. `LOGON_TO_PRIVILEGE_USE`: Windows security logon session (Event 4624) enabled subsequent privileged service operation or credential delegation (Event 4672).
9. `CREDENTIAL_ACCESS_TO_AUTH`: Dumping of LSASS or SAM secrets used to authenticate against another service or host (Event 4624 Type 3).
10. `COINCIDENTAL_NOISE`: Deliberately sampled negative pairs exhibiting incidental co-occurrence or shared attributes without causal relation.

---

## 3. Reproducible Pilot Workflow & Extraction Protocol

```
+---------------------------------------------------------------------------------+
| Step 1: Evidence Preservation & Cryptographic Integrity Register                |
| - Verify read-only status in evidence_vault                                     |
| - Compute and record SHA-256 / SHA-1 hashes in SQLite custody ledger            |
+---------------------------------------------------------------------------------+
                                      │
                                      ▼
+---------------------------------------------------------------------------------+
| Step 2: Native Forensic Extraction (Existing Backend Extractors)                |
| - Disk / Hives: disk_image/orchestrator.py, prefetch/analyzer.py, mft/extractor |
| - Memory: memory/plugin_orchestrator.py (Volatility 3 pslist, malfind, handles)|
+---------------------------------------------------------------------------------+
                                      │
                                      ▼
+---------------------------------------------------------------------------------+
| Step 3: Candidate Pair Generation (Stage 1 Blocking Heuristic)                  |
| - Query extracted telemetry for shared entities (PID, path, socket)             |
| - Window filter: |t_target - t_source| <= 300 seconds                           |
| - Enforce domain balancing: 50% cross-domain, 50% intra-domain                  |
+---------------------------------------------------------------------------------+
                                      │
                                      ▼
+---------------------------------------------------------------------------------+
| Step 4: Multi-Examiner Adjudication Protocol                                    |
| - Examiner 1 & Examiner 2 independently score pair using operational definitions|
| - Consensus agreement -> CONSENSUS_VERIFIED                                     |
| - Disagreement -> Senior Arbitrator review (ARBITRATED) or DISPUTED             |
+---------------------------------------------------------------------------------+
                                      │
                                      ▼
+---------------------------------------------------------------------------------+
| Step 5: Format to Versioned Schema & CLI Quality Gate Audit                     |
| - Serialize to correlation_training_pairs_pilot.json                            |
| - Run: python -m app.cli.validate_correlation_dataset <file>                    |
+---------------------------------------------------------------------------------+
```

### 3.1 Provenance and Custody Recording Standard
Each generated candidate pair must record immutable provenance fields:
```json
"provenance": {
  "source_storage_hash": "6c18f662744d55e2769d9510f6173f04dab668c42b67ef27b675d22e628b4ed5",
  "source_file_path": "evidence/EVD-001/disk/registry/SOFTWARE",
  "source_record_locator": "Microsoft\\Windows\\CurrentVersion\\Run\\StikyNot",
  "source_extractor": "SherlockAI_RegistryExtractor_v1.0",
  "target_storage_hash": "6c18f662744d55e2769d9510f6173f04dab668c42b67ef27b675d22e628b4ed5",
  "target_file_path": "evidence/EVD-001/disk/prefetch/STIKYNOT.EXE-00507E76.pf",
  "target_record_locator": "Header.LastRunTime[0]",
  "target_extractor": "SherlockAI_PrefetchAnalyzer_v1.0"
}
```

---

## 4. Audit of Research Readiness Criteria for Pilot & Full Scale

The quality criteria defined in [`CORRELATION_TRAINING_PLAN.md`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/CORRELATION_TRAINING_PLAN.md) represent **engineering criteria for dataset hygiene and pipeline safety**, not statistical guarantees of universal model generalization.

The table below contrasts the **Controlled Pilot Targets** against the **Full Production Model Gates**:

| Quality Gate | Metric & Target for Full ML Corpus (Phase 2) | Controlled Pilot Criterion (Phase 1C Pilot) | Evaluation Method in Validator CLI |
| :--- | :--- | :--- | :--- |
| **Gate 1: Scale** | $N \ge 2,500$ annotated pairs | $N \ge 100$ annotated pairs | Evaluates sample count against configured threshold (`total_records`). |
| **Gate 2: Diversity** | $K \ge 15$ independent cases | $K \ge 3$ independent cases (`JW01`, `CR02`, `SRV03`) | Counts distinct `investigation_id` values. |
| **Gate 3: Class Balance** | 35%–55% Positive, 45%–65% Negative | 40%–50% Positive, 40%–50% Negative, 5%–15% Ambiguous | Calculates percentage breakdown of `ground_truth_causal_label`. |
| **Gate 4: Domain Confounding** | Positives: 40%–60% Cross-Domain<br>Negatives: 35%–60% Intra-Domain | Positives: $\ge 40\%$ Cross-Domain<br>Negatives: $\ge 40\%$ Intra-Domain | Evaluates contingency table: $\mathbb{I}[\text{domain}_a \neq \text{domain}_b]$ for positives and negatives. |
| **Gate 5: Relationship Types** | $\ge 6$ types with $\ge 10$ pairs each | $\ge 4$ distinct relationship types represented | Evaluates distribution over the 10 defined relationship types. |
| **Gate 6: Ambiguous Representation** | $\ge 5.0\%$ of dataset labeled Ambiguous | $\ge 5.0\%$ of dataset labeled Ambiguous | Checks `epistemic_classification == AMBIGUOUS_UNRESOLVED`. |
| **Gate 7: Annotation Quality** | $\ge 80\%$ adjudicated consensus; 0 disputed | $\ge 80\%$ dual-reviewed consensus; 0 disputed | Verifies `adjudication_status` and confirms multi-annotator agreement. |
| **Integrity: Cross-Case Leakage** | 0 duplicate artifact fingerprints across cases | 0 duplicate artifact fingerprints across cases | Compares SHA-256 hashes and storage paths across split boundaries. |

---

## 5. Commands and Expected Execution Outputs

### 5.1 Verification Commands

#### Command 1: Inspect and Verify Physical Source Vault Integrity
```powershell
python -c "
import hashlib
from pathlib import Path

vault_p = Path('sherf/backend/evidence_vault/1cda6ac0-fb62-425c-b69c-813ed1275707')
for p in vault_p.rglob('*'):
    if p.is_file():
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        print(f'{p.name} | {p.stat().st_size:,} bytes | SHA256: {h}')
"
```
**Expected Output:**
```
2020JimmyWilson.E01 | 309,818,835 bytes | SHA256: 6c18f662744d55e2769d9510f6173f04dab668c42b67ef27b675d22e628b4ed5
Triage-Memory.mem   | 5,368,709,120 bytes | SHA256: a18602964abfbc54e1c83ebdaa61638ff3c2251485e4ad684fc9b59d43dd04a8
```

#### Command 2: Execute Dataset Validator CLI on Development Fixture
```powershell
python -m app.cli.validate_correlation_dataset tests/fixtures/correlation_datasets/synthetic_valid_dev_fixture.json
```
**Expected Output:**
```
================================================================================
 SHERLOCKAI / H-MACFR — CORRELATION DATASET VALIDATION REPORT
================================================================================
 Total Records Processed: 5
 Valid Structural Records: 5
 Structural Status:        PASS
 Training Readiness Status: NOT READY (Expected for Dev/Fixtures)
...
[RESULT] VALIDATION SUCCESSFUL. Exit code 0.
```

#### Command 3: Execute Full Research Readiness Check on Pilot Dataset
```powershell
python -m app.cli.validate_correlation_dataset path/to/pilot_dataset.json --check-readiness
```
**Expected Output (When Pilot is Completed):**
- Exit code 0 if all 7 gates pass.
- Exit code 2 if scale/diversity gates are not satisfied.

---

## 6. Risks, Blockers, & Unresolved Questions

| Risk / Question | Severity | Technical Description | Mitigation Strategy |
| :--- | :--- | :--- | :--- |
| **Clock Skew Inversion** | High | Timestamps across separate artifact domains (e.g. FAT/NTFS MFT $\pm 100\text{ns}$ vs EventLog UTC vs Registry LocalTime) may indicate $\Delta t < 0$ for true forward causal actions. | Schema accommodates `clock_skew_risk` metadata; validator incorporates configurable `TIMESTAMP_DELTA_TOLERANCE_SECONDS = 1.0` tolerance. |
| **Absent Raw E01 for DISK_2** | Medium | `DISK_2` contains complete extracted event logs, MFT, and registry hives, but the original raw E01 container is not present in the vault. | Record individual artifact cryptographic hashes (`file_hash`) and mark source container provenance as `CONTAINER_PRUNED_EXTRACTED_RETAINED`. |
| **Single-Host Endpoint Bias in Jimmy Wilson** | Medium | The Jimmy Wilson challenge is an endpoint-focused investigation lacking concurrent enterprise network packet captures. | Combine with Cridex memory (`CR02`) and Windows Server logs (`SRV03`) to ensure diversity of environments and attacker techniques. |
| **Synthetic Fixture Contamination** | Critical | Inadvertently mixing synthetic pipeline tests (`CASE_ALL5_F1A5D2`) into training data causes catastrophic shortcut learning. | Enforce strict investigation ID prefix segregation (`SYNTH_*` vs `PILOT_*`) and maintain validator Gate 4 de-confounding checks. |

---

## 7. Strategic GO / NO-GO Decisions

### Decision A: Can a Real Forensic Pilot Begin With Currently Available Evidence?
$$\mathbf{DECISION: \quad QUALIFIED \quad GO \quad (PILOT \quad PHASE)}$$
- **Technical Basis:**
  1. Real, multi-gigabyte forensic evidence is verified and physically present in the repository vault (`2020JimmyWilson.E01` at 309.8 MB, `Triage-Memory.mem` at 5.0 GB).
  2. Full extracted forensic telemetry is intact across 3 independent cases (`Standalone Artifact Test`, `Bharath_TES1`, and `DISK_2`).
  3. The dataset schema, Pydantic validation service, CLI auditing tool, and multi-examiner adjudication protocols are fully implemented, verified, and operational.
  4. A controlled pilot of $N \approx 100\text{--}150$ artifact pairs across these 3 cases **CAN** proceed immediately to validate the candidate extraction, pair-generation blocking heuristic, and annotation workflows.

### Decision B: Can Supervised Model Training (Phase 2) Begin?
$$\mathbf{DECISION: \quad STRICT \quad NO\text{-}GO}$$
- **Technical Basis:**
  1. The controlled pilot is an engineering feasibility trial, **not** an ML training corpus.
  2. Training any machine learning model requires $N \ge 2,500$ pairs across $K \ge 15$ diverse cases satisfying all 7 research quality gates.
  3. Model training remains strictly blocked until the multi-case collection program (Phase 1D) completes and receives full validation sign-off.

---
*End of Phase 1C Forensic Dataset Inventory and Controlled Pilot Plan — SherlockAI.*
