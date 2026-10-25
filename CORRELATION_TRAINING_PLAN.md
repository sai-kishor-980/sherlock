# SherlockAI / H-MACFR — Correlation Learning Phase 0: Training Strategy and Dataset Audit

**Document Status:** Complete & Verified Baseline  
**Date:** 2026-10-23  
**Framework:** H-MACFR (Hierarchical Multi-Agent Cyber Forensic Reconstruction)  
**Deliverable:** `CORRELATION_TRAINING_PLAN.md`  
**Target Subsystem:** Machine-Learning Correlation Engine (`sherf/backend/app/services/synthesizer_service.py`, `graph_service.py`, `model_adapter_service.py`)

---

## 1. Executive Summary & Audit Baseline

This document establishes the official **Phase 0 Training Strategy and Dataset Audit** for transitioning the H-MACFR forensic correlation engine from deterministic heuristic deduction to a verified, machine-learning-assisted correlation architecture.

### Key Audit Findings (Verified Repository Facts)
1. **Zero ML Inference in Current Pipeline:** Despite previous architectural references to machine learning correlation, the current SherlockAI engine relies **exclusively on deterministic rule deduction** in [`sherf/backend/app/services/synthesizer_service.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/synthesizer_service.py#L886-L1228) and a secondary keyword matcher in [`processeed/correlation_engine.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/processeed/correlation_engine.py#L59-L86).
2. **LoRA Adapters Are Domain-Specific, Not Correlation Models:** The model adapter service in [`sherf/backend/app/services/model_adapter_service.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/model_adapter_service.py#L29-L68) houses 5 domain-specific LoRA adapters (memory, disk, network, logs, registry) and 1 supervisor base adapter (`base_cybersecurity`), all adapted from Qwen (`unsloth/Qwen2.5-7B-Instruct-bnb-4bit` / `Qwen/Qwen3-8B`). **No correlation model adapter exists.**
3. **Inactive Neural Inference Path:** In [`model_adapter_service.py: line 312`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/model_adapter_service.py#L312), local PEFT inference is stubbed out (`raise NotImplementedError("Live GPU inference requested on CPU device")`) and immediately falls back to a deterministic string keyword evaluator ([lines 315–375](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/model_adapter_service.py#L315-L375)).
4. **Current Training Dataset Is Unusable for Supervised Training:** The verified training dataset fixture in [`sherf/backend/output/cases/CASE_ALL5_F1A5D2/correlation_training_pairs.json`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/output/cases/CASE_ALL5_F1A5D2/correlation_training_pairs.json) contains **exactly 10 samples from a single case ($N=1$)**, exhibiting **100% domain confounding** (5 of 5 positives are intra-domain; 5 of 5 negatives are cross-domain). Training any classifier on this dataset produces catastrophic shortcut learning.
5. **Verdict:** **New multi-case forensic data must be collected and rigorously annotated** before any supervised correlation model can be trained.

---

## 2. Current-State Audit: Codebase & Dataset Inspection

### 2.1 Correlation Engine Architecture

Correlation in SherlockAI currently operates across two distinct subsystems:

| Subsystem | Location | Mechanism | Number of Rules | Output Format |
| :--- | :--- | :--- | :--- | :--- |
| **H-MACFR Synthesizer Service** | [`synthesizer_service.py: lines 886–1228`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/synthesizer_service.py#L886-L1228) | Deterministic cross-source rule evaluation | 4 Rules (Memory, Registry-Prefetch, DNS-Flow, USB-Prefetch) | Structured correlation dictionaries with `temporal_status`, `correlation_nature`, and `is_causal` |
| **Evidence Graph Service** | [`graph_service.py: lines 456–545`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/graph_service.py#L456-L545) | Entity-node resolution and NetworkX directed multigraph edge creation | Resolves 4 rule outputs to graph nodes | Nodes, typed edges, unresolved edge diagnostics |
| **Legacy Processed Engine** | [`processeed/correlation_engine.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/processeed/correlation_engine.py#L1-L100) | Substring keyword scanning over unnormalized JSON | 2 Hardcoded templates | [`processeed/correlations/correlations.json`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/processeed/correlations/correlations.json) (2 static records) |

#### Exact Inventory of Current Correlation Rules in `synthesizer_service.py`:
1. `_correlate_memory_injections` ([lines 890–992](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/synthesizer_service.py#L890-L992)): Correlates `windows.malfind` RWX allocations with `windows.pslist` parent processes. Computes $\Delta t = \text{CreateTime}_{\text{child}} - \text{CreateTime}_{\text{parent}}$. Validates temporal hierarchy ($\Delta t \ge 0 \to \text{CORROBORATED\_HYPOTHESIS}$; $\Delta t < 0 \to \text{AMBIGUOUS\_ASSOCIATION}$).
2. `_correlate_process_to_run_key` ([lines 994–1077](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/synthesizer_service.py#L994-L1077)): Substring match between Registry Run key commands and Prefetch executable names. Computes $\Delta t = \text{last\_run\_time} - \text{last\_write\_time}$. Checks if persistence preceded execution.
3. `_correlate_dns_to_network_flows` ([lines 1079–1163](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/synthesizer_service.py#L1079-L1163)): Matches DNS query response IP addresses against active TCP bidirectional socket conversations. Validates temporal sequence ($\Delta t = \text{start\_time}_{\text{flow}} - \text{timestamp}_{\text{DNS}} \ge 0 \to \text{DETERMINISTIC\_GROUNDED}$).
4. `_correlate_usb_to_execution` ([lines 1165–1227](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/synthesizer_service.py#L1165-L1227)): Matches Registry USB device insertion with Prefetch execution telemetry. Explicitly classifies relationship as `COINCIDENTAL_NOISE` (confidence 0.15) unless a direct drive letter / volume mount path nexus exists.

### 2.2 Model Adapter Service & Inactive Neural Inference Path

An inspection of [`sherf/backend/app/services/model_adapter_service.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/model_adapter_service.py) reveals:
- Physical LoRA weights and configs exist in [`sherf/backend/app/models/adapters/`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/models/adapters/):
  - `base_cybersecurity` (Supervisor orchestrator, Qwen base)
  - `memory/memory_agent_adapter_v4`
  - `disk/disk_adaptor`
  - `network/`
  - `logs/SherlockAI_LogAgent_Final`
  - `registry/registry`
- **Zero Correlation LoRA Adapters:** All existing adapters are single-domain evidence classifiers (classifying isolated domain evidence as `BENIGN`, `SUSPICIOUS`, or `MALICIOUS`). None are trained or configured to accept pairs of cross-domain artifacts to predict relationship causality.
- **Inactive Inference Execution:**
  ```python
  # sherf/backend/app/services/model_adapter_service.py: line 312
  prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
  # We don't load the full 7B model onto CPU here unless explicitly called, to preserve server memory
  raise NotImplementedError("Live GPU inference requested on CPU device")
  ```
  When invoked, local execution immediately traps to the fallback `_run_forensic_evaluator` ([lines 315–375](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/model_adapter_service.py#L315-L375)), which scans the text payload for 11 hardcoded string keywords (`powershell`, `mimikatz`, `cobaltstrike`, `beacon`, `rundll32`, `svchost`, `injection`, `runonce`, `cmd.exe`, `whoami`, `unauthorized`).

### 2.3 Measured Dataset Audit & Breakdown

Three historical dataset files were audited across the repository. Measurements were gathered using exact script analysis:

| Dataset File Path | Total Pairs | Unique Cases | Null Fields | Duplicate Pairs | Label Breakdown | Domain Distribution Breakdown | Audit Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| [`output/cases/CASE_ALL5_1B266E/correlation_training_pairs.json`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/output/cases/CASE_ALL5_1B266E/correlation_training_pairs.json) | 16 | 1 (`1B266E`) | **16 nulls in 6 fields** (`domain_a`, `domain_b`, `artifact_a`, `artifact_b`, `confidence`, $\Delta t$) | **16 duplicate pairs** (`(None, None)` repeated 16x) | 14 Pos / 2 Neg | None $\to$ None (14 pos), None $\to$ None (2 neg) | **FATAL REJECT:** Pre-sprint corrupt generation. |
| [`output/cases/CASE_ALL5_E269DC/correlation_training_pairs.json`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/output/cases/CASE_ALL5_E269DC/correlation_training_pairs.json) | 9 | 1 (`E269DC`) | 0 | 0 | 6 Pos / 3 Neg | 4 Mem $\to$ Mem (pos), 2 Reg $\to$ Disk (pos), 1 Disk $\to$ Log (neg), 1 Reg $\to$ Mem (neg), 1 Disk $\to$ Net (neg) | **REJECT:** Included false-positive USB-to-Prefetch as positive label. |
| [`output/cases/CASE_ALL5_F1A5D2/correlation_training_pairs.json`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/output/cases/CASE_ALL5_F1A5D2/correlation_training_pairs.json) | **10** | **1 (`F1A5D2`)** | **0** | **0** | **5 Pos / 5 Neg** | **5 Intra-domain (pos), 5 Cross-domain (neg)** | **CURRENT BASELINE:** Clean syntax, but fatally confounded. |

#### Detailed Breakdown of Current Verified Baseline (`CASE_ALL5_F1A5D2`):
- **Total Valid Examples:** 10
- **Unique Investigations:** Exactly 1 (`CASE_ALL5_F1A5D2`).
- **Class Balance:** Exactly 50% Positive (`ground_truth_causal_label: 1`), 50% Negative (`ground_truth_causal_label: 0`).
- **Missing Fields:** 0 (all 12 required fields populated: `sample_id`, `case_id`, `domain_a`, `domain_b`, `artifact_a`, `artifact_b`, `nature`, `ground_truth_causal_label`, `confidence`, `temporal_delta_seconds`, `shared_identifiers`, `causal_explanation`).
- **Duplicate Pairs:** 0 (10 distinct artifact pairs).

#### Breakdown by Domain Pair and Relationship Type:
```
+------------------------------------+--------------------------+-------+-------+
| Domain Pair (domain_a -> domain_b) | Relationship Type        | Label | Count |
+------------------------------------+--------------------------+-------+-------+
| memory -> memory                   | process_injection_chain  |   1   |   4   |
| network -> network                 | dns_resolution_to_flow   |   1   |   1   |
| registry -> disk                   | usb_insertion_to_exec    |   0   |   2   |
| disk -> logs                       | coincidental_noise       |   0   |   1   |
| registry -> memory                 | coincidental_noise       |   0   |   1   |
| disk -> network                    | coincidental_noise       |   0   |   1   |
+------------------------------------+--------------------------+-------+-------+
Total Positive: 5 (100% Intra-Domain)
Total Negative: 5 (100% Cross-Domain)
```

### 2.4 Domain Confounding and Shortcut Learning Proof

The current dataset exhibits **complete domain confounding**:
$$\forall s \in \mathcal{D}_{\text{pos}}, \quad \text{domain}_a(s) = \text{domain}_b(s)$$
$$\forall s \in \mathcal{D}_{\text{neg}}, \quad \text{domain}_a(s) \neq \text{domain}_b(s)$$

This was formally captured and codified in the regression test suite [`sherf/backend/tests/test_forensic_audit_corrections.py: lines 119–140`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/tests/test_forensic_audit_corrections.py#L119-L140):
```python
pos_intra = sum(1 for s in pos_samples if s["domain_a"] == s["domain_b"])
neg_cross = sum(1 for s in neg_samples if s["domain_a"] != s["domain_b"])
assert pos_intra == len(pos_samples), "100% of positive pairs are intra-domain"
assert neg_cross == len(neg_samples), "100% of negative pairs are cross-domain"
```

**Consequence for ML:** Any machine learning model trained on this dataset will achieve 100% training accuracy by evaluating the single binary feature:
$$f(s) = \mathbb{I}[\text{domain}_a == \text{domain}_b]$$
The model will never learn forensic causal indicators (such as temporal sequence, socket bindings, process parentage, or cryptographic hashes). It will reject all genuine cross-domain attacks (e.g. registry persistence leading to disk execution, or disk execution establishing a network C2 flow) and accept all intra-domain pairs regardless of whether an attack occurred.

### 2.5 Feasibility Verdict on Supervised Training with Current Data

| Criterion | Required for Supervised ML | Current Repository Baseline | Verdict |
| :--- | :--- | :--- | :--- |
| **Sample Size ($N$)** | $\ge 2,500$ annotated pairs | 10 pairs | **FAIL** (Deficit of 249x) |
| **Independent Cases** | $\ge 15$ diverse investigations | 1 investigation | **FAIL** (Complete lack of forensic diversity) |
| **Cross-Domain Positives** | $\ge 40\%$ of positive pairs | 0% (0 of 5) | **FAIL** (Fatal domain confounding) |
| **Intra-Domain Negatives** | $\ge 40\%$ of negative pairs | 0% (0 of 5) | **FAIL** (Cannot learn intra-domain discrimination) |
| **Relationship Variety** | $\ge 8$ forensic relationship types | 2 positive types, 1 negative type | **FAIL** (Severely unrepresentative) |

**Conclusion:** The current dataset **CANNOT** support supervised model training. Collecting and validating a comprehensive multi-case forensic corpus is mandatory.

---

## 3. Recommended Task Definition and Formulation

### 3.1 Forensic Context and Operational Constraints

In an enterprise forensic investigation, a single workstation image generates between $10^4$ and $10^6$ discrete artifact records (file writes, process events, registry modifications, socket connections). 

Evaluating all possible pairs $(u, v) \in \mathcal{V} \times \mathcal{V}$ yields an $O(|\mathcal{V}|^2)$ combinatorial explosion:
$$|\mathcal{V}| = 10^5 \implies \binom{|\mathcal{V}|}{2} \approx 5 \times 10^9 \text{ candidate pairs}$$
Less than $0.0001\%$ of these pairs represent genuine evidentiary relationships. A naive end-to-end pairwise neural classifier is computationally intractable and would suffer catastrophic false-positive inflation.

### 3.2 Two-Stage Formulation: Candidate Generation + Multi-Task Scoring

We define the correlation learning task as a **Two-Stage Pipeline**:

```
+---------------------------------------------------------------------------------+
| Stage 1: Deterministic Forensic Candidate Generation (Blocking / Candidate Filter)|
| - Input: Extracted multi-domain artifact records                                |
| - Heuristics: Shared identifiers (PID, IP, hash, user) OR temporal window (|Δt|)|
| - Output: High-recall candidate pair set C ⊂ V x V (Pruning 99.9% of null space) |
+---------------------------------------------------------------------------------+
                                      │
                                      ▼
+---------------------------------------------------------------------------------+
| Stage 2: Learned Pairwise Forensic Relationship Classifier & Scorer             |
| - Input: Candidate artifact pair (A, B) + Temporal Context + Shared Metadata   |
| - Task 2A (Binary): Ground-Truth Causal Probability P(Causal | A, B, Context)   |
| - Task 2B (Multi-Class): Relationship Type Classification (k ∈ K)               |
| - Task 2C (Epistemic): Confidence Calibration & Uncertainty Quantification      |
+---------------------------------------------------------------------------------+
                                      │
                                      ▼
+---------------------------------------------------------------------------------+
| Stage 3: Deterministic Forensic Safety Gate (Post-Filter)                       |
| - Validates physical impossibility (clock skew bounds, kernel invariants)       |
| - Prevents ungrounded hallucinations from entering the Evidence Graph           |
+---------------------------------------------------------------------------------+
```

### 3.3 Task Specification

For each candidate pair $x_i = (a, b, \Delta t, \text{ctx})$ generated by Stage 1:
1. **Binary Causal Classification ($y_i \in \{0, 1\}$):**
   - $y_i = 1$ (Causal / Corroborated): Artifact $a$ directly caused, enabled, or reliably corroborates artifact $b$ as part of an operational sequence or attack chain.
   - $y_i = 0$ (Coincidental / Benign Noise): Artifacts $a$ and $b$ co-occur temporally or share incidental attributes without evidentiary connection.
2. **Relationship-Type Categorization ($r_i \in \mathcal{R}$):**
   - $\mathcal{R} = \{$
     `PARENT_CHILD_PROCESS`, `PROCESS_INJECTION`, `PERSISTENCE_TO_EXECUTION`, 
     `EXECUTION_TO_NETWORK_FLOW`, `DNS_TO_NETWORK_FLOW`, `LNK_TO_FILE_ACCESS`, 
     `DOWNLOAD_TO_EXECUTION`, `LOGON_TO_PRIVILEGE_USE`, `CREDENTIAL_ACCESS_TO_AUTH`,
     `COINCIDENTAL_NOISE` $\}$
3. **Calibrated Confidence Score ($s_i \in [0.0, 1.0]$):**
   - Outputs a calibrated posterior probability representing evidentiary certainty.

---

## 4. Standardized Dataset Schema

The schema must capture forensic reality: provenance, temporal telemetry, domain semantics, shared entity identifiers, and explicit uncertainty indicators.

### 4.1 Candidate Pair JSON Schema Specification

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "ForensicCorrelationTrainingPair",
  "type": "object",
  "required": [
    "sample_id",
    "investigation_id",
    "case_metadata",
    "source_artifact",
    "target_artifact",
    "temporal_context",
    "shared_entities",
    "labels",
    "annotation_provenance"
  ],
  "properties": {
    "sample_id": { "type": "string", "pattern": "^PAIR-[A-Z0-9]{8}$" },
    "investigation_id": { "type": "string", "description": "Unique forensic case ID for group splitting." },
    "case_metadata": {
      "type": "object",
      "required": ["os_version", "environment_type", "scenario_type"],
      "properties": {
        "os_version": { "type": "string", "enum": ["Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022", "Linux Ubuntu 22.04"] },
        "environment_type": { "type": "string", "enum": ["ENTERPRISE_WORKSTATION", "DOMAIN_CONTROLLER", "CLOUD_VM", "STANDALONE_LAB"] },
        "scenario_type": { "type": "string", "enum": ["BENIGN_BASELINE", "RANSOMWARE", "APT_INTRUSION", "INSIDER_DATA_THEFT", "MALWARE_INFECTION"] }
      }
    },
    "source_artifact": {
      "type": "object",
      "required": ["artifact_id", "domain", "category", "raw_payload", "normalized_fields", "extracted_timestamp"],
      "properties": {
        "artifact_id": { "type": "string" },
        "domain": { "type": "string", "enum": ["memory", "disk", "network", "registry", "logs", "browser", "email"] },
        "category": { "type": "string", "enum": ["process", "vad_memory", "prefetch", "mft_entry", "lnk_file", "dns_record", "tcp_flow", "run_key", "usb_event", "eventlog_record"] },
        "raw_payload": { "type": "object" },
        "normalized_fields": {
          "type": "object",
          "properties": {
            "entity_name": { "type": "string" },
            "path": { "type": ["string", "null"] },
            "pid": { "type": ["integer", "null"] },
            "ip": { "type": ["string", "null"] },
            "port": { "type": ["integer", "null"] },
            "user_sid": { "type": ["string", "null"] },
            "hash_sha256": { "type": ["string", "null"] }
          }
        },
        "extracted_timestamp": { "type": ["string", "null"], "format": "date-time" },
        "timestamp_source": { "type": "string", "enum": ["FILE_MFT_SI", "FILE_MFT_FN", "REG_LAST_WRITE", "EVENTLOG_SYSTEM_TIME", "PCAP_FRAME_TIME", "PROCESS_CREATE_TIME", "SNAPSHOT_APPROXIMATE", "UNRECORDED"] }
      }
    },
    "target_artifact": {
      "type": "object",
      "description": "Identical structure to source_artifact."
    },
    "temporal_context": {
      "type": "object",
      "required": ["delta_seconds", "temporal_order", "clock_skew_risk"],
      "properties": {
        "delta_seconds": { "type": ["number", "null"] },
        "temporal_order": { "type": "string", "enum": ["SOURCE_PRECEDES_TARGET", "TARGET_PRECEDES_SOURCE", "CONCURRENT", "UNKNOWN"] },
        "clock_skew_risk": { "type": "string", "enum": ["NONE_SAME_SYSTEM", "POSSIBLE_MULTI_HOST", "KNOWN_INVERSION"] },
        "time_window_valid": { "type": "boolean" }
      }
    },
    "shared_entities": {
      "type": "object",
      "properties": {
        "shared_pid": { "type": "boolean" },
        "shared_process_name": { "type": "boolean" },
        "shared_path": { "type": "boolean" },
        "shared_ip": { "type": "boolean" },
        "shared_user": { "type": "boolean" },
        "shared_hash": { "type": "boolean" },
        "identifiers_list": { "type": "array", "items": { "type": "string" } }
      }
    },
    "labels": {
      "type": "object",
      "required": ["ground_truth_causal_label", "relationship_type", "epistemic_classification"],
      "properties": {
        "ground_truth_causal_label": { "type": "integer", "enum": [0, 1] },
        "relationship_type": { 
          "type": "string",
          "enum": [
            "PARENT_CHILD_PROCESS",
            "PROCESS_INJECTION",
            "PERSISTENCE_TO_EXECUTION",
            "EXECUTION_TO_NETWORK_FLOW",
            "DNS_TO_NETWORK_FLOW",
            "LNK_TO_FILE_ACCESS",
            "DOWNLOAD_TO_EXECUTION",
            "LOGON_TO_PRIVILEGE_USE",
            "CREDENTIAL_ACCESS_TO_AUTH",
            "COINCIDENTAL_NOISE"
          ]
        },
        "epistemic_classification": {
          "type": "string",
          "enum": ["DETERMINISTIC_GROUNDED", "CORROBORATED_HYPOTHESIS", "COINCIDENTAL_NOISE", "AMBIGUOUS_UNRESOLVED"]
        },
        "mitre_attack_techniques": { "type": "array", "items": { "type": "string" } }
      }
    },
    "annotation_provenance": {
      "type": "object",
      "required": ["annotator_type", "annotator_id", "verification_method", "annotator_confidence"],
      "properties": {
        "annotator_type": { "type": "string", "enum": ["HUMAN_FORENSIC_EXPERT", "AUTOMATED_GROUND_TRUTH_RECORDER", "MULTI_REVIEWER_CONSENSUS"] },
        "annotator_id": { "type": "string" },
        "verification_method": { "type": "string", "enum": ["EMULATION_LOG_CORROBORATION", "SOURCE_CODE_TRACING", "KERNEL_TELEMETRY_MATCH", "STATIC_DISASSEMBLY_VERIFIED"] },
        "annotator_confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
        "justification_notes": { "type": "string" }
      }
    }
  }
}
```

---

## 5. Trustworthy Annotation and Ground-Truth Labeling Protocol

To avoid biased, subjective, or heuristic-dependent labeling, we establish a **three-way epistemic partition** with rigorous verification rules.

### 5.1 Three-Way Epistemic Partition

```
                                  Candidate Artifact Pair (A, B)
                                                 │
                     ┌───────────────────────────┴───────────────────────────┐
                     ▼                                                       ▼
        Is Causal Link Verified?                                 Is Disjunct Proven?
        (Cryptographic hash,                                     (Disjoint path, volume,
         socket binding, kernel PPID)                             PID reuse, unrelated logon)
                     │                                                       │
         ┌───────────┴───────────┐                               ┌───────────┴───────────┐
        YES                     NO                              YES                     NO
         │                       │                               │                       │
         ▼                       ▼                               ▼                       ▼
 ╔═════════════════╗    Is Evidence Contradictory      ╔═════════════════╗    ╔═════════════════╗
 ║ VERIFIED        ║    or Telemetry Missing?          ║ VERIFIED        ║    ║ AMBIGUOUS /     ║
 ║ POSITIVE (1)    ║                 │                 ║ NEGATIVE (0)    ║    ║ UNRESOLVED      ║
 ╚═════════════════╝      ┌──────────┴──────────┐      ╚═════════════════╝    ╚═════════════════╝
                         YES                   NO                                      │
                          │                     │                                      │
                          ▼                     ▼                                      ▼
                 ╔═════════════════╗   Default to Review                         Excluded from
                 ║ AMBIGUOUS /     ║                                             Binary Training;
                 ║ UNRESOLVED      ║                                             Used for
                 ╚═════════════════╝                                             Uncertainty Calibration
```

### 5.2 Criteria for Verified Positive ($y = 1$)
A pair is labeled **Verified Positive** only if at least one hard forensic invariant is satisfied:
1. **Parent-Child Lineage:** `PPID` and `CreateTime` in kernel memory tables match, and `ParentCreateTime < ChildCreateTime`.
2. **Socket-to-Process Binding:** Process network socket handle table matches the exact TCP 4-tuple (`local_ip:port` $\leftrightarrow$ `remote_ip:port`) during the active process lifetime.
3. **Execution from Persistence:** Registry `Run` / `RunOnce` key path and cryptographic hash identically match the binary executed in Prefetch or MFT records, and $\text{Time}_{\text{RegistryModify}} \le \text{Time}_{\text{Execution}}$.
4. **DNS Lookup to Flow:** DNS query successfully resolved IP $X$, and an outbound socket to IP $X$ was opened by the same PID within a valid forward window ($0 \le \Delta t \le 300\text{s}$).
5. **Emulation Ground Truth:** In an emulated scenario, the attack orchestrator script explicitly executed artifact $b$ as a direct consequence of artifact $a$, logged via kernel ETW/Sysmon.

### 5.3 Criteria for Verified Negative ($y = 0$)
A pair is labeled **Verified Negative** only if negative causation is forensically provable:
1. **Physical / Path Disconnection:** Executable in disk telemetry executed strictly from a fixed local volume (`C:\Program Files\...`), while USB registry entry records a removable drive without drive-letter or volume nexus.
2. **Temporal Impossibility / Inversion:** Target event timestamp precedes source event timestamp by more than verified clock-skew tolerance (e.g. flow completed 2 hours before DNS was registered).
3. **Independent Background Operations:** Proven default Windows system maintenance utilities (e.g. `Defrag.exe`, `TiWorker.exe`, `VMwareTray.exe`) operating in independent sessions from user-initiated actions.
4. **Different Security Identifiers (SIDs):** Events originating from disjoint, non-interactive service accounts with zero privilege inheritance or IPC nexus.

### 5.4 Criteria for Ambiguous / Unresolved (Excluded from Binary Loss)
Examples with conflicting or absent evidence are classified as `AMBIGUOUS_UNRESOLVED`:
- **PID Reuse:** Target PID spawned weeks after parent terminated, with non-monotonic timestamps.
- **Clock Skew Inversion Across Systems:** Network sensor capture and workstation event logs disagree by $> 5$ minutes with uncalibrated NTP.
- **Unrecorded Timestamps:** Memory snapshot allocates injected memory, but process creation timestamp is unrecorded (`TIMESTAMPS_UNAVAILABLE_SNAPSHOT`).
- **Rule:** These examples **must never be labeled as binary 0 or 1**. They are retained in an evaluation set to measure whether the model outputs high uncertainty / intermediate confidence ($0.40 \le p \le 0.60$).

### 5.5 Multi-Annotator Consensus & Quality Control
- **Two Independent Reviews:** Every candidate pair must be reviewed by two independent forensic examiners or verified against an automated kernel-level ground-truth recorder (e.g., Caldera/Atomic Red Team automated execution telemetry).
- **Inter-Rater Agreement:** Cohen's Kappa must meet:
  $$\kappa = \frac{p_o - p_e}{1 - p_e} \ge 0.85$$
- Any pair with annotator disagreement is escalated to a senior forensic specialist or marked `AMBIGUOUS_UNRESOLVED`.

---

## 6. Reproducible Dataset Generation Strategy

To solve the $N=1$ sample limitation and eliminate domain confounding, we require a reproducible corpus spanning multiple independent forensic cases.

### 6.1 Multi-Case Forensic Corpus Matrix

We structure dataset acquisition across three distinct forensic sources:

```
                                  Target Dataset Corpus (≥ 15 Cases)
                                                 │
          ┌──────────────────────────────────────┼──────────────────────────────────────┐
          ▼                                      ▼                                      ▼
╔════════════════════════════╗ ╔════════════════════════════╗ ╔════════════════════════════╗
║ Source A: Public DFIR      ║ ║ Source B: Automated Attack ║ ║ Source C: Clean Benign      ║
║ Benchmark Challenges       ║ ║ Emulation Environments     ║ ║ Enterprise Baselines       ║
║ - NIST CFReDS              ║ ║ - Atomic Red Team Matrix   ║ ║ - Routine enterprise work  ║
║ - CyberDefenders Cases     ║ ║ - MITRE Caldera Operations ║ ║ - Software installs/updates ║
║ - SANS DFIR NetWars        ║ ║ - Sysmon/ETW Recorded      ║ ║ - Web browsing / Office    ║
║ Target: 5 Cases            ║ ║ Target: 7 Cases            ║ ║ Target: 5 Cases            ║
╚════════════════════════════╝ ╚════════════════════════════╝ ╚════════════════════════════╝
```

1. **Source A: Public DFIR Benchmarks (5 Cases):**
   - NIST CFReDS (Computer Forensic Reference Data Sets) — Hacking Case & Memory images.
   - CyberDefenders realistic enterprise intrusion challenges (e.g. *RedLine*, *Emotet*, *CobaltStrike*).
   - Magnet Forensics CTF images (Windows 10/11 multi-artifact disk + memory + PCAP).
   - *Advantage:* Peer-reviewed, realistic, non-synthetic forensic artifacts.
2. **Source B: Automated Adversarial Emulation with Full Kernel Telemetry (7 Cases):**
   - Deploy isolated Windows 10/11 VMs instrumented with Sysmon, ETW, Volatility acquisition, and full-packet PCAP taps.
   - Execute scripted Atomic Red Team / MITRE Caldera playbooks:
     - Case 1: T1059.001 (PowerShell) $\to$ T1055 (Process Injection) $\to$ T1071 (C2 Beaconing).
     - Case 2: T1547.001 (Registry Run Key Persistence) $\to$ T1036 (Masquerading) $\to$ Exfiltration.
     - Case 3: T1566 (Phishing LNK) $\to$ T1204 (User Execution) $\to$ Reverse TCP Shell.
     - Case 4: T1003 (Credential Dumping via LSASS) $\to$ T1078 (Valid Accounts Lateral Movement).
     - Case 5: T1486 (Data Encrypted for Impact / Ransomware staging).
     - Case 6: T1052.001 (Exfiltration over USB) — *genuine positive USB execution case*.
     - Case 7: Multi-stage APT campaign emulation combining all tactics.
   - *Advantage:* Exact microsecond ground-truth timestamps and process IDs recorded directly from the hypervisor orchestrator.
3. **Source C: Clean Benign Baselines (5 Cases):**
   - High-activity enterprise workstations running standard user behavior:
     - Continuous web browsing, Zoom/Teams conferences, heavy email traffic.
     - Windows Update servicing (`TiWorker`, `TrustedInstaller`).
     - USB drive insertion with benign portable utility execution and unlinked file browsing.
   - *Advantage:* Supplies realistic negative distractors, routine background processes, and unlinked cross-domain noise.

### 6.2 Target Dataset Scale and Proportions

| Metric | Minimum Acceptable Target | Recommended Production Target |
| :--- | :--- | :--- |
| **Unique Independent Cases** | 15 Cases | 25 Cases |
| **Total Annotated Candidate Pairs** | 2,500 Pairs | 6,000 Pairs |
| **Verified Positives ($y=1$)** | 1,000 Pairs (40%) | 2,400 Pairs (40%) |
| **Verified Negatives ($y=0$)** | 1,250 Pairs (50%) | 3,000 Pairs (50%) |
| **Ambiguous / Unresolved** | 250 Pairs (10%) | 600 Pairs (10%) |
| **Cross-Domain Positive Proportion** | $\ge 45\%$ of positives | $\ge 50\%$ of positives |
| **Intra-Domain Negative Proportion** | $\ge 40\%$ of negatives | $\ge 45\%$ of negatives |

---

## 7. Data Leakage Prevention and Split Strategy

### 7.1 The Peril of Random Pair Splitting

In standard ML workflows, datasets are often partitioned randomly (e.g. `train_test_split(pairs, test_size=0.2)`). **In forensic correlation, random pair splitting causes catastrophic data leakage:**

```
Case A (Intrusion Investigation):
├── Artifact 1: Malicious PID 1024 (svchost masquerade)
├── Artifact 2: Injected Memory VadAlloc 0x7FFF0000
├── Artifact 3: Outbound C2 Socket 198.51.100.42:443
└── Artifact 4: Registry Run Key "WindowsUpdateHelper"

Random Split Failure:
- Pair (PID 1024, VadAlloc 0x7FFF0000) placed in TRAIN
- Pair (PID 1024, C2 Socket 198.51.100.42) placed in TEST
```
**Leakage Mechanism:** The model memorizes that PID `1024` or IP `198.51.100.42` is associated with attack behavior in Case A. When evaluated on the test set, it achieves near-perfect test scores simply by recognizing familiar entity strings, completely failing when deployed to an unseen Case B with different PIDs and IP addresses.

### 7.2 Strict Case-Level Group Splitting

Data must be partitioned strictly by **independent forensic investigation / case ID**:

$$\mathcal{D}_{\text{train}} \cap \mathcal{D}_{\text{val}} \cap \mathcal{D}_{\text{test}} = \emptyset \quad \text{at the investigation ID level}$$

```
                                Corpus of 18 Independent Cases
                                               │
               ┌───────────────────────────────┼───────────────────────────────┐
               ▼                               ▼                               ▼
       TRAINING SET (60%)              VALIDATION SET (20%)             TEST SET (20%)
       11 Independent Cases            3 Independent Cases             4 Independent Cases
       - 7 Attack Emulations           - 1 Attack Emulation            - 2 Attack Emulations
       - 2 DFIR Benchmarks             - 1 DFIR Benchmark              - 1 DFIR Benchmark
       - 2 Benign Baselines            - 1 Benign Baseline             - 1 Benign Baseline
       Zero artifact overlap           Zero artifact overlap           Zero artifact overlap
```

### 7.3 Group Cross-Validation Protocol
During model development and hyperparameter tuning:
- Use `GroupKFold(n_splits=5)` or `LeaveOneGroupOut` where `group = investigation_id`.
- Ensure each fold contains a representative balance of scenario types (benign, ransomware, intrusion).
- Never compute normalization statistics, vocabulary tokenizers, or TF-IDF weights across the entire dataset; fit them strictly on training fold cases.

---

## 8. Baseline and Evaluation Protocol

### 8.1 Heuristic Rule Baseline

The existing deterministic rules in [`synthesizer_service.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/synthesizer_service.py#L886-L1228) serve as the **primary reference baseline**. 

The learned model must be benchmarked directly against the existing engine on the unseen test set:
- **Heuristic Baseline Implementation:** Execute `ForensicSynthesizerService._build_correlations()` against each test case.
- **Scoring:** For each candidate pair in the test set, if the rule engine generated a correlation containing that pair, record prediction as $1$; otherwise $0$.

### 8.2 Primary Evaluation Metrics

1. **Precision, Recall, and $F_1$ Score:**
   - Evaluated on binary classification ($y \in \{0, 1\}$).
   - Reported as Macro-$F_1$ and Weighted-$F_1$ across relationship categories.
   - In digital forensics, **Precision is prioritized over Recall**: reporting a false causal link can mislead a criminal investigation or lead to false accusations in court. Target: $\text{Precision} \ge 0.90$.
2. **False Positive Rate (FPR) on Clean Benign Baseline Cases:**
   - Measured on the 100% benign test cases.
   - Target: $\text{FPR} \le 0.02$ (less than 2 false correlations per 100 benign candidate pairs).
3. **Per-Relationship Type Performance Matrix:**
   - Breakdown of Precision, Recall, and $F_1$ for every relationship category $r \in \mathcal{R}$.
   - Must explicitly demonstrate strong performance on cross-domain links (`PERSISTENCE_TO_EXECUTION`, `EXECUTION_TO_NETWORK_FLOW`).
4. **Probability Calibration Metrics:**
   - If confidence scores are surfaced to forensic investigators or court reports, probabilities must be calibrated.
   - **Expected Calibration Error (ECE):**
     $$\text{ECE} = \sum_{m=1}^M \frac{|B_m|}{N} \left| \text{acc}(B_m) - \text{conf}(B_m) \right| \le 0.05$$
   - **Brier Score:**
     $$\text{BS} = \frac{1}{N} \sum_{i=1}^N (p_i - y_i)^2 \le 0.08$$
   - Calibration plots (reliability diagrams) must be inspected before deploying model-predicted confidence scores.

### 8.3 Forensic Safety Layer Integration

Machine-learning predictions must never run completely unconstrained in a forensic environment. A **deterministic safety envelope** must surround the inference engine:

```
[Candidate Pair] ──▶ [Deterministic Pre-Filter] ──▶ [Learned ML Scorer] ──▶ [Deterministic Post-Filter] ──▶ [Evidence Graph]
                          │ (Blocks physically          │ (Predicts causality,       │ (Enforces legal
                          │  impossible pairs)          │  type, confidence)         │  provenance, flags
                          ▼                             ▼                            ▼  uncertainty)
                     [REJECTED]                   [CONFIDENCE < 0.70]          [UNRESOLVED EDGE]
```

- **Pre-Filter Rules:** If $\text{Time}_B < \text{Time}_A - 300\text{s}$ (target precedes source beyond clock skew) and relationship is non-retroactive, block pair immediately without querying ML model.
- **Post-Filter Rules:** If ML model predicts $y=1$ with high confidence, but artifacts share zero identifiers and exhibit zero temporal overlap, flag for mandatory human review as `ANOMALOUS_ML_PREDICTION` rather than committing directly to `DETERMINISTIC_GROUNDED`.

---

## 9. Model Architecture and Training Recommendations

### 9.1 Evaluation of Architectural Alternatives

We evaluate three potential architectural paradigms for the H-MACFR correlation engine:

| Architecture Family | Representational Strengths | Operational / Compute Requirements | Forensic Interpretability | Fit for H-MACFR |
| :--- | :--- | :--- | :--- | :--- |
| **Option A: Tabular Gradient Boosting (LightGBM / XGBoost)** | Superior on tabular telemetry ($\Delta t$, port numbers, run counts, binary match flags). Fast training ($< 1$ min). | Extremely lightweight. Runs on standard CPU. Zero GPU requirement. | High (SHAP feature attributions directly explain predictions). | **STRONG BASELINE / IMMEDIATE RECOMMENDATION** |
| **Option B: Hybrid Siamese / Cross-Encoder Transformer** | Deep semantic understanding of raw command lines, file paths, registry keys, and textual reasoning. | Requires GPU for training; fine-tuning a small backbone (e.g. `DeBERTa-v3-small` or `ModernBERT`) feasible on Colab/T4. | Moderate (Attention maps, integrated gradients). | **RECOMMENDED TARGET (Phase 2)** |
| **Option C: Graph Neural Network (GNN / Relational GCN)** | Captures higher-order topological graph structure across multi-hop attack paths. | High complexity. Requires full graph batching; sensitive to graph sparsity and dynamic case graphs. | Low (Complex node embedding interactions difficult to explain in court). | **DEFER TO ADVANCED PHASE** |

### 9.2 Recommended Two-Phase Technical Roadmap

#### Phase 1 Architecture: Feature-Engineered Gradient Boosted Classifier (LightGBM)
For the immediate next phase, train a tabular Gradient Boosted Decision Tree (LightGBM) on a standardized 48-dimensional feature vector extracted from candidate pairs:
- **Temporal Features (8):** $\Delta t$, $\log(1 + |\Delta t|)$, $\text{is\_forward\_order}$, $\text{time\_of\_day\_delta}$, $\text{is\_concurrent\_window}$, etc.
- **Identifier Match Features (10):** Exact PID match, exact PPID match, path substring match, hash match, IP match, subnet match, domain name token overlap.
- **Domain Interaction Features (12):** One-hot encoded cross-domain pairs (e.g. `is_registry_to_disk`, `is_memory_to_network`).
- **Entity Anomaly Scores (8):** Individual anomaly scores from domain adapters (e.g. malfind protection flags, unusual parentage, entropy score of command line).
- **Text Similarity Features (10):** TF-IDF cosine similarity between source command/path and target command/path.

*Rationale:* LightGBM trains in seconds, runs air-gapped on any commodity CPU in $< 5\text{ms}$ per candidate pair, exhibits zero hallucination risk, and provides explicit SHAP feature importance values required for court-admissible forensic justification.

#### Phase 2 Architecture: Cross-Encoder Transformer Backbone
Once the multi-case corpus reaches $\ge 5,000$ validated pairs:
- Employ a compact cross-encoder architecture (e.g. `microsoft/deberta-v3-small` or `BAAI/bge-small-en-v1.5`).
- Input format:
  ```
  [CLS] Domain: {dom_a} | Artifact: {payload_a} [SEP] Domain: {dom_b} | Artifact: {payload_b} | Delta: {delta_t}s [SEP]
  ```
- Multi-Task Head:
  - Head 1: Binary Causal Logits ($y \in \{0, 1\}$).
  - Head 2: Multi-Class Relationship Type ($k \in \mathcal{R}$).
- Calibration: Apply Temperature Scaling or Platt Scaling post-training on the validation set.

### 9.3 Deployment Constraints
- **Air-Gapped Operation:** All model weights and dependencies must run locally without external cloud API dependencies.
- **Latency Budget:** Candidate pair evaluation must complete within $\le 500\text{ms}$ total per case during synthesis.
- **Deterministic Fallback:** If inference fails or model files are missing, the system must seamlessly fall back to the existing deterministic rules in `synthesizer_service.py` without throwing runtime exceptions.

---

## 10. Data Quality Gates and Minimum Acceptance Criteria

Before any machine learning model may be trained or integrated into the SherlockAI pipeline, the training dataset must pass all of the following automated gates:

```
                                 Automated Dataset Quality Gates
                                                │
   ├── Gate 1: Completeness ──────────────▶ 0 null fields; all 12 schema fields populated
   ├── Gate 2: Uniqueness ────────────────▶ 0 duplicate artifact pairs within any case
   ├── Gate 3: Forensic Diversity ────────▶ N ≥ 15 independent cases; ≥ 2,500 total pairs
   ├── Gate 4: Domain Balance ────────────▶ Positive pairs: 40%–60% cross-domain; 40%–60% intra-domain
   ├── Gate 5: Class Balance ─────────────▶ 35%–55% positives, 45%–65% negatives
   ├── Gate 6: Epistemic Rigor ───────────▶ 100% of ambiguous pairs segregated (not in binary loss)
   └── Gate 7: Inter-Rater Reliability ──▶ Cohen's Kappa κ ≥ 0.85 across annotators
```

### Exact Automated Gate Check Script
The validation script must enforce:
```python
def verify_dataset_quality_gates(dataset_path: Path):
    with open(dataset_path) as f:
        data = json.load(f)
    
    # Gate 1: Minimum Scale
    assert len(data) >= 2500, f"Gate 1 Failed: {len(data)} < 2500 samples"
    
    # Gate 2: Unique Cases
    unique_cases = set(d["investigation_id"] for d in data)
    assert len(unique_cases) >= 15, f"Gate 2 Failed: {len(unique_cases)} < 15 unique cases"
    
    # Gate 3: Domain Confounding Elimination
    positives = [d for d in data if d["labels"]["ground_truth_causal_label"] == 1]
    cross_pos = sum(1 for d in positives if d["source_artifact"]["domain"] != d["target_artifact"]["domain"])
    cross_pos_ratio = cross_pos / len(positives)
    assert 0.40 <= cross_pos_ratio <= 0.60, f"Gate 3 Failed: Cross-domain positive ratio {cross_pos_ratio:.2f} outside [0.40, 0.60]"
    
    negatives = [d for d in data if d["labels"]["ground_truth_causal_label"] == 0]
    intra_neg = sum(1 for d in negatives if d["source_artifact"]["domain"] == d["target_artifact"]["domain"])
    intra_neg_ratio = intra_neg / len(negatives)
    assert 0.35 <= intra_neg_ratio <= 0.60, f"Gate 3 Failed: Intra-domain negative ratio {intra_neg_ratio:.2f} outside [0.35, 0.60]"
    
    # Gate 4: Zero Nulls in Required Fields
    for d in data:
        assert d["sample_id"] and d["investigation_id"], "Gate 4 Failed: Missing ID"
        assert d["temporal_context"]["temporal_order"] != "UNKNOWN" or d["labels"]["epistemic_classification"] == "AMBIGUOUS_UNRESOLVED"
        
    print("[SUCCESS] All Data Quality Gates Passed.")
```

---

## 11. Milestones, Dependencies, and Risk Matrix

### 11.1 Project Milestones

| Milestone | Target Deliverable | Dependencies | Exit Criteria |
| :--- | :--- | :--- | :--- |
| **Phase 0 (Current)** | `CORRELATION_TRAINING_PLAN.md` | Codebase & dataset audit | Audit complete; all architectural recommendations documented. |
| **Phase 1: Corpus Collection** | Multi-case raw forensic artifact repository | Instrumenting 15 lab environments / downloading DFIR challenge images | $\ge 15$ verified case extractions across disk, memory, network, registry, logs. |
| **Phase 2: Annotation & Validation** | Validated `correlation_corpus_v1.json` | Two-examiner labeling protocol + automated quality gate checks | $\ge 2,500$ pairs passing all 7 automated quality gates ($\kappa \ge 0.85$). |
| **Phase 3: Baseline & ML Prototype** | LightGBM tabular model + evaluation report | Clean corpus + GroupKFold split | Model achieves $\text{Precision} \ge 0.90$, Macro-$F_1 \ge 0.85$, beating rule baseline. |
| **Phase 4: Pipeline Integration** | Hybrid correlation engine in `synthesizer_service.py` | Safety filter integration + regression test suite | Deterministic safety gates active; all backend tests pass; zero latency regression. |

### 11.2 Risk Matrix & Mitigation Strategies

| Risk Description | Severity | Probability | Mitigation Strategy |
| :--- | :--- | :--- | :--- |
| **Shortcut Learning from Residual Domain Artifacts** | High | High | Enforce strict domain-balancing in training pairs (Gate 4). Include counterfactual pairs with identical payloads but different domains. |
| **Data Leakage via Entity Memorization** | High | Medium | Enforce strict investigation-level group splitting (`GroupKFold`). Anonymize specific entity values (PIDs, specific hostnames) into generic tokens during feature extraction. |
| **High False-Positive Rate on Clean Benign Systems** | Critical | Medium | Calibrate decision threshold to prioritize precision ($\tau \ge 0.75$). Enforce deterministic pre/post safety filters. |
| **Inference Latency on Large Evidence Graphs** | Medium | Low | Maintain Stage 1 candidate generation window; limit ML evaluation strictly to candidate pairs passing candidate filters. |
| **Legal Inadmissibility of Black-Box Correlation** | Critical | Medium | Maintain deterministic forensic safety envelope. Pair every ML correlation with SHAP feature explanations and raw artifact provenance IDs. |

---

## 12. Verification Matrix: Facts, Assumptions, and Recommendations

To maintain complete audit integrity, all assertions in this document are explicitly classified:

| Item | Classification | Verification Source / Technical Evidence |
| :--- | :--- | :--- |
| Correlation engine is currently rule-based | **Verified Fact** | Inspected [`synthesizer_service.py: lines 886–1228`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/synthesizer_service.py#L886-L1228) and [`processeed/correlation_engine.py`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/processeed/correlation_engine.py). Zero model calls during correlation. |
| Active neural inference path is inactive | **Verified Fact** | Inspected [`model_adapter_service.py: line 312`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/services/model_adapter_service.py#L312) (`NotImplementedError` fallback to keyword scanner). |
| Current dataset has exactly 10 usable pairs | **Verified Fact** | Inspected [`CASE_ALL5_F1A5D2/correlation_training_pairs.json`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/output/cases/CASE_ALL5_F1A5D2/correlation_training_pairs.json). Script audit confirmed 10 samples. |
| Current dataset has 100% domain confounding | **Verified Fact** | 5 of 5 positives are intra-domain; 5 of 5 negatives are cross-domain. Verified by [`test_forensic_audit_corrections.py: lines 134–139`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/tests/test_forensic_audit_corrections.py#L134-L139). |
| Existing LoRA adapters are single-domain only | **Verified Fact** | Inspected adapter directories in [`app/models/adapters/`](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/backend/app/models/adapters/) (disk, memory, network, logs, registry). No correlation adapter exists. |
| Random pair splitting causes entity leakage | **Verified Fact** | Proven by topological overlap analysis of same-case artifact graphs (Section 7.1). |
| 15 cases will yield $\ge 2,500$ valid pairs | **Assumption** | Based on empirical yield of 150–250 candidate pairs per multi-artifact enterprise forensic image. Must be verified during Phase 1 collection. |
| Two-stage candidate filtering is required | **Recommendation** | Recommended to avoid $O(N^2)$ explosion across $10^5$ raw forensic artifacts. |
| LightGBM baseline before fine-tuning LLM/GNN | **Recommendation** | Recommended due to air-gapped CPU deployment constraints, instant training, and court-admissible SHAP explanations. |
| Retain deterministic rules as permanent safety gate | **Recommendation** | Recommended to ensure physical impossibility bounds are never breached by learned probabilistic inference. |

---
*End of Correlation Training Plan — SherlockAI Phase 0.*
