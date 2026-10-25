# SherlockAI — Sprint 3 Readiness Assessment & Roadmap

**Date:** 2026-10-23  
**Status:** **CONDITIONAL GO FOR SPRINT 3**  
**Prerequisite Baseline:** All 6 defects identified in `SPRINT_2_INDEPENDENT_AUDIT.md` resolved; full test suite passing (**43/43 tests, 0 failures**).

---

## 1. Readiness Verdict & Executive Summary

The SherlockAI / H-MACFR platform is **READY** to proceed to Sprint 3 under strict engineering conditions:
* **Ready Subsystems**: Evidence vaulting, cryptographic hashing, SQLite chain of custody, STIX 2.1 vector ingestion into persistent ChromaDB, deterministic NetworkX evidence graph construction, finding deduplication, and forensic epistemic classification.
* **Prohibited Actions (Blocked until Prerequisites Met)**:
  1. **Do NOT train a machine learning correlation model** on the current 10-pair prototype dataset (`correlation_training_pairs.json`). It suffers from 100% domain confounding (all positives are intra-domain; all negatives are cross-domain).
  2. **Do NOT claim live LoRA neural execution locally** unless an active local quantized engine (e.g. `llama-cpp-python` / GGUF) or validated Colab GPU bridge is verified with an automated health check.
  3. **Do NOT upgrade uncorroborated hypotheses into malicious facts** in automated report narratives.

---

## 2. Sprint 3 Prioritized Work Breakdown

### Phase 1: Evidence Graph API & Dashboard Interoperability (Priority: HIGH)
* **Objective**: Expose the verified, deduplicated NetworkX evidence graph directly to the web and desktop UI.
* **Deliverables**:
  - Implement `GET /api/v1/cases/{case_id}/graph` endpoint in `backend/app/api/routes/cases.py`.
  - Return standardized JSON payload compatible with Cytoscape.js and D3.js.
  - Implement node filtering parameters (`?entity_type=process,finding`, `?min_confidence=0.80`).
  - Implement explicit visual edge styling based on nature:
    * `OBSERVED_FACT` $\rightarrow$ Solid black/blue directed arrow (Confidence 1.0).
    * `CORROBORATED_HYPOTHESIS` $\rightarrow$ Dashed amber directed arrow (Confidence $\le 0.85$).
    * `ATTACK_MAPPING` $\rightarrow$ Dotted purple directed arrow with disclaimer tooltip.
* **Acceptance Criteria**: Automated test verifying JSON response structure, HTTP status 200 on `CASE_ALL5_F1A5D2`, and graceful 404 on invalid case ID.

### Phase 2: GraphRAG Local Cognitive Synthesis Layer (Priority: HIGH)
* **Objective**: Ground the Supervisor LLM explanation layer in verified graph neighborhoods rather than generic hallucinated text.
* **Architecture**:
  ```
  Case Question / Prompt
         │
         ├──► 1. Query ChromaDB: Top-K MITRE Techniques (Semantic Vector Search)
         │
         ├──► 2. Query NetworkX: Subgraph Neighborhood (Source Evidence -> Artifact -> Finding)
         │
         └──► 3. Compose Structured Context:
                   - Grounded Physical Facts (Nodes with OBSERVED_FACT)
                   - Qualified Inferences (Edges with CORROBORATED_HYPOTHESIS)
                   - ATT&CK Classifications (Nodes with ATTACK_MAPPING)
                   │
                   ▼
       Local LLM / Forensic Explanation Agent (Strict Guardrails: No Unbacked Claims)
  ```
* **Acceptance Criteria**:
  - RAG prompt contains exact evidence IDs, SHA-256 digests, and PID citations.
  - LLM response passes deterministic regex assertion verifying it does not claim exfiltration when only `T1200` device registration is present.

### Phase 3: Defensible Cross-Domain Correlation Dataset Construction (Priority: MEDIUM)
* **Objective**: Replace the confounded 10-pair prototype with an authentic, multi-scenario forensic evaluation benchmark.
* **Required Dataset Schema**:
  - Minimum **50 balanced sample pairs** across at least 3 distinct intrusion scenarios (e.g., Cobalt Strike beaconing, USB ransomware staging, living-off-the-land script persistence).
  - True cross-domain positive pairs (e.g., Registry Run key `cmd.exe /c` $\leftrightarrow$ Prefetch `cmd.exe` execution; Memory injected PID $\leftrightarrow$ PCAP socket endpoint).
  - True intra-domain negative pairs (e.g., Benign PID-4 `System` vs Benign PID-584 `csrss.exe`; DNS query `google.com` vs IP flow to unrelated subnet).
* **Acceptance Criteria**: Inter-annotator agreement or deterministic ground truth verification from open-source forensic challenge images (e.g., NIST CFReDS, Volatility Foundation test images).

### Phase 4: True Local Quantized Inference or Formalized Air-Gap Boundary (Priority: MEDIUM)
* **Objective**: Eliminate the keyword-matching fallback illusion in `ModelAdapterService`.
* **Decision Path**:
  - **Option A (Air-Gapped Local Inference)**: Package a quantized 4-bit GGUF model (e.g., `Qwen2.5-Coder-7B-Instruct-Q4_K_M` via `llama-cpp-python`).
  - **Option B (Transparent Rule-Based Engine)**: Explicitly label `_run_forensic_evaluator` as a *"Deterministic Forensic Rule Engine"* in all documentation, UI tags, and API manifests, completely removing claims of active local neural adapter execution.
* **Acceptance Criteria**: Automated integration test proving that whichever path is selected, system output accurately reflects the actual engine provider without misleading labels.

---

## 3. Sprint 3 Acceptance Gates

| Gate # | Milestone Gate | Verification Mechanism | Status |
| :---: | :--- | :--- | :---: |
| **Gate 1** | **Audit Regression Integrity** | `pytest tests/test_forensic_audit_corrections.py` passes 6/6 tests. | **PASS** |
| **Gate 2** | **Full Suite Stability** | `pytest tests/` passes 43/43 tests without regressions. | **PASS** |
| **Gate 3** | **Zero Duplicate Findings** | `synthesize_case()` produces $\le 1$ finding per unique process PID. | **PASS** |
| **Gate 4** | **Calibrated Hypothesis Confidence** | All `CORROBORATED_HYPOTHESIS` edges enforce confidence $\le 0.85$. | **PASS** |
| **Gate 5** | **USB Exfiltration Separation** | USB device presence classified as `T1200`, not `T1052.001`. | **PASS** |
| **Gate 6** | **Network Tuple Fidelity** | PCAP correlations match actual packet capture endpoints. | **PASS** |

---

## 4. Single Highest-Priority Next Action

**Implement the Graph API route (`GET /api/v1/cases/{case_id}/graph`) and connect it to the case dashboard.**  
*Justification*: The evidence graph is now clean (76 nodes, 89 edges, deduplicated findings, calibrated hypotheses). Exposing this verified graph to investigators through the UI provides immediate operational value and establishes the data contract required for the Sprint 3 GraphRAG cognitive layer.
