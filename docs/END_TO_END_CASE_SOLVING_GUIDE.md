# 🧭 Investigator Operator Manual — End-to-End Case Solving Guide

**Platform**: Agentic Sherlock AI (H-MACFR)  
**Target Audience**: Digital Forensics Examiners, Incident Responders, Law Enforcement Investigators

---

## 1. System Initialization & Startup

### Step 1.1: Launch the Backend Server
Open your terminal in the backend directory and launch the FastAPI server:
```powershell
cd c:\Users\saiki\Desktop\BTECH\ForensicAI\project\sherf\backend
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```
*Verification*: Open your browser and navigate to `http://127.0.0.1:8000/docs` to verify that the Swagger UI is responding with status 200.

### Step 1.2: Connect the Google Colab GPU Bridge (Optional for Cloud GPU Acceleration)
1. Open [docs/SherlockAI_Colab_Inference_Bridge.ipynb](file:///c:/Users/saiki/Desktop/BTECH/ForensicAI/project/sherf/docs/SherlockAI_Colab_Inference_Bridge.ipynb) in Google Colab.
2. Select **Runtime → Change runtime type → T4 GPU → Save**.
3. Run the notebook cells to start the Cloudflare tunnel.
4. Copy the generated `https://<unique-id>.trycloudflare.com` URL into `backend/.env`:
   ```ini
   COLAB_GPU_INFERENCE_URL=https://<your-subdomain>.trycloudflare.com
   ```
*(Note: If no GPU bridge is running, the system will automatically utilize the local deterministic forensic evaluator with zero disruption).*

---

## 2. Authentication & Access Control

1. Navigate to `http://127.0.0.1:8000/` or open `frontend/index.html`.
2. Click **Sign In** on the top navigation bar.
3. Use the default seeded credentials:
   - **Lead Investigator / Administrator**:
     - **Username**: `admin`
     - **Password**: `Admin@123`
   - **Forensic Investigator**:
     - **Username**: `investigator1`
     - **Password**: `Password@123`
4. The system validates the JWT signature and presents the active **Forensic Investigation Workspace**.

---

## 3. Creating an Investigation Case

1. In the sidebar, select **New Case** (or click **+ Initialize Investigation** on the dashboard).
2. Complete the Case Registration Form:
   - **Case Name**: e.g., `Operation DarkBeacon Incident`
   - **Target Host / Scope**: e.g., `Workstation-HR-04 (192.168.1.50)`
   - **Priority**: `Critical`, `High`, `Medium`, or `Low`
   - **Expected Evidence Items**: e.g., `2` (PCAP + Memory Dump)
   - **Case Description**: Detailed context regarding the security alert or breach hypothesis.
3. Click **Initialize Case**.
4. The backend initializes the case directory structure:
   ```
   backend/evidence_vault/<CASE_ID>/
   backend/output/cases/<CASE_ID>/
   ```
   The case status is set to `Active`, and the Evidence Vault is initialized in the `OPEN` state.

---

## 4. Evidence Ingestion (+ Upload More Evidence)

Digital evidence can be ingested across 5 core forensic categories:
- **Network**: `.pcap`, `.pcapng` packet captures.
- **Memory**: `.raw`, `.dmp`, `.mem` RAM volatile images.
- **Disk**: `.e01`, `.dd`, `.raw`, `.img`, `$MFT`, `.pf` (Prefetch).
- **Logs**: `.evtx` Windows Security / Sysmon event logs.
- **Registry**: `SYSTEM`, `SOFTWARE`, `SAM`, `NTUSER.DAT` offline hives.

### Uploading Evidence:
1. Select the **Evidence Vault** section.
2. Drag and drop your evidence file or click to browse.
3. Select the appropriate **Evidence Category** and **Type**.
4. Click **Seal & Deposit to Vault**.
5. **Cryptographic Verification**:
   - The platform streams the binary, computes the **SHA-256** checksum and **HMAC-SHA256** digital signature.
   - Logs the transaction into `logs/audit_ledger.jsonl`.
6. **Continuous Ingestion**: While the vault is `OPEN`, investigators can click **`+ Upload More`** at any time to append additional forensic artifacts as the triage progresses.

---

## 5. Freezing the Evidence Pool (Vault Locking)

To satisfy **ISO/IEC 27037** courtroom preservation standards before running extraction:
1. Click **Lock Evidence Vault**.
2. The vault transitions to `LOCKED`:
   - All subsequent upload requests are rejected (`400 Bad Request`).
   - File deletion requests are blocked.
   - Evidence files receive read-only write-blocking flags.
3. *(Optional)* If new evidence is discovered later, the Lead Investigator can click **Unlock Vault**, which prompts for a mandatory audited unlock justification.

---

## 6. Triggering Real Forensic Artifact Extraction

1. Navigate to the **Artifact Extraction** tab.
2. Click **Run Artifact Extraction**.
3. The central `PluginManager` executes the appropriate domain parsers:
   - **PCAP**: Executes Scapy stream dissectors, carving HTTP sessions, DNS queries, and network connection matrices (~25–35 seconds on real captures).
   - **Memory**: Runs Volatility 3 plugins for hidden processes, injected memory pages, and handles.
   - **Event Logs**: Parses XML structures for Sysmon and PowerShell activity.
   - **Disk**: Parses NTFS MFT records, LNK shortcuts, and prefetch execution counts.
4. **Normalized Contracts**: Parsed data is written directly to:
   ```
   output/cases/<CASE_ID>/extracted_artifacts/<domain>/<contract>.json
   ```
   A `supervisor_manifest.json` file is produced certifying extraction completeness.

---

## 7. Running Multi-Agent Cognitive Analysis

1. Navigate to the **Multi-Agent Analysis** section.
2. The 5 specialized agents are displayed on the dispatch board:
   - **Pranay** (Network Agent)
   - **Bharath** (Memory Agent)
   - **Aswith** (Disk Agent)
   - **Sanhith** (Log Agent)
   - **Kishor** (Registry Agent)
3. Click **Dispatch Multi-Agent Reasoning**.
4. The system queries the fine-tuned **Qwen2.5-7B LoRA** model (via the live Colab GPU tunnel):
   - Categorizes risk: `INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.
   - Assesses classification: `BENIGN`, `SUSPICIOUS`, or `MALICIOUS`.
   - Synthesizes detailed forensic reasoning explaining attack vectors and malicious intent.

---

## 8. Cross-Domain Attack Correlation & Graph Reconstruction

1. Once domain agents finish, the **Master Supervisor Agent** correlates findings:
   - Evaluates cross-domain entity overlaps (e.g., matching a DNS beacon IP `185.220.101.5` with injected code in `csrss.exe`).
   - Assigns epistemic classifications (`CAUSAL_DEPENDENCY`, `CORRELATIONAL_ASSOCIATION`).
2. Navigate to the **Knowledge Graph** tab:
   - Inspect interactive interactive nodes (`Process`, `IP`, `Domain`, `Technique`, `File`).
   - Trace the causal attack trajectory from initial access to persistence.

---

## 9. Structured Investigation State (SIS) & Reporting

1. **Review SIS State**:
   - The platform produces a comprehensive **Structured Investigation State (SIS)** JSON summarizing all confirmed facts, suspicious indicators, and gaps.
   - Human-in-the-loop review allows investigators to add investigator notes or accept/reject specific hypotheses.
2. **AI Case Assistant**:
   - Click **Chat with AI** to ask grounded natural language questions (e.g. *"What persistence mechanism was established?"* or *"List all external C2 IPs observed"*).
3. **Court-Ready Export**:
   - Click **Generate Court Report**.
   - Produces an exportable report including cryptographic hashes, chain of custody logs, MITRE ATT&CK mappings, and investigator sign-offs.
