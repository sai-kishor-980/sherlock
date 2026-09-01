# HMACFR Backend API Documentation

The **HMACFR** (Hierarchical Multi-Agent Cognitive Forensic Reconstruction Framework) REST API provides endpoints for Case Management, Evidence Ingestion, Chain of Custody Auditing, Cryptographic Preservation, AES-256-GCM Encryption, and Multi-Factor Verification.

---

## Core API Endpoints

### 1. Case Management (`/api/v1/cases`)
- `POST /api/v1/cases/`: Create a new forensic investigation case.
- `GET /api/v1/cases/`: List all cases.
- `GET /api/v1/cases/{case_id}`: Retrieve case details and linked evidence list.
- `PUT /api/v1/cases/{case_id}`: Update case priority, status, or description.

### 2. Evidence Upload & Ingestion (`/api/v1/upload`)
- `POST /api/v1/upload/`: Ingest evidence file, generate SHA-256 hash & HMAC signature, and store in `EvidenceVault/<case_id>/<category>/`.

### 3. Evidence Management (`/api/v1/evidence`)
- `GET /api/v1/evidence/case/{case_id}`: List all evidence artifacts for a specific case.
- `GET /api/v1/evidence/{evidence_id}`: Retrieve detailed metadata for a single evidence item.

### 4. Integrity & Verification (`/api/v1/verification`)
- `GET /api/v1/verification/audit/{evidence_id}`: Multi-factor integrity verification (Hash + HMAC + ReadOnly + Size).
- `GET /api/v1/verification/audit-case/{case_id}`: Batch integrity audit across an entire case.
- `POST /api/v1/verification/lock/{evidence_id}`: Apply OS write-protection to evidence file.

### 5. Hashing Service (`/api/v1/hashing`)
- `POST /api/v1/hashing/bytes`: Compute SHA256 / SHA512 / MD5 / BLAKE2b digest for data string.
- `GET /api/v1/hashing/evidence/{evidence_id}`: Calculate digest for stored file on disk.

### 6. AES-256-GCM Encryption (`/api/v1/encryption`)
- `POST /api/v1/encryption/encrypt/{evidence_id}`: Encrypt evidence payload at rest using AES-256-GCM.

### 7. Chain of Custody (`/api/v1/custody`)
- `GET /api/v1/custody/evidence/{evidence_id}`: Retrieve complete forensic audit trail logs for an evidence item.
