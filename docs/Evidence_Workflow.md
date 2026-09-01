# HMACFR Evidence Preservation Workflow

## Step 1: Case Creation & Vault Directory Provisioning
- Investigator creates a case (`POST /api/v1/cases/`).
- System provisions evidence vault folder structure: `EvidenceVault/<case_id>/<category>/`.

## Step 2: Evidence Upload & Hashing
- Ingestion validator verifies permitted file extensions.
- Compute SHA-256 hash digest and HMAC-SHA256 signature in real-time.
- Duplicate filenames are auto-incremented (`memory.raw` -> `memory_1.raw`).

## Step 3: Layer 1 Security & Read-Only Locking
- Move payload to `EvidenceVault/readonly/<case_id>/`.
- Revoke write permissions (`chmod 0444`, `stat.S_IREAD`).
- Optionally encrypt payload at rest using AES-256-GCM symmetric encryption.

## Step 4: Multi-Factor Verification & Audit Reporting
- Run automated integrity checks (`GET /api/v1/verification/audit/{evidence_id}`).
- If current hash != recorded hash, flag as `tampered`, quarantine payload, and log alert to `error.log`.
