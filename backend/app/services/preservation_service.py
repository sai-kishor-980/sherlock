"""
Evidence Preservation & Security Pipeline Service for HMACFR (Layer 1 Preservation Engine).

Processes evidence handed off by Person A (Upload/Storage/Metadata):
1. Receive input handoff payload (evidence_id, case_id, storage_path, category, status).
2. Computes SHA-256 cryptographic hash.
3. Computes MD5 cryptographic hash.
4. Performs AES-256-GCM symmetric payload encryption at rest.
5. Applies OS read-only file write-protection (stat.S_IREAD).
6. Deposits and isolates payload inside Evidence Vault structure (evidence_vault/readonly/<case_id>/).
7. Performs multi-factor integrity verification audit.
8. Updates database status to 'READY_FOR_PROCESSING', logs Chain of Custody entry, & publishes 'EVIDENCE_READY' event payload.
9. Evaluates if all case evidence items are preserved; after the final evidence, publishes 'CASE_UPLOAD_COMPLETE' event payload.
"""

from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from fastapi.responses import StreamingResponse

from app.db.repositories import CaseRepository, EvidenceRepository, CustodyRepository
from app.services.hashing_service import AdvancedHashingService
from app.services.encryption_service import EvidenceEncryptionService
from app.services.readonly_service import ReadOnlyProtectionService
from app.services.vault_service import EvidenceVaultService
from app.services.verification_service import AdvancedVerificationService
from app.services.streaming_service import StreamService
from app.core.logger import log_verification_event, log_custody_event, log_error_event, log_encryption_event
from app.services.event_publisher import EventPublisherService
from app.db.schemas import (
    EvidencePreserveInput,
    EvidenceReadyEventPayload,
    CaseUploadCompleteEventPayload,
    PreservationPipelineResult
)


class EvidencePreservationService:
    """
    Service executing Layer 1 Evidence Preservation responsibilities.
    """

    @classmethod
    def preserve_evidence_payload(
        cls, db: Session, payload: EvidencePreserveInput, secret_key: Optional[str] = None
    ) -> PreservationPipelineResult:
        evidence_id = payload.evidence_id
        case_id = payload.case_id

        # 1. Fetch DB record & Validate Storage Path
        record = EvidenceRepository.get_by_id(db, evidence_id)
        if not record:
            err_msg = f"Evidence with ID '{evidence_id}' not found in database."
            log_error_event(err_msg)
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=err_msg
            )

        # Resolve valid storage path: prefer DB record storage_path if file exists on disk
        if record.storage_path and Path(record.storage_path).is_file():
            storage_path = Path(record.storage_path).resolve()
        elif payload.storage_path and Path(payload.storage_path).is_file():
            storage_path = Path(payload.storage_path).resolve()
        else:
            storage_path = Path(payload.storage_path or record.storage_path or "").resolve()

        if not storage_path.is_file():
            err_msg = f"Evidence payload file missing at storage path: '{storage_path}'"
            log_error_event(err_msg)
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=err_msg
            )

        # STEP 1: SHA-256 Hash Computation
        sha256_digest = AdvancedHashingService.calculate_file_hash(storage_path, "sha256")
        log_custody_event(evidence_id, "SHA-256 Calculated", f"Digest: {sha256_digest}")

        # STEP 2: MD5 Hash Computation
        md5_digest = AdvancedHashingService.calculate_file_hash(storage_path, "md5")
        log_custody_event(evidence_id, "MD5 Calculated", f"Digest: {md5_digest}")

        # Generate HMAC-SHA256 signature
        content_bytes = storage_path.read_bytes()
        hmac_sig = AdvancedHashingService.calculate_hmac(content_bytes, secret_key)

        # STEP 3: AES-256-GCM Symmetric Payload Encryption at Rest
        encrypted_vault_dir = EvidenceVaultService.get_vault_root() / "encrypted" / case_id
        encrypted_vault_dir.mkdir(parents=True, exist_ok=True)
        enc_target_path = encrypted_vault_dir / f"{record.stored_filename}.enc"

        encryption_ok = EvidenceEncryptionService.encrypt_file(
            source_path=storage_path,
            dest_path=enc_target_path,
            secret_key=secret_key
        )
        if not encryption_ok:
            err_msg = f"AES-256 encryption failed for evidence payload '{evidence_id}'."
            log_error_event(err_msg)
            EvidenceVaultService.handle_preservation_failure(storage_path, case_id, err_msg)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=err_msg
            )
        log_encryption_event(record.stored_filename, "AES-256 Encrypted at Rest", "Success")

        # STEP 4 & 5: Read-Only Protection & Evidence Vault Storage Deposit
        target_vault_path = EvidenceVaultService.deposit_to_readonly_vault(
            source_path=storage_path,
            case_id=case_id,
            filename=record.stored_filename
        )
        readonly_ok = ReadOnlyProtectionService.check_readonly_status(target_vault_path)
        log_custody_event(evidence_id, "Vault Deposit & Read-Only Enforced", f"Vault Path: {target_vault_path} | ReadOnly: {readonly_ok}")

        # STEP 6: Multi-Factor Post-Preservation Integrity Verification
        current_vault_hash = AdvancedHashingService.calculate_file_hash(target_vault_path, "sha256")
        if current_vault_hash.lower() != sha256_digest.lower():
            err_msg = f"Post-preservation SHA-256 hash mismatch for evidence '{evidence_id}'."
            log_error_event(err_msg)
            EvidenceVaultService.quarantine_evidence(target_vault_path, err_msg)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=err_msg
            )
        log_verification_event(evidence_id, True, "Post-Preservation Integrity Audit Passed")

        # STEP 7: Update DB Record & Log Custody
        EvidenceRepository.update_preservation(
            db,
            evidence_id=record.evidence_id,
            storage_path=str(target_vault_path),
            file_hash=sha256_digest,
            hmac_signature=hmac_sig,
            status="READY_FOR_PROCESSING"
        )

        CustodyRepository.add_log(
            db,
            evidence_id=record.evidence_id,
            action="Preservation Complete",
            performed_by="Preservation Engine",
            remarks=f"SHA-256: {sha256_digest[:16]}... | MD5: {md5_digest} | AES-256 Encrypted | ReadOnly Enforced"
        )

        log_custody_event(evidence_id, "Preservation Complete", "Preservation Engine")

        category_val = record.category or payload.category or "Memory"

        # Publish EVIDENCE_READY Event Payload
        EventPublisherService.publish_evidence_ready(
            evidence_id=record.evidence_id,
            case_id=record.case_id,
            storage_path=str(target_vault_path),
            category=category_val,
            status="READY_FOR_PROCESSING"
        )

        ready_event = EvidenceReadyEventPayload(
            event="EVIDENCE_READY",
            evidence_id=record.evidence_id,
            case_id=record.case_id,
            storage_path=str(target_vault_path),
            category=category_val,
            status="READY_FOR_PROCESSING"
        )

        # STEP 8: Check if all evidence items for case are preserved -> Publish CASE_UPLOAD_COMPLETE
        case_complete_event: Optional[CaseUploadCompleteEventPayload] = None
        case_obj = CaseRepository.get_by_id(db, case_id)

        if case_obj and case_obj.status != "CASE_UPLOAD_COMPLETE":
            all_case_evidences = EvidenceRepository.get_by_case(db, case_id)
            preserved_count = sum(1 for ev in all_case_evidences if ev.status == "READY_FOR_PROCESSING")
            
            expected_count = case_obj.expected_evidence_count if (case_obj.expected_evidence_count and case_obj.expected_evidence_count > 0) else len(all_case_evidences)

            if preserved_count >= expected_count and expected_count > 0:
                CaseRepository.update_status(db, case_id, "CASE_UPLOAD_COMPLETE")

                EventPublisherService.publish_case_upload_complete(case_id=case_id)
                case_complete_event = CaseUploadCompleteEventPayload(
                    event="CASE_UPLOAD_COMPLETE",
                    case_id=case_id
                )
                log_custody_event(case_id, "CASE_UPLOAD_COMPLETE Published", f"Total Preserved Evidences: {preserved_count}/{expected_count}")

        return PreservationPipelineResult(
            evidence_ready_event=ready_event,
            case_complete_event=case_complete_event,
            sha256=sha256_digest,
            md5=md5_digest,
            readonly_protected=readonly_ok,
            encrypted=encryption_ok
        )

    @classmethod
    def preserve_case_evidence(
        cls, db: Session, case_id: str, secret_key: Optional[str] = None
    ) -> List[PreservationPipelineResult]:
        case_obj = CaseRepository.get_by_id(db, case_id)
        if not case_obj:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Case with ID '{case_id}' not found."
            )

        pending_evidences = EvidenceRepository.get_pending_by_case(db, case_id)

        results = []
        for ev in pending_evidences:
            input_payload = EvidencePreserveInput(
                evidence_id=ev.evidence_id,
                case_id=ev.case_id,
                storage_path=ev.storage_path,
                category=ev.category or "Memory",
                status=ev.status or "UPLOADED"
            )
            res = cls.preserve_evidence_payload(db=db, payload=input_payload, secret_key=secret_key)
            results.append(res)

        return results

    @classmethod
    def stream_preserved_evidence_to_plugin_manager(
        cls, db: Session, evidence_id: str
    ) -> StreamingResponse:
        record = EvidenceRepository.get_by_id(db, evidence_id)
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")

        file_path = Path(record.storage_path)
        if not file_path.is_file():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Preserved file missing")

        return StreamService.create_streaming_response(
            filepath=file_path,
            media_type="application/octet-stream",
            filename=record.original_filename
        )

