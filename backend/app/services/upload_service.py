import os
import uuid
from typing import Optional
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from app.db.models import Evidence
from app.db.repositories import CaseRepository, EvidenceRepository, CustodyRepository
from app.services.hashing_service import calculate_sha256
from app.services.storage_service import StorageService
from app.core.security import generate_hmac
from app.core.logger import log_upload_event, log_error_event
from app.utils.file_utils import sanitize_filename, get_file_extension


class UploadService:
    @staticmethod
    def process_file_upload(
        db: Session,
        case_id: str,
        investigator: str,
        original_filename: str,
        content: bytes,
        category: Optional[str] = None,
        evidence_type: Optional[str] = None,
        description: Optional[str] = None
    ) -> Evidence:
        # 1. Validate Case Existence
        case_obj = CaseRepository.get_by_id(db, case_id)
        if not case_obj:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Case with ID '{case_id}' does not exist"
            )

        # 2. File Metadata Computation
        file_size = len(content)
        extension = get_file_extension(original_filename)
        cat = category or "General"

        # 3. Storage Management: Resolve duplicates & store in EvidenceVault/<case_id>/<category>/
        stored_filename, storage_path = StorageService.store_evidence_file(
            case_id=case_id,
            category=cat,
            original_filename=original_filename,
            content=content
        )

        # 4. Security & Cryptographic Hashing
        file_hash = calculate_sha256(content)
        hmac_sig = generate_hmac(content)

        # 5. Create Evidence Record
        evidence_record = Evidence(
            case_id=case_id,
            original_filename=original_filename,
            stored_filename=stored_filename,
            category=category or "General",
            type=evidence_type or extension.replace(".", "").upper(),
            extension=extension,
            file_size=file_size,
            storage_path=storage_path,
            status="Uploaded",
            file_hash=file_hash,
            hmac_signature=hmac_sig
        )
        saved_record = EvidenceRepository.create(db, evidence_record)

        # 6. Create Initial Chain of Custody Entry
        CustodyRepository.add_log(
            db,
            evidence_id=saved_record.evidence_id,
            action="Uploaded",
            performed_by=investigator,
            remarks=description if (description and description.strip()) else "Uploaded"
        )

        # 7. Log Event
        log_upload_event(case_id=case_id, filename=original_filename, status="Uploaded")

        return saved_record
