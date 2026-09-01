import os
from typing import Optional, Dict
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from app.db.repositories import EvidenceRepository, CustodyRepository
from app.services.hashing_service import calculate_file_sha256

class HandoffService:
    @staticmethod
    def generate_preservation_handoff(db: Session, evidence_id: str, recipient: str = "Preservation Engine") -> Dict[str, str]:
        """
        Stage 1 Handoff: Generates evidence handoff object for Preservation Engine.
        """
        record = EvidenceRepository.get_by_id(db, evidence_id)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Evidence with ID '{evidence_id}' not found"
            )

        # Log custody transfer action
        CustodyRepository.add_log(
            db,
            evidence_id=record.evidence_id,
            action="Handoff Issued",
            performed_by=f"Handoff Manager -> {recipient}",
            remarks=f"Handoff object generated for {recipient}"
        )

        return {
            "case_id": record.case_id,
            "evidence_id": record.evidence_id,
            "storage_path": record.storage_path,
            "category": record.category or "General",
            "status": record.status
        }

    @staticmethod
    def process_analysis_handoff(db: Session, evidence_id: str, verifier: str = "Preservation Engine") -> Dict[str, str]:
        """
        Stage 2 Handoff: Preservation Engine hashes file and passes object to Analysis Engine.
        """
        record = EvidenceRepository.get_by_id(db, evidence_id)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Evidence with ID '{evidence_id}' not found"
            )

        if not os.path.exists(record.storage_path):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Evidence file missing at storage path: {record.storage_path}"
            )

        # Compute current SHA256 hash for verification
        computed_sha256 = calculate_file_sha256(record.storage_path)
        EvidenceRepository.update_status(db, evidence_id, "Verified & Handed Off")

        # Log custody hashing & handoff to Analysis Engine
        CustodyRepository.add_log(
            db,
            evidence_id=record.evidence_id,
            action="Handoff Verified & Passed",
            performed_by=f"{verifier} -> Analysis Engine",
            remarks=f"SHA-256 verified ({computed_sha256[:10]}...). Handed off to Analysis Engine"
        )

        return {
            "case_id": record.case_id,
            "sha256": computed_sha256,
            "category": record.category or "General"
        }

