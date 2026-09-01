"""
Verification API Router for HMACFR.

Exposes REST API endpoints for multi-factor integrity audit and batch verification.
"""

from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.services.verification_service import AdvancedVerificationService
from app.services.readonly_service import ReadOnlyProtectionService
from app.db.repositories import EvidenceRepository

router = APIRouter()


@router.get("/audit/{evidence_id}", summary="Perform multi-factor integrity audit on evidence item")
def audit_evidence_endpoint(evidence_id: str, db: Session = Depends(get_db)):
    """
    Executes multi-factor integrity verification (Hash + HMAC + ReadOnly + File Size).
    """
    result = AdvancedVerificationService.verify_evidence_record(db, evidence_id)
    if result.get("status") == "not_found":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=result.get("details"))
    return result


@router.get("/audit-case/{case_id}", summary="Perform batch integrity audit on all evidence in a case")
def audit_case_endpoint(case_id: str, db: Session = Depends(get_db)):
    """
    Executes batch integrity verification on all evidence artifacts associated with a case.
    """
    return AdvancedVerificationService.audit_case_evidence(db, case_id)


@router.post("/lock/{evidence_id}", summary="Apply read-only protection to evidence file")
def lock_evidence_endpoint(evidence_id: str, db: Session = Depends(get_db)):
    """
    Applies OS write-protection (read-only bit) to evidence file.
    """
    evidence = EvidenceRepository.get_by_id(db, evidence_id)
    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")

    success = ReadOnlyProtectionService.apply_readonly_protection(evidence.storage_path)
    if success:
        EvidenceRepository.update_status(db, evidence_id, "ReadOnly")
    return {"evidence_id": evidence_id, "readonly_protected": success}
