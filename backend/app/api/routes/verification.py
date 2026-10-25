"""
Verification API Router for HMACFR.

Exposes REST API endpoints for multi-factor integrity audit and batch verification.
Enforces case-level RBAC authorization.
"""

from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.services.verification_service import AdvancedVerificationService
from app.services.readonly_service import ReadOnlyProtectionService
from app.services.rbac_service import RBACService
from app.services.audit_service import AuditService
from app.api.dependencies import get_current_user
from app.db.repositories import EvidenceRepository
from app.db.models.user import User
from app.core.logger import log_app_event

router = APIRouter()


@router.get("/audit/{evidence_id}", summary="Perform multi-factor integrity audit on evidence item")
def audit_evidence_endpoint(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Executes multi-factor integrity verification (Hash + HMAC + ReadOnly + File Size).
    Requires evidence:read permission on the associated case.
    """
    has_access, case_id = RBACService.check_evidence_access(db, current_user, evidence_id, permission="evidence:read")
    if case_id is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence with ID '{evidence_id}' not found"
        )
    if not has_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission Denied: You do not have access to evidence in Case '{case_id}'."
        )

    result = AdvancedVerificationService.verify_evidence_record(db, evidence_id)
    if result.get("status") == "not_found":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=result.get("details"))
    return result


@router.get("/audit-case/{case_id}", summary="Perform batch integrity audit on all evidence in a case")
def audit_case_endpoint(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Executes batch integrity verification on all evidence artifacts associated with a case.
    Requires evidence:read permission on the case.
    """
    if not RBACService.check_case_access(db, current_user, case_id, permission="evidence:read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission Denied: You do not have access to Case '{case_id}'."
        )

    return AdvancedVerificationService.audit_case_evidence(db, case_id)


@router.post("/lock/{evidence_id}", summary="Apply read-only protection to evidence file")
def lock_evidence_endpoint(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Applies OS write-protection (read-only bit) to evidence file.
    Requires evidence:preserve permission on the associated case.
    """
    has_access, case_id = RBACService.check_evidence_access(db, current_user, evidence_id, permission="evidence:preserve")
    if case_id is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence with ID '{evidence_id}' not found"
        )
    if not has_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission Denied: You do not have preservation permission on Case '{case_id}'."
        )

    evidence = EvidenceRepository.get_by_id(db, evidence_id)
    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")

    success = ReadOnlyProtectionService.apply_readonly_protection(evidence.storage_path)
    if success:
        EvidenceRepository.update_status(db, evidence_id, "ReadOnly")

    try:
        AuditService.record_event(
            db=db,
            action="EVIDENCE_LOCK_READONLY",
            target_resource="evidence",
            user_id=current_user.user_id,
            username=current_user.username,
            resource_id=evidence_id,
            case_id=case_id,
            details=f"Read-only protection locked for Evidence '{evidence_id}' by {current_user.username}."
        )
    except Exception as e:
        log_app_event(f"Audit event recording skipped: {e}")

    return {"evidence_id": evidence_id, "readonly_protected": success}
