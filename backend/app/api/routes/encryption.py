"""
Encryption API Router for HMACFR.

Exposes REST API endpoints for AES-256-GCM symmetric payload encryption and decryption.
Enforces case-level RBAC authorization.
"""

from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.db.models import Evidence
from app.services.encryption_service import EvidenceEncryptionService
from app.services.rbac_service import RBACService
from app.services.audit_service import AuditService
from app.api.dependencies import get_current_user
from app.db.repositories import EvidenceRepository
from app.db.models.user import User
from app.core.logger import log_app_event

router = APIRouter()


@router.post("/encrypt/{evidence_id}", summary="Encrypt stored evidence file at rest")
def encrypt_evidence_endpoint(
    evidence_id: str,
    secret_key: str = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Encrypts stored evidence payload using AES-256-GCM authenticated encryption.
    Requires evidence:preserve permission on the associated case.
    """
    has_access, case_id = RBACService.check_evidence_access(db, current_user, evidence_id, permission="evidence:preserve")
    if case_id is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence '{evidence_id}' not found"
        )
    if not has_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission Denied: You do not have preservation permission on Case '{case_id}'."
        )

    evidence = EvidenceRepository.get_by_id(db, evidence_id)
    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Evidence '{evidence_id}' not found")

    encrypted_path = evidence.storage_path + ".enc"
    success = EvidenceEncryptionService.encrypt_file(evidence.storage_path, encrypted_path, secret_key)
    if not success:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Encryption failed")

    EvidenceRepository.update_status(db, evidence_id, "Encrypted")

    try:
        AuditService.record_event(
            db=db,
            action="EVIDENCE_ENCRYPT",
            target_resource="evidence",
            user_id=current_user.user_id,
            username=current_user.username,
            resource_id=evidence_id,
            case_id=case_id,
            details=f"Evidence '{evidence_id}' encrypted at rest by {current_user.username}."
        )
    except Exception as e:
        log_app_event(f"Audit event recording skipped: {e}")

    return {
        "evidence_id": evidence_id,
        "status": "Encrypted",
        "encrypted_path": encrypted_path
    }
