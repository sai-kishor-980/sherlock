from typing import Optional
from fastapi import APIRouter, UploadFile, File, Form, Depends, status, HTTPException
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.db.schemas import EvidenceResponse
from app.services.upload_service import UploadService
from app.services.rbac_service import RBACService
from app.services.audit_service import AuditService
from app.api.dependencies import get_current_user
from app.db.models.user import User
from app.utils.validation_utils import validate_upload_payload
from app.core.logger import log_app_event

router = APIRouter()

@router.post("/", response_model=EvidenceResponse, status_code=status.HTTP_201_CREATED)
async def upload_evidence(
    case_id: str = Form(..., description="ID of the associated investigation case"),
    investigator: str = Form(..., description="Name of the investigator uploading the evidence"),
    file: UploadFile = File(..., description="The evidence file binary"),
    category: Optional[str] = Form(None, description="Category of evidence e.g. Audio, Video, Document"),
    type: Optional[str] = Form(None, description="Type of evidence e.g. Media, Forensic Image"),
    description: Optional[str] = Form(None, description="Detailed description or notes"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Validate request payload, verify case-level upload authorization, store file, hash,
    and record initial chain of custody.
    """
    # Verify case-level authorization
    if not RBACService.check_case_access(db, current_user, case_id, permission="evidence:upload"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission Denied: You do not have upload permission on Case '{case_id}'."
        )

    # Check if Evidence Vault is LOCKED
    from app.db.models.case import Case
    case_obj = db.query(Case).filter(Case.case_id == case_id).first()
    if case_obj and getattr(case_obj, "vault_status", "OPEN") == "LOCKED":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot upload evidence: Evidence Vault is LOCKED. Unlock vault first to ingest new items."
        )

    content = await file.read() if file else None

    # Step 1: Execute file validation checklist (File exists, size > 0, required fields, allowed extension)
    validate_upload_payload(
        file=file,
        case_id=case_id,
        investigator=investigator,
        content_bytes=content
    )

    # Step 2: Verify Case ID existence & Process Upload
    evidence_record = UploadService.process_file_upload(
        db=db,
        case_id=case_id,
        investigator=investigator,
        original_filename=file.filename,
        content=content,
        category=category,
        evidence_type=type,
        description=description
    )

    # Record audit event
    try:
        AuditService.record_event(
            db=db,
            action="EVIDENCE_UPLOAD",
            target_resource="evidence",
            user_id=current_user.user_id,
            username=current_user.username,
            resource_id=evidence_record.evidence_id,
            case_id=case_id,
            details=f"Evidence '{file.filename}' uploaded to Case '{case_id}' by {current_user.username}."
        )
    except Exception as e:
        log_app_event(f"Audit event recording skipped: {e}")

    return evidence_record
