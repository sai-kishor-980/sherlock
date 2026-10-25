from typing import List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.db.schemas import EvidenceResponse
from app.db.models import Evidence
from app.services.custody_service import CustodyService
from app.services.rbac_service import RBACService
from app.services.audit_service import AuditService
from app.api.dependencies import get_current_user
from app.db.models.user import User
from app.core.logger import log_app_event

router = APIRouter()

@router.get("/", response_model=List[EvidenceResponse])
def list_evidence(
    case_id: str = Query(None, description="Filter evidence by case_id"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    List evidence items.
    If case_id is specified, validates user access to that specific case.
    Otherwise, restricts results to cases the user is authorized to view.
    """
    if case_id:
        if not RBACService.check_case_access(db, current_user, case_id, permission="evidence:read"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission Denied: You do not have access to evidence in Case '{case_id}'."
            )
        return db.query(Evidence).filter(Evidence.case_id == case_id).offset(skip).limit(limit).all()

    accessible_ids = RBACService.get_accessible_case_ids(db, current_user)
    query = db.query(Evidence)
    if accessible_ids is not None:
        query = query.filter(Evidence.case_id.in_(accessible_ids))

    return query.offset(skip).limit(limit).all()


@router.get("/{id}", response_model=EvidenceResponse)
def get_evidence(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get evidence record by ID.
    Enforces that user has evidence:read permission on the associated case.
    Prevents unauthorized cross-case IDOR access.
    """
    record = db.query(Evidence).filter(Evidence.evidence_id == id).first()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence record with ID '{id}' not found"
        )

    if not RBACService.check_case_access(db, current_user, record.case_id, permission="evidence:read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission Denied: You do not have access to evidence in Case '{record.case_id}'."
        )

    return record


@router.post("/{id}/vault", response_model=EvidenceResponse)
def move_to_vault(
    id: str,
    performed_by: str = Query(None, description="Optional performing investigator name"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Transfer evidence to secure read-only vault.
    Requires evidence:preserve permission on the associated case.
    """
    ev = db.query(Evidence).filter(Evidence.evidence_id == id).first()
    if not ev:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence record with ID '{id}' not found"
        )

    if not RBACService.check_case_access(db, current_user, ev.case_id, permission="evidence:preserve"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission Denied: You do not have preservation permissions on Case '{ev.case_id}'."
        )

    performer = performed_by or current_user.username
    record = CustodyService.transfer_to_vault(db, evidence_id=id, performed_by=performer)

    try:
        AuditService.record_event(
            db=db,
            action="EVIDENCE_VAULT_TRANSFER",
            target_resource="evidence",
            user_id=current_user.user_id,
            username=current_user.username,
            resource_id=id,
            case_id=ev.case_id,
            details=f"Evidence '{id}' moved to vault by {current_user.username}."
        )
    except Exception as e:
        log_app_event(f"Audit event recording skipped: {e}")

    return record
