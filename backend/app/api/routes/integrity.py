from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.db.schemas import IntegrityCheckResponse
from app.services.integrity_service import IntegrityService
from app.services.rbac_service import RBACService
from app.api.dependencies import get_current_user
from app.db.models.user import User

router = APIRouter()

@router.get("/{id}", response_model=IntegrityCheckResponse)
def verify_integrity(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Verify SHA-256 hash and HMAC signature of stored evidence file.
    Requires evidence:read permission on the associated case.
    """
    has_access, case_id = RBACService.check_evidence_access(db, current_user, id, permission="evidence:read")
    if case_id is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence with ID '{id}' not found"
        )
    if not has_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission Denied: You do not have access to evidence in Case '{case_id}'."
        )

    result = IntegrityService.verify_record_integrity(db, evidence_id=id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence with ID '{id}' not found"
        )
    return result
