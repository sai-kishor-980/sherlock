"""
Chain of Custody API Router for HMACFR.

Exposes REST API endpoints for fetching and recording forensic audit trail logs.
Enforces case-level custody read authorization.
"""

from fastapi import APIRouter, HTTPException, Depends, status
from typing import List
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.db.schemas import ChainOfCustodyResponse
from app.db.repositories import CustodyRepository
from app.db.models.evidence import Evidence
from app.services.rbac_service import RBACService
from app.api.dependencies import get_current_user
from app.db.models.user import User

router = APIRouter()


@router.get("/evidence/{evidence_id}", response_model=List[ChainOfCustodyResponse], summary="Get custody audit trail for evidence item")
def get_evidence_custody_logs(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns full Chain of Custody audit history for a specific evidence item.
    Requires custody:read permission on the associated case.
    """
    ev = db.query(Evidence).filter(Evidence.evidence_id == evidence_id).first()
    if not ev:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence record with ID '{evidence_id}' not found"
        )

    if not RBACService.check_case_access(db, current_user, ev.case_id, permission="custody:read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission Denied: You do not have access to custody records for Case '{ev.case_id}'."
        )

    logs = CustodyRepository.get_logs_by_evidence(db, evidence_id)
    return logs
