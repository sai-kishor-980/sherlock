"""
Event Notifications & Handoff API Router for HMACFR.

Exposes REST API endpoints for generating evidence handoff payloads
and event notifications across framework layers.
Enforces case-level RBAC authorization.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.db.schemas import PersonBHandoffPayload, Person5HandoffPayload
from app.services.handoff_service import HandoffService
from app.services.rbac_service import RBACService
from app.api.dependencies import get_current_user
from app.db.models.user import User
from app.db.models.evidence import Evidence

router = APIRouter(tags=["Event Notifications & Handoff"])


@router.post(
    "/{id}/preservation",
    response_model=PersonBHandoffPayload,
    summary="Generate initial preservation handoff payload",
    description="Generates handoff payload containing evidence storage location and metadata for the Preservation Layer."
)
def generate_preservation_handoff(
    id: str,
    recipient: str = Query("Preservation Engine", description="Recipient name"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Generate initial handoff payload for Preservation Engine.
    Requires evidence:preserve permission on the associated case.
    """
    has_access, case_id = RBACService.check_evidence_access(db, current_user, id, permission="evidence:preserve")
    if case_id is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence with ID '{id}' not found"
        )
    if not has_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission Denied: You do not have preservation permission on Case '{case_id}'."
        )

    return HandoffService.generate_preservation_handoff(db=db, evidence_id=id, recipient=recipient)


@router.post(
    "/{id}/analysis",
    response_model=Person5HandoffPayload,
    summary="Process preservation handoff & forward to Analysis Engine",
    description="Computes SHA-256 verification digest and formats handoff payload for downstream analysis."
)
def process_analysis_handoff(
    id: str,
    verifier: str = Query("Preservation Engine", description="Verifier name"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Process preservation verification and return payload for Analysis Engine.
    Requires analysis:run permission on the associated case.
    """
    has_access, case_id = RBACService.check_evidence_access(db, current_user, id, permission="analysis:run")
    if case_id is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence with ID '{id}' not found"
        )
    if not has_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission Denied: You do not have analysis permission on Case '{case_id}'."
        )

    return HandoffService.process_analysis_handoff(db=db, evidence_id=id, verifier=verifier)
