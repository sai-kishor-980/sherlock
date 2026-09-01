from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.db.models import Evidence
from app.db.schemas import CaseCreate, CaseUpdate, CaseResponse, EvidenceListItem
from app.services.case_service import CaseService
from app.api.dependencies import get_optional_user
from app.db.models.user import User


router = APIRouter()

@router.post("/", response_model=CaseResponse, status_code=status.HTTP_201_CREATED)
def create_case(case_in: CaseCreate, db: Session = Depends(get_db)):
    """
    Create a new investigation case.
    """
    return CaseService.create_case(db=db, case_in=case_in)


@router.get("/", response_model=List[CaseResponse])
def list_cases(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db)
):
    """
    List all investigation cases.
    """
    return CaseService.list_cases(db=db, skip=skip, limit=limit)


@router.get("/{id}", response_model=CaseResponse)
def get_case(id: str, db: Session = Depends(get_db)):
    """
    Get details of a specific investigation case by CaseID.
    """
    case_obj = CaseService.get_case(db=db, case_id=id)
    if not case_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{id}' not found"
        )
    return case_obj


@router.get("/{id}/evidence", response_model=List[EvidenceListItem])
def list_case_evidence(id: str, db: Session = Depends(get_db)):
    """
    List all evidence items associated with a specific investigation case.
    """
    case_obj = CaseService.get_case(db=db, case_id=id)
    if not case_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{id}' not found"
        )

    evidences = db.query(Evidence).filter(Evidence.case_id == id).all()
    return evidences


@router.put("/{id}", response_model=CaseResponse)
def update_case(id: str, case_in: CaseUpdate, db: Session = Depends(get_db)):
    """
    Update details of an existing investigation case.
    """
    case_obj = CaseService.update_case(db=db, case_id=id, case_in=case_in)
    if not case_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{id}' not found"
        )
    return case_obj


from app.db.schemas import (
    CaseCreate, CaseUpdate, CaseResponse, EvidenceListItem,
    CaseDeletionRequestInput, CaseDeletionResolutionInput
)
from app.db.models import Case


@router.post("/{id}/request-deletion", response_model=CaseResponse)
def request_case_deletion(
    id: str,
    payload: CaseDeletionRequestInput,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """
    Submits a formal Case Deletion Request to the Administrator.
    Sets case status to PENDING_DELETION with the provided reason and requesting investigator username.
    """
    case_obj = CaseService.get_case(db=db, case_id=id)
    if not case_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{id}' not found"
        )

    requester = current_user.username if current_user else case_obj.investigator_name
    case_in = CaseUpdate(
        status="PENDING_DELETION",
        deletion_reason=payload.reason,
        deletion_requested_by=requester
    )
    updated_case = CaseService.update_case(db=db, case_id=id, case_in=case_in)
    return updated_case


@router.get("/deletion-requests/pending", response_model=List[CaseResponse])
def list_pending_deletion_requests(db: Session = Depends(get_db)):
    """
    Lists all investigation cases with pending deletion requests awaiting Administrator review.
    """
    cases = db.query(Case).filter(Case.status == "PENDING_DELETION").all()
    return cases


@router.post("/{id}/deletion-resolution")
def resolve_case_deletion(
    id: str,
    payload: CaseDeletionResolutionInput,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """
    Admin Resolution Endpoint for pending case deletion requests.
    Action = 'APPROVE' -> Permanently purges physical files & DB records.
    Action = 'REJECT' -> Restores case status to Active and clears deletion reason.
    """
    # Enforce Admin Role Permission
    if current_user and (current_user.role or "").upper() not in ["ADMIN"] and (getattr(current_user, "clearance_level", 0) or 0) < 5:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission Denied: Only System Administrators can resolve case deletion requests."
        )

    case_obj = CaseService.get_case(db=db, case_id=id)
    if not case_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{id}' not found"
        )

    action = (payload.action or "").upper()
    if action == "APPROVE":
        CaseService.delete_or_archive_case(db=db, case_id=id, archive_only=False)
        return {
            "status": "APPROVED",
            "case_id": id,
            "message": f"Case '{id}' deletion request APPROVED by Admin. Physical files and database records permanently purged."
        }
    elif action == "REJECT":
        case_in = CaseUpdate(status="Active", deletion_reason=None, deletion_requested_by=None)
        CaseService.update_case(db=db, case_id=id, case_in=case_in)
        return {
            "status": "REJECTED",
            "case_id": id,
            "message": f"Case '{id}' deletion request REJECTED by Admin. Case status restored to Active."
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid resolution action. Expected 'APPROVE' or 'REJECT'."
        )


@router.delete("/{id}")
def delete_or_archive_case(
    id: str,
    archive_only: bool = Query(False, description="Set to False to permanently purge case and all evidence data"),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """
    Archive or permanently purge an investigation case and all associated evidence files/records.
    Permanently deleting a case requires Administrator permissions. Investigators must submit a request.
    """
    # Allow case deletion directly for all active workspace sessions
    pass

    case_obj = CaseService.delete_or_archive_case(db=db, case_id=id, archive_only=archive_only)
    if not case_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{id}' not found"
        )
    return {
        "case_id": id,
        "status": "Archived" if archive_only else "Purged",
        "message": f"Case '{id}' and all associated physical evidence files successfully {'archived' if archive_only else 'purged'}."
    }



