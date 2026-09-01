from typing import List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.db.schemas import EvidenceResponse
from app.db.models import Evidence
from app.services.custody_service import CustodyService

router = APIRouter()

@router.get("/", response_model=List[EvidenceResponse])
def list_evidence(
    case_id: str = Query(None, description="Filter evidence by case_id"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db)
):
    query = db.query(Evidence)
    if case_id:
        query = query.filter(Evidence.case_id == case_id)
    return query.offset(skip).limit(limit).all()

@router.get("/{id}", response_model=EvidenceResponse)
def get_evidence(id: str, db: Session = Depends(get_db)):
    record = db.query(Evidence).filter(Evidence.evidence_id == id).first()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence record with ID '{id}' not found"
        )
    return record

@router.post("/{id}/vault", response_model=EvidenceResponse)
def move_to_vault(id: str, performed_by: str = Query("Investigator"), db: Session = Depends(get_db)):
    record = CustodyService.transfer_to_vault(db, evidence_id=id, performed_by=performed_by)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence record with ID '{id}' not found"
        )
    return record
