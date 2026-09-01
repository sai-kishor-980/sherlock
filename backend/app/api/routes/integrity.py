from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.db.schemas import IntegrityCheckResponse
from app.services.integrity_service import IntegrityService

router = APIRouter()

@router.get("/{id}", response_model=IntegrityCheckResponse)
def verify_integrity(id: str, db: Session = Depends(get_db)):
    """
    Verify SHA-256 hash and HMAC signature of stored evidence file.
    """
    result = IntegrityService.verify_record_integrity(db, evidence_id=id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence with ID '{id}' not found"
        )
    return result
