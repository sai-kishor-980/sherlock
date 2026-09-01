"""
Chain of Custody API Router for HMACFR.

Exposes REST API endpoints for fetching and recording forensic audit trail logs.
"""

from fastapi import APIRouter, HTTPException, Depends, status
from typing import List
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.db.schemas import ChainOfCustodyResponse
from app.db.repositories import CustodyRepository

router = APIRouter()


@router.get("/evidence/{evidence_id}", response_model=List[ChainOfCustodyResponse], summary="Get custody audit trail for evidence item")
def get_evidence_custody_logs(evidence_id: str, db: Session = Depends(get_db)):
    """
    Returns full Chain of Custody audit history for a specific evidence item.
    """
    logs = CustodyRepository.get_logs_by_evidence(db, evidence_id)
    return logs
