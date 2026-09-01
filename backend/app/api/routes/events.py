"""
Event Notifications & Handoff API Router for HMACFR.

Exposes REST API endpoints for generating evidence handoff payloads
and event notifications across framework layers.
"""

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.db.schemas import PersonBHandoffPayload, Person5HandoffPayload
from app.services.handoff_service import HandoffService

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
    db: Session = Depends(get_db)
):
    """
    Generate initial handoff payload for Preservation Engine containing evidence location & metadata.
    """
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
    db: Session = Depends(get_db)
):
    """
    Process preservation verification, compute SHA256 checksum, update audit log, and return payload for Analysis Engine.
    """
    return HandoffService.process_analysis_handoff(db=db, evidence_id=id, verifier=verifier)
