"""
Hashing API Router for HMACFR.

Exposes REST API endpoints for multi-algorithm cryptographic hashing and verification.
"""

from fastapi import APIRouter, HTTPException, Depends, status
from typing import Dict, Optional
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.services.hashing_service import AdvancedHashingService
from app.services.integrity_service import IntegrityService

router = APIRouter()


@router.post("/bytes", summary="Calculate hash digest for raw content")
def hash_bytes_endpoint(content: str, algorithm: str = "sha256"):
    """
    Calculates cryptographic hash digest for string content.
    """
    try:
        digest = AdvancedHashingService.calculate_bytes_hash(content.encode("utf-8"), algorithm)
        return {"algorithm": algorithm, "hash": digest}
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))


@router.get("/evidence/{evidence_id}", summary="Calculate hash for stored evidence file")
def hash_evidence_endpoint(evidence_id: str, algorithm: str = "sha256", db: Session = Depends(get_db)):
    """
    Calculates cryptographic hash digest for a stored evidence file by evidence_id.
    """
    record = IntegrityService.verify_record_integrity(db, evidence_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")
    return {
        "evidence_id": evidence_id,
        "algorithm": algorithm,
        "hash": record.get("current_hash")
    }


@router.post("/compute", summary="Compute streaming SHA-256 and MD5 hashes from Person A storage_path")
def compute_hashes_endpoint(
    storage_path: str,
    evidence_id: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Accepts storage_path from Person A, computes SHA-256 and MD5 using streaming file reads,
    stores hashes in Evidence metadata if evidence_id is provided, verifies rehash capability,
    and returns {"sha256": "...", "md5": "..."}.
    """
    try:
        hashes = AdvancedHashingService.compute_evidence_hashes(storage_path)
        if evidence_id:
            from app.db.models import Evidence
            record = db.query(Evidence).filter(Evidence.evidence_id == evidence_id).first()
            if record:
                record.file_hash = hashes["sha256"]
                db.commit()
        return hashes
    except FileNotFoundError as fnf:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(fnf))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))
