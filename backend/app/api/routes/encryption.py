"""
Encryption API Router for HMACFR.

Exposes REST API endpoints for AES-256-GCM symmetric payload encryption and decryption.
"""

from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.db.models import Evidence
from app.services.encryption_service import EvidenceEncryptionService
from app.db.repositories import EvidenceRepository

router = APIRouter()


@router.post("/encrypt/{evidence_id}", summary="Encrypt stored evidence file at rest")
def encrypt_evidence_endpoint(evidence_id: str, secret_key: str = None, db: Session = Depends(get_db)):
    """
    Encrypts stored evidence payload using AES-256-GCM authenticated encryption.
    """
    evidence = EvidenceRepository.get_by_id(db, evidence_id)
    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Evidence '{evidence_id}' not found")

    encrypted_path = evidence.storage_path + ".enc"
    success = EvidenceEncryptionService.encrypt_file(evidence.storage_path, encrypted_path, secret_key)
    if not success:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Encryption failed")

    EvidenceRepository.update_status(db, evidence_id, "Encrypted")
    return {
        "evidence_id": evidence_id,
        "status": "Encrypted",
        "encrypted_path": encrypted_path
    }
