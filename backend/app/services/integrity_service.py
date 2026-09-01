import os
from sqlalchemy.orm import Session
from app.db.repositories import EvidenceRepository
from app.services.hashing_service import calculate_file_sha256
from app.core.security import verify_hmac

class IntegrityService:
    @staticmethod
    def verify_record_integrity(db: Session, evidence_id: str):
        record = EvidenceRepository.get_by_id(db, evidence_id)
        if not record:
            return None

        active_path = record.storage_path
        if not os.path.exists(active_path):
            return {
                "evidence_id": record.evidence_id,
                "original_filename": record.original_filename,
                "is_valid": False,
                "current_hash": "FILE_NOT_FOUND",
                "recorded_hash": record.file_hash or "",
                "hmac_verified": False,
                "status": "missing_file"
            }

        with open(active_path, "rb") as f:
            content = f.read()

        current_hash = calculate_file_sha256(active_path)
        hmac_ok = verify_hmac(content, record.hmac_signature) if record.hmac_signature else False
        hash_ok = (current_hash == record.file_hash)
        is_valid = hash_ok and hmac_ok

        return {
            "evidence_id": record.evidence_id,
            "original_filename": record.original_filename,
            "is_valid": is_valid,
            "current_hash": current_hash,
            "recorded_hash": record.file_hash or "",
            "hmac_verified": hmac_ok,
            "status": "intact" if is_valid else "tampered"
        }


# Reusable Integrity Verification Service for H-MACFR Evidence Preservation
from pathlib import Path
from typing import Dict, Any, Optional, Union
from fastapi import HTTPException, status as http_status
from app.services.hashing_service import AdvancedHashingService
from app.core.logger import log_verification_event, log_error_event


class IntegrityVerificationError(Exception):
    """Exception raised when evidence fails post-preservation integrity verification."""
    def __init__(self, message: str, evidence_id: Optional[str] = None, quarantine_path: Optional[str] = None):
        super().__init__(message)
        self.evidence_id = evidence_id
        self.quarantine_path = quarantine_path


class IntegrityVerificationService:
    """
    Reusable Integrity Verification Service for HMACFR.

    Verifies recalculated SHA-256 hash against original hash.
    If hashes match: returns verified = True.
    Else: moves evidence to quarantine and raises IntegrityVerificationError.
    """

    @classmethod
    def verify_file_sha256(
        cls, filepath: Union[str, Path], original_hash: str, evidence_id: Optional[str] = None
    ) -> bool:
        """
        Recalculates SHA-256 for a file on disk using streaming reads and compares with original_hash.

        :param filepath: Path to evidence file.
        :param original_hash: Original SHA-256 digest string.
        :param evidence_id: Optional evidence identifier.
        :return: True if verified.
        :raises IntegrityVerificationError: If hashes mismatch (file moved to quarantine).
        :raises FileNotFoundError: If file does not exist.
        """
        path = Path(filepath) if isinstance(filepath, str) else filepath
        if not path.is_file():
            err_msg = f"Integrity verification failed: File '{path}' does not exist."
            log_error_event(err_msg)
            raise FileNotFoundError(err_msg)

        current_hash = AdvancedHashingService.calculate_file_hash(path, "sha256")
        hashes_match = (current_hash.lower() == original_hash.lower())

        if hashes_match:
            log_verification_event(evidence_id or path.name, True, "INTACT")
            return True
        else:
            # Hashes mismatch: Move evidence file to quarantine
            from app.services.vault_service import EvidenceVaultService
            quarantine_path = EvidenceVaultService.quarantine_evidence(
                filepath=path,
                reason=f"SHA-256 hash mismatch! Current: {current_hash} != Original: {original_hash}"
            )
            err_msg = f"Integrity check failed for '{path.name}'! Hash mismatch: current '{current_hash}' != original '{original_hash}'. Evidence moved to quarantine at '{quarantine_path}'."
            log_error_event(err_msg)
            log_verification_event(evidence_id or path.name, False, "QUARANTINED")
            raise IntegrityVerificationError(
                message=err_msg,
                evidence_id=evidence_id,
                quarantine_path=str(quarantine_path)
            )

    @classmethod
    def verify_preservation_finish(
        cls, db: Session, evidence_id: str, original_hash: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes post-preservation integrity verification on DB evidence record.
        Recalculates SHA-256, compares with original, sets verified = True if match,
        else moves file to quarantine and raises IntegrityVerificationError.

        :param db: SQLAlchemy Session.
        :param evidence_id: Evidence unique identifier.
        :param original_hash: Optional override for expected original hash.
        :return: Dict containing {"verified": True, "evidence_id": evidence_id, "current_hash": sha256}.
        """
        record = EvidenceRepository.get_by_id(db, evidence_id)
        if not record:
            raise HTTPException(
                status_code=http_status.HTTP_404_NOT_FOUND,
                detail=f"Evidence with ID '{evidence_id}' not found."
            )

        expected_hash = original_hash or record.file_hash
        if not expected_hash:
            raise ValueError(f"No recorded hash available for evidence '{evidence_id}'.")

        is_verified = cls.verify_file_sha256(
            filepath=record.storage_path,
            original_hash=expected_hash,
            evidence_id=evidence_id
        )

        return {
            "verified": is_verified,
            "evidence_id": evidence_id,
            "current_hash": expected_hash,
            "status": "INTACT"
        }

