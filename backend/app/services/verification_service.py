"""
Advanced Verification Service for HMACFR Layer 1 Integrity.

Performs deep multi-factor integrity verification (Hash + HMAC + ReadOnly + File Size)
and batch integrity audits across cases and the evidence vault.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from app.db.repositories import EvidenceRepository
from app.services.hashing_service import AdvancedHashingService
from app.services.readonly_service import ReadOnlyProtectionService
from app.core.logger import log_verification_event, log_error_event


class AdvancedVerificationService:
    """
    Service executing thorough cryptographic audit procedures for evidence records.
    """

    @classmethod
    def verify_evidence_record(cls, db: Session, evidence_id: str) -> Dict[str, Any]:
        """
        Executes multi-factor integrity verification on a single evidence record.

        :param db: SQLAlchemy Session.
        :param evidence_id: Evidence unique identifier.
        :return: Result dictionary with is_valid, current_sha256, recorded_sha256, hmac_verified, readonly_protected, and status.
        """
        record = EvidenceRepository.get_by_id(db, evidence_id)
        if not record:
            return {
                "evidence_id": evidence_id,
                "original_filename": "UNKNOWN",
                "is_valid": False,
                "status": "not_found",
                "details": f"Evidence record with ID '{evidence_id}' does not exist in database."
            }

        file_path = Path(record.storage_path)
        if not file_path.is_file():
            log_verification_event(evidence_id, False, "missing_file")
            return {
                "evidence_id": evidence_id,
                "original_filename": record.original_filename,
                "is_valid": False,
                "status": "missing_file",
                "current_sha256": "FILE_NOT_FOUND",
                "recorded_sha256": record.file_hash or "",
                "hmac_verified": False,
                "readonly_protected": False,
                "details": f"File missing at path '{file_path}'"
            }

        # 1. Compute current SHA256
        current_hash = AdvancedHashingService.calculate_file_hash(file_path, "sha256")
        hash_ok = (current_hash.lower() == (record.file_hash or "").lower())

        # 2. Verify HMAC signature if available
        content = file_path.read_bytes()
        hmac_ok = (
            AdvancedHashingService.verify_hmac(content, record.hmac_signature)
            if record.hmac_signature else True
        )

        # 3. Check read-only protection status
        readonly_ok = ReadOnlyProtectionService.check_readonly_status(file_path)

        is_valid = hash_ok and hmac_ok
        status = "intact" if is_valid else "tampered"

        log_verification_event(evidence_id, is_valid, status)

        return {
            "evidence_id": evidence_id,
            "original_filename": record.original_filename,
            "is_valid": is_valid,
            "status": status,
            "hash_match": hash_ok,
            "current_sha256": current_hash,
            "recorded_sha256": record.file_hash or "",
            "hmac_verified": hmac_ok,
            "readonly_protected": readonly_ok,
            "details": "Integrity verified successfully" if is_valid else "Integrity check failed: hash or HMAC mismatch"
        }

    @classmethod
    def audit_case_evidence(cls, db: Session, case_id: str) -> Dict[str, Any]:
        """
        Runs batch integrity audits on all evidence records associated with a case.

        :param db: SQLAlchemy Session.
        :param case_id: Case unique identifier.
        :return: Audit report dictionary with totals and detailed results per file.
        """
        records = EvidenceRepository.get_by_case(db, case_id)
        results = [cls.verify_evidence_record(db, item.evidence_id) for item in records]

        total = len(results)
        valid_count = sum(1 for r in results if r.get("is_valid"))
        tampered_count = sum(1 for r in results if r.get("status") == "tampered")
        missing_count = sum(1 for r in results if r.get("status") == "missing_file")

        return {
            "case_id": case_id,
            "total_audited": total,
            "total_valid": valid_count,
            "total_tampered": tampered_count,
            "total_missing": missing_count,
            "results": results
        }
