from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from app.db.models import Evidence, ChainOfCustody

class EvidenceRepository:
    """Repository managing Evidence database operations."""

    @staticmethod
    def get_by_id(db: Session, evidence_id: str) -> Optional[Evidence]:
        """Fetch an Evidence record by unique evidence_id."""
        return db.query(Evidence).filter(Evidence.evidence_id == evidence_id).first()

    @staticmethod
    def get_by_case(db: Session, case_id: str) -> List[Evidence]:
        """Fetch all Evidence records belonging to a specific case_id."""
        return db.query(Evidence).filter(Evidence.case_id == case_id).all()

    @staticmethod
    def get_pending_by_case(db: Session, case_id: str) -> List[Evidence]:
        """Fetch all Evidence records belonging to a case that are not yet preserved."""
        return db.query(Evidence).filter(
            Evidence.case_id == case_id,
            Evidence.status != "READY_FOR_PROCESSING"
        ).all()

    @staticmethod
    def get_all(db: Session, skip: int = 0, limit: int = 100) -> List[Evidence]:
        """Fetch all Evidence records across cases."""
        return db.query(Evidence).offset(skip).limit(limit).all()

    @staticmethod
    def create(db: Session, evidence_obj: Evidence) -> Evidence:
        """Persist a new Evidence instance to the database."""
        db.add(evidence_obj)
        db.commit()
        db.refresh(evidence_obj)
        return evidence_obj

    @staticmethod
    def update_status(db: Session, evidence_id: str, new_status: str) -> Optional[Evidence]:
        """Update the status string of an evidence record."""
        evidence = EvidenceRepository.get_by_id(db, evidence_id)
        if evidence:
            evidence.status = new_status
            db.commit()
            db.refresh(evidence)
        return evidence

    @staticmethod
    def update_preservation(
        db: Session,
        evidence_id: str,
        storage_path: str,
        file_hash: str,
        hmac_signature: str,
        status: str = "READY_FOR_PROCESSING"
    ) -> Optional[Evidence]:
        """Update preserved evidence metadata and status."""
        evidence = EvidenceRepository.get_by_id(db, evidence_id)
        if evidence:
            evidence.storage_path = storage_path
            evidence.file_hash = file_hash
            evidence.hmac_signature = hmac_signature
            evidence.status = status
            db.commit()
            db.refresh(evidence)
        return evidence


class CustodyRepository:
    """Repository managing Chain of Custody database operations."""

    @staticmethod
    def get_logs_by_evidence(db: Session, evidence_id: str) -> List[ChainOfCustody]:
        """Fetch all audit trail entries for a specific evidence item."""
        return db.query(ChainOfCustody).filter(ChainOfCustody.evidence_id == evidence_id).all()

    @staticmethod
    def add_log(
        db: Session,
        evidence_id: str,
        action: str,
        performed_by: str,
        remarks: Optional[str] = None
    ) -> ChainOfCustody:
        """Create and append a new Chain of Custody entry."""
        log_obj = ChainOfCustody(
            evidence_id=evidence_id,
            action=action,
            performed_by=performed_by,
            remarks=remarks
        )
        db.add(log_obj)
        db.commit()
        db.refresh(log_obj)
        return log_obj
