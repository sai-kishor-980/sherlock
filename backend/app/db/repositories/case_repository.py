from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from app.db.models import Case

class CaseRepository:
    """Repository managing Case database operations."""

    @staticmethod
    def get_by_id(db: Session, case_id: str) -> Optional[Case]:
        """Fetch a Case record by unique case_id."""
        return db.query(Case).filter(Case.case_id == case_id).first()

    @staticmethod
    def get_all(db: Session, skip: int = 0, limit: int = 100) -> List[Case]:
        """Fetch all Case records with pagination."""
        return db.query(Case).offset(skip).limit(limit).all()

    @staticmethod
    def create(db: Session, case_obj: Case) -> Case:
        """Persist a new Case instance to the database."""
        db.add(case_obj)
        db.commit()
        db.refresh(case_obj)
        return case_obj

    @staticmethod
    def update(db: Session, case_id: str, update_data: Dict[str, Any]) -> Optional[Case]:
        """Update fields of a Case record."""
        case_obj = CaseRepository.get_by_id(db, case_id)
        if not case_obj:
            return None
        for field, value in update_data.items():
            if value is not None and hasattr(case_obj, field):
                setattr(case_obj, field, value)
        db.commit()
        db.refresh(case_obj)
        return case_obj

    @staticmethod
    def update_status(db: Session, case_id: str, new_status: str) -> Optional[Case]:
        """Update case status string."""
        case_obj = CaseRepository.get_by_id(db, case_id)
        if case_obj:
            case_obj.status = new_status
            db.commit()
            db.refresh(case_obj)
        return case_obj

    @staticmethod
    def delete(db: Session, case_id: str) -> bool:
        """Delete a Case record from database."""
        case_obj = CaseRepository.get_by_id(db, case_id)
        if case_obj:
            db.delete(case_obj)
            db.commit()
            return True
        return False
