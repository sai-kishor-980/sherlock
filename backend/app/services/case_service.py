import os
import shutil
from typing import List, Optional
from sqlalchemy.orm import Session
from app.db.models import Case, Evidence
from app.db.schemas import CaseCreate, CaseUpdate
from app.db.repositories import CaseRepository
from app.services.storage_service import StorageService
from app.core.config import settings
from app.core.logger import log_app_event, log_error_event
from app.utils.file_utils import sanitize_filename

class CaseService:
    @staticmethod
    def create_case(db: Session, case_in: CaseCreate) -> Case:
        new_case = Case(
            case_name=case_in.case_name,
            investigator_name=case_in.investigator_name,
            description=case_in.description,
            priority=case_in.priority or "Medium",
            status=case_in.status or "Active"
        )
        saved_case = CaseRepository.create(db, new_case)

        # Automatically create standard case subdirectories under EvidenceVault/{case_id}/
        StorageService.init_case_directory_structure(saved_case.case_id)

        return saved_case

    @staticmethod
    def get_case(db: Session, case_id: str) -> Optional[Case]:
        return CaseRepository.get_by_id(db, case_id)

    @staticmethod
    def list_cases(db: Session, skip: int = 0, limit: int = 100) -> List[Case]:
        return CaseRepository.get_all(db, skip=skip, limit=limit)

    @staticmethod
    def update_case(db: Session, case_id: str, case_in: CaseUpdate) -> Optional[Case]:
        update_data = case_in.model_dump(exclude_unset=True) if hasattr(case_in, "model_dump") else case_in.dict(exclude_unset=True)
        return CaseRepository.update(db, case_id, update_data)

    @staticmethod
    def delete_or_archive_case(db: Session, case_id: str, archive_only: bool = True) -> Optional[Case]:
        case_obj = CaseRepository.get_by_id(db, case_id)
        if not case_obj:
            return None

        if archive_only:
            return CaseRepository.update_status(db, case_id, "Archived")
        else:
            log_app_event(f"Purging case '{case_id}' and all associated evidence data...")

            # 1. Clean up physical evidence storage files on disk
            try:
                evidences = db.query(Evidence).filter(Evidence.case_id == case_id).all()
                for ev in evidences:
                    if ev.storage_path and os.path.exists(ev.storage_path):
                        try:
                            os.remove(ev.storage_path)
                        except Exception as e:
                            log_error_event(f"Failed to remove evidence file {ev.storage_path}: {e}")
            except Exception as e:
                log_error_event(f"Error querying evidence items for purge: {e}")

            # 2. Delete Evidence Vault directory for this case
            clean_id = sanitize_filename(case_id)
            vault_case_dir = os.path.join(settings.EVIDENCE_VAULT_DIR, clean_id)
            if os.path.exists(vault_case_dir):
                try:
                    shutil.rmtree(vault_case_dir, ignore_errors=True)
                    log_app_event(f"Removed vault case directory: {vault_case_dir}")
                except Exception as e:
                    log_error_event(f"Failed to rmtree vault directory {vault_case_dir}: {e}")

            # 3. Delete Uploads directory for this case if present
            uploads_case_dir = os.path.join(settings.UPLOADS_DIR, clean_id)
            if os.path.exists(uploads_case_dir):
                try:
                    shutil.rmtree(uploads_case_dir, ignore_errors=True)
                except Exception as e:
                    log_error_event(f"Failed to rmtree uploads directory {uploads_case_dir}: {e}")

            # 4. Delete Database Record (Cascades to Evidence & ChainOfCustody)
            CaseRepository.delete(db, case_id)
            return case_obj

