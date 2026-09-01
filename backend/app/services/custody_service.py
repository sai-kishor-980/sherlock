from typing import Optional
from sqlalchemy.orm import Session
from app.db.models import Evidence
from app.db.repositories import EvidenceRepository, CustodyRepository
from app.services.storage_service import StorageService

class CustodyService:
    @staticmethod
    def transfer_to_vault(db: Session, evidence_id: str, performed_by: str = "System") -> Optional[Evidence]:
        record = EvidenceRepository.get_by_id(db, evidence_id)
        if not record or not record.storage_path:
            return None

        _, vault_path = StorageService.move_to_vault(
            source_path=record.storage_path,
            case_id=record.case_id,
            category=record.category or "General",
            filename=record.stored_filename
        )
        
        CustodyRepository.add_log(
            db,
            evidence_id=record.evidence_id,
            action="Transferred to Vault",
            performed_by=performed_by,
            remarks=f"Evidence moved to secured vault storage path: {vault_path}"
        )

        return EvidenceRepository.update_preservation(
            db,
            evidence_id=record.evidence_id,
            storage_path=vault_path,
            file_hash=record.file_hash or "",
            hmac_signature=record.hmac_signature or "",
            status="Vaulted"
        )
