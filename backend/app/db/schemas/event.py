from pydantic import BaseModel, ConfigDict
from typing import Optional

class EvidenceReadyEventPayload(BaseModel):
    event: str = "EVIDENCE_READY"
    evidence_id: str
    case_id: str
    storage_path: str
    category: str
    status: str = "READY_FOR_PROCESSING"

    model_config = ConfigDict(from_attributes=True)


class CaseUploadCompleteEventPayload(BaseModel):
    event: str = "CASE_UPLOAD_COMPLETE"
    case_id: str

    model_config = ConfigDict(from_attributes=True)


class PreservationPipelineResult(BaseModel):
    evidence_ready_event: EvidenceReadyEventPayload
    case_complete_event: Optional[CaseUploadCompleteEventPayload] = None
    sha256: str
    md5: str
    readonly_protected: bool
    encrypted: bool
