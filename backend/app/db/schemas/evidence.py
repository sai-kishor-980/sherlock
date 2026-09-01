from pydantic import BaseModel, Field, AliasChoices, ConfigDict
from datetime import datetime
from typing import Optional, List

class EvidenceBase(BaseModel):
    case_id: str
    original_filename: str
    category: Optional[str] = None
    type: Optional[str] = None

class EvidenceCreate(EvidenceBase):
    pass

class ChainOfCustodyResponse(BaseModel):
    log_id: str
    evidence_id: str
    action: str
    performed_by: str
    timestamp: datetime
    remarks: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

class EvidenceResponse(BaseModel):
    evidence_id: str
    case_id: str
    original_filename: str
    stored_filename: str
    category: Optional[str] = None
    type: Optional[str] = None
    extension: str
    file_size: int
    storage_path: str
    upload_timestamp: datetime
    status: str
    file_hash: Optional[str] = None
    hmac_signature: Optional[str] = None
    custody_logs: List[ChainOfCustodyResponse] = []

    model_config = ConfigDict(from_attributes=True)

class EvidenceListItem(BaseModel):
    EvidenceID: str = Field(..., validation_alias=AliasChoices("evidence_id", "EvidenceID"), serialization_alias="EvidenceID")
    Filename: str = Field(..., validation_alias=AliasChoices("original_filename", "filename", "Filename"), serialization_alias="Filename")
    Category: Optional[str] = Field("General", validation_alias=AliasChoices("category", "Category"), serialization_alias="Category")

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

class EvidencePreserveInput(BaseModel):
    evidence_id: str
    case_id: str
    storage_path: str
    category: Optional[str] = "Memory"
    status: Optional[str] = "UPLOADED"

    model_config = ConfigDict(from_attributes=True)
