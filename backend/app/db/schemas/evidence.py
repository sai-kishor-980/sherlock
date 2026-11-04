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
    # Primary canonical fields (used by frontend types/forensic.ts)
    evidence_id: str = Field(..., validation_alias=AliasChoices("evidence_id", "EvidenceID"))
    name: str = Field(..., validation_alias=AliasChoices("original_filename", "filename", "name", "Filename"))
    original_filename: Optional[str] = Field(None, validation_alias=AliasChoices("original_filename", "filename", "Filename"))
    category: Optional[str] = Field("General", validation_alias=AliasChoices("category", "Category"))
    type: Optional[str] = Field(None, validation_alias=AliasChoices("type", "Type"))
    file_size: int = Field(0, validation_alias=AliasChoices("file_size", "FileSize", "size"))
    sha256_hash: Optional[str] = Field(None, validation_alias=AliasChoices("file_hash", "FileHash", "sha256_hash", "sha256"))
    file_hash: Optional[str] = Field(None, validation_alias=AliasChoices("file_hash", "FileHash", "sha256_hash", "sha256"))
    status: str = Field("VALIDATED", validation_alias=AliasChoices("status", "Status"))
    storage_path: Optional[str] = Field(None, validation_alias=AliasChoices("storage_path", "StoragePath", "path"))
    upload_timestamp: Optional[datetime] = Field(None, validation_alias=AliasChoices("upload_timestamp", "UploadTimestamp", "created_at"))
    
    # Backward compatibility with any legacy consumer looking for PascalCase
    EvidenceID: Optional[str] = Field(None, validation_alias=AliasChoices("evidence_id", "EvidenceID"))
    Filename: Optional[str] = Field(None, validation_alias=AliasChoices("original_filename", "filename", "Filename"))
    Category: Optional[str] = Field("General", validation_alias=AliasChoices("category", "Category"))

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

class EvidencePreserveInput(BaseModel):
    evidence_id: str
    case_id: str
    storage_path: str
    category: Optional[str] = "Memory"
    status: Optional[str] = "UPLOADED"

    model_config = ConfigDict(from_attributes=True)
