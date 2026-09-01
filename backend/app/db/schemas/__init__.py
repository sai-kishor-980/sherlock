"""
Pydantic Schemas & DTO Package for HMACFR.
"""

from pydantic import BaseModel, Field, AliasChoices, ConfigDict
from datetime import datetime
from typing import Optional, List

from app.db.schemas.evidence import (
    EvidenceBase, EvidenceCreate, EvidenceResponse, EvidenceListItem,
    EvidencePreserveInput, ChainOfCustodyResponse
)
from app.db.schemas.event import (
    EvidenceReadyEventPayload, CaseUploadCompleteEventPayload, PreservationPipelineResult
)
from app.db.schemas.user import (
    UserBase, UserCreate, UserLogin, UserResponse, Token, TokenData
)


class CaseBase(BaseModel):
    case_name: str
    investigator_name: str = Field(
        ...,
        validation_alias=AliasChoices('investigator_name', 'investigator'),
        serialization_alias="investigator_name"
    )
    description: Optional[str] = None
    priority: Optional[str] = Field(default="Medium", description="Priority level: Low, Medium, High, Critical")
    status: Optional[str] = Field(default="Active", description="Status: Active, Pending, Closed, Archived, PENDING_DELETION")
    deletion_reason: Optional[str] = None
    deletion_requested_by: Optional[str] = None
    expected_evidence_count: Optional[int] = Field(default=0, description="Total expected evidence items for case completion tracking")

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

class CaseCreate(CaseBase):
    pass

class CaseUpdate(BaseModel):
    case_name: Optional[str] = None
    investigator_name: Optional[str] = Field(
        None,
        validation_alias=AliasChoices('investigator_name', 'investigator'),
        serialization_alias="investigator_name"
    )
    description: Optional[str] = None
    priority: Optional[str] = None
    status: Optional[str] = None
    deletion_reason: Optional[str] = None
    deletion_requested_by: Optional[str] = None

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

class CaseResponse(CaseBase):
    case_id: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

class CaseDeletionRequestInput(BaseModel):
    reason: Optional[str] = Field(default="Case deletion requested by investigator", description="Reason for case deletion request")

class CaseDeletionResolutionInput(BaseModel):
    action: str = Field(..., description="Resolution action: 'APPROVE' or 'REJECT'")


class ChainOfCustodyBase(BaseModel):
    action: str = "Uploaded"
    performed_by: str
    remarks: Optional[str] = "Uploaded"

class ChainOfCustodyCreate(ChainOfCustodyBase):
    evidence_id: str

class PersonBHandoffPayload(BaseModel):
    case_id: str
    evidence_id: str
    storage_path: str
    category: str
    status: str

    model_config = ConfigDict(from_attributes=True)

class Person5HandoffPayload(BaseModel):
    case_id: str
    sha256: str
    category: str

    model_config = ConfigDict(from_attributes=True)

class IntegrityCheckResponse(BaseModel):
    evidence_id: str
    original_filename: str
    is_valid: bool
    current_hash: str
    recorded_hash: str
    hmac_verified: bool
    status: str

__all__ = [
    "CaseBase", "CaseCreate", "CaseUpdate", "CaseResponse",
    "ChainOfCustodyBase", "ChainOfCustodyCreate", "ChainOfCustodyResponse",
    "EvidenceBase", "EvidenceCreate", "EvidenceResponse", "EvidenceListItem",
    "EvidencePreserveInput", "PersonBHandoffPayload", "Person5HandoffPayload",
    "IntegrityCheckResponse", "EvidenceReadyEventPayload",
    "CaseUploadCompleteEventPayload", "PreservationPipelineResult"
]
