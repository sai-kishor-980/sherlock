from typing import Optional
from fastapi import APIRouter, UploadFile, File, Form, Depends, status
from sqlalchemy.orm import Session
from app.db.connection import get_db
from app.db.schemas import EvidenceResponse
from app.services.upload_service import UploadService
from app.utils.validation_utils import validate_upload_payload

router = APIRouter()

@router.post("/", response_model=EvidenceResponse, status_code=status.HTTP_201_CREATED)
async def upload_evidence(
    case_id: str = Form(..., description="ID of the associated investigation case"),
    investigator: str = Form(..., description="Name of the investigator uploading the evidence"),
    file: UploadFile = File(..., description="The evidence file binary"),
    category: Optional[str] = Form(None, description="Category of evidence e.g. Audio, Video, Document"),
    type: Optional[str] = Form(None, description="Type of evidence e.g. Media, Forensic Image"),
    description: Optional[str] = Form(None, description="Detailed description or notes"),
    db: Session = Depends(get_db)
):
    """
    Validate request payload, check file & case parameters, store file, hash, and record initial chain of custody.
    """
    content = await file.read() if file else None

    # Step 1: Execute file validation checklist (File exists, size > 0, required fields, allowed extension)
    validate_upload_payload(
        file=file,
        case_id=case_id,
        investigator=investigator,
        content_bytes=content
    )

    # Step 2: Verify Case ID existence & Process Upload
    evidence_record = UploadService.process_file_upload(
        db=db,
        case_id=case_id,
        investigator=investigator,
        original_filename=file.filename,
        content=content,
        category=category,
        evidence_type=type,
        description=description
    )

    return evidence_record
