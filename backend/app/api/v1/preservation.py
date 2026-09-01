"""
Evidence Preservation Layer API Router for HMACFR.

Exposes asynchronous REST API endpoints for:
1. Receiving evidence handoff payloads.
2. Executing Layer 1 preservation pipeline:
   - SHA-256 computation
   - MD5 computation
   - AES-256-GCM symmetric encryption
   - Read-only protection (stat.S_IREAD)
   - Evidence Vault deposit
   - Post-preservation integrity audit
3. Publishing EVIDENCE_READY & CASE_UPLOAD_COMPLETE event payloads.
4. Memory-efficient chunked streaming of preserved evidence.
"""

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
import anyio

from app.api.dependencies import get_db, get_settings, get_preservation_service
from app.core.config import Settings
from app.db.schemas import (
    EvidencePreserveInput,
    PreservationPipelineResult,
    EvidenceReadyEventPayload,
    CaseUploadCompleteEventPayload
)
from app.services.preservation_service import EvidencePreservationService

router = APIRouter(tags=["Evidence Preservation Layer"])


@router.post(
    "/preserve",
    response_model=PreservationPipelineResult,
    summary="Process handoff payload & execute evidence preservation pipeline",
    status_code=status.HTTP_200_OK
)
async def preserve_evidence_endpoint(
    payload: EvidencePreserveInput,
    secret_key: Optional[str] = Query(None, description="Optional AES-256 master key override"),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    service: type[EvidencePreservationService] = Depends(get_preservation_service)
) -> PreservationPipelineResult:
    """
    Asynchronous Evidence Preservation Pipeline Entry Point.

    Input received from Handoff:
    {
      "evidence_id": "EV001",
      "case_id": "CASE001",
      "storage_path": "...",
      "category": "Memory",
      "status": "UPLOADED"
    }

    Executes 7 preservation steps asynchronously:
    1. SHA-256 hashing
    2. MD5 hashing
    3. AES-256-GCM payload encryption at rest
    4. Read-only filesystem write protection (stat.S_IREAD)
    5. Evidence Vault storage isolation (evidence_vault/readonly/<case_id>/)
    6. Multi-factor integrity verification audit
    7. Event payload publishing (EVIDENCE_READY and CASE_UPLOAD_COMPLETE)
    """
    key_to_use = secret_key or settings.ENCRYPTION_SECRET_KEY
    return await anyio.to_thread.run_sync(
        service.preserve_evidence_payload,
        db,
        payload,
        key_to_use
    )


@router.post(
    "/preserve-case/{case_id}",
    response_model=List[PreservationPipelineResult],
    summary="Batch execute preservation pipeline for all evidence items in a case",
    status_code=status.HTTP_200_OK
)
async def preserve_case_evidence_endpoint(
    case_id: str,
    secret_key: Optional[str] = Query(None, description="Optional AES-256 master key override"),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    service: type[EvidencePreservationService] = Depends(get_preservation_service)
) -> List[PreservationPipelineResult]:
    """
    Asynchronously batch preserves all registered evidence items belonging to a case.
    """
    key_to_use = secret_key or settings.ENCRYPTION_SECRET_KEY
    return await anyio.to_thread.run_sync(
        service.preserve_case_evidence,
        db,
        case_id,
        key_to_use
    )


@router.get(
    "/stream/{evidence_id}",
    summary="Stream preserved evidence payload directly to Plugin Manager",
    description="Memory-efficient chunked streaming download endpoint for Plugin Manager consumption."
)
async def stream_to_plugin_manager_endpoint(
    evidence_id: str,
    db: Session = Depends(get_db),
    service: type[EvidencePreservationService] = Depends(get_preservation_service)
):
    """
    Streams preserved evidence file to the Plugin Manager using FastAPI StreamingResponse.
    """
    return await anyio.to_thread.run_sync(
        service.stream_preserved_evidence_to_plugin_manager,
        db,
        evidence_id
    )
