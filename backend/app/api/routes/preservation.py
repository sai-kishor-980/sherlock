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
Enforces case-level preservation authorization.
"""

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
import anyio

from app.api.dependencies import get_db, get_settings, get_preservation_service, get_current_user
from app.core.config import Settings
from app.db.schemas import (
    EvidencePreserveInput,
    PreservationPipelineResult,
    EvidenceReadyEventPayload,
    CaseUploadCompleteEventPayload
)
from app.services.preservation_service import EvidencePreservationService
from app.services.rbac_service import RBACService
from app.services.audit_service import AuditService
from app.db.models.user import User
from app.db.models.evidence import Evidence
from app.core.logger import log_app_event

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
    service: type[EvidencePreservationService] = Depends(get_preservation_service),
    current_user: User = Depends(get_current_user)
) -> PreservationPipelineResult:
    """
    Asynchronous Evidence Preservation Pipeline Entry Point.
    Requires evidence:preserve permission on the target case.
    """
    if not RBACService.check_case_access(db, current_user, payload.case_id, permission="evidence:preserve"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission Denied: You do not have preservation permission on Case '{payload.case_id}'."
        )

    key_to_use = secret_key or settings.ENCRYPTION_SECRET_KEY
    result = await anyio.to_thread.run_sync(
        service.preserve_evidence_payload,
        db,
        payload,
        key_to_use
    )

    try:
        AuditService.record_event(
            db=db,
            action="EVIDENCE_PRESERVE",
            target_resource="evidence",
            user_id=current_user.user_id,
            username=current_user.username,
            resource_id=payload.evidence_id,
            case_id=payload.case_id,
            details=f"Evidence '{payload.evidence_id}' preserved by {current_user.username} (SHA256: {result.sha256[:16]}...)."
        )
    except Exception as e:
        log_app_event(f"Audit event recording skipped: {e}")

    return result


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
    service: type[EvidencePreservationService] = Depends(get_preservation_service),
    current_user: User = Depends(get_current_user)
) -> List[PreservationPipelineResult]:
    """
    Asynchronously batch preserves all registered evidence items belonging to a case.
    Requires evidence:preserve permission on the case.
    """
    if not RBACService.check_case_access(db, current_user, case_id, permission="evidence:preserve"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission Denied: You do not have preservation permission on Case '{case_id}'."
        )

    key_to_use = secret_key or settings.ENCRYPTION_SECRET_KEY
    results = await anyio.to_thread.run_sync(
        service.preserve_case_evidence,
        db,
        case_id,
        key_to_use
    )

    try:
        AuditService.record_event(
            db=db,
            action="CASE_BATCH_PRESERVE",
            target_resource="case",
            user_id=current_user.user_id,
            username=current_user.username,
            resource_id=case_id,
            case_id=case_id,
            details=f"Batch preservation executed for {len(results)} item(s) in Case '{case_id}' by {current_user.username}."
        )
    except Exception as e:
        log_app_event(f"Audit event recording skipped: {e}")

    return results


@router.get(
    "/stream/{evidence_id}",
    summary="Stream preserved evidence payload directly to Plugin Manager",
    description="Memory-efficient chunked streaming download endpoint for Plugin Manager consumption."
)
async def stream_to_plugin_manager_endpoint(
    evidence_id: str,
    db: Session = Depends(get_db),
    service: type[EvidencePreservationService] = Depends(get_preservation_service),
    current_user: User = Depends(get_current_user)
):
    """
    Streams preserved evidence file using FastAPI StreamingResponse.
    Requires evidence:read permission on the associated case.
    """
    ev = db.query(Evidence).filter(Evidence.evidence_id == evidence_id).first()
    if not ev:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence with ID '{evidence_id}' not found"
        )

    if not RBACService.check_case_access(db, current_user, ev.case_id, permission="evidence:read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission Denied: You do not have access to evidence in Case '{ev.case_id}'."
        )

    return await anyio.to_thread.run_sync(
        service.stream_preserved_evidence_to_plugin_manager,
        db,
        evidence_id
    )
