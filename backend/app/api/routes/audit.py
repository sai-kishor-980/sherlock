"""
System Audit API Router for HMACFR.
Provides endpoints for querying tamper-evident immutable audit logs,
verifying cryptographic hash-chain integrity, and reviewing dual-store reconciliation.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from pydantic import BaseModel, ConfigDict
from datetime import datetime

from app.db.connection import get_db
from app.db.models.audit_log import SystemAuditLog
from app.services.audit_service import AuditService
from app.services.rbac_service import RBACService
from app.api.dependencies import get_current_user
from app.db.models.user import User

router = APIRouter()


class AuditLogResponse(BaseModel):
    sequence_id: int
    log_id: str
    timestamp: datetime
    user_id: Optional[str] = None
    username: Optional[str] = None
    action: str
    target_resource: str
    resource_id: Optional[str] = None
    case_id: Optional[str] = None
    ip_address: Optional[str] = None
    details: Optional[str] = None
    row_hash: str
    hmac_signature: str

    model_config = ConfigDict(from_attributes=True)


@router.get("/logs", response_model=List[AuditLogResponse], summary="List System Audit Logs")
def get_audit_logs(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    case_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns immutable system audit logs.
    Requires global audit:read permission (Admins and Platform Auditors).
    """
    has_perm = RBACService.has_global_permission(db, current_user, "audit:read")
    if not has_perm:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission Denied: System audit log access requires Platform Auditor or Administrator role."
        )

    query = db.query(SystemAuditLog)
    if case_id:
        query = query.filter(SystemAuditLog.case_id == case_id)

    logs = query.order_by(desc(SystemAuditLog.sequence_id)).offset(offset).limit(limit).all()
    return logs


@router.get("/verify", summary="Verify Audit Hash Chain & HMAC Integrity")
def verify_audit_chain(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Verifies cryptographic hash chain and HMAC signatures across all system audit records.
    Requires global audit:read permission.
    """
    has_perm = RBACService.has_global_permission(db, current_user, "audit:read")
    if not has_perm:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission Denied: Audit verification requires Platform Auditor or Administrator role."
        )

    is_valid, issues = AuditService.verify_chain_integrity(db)
    total_records = db.query(SystemAuditLog).count()

    return {
        "status": "VALID" if is_valid else "TAMPER_DETECTED",
        "is_valid": is_valid,
        "total_records_checked": total_records,
        "issues": issues,
        "verified_at": datetime.utcnow().isoformat()
    }


@router.get("/reconciliation", summary="Audit Dual-Store Reconciliation Status")
def get_reconciliation_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns dual-store reconciliation status between SQLite and the external JSONL ledger.
    Requires global audit:read permission.
    """
    has_perm = RBACService.has_global_permission(db, current_user, "audit:read")
    if not has_perm:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission Denied: Reconciliation status requires Platform Auditor or Administrator role."
        )

    return AuditService.reconcile_audit_stores(db)
