"""
Cases API Router for HMACFR.
Implements granular case access authorization, member segregation,
and administrative deletion resolution under the RBAC model.
"""

import os
import json
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, status, Query, Path as FastAPIPath
from sqlalchemy.orm import Session

from app.db.connection import get_db
from app.db.models import Evidence, Case
from app.db.models.case_assignment import CaseMember, CaseMemberResponsibility
from app.db.schemas import (
    CaseCreate, CaseUpdate, CaseResponse, EvidenceListItem,
    CaseDeletionRequestInput, CaseDeletionResolutionInput,
    CaseMemberAssignmentInput, CaseMemberResponse, EvidenceGraphResponse
)
from app.services.case_service import CaseService
from app.services.rbac_service import RBACService
from app.services.audit_service import AuditService
from app.services.graph_service import EvidenceGraphService
from app.api.dependencies import get_current_user, require_admin_access
from app.db.models.user import User
from app.core.logger import log_app_event

router = APIRouter()


@router.post("/", response_model=CaseResponse, status_code=status.HTTP_201_CREATED)
def create_case(
    case_in: CaseCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Create a new investigation case.
    Automatically establishes case membership and primary responsibilities
    (Lead Investigator, Investigator, Forensic Analyst) for the creating user.
    """
    # If investigator_name not specified, default to current_user.username
    if not case_in.investigator_name:
        case_in.investigator_name = current_user.username

    created_case = CaseService.create_case(db=db, case_in=case_in)

    # Assign creator as Lead Investigator
    RBACService.assign_case_creator(db=db, case_id=created_case.case_id, user_id=current_user.user_id)

    # Record audit event
    try:
        AuditService.record_event(
            db=db,
            action="CASE_CREATE",
            target_resource="case",
            user_id=current_user.user_id,
            username=current_user.username,
            resource_id=created_case.case_id,
            case_id=created_case.case_id,
            details=f"Case '{created_case.case_name}' created by {current_user.username}."
        )
    except Exception as e:
        log_app_event(f"Audit event recording skipped: {e}")

    return created_case


@router.get("/", response_model=List[CaseResponse])
def list_cases(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    List investigation cases.
    Administrators and Platform Auditors see all cases.
    Investigators and Analysts see only cases where they are assigned members.
    """
    accessible_ids = RBACService.get_accessible_case_ids(db, current_user)
    if accessible_ids is None:
        # Global view
        return CaseService.list_cases(db=db, skip=skip, limit=limit)

    # Member-restricted view
    cases = db.query(Case).filter(Case.case_id.in_(accessible_ids)).offset(skip).limit(limit).all()
    return cases


@router.get("/{id}", response_model=CaseResponse)
def get_case(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get details of a specific investigation case by CaseID.
    Enforces case-level read authorization.
    """
    case_obj = CaseService.get_case(db=db, case_id=id)
    if not case_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{id}' not found"
        )

    if not RBACService.check_case_access(db, current_user, id, permission="case:read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission Denied: You do not have access to Case '{id}'."
        )

    return case_obj


@router.get("/{id}/evidence", response_model=List[EvidenceListItem])
def list_case_evidence(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    List all evidence items associated with a specific investigation case.
    Enforces case-level evidence read authorization.
    """
    case_obj = CaseService.get_case(db=db, case_id=id)
    if not case_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{id}' not found"
        )

    if not RBACService.check_case_access(db, current_user, id, permission="evidence:read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission Denied: You do not have access to evidence in Case '{id}'."
        )

    evidences = db.query(Evidence).filter(Evidence.case_id == id).all()
    return evidences


@router.put("/{id}", response_model=CaseResponse)
def update_case(
    id: str,
    case_in: CaseUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Update details of an existing investigation case.
    Requires case update permission (Lead Investigator, Investigator, or Administrator).
    """
    case_obj = CaseService.get_case(db=db, case_id=id)
    if not case_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{id}' not found"
        )

    if not RBACService.check_case_access(db, current_user, id, permission="case:update"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission Denied: You do not have update permissions on Case '{id}'."
        )

    updated = CaseService.update_case(db=db, case_id=id, case_in=case_in)

    try:
        AuditService.record_event(
            db=db,
            action="CASE_UPDATE",
            target_resource="case",
            user_id=current_user.user_id,
            username=current_user.username,
            resource_id=id,
            case_id=id,
            details=f"Case '{id}' updated by {current_user.username}."
        )
    except Exception as e:
        log_app_event(f"Audit event recording skipped: {e}")

    return updated


@router.post("/{id}/request-deletion", response_model=CaseResponse)
def request_case_deletion(
    id: str,
    payload: CaseDeletionRequestInput,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Submits a formal Case Deletion Request to the Administrator.
    Requires case deletion request permission.
    """
    case_obj = CaseService.get_case(db=db, case_id=id)
    if not case_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{id}' not found"
        )

    if not RBACService.check_case_access(db, current_user, id, permission="case:request_deletion"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission Denied: You do not have permission to request deletion of Case '{id}'."
        )

    case_in = CaseUpdate(
        status="PENDING_DELETION",
        deletion_reason=payload.reason,
        deletion_requested_by=current_user.username
    )
    updated_case = CaseService.update_case(db=db, case_id=id, case_in=case_in)

    try:
        AuditService.record_event(
            db=db,
            action="CASE_DELETION_REQUEST",
            target_resource="case",
            user_id=current_user.user_id,
            username=current_user.username,
            resource_id=id,
            case_id=id,
            details=f"Deletion requested for Case '{id}' with reason: {payload.reason}."
        )
    except Exception as e:
        log_app_event(f"Audit event recording skipped: {e}")

    return updated_case


@router.get("/deletion-requests/pending", response_model=List[CaseResponse])
def list_pending_deletion_requests(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_access)
):
    """
    Lists all investigation cases with pending deletion requests awaiting Administrator review.
    Requires Administrative privileges under RBAC.
    """
    cases = db.query(Case).filter(Case.status == "PENDING_DELETION").all()
    return cases


@router.post("/{id}/deletion-resolution")
def resolve_case_deletion(
    id: str,
    payload: CaseDeletionResolutionInput,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_access)
):
    """
    Admin Resolution Endpoint for pending case deletion requests.
    Strictly requires Administrator privileges under RBAC.
    Action = 'APPROVE' -> Permanently purges physical files & DB records.
    Action = 'REJECT' -> Restores case status to Active and clears deletion reason.
    """
    case_obj = CaseService.get_case(db=db, case_id=id)
    if not case_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{id}' not found"
        )

    action = (payload.action or "").upper()
    if action == "APPROVE":
        CaseService.delete_or_archive_case(db=db, case_id=id, archive_only=False)
        try:
            AuditService.record_event(
                db=db,
                action="CASE_DELETION_RESOLVED_APPROVED",
                target_resource="case",
                user_id=current_user.user_id,
                username=current_user.username,
                resource_id=id,
                case_id=id,
                details=f"Case '{id}' deletion APPROVED and permanently purged by Administrator {current_user.username}."
            )
        except Exception as e:
            log_app_event(f"Audit event recording skipped: {e}")

        return {
            "status": "APPROVED",
            "case_id": id,
            "message": f"Case '{id}' deletion request APPROVED by Admin. Physical files and database records permanently purged."
        }
    elif action == "REJECT":
        case_in = CaseUpdate(status="Active", deletion_reason=None, deletion_requested_by=None)
        CaseService.update_case(db=db, case_id=id, case_in=case_in)
        try:
            AuditService.record_event(
                db=db,
                action="CASE_DELETION_RESOLVED_REJECTED",
                target_resource="case",
                user_id=current_user.user_id,
                username=current_user.username,
                resource_id=id,
                case_id=id,
                details=f"Case '{id}' deletion REJECTED and restored to Active by Administrator {current_user.username}."
            )
        except Exception as e:
            log_app_event(f"Audit event recording skipped: {e}")

        return {
            "status": "REJECTED",
            "case_id": id,
            "message": f"Case '{id}' deletion request REJECTED by Admin. Case status restored to Active."
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid resolution action. Expected 'APPROVE' or 'REJECT'."
        )


@router.delete("/{id}")
def delete_or_archive_case(
    id: str,
    archive_only: bool = Query(False, description="Set to False to permanently purge case and all evidence data"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin_access)
):
    """
    Archive or permanently purge an investigation case and all associated evidence files/records.
    Strictly requires Administrator privileges under RBAC.
    """
    case_obj = CaseService.delete_or_archive_case(db=db, case_id=id, archive_only=archive_only)
    if not case_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{id}' not found"
        )

    try:
        AuditService.record_event(
            db=db,
            action="CASE_ARCHIVE" if archive_only else "CASE_PURGE",
            target_resource="case",
            user_id=current_user.user_id,
            username=current_user.username,
            resource_id=id,
            case_id=id,
            details=f"Case '{id}' {'archived' if archive_only else 'permanently purged'} by Administrator {current_user.username}."
        )
    except Exception as e:
        log_app_event(f"Audit event recording skipped: {e}")

    return {
        "case_id": id,
        "status": "Archived" if archive_only else "Purged",
        "message": f"Case '{id}' and all associated physical evidence files successfully {'archived' if archive_only else 'purged'}."
    }


@router.get("/{id}/members", response_model=List[CaseMemberResponse])
def list_case_members(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    List all assigned members and their responsibilities for an investigation case.
    Requires case:read permission or global admin privilege.
    """
    case_obj = CaseService.get_case(db=db, case_id=id)
    if not case_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case with ID '{id}' not found")

    if not RBACService.check_case_access(db, current_user, id, permission="case:read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission Denied: You do not have access to Case '{id}'."
        )

    members = db.query(CaseMember).filter(CaseMember.case_id == id).all()
    results = []
    for m in members:
        u = db.query(User).filter(User.user_id == m.user_id).first()
        resps = [r.responsibility_name for r in m.responsibilities]
        results.append(CaseMemberResponse(
            id=m.id,
            case_id=m.case_id,
            user_id=m.user_id,
            username=u.username if u else m.user_id,
            assigned_at=m.assigned_at,
            responsibilities=resps
        ))
    return results


@router.get("/{id}/my-permissions")
def get_my_case_permissions(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns effective permissions, responsibilities, and role status for the calling user on a specific case.
    Used for instant dynamic UI gating without requiring logout/login.
    """
    case_obj = CaseService.get_case(db=db, case_id=id)
    if not case_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case with ID '{id}' not found")

    roles = RBACService.get_user_global_roles(db, current_user.user_id)
    is_admin = RBACService.has_global_admin_access(db, current_user)
    is_super_admin = "Platform Super Admin" in roles
    is_platform_auditor = "Platform Auditor" in roles

    member = db.query(CaseMember).filter(CaseMember.case_id == id, CaseMember.user_id == current_user.user_id).first()
    responsibilities = []
    if member:
        responsibilities = [r.responsibility_name for r in member.responsibilities]

    # Resolve all permissions
    all_possible_perms = [
        "case:read", "case:update", "case:request_deletion", "case:assign_members",
        "evidence:read", "evidence:upload", "evidence:preserve",
        "analysis:run", "analysis:read", "report:generate", "report:read", "report:approve",
        "custody:read"
    ]
    granted_perms = []
    for p in all_possible_perms:
        if p == "case:assign_members":
            if is_admin or "Lead Investigator" in responsibilities:
                granted_perms.append(p)
        elif RBACService.check_case_access(db, current_user, id, permission=p):
            granted_perms.append(p)

    is_creator = (case_obj.investigator_name == current_user.username) or (member and member.assigned_by == current_user.user_id)

    return {
        "case_id": id,
        "user_id": current_user.user_id,
        "username": current_user.username,
        "global_roles": roles,
        "responsibilities": responsibilities,
        "permissions": granted_perms,
        "is_lead": "Lead Investigator" in responsibilities or is_admin,
        "is_admin": is_admin,
        "is_super_admin": is_super_admin,
        "is_platform_auditor": is_platform_auditor,
        "is_creator": is_creator,
        "creator_name": case_obj.investigator_name,
        "created_at": case_obj.created_at.isoformat() if case_obj.created_at else None,
        "vault_status": getattr(case_obj, "vault_status", "OPEN"),
        "vault_locked_at": case_obj.vault_locked_at.isoformat() if getattr(case_obj, "vault_locked_at", None) else None,
        "vault_locked_by": getattr(case_obj, "vault_locked_by", None),
        "vault_unlock_reason": getattr(case_obj, "vault_unlock_reason", None)
    }


@router.post("/{id}/members", response_model=CaseMemberResponse)
def assign_case_member(
    id: str,
    payload: CaseMemberAssignmentInput,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Assign a user to a case with specific case responsibilities, or update their responsibilities.
    Requires Lead Investigator status on this case or Administrative privileges under RBAC.
    Enforces Protected Succession: prevents demoting the last Lead Investigator.
    """
    case_obj = CaseService.get_case(db=db, case_id=id)
    if not case_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case with ID '{id}' not found")

    is_admin = RBACService.has_global_admin_access(db, current_user)
    is_lead = RBACService.check_case_access(db, current_user, id, permission="case:update")
    if not (is_admin or is_lead):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission Denied: Only Lead Investigators or Administrators can assign team members."
        )

    target_user = db.query(User).filter(User.user_id == payload.user_id).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User '{payload.user_id}' not found")

    import uuid
    member = db.query(CaseMember).filter(CaseMember.case_id == id, CaseMember.user_id == payload.user_id).first()
    if not member:
        member = CaseMember(
            id=f"MBR_{uuid.uuid4().hex[:12]}",
            case_id=id,
            user_id=payload.user_id,
            assigned_by=current_user.user_id
        )
        db.add(member)
        db.flush()
    else:
        # Check if we are demoting an existing Lead Investigator
        is_currently_lead = db.query(CaseMemberResponsibility).filter(
            CaseMemberResponsibility.case_member_id == member.id,
            CaseMemberResponsibility.responsibility_name == "Lead Investigator"
        ).first() is not None

        will_be_lead = "Lead Investigator" in payload.responsibilities
        if is_currently_lead and not will_be_lead:
            other_leads_count = (
                db.query(CaseMemberResponsibility)
                .join(CaseMember, CaseMember.id == CaseMemberResponsibility.case_member_id)
                .filter(
                    CaseMember.case_id == id,
                    CaseMember.id != member.id,
                    CaseMemberResponsibility.responsibility_name == "Lead Investigator"
                )
                .count()
            )
            if other_leads_count == 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot demote the only Lead Investigator on the case. Assign another Lead Investigator first."
                )

    # Clear and replace responsibilities
    db.query(CaseMemberResponsibility).filter(CaseMemberResponsibility.case_member_id == member.id).delete()
    for resp_name in payload.responsibilities:
        clean_resp = resp_name.strip()
        if clean_resp:
            db.add(CaseMemberResponsibility(
                id=f"RES_{uuid.uuid4().hex[:12]}",
                case_member_id=member.id,
                responsibility_name=clean_resp
            ))
    db.commit()
    db.refresh(member)

    # Invalidate user session version so permissions re-evaluate dynamically
    target_user.token_version = (target_user.token_version or 1) + 1
    db.commit()

    try:
        AuditService.record_event(
            db=db,
            action="CASE_MEMBER_ASSIGN",
            target_resource="case_member",
            user_id=current_user.user_id,
            username=current_user.username,
            resource_id=member.id,
            case_id=id,
            details=f"Assigned user {target_user.username} to Case {id} with responsibilities: {payload.responsibilities}"
        )
    except Exception as e:
        log_app_event(f"Audit event recording skipped: {e}")

    return CaseMemberResponse(
        id=member.id,
        case_id=member.case_id,
        user_id=member.user_id,
        username=target_user.username,
        assigned_at=member.assigned_at,
        responsibilities=payload.responsibilities
    )


@router.delete("/{id}/members/{user_id}")
def remove_case_member(
    id: str,
    user_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Remove a member from an investigation case.
    Requires Lead Investigator status on this case or Administrative privileges under RBAC.
    Enforces Protected Succession: prevents removing the last Lead Investigator.
    """
    case_obj = CaseService.get_case(db=db, case_id=id)
    if not case_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case with ID '{id}' not found")

    is_admin = RBACService.has_global_admin_access(db, current_user)
    is_lead = RBACService.check_case_access(db, current_user, id, permission="case:update")
    if not (is_admin or is_lead):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission Denied: Only Lead Investigators or Administrators can remove team members."
        )

    member = db.query(CaseMember).filter(CaseMember.case_id == id, CaseMember.user_id == user_id).first()
    if not member:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found on this case")

    # Protected Succession: check if removing this member leaves the case without any Lead Investigator
    is_member_lead = db.query(CaseMemberResponsibility).filter(
        CaseMemberResponsibility.case_member_id == member.id,
        CaseMemberResponsibility.responsibility_name == "Lead Investigator"
    ).first() is not None

    if is_member_lead:
        other_leads_count = (
            db.query(CaseMemberResponsibility)
            .join(CaseMember, CaseMember.id == CaseMemberResponsibility.case_member_id)
            .filter(
                CaseMember.case_id == id,
                CaseMember.id != member.id,
                CaseMemberResponsibility.responsibility_name == "Lead Investigator"
            )
            .count()
        )
        if other_leads_count == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot remove the only Lead Investigator from the case. Assign another Lead Investigator first."
            )

    db.delete(member)
    db.commit()

    target_user = db.query(User).filter(User.user_id == user_id).first()
    if target_user:
        target_user.token_version = (target_user.token_version or 1) + 1
        db.commit()

    try:
        AuditService.record_event(
            db=db,
            action="CASE_MEMBER_REMOVE",
            target_resource="case_member",
            user_id=current_user.user_id,
            username=current_user.username,
            resource_id=user_id,
            case_id=id,
            details=f"Removed user {user_id} from Case {id}"
        )
    except Exception as e:
        log_app_event(f"Audit event recording skipped: {e}")

    return {"status": "SUCCESS", "message": f"User '{user_id}' removed from Case '{id}'."}


@router.get("/{id}/extracted-artifacts")
def get_case_extracted_artifacts(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get all finalized JSON artifact extraction files for a case grouped by the 5 specialized Domain Agents.
    Scans extracted_artifacts/<domain>/, filtering for final .json files only.
    Excludes all intermediate carve buffers and temporary dump files.
    """
    if not RBACService.check_case_access(db, current_user, id, permission="evidence:read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission Denied: You do not have access to Case '{id}'."
        )

    from app.services.supervisor_service import SupervisorService
    return SupervisorService.get_case_artifacts_tree(case_id=id)


@router.get("/{id}/supervisor/status")
def get_case_supervisor_status(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get orchestration manifest, active agents, and model adapter status for a case.
    """
    if not RBACService.check_case_access(db, current_user, id, permission="evidence:read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission Denied: You do not have access to Case '{id}'."
        )

    from app.services.supervisor_service import SupervisorService
    from app.services.model_adapter_service import ModelAdapterService

    artifacts_tree = SupervisorService.get_case_artifacts_tree(case_id=id)
    adapter_status = ModelAdapterService.get_status()

    return {
        "status": "SUCCESS",
        "case_id": id,
        "supervisor_manifest": artifacts_tree.get("summary") or {},
        "adapter_status": adapter_status,
        "total_artifacts": artifacts_tree.get("total_artifacts", 0),
        "categories": artifacts_tree.get("categories", [])
    }


@router.get("/models/adapters/status")
def get_model_adapters_global_status(
    current_user: User = Depends(get_current_user)
):
    """
    Get status of Qwen base adapter and the 5 domain LoRA adapters.
    """
    from app.services.model_adapter_service import ModelAdapterService
    return {
        "status": "SUCCESS",
        "adapters": ModelAdapterService.get_status()
    }


class ColabBridgeRequest(BaseModel):
    colab_url: Optional[str] = None


@router.get("/models/colab-bridge")
def get_colab_bridge_status(
    current_user: User = Depends(get_current_user)
):
    """
    Get current Google Colab GPU Bridge URL and connectivity status.
    """
    import urllib.request
    from app.services.model_adapter_service import ModelAdapterService
    
    current_url = ModelAdapterService.get_remote_gpu_url()
    connected = False
    ping_info = None
    
    if current_url:
        for probe_path in ["/health", "/"]:
            try:
                req = urllib.request.Request(
                    f"{current_url.rstrip('/')}{probe_path}",
                    headers={"User-Agent": "SherlockAI-Client"}
                )
                with urllib.request.urlopen(req, timeout=4) as resp:
                    if resp.status == 200:
                        connected = True
                        ping_info = json.loads(resp.read().decode("utf-8"))
                        break
            except Exception as e:
                ping_info = {"error": str(e)}

    return {
        "status": "SUCCESS",
        "colab_url": current_url,
        "is_connected": connected,
        "mode": "Google Colab Cloud GPU" if connected else "Local Air-Gapped Cognitive Engine",
        "health": ping_info
    }


@router.post("/models/colab-bridge")
def set_colab_bridge_url(
    req: ColabBridgeRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Set or update Google Colab GPU Bridge URL and verify connection.
    """
    import urllib.request
    from app.services.model_adapter_service import ModelAdapterService

    url = (req.colab_url or "").strip()
    if not url:
        ModelAdapterService.set_remote_gpu_url(None)
        return {
            "status": "SUCCESS",
            "message": "Colab GPU Bridge disabled. Switched to Local Air-Gapped Engine.",
            "colab_url": None,
            "is_connected": False,
            "mode": "Local Air-Gapped Cognitive Engine"
        }

    ModelAdapterService.set_remote_gpu_url(url)
    connected = False
    details = {}
    for probe_path in ["/health", "/"]:
        try:
            test_req = urllib.request.Request(
                f"{url.rstrip('/')}{probe_path}",
                headers={"User-Agent": "SherlockAI-Client"}
            )
            with urllib.request.urlopen(test_req, timeout=5) as resp:
                if resp.status == 200:
                    connected = True
                    details = json.loads(resp.read().decode("utf-8"))
                    break
        except Exception as e:
            details = {"error": f"Failed to reach Colab endpoint {probe_path}: {str(e)}"}

    return {
        "status": "SUCCESS",
        "colab_url": url,
        "is_connected": connected,
        "mode": "Google Colab Cloud GPU" if connected else "Local Air-Gapped Cognitive Engine (Fallback)",
        "details": details
    }



@router.get("/{id}/extracted-artifacts/view")
def view_case_artifact_content(
    id: str,
    file_path: str = Query(..., description="Relative path of JSON artifact"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Read and return parsed JSON content of a specific final extracted artifact file.
    Prevents path traversal and strictly validates file extension.
    """
    if not RBACService.check_case_access(db, current_user, id, permission="evidence:read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission Denied: You do not have access to Case '{id}'."
        )

    import os, json
    from pathlib import Path

    clean_rel = file_path.replace("\\", "/").strip("/")
    if ".." in clean_rel or not clean_rel.lower().endswith(".json"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid file path.")

    project_root = Path(__file__).resolve().parents[5]
    backend_root = Path(__file__).resolve().parents[3]
    candidate_dirs = [
        backend_root / "output" / "cases" / id,
        project_root / "prot1-main" / "output" / "cases" / id,
        project_root / "output" / "cases" / id,
        backend_root.parent / "dist" / "SherlockAI" / "_internal" / "backend" / "output" / "cases" / id,
        Path(__file__).resolve().parents[2] / "data" / "extracted" / id
    ]

    target_file = None
    for c_dir in candidate_dirs:
        p = c_dir / clean_rel
        if p.exists() and p.is_file():
            target_file = p
            break

    if not target_file:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Artifact file '{clean_rel}' not found.")

    try:
        with open(target_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {
            "case_id": id,
            "filename": os.path.basename(clean_rel),
            "rel_path": clean_rel,
            "data": data
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error reading artifact JSON: {str(e)}")


@router.post("/{id}/extract")
def run_case_artifact_extraction(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Trigger real forensic artifact extraction via PluginManager for all evidence in this case.
    """
    if not RBACService.check_case_access(db, current_user, id, permission="extraction:execute"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission Denied: You do not have extraction permission on Case '{id}'."
        )

    case_obj = CaseService.get_case(db=db, case_id=id)
    if not case_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{id}' not found")

    evidences = db.query(Evidence).filter(Evidence.case_id == id).all()
    if not evidences:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No evidence files registered in this case to extract.")

    import sys
    from pathlib import Path
    project_root = Path(__file__).resolve().parents[5]
    prot1_root = project_root / "prot1-main"
    pm_root = prot1_root / "artifact_extraction" / "plugin_manager"

    try:
        from app.services.supervisor_service import SupervisorService
        registered = []
        for ev in evidences:
            if ev.storage_path and os.path.exists(ev.storage_path):
                registered.append({
                    "path": ev.storage_path,
                    "type": ev.type,
                    "name": ev.original_filename,
                    "evidence_id": ev.evidence_id
                })

        manifest = SupervisorService.orchestrate_case_extraction(case_id=id, evidence_list=registered)

        AuditService.record_event(
            db=db,
            action="ARTIFACT_EXTRACTION_EXECUTE",
            target_resource="extraction",
            user_id=current_user.user_id,
            username=current_user.username,
            resource_id=id,
            case_id=id,
            details=f"Artifact extraction orchestrated across 5 domain agents for Case '{id}' by {current_user.username}."
        )

        return {
            "status": "SUCCESS",
            "case_id": id,
            "evidence_count": len(registered),
            "manifest": manifest,
            "summary": manifest
        }
    except Exception as ex:
        log_app_event(f"Error in run_case_artifact_extraction: {ex}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Extraction engine error: {str(ex)}")


class VaultUnlockPayload(BaseModel):
    reason: Optional[str] = "Insufficient evidence identified during investigation analysis"


@router.post("/{id}/vault/lock")
def lock_case_vault(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Lock the Evidence Vault for an investigation case.
    Prevents further uploads, deletions, or staging changes.
    Enforces forensic immutability before Agent Analysis.
    Requires Lead Investigator or Administrator privileges.
    """
    case_obj = CaseService.get_case(db=db, case_id=id)
    if not case_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{id}' not found")

    is_admin = RBACService.has_global_admin_access(db, current_user)
    is_lead = RBACService.check_case_access(db, current_user, id, permission="case:update")
    if not (is_admin or is_lead):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission Denied: Only Lead Investigators or Admins can lock the evidence vault.")

    now = datetime.utcnow()
    case_obj.vault_status = "LOCKED"
    case_obj.vault_locked_at = now
    case_obj.vault_locked_by = current_user.username
    db.commit()
    db.refresh(case_obj)

    try:
        AuditService.record_event(
            db=db,
            action="VAULT_LOCK",
            target_resource="evidence_vault",
            user_id=current_user.user_id,
            username=current_user.username,
            resource_id=id,
            case_id=id,
            details=f"Evidence vault sealed and locked for Case '{id}' by {current_user.username}."
        )
    except Exception as e:
        log_app_event(f"Audit log skipped: {e}")

    return {
        "status": "SUCCESS",
        "case_id": id,
        "vault_status": "LOCKED",
        "locked_at": case_obj.vault_locked_at.isoformat() if case_obj.vault_locked_at else None,
        "locked_by": case_obj.vault_locked_by
    }


@router.post("/{id}/vault/unlock")
def unlock_case_vault(
    id: str,
    payload: Optional[VaultUnlockPayload] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Reopen the Evidence Vault when additional artifacts are needed (e.g. INSUFFICIENT_EVIDENCE flagged by agents).
    Requires Lead Investigator or Administrator privileges and records mandatory reason to audit ledger.
    """
    case_obj = CaseService.get_case(db=db, case_id=id)
    if not case_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{id}' not found")

    is_admin = RBACService.has_global_admin_access(db, current_user)
    is_lead = RBACService.check_case_access(db, current_user, id, permission="case:update")
    if not (is_admin or is_lead):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission Denied: Only Lead Investigators or Admins can unlock the evidence vault.")

    reason = payload.reason if (payload and payload.reason) else "Insufficient evidence identified during investigation analysis"
    case_obj.vault_status = "OPEN"
    case_obj.vault_unlock_reason = reason
    db.commit()
    db.refresh(case_obj)

    try:
        AuditService.record_event(
            db=db,
            action="VAULT_UNLOCK",
            target_resource="evidence_vault",
            user_id=current_user.user_id,
            username=current_user.username,
            resource_id=id,
            case_id=id,
            details=f"Evidence vault reopened for Case '{id}' by {current_user.username}. Reason: {reason}"
        )
    except Exception as e:
        log_app_event(f"Audit log skipped: {e}")

    return {
        "status": "SUCCESS",
        "case_id": id,
        "vault_status": "OPEN",
        "unlocked_by": current_user.username,
        "reason": reason
    }


@router.post("/{id}/evidence/{evidence_id}/extract")
def extract_single_evidence(
    id: str,
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Triggers real forensic artifact extraction via PluginManager for a single independent evidence item.
    """
    case_obj = CaseService.get_case(db=db, case_id=id)
    if not case_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{id}' not found")

    if not RBACService.check_case_access(db, current_user, id, permission="analysis:run"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission Denied.")

    ev = db.query(Evidence).filter(Evidence.case_id == id, Evidence.evidence_id == evidence_id).first()
    if not ev:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Evidence '{evidence_id}' not found on Case '{id}'.")

    from app.services.supervisor_service import SupervisorService
    registered = [{
        "path": ev.storage_path,
        "type": ev.type,
        "name": ev.original_filename,
        "evidence_id": ev.evidence_id
    }]
    manifest = SupervisorService.orchestrate_case_extraction(case_id=id, evidence_list=registered)

    return {
        "status": "SUCCESS",
        "case_id": id,
        "evidence_id": evidence_id,
        "filename": ev.original_filename,
        "manifest": manifest
    }


@router.get("/{id}/evidence/{evidence_id}/artifacts")
def get_evidence_artifacts(
    id: str,
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns extracted forensic artifacts and details for a specific evidence file.
    """
    if not RBACService.check_case_access(db, current_user, id, permission="case:read"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission Denied.")

    ev = db.query(Evidence).filter(Evidence.case_id == id, Evidence.evidence_id == evidence_id).first()
    if not ev:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Evidence '{evidence_id}' not found.")

    from app.services.synthesizer_service import ForensicSynthesizerService
    synth = ForensicSynthesizerService.get_synthesized_case(id) or {}
    findings = [f for f in synth.get("findings", []) if f.get("source_file") == ev.original_filename or f.get("evidence_id") == evidence_id]

    return {
        "status": "SUCCESS",
        "case_id": id,
        "evidence_id": evidence_id,
        "filename": ev.original_filename,
        "type": ev.type,
        "findings_count": len(findings),
        "artifacts": findings
    }


@router.delete("/{id}/evidence/{evidence_id}")
def delete_case_evidence(
    id: str,
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Deletes an un-locked evidence item from an active case.
    Strictly forbidden if the case vault is in LOCKED state.
    """
    case_obj = CaseService.get_case(db=db, case_id=id)
    if not case_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{id}' not found")

    if not RBACService.check_case_access(db, current_user, id, permission="case:update"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission Denied.")

    if getattr(case_obj, "vault_status", "OPEN") == "LOCKED":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete evidence: Evidence Vault is LOCKED. Unlock vault first to remove items."
        )

    ev = db.query(Evidence).filter(Evidence.case_id == id, Evidence.evidence_id == evidence_id).first()
    if not ev:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Evidence '{evidence_id}' not found on Case '{id}'.")

    # Remove physical file if present
    if ev.storage_path and os.path.exists(ev.storage_path):
        try:
            os.remove(ev.storage_path)
        except Exception as e:
            log_app_event(f"Notice: failed to remove physical file {ev.storage_path}: {e}")

    filename = ev.original_filename
    db.delete(ev)
    db.commit()

    try:
        AuditService.record_event(
            db=db,
            action="EVIDENCE_DELETE",
            target_resource="evidence",
            user_id=current_user.user_id,
            username=current_user.username,
            resource_id=evidence_id,
            case_id=id,
            details=f"Deleted evidence '{filename}' ({evidence_id}) from Case '{id}'."
        )
    except Exception as e:
        log_app_event(f"Audit log skipped: {e}")

    return {"status": "SUCCESS", "message": f"Evidence '{filename}' deleted from Case '{id}'."}


class SISReviewRequest(BaseModel):
    action: str
    notes: Optional[str] = None


@router.get("/{id}/sis")
def get_case_sis_state(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Returns the Structured Investigation State (SIS) for a case.
    """
    if not RBACService.check_case_access(db, current_user, id, permission="analysis:read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission Denied: You do not have access to Case '{id}'."
        )

    from app.services.synthesizer_service import ForensicSynthesizerService
    sis = ForensicSynthesizerService.get_sis_state(id)
    if not sis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SIS state not found for Case '{id}'. Please run analysis first."
        )
    return sis


@router.post("/{id}/sis/review")
def review_case_sis_state(
    id: str,
    req: SISReviewRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Human-in-the-Loop Review Station: Approve or Reject the Structured Investigation State.
    """
    if not RBACService.check_case_access(db, current_user, id, permission="case:update"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission Denied: You do not have permission to review Case '{id}'."
        )

    from app.services.synthesizer_service import ForensicSynthesizerService
    try:
        updated_sis = ForensicSynthesizerService.update_sis_review(
            case_id=id,
            action=req.action,
            reviewer=current_user.username,
            notes=req.notes
        )

        AuditService.record_event(
            db=db,
            action=f"SIS_REVIEW_{req.action.upper()}",
            target_resource="sis_state",
            user_id=current_user.user_id,
            username=current_user.username,
            resource_id=id,
            case_id=id,
            details=f"Investigator {current_user.username} marked SIS state as {req.action.upper()} with notes: {req.notes or 'None'}"
        )

        return {
            "status": "SUCCESS",
            "message": f"SIS state successfully updated to {updated_sis.get('investigation_status')}.",
            "sis": updated_sis
        }
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as ex:
        log_app_event(f"Error in review_case_sis_state: {ex}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Review error: {str(ex)}")


@router.get(
    "/{case_id}/graph",
    response_model=EvidenceGraphResponse,
    summary="Get Case Evidence Graph",
    tags=["Cases", "Evidence Graph"]
)
def get_case_evidence_graph(
    case_id: str = FastAPIPath(..., description="Unique investigation case ID"),
    include_noise: bool = Query(True, description="Whether to include coincidental noise and ambiguous non-causal associations"),
    min_confidence: float = Query(0.0, ge=0.0, le=1.0, description="Minimum confidence threshold in [0.0, 1.0]"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieves the Forensic Evidence Graph for a specific investigation case.
    Enforces case-level read authorization ('case:read').
    Supports non-destructive in-memory filtering by noise and confidence.
    """
    case_obj = CaseService.get_case(db=db, case_id=case_id)
    if not case_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' not found"
        )

    if not RBACService.check_case_access(db, current_user, case_id, permission="case:read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission Denied: You do not have access to Case '{case_id}'."
        )

    try:
        graph_data = EvidenceGraphService.get_case_evidence_graph_data(
            case_id=case_id,
            include_noise=include_noise,
            min_confidence=min_confidence
        )
        return graph_data
    except Exception as ex:
        log_app_event(f"Error retrieving evidence graph for Case {case_id}: {ex}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate evidence graph: {str(ex)}"
        )


@router.post(
    "/{case_id}/correlation/run",
    summary="Run Hybrid Neuro-Symbolic Correlation Engine",
    tags=["Cases", "Correlation"]
)
def run_case_correlation(
    case_id: str = FastAPIPath(..., description="Unique investigation case ID"),
    invoke_supervisor: bool = Query(True, description="Whether to invoke Supervisor LLM for cross-domain hypothesis generation"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Executes the Hybrid Neuro-Symbolic Correlation Engine:
    1. Consumes specialist findings across the 5 domains (Network, Memory, Disk, Logs, Registry).
    2. Runs deterministic candidate generation via 6 Explainable Forensic Rules.
    3. Triggers Supervisor LLM on remote GPU for cross-domain hypothesis reasoning.
    4. Enforces independent validation: rejects fabricated IDs, verifies evidence references.
    5. Outputs multi-tier explainable graph, unified timeline, and incident narrative.
    """
    case_obj = CaseService.get_case(db=db, case_id=case_id)
    if not case_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case with ID '{case_id}' not found")

    if not RBACService.check_case_access(db, current_user, case_id, permission="analysis:run"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission Denied: Requires analysis:run permission to execute hybrid correlation."
        )

    from app.services.synthesizer_service import ForensicSynthesizerService
    from app.services.correlation_engine import ExplainableCorrelationEngine
    from pathlib import Path

    case_dir = ForensicSynthesizerService.get_case_output_dir(case_id)
    findings = []

    # 1. Look for existing findings in synthesized report
    synth = ForensicSynthesizerService.get_synthesized_case(case_id)
    if synth and synth.get("findings"):
        findings = synth["findings"]
    elif case_dir.exists():
        # Fallback to synthesizing case on the fly
        try:
            synth = ForensicSynthesizerService.synthesize_case(case_id)
            findings = synth.get("findings", [])
        except Exception as se:
            log_app_event(f"On-demand synthesis note for {case_id}: {se}")

    # 2. Check if case has specialized agent output findings on disk
    agent_findings_dir = case_dir / "findings"
    if agent_findings_dir.exists() and agent_findings_dir.is_dir():
        for fpath in agent_findings_dir.glob("*.json"):
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        findings.extend(data)
                    elif isinstance(data, dict):
                        findings.append(data)
            except Exception:
                pass

    # 3. Execute hybrid correlation
    correlation_result = ExplainableCorrelationEngine.correlate_case_findings(
        findings=findings,
        case_id=case_id,
        case_context={"case_id": case_id, "case_name": case_obj.case_name},
        invoke_supervisor=invoke_supervisor
    )

    # 4. Persist correlation output
    case_dir.mkdir(parents=True, exist_ok=True)
    corr_file = case_dir / "correlation_results.json"
    try:
        with open(corr_file, "w", encoding="utf-8") as f:
            json.dump(correlation_result, f, indent=2, default=str)
    except Exception as we:
        log_app_event(f"Failed to write correlation_results.json: {we}")

    # Record audit event
    try:
        AuditService.record_event(
            db=db,
            action="RUN_HYBRID_CORRELATION",
            target_resource="correlation_engine",
            user_id=current_user.user_id,
            username=current_user.username,
            resource_id=case_id,
            case_id=case_id,
            details=f"Hybrid correlation executed on {len(findings)} findings. Generated {correlation_result.get('total_correlations')} edges."
        )
    except Exception:
        pass

    return {
        "status": "SUCCESS",
        "case_id": case_id,
        "total_findings": correlation_result.get("total_findings", 0),
        "total_correlations": correlation_result.get("total_correlations", 0),
        "epistemic_summary": correlation_result.get("epistemic_summary", {}),
        "correlation_edges": correlation_result.get("correlation_edges", []),
        "evidence_graph": correlation_result.get("evidence_graph", {}),
        "unified_timeline": correlation_result.get("unified_timeline", []),
        "incident_narrative": correlation_result.get("incident_narrative", ""),
        "supervisor_telemetry": correlation_result.get("supervisor_telemetry")
    }


@router.get(
    "/{case_id}/correlation/results",
    summary="Get Case Hybrid Correlation Results",
    tags=["Cases", "Correlation"]
)
def get_case_correlation_results(
    case_id: str = FastAPIPath(..., description="Unique investigation case ID"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieves stored correlation results and multi-tier evidence graph for a case.
    """
    case_obj = CaseService.get_case(db=db, case_id=case_id)
    if not case_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case with ID '{case_id}' not found")

    if not RBACService.check_case_access(db, current_user, case_id, permission="case:read"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission Denied.")

    from app.services.synthesizer_service import ForensicSynthesizerService
    case_dir = ForensicSynthesizerService.get_case_output_dir(case_id)
    corr_file = case_dir / "correlation_results.json"

    if corr_file.exists():
        try:
            with open(corr_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return {
                    "status": "SUCCESS",
                    "case_id": case_id,
                    "cached": True,
                    **data
                }
        except Exception as re:
            log_app_event(f"Error reading correlation_results.json: {re}")

    # If not run yet, run synchronously
    return run_case_correlation(case_id=case_id, invoke_supervisor=False, db=db, current_user=current_user)




