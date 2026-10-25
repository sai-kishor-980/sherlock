"""
RBAC Service for HMACFR.
Implements granular permission resolution, global administrative authorization,
case-level membership verification, and responsibility-based access control.
"""

import uuid
from typing import List, Optional, Set, Tuple
from sqlalchemy.orm import Session

from app.db.models.user import User
from app.db.models.user_role import UserGlobalRole
from app.db.models.case_assignment import CaseMember, CaseMemberResponsibility
from app.db.models.evidence import Evidence
from app.core.logger import log_app_event


class RBACService:
    # -------------------------------------------------------------------------
    # Role & Responsibility Permission Mappings
    # -------------------------------------------------------------------------
    GLOBAL_ROLE_PERMISSIONS = {
        "Platform Super Admin": {"*"},
        "Access Administrator": {
            "user:read", "user:manage", "user:manage_roles", "user:manage_passwords",
            "user:delete", "case:assign_members", "audit:read"
        },
        "Platform Auditor": {
            "case:read", "evidence:read", "analysis:read", "report:read", "audit:read", "custody:read"
        },
        "Pending_Admin_Review": set()
    }

    CASE_RESPONSIBILITY_PERMISSIONS = {
        "Lead Investigator": {
            "case:read", "case:update", "case:request_deletion",
            "evidence:read", "evidence:upload", "evidence:preserve", "evidence:delete",
            "analysis:run", "analysis:read", "extraction:execute", "report:generate", "report:read", "report:approve",
            "custody:read"
        },
        "Investigator": {
            "case:read", "case:update", "case:request_deletion",
            "evidence:read", "evidence:upload", "evidence:preserve",
            "analysis:run", "analysis:read", "extraction:execute", "report:generate", "report:read",
            "custody:read"
        },
        "Forensic Analyst": {
            "case:read",
            "evidence:read", "evidence:preserve",
            "analysis:run", "analysis:read", "extraction:execute", "report:generate", "report:read",
            "custody:read"
        },
        "Reviewer": {
            "case:read",
            "evidence:read", "analysis:read", "report:read", "report:approve",
            "custody:read"
        },
        "Case Auditor": {
            "case:read",
            "evidence:read", "analysis:read", "report:read",
            "custody:read"
        }
    }

    # -------------------------------------------------------------------------
    # Global Role Queries
    # -------------------------------------------------------------------------
    @classmethod
    def get_user_global_roles(cls, db: Session, user_id: str) -> List[str]:
        """Returns list of active global role names for the user."""
        try:
            roles = db.query(UserGlobalRole).filter(UserGlobalRole.user_id == user_id).all()
            return [r.role_name for r in roles]
        except Exception:
            return []

    @classmethod
    def has_global_admin_access(cls, db: Session, user: User) -> bool:
        """
        Verifies if user has active administrative privileges (Platform Super Admin or Access Administrator).
        Quarantined users in 'Pending_Admin_Review' are strictly rejected.
        Legacy users.role is never trusted to bypass RBAC.
        """
        roles = cls.get_user_global_roles(db, user.user_id)
        if "Pending_Admin_Review" in roles:
            return False
        if "Platform Super Admin" in roles or "Access Administrator" in roles:
            return True
        return False

    @classmethod
    def has_super_admin_access(cls, db: Session, user: User) -> bool:
        """Verifies if user has Platform Super Admin privileges."""
        roles = cls.get_user_global_roles(db, user.user_id)
        if "Pending_Admin_Review" in roles:
            return False
        return "Platform Super Admin" in roles

    @classmethod
    def has_global_permission(cls, db: Session, user: User, permission: str) -> bool:
        """Checks if any assigned global role grants the requested permission."""
        roles = cls.get_user_global_roles(db, user.user_id)
        if "Pending_Admin_Review" in roles:
            return False
        if "Platform Super Admin" in roles:
            return True
        for r_name in roles:
            perms = cls.GLOBAL_ROLE_PERMISSIONS.get(r_name, set())
            if "*" in perms or permission in perms:
                return True
        return False

    # -------------------------------------------------------------------------
    # Case Membership & Responsibility Authorization
    # -------------------------------------------------------------------------
    @classmethod
    def check_case_access(
        cls,
        db: Session,
        user: User,
        case_id: str,
        permission: str = "case:read"
    ) -> bool:
        """
        Evaluates whether user has permission on a specific case:
        1. Platform Super Admin -> granted all permissions across all cases.
        2. Platform Auditor -> granted read-only permissions across all cases.
        3. Assigned CaseMember -> evaluated against their assigned responsibilities.
        """
        roles = cls.get_user_global_roles(db, user.user_id)

        # Quarantined admins cannot access cases
        if "Pending_Admin_Review" in roles:
            return False

        # Super Admin override
        if "Platform Super Admin" in roles:
            return True

        # Platform Auditor read-only access
        if "Platform Auditor" in roles:
            read_perms = {"case:read", "evidence:read", "analysis:read", "report:read", "custody:read"}
            return permission in read_perms

        # Check explicit case membership
        try:
            member = db.query(CaseMember).filter(
                CaseMember.case_id == case_id,
                CaseMember.user_id == user.user_id
            ).first()
            if not member:
                return False

            # Base membership grants case:read
            if permission == "case:read":
                return True

            # Evaluate specific responsibilities
            resps = db.query(CaseMemberResponsibility).filter(
                CaseMemberResponsibility.case_member_id == member.id
            ).all()
            for r in resps:
                allowed_perms = cls.CASE_RESPONSIBILITY_PERMISSIONS.get(r.responsibility_name, set())
                if permission in allowed_perms:
                    return True

            return False
        except Exception as e:
            log_app_event(f"Error checking case access for user {user.username} on case {case_id}: {e}")
            return False

    @classmethod
    def get_accessible_case_ids(cls, db: Session, user: User) -> Optional[List[str]]:
        """
        Returns list of case IDs accessible to the user.
        Returns None if user has global read access (Super Admin or Platform Auditor).
        """
        roles = cls.get_user_global_roles(db, user.user_id)
        if "Platform Super Admin" in roles or "Platform Auditor" in roles:
            return None  # Unrestricted

        try:
            memberships = db.query(CaseMember.case_id).filter(
                CaseMember.user_id == user.user_id
            ).all()
            return [m[0] for m in memberships]
        except Exception:
            return []

    @classmethod
    def assign_case_creator(cls, db: Session, case_id: str, user_id: str):
        """
        Automatically establishes case membership and primary responsibilities
        (Lead Investigator, Investigator, Forensic Analyst) for the user creating the case.
        """
        try:
            existing = db.query(CaseMember).filter(
                CaseMember.case_id == case_id,
                CaseMember.user_id == user_id
            ).first()
            if not existing:
                member_id = f"MBR_{uuid.uuid4().hex[:12]}"
                member = CaseMember(
                    id=member_id,
                    case_id=case_id,
                    user_id=user_id,
                    assigned_by=user_id
                )
                db.add(member)
                db.flush()

                for resp_name in ["Lead Investigator", "Investigator", "Forensic Analyst"]:
                    resp = CaseMemberResponsibility(
                        id=f"RES_{uuid.uuid4().hex[:12]}",
                        case_member_id=member_id,
                        responsibility_name=resp_name
                    )
                    db.add(resp)
                db.commit()
        except Exception as e:
            db.rollback()
            log_app_event(f"Error assigning case creator membership: {e}")

    # -------------------------------------------------------------------------
    # Evidence & Artifact Resolution
    # -------------------------------------------------------------------------
    @classmethod
    def check_evidence_access(
        cls,
        db: Session,
        user: User,
        evidence_id: str,
        permission: str = "evidence:read"
    ) -> Tuple[bool, Optional[str]]:
        """
        Resolves evidence to its parent case and validates permission.
        Returns (has_access: bool, case_id: Optional[str]).
        If evidence not found, returns (False, None).
        """
        try:
            ev = db.query(Evidence).filter(Evidence.evidence_id == evidence_id).first()
            if not ev:
                return False, None
            has_access = cls.check_case_access(db, user, ev.case_id, permission=permission)
            return has_access, ev.case_id
        except Exception as e:
            log_app_event(f"Error resolving evidence access for {evidence_id}: {e}")
            return False, None
