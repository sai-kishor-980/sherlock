"""
Legacy Administrator Review CLI.
Enforces the explicit review policy (Fix #2):
Inspects accounts in 'Pending_Admin_Review' status and allows deliberate assignment
of 'Platform Super Admin', 'Access Administrator', or rejection.
"""

import sys
import uuid
from typing import List, Dict, Any
from sqlalchemy.orm import Session

from app.db.connection import SessionLocal
from app.db.models.user import User
from app.db.models.user_role import UserGlobalRole
from app.core.logger import log_app_event


def list_pending_admins(db: Session) -> List[Dict[str, Any]]:
    pending_roles = db.query(UserGlobalRole).filter(UserGlobalRole.role_name == "Pending_Admin_Review").all()
    results = []
    for pr in pending_roles:
        u = db.query(User).filter(User.user_id == pr.user_id).first()
        if u:
            results.append({
                "role_id": pr.id,
                "user_id": u.user_id,
                "username": u.username,
                "email": u.email,
                "created_at": str(u.created_at)
            })
    return results


def promote_legacy_admin(db: Session, user_id: str, grant_super_admin: bool, grant_access_admin: bool) -> Dict[str, Any]:
    # 1. Verify user exists and is in Pending_Admin_Review
    pending = db.query(UserGlobalRole).filter(
        UserGlobalRole.user_id == user_id,
        UserGlobalRole.role_name == "Pending_Admin_Review"
    ).first()

    if not pending:
        raise ValueError(f"User '{user_id}' is not in Pending_Admin_Review status.")

    # 2. Remove quarantine role
    db.delete(pending)

    granted = []
    if grant_super_admin:
        db.add(UserGlobalRole(id=f"UGR_{uuid.uuid4().hex[:12]}", user_id=user_id, role_name="Platform Super Admin"))
        granted.append("Platform Super Admin")

    if grant_access_admin:
        db.add(UserGlobalRole(id=f"UGR_{uuid.uuid4().hex[:12]}", user_id=user_id, role_name="Access Administrator"))
        granted.append("Access Administrator")

    # Increment token_version to ensure old sessions re-authenticate
    u = db.query(User).filter(User.user_id == user_id).first()
    if u:
        u.token_version = (u.token_version or 1) + 1

    db.commit()
    log_app_event(f"Legacy admin '{user_id}' promoted to: {granted}")
    return {"status": "SUCCESS", "user_id": user_id, "granted_roles": granted}


if __name__ == "__main__":
    db = SessionLocal()
    try:
        pending = list_pending_admins(db)
        if not pending:
            print("[INFO] No legacy admin accounts currently pending review.")
            sys.exit(0)

        print(f"\nFound {len(pending)} legacy admin account(s) pending review:")
        for idx, p in enumerate(pending, 1):
            print(f"  [{idx}] Username: {p['username']} | Email: {p['email']} | UserID: {p['user_id']}")

        choice = input("\nEnter account number to review (or 'q' to quit): ").strip()
        if choice.lower() == 'q':
            sys.exit(0)

        selected = pending[int(choice) - 1]
        print(f"\nReviewing: {selected['username']}")
        grant_super = input("Grant Platform Super Admin role? (y/N): ").strip().lower() == 'y'
        grant_access = input("Grant Access Administrator role? (y/N): ").strip().lower() == 'y'

        res = promote_legacy_admin(db, selected['user_id'], grant_super, grant_access)
        print(f"\n[SUCCESS] Updated {selected['username']} roles to: {res['granted_roles']}")

    except Exception as e:
        print(f"\n[ERROR] Review failed: {e}")
        db.rollback()
    finally:
        db.close()
