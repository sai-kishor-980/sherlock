"""
Bootstrap Administrator CLI.
Allows an investigator or system operator to provision the initial Platform Super Admin and Access Administrator
accounts without hardcoded credentials when the system is initialized.
"""

import sys
import argparse
import uuid
from getpass import getpass
from sqlalchemy.orm import Session

from app.db.connection import SessionLocal
from app.db.models.user import User
from app.db.models.user_role import UserGlobalRole
from app.core.security import get_password_hash
from app.core.logger import log_app_event


def bootstrap_admin(username: str, email: str, password: str, db: Session = None) -> dict:
    if not username or not email or not password:
        raise ValueError("Username, email, and password must not be empty.")

    should_close = False
    if db is None:
        db = SessionLocal()
        should_close = True

    try:
        # Check if username or email exists
        existing_user = db.query(User).filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            raise ValueError(f"User with username '{username}' or email '{email}' already exists.")

        user_id = f"USR_{uuid.uuid4().hex[:12]}"
        hashed_pw = get_password_hash(password)

        new_user = User(
            user_id=user_id,
            username=username,
            email=email,
            hashed_password=hashed_pw,
            role="Admin",  # Legacy fallback
            token_version=1,
            is_active=True
        )
        db.add(new_user)
        db.flush()

        # Grant both Platform Super Admin and Access Administrator explicitly
        for role_name in ["Platform Super Admin", "Access Administrator"]:
            db.add(UserGlobalRole(
                id=f"UGR_{uuid.uuid4().hex[:12]}",
                user_id=user_id,
                role_name=role_name
            ))

        db.commit()
        log_app_event(f"Successfully bootstrapped administrator account: {username} ({user_id})")
        return {"status": "SUCCESS", "user_id": user_id, "username": username}

    except Exception as e:
        db.rollback()
        raise e
    finally:
        if should_close:
            db.close()



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bootstrap initial Sherlock AI Platform Administrator")
    parser.add_argument("--username", help="Administrator username")
    parser.add_argument("--email", help="Administrator official email")
    parser.add_argument("--password", help="Administrator secure password (prompted if omitted)")

    args = parser.parse_args()

    u = args.username or input("Enter Administrator Username: ").strip()
    e = args.email or input("Enter Administrator Email: ").strip()
    p = args.password or getpass("Enter Administrator Password: ").strip()

    try:
        res = bootstrap_admin(u, e, p)
        print(f"\n[SUCCESS] Administrator '{res['username']}' provisioned successfully (ID: {res['user_id']}).")
    except Exception as ex:
        print(f"\n[ERROR] Bootstrap failed: {ex}")
        sys.exit(1)
