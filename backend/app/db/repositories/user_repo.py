"""
User Repository for Authentication Database Operations.
"""

from typing import Optional, List
from sqlalchemy.orm import Session
from app.db.models.user import User
from app.db.schemas.user import UserCreate
from app.core.logger import log_app_event


class UserRepository:
    @staticmethod
    def get_by_id(db: Session, user_id: str) -> Optional[User]:
        return db.query(User).filter(User.user_id == user_id).first()

    @staticmethod
    def get_by_username(db: Session, username: str) -> Optional[User]:
        return db.query(User).filter(User.username == username).first()

    @staticmethod
    def get_by_email(db: Session, email: str) -> Optional[User]:
        return db.query(User).filter(User.email == email).first()

    @staticmethod
    def get_all(db: Session, skip: int = 0, limit: int = 100) -> List[User]:
        return db.query(User).offset(skip).limit(limit).all()

    @staticmethod
    def create(db: Session, user_in: UserCreate, hashed_password: str) -> User:
        user = User(
            username=user_in.username,
            email=user_in.email,
            hashed_password=hashed_password,
            role=user_in.role or "Investigator"
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    @staticmethod
    def update_password(db: Session, user_id: str, hashed_password: str) -> Optional[User]:
        user = db.query(User).filter(User.user_id == user_id).first()
        if user:
            user.hashed_password = hashed_password
            user.token_version = (getattr(user, "token_version", 1) or 1) + 1
            db.commit()
            db.refresh(user)
        return user

    @staticmethod
    def update_role(db: Session, user_id: str, new_role: str) -> Optional[User]:
        user = db.query(User).filter(User.user_id == user_id).first()
        if user:
            user.role = new_role
            user.token_version = (getattr(user, "token_version", 1) or 1) + 1
            db.commit()
            db.refresh(user)
        return user

    @staticmethod
    def delete(db: Session, user_id: str) -> bool:
        user = db.query(User).filter(User.user_id == user_id).first()
        if user:
            db.delete(user)
            db.commit()
            return True
        return False


    @staticmethod
    def seed_default_users(db: Session, investigator_hash: str, admin_hash: str):
        """
        Seeds default admin and investigator accounts if not present.
        Default Admin: admin / Admin@2026
        Default Investigator: investigator1 / Investigator@2026
        """
        admin_user = db.query(User).filter(User.username == "admin").first()
        if not admin_user:
            admin_user = User(
                username="admin",
                email="admin@hmacfr.org",
                hashed_password=admin_hash,
                role="Admin"
            )
            db.add(admin_user)
            log_app_event("Seeded default admin account: admin / Admin@2026")

        inv_user = db.query(User).filter(User.username == "investigator1").first()
        if not inv_user:
            inv_user = User(
                username="investigator1",
                email="investigator@hmacfr.org",
                hashed_password=investigator_hash,
                role="Investigator"
            )
            db.add(inv_user)
            log_app_event("Seeded default investigator account: investigator1 / Investigator@2026")

        db.commit()
