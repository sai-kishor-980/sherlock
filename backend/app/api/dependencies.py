"""
FastAPI Request Dependencies & Security Authentication Injection.
"""

from typing import Generator, Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.db.connection import get_db
from app.db.models.user import User
from app.db.repositories.user_repo import UserRepository
from app.core.security import decode_access_token
from app.core.config import settings, Settings
from app.services.preservation_service import EvidencePreservationService


def get_settings() -> Settings:
    return settings


def get_preservation_service() -> type[EvidencePreservationService]:
    return EvidencePreservationService


from jose import ExpiredSignatureError

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    """
    Extracts, decodes, and validates bearer token to resolve active User instance.
    If no token, invalid token, or expired token, raises 401 Unauthorized exception.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise credentials_exception

    try:
        payload = decode_access_token(token)
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not payload:
        raise credentials_exception

    username: str = payload.get("sub")
    if not username:
        raise credentials_exception

    user = UserRepository.get_by_username(db, username=username)
    if user is None or not user.is_active:
        raise credentials_exception

    return user


def get_optional_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """
    Optional authentication resolver returning User if valid token is provided, None otherwise.
    """
    if not token:
        return None
    payload = decode_access_token(token)
    if not payload:
        return None
    username: str = payload.get("sub")
    if not username:
        return None
    return UserRepository.get_by_username(db, username=username)
