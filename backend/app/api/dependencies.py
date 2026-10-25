"""
FastAPI Request Dependencies & Security Authentication Injection.
"""

from typing import Generator, Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from jose import ExpiredSignatureError

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


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    """
    Extracts, decodes, and validates bearer token to resolve active User instance.
    Enforces strict token_version matching.
    If no token, invalid token, expired token, or version mismatch, raises 401 Unauthorized.
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

    # Enforce immediate token revocation and version matching via token_version
    token_ver = payload.get("ver")
    if token_ver is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session authentication error: Token version missing or invalid. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    expected_ver = getattr(user, "token_version", 1)
    if token_ver != expected_ver:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session revoked: Account permissions or credentials have changed. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def get_optional_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """
    Hardened optional authentication resolver.
    Returns User if a valid, active, non-stale token is provided.
    Returns None only if NO token was provided.
    If a token WAS provided but is invalid, expired, revoked, or belongs to an inactive user,
    raises 401 Unauthorized to prevent accidental anonymous access escalation.
    """
    if not token:
        return None

    try:
        payload = decode_access_token(token)
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    username: str = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = UserRepository.get_by_username(db, username=username)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account inactive or not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_ver = payload.get("ver")
    if token_ver is None or token_ver != getattr(user, "token_version", 1):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session revoked: Account permissions or credentials have changed. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_admin_access(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> User:
    """
    Dependency ensuring active user has administrative privileges under RBAC
    (Platform Super Admin or Access Administrator).
    Quarantined accounts (Pending_Admin_Review) and regular investigators are strictly rejected.
    """
    from app.services.rbac_service import RBACService
    if not RBACService.has_global_admin_access(db, current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission Denied: Administrative privileges required."
        )
    return current_user


def require_super_admin(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> User:
    """
    Dependency ensuring active user has Platform Super Admin privileges.
    """
    from app.services.rbac_service import RBACService
    if not RBACService.has_super_admin_access(db, current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission Denied: Platform Super Admin privileges required."
        )
    return current_user


def check_user_has_admin_access(db: Session, user: User) -> bool:
    """
    Checks if user has active administrative access under the RBAC model.
    """
    from app.services.rbac_service import RBACService
    return RBACService.has_global_admin_access(db, user)
