"""
Authentication & Authorization API Routes.
"""

from typing import List
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.db.connection import get_db
from app.db.schemas.user import UserCreate, UserLogin, UserResponse, Token
from app.db.repositories.user_repo import UserRepository
from app.core.security import verify_password, get_password_hash, create_access_token
from app.api.dependencies import get_current_user, require_admin_access
from app.services.rbac_service import RBACService
from app.services.audit_service import AuditService
from app.db.models.user_role import UserGlobalRole
from app.core.logger import log_app_event

router = APIRouter()


@router.post("/login", response_model=Token, summary="Investigator Login & Token Issuance")
def login(login_input: UserLogin, db: Session = Depends(get_db)):
    """
    Authenticates investigator credentials (username/id + password) and returns JWT access token
    with token_version ('ver') claim embedded.
    """
    user = UserRepository.get_by_username(db, username=login_input.username)
    if not user or not verify_password(login_input.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user account"
        )

    ver = getattr(user, "token_version", 1) or 1
    access_token = create_access_token(data={
        "sub": user.username,
        "role": user.role,
        "id": user.user_id,
        "ver": ver
    })
    return Token(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse.model_validate(user)
    )


@router.post("/login/form", response_model=Token, summary="OAuth2 Form Compatible Login")
def login_form(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Form-data compatible login route for Swagger UI and standard OAuth2 clients
    with token_version ('ver') claim embedded.
    """
    user = UserRepository.get_by_username(db, username=form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user account"
        )

    ver = getattr(user, "token_version", 1) or 1
    access_token = create_access_token(data={
        "sub": user.username,
        "role": user.role,
        "id": user.user_id,
        "ver": ver
    })
    return Token(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse.model_validate(user)
    )


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED, summary="Register New Investigator")
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    """
    Registers a new investigator account.
    """
    existing_username = UserRepository.get_by_username(db, username=user_in.username)
    if existing_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )

    existing_email = UserRepository.get_by_email(db, email=user_in.email)
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email address already registered"
        )

    hashed_pw = get_password_hash(user_in.password)
    user = UserRepository.create(db, user_in=user_in, hashed_password=hashed_pw)
    return UserResponse.model_validate(user)


@router.get("/me", response_model=UserResponse, summary="Get Current Investigator Profile")
def get_me(current_user=Depends(get_current_user)):
    """
    Returns profile information for the currently authenticated investigator.
    """
    return UserResponse.model_validate(current_user)


class PasswordResetInput(BaseModel):
    new_password: str


@router.get("/users", response_model=List[UserResponse], summary="List All User Accounts")
def list_users(db: Session = Depends(get_db), current_user=Depends(require_admin_access)):
    """
    Returns all registered user accounts in the platform.
    Requires Administrative privileges under RBAC.
    """
    users = UserRepository.get_all(db)
    return [UserResponse.model_validate(u) for u in users]


@router.put("/users/{user_id}/password", response_model=UserResponse, summary="Reset User Password")
def update_user_password(
    user_id: str,
    payload: PasswordResetInput,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """
    Resets password for a user and invalidates all existing sessions.
    Users can reset their own password; resetting another user's password requires Admin privileges.
    """
    if current_user.user_id != user_id and not RBACService.has_global_admin_access(db, current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission Denied: Administrative privileges required to reset another user's password."
        )

    hashed_pw = get_password_hash(payload.new_password)
    updated = UserRepository.update_password(db, user_id=user_id, hashed_password=hashed_pw)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Record secure audit event without logging the password
    try:
        AuditService.record_event(
            db=db,
            action="PASSWORD_RESET",
            target_resource="user",
            user_id=current_user.user_id,
            username=current_user.username,
            resource_id=user_id,
            details=f"Password updated for user {updated.username}; token_version incremented to {updated.token_version}."
        )
    except Exception as e:
        log_app_event(f"Audit event recording skipped: {e}")

    return UserResponse.model_validate(updated)


class RoleUpdateInput(BaseModel):
    role: str


@router.put("/users/{user_id}/role", response_model=UserResponse, summary="Update User Role")
def update_user_role(
    user_id: str,
    payload: RoleUpdateInput,
    db: Session = Depends(get_db),
    current_user=Depends(require_admin_access)
):
    """
    Updates system access role for a target user and invalidates their active sessions.
    Requires Administrative privileges under RBAC.
    """
    updated = UserRepository.update_role(db, user_id=user_id, new_role=payload.role)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Map to RBAC user_global_roles if applicable
    import uuid
    clean_role = payload.role.strip()
    valid_global_roles = ["Platform Super Admin", "Access Administrator", "Platform Auditor"]
    for g_role in valid_global_roles:
        if clean_role.lower() == g_role.lower() or (clean_role.upper() == "ADMIN" and g_role == "Access Administrator"):
            existing = db.query(UserGlobalRole).filter(
                UserGlobalRole.user_id == user_id,
                UserGlobalRole.role_name == g_role
            ).first()
            if not existing:
                db.add(UserGlobalRole(
                    id=f"UGR_{uuid.uuid4().hex[:12]}",
                    user_id=user_id,
                    role_name=g_role,
                    assigned_by=current_user.user_id
                ))
                db.commit()

    # Record audit event
    try:
        AuditService.record_event(
            db=db,
            action="ROLE_UPDATE",
            target_resource="user",
            user_id=current_user.user_id,
            username=current_user.username,
            resource_id=user_id,
            details=f"Role updated to '{payload.role}' for user {updated.username}; token_version incremented to {updated.token_version}."
        )
    except Exception as e:
        log_app_event(f"Audit event recording skipped: {e}")

    return UserResponse.model_validate(updated)


class UserDeleteInput(BaseModel):
    admin_password: str


@router.delete("/users/{user_id}", summary="Delete User Account with Admin Password Verification")
def delete_user(
    user_id: str,
    payload: UserDeleteInput,
    db: Session = Depends(get_db),
    current_user=Depends(require_admin_access)
):
    """
    Deletes a target user account.
    Requires Administrator privileges under RBAC and password re-authentication.
    """
    # 1. Verify Admin Password
    if not verify_password(payload.admin_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Security Authentication Failed: Invalid Administrator password."
        )

    # 2. Prevent Self Deletion
    if current_user.user_id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Action Rejected: System Administrator cannot delete their own active account."
        )

    # 3. Fetch Target User
    target_user = UserRepository.get_by_id(db, user_id=user_id)
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID '{user_id}' not found."
        )

    username = target_user.username
    UserRepository.delete(db, user_id=user_id)

    # Record audit event
    try:
        AuditService.record_event(
            db=db,
            action="USER_DELETE",
            target_resource="user",
            user_id=current_user.user_id,
            username=current_user.username,
            resource_id=user_id,
            details=f"User account '{username}' (ID: {user_id}) permanently deleted by {current_user.username}."
        )
    except Exception as e:
        log_app_event(f"Audit event recording skipped: {e}")

    return {
        "status": "success",
        "user_id": user_id,
        "username": username,
        "message": f"User account '{username}' successfully deleted."
    }


class GlobalRolesUpdateInput(BaseModel):
    roles: List[str]


@router.get("/users/{user_id}/roles", summary="Get User Global Roles")
def get_user_roles(
    user_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_admin_access)
):
    """
    Returns assigned global roles for a target user.
    Requires Administrative privileges under RBAC.
    """
    target_user = UserRepository.get_by_id(db, user_id=user_id)
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User with ID '{user_id}' not found.")
    roles = RBACService.get_user_global_roles(db, user_id=user_id)
    return {"user_id": user_id, "username": target_user.username, "global_roles": roles}


@router.put("/users/{user_id}/global-roles", summary="Update User Global Roles")
def update_user_global_roles(
    user_id: str,
    payload: GlobalRolesUpdateInput,
    db: Session = Depends(get_db),
    current_user=Depends(require_admin_access)
):
    """
    Updates assigned global roles for a target user and increments their token version.
    Requires Administrative privileges under RBAC.
    """
    target_user = UserRepository.get_by_id(db, user_id=user_id)
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User with ID '{user_id}' not found.")

    import uuid
    db.query(UserGlobalRole).filter(UserGlobalRole.user_id == user_id).delete()
    for r in payload.roles:
        clean = r.strip()
        if clean:
            db.add(UserGlobalRole(
                id=f"UGR_{uuid.uuid4().hex[:12]}",
                user_id=user_id,
                role_name=clean,
                assigned_by=current_user.user_id
            ))

    if "Platform Super Admin" in payload.roles or "Access Administrator" in payload.roles:
        target_user.role = "Admin"
    elif "Platform Auditor" in payload.roles:
        target_user.role = "Lead_Auditor"
    else:
        target_user.role = "Investigator"

    target_user.token_version = (target_user.token_version or 1) + 1
    db.commit()

    try:
        AuditService.record_event(
            db=db,
            action="GLOBAL_ROLES_UPDATE",
            target_resource="user",
            user_id=current_user.user_id,
            username=current_user.username,
            resource_id=user_id,
            details=f"Global roles updated to {payload.roles} for user {target_user.username}."
        )
    except Exception as e:
        log_app_event(f"Audit event recording skipped: {e}")

    return {"user_id": user_id, "username": target_user.username, "global_roles": payload.roles}

