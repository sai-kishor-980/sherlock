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
from app.api.dependencies import get_current_user

router = APIRouter()


@router.post("/login", response_model=Token, summary="Investigator Login & Token Issuance")
def login(login_input: UserLogin, db: Session = Depends(get_db)):
    """
    Authenticates investigator credentials (username/id + password) and returns JWT access token.
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

    access_token = create_access_token(data={"sub": user.username, "role": user.role, "id": user.user_id})
    return Token(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse.model_validate(user)
    )


@router.post("/login/form", response_model=Token, summary="OAuth2 Form Compatible Login")
def login_form(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Form-data compatible login route for Swagger UI and standard OAuth2 clients.
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

    access_token = create_access_token(data={"sub": user.username, "role": user.role, "id": user.user_id})
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
def list_users(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    """
    Returns all registered user accounts in the platform.
    """
    users = UserRepository.get_all(db)
    return [UserResponse.model_validate(u) for u in users]


@router.put("/users/{user_id}/password", response_model=UserResponse, summary="Reset User Password")
def update_user_password(user_id: str, payload: PasswordResetInput, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    """
    Resets the password for a target user.
    """
    hashed_pw = get_password_hash(payload.new_password)
    updated = UserRepository.update_password(db, user_id=user_id, hashed_password=hashed_pw)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserResponse.model_validate(updated)


class RoleUpdateInput(BaseModel):
    role: str


@router.put("/users/{user_id}/role", response_model=UserResponse, summary="Update User Role")
def update_user_role(user_id: str, payload: RoleUpdateInput, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    """
    Updates system access role for a target user.
    """
    updated = UserRepository.update_role(db, user_id=user_id, new_role=payload.role)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserResponse.model_validate(updated)


class UserDeleteInput(BaseModel):
    admin_password: str


@router.delete("/users/{user_id}", summary="Delete User Account with Admin Password Verification")
def delete_user(
    user_id: str,
    payload: UserDeleteInput,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """
    Deletes a target user account. Requires valid Administrator password verification.
    """
    # 1. Enforce Admin Role
    if (current_user.role or "").upper() not in ["ADMIN"] and (getattr(current_user, "clearance_level", 0) or 0) < 5:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission Denied: Only System Administrators can delete user accounts."
        )

    # 2. Verify Admin Password
    if not verify_password(payload.admin_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Security Authentication Failed: Invalid Administrator password."
        )

    # 3. Prevent Self Deletion
    if current_user.user_id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Action Rejected: System Administrator cannot delete their own active account."
        )

    # 4. Fetch Target User
    target_user = UserRepository.get_by_id(db, user_id=user_id)
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID '{user_id}' not found."
        )

    username = target_user.username
    UserRepository.delete(db, user_id=user_id)

    return {
        "status": "success",
        "user_id": user_id,
        "username": username,
        "message": f"User account '{username}' successfully deleted."
    }

