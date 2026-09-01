"""
Pydantic Schemas for Authentication and User Management.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field


class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Investigator unique username")
    email: str = Field(..., description="Investigator official email address")
    role: Optional[str] = Field("Investigator", description="Role: Investigator, Lead_Auditor, Admin")


class UserCreate(UserBase):
    password: str = Field(..., min_length=6, description="Password (min 6 characters)")


class UserLogin(BaseModel):
    username: str
    password: str


class UserResponse(UserBase):
    user_id: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None
