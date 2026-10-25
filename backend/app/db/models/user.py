"""
User Database Model for HMACFR Authentication and Role-Based Authorization.
"""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, Integer
from sqlalchemy.orm import relationship
from app.db.connection import Base



class User(Base):
    __tablename__ = "users"

    user_id = Column(String(36), primary_key=True, default=lambda: f"USR_{uuid.uuid4().hex[:12]}")
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(30), nullable=False, default="Investigator")  # Legacy role preserved for backward compatibility
    token_version = Column(Integer, default=1, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # RBAC Relationships
    global_roles = relationship("UserGlobalRole", back_populates="user", cascade="all, delete-orphan", foreign_keys="UserGlobalRole.user_id")
    case_memberships = relationship("CaseMember", back_populates="user", cascade="all, delete-orphan", foreign_keys="CaseMember.user_id")

