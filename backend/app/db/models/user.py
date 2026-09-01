"""
User Database Model for HMACFR Authentication and Role-Based Authorization.
"""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime
from app.db.connection import Base


class User(Base):
    __tablename__ = "users"

    user_id = Column(String(36), primary_key=True, default=lambda: f"USR_{uuid.uuid4().hex[:12]}")
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(30), nullable=False, default="Investigator")  # Investigator, Lead_Auditor, Admin
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
