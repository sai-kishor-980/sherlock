import uuid
import datetime
from sqlalchemy import Column, String, Integer, DateTime, Text
from sqlalchemy.orm import relationship
from app.db.connection import Base

class Case(Base):
    __tablename__ = "cases"

    case_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    case_name = Column(String, nullable=False)
    investigator_name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    priority = Column(String, default="Medium")  # Low, Medium, High, Critical
    status = Column(String, default="Active")    # Active, Pending, Closed, Archived, PENDING_DELETION
    deletion_reason = Column(Text, nullable=True)
    deletion_requested_by = Column(String, nullable=True)
    expected_evidence_count = Column(Integer, nullable=True, default=0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    # Relationships
    evidences = relationship("Evidence", back_populates="case", cascade="all, delete-orphan")

