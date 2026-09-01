import uuid
import datetime
from sqlalchemy import Column, String, BigInteger, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.db.connection import Base

class Evidence(Base):
    __tablename__ = "evidence"

    evidence_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    case_id = Column(String(36), ForeignKey("cases.case_id"), nullable=False)
    original_filename = Column(String, nullable=False)
    stored_filename = Column(String, nullable=False)
    category = Column(String, nullable=True)   # e.g., Audio, Video, Image, Document, Memory
    type = Column(String, nullable=True)       # e.g., Media, Text, Binary
    extension = Column(String, nullable=False)
    file_size = Column(BigInteger, nullable=False)
    storage_path = Column(String, nullable=False)
    upload_timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    status = Column(String, default="Uploaded")
    
    # Security integrity metadata
    file_hash = Column(String, nullable=True, index=True)
    hmac_signature = Column(String, nullable=True)

    # Relationships
    case = relationship("Case", back_populates="evidences")
    custody_logs = relationship("ChainOfCustody", back_populates="evidence", cascade="all, delete-orphan")
