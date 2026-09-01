import uuid
import datetime
from sqlalchemy import Column, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.db.connection import Base

class ChainOfCustody(Base):
    __tablename__ = "chain_of_custody"

    log_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    evidence_id = Column(String(36), ForeignKey("evidence.evidence_id"), nullable=False)
    action = Column(String, nullable=False, default="Uploaded")
    performed_by = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    remarks = Column(Text, nullable=True, default="Uploaded")

    # Relationships
    evidence = relationship("Evidence", back_populates="custody_logs")
