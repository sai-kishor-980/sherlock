from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Evidence:
    evidence_id: str
    path: str
    evidence_type: str
    file_format: str
    name: str

    status: str = "PENDING"
    parent_evidence_id: Optional[str] = None

    def to_dict(self):
        return {
            "evidence_id": self.evidence_id,
            "path": self.path,
            "evidence_type": self.evidence_type,
            "file_format": self.file_format,
            "name": self.name,
            "status": self.status,
            "parent_evidence_id": self.parent_evidence_id,
        }


@dataclass
class Case:
    case_id: str
    evidence: List[Evidence] = field(default_factory=list)