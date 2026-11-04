"""
Domain Agent Finding Pydantic Schemas & Output Contracts for SherlockAI / H-MACFR.
Enforces rigorous validation:
- Valid classification: BENIGN, SUSPICIOUS, MALICIOUS, INCONCLUSIVE, INSUFFICIENT_EVIDENCE
- Valid risk_level: LOW, MEDIUM, HIGH, CRITICAL, INFORMATIONAL
- Confidence strictly bounded between 0.0 and 1.0
- Missing domain results must carry is_examination_status=True and confidence=0.0
"""

from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field, field_validator


class AgentObservationAccounting(BaseModel):
    total_observations: int = Field(default=1, ge=0)
    analyzed_observations: int = Field(default=1, ge=0)
    skipped_observations: int = Field(default=0, ge=0)
    failed_observations: int = Field(default=0, ge=0)
    batch_count: int = Field(default=1, ge=1)
    accounting_status: Literal["COMPLETE", "PARTIAL", "FAILED", "EMPTY"] = "COMPLETE"
    source_artifact: Optional[str] = None


class AgentFindingContract(BaseModel):
    domain: Literal["network", "memory", "disk", "logs", "registry", "supervisor"]
    agent_name: str
    team_member: str
    evidence_type: str
    source_artifact: Optional[str] = None
    status: Literal["SUCCESS", "INSUFFICIENT_EVIDENCE", "FAILED"] = "SUCCESS"
    classification: Literal["BENIGN", "SUSPICIOUS", "MALICIOUS", "INCONCLUSIVE", "INSUFFICIENT_EVIDENCE"]
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "INFORMATIONAL"]
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    observation: str
    reasoning: str
    key_evidence: List[str] = Field(default_factory=list)
    entities: List[str] = Field(default_factory=list)
    contract_validated: bool = True
    schema_conforming: bool = True
    is_examination_status: bool = False
    analysis_mode: str = "AI-assisted"
    inference_provider: str = "Remote GPU LoRA Adapter"
    observation_accounting: Optional[AgentObservationAccounting] = None
    model_info: Optional[Dict[str, Any]] = None

    @field_validator("confidence")
    @classmethod
    def validate_confidence_for_insufficient(cls, v: float, info) -> float:
        # If classification is INSUFFICIENT_EVIDENCE, confidence must be 0.0
        return round(float(v), 3)


class SupervisorCorrelationEdgeContract(BaseModel):
    correlation_id: str
    edge_type: Literal["CAUSAL_DEPENDENCY", "CORRELATIONAL_ASSOCIATION", "COINCIDENTAL_NOISE", "AMBIGUOUS_UNKNOWN"]
    source_entity: str
    target_entity: str
    source_domain: str
    target_domain: str
    source_finding_id: Optional[str] = None
    target_finding_id: Optional[str] = None
    telemetry_clue_ids: List[str] = Field(default_factory=list)
    mitre_attack_id: Optional[str] = None
    confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    explanation: str
    deterministic_rule: Optional[str] = None
    cross_domain_verified: bool = True

