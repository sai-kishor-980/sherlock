"""
Pydantic Schemas for Evidence Graph API (Phase 2B).
Defines strongly-typed DTOs for nodes, edges, filtering metadata, and graph responses.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict


class GraphFilterMetadata(BaseModel):
    include_noise: bool = Field(..., description="Whether coincidental noise and ambiguous non-causal associations are included")
    min_confidence: float = Field(..., description="Minimum confidence threshold applied to edges")
    total_unfiltered_nodes: int = Field(..., description="Total node count in source evidence graph")
    total_unfiltered_edges: int = Field(..., description="Total edge count in source evidence graph")
    returned_nodes_count: int = Field(..., description="Number of nodes returned in this view")
    returned_edges_count: int = Field(..., description="Number of edges returned in this view")
    is_filtered: bool = Field(..., description="Flag indicating whether filtering parameters altered the returned graph")


class UnresolvedCorrelationEdge(BaseModel):
    correlation_id: Optional[str] = Field(None, description="Correlation rule instance ID")
    relationship_type: Optional[str] = Field(None, description="Relationship type (e.g. process_injection_chain)")
    source_a: Optional[str] = Field(None, description="Source artifact or entity ID")
    source_b: Optional[str] = Field(None, description="Target artifact or entity ID")
    unresolved_reasons: List[str] = Field(default_factory=list, description="Reason entity was not resolved to an active graph node")
    diagnostic: Optional[str] = Field(None, description="Forensic explanation of omission")


class EvidenceGraphResponse(BaseModel):
    case_id: str = Field(..., description="Unique case identifier")
    generated_at: Optional[str] = Field(None, description="Timestamp graph was generated")
    framework: str = Field("H-MACFR Forensic Evidence Graph", description="Graph framework schema")
    confidence_metric_disclaimer: str = Field(
        "Confidence values are expert-calibrated heuristic ordinal risk scores; they do not represent statistical Bayesian probabilities.",
        description="Forensic evidentiary disclaimer regarding confidence values"
    )
    filtering: GraphFilterMetadata = Field(..., description="Applied filtering parameters and boundary counts")
    metrics: Dict[str, Any] = Field(default_factory=dict, description="Node, relationship, and epistemic nature distributions")
    nodes: List[Dict[str, Any]] = Field(default_factory=list, description="List of graph nodes with entity types and attributes")
    edges: List[Dict[str, Any]] = Field(default_factory=list, description="List of directed graph edges with epistemic attributes")
    unresolved_correlation_edges: List[UnresolvedCorrelationEdge] = Field(default_factory=list, description="Diagnostics for correlation edges where source/target entities do not exist in evidence")

    model_config = ConfigDict(from_attributes=True)
