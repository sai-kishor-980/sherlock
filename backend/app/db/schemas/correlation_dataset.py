"""
Versioned Pydantic Schema for H-MACFR Forensic Correlation Learning Dataset (Phase 1A).

Adheres to specifications defined in CORRELATION_TRAINING_PLAN.md:
- Versioned schema ('1.0.0')
- Epistemic labels: VERIFIED_POSITIVE, VERIFIED_NEGATIVE, AMBIGUOUS_UNRESOLVED
- Full artifact representation, temporal ordering, and missing-timestamp handling
- Shared identifier tracking and relationship-specific features
- Provenance and evidence traceability without raw payload leakage
- Strict consistency validators
"""

from enum import Enum
from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict, model_validator

CORRELATION_SCHEMA_VERSION = "1.0.0"
TIMESTAMP_DELTA_TOLERANCE_SECONDS: float = 1.0


def parse_iso_timestamp(ts: str) -> datetime:
    """
    Parses ISO-8601 timestamp string with robust UTC 'Z' handling and microsecond precision.
    """
    ts_clean = ts.strip()
    if ts_clean.endswith("Z"):
        ts_clean = ts_clean[:-1] + "+00:00"
    return datetime.fromisoformat(ts_clean)


class EpistemicLabel(str, Enum):
    VERIFIED_POSITIVE = "VERIFIED_POSITIVE"
    VERIFIED_NEGATIVE = "VERIFIED_NEGATIVE"
    AMBIGUOUS_UNRESOLVED = "AMBIGUOUS_UNRESOLVED"


class RelationshipType(str, Enum):
    PARENT_CHILD_PROCESS = "PARENT_CHILD_PROCESS"
    PROCESS_INJECTION = "PROCESS_INJECTION"
    PERSISTENCE_TO_EXECUTION = "PERSISTENCE_TO_EXECUTION"
    EXECUTION_TO_NETWORK_FLOW = "EXECUTION_TO_NETWORK_FLOW"
    DNS_TO_NETWORK_FLOW = "DNS_TO_NETWORK_FLOW"
    LNK_TO_FILE_ACCESS = "LNK_TO_FILE_ACCESS"
    DOWNLOAD_TO_EXECUTION = "DOWNLOAD_TO_EXECUTION"
    LOGON_TO_PRIVILEGE_USE = "LOGON_TO_PRIVILEGE_USE"
    CREDENTIAL_ACCESS_TO_AUTH = "CREDENTIAL_ACCESS_TO_AUTH"
    COINCIDENTAL_NOISE = "COINCIDENTAL_NOISE"


# Directionality taxonomy: COINCIDENTAL_NOISE is symmetric/undirected; all others are strictly directed
UNDIRECTED_RELATIONSHIP_TYPES = {RelationshipType.COINCIDENTAL_NOISE}
DIRECTED_RELATIONSHIP_TYPES = set(RelationshipType) - UNDIRECTED_RELATIONSHIP_TYPES

# Forward causal relationships where the causal source event must physically precede or be concurrent with target effect
FORWARD_CAUSAL_RELATIONSHIPS = {
    RelationshipType.PARENT_CHILD_PROCESS,
    RelationshipType.PERSISTENCE_TO_EXECUTION,
    RelationshipType.DOWNLOAD_TO_EXECUTION,
    RelationshipType.LOGON_TO_PRIVILEGE_USE,
    RelationshipType.CREDENTIAL_ACCESS_TO_AUTH,
    RelationshipType.EXECUTION_TO_NETWORK_FLOW,
}


class ArtifactDomain(str, Enum):
    MEMORY = "memory"
    DISK = "disk"
    NETWORK = "network"
    REGISTRY = "registry"
    LOGS = "logs"
    BROWSER = "browser"
    EMAIL = "email"


class TemporalOrderStatus(str, Enum):
    SOURCE_PRECEDES_TARGET = "SOURCE_PRECEDES_TARGET"
    TARGET_PRECEDES_SOURCE = "TARGET_PRECEDES_SOURCE"
    CONCURRENT = "CONCURRENT"
    UNKNOWN = "UNKNOWN"


class TimestampQuality(str, Enum):
    EXACT_ACQUISITION = "EXACT_ACQUISITION"
    EXACT_ORIGIN = "EXACT_ORIGIN"
    APPROXIMATE_LIFETIME = "APPROXIMATE_LIFETIME"
    UNRECORDED = "UNRECORDED"
    UNAVAILABLE = "UNAVAILABLE"
    DERIVED = "DERIVED"


class ClockSkewRisk(str, Enum):
    NONE_SAME_SYSTEM = "NONE_SAME_SYSTEM"
    POSSIBLE_MULTI_HOST = "POSSIBLE_MULTI_HOST"
    KNOWN_INVERSION = "KNOWN_INVERSION"


class DatasetSplit(str, Enum):
    TRAIN = "TRAIN"
    VALIDATION = "VALIDATION"
    TEST = "TEST"
    UNASSIGNED = "UNASSIGNED"


class AdjudicationStatus(str, Enum):
    UNREVIEWED = "UNREVIEWED"
    SINGLE_REVIEWER = "SINGLE_REVIEWER"
    CONSENSUS_VERIFIED = "CONSENSUS_VERIFIED"
    DISPUTED = "DISPUTED"
    ARBITRATED = "ARBITRATED"


class EvidenceProvenance(BaseModel):
    file_path: Optional[str] = Field(None, description="Relative path of the source extraction file")
    evidence_id: Optional[str] = Field(None, description="Raw evidence file identifier or database record ID")
    extractor_name: Optional[str] = Field(None, description="Tool or plugin that extracted this artifact (e.g. Volatility windows.pslist)")
    record_locator: Optional[str] = Field(None, description="Line number, JSON key, or offset within source extraction")
    storage_hash: Optional[str] = Field(None, description="SHA-256 hash of the parent raw evidence file")

    model_config = ConfigDict(extra="forbid")


class NormalizedFeatures(BaseModel):
    entity_name: Optional[str] = Field(None, description="Primary entity name (process image, domain name, filename, key name)")
    path: Optional[str] = Field(None, description="File, registry, or URL path")
    pid: Optional[int] = Field(None, description="Process identifier")
    ppid: Optional[int] = Field(None, description="Parent process identifier")
    ip: Optional[str] = Field(None, description="IP address")
    port: Optional[int] = Field(None, description="Network port number")
    user_sid: Optional[str] = Field(None, description="User SID or username")
    hash_sha256: Optional[str] = Field(None, description="Cryptographic hash of the entity")
    extra_attributes: Dict[str, Any] = Field(default_factory=dict, description="Domain-specific structured attributes")

    model_config = ConfigDict(extra="forbid")


class DatasetArtifact(BaseModel):
    artifact_id: str = Field(..., description="Unique artifact identifier within investigation (e.g. PID-584, DNS-c2.corp)")
    domain: ArtifactDomain = Field(..., description="Forensic source domain")
    artifact_type: str = Field(..., description="Specific artifact classification (e.g. process, dns_record, run_key, prefetch)")
    normalized_features: NormalizedFeatures = Field(default_factory=NormalizedFeatures, description="Normalized entity features")
    timestamp: Optional[str] = Field(None, description="ISO-8601 formatted event timestamp, or null if unrecorded")
    timestamp_quality: TimestampQuality = Field(TimestampQuality.EXACT_ORIGIN, description="Epistemic reliability of the timestamp")
    timestamp_source: Optional[str] = Field(None, description="Underlying telemetry field name (e.g. CreateTime, LastWriteTime)")
    provenance: EvidenceProvenance = Field(default_factory=EvidenceProvenance, description="Audit chain of custody and file provenance")

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def validate_timestamp_honesty(self):
        if self.timestamp is None and self.timestamp_quality in (TimestampQuality.EXACT_ACQUISITION, TimestampQuality.EXACT_ORIGIN):
            raise ValueError(
                f"Artifact '{self.artifact_id}' has timestamp=None but timestamp_quality is '{self.timestamp_quality.value}'. "
                f"Missing timestamps must be declared as UNRECORDED or UNAVAILABLE."
            )
        if self.timestamp is not None:
            try:
                parse_iso_timestamp(self.timestamp)
            except Exception as ex:
                raise ValueError(
                    f"Artifact '{self.artifact_id}' has invalid ISO-8601 timestamp '{self.timestamp}': {str(ex)}"
                )
        return self



class DatasetTemporalContext(BaseModel):
    delta_seconds: Optional[float] = Field(None, description="Signed time delta: Target_Time - Source_Time in seconds, or null if unavailable")
    temporal_order: TemporalOrderStatus = Field(..., description="Directional sequence of the pair")
    clock_skew_risk: ClockSkewRisk = Field(ClockSkewRisk.NONE_SAME_SYSTEM, description="Assessed risk of cross-host clock skew")
    time_window_valid: bool = Field(True, description="Whether the delta falls within forensically feasible bounds")

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def validate_temporal_consistency(self):
        if self.delta_seconds is not None:
            if self.delta_seconds > 0 and self.temporal_order == TemporalOrderStatus.TARGET_PRECEDES_SOURCE:
                raise ValueError("delta_seconds is positive but temporal_order is TARGET_PRECEDES_SOURCE")
            if self.delta_seconds < 0 and self.temporal_order == TemporalOrderStatus.SOURCE_PRECEDES_TARGET:
                raise ValueError("delta_seconds is negative but temporal_order is SOURCE_PRECEDES_TARGET")
            if self.delta_seconds == 0 and self.temporal_order not in (TemporalOrderStatus.CONCURRENT, TemporalOrderStatus.SOURCE_PRECEDES_TARGET, TemporalOrderStatus.TARGET_PRECEDES_SOURCE):
                raise ValueError("delta_seconds is 0.0 but temporal_order is UNKNOWN")
        return self


class DatasetSharedEntities(BaseModel):
    shared_pid: bool = Field(False, description="Source and target share the same process ID")
    shared_process_name: bool = Field(False, description="Source and target share the same executable image name")
    shared_path: bool = Field(False, description="Source and target share a common filesystem or registry path")
    shared_ip: bool = Field(False, description="Source and target share a common IP address")
    shared_user: bool = Field(False, description="Source and target share the same user account or SID")
    shared_hash: bool = Field(False, description="Source and target share an identical file hash")
    identifiers_list: List[str] = Field(default_factory=list, description="Specific matching identifier values")

    model_config = ConfigDict(extra="forbid")


class DatasetAnnotation(BaseModel):
    epistemic_label: EpistemicLabel = Field(..., description="Three-way epistemic label: VERIFIED_POSITIVE, VERIFIED_NEGATIVE, AMBIGUOUS_UNRESOLVED")
    ground_truth_causal_label: Optional[int] = Field(None, description="Binary supervisory label: 1 (positive), 0 (negative), or null (ambiguous)")
    relationship_type: RelationshipType = Field(..., description="Forensic relationship taxonomy")
    label_rationale: str = Field(..., min_length=10, description="Detailed evidentiary reasoning for the assigned label")
    annotation_source: str = Field(..., description="Methodology of annotation: EMULATION_LOG, HUMAN_EXPERT, SOURCE_CODE_TRACE, CONSENSUS")
    annotator_ids: List[str] = Field(..., min_length=1, description="Identifiers of reviewers or automated annotators")
    adjudication_status: AdjudicationStatus = Field(AdjudicationStatus.UNREVIEWED, description="Consensus and adjudication workflow status")
    annotator_confidence: float = Field(1.0, ge=0.0, le=1.0, description="Annotator subjective certainty in label assignment")
    mitre_attack_techniques: List[str] = Field(default_factory=list, description="Associated MITRE ATT&CK technique IDs (e.g. T1055)")

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def validate_label_consistency(self):
        # Strict consistency between EpistemicLabel and ground_truth_causal_label
        if self.epistemic_label == EpistemicLabel.VERIFIED_POSITIVE:
            if self.ground_truth_causal_label != 1:
                raise ValueError("VERIFIED_POSITIVE examples must have ground_truth_causal_label == 1")
            if self.relationship_type == RelationshipType.COINCIDENTAL_NOISE:
                raise ValueError("VERIFIED_POSITIVE examples cannot have relationship_type == COINCIDENTAL_NOISE")

        elif self.epistemic_label == EpistemicLabel.VERIFIED_NEGATIVE:
            if self.ground_truth_causal_label != 0:
                raise ValueError("VERIFIED_NEGATIVE examples must have ground_truth_causal_label == 0")

        elif self.epistemic_label == EpistemicLabel.AMBIGUOUS_UNRESOLVED:
            if self.ground_truth_causal_label is not None:
                raise ValueError(
                    f"AMBIGUOUS_UNRESOLVED examples must have ground_truth_causal_label == None. "
                    f"Got ground_truth_causal_label={self.ground_truth_causal_label}. "
                    f"Ambiguous examples must not be forced into a binary classification label."
                )

        return self


class DatasetCaseMetadata(BaseModel):
    os_version: str = Field("Windows 10", description="Operating system release and architecture")
    environment_type: str = Field("ENTERPRISE_WORKSTATION", description="Workstation, domain controller, or lab VM")
    scenario_type: str = Field("BENIGN_BASELINE", description="Intrusion scenario taxonomy")
    synthetic_fixture: bool = Field(False, description="Flag indicating if this case is a synthetic unit-test fixture")

    model_config = ConfigDict(extra="forbid")


class CorrelationSample(BaseModel):
    sample_id: str = Field(..., description="Unique sample identifier (e.g. PAIR-POS-1A2B3C4D)")
    investigation_id: str = Field(..., description="Unique forensic case identifier (e.g. CASE_INT_001)")
    schema_version: str = Field(CORRELATION_SCHEMA_VERSION, description="Dataset schema specification version")
    case_metadata: DatasetCaseMetadata = Field(default_factory=DatasetCaseMetadata, description="Case environmental context")
    source_artifact: DatasetArtifact = Field(..., description="Source (originating/causal) artifact representation")
    target_artifact: DatasetArtifact = Field(..., description="Target (resulting/affected) artifact representation")
    temporal_context: DatasetTemporalContext = Field(..., description="Temporal sequence and delta metadata")
    shared_entities: DatasetSharedEntities = Field(default_factory=DatasetSharedEntities, description="Cross-artifact entity overlaps")
    annotation: DatasetAnnotation = Field(..., description="Epistemic ground-truth annotation and rationale")
    split: DatasetSplit = Field(DatasetSplit.UNASSIGNED, description="Assigned group-level evaluation split")

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def validate_sample_integrity(self):
        # Prevent self-loop on identical artifact ID within the exact same domain
        if (
            self.source_artifact.artifact_id == self.target_artifact.artifact_id
            and self.source_artifact.domain == self.target_artifact.domain
        ):
            raise ValueError(
                f"Sample '{self.sample_id}' has identical source and target artifact: '{self.source_artifact.artifact_id}'"
            )

        # Validate major schema version compatibility
        expected_major = CORRELATION_SCHEMA_VERSION.split(".")[0]
        actual_major = str(self.schema_version).split(".")[0]
        if actual_major != expected_major:
            raise ValueError(
                f"Incompatible schema version '{self.schema_version}'. Expected major version '{expected_major}.x.x'"
            )

        # Validate timestamp delta consistency when both timestamps are present
        ts_a = self.source_artifact.timestamp
        ts_b = self.target_artifact.timestamp
        delta = self.temporal_context.delta_seconds

        if ts_a is not None and ts_b is not None:
            try:
                dt_a = parse_iso_timestamp(ts_a)
                dt_b = parse_iso_timestamp(ts_b)

                # Timezone compatibility check
                if (dt_a.tzinfo is None and dt_b.tzinfo is not None) or (dt_a.tzinfo is not None and dt_b.tzinfo is None):
                    raise ValueError(
                        f"Sample '{self.sample_id}' has mixed timezone-aware and timezone-naive timestamps: "
                        f"source='{ts_a}', target='{ts_b}'. Both must be UTC or offset-specified."
                    )

                computed_delta = (dt_b - dt_a).total_seconds()

                # Mathematical delta consistency check
                if delta is not None:
                    if abs(delta - computed_delta) > TIMESTAMP_DELTA_TOLERANCE_SECONDS:
                        raise ValueError(
                            f"Sample '{self.sample_id}' has inconsistent temporal delta: "
                            f"delta_seconds is {delta:.2f}s, but timestamp difference (target - source) is {computed_delta:.2f}s "
                            f"(tolerance: {TIMESTAMP_DELTA_TOLERANCE_SECONDS:.1f}s)."
                        )

                # Causal validity check: forward causal positive relations cannot have target preceding source
                if (
                    self.annotation.epistemic_label == EpistemicLabel.VERIFIED_POSITIVE
                    and self.annotation.relationship_type in FORWARD_CAUSAL_RELATIONSHIPS
                    and self.temporal_context.clock_skew_risk == ClockSkewRisk.NONE_SAME_SYSTEM
                    and self.source_artifact.timestamp_quality == TimestampQuality.EXACT_ORIGIN
                    and self.target_artifact.timestamp_quality == TimestampQuality.EXACT_ORIGIN
                ):
                    if computed_delta < -TIMESTAMP_DELTA_TOLERANCE_SECONDS:
                        raise ValueError(
                            f"Sample '{self.sample_id}' violates forward causal validity: positive causal relationship "
                            f"'{self.annotation.relationship_type.value}' has target event occurring {abs(computed_delta):.2f}s "
                            f"before source event on the same host without clock skew."
                        )

            except Exception as ex:
                if any(phrase in str(ex) for phrase in ("inconsistent temporal delta", "mixed timezone-aware", "violates forward causal validity")):
                    raise
                # Syntax errors are caught by DatasetArtifact validator

        return self

