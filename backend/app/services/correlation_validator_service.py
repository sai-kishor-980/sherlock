"""
Forensic Correlation Dataset Validator & Quality Gate Engine (Phase 1B).

Implements independent verification of:
1. Structural Validity:
   - Schema compliance & versioning
   - Internal field consistency & ISO-8601 timestamps
   - Directionality-aware duplicate pair detection (distinguishing directed vs symmetric)
   - Cyclic directed relationship detection
   - Contradictory label conflicts for identical artifact pairs
   - Investigation-level and artifact-level cross-split leakage
2. Training Readiness:
   - Research criteria from CORRELATION_TRAINING_PLAN.md
   - Gate 1: Scale (N >= 2,500)
   - Gate 2: Case Diversity (K >= 15)
   - Gate 3: Class Balance
   - Gate 4: Domain Confounding
   - Gate 5: Relationship Taxonomy Coverage
   - Gate 6: Ambiguous / Uncertainty Segregation
   - Gate 7: Adjudicated Consensus (distinguishing actual adjudication from merely multiple IDs)
"""

import os
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Set
from collections import Counter, defaultdict
from pydantic import ValidationError

from app.db.schemas.correlation_dataset import (
    CORRELATION_SCHEMA_VERSION,
    CorrelationSample,
    EpistemicLabel,
    RelationshipType,
    ArtifactDomain,
    DatasetSplit,
    TimestampQuality,
    TemporalOrderStatus,
    AdjudicationStatus,
    UNDIRECTED_RELATIONSHIP_TYPES,
    DIRECTED_RELATIONSHIP_TYPES,
    DatasetArtifact
)


def compute_artifact_evidence_fingerprint(artifact: DatasetArtifact) -> Optional[str]:
    """
    Computes a globally stable evidence fingerprint for an artifact.
    Returns None if only locally-scoped artifact identifiers are present without cryptographic hashes or physical evidence provenance.
    """
    # 1. Cryptographic hash of the entity itself
    if artifact.normalized_features and artifact.normalized_features.hash_sha256:
        return f"sha256:{artifact.normalized_features.hash_sha256.strip().lower()}"
    
    # 2. Raw evidence storage hash + locator (exact physical bitstream reference)
    prov = artifact.provenance
    if prov and prov.storage_hash:
        loc = (prov.record_locator or prov.file_path or "").strip().lower()
        return f"storage:{prov.storage_hash.strip().lower()}:{loc}"
    
    return None


class DatasetValidationResult:
    def __init__(self):
        self.total_records_processed: int = 0
        self.valid_record_count: int = 0
        self.structural_errors: List[Dict[str, Any]] = []
        self.structural_warnings: List[Dict[str, Any]] = []
        
        # Distributions
        self.label_distribution: Dict[str, int] = Counter()
        self.binary_label_distribution: Dict[str, int] = Counter()
        self.investigation_distribution: Dict[str, int] = Counter()
        self.relationship_distribution: Dict[str, int] = Counter()
        self.domain_pairs_by_label: Dict[str, Dict[str, int]] = defaultdict(Counter)
        self.domain_pair_contingency: Dict[str, Dict[str, int]] = defaultdict(Counter)
        self.split_distribution: Dict[str, int] = Counter()
        self.timestamp_quality_distribution: Dict[str, int] = Counter()
        self.provenance_missing_count: int = 0
        self.annotation_breakdown: Dict[str, int] = Counter()
        
        # Anomaly & Conflict Tracking
        self.duplicate_sample_ids: List[str] = []
        self.duplicate_artifact_pairs: List[Dict[str, Any]] = []
        self.contradictory_label_conflicts: List[Dict[str, Any]] = []
        self.cyclic_directed_relationships: List[Dict[str, Any]] = []
        self.split_investigation_leakage: List[Dict[str, Any]] = []
        self.cross_split_evidence_leakage: List[Dict[str, Any]] = []
        self.suspicious_id_similarity_diagnostics: List[Dict[str, Any]] = []
        self.partial_domain_confounding_warnings: List[str] = []
        
        # Gates & Status
        self.is_structurally_valid: bool = False
        self.is_training_ready: bool = False
        self.training_readiness_gates: Dict[str, Dict[str, Any]] = {}
        self.fatal_domain_confounding_detected: bool = False
        self.domain_confounding_details: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": {
                "total_records_processed": self.total_records_processed,
                "valid_record_count": self.valid_record_count,
                "is_structurally_valid": self.is_structurally_valid,
                "is_training_ready": self.is_training_ready,
                "structural_errors_count": len(self.structural_errors),
                "structural_warnings_count": len(self.structural_warnings),
            },
            "structural_validity": {
                "passed": self.is_structurally_valid,
                "errors": self.structural_errors,
                "warnings": self.structural_warnings,
                "duplicate_sample_ids": self.duplicate_sample_ids,
                "duplicate_artifact_pairs": self.duplicate_artifact_pairs,
                "contradictory_label_conflicts": self.contradictory_label_conflicts,
                "cyclic_directed_relationships": self.cyclic_directed_relationships,
                "split_leakage": self.split_investigation_leakage,
                "cross_split_evidence_leakage": self.cross_split_evidence_leakage,
                "suspicious_id_similarity": self.suspicious_id_similarity_diagnostics,
            },
            "distributions": {
                "epistemic_labels": dict(self.label_distribution),
                "binary_causal_labels": dict(self.binary_label_distribution),
                "investigations": dict(self.investigation_distribution),
                "unique_investigations_count": len(self.investigation_distribution),
                "relationship_types": dict(self.relationship_distribution),
                "domain_pairs_by_label": {k: dict(v) for k, v in self.domain_pairs_by_label.items()},
                "domain_pair_contingency": {k: dict(v) for k, v in self.domain_pair_contingency.items()},
                "splits": dict(self.split_distribution),
                "timestamp_qualities": dict(self.timestamp_quality_distribution),
                "provenance_missing_count": self.provenance_missing_count,
                "annotation_breakdown": dict(self.annotation_breakdown),
            },
            "training_readiness": {
                "passed": self.is_training_ready,
                "fatal_domain_confounding": self.fatal_domain_confounding_detected,
                "domain_confounding_details": self.domain_confounding_details,
                "partial_domain_confounding_warnings": self.partial_domain_confounding_warnings,
                "gates": self.training_readiness_gates,
            }
        }

    def to_text_report(self) -> str:
        lines = []
        lines.append("=" * 80)
        lines.append(" SHERLOCKAI / H-MACFR — CORRELATION DATASET VALIDATION REPORT")
        lines.append("=" * 80)
        lines.append(f" Total Records Processed: {self.total_records_processed}")
        lines.append(f" Valid Structural Records: {self.valid_record_count}")
        lines.append(f" Structural Status:        {'PASS' if self.is_structurally_valid else 'FAIL'}")
        lines.append(f" Training Readiness Status: {'READY' if self.is_training_ready else 'NOT READY (Expected for Dev/Fixtures)'}")
        lines.append("-" * 80)
        
        # Section A: Structural Validity
        lines.append(" [SECTION A] STRUCTURAL VALIDITY REPORT")
        if self.is_structurally_valid:
            lines.append("  [OK] Dataset is structurally valid, directionally sound, and internally consistent.")
        else:
            lines.append(f"  [FAIL] Found {len(self.structural_errors)} structural error(s):")
            for idx, err in enumerate(self.structural_errors[:15], 1):
                rec = err.get("record_index", "?")
                sid = err.get("sample_id", "N/A")
                msg = err.get("message", "")
                lines.append(f"    {idx}. [Rec {rec} | ID: {sid}] {msg}")
            if len(self.structural_errors) > 15:
                lines.append(f"    ... and {len(self.structural_errors) - 15} more error(s).")

        if self.duplicate_sample_ids:
            lines.append(f"  [ERROR] Duplicate Sample IDs ({len(self.duplicate_sample_ids)}): {self.duplicate_sample_ids[:5]}")
        if self.duplicate_artifact_pairs:
            lines.append(f"  [ERROR] Duplicate Artifact Pairs: {len(self.duplicate_artifact_pairs)} occurrence(s) detected.")
        if self.contradictory_label_conflicts:
            lines.append(f"  [CRITICAL] Contradictory Label Conflicts: {len(self.contradictory_label_conflicts)} conflict(s) detected for same evidence pairs!")
            for c in self.contradictory_label_conflicts[:3]:
                inv = c.get("investigation_id")
                assertion_str = c.get("assertion") or c.get("pair")
                lines.append(f"    - Case '{inv}' {assertion_str}: labels={c.get('conflicting_labels')}")
        if self.cyclic_directed_relationships:
            lines.append(f"  [CRITICAL] Cyclic Directed Relationships: {len(self.cyclic_directed_relationships)} physical impossibility cycle(s) detected!")
        if self.split_investigation_leakage:
            lines.append(f"  [CRITICAL] Investigation-Level Split Leakage: {len(self.split_investigation_leakage)} case(s) found across multiple splits!")
            for leak in self.split_investigation_leakage:
                lines.append(f"    - Case '{leak.get('investigation_id')}' in splits: {leak.get('splits')}")
        if self.cross_split_evidence_leakage:
            lines.append(f"  [CRITICAL] Artifact-Level Cross-Split Leakage: {len(self.cross_split_evidence_leakage)} evidence pair(s) present in multiple splits!")

        if self.suspicious_id_similarity_diagnostics:
            lines.append(f"  [INFO] Suspicious Generic ID Similarities ({len(self.suspicious_id_similarity_diagnostics)}): Non-confounding local ID collisions across splits.")

        if self.structural_warnings:
            lines.append(f"  [WARNING] {len(self.structural_warnings)} structural warning(s):")
            for idx, warn in enumerate(self.structural_warnings[:10], 1):
                lines.append(f"    {idx}. {warn.get('message')}")

        lines.append("-" * 80)
        # Section B: Distributions & Forensic Metrics
        lines.append(" [SECTION B] FORENSIC DISTRIBUTIONS & STATISTICS")
        lines.append(f"  Investigations (Cases): {len(self.investigation_distribution)} unique case(s)")
        for inv, count in self.investigation_distribution.most_common(5):
            lines.append(f"    - {inv}: {count} pair(s)")
        if len(self.investigation_distribution) > 5:
            lines.append(f"    ... and {len(self.investigation_distribution) - 5} more case(s)")

        lines.append(f"  Epistemic Labels: {dict(self.label_distribution)}")
        lines.append(f"  Binary Causal Labels: {dict(self.binary_label_distribution)}")
        lines.append(f"  Relationship Types: {dict(self.relationship_distribution)}")
        
        if self.annotation_breakdown:
            lines.append("  Annotation Pathways & Adjudication Breakdown:")
            for k in ["EMULATION_LOG", "CONSENSUS_VERIFIED", "ARBITRATED", "SINGLE_REVIEWER", "UNREVIEWED", "DISPUTED"]:
                cnt = self.annotation_breakdown.get(k, 0)
                lines.append(f"    - {k}: {cnt} record(s)")

        if self.domain_pair_contingency:
            lines.append("  Top Domain Transitions Contingency (Source -> Target):")
            for dp, counts in sorted(self.domain_pair_contingency.items(), key=lambda x: x[1].get("TOTAL", 0), reverse=True)[:6]:
                pos = counts.get("VERIFIED_POSITIVE", 0)
                neg = counts.get("VERIFIED_NEGATIVE", 0)
                amb = counts.get("AMBIGUOUS_UNRESOLVED", 0)
                tot = counts.get("TOTAL", 0)
                lines.append(f"    - {dp}: Total={tot} (Pos={pos}, Neg={neg}, Amb={amb})")

        lines.append(f"  Artifact Missing Provenance Count: {self.provenance_missing_count}")
        lines.append(f"  Timestamp Qualities: {dict(self.timestamp_quality_distribution)}")

        lines.append("-" * 80)
        # Section C: Training Readiness Gates
        lines.append(" [SECTION C] RESEARCH TRAINING READINESS GATES")
        lines.append("  (Evaluates compliance with CORRELATION_TRAINING_PLAN.md criteria)")
        for gate_name, gate_info in self.training_readiness_gates.items():
            status = gate_info.get("status", "FAIL")
            target = gate_info.get("target", "")
            actual = gate_info.get("actual", "")
            lines.append(f"  - {gate_name}: [{status}] (Target: {target} | Measured: {actual})")
            if status != "PASS" and "diagnostic" in gate_info:
                lines.append(f"      Diagnostic: {gate_info['diagnostic']}")

        if self.partial_domain_confounding_warnings:
            lines.append("  [WARNING] Partial Domain Confounding Diagnostics:")
            for warn in self.partial_domain_confounding_warnings[:5]:
                lines.append(f"    - {warn}")

        if self.fatal_domain_confounding_detected:
            lines.append(f"  [FATAL CONFLICT] Domain Confounding Detected: {self.domain_confounding_details}")

        lines.append("=" * 80)
        return "\n".join(lines)


class CorrelationDatasetValidator:
    """
    Validator service for forensic correlation datasets.
    """

    @classmethod
    def load_dataset_file(cls, file_path: Path) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Loads records from JSON (array of objects) or JSONL (one object per line).
        Optimized for large files via streaming line-by-line reading when JSONL.
        """
        records = []
        load_errors = []
        path = Path(file_path)

        if not path.exists():
            return [], [{"record_index": 0, "message": f"File does not exist: {path}"}]

        file_size = path.stat().st_size
        if file_size == 0:
            return [], [{"record_index": 0, "message": "Dataset file is empty (0 bytes)."}]

        # Check file extension or stream first non-empty byte
        is_jsonl = path.suffix.lower() == ".jsonl"

        if not is_jsonl:
            # Peek first character
            with open(path, "r", encoding="utf-8") as peek_f:
                first_char = peek_f.read(1)
                while first_char and first_char.isspace():
                    first_char = peek_f.read(1)
                if first_char == "[":
                    # Load as standard JSON array
                    peek_f.seek(0)
                    try:
                        data = json.load(peek_f)
                        if isinstance(data, list):
                            return data, []
                        else:
                            return [], [{"record_index": 0, "message": "Root element of JSON dataset must be an array."}]
                    except json.JSONDecodeError as ex:
                        return [], [{"record_index": 0, "message": f"JSON syntax parse error: {str(ex)}"}]

        # Stream as JSONL line by line (memory-efficient for large datasets)
        with open(path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, start=1):
                line_str = line.strip()
                if not line_str or line_str.startswith("#"):
                    continue
                try:
                    obj = json.loads(line_str)
                    records.append(obj)
                except json.JSONDecodeError as ex:
                    load_errors.append({"record_index": line_num, "message": f"JSONL parse error on line {line_num}: {str(ex)}"})

        return records, load_errors

    @classmethod
    def validate(cls, data_or_path: Any) -> DatasetValidationResult:
        """
        Main validation entrypoint. Accepts file path (str or Path) or in-memory list of dicts.
        """
        result = DatasetValidationResult()

        raw_records = []
        if isinstance(data_or_path, (str, Path)):
            raw_records, load_errors = cls.load_dataset_file(Path(data_or_path))
            result.structural_errors.extend(load_errors)
            if load_errors:
                result.is_structurally_valid = False
                return result
        elif isinstance(data_or_path, list):
            raw_records = data_or_path
        else:
            result.structural_errors.append({"record_index": 0, "message": "Input must be a valid file path or list of dictionaries."})
            result.is_structurally_valid = False
            return result

        result.total_records_processed = len(raw_records)
        if len(raw_records) == 0:
            result.structural_errors.append({"record_index": 0, "message": "Dataset contains 0 records."})
            result.is_structurally_valid = False
            return result

        seen_sample_ids: Set[str] = set()
        
        # Assertion records:
        # Key: (investigation_id, src_dom, src_id, tgt_dom, tgt_id, rel_type, directionality_str)
        assertion_records: Dict[Tuple[str, str, str, str, str, str, str], List[Dict[str, Any]]] = defaultdict(list)
        
        # Positive directed edges for cyclic causality detection:
        # Key: (investigation_id, (src_dom, src_id), (tgt_dom, tgt_id))
        positive_directed_edges: Dict[Tuple[str, Tuple[str, str], Tuple[str, str]], List[Dict[str, Any]]] = defaultdict(list)
        
        # Pair-level tracking for causal link vs coincidental noise contradiction:
        # Key: (investigation_id, min_ent, max_ent)
        pair_causal_positives: Dict[Tuple[str, Tuple[str, str], Tuple[str, str]], List[Dict[str, Any]]] = defaultdict(list)
        pair_coincidental_noise: Dict[Tuple[str, Tuple[str, str], Tuple[str, str]], List[Dict[str, Any]]] = defaultdict(list)
        
        # Cross-split tracking:
        # Confirmed physical evidence fingerprints:
        global_fingerprint_splits: Dict[Tuple[str, str], Dict[str, List[Tuple[str, str]]]] = defaultdict(lambda: defaultdict(list))
        # Generic local artifact IDs (for non-fatal similarity diagnostics):
        global_generic_id_splits: Dict[Tuple[Tuple[str, str], Tuple[str, str]], Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))
        # Case splits:
        investigation_splits: Dict[str, Set[str]] = defaultdict(set)
        
        valid_samples: List[CorrelationSample] = []

        # -----------------------------------------------------------------
        # STEP 1: Record-by-Record Structural Validation
        # -----------------------------------------------------------------
        for idx, rec in enumerate(raw_records, start=1):
            if not isinstance(rec, dict):
                result.structural_errors.append({
                    "record_index": idx,
                    "sample_id": "N/A",
                    "message": f"Record must be a JSON object; got {type(rec).__name__}"
                })
                continue

            sid = rec.get("sample_id", f"REC-{idx}")
            inv_id = rec.get("investigation_id")

            # Check Sample ID Duplication
            if sid in seen_sample_ids:
                result.duplicate_sample_ids.append(sid)
                result.structural_errors.append({
                    "record_index": idx,
                    "sample_id": sid,
                    "message": f"Duplicate sample_id '{sid}' detected."
                })
            seen_sample_ids.add(sid)

            # Schema version check
            ver = rec.get("schema_version")
            if not ver:
                result.structural_errors.append({
                    "record_index": idx,
                    "sample_id": sid,
                    "message": "Missing required field 'schema_version'."
                })
            elif str(ver).split(".")[0] != CORRELATION_SCHEMA_VERSION.split(".")[0]:
                result.structural_errors.append({
                    "record_index": idx,
                    "sample_id": sid,
                    "message": f"Incompatible major schema_version '{ver}'. Expected '{CORRELATION_SCHEMA_VERSION.split('.')[0]}.x.x'"
                })
            elif ver != CORRELATION_SCHEMA_VERSION:
                result.structural_warnings.append({
                    "record_index": idx,
                    "sample_id": sid,
                    "message": f"Sample schema_version '{ver}' differs from current specification '{CORRELATION_SCHEMA_VERSION}'"
                })

            # Pydantic Model Validation
            try:
                sample = CorrelationSample.model_validate(rec)
                valid_samples.append(sample)
                result.valid_record_count += 1
            except ValidationError as ve:
                for err in ve.errors():
                    field_path = ".".join(str(p) for p in err.get("loc", []))
                    err_msg = err.get("msg", "")
                    result.structural_errors.append({
                        "record_index": idx,
                        "sample_id": sid,
                        "field": field_path,
                        "message": f"Field '{field_path}': {err_msg}"
                    })
                continue

            src_a = sample.source_artifact
            src_b = sample.target_artifact
            rel_type = sample.annotation.relationship_type
            ep_label = sample.annotation.epistemic_label
            causal_label = sample.annotation.ground_truth_causal_label

            pair_meta = {
                "sample_id": sample.sample_id,
                "epistemic_label": ep_label.value,
                "causal_label": causal_label,
                "rel_type": rel_type.value,
                "split": sample.split.value,
                "source": f"{src_a.domain.value}:{src_a.artifact_id}",
                "target": f"{src_b.domain.value}:{src_b.artifact_id}"
            }

            ent_a = (src_a.domain.value, src_a.artifact_id)
            ent_b = (src_b.domain.value, src_b.artifact_id)
            min_ent, max_ent = sorted([ent_a, ent_b])
            canon_pair_key = (sample.investigation_id, min_ent, max_ent)

            # 1. Assertion Registration
            if rel_type in UNDIRECTED_RELATIONSHIP_TYPES:
                # Symmetrically unlinked (e.g. COINCIDENTAL_NOISE)
                assertion_key = (
                    sample.investigation_id,
                    min_ent[0], min_ent[1],
                    max_ent[0], max_ent[1],
                    rel_type.value,
                    "UNDIRECTED_SYMMETRIC"
                )
            else:
                # Directed assertion (A -> B for specific relationship)
                assertion_key = (
                    sample.investigation_id,
                    src_a.domain.value, src_a.artifact_id,
                    src_b.domain.value, src_b.artifact_id,
                    rel_type.value,
                    "DIRECTED"
                )
            assertion_records[assertion_key].append(pair_meta)

            # 2. Directed positive edges for cycle tracking
            if causal_label == 1 and rel_type in DIRECTED_RELATIONSHIP_TYPES:
                pos_dir_key = (sample.investigation_id, ent_a, ent_b)
                positive_directed_edges[pos_dir_key].append(pair_meta)
                pair_causal_positives[canon_pair_key].append(pair_meta)

            if rel_type == RelationshipType.COINCIDENTAL_NOISE:
                pair_coincidental_noise[canon_pair_key].append(pair_meta)

            # 3. Cross-Split Evidence Tracking
            if sample.split != DatasetSplit.UNASSIGNED:
                investigation_splits[sample.investigation_id].add(sample.split.value)

                # Stable physical evidence fingerprint
                fp_a = compute_artifact_evidence_fingerprint(src_a)
                fp_b = compute_artifact_evidence_fingerprint(src_b)
                if fp_a and fp_b:
                    canon_fp = tuple(sorted([fp_a, fp_b]))
                    global_fingerprint_splits[canon_fp][sample.split.value].append((sample.investigation_id, sample.sample_id))

                # Local generic ID pair similarity
                canon_glob_id = (min_ent, max_ent)
                global_generic_id_splits[canon_glob_id][sample.split.value].add(sample.investigation_id)

            # Accumulate distributions
            result.label_distribution[ep_label.value] += 1
            bin_label = "POSITIVE (1)" if causal_label == 1 else (
                "NEGATIVE (0)" if causal_label == 0 else "AMBIGUOUS (null)"
            )
            result.binary_label_distribution[bin_label] += 1
            result.investigation_distribution[sample.investigation_id] += 1
            result.relationship_distribution[rel_type.value] += 1
            result.split_distribution[sample.split.value] += 1

            # Domain contingency & cross vs intra
            domain_pair_str = f"{src_a.domain.value} -> {src_b.domain.value}"
            result.domain_pairs_by_label[ep_label.value][domain_pair_str] += 1
            result.domain_pair_contingency[domain_pair_str][ep_label.value] += 1
            result.domain_pair_contingency[domain_pair_str]["TOTAL"] += 1

            # Timestamp quality
            result.timestamp_quality_distribution[f"src_{src_a.timestamp_quality.value}"] += 1
            result.timestamp_quality_distribution[f"tgt_{src_b.timestamp_quality.value}"] += 1

            # Provenance tracking
            if not src_a.provenance.file_path and not src_a.provenance.evidence_id and not src_a.provenance.storage_hash:
                result.provenance_missing_count += 1
            if not src_b.provenance.file_path and not src_b.provenance.evidence_id and not src_b.provenance.storage_hash:
                result.provenance_missing_count += 1

        # -----------------------------------------------------------------
        # STEP 2: Duplicate, Contradiction, and Cycle Analysis
        # -----------------------------------------------------------------
        # 2A. Assertion Duplicates & Assertion Contradictions
        for (inv, da, aa, db, ab, rel, dir_type), metas in assertion_records.items():
            if len(metas) > 1:
                sids = [m["sample_id"] for m in metas]
                labels = sorted(list(set(m["epistemic_label"] for m in metas)))
                if len(labels) > 1:
                    # Contradictory labels for identical assertion
                    result.contradictory_label_conflicts.append({
                        "investigation_id": inv,
                        "assertion": f"{da}:{aa} -> {db}:{ab} ({rel})",
                        "conflicting_labels": labels,
                        "sample_ids": sids
                    })
                    result.structural_errors.append({
                        "record_index": 0,
                        "sample_id": sids[0],
                        "message": f"Contradictory label conflict in investigation '{inv}': Assertion {da}:{aa} -> {db}:{ab} for '{rel}' has conflicting labels {labels} across samples {sids}."
                    })
                else:
                    # Duplicate identical assertion
                    result.duplicate_artifact_pairs.append({
                        "investigation_id": inv,
                        "source": f"{da}:{aa}",
                        "target": f"{db}:{ab}",
                        "relationship_type": rel,
                        "directionality": dir_type,
                        "sample_ids": sids,
                        "count": len(sids)
                    })
                    dir_str = "symmetric" if dir_type == "UNDIRECTED_SYMMETRIC" else "directed"
                    result.structural_errors.append({
                        "record_index": 0,
                        "sample_id": sids[0],
                        "message": f"Duplicate pair detected ({dir_str}) in investigation '{inv}': {da}:{aa} -> {db}:{ab} for relationship '{rel}' repeated {len(sids)} times across samples {sids}."
                    })

        # 2B. Causal vs Coincidental Noise Contradiction on Evidence Pair
        for canon_pair_key, pos_metas in pair_causal_positives.items():
            if canon_pair_key in pair_coincidental_noise:
                noise_metas = pair_coincidental_noise[canon_pair_key]
                inv, (da, aa), (db, ab) = canon_pair_key
                sids_pos = [m["sample_id"] for m in pos_metas]
                sids_noise = [m["sample_id"] for m in noise_metas]
                rel_pos = sorted(list(set(m["rel_type"] for m in pos_metas)))
                result.contradictory_label_conflicts.append({
                    "investigation_id": inv,
                    "pair": f"{da}:{aa} <-> {db}:{ab}",
                    "conflicting_labels": ["VERIFIED_POSITIVE_CAUSAL", "COINCIDENTAL_NOISE"],
                    "sample_ids": sids_pos + sids_noise
                })
                result.structural_errors.append({
                    "record_index": 0,
                    "sample_id": sids_pos[0],
                    "message": f"Contradictory label conflict in investigation '{inv}': Evidence pair {da}:{aa} <-> {db}:{ab} has samples claiming verified positive causal relationship ({rel_pos}) while sample(s) {sids_noise} claim COINCIDENTAL_NOISE."
                })

        # 2C. Causal Cycle Detection on Directed Positive Edges
        seen_cycles: Set[Tuple[str, Tuple[str, str], Tuple[str, str]]] = set()
        for (inv, ent_a, ent_b), pos_fwd in positive_directed_edges.items():
            rev_key = (inv, ent_b, ent_a)
            if rev_key in positive_directed_edges:
                pos_rev = positive_directed_edges[rev_key]
                canon_cycle = (inv, min(ent_a, ent_b), max(ent_a, ent_b))
                if canon_cycle not in seen_cycles:
                    seen_cycles.add(canon_cycle)
                    da, aa = ent_a
                    db, ab = ent_b
                    result.cyclic_directed_relationships.append({
                        "investigation_id": inv,
                        "pair_forward": f"{da}:{aa} -> {db}:{ab}",
                        "pair_reverse": f"{db}:{ab} -> {da}:{aa}",
                        "sample_ids": [pos_fwd[0]["sample_id"], pos_rev[0]["sample_id"]]
                    })
                    result.structural_errors.append({
                        "record_index": 0,
                        "sample_id": pos_fwd[0]["sample_id"],
                        "message": f"Cyclic / inverted directed causality error in investigation '{inv}': Both {da}:{aa} -> {db}:{ab} and {db}:{ab} -> {da}:{aa} claim positive causal lineage."
                    })

        # -----------------------------------------------------------------
        # STEP 3: Leakage Detection (Investigation-Level & Artifact-Level)
        # -----------------------------------------------------------------
        # 3A. Investigation Split Leakage
        for inv_id, splits in investigation_splits.items():
            if len(splits) > 1:
                leak_info = {"investigation_id": inv_id, "splits": sorted(list(splits))}
                result.split_investigation_leakage.append(leak_info)
                result.structural_errors.append({
                    "record_index": 0,
                    "sample_id": "N/A",
                    "message": f"Data leakage error: Investigation '{inv_id}' is partitioned across multiple splits: {sorted(list(splits))}. Cases must be strictly group-partitioned."
                })

        # 3B. Confirmed Artifact-Level Cross-Split Evidence Leakage (via stable fingerprint)
        for (fp1, fp2), splits_dict in global_fingerprint_splits.items():
            if len(splits_dict) > 1:
                splits_list = sorted(list(splits_dict.keys()))
                leak_detail = {
                    "fingerprints": f"{fp1} <-> {fp2}",
                    "splits": splits_list,
                    "samples_by_split": {s: items for s, items in splits_dict.items()}
                }
                result.cross_split_evidence_leakage.append(leak_detail)
                result.structural_errors.append({
                    "record_index": 0,
                    "sample_id": "N/A",
                    "message": f"Cross-split duplicate evidence leakage: Artifact pair with fingerprints {fp1} <-> {fp2} appears across multiple splits: {splits_list} (samples: {dict(splits_dict)})."
                })

        # 3C. Generic ID Similarity across splits (Warning only, not structural error)
        for (min_ent, max_ent), splits_dict in global_generic_id_splits.items():
            if len(splits_dict) > 1:
                splits_list = sorted(list(splits_dict.keys()))
                da, aa = min_ent
                db, ab = max_ent
                sim_detail = {
                    "pair": f"{da}:{aa} <-> {db}:{ab}",
                    "splits": splits_list,
                    "cases": {s: list(cases) for s, cases in splits_dict.items()}
                }
                result.suspicious_id_similarity_diagnostics.append(sim_detail)
                result.structural_warnings.append({
                    "record_index": 0,
                    "sample_id": "N/A",
                    "message": f"Suspicious generic ID similarity across splits: Pair {da}:{aa} <-> {db}:{ab} appears across splits {splits_list} in cases {dict(splits_dict)}. Verify local identifier namespace independence."
                })

        # Set Structural Validity
        result.is_structurally_valid = (
            len(result.structural_errors) == 0
            and len(result.duplicate_sample_ids) == 0
            and len(result.duplicate_artifact_pairs) == 0
            and len(result.contradictory_label_conflicts) == 0
            and len(result.cyclic_directed_relationships) == 0
            and len(result.split_investigation_leakage) == 0
            and len(result.cross_split_evidence_leakage) == 0
            and result.valid_record_count > 0
        )

        # -----------------------------------------------------------------
        # STEP 4: Research Training Readiness Gates
        # Evaluates full production criteria from CORRELATION_TRAINING_PLAN.md
        # -----------------------------------------------------------------
        cls._evaluate_training_readiness(result, valid_samples)

        return result

    @classmethod
    def _evaluate_training_readiness(cls, result: DatasetValidationResult, samples: List[CorrelationSample]):
        gates = {}
        total = len(samples)

        # Gate 1: Scale (Target: >= 2,500 samples)
        g1_pass = total >= 2500
        gates["Gate 1: Minimum Scale"] = {
            "status": "PASS" if g1_pass else "FAIL",
            "target": ">= 2,500 pairs",
            "actual": f"{total} pairs",
            "diagnostic": "Corpus scale satisfies minimum statistical requirement." if g1_pass else f"Corpus has {total} pairs; requires >= 2,500 pairs for supervised training."
        }

        # Gate 2: Case Diversity (Target: >= 15 independent investigations)
        unique_cases = len(result.investigation_distribution)
        g2_pass = unique_cases >= 15
        gates["Gate 2: Case Diversity"] = {
            "status": "PASS" if g2_pass else "FAIL",
            "target": ">= 15 independent investigations",
            "actual": f"{unique_cases} investigations",
            "diagnostic": "Investigation diversity satisfies case-generalization requirement." if g2_pass else f"Only {unique_cases} case(s) present. Model risks memorizing specific environment topology."
        }

        # Gate 3: Class Balance (Target: 35% - 55% positive, 45% - 65% negative)
        positives = [s for s in samples if s.annotation.epistemic_label == EpistemicLabel.VERIFIED_POSITIVE]
        negatives = [s for s in samples if s.annotation.epistemic_label == EpistemicLabel.VERIFIED_NEGATIVE]
        ambiguous = [s for s in samples if s.annotation.epistemic_label == EpistemicLabel.AMBIGUOUS_UNRESOLVED]

        pos_ratio = (len(positives) / total) if total > 0 else 0.0
        neg_ratio = (len(negatives) / total) if total > 0 else 0.0
        amb_ratio = (len(ambiguous) / total) if total > 0 else 0.0

        g3_pass = (0.35 <= pos_ratio <= 0.55) and (0.45 <= neg_ratio <= 0.65)
        gates["Gate 3: Class Balance"] = {
            "status": "PASS" if g3_pass else "FAIL",
            "target": "35%-55% Positives, 45%-65% Negatives",
            "actual": f"{pos_ratio*100:.1f}% Pos, {neg_ratio*100:.1f}% Neg, {amb_ratio*100:.1f}% Amb",
            "diagnostic": "Class balance within acceptable statistical bounds." if g3_pass else f"Imbalance detected: Positives={pos_ratio*100:.1f}%, Negatives={neg_ratio*100:.1f}%."
        }

        # Gate 4: Domain Balance & Confounding Check
        pos_cross = sum(1 for s in positives if s.source_artifact.domain != s.target_artifact.domain)
        pos_cross_ratio = (pos_cross / len(positives)) if positives else 0.0

        neg_intra = sum(1 for s in negatives if s.source_artifact.domain == s.target_artifact.domain)
        neg_intra_ratio = (neg_intra / len(negatives)) if negatives else 0.0

        # Fatal Confounding Check (both directions)
        if len(positives) > 0 and len(negatives) > 0:
            if pos_cross == 0 and neg_intra == 0:
                result.fatal_domain_confounding_detected = True
                result.domain_confounding_details = (
                    "100% of positive pairs are intra-domain AND 100% of negative pairs are cross-domain. "
                    "A classifier will trivially memorize domain equality instead of causal forensic features."
                )
            elif pos_cross == len(positives) and neg_intra == len(negatives):
                result.fatal_domain_confounding_detected = True
                result.domain_confounding_details = (
                    "100% of positive pairs are cross-domain AND 100% of negative pairs are intra-domain. "
                    "A classifier will trivially memorize domain difference instead of causal forensic features."
                )

        # Partial Confounding Diagnostics
        for dp_str, counts in result.domain_pair_contingency.items():
            pos = counts.get("VERIFIED_POSITIVE", 0)
            neg = counts.get("VERIFIED_NEGATIVE", 0)
            total_eval = pos + neg
            if total_eval >= 5:
                pos_pct = pos / total_eval
                if pos_pct >= 0.90:
                    result.partial_domain_confounding_warnings.append(
                        f"Transition '{dp_str}' is {pos_pct*100:.1f}% positive ({pos}/{total_eval}). Potential domain shortcut."
                    )
                elif pos_pct <= 0.10:
                    result.partial_domain_confounding_warnings.append(
                        f"Transition '{dp_str}' is {pos_pct*100:.1f}% positive ({pos}/{total_eval}) ({neg} negatives). Potential domain shortcut."
                    )

        g4_pass = (0.40 <= pos_cross_ratio <= 0.60) and (0.35 <= neg_intra_ratio <= 0.60) and not result.fatal_domain_confounding_detected
        gates["Gate 4: Domain Balance (No Confounding)"] = {
            "status": "PASS" if g4_pass else "FAIL",
            "target": "Positives: 40%-60% cross-domain; Negatives: 35%-60% intra-domain",
            "actual": f"Pos Cross={pos_cross_ratio*100:.1f}%, Neg Intra={neg_intra_ratio*100:.1f}%",
            "diagnostic": "Domain representation is balanced across classes." if g4_pass else (
                result.domain_confounding_details or f"Domain confounding present: Positives Cross={pos_cross_ratio*100:.1f}%, Negatives Intra={neg_intra_ratio*100:.1f}%"
            )
        }

        # Gate 5: Relationship Taxonomy Coverage (Target: >= 6 distinct types with >= 10 pairs each)
        distinct_types = len(result.relationship_distribution)
        g5_pass = distinct_types >= 6 and all(count >= 10 for count in result.relationship_distribution.values())
        gates["Gate 5: Relationship Type Coverage"] = {
            "status": "PASS" if g5_pass else "FAIL",
            "target": ">= 6 relationship types with >= 10 pairs each",
            "actual": f"{distinct_types} distinct types represented",
            "diagnostic": "Relationship taxonomy is well represented." if g5_pass else f"Limited relationship coverage: only {distinct_types} distinct types."
        }

        # Gate 6: Ambiguous / Uncertainty Segregation (Target: >= 5% ambiguous examples present)
        g6_pass = amb_ratio >= 0.05
        gates["Gate 6: Ambiguous / Uncertainty Representation"] = {
            "status": "PASS" if g6_pass else "FAIL",
            "target": ">= 5.0% Ambiguous/Unresolved pairs",
            "actual": f"{amb_ratio*100:.1f}% ({len(ambiguous)} pairs)",
            "diagnostic": "Sufficient ambiguous examples for calibration/uncertainty evaluation." if g6_pass else f"Ambiguous ratio is {amb_ratio*100:.1f}%; must have >= 5% to evaluate model calibration."
        }

        # Gate 7: Adjudicated Consensus & Provenance
        # Strictly separates independent annotation consensus, arbitration, and emulation-backed ground truth.
        emulation_count = 0
        consensus_count = 0
        arbitrated_count = 0
        single_count = 0
        unreviewed_count = 0
        disputed_count = 0

        for s in samples:
            ann = s.annotation
            if ann.adjudication_status == AdjudicationStatus.DISPUTED:
                disputed_count += 1
            elif ann.annotation_source == "EMULATION_LOG":
                emulation_count += 1
            elif len(ann.annotator_ids) >= 2 and ann.adjudication_status == AdjudicationStatus.CONSENSUS_VERIFIED:
                consensus_count += 1
            elif len(ann.annotator_ids) >= 2 and ann.adjudication_status == AdjudicationStatus.ARBITRATED:
                arbitrated_count += 1
            elif ann.adjudication_status == AdjudicationStatus.SINGLE_REVIEWER:
                single_count += 1
            else:
                unreviewed_count += 1

        result.annotation_breakdown = {
            "EMULATION_LOG": emulation_count,
            "CONSENSUS_VERIFIED": consensus_count,
            "ARBITRATED": arbitrated_count,
            "SINGLE_REVIEWER": single_count,
            "UNREVIEWED": unreviewed_count,
            "DISPUTED": disputed_count,
        }

        verified_total = emulation_count + consensus_count + arbitrated_count
        consensus_ratio = (verified_total / total) if total > 0 else 0.0
        g7_pass = consensus_ratio >= 0.80 and disputed_count == 0

        gates["Gate 7: Annotation Consensus & Quality"] = {
            "status": "PASS" if g7_pass else "FAIL",
            "target": ">= 80% adjudicated consensus or emulation verified; 0 disputed",
            "actual": f"{consensus_ratio*100:.1f}% verified ({verified_total}/{total}), {disputed_count} disputed",
            "diagnostic": (
                f"Consensus protocol satisfied: {verified_total}/{total} verified "
                f"[Emulation: {emulation_count}, Consensus: {consensus_count}, Arbitrated: {arbitrated_count}]."
                if g7_pass else (
                    f"Consensus gate failed: {consensus_ratio*100:.1f}% verified (target >= 80%), {disputed_count} unresolved disputed label(s)."
                )
            )
        }

        result.training_readiness_gates = gates
        result.is_training_ready = (
            result.is_structurally_valid
            and g1_pass and g2_pass and g3_pass and g4_pass and g5_pass and g6_pass and g7_pass
        )
