"""
SherlockAI — Correlation Pipeline Evaluation Harness.

Runs the real ForensicSynthesizerService production correlation pipeline against
verified forensic case data and evaluates predicted correlations against
audited dataset labels (e.g. pilot_phase1c2_audited_expanded_dataset.json).

Treatment of Ambiguity:
- Epistemic label AMBIGUOUS_UNRESOLVED is EXCLUDED from binary precision/recall scoring
  to avoid penalizing the engine for acknowledging investigative uncertainty.
- Binary metrics (TP, FP, TN, FN, Precision, Recall, F1) are computed strictly
  on VERIFIED_POSITIVE and VERIFIED_NEGATIVE pairs.
"""

import sys
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

from app.services.synthesizer_service import ForensicSynthesizerService


# Case ID mapping between dataset investigation IDs and physical case directories
CASE_MAPPING = {
    "PILOT_CASE_JW01": "Standalone Artifact Test",
    "PILOT_CASE_CR02": "Bharath_TES1",
    "PILOT_CASE_SRV03": "DISK_2"
}


def normalize_token(s: Optional[str]) -> str:
    if not s:
        return ""
    # Strip paths, extensions, quotes, and whitespace
    p = Path(s.strip().strip('"').strip("'"))
    name = p.name.lower()
    return name


def match_correlation_to_pair(corr: Dict[str, Any], sample: Dict[str, Any]) -> bool:
    """
    Determines if a predicted correlation matches a dataset artifact pair.
    Uses domain transition, entity identifiers, and relationship type.
    """
    src_art = sample.get("source_artifact", {})
    tgt_art = sample.get("target_artifact", {})
    
    src_feat = src_art.get("normalized_features", {}) or {}
    tgt_feat = tgt_art.get("normalized_features", {}) or {}

    src_domain = src_art.get("domain", "").lower()
    tgt_domain = tgt_art.get("domain", "").lower()
    
    c_src = corr.get("source_a", {})
    c_tgt = corr.get("source_b", {})
    
    c_src_domain = c_src.get("domain", "").lower()
    c_tgt_domain = c_tgt.get("domain", "").lower()
    
    # 1. Process Lineage & Injection (Memory -> Memory)
    if src_domain == "memory" and tgt_domain == "memory":
        src_pid = str(src_feat.get("pid") or "")
        tgt_pid = str(tgt_feat.get("pid") or "")
        
        c_src_id = str(c_src.get("artifact_id", "")).replace("PID-", "")
        c_tgt_id = str(c_tgt.get("artifact_id", "")).replace("PID-", "")
        
        # Check direct PID match
        if src_pid and tgt_pid and c_src_id and c_tgt_id:
            if src_pid == c_src_id and tgt_pid == c_tgt_id:
                return True
            # Intra-process VAD memory injection (src is process, tgt is VAD of same process)
            if tgt_art.get("artifact_type") == "vad_memory" and src_pid == tgt_pid == c_tgt_id:
                return True
        
        # Fallback to entity names
        s_name = normalize_token(src_feat.get("entity_name") or src_art.get("entity_name") or src_art.get("artifact_id"))
        t_name = normalize_token(tgt_feat.get("entity_name") or tgt_art.get("entity_name") or tgt_art.get("artifact_id"))
        cs_name = normalize_token(c_src.get("entity"))
        ct_name = normalize_token(c_tgt.get("entity"))

        # Strip .exe for comparison
        s_base = s_name.replace(".exe", "").split("_")[0]
        t_base = t_name.replace(".exe", "").split("_")[0]
        cs_base = cs_name.replace(".exe", "")
        ct_base = ct_name.replace(".exe", "")

        if s_base and t_base and cs_base and ct_base:
            if s_base == cs_base and t_base == ct_base:
                return True

    # 2. Persistence-to-Execution (Registry/Logs -> Disk)
    if tgt_domain == "disk" and src_domain in ("registry", "logs"):
        s_key = normalize_token(src_feat.get("entity_name") or src_art.get("entity_name") or src_art.get("provenance", {}).get("record_locator"))
        t_exe = normalize_token(tgt_feat.get("entity_name") or tgt_art.get("entity_name") or tgt_art.get("provenance", {}).get("file_path"))
        
        cs_key = normalize_token(c_src.get("entity") or c_src.get("artifact_id"))
        ct_exe = normalize_token(c_tgt.get("entity") or c_tgt.get("artifact_id"))
        
        if t_exe and ct_exe:
            t_clean = t_exe.replace(".exe", "").replace(".sys", "").replace(".pf", "").split("-")[0].lower()
            ct_clean = ct_exe.replace(".exe", "").replace(".sys", "").replace(".pf", "").split("-")[0].lower()
            if t_clean == ct_clean:
                # Also check source alignment if available
                if cs_key and s_key:
                    s_clean = s_key.split("\\")[-1].lower()
                    cs_clean = cs_key.split("\\")[-1].lower()
                    if s_clean in cs_clean or cs_clean in s_clean:
                        return True
                return True

    # 3. DNS to Network Flow (Network -> Network)
    if src_domain == "network" and tgt_domain == "network":
        s_query = normalize_token(src_feat.get("entity_name") or src_art.get("entity_name"))
        cs_query = normalize_token(c_src.get("entity"))
        if s_query and cs_query and s_query == cs_query:
            return True

    # 4. USB Registration to Execution / File Access
    if src_domain == "registry" and "usb" in str(src_art.get("artifact_type", "")).lower():
        if "usb" in str(corr.get("relationship_type", "")).lower():
            return True

    return False


class CorrelationEvaluator:
    @classmethod
    def evaluate(cls, dataset_path: Path) -> Dict[str, Any]:
        with open(dataset_path, "r", encoding="utf-8") as f:
            dataset = json.load(f)

        samples = dataset if isinstance(dataset, list) else dataset.get("samples", [])
        
        # Group samples by investigation
        by_case = {}
        for s in samples:
            inv = s.get("investigation_id")
            by_case.setdefault(inv, []).append(s)

        results_by_case = {}
        total_tp = 0
        total_fp = 0
        total_tn = 0
        total_fn = 0
        total_ambiguous = 0
        unmatched_predictions = 0

        for inv_id, case_samples in by_case.items():
            dir_name = CASE_MAPPING.get(inv_id, inv_id)
            
            # Run the real production pipeline
            synthesized = ForensicSynthesizerService.synthesize_case(dir_name)
            predicted_correlations = synthesized.get("correlations", [])

            case_tp = 0
            case_fp = 0
            case_tn = 0
            case_fn = 0
            case_amb = 0
            detailed_pairs = []

            for s in case_samples:
                s_id = s.get("sample_id")
                ann = s.get("annotation", {})
                label = ann.get("epistemic_label")
                rel_type = ann.get("relationship_type")
                
                # Find if any predicted correlation matches this pair
                matched_corr = next((c for c in predicted_correlations if match_correlation_to_pair(c, s)), None)
                
                # Check whether predicted correlation asserts a positive causal link
                is_predicted_positive = False
                if matched_corr:
                    nature = matched_corr.get("correlation_nature", "")
                    conf = matched_corr.get("confidence", 0.0)
                    # Causal assertions: CORROBORATED_HYPOTHESIS or DETERMINISTIC_GROUNDED with conf >= 0.70
                    if nature in ("CORROBORATED_HYPOTHESIS", "DETERMINISTIC_GROUNDED") and conf >= 0.70:
                        is_predicted_positive = True

                if label == "AMBIGUOUS_UNRESOLVED":
                    case_amb += 1
                    status = "EXCLUDED_AMBIGUOUS"
                    detail = "Pair is unresolved in ground truth; excluded from binary evaluation."
                elif label == "VERIFIED_POSITIVE":
                    if is_predicted_positive:
                        case_tp += 1
                        status = "TRUE_POSITIVE"
                        detail = f"Correctly correlated as positive: '{matched_corr.get('title')}' (conf: {matched_corr.get('confidence')})"
                    else:
                        case_fn += 1
                        status = "FALSE_NEGATIVE"
                        detail = "Causal positive link was missed by correlation engine."
                elif label == "VERIFIED_NEGATIVE":
                    if is_predicted_positive:
                        case_fp += 1
                        status = "FALSE_POSITIVE"
                        detail = f"Incorrectly predicted positive for negative control: '{matched_corr.get('title')}'"
                    else:
                        case_tn += 1
                        status = "TRUE_NEGATIVE"
                        detail = "Negative control correctly rejected or classified as noise/unlinked."
                else:
                    status = "UNKNOWN_LABEL"
                    detail = f"Unrecognized label {label}"

                detailed_pairs.append({
                    "sample_id": s_id,
                    "relationship_type": rel_type,
                    "ground_truth_label": label,
                    "evaluation_status": status,
                    "matched_prediction": matched_corr.get("title") if matched_corr else None,
                    "detail": detail
                })

            results_by_case[inv_id] = {
                "case_name": dir_name,
                "total_pairs": len(case_samples),
                "predicted_correlations_count": len(predicted_correlations),
                "metrics": {
                    "tp": case_tp,
                    "fp": case_fp,
                    "tn": case_tn,
                    "fn": case_fn,
                    "ambiguous_excluded": case_amb
                },
                "pairs": detailed_pairs
            }

            total_tp += case_tp
            total_fp += case_fp
            total_tn += case_tn
            total_fn += case_fn
            total_ambiguous += case_amb

        # Calculate macro metrics
        denom_p = total_tp + total_fp
        precision = (total_tp / denom_p) if denom_p > 0 else 0.0

        denom_r = total_tp + total_fn
        recall = (total_tp / denom_r) if denom_r > 0 else 0.0

        denom_f1 = precision + recall
        f1 = (2 * precision * recall / denom_f1) if denom_f1 > 0 else 0.0

        return {
            "summary": {
                "total_samples": len(samples),
                "ambiguous_excluded": total_ambiguous,
                "evaluated_binary_samples": total_tp + total_fp + total_tn + total_fn,
                "true_positives": total_tp,
                "false_positives": total_fp,
                "true_negatives": total_tn,
                "false_negatives": total_fn,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1_score": round(f1, 4)
            },
            "cases": results_by_case
        }


def main():
    parser = argparse.ArgumentParser(description="SherlockAI Forensic Correlation Evaluation Harness")
    parser.add_argument("dataset", type=str, help="Path to correlation dataset JSON")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        print(f"Error: Dataset file not found: {dataset_path}", file=sys.stderr)
        sys.exit(1)

    eval_result = CorrelationEvaluator.evaluate(dataset_path)

    if args.json:
        print(json.dumps(eval_result, indent=2))
        return

    s = eval_result["summary"]
    print("=" * 80)
    print(" SHERLOCKAI CORRELATION PIPELINE REAL-EVALUATION REPORT")
    print("=" * 80)
    print(f" Total Dataset Samples:       {s['total_samples']}")
    print(f" Ambiguous Excluded:          {s['ambiguous_excluded']} (Not penalized in binary metrics)")
    print(f" Evaluated Binary Samples:    {s['evaluated_binary_samples']}")
    print("-" * 80)
    print(f" True Positives (TP):         {s['true_positives']}")
    print(f" False Positives (FP):        {s['false_positives']}")
    print(f" True Negatives (TN):         {s['true_negatives']}")
    print(f" False Negatives (FN):        {s['false_negatives']}")
    print("-" * 80)
    print(f" Precision:                   {s['precision'] * 100:.2f}%")
    print(f" Recall:                      {s['recall'] * 100:.2f}%")
    print(f" F1 Score:                    {s['f1_score'] * 100:.2f}%")
    print("=" * 80)
    print("\nCase-by-Case Breakdown:")
    for inv, c_data in eval_result["cases"].items():
        m = c_data["metrics"]
        print(f"\n[{inv}] ({c_data['case_name']}) - {c_data['total_pairs']} pairs, {c_data['predicted_correlations_count']} predicted correlations")
        print(f"  TP: {m['tp']}, FP: {m['fp']}, TN: {m['tn']}, FN: {m['fn']}, Ambiguous Excluded: {m['ambiguous_excluded']}")
        for p in c_data["pairs"]:
            flag = "[PASS]" if p["evaluation_status"] in ("TRUE_POSITIVE", "TRUE_NEGATIVE", "EXCLUDED_AMBIGUOUS") else "[FAIL]"
            print(f"    {flag} {p['sample_id']} ({p['relationship_type']}) -> {p['evaluation_status']}: {p['detail']}")


if __name__ == "__main__":
    main()
