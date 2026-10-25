#!/usr/bin/env python3
"""
Command-Line Interface for Forensic Correlation Dataset Validation (Phase 1A).

Usage:
    python -m app.cli.validate_correlation_dataset <path_to_dataset.json_or_jsonl> [options]

Options:
    --check-readiness   Enforce full research training-readiness gates (exits with code 2 if not ready).
    --json              Output validation results as machine-readable JSON.
    --output FILE       Write validation report to FILE instead of / in addition to stdout.

Exit Codes:
    0: Success (Dataset is structurally valid; and training-ready if --check-readiness is specified)
    1: Structural Validation Failure (Schema invalid, duplicate pairs, contradictory labels, split leakage)
    2: Training Readiness Failure (Structurally valid, but does not meet scale/diversity/confounding criteria)
"""

import sys
import json
import argparse
from pathlib import Path

# Add backend directory to sys.path if running as standalone script
backend_dir = Path(__file__).resolve().parents[2]
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.services.correlation_validator_service import CorrelationDatasetValidator


def main():
    parser = argparse.ArgumentParser(
        description="SherlockAI / H-MACFR Forensic Correlation Dataset Validator & Quality Gate CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "dataset_path",
        type=str,
        help="Path to dataset file (.json or .jsonl)"
    )
    parser.add_argument(
        "--check-readiness",
        action="store_true",
        help="Enforce research training readiness criteria (CORRELATION_TRAINING_PLAN.md gates)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output raw JSON validation dictionary"
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Write report output to specified file"
    )

    args = parser.parse_args()
    dataset_file = Path(args.dataset_path)

    if not dataset_file.exists():
        print(f"[FATAL] Dataset file not found: {dataset_file}", file=sys.stderr)
        sys.exit(1)

    result = CorrelationDatasetValidator.validate(dataset_file)

    # Prepare output representation
    if args.json_output:
        report_text = json.dumps(result.to_dict(), indent=2)
    else:
        report_text = result.to_text_report()

    # Write or print report
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(report_text)
        print(f"[OK] Report written to: {out_path}")

    print(report_text)

    # Determine exit code
    if not result.is_structurally_valid:
        print("\n[RESULT] STRUCTURAL VALIDATION FAILED. Exit code 1.", file=sys.stderr)
        sys.exit(1)

    if args.check_readiness and not result.is_training_ready:
        print("\n[RESULT] TRAINING READINESS GATES FAILED (Structurally valid, but not research-ready). Exit code 2.", file=sys.stderr)
        sys.exit(2)

    print("\n[RESULT] VALIDATION SUCCESSFUL. Exit code 0.")
    sys.exit(0)


if __name__ == "__main__":
    main()
