"""
Real GPU Agent Inference Test Runner: Test 1 - Disk Forensics Agent (Aswith)
Tests the Disk Agent with real Prefetch evidence from CASE_DISK_1 against the live GPU.
"""

import os
import sys
import json
import time
import urllib.request
from pathlib import Path

# Add backend directory to sys.path
BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app.core.config import settings
from app.services.model_adapter_service import ModelAdapterService

# Real Prefetch Artifact Path
PREFETCH_FILE = BACKEND_DIR / "output" / "cases" / "DISK_1" / "disk" / "analyzed" / "prefetch_analysis.json"
if not PREFETCH_FILE.exists():
    PREFETCH_FILE = BACKEND_DIR.parent.parent / "prot1-main" / "output" / "cases" / "DISK_1" / "disk" / "analyzed" / "prefetch_analysis.json"


def run_disk_agent_test():
    print("=" * 70)
    print("[TEST 1] DISK FORENSICS AGENT (ASWITH) - REAL GPU INFERENCE")
    print("=" * 70)

    # 1. Load real extracted Prefetch record
    assert PREFETCH_FILE.exists(), f"Prefetch analysis fixture not found at {PREFETCH_FILE}"
    with open(PREFETCH_FILE, "r", encoding="utf-8") as f:
        records = json.load(f)

    # Locate VMwareTray record
    vmware_record = next((r for r in records if "VMWARETRAY" in r.get("executable_name", "")), records[0])
    print(f"[*] Input Fixture: {vmware_record.get('source_file')}")
    print(f"    Executable: {vmware_record.get('executable_name')}")
    print(f"    Run Count:  {vmware_record.get('run_count')}")
    print(f"    Referenced: {len(vmware_record.get('referenced_files', []))} files")

    # 2. Construct Standardized Input Contract Payload
    input_payload = {
        "evidence_id": "EV-DISK-PREFETCH-001",
        "artifact_type": "Windows Prefetch",
        "source_file": vmware_record.get("source_file"),
        "extracted_records": [
            {
                "executable_name": vmware_record.get("executable_name"),
                "run_count": vmware_record.get("run_count"),
                "prefetch_hash": vmware_record.get("prefetch_hash"),
                "windows_version": vmware_record.get("windows_version"),
                "referenced_files": vmware_record.get("referenced_files", [])[:8]
            }
        ]
    }

    # 3. Check Remote GPU Tunnel Status
    remote_url = ModelAdapterService.get_remote_gpu_url()
    print(f"\n[*] Active Remote Inference URL: {remote_url}")

    # 4. Execute Inference via ModelAdapterService
    start_time = time.time()
    result = ModelAdapterService.analyze_domain_evidence(
        domain="disk",
        evidence_type="Windows Prefetch",
        evidence_content=input_payload
    )
    duration = time.time() - start_time

    # 5. Output Verification
    print(f"\n[+] Inference Completed in {duration:.2f} seconds")
    print(f"    Provider: {result.get('inference_provider', 'Unknown')}")
    print("\n--- Parsed Finding Schema ---")
    print(json.dumps(result, indent=2))

    # 6. Schema Validation Assertions
    print("\n--- Validating Finding Quality Gates ---")
    assert result.get("domain") == "disk" or result.get("agent") in ("disk", "Disk Agent"), "Agent identifier mismatch"
    assert "classification" in result or "assessment" in result, "Missing assessment/classification field"
    assert "risk_level" in result or "risk" in result, "Missing risk field"
    assert len(str(result.get("reasoning", ""))) > 15, "Reasoning is empty or too short"
    assert result.get("contract_validated") is True, "Output contract validation failed"

    print("[SUCCESS] All Test 1 Quality Gates Passed!")
    print("=" * 70)
    return result


if __name__ == "__main__":
    run_disk_agent_test()
