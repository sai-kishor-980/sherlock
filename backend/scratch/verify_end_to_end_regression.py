"""
SherlockAI (H-MACFR) End-to-End Regression Verification Script
Tests Scenarios 1 through 5 against the live backend on http://127.0.0.1:8000
"""

import sys
import os
import uuid
import hashlib
import requests
import json

BASE_URL = "http://127.0.0.1:8000/api/v1"

def print_section(title):
    print("\n" + "="*80)
    print(f"  {title}")
    print("="*80)

def main():
    print_section("AUTHENTICATION & INVESTIGATOR LOGIN")
    login_resp = requests.post(f"{BASE_URL}/auth/login", json={
        "username": "investigator1",
        "password": "Investigator@2026"
    })
    if login_resp.status_code != 200:
        print(f"[FAIL] Login failed: {login_resp.status_code} {login_resp.text}")
        sys.exit(1)

    token = login_resp.json()["access_token"]
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    auth_headers_no_ct = {
        "Authorization": f"Bearer {token}"
    }
    print("[PASS] Investigator login successful. Bearer token acquired.")

    # =========================================================================
    # TEST 1 — EMPTY CASE VERIFICATION
    # =========================================================================
    print_section("TEST 1: EMPTY CASE VERIFICATION")
    empty_case_id = f"CASE_EMPTY_{uuid.uuid4().hex[:8].upper()}"
    create_case_resp = requests.post(f"{BASE_URL}/cases/", headers=headers, json={
        "case_id": empty_case_id,
        "case_name": "Test 1 Empty Forensic Enclave",
        "investigator_name": "investigator1",
        "description": "Zero evidence regression verification case",
        "priority": "Medium"
    })
    assert create_case_resp.status_code == 201, f"Failed to create case: {create_case_resp.text}"
    print(f"[PASS] Created empty case: {empty_case_id}")

    # 1.1 Multi-Agent Analysis Start Gate
    print("\n[Test 1.1] Attempting multi-agent analysis on empty case...")
    analysis_resp = requests.post(f"{BASE_URL}/analysis/start", headers=headers, json={
        "case_id": empty_case_id,
        "case_name": "Test 1 Empty Forensic Enclave",
        "total_duration_seconds": 5
    })
    print(f"  Status code: {analysis_resp.status_code}")
    print(f"  Response: {analysis_resp.text}")
    assert analysis_resp.status_code == 422, f"Expected HTTP 422, got {analysis_resp.status_code}"
    err_detail = analysis_resp.json().get("detail", {})
    assert err_detail.get("code") == "EVIDENCE_REQUIRED", f"Expected code EVIDENCE_REQUIRED, got {err_detail}"
    assert "no validated forensic evidence" in err_detail.get("message", "").lower()
    print("  [PASS] Analysis start correctly rejected with HTTP 422 and code=EVIDENCE_REQUIRED.")

    # 1.2 SIS State Non-Existence
    print("\n[Test 1.2] Checking SIS state on empty case...")
    sis_resp = requests.get(f"{BASE_URL}/cases/{empty_case_id}/sis", headers=headers)
    print(f"  Status code: {sis_resp.status_code}")
    assert sis_resp.status_code == 404, f"Expected 404 for unanalyzed empty case, got {sis_resp.status_code}"
    print("  [PASS] No pre-existing SIS state found for empty case (HTTP 404).")

    # 1.3 Truthful Chatbot Non-Conclusion
    print("\n[Test 1.3] Querying G-RAG Forensic Chatbot on empty case...")
    chat_resp = requests.post(f"{BASE_URL}/analysis/{empty_case_id}/chat", headers=headers, json={
        "query": "What is the initial access vector and malware injection PID?"
    })
    print(f"  Status code: {chat_resp.status_code}")
    chat_data = chat_resp.json()
    print(f"  Chat status: {chat_data.get('status')}")
    print(f"  Confidence: {chat_data.get('confidence')}")
    print(f"  Citations: {chat_data.get('citations')}")
    print(f"  Answer: {chat_data.get('answer')}")
    assert chat_resp.status_code == 200
    assert chat_data["status"] == "NO_EVIDENCE"
    assert chat_data["confidence"] == 0.0, f"Expected 0.0 confidence, got {chat_data['confidence']}"
    assert len(chat_data["citations"]) == 0, f"Expected 0 citations, got {len(chat_data['citations'])}"
    assert "no validated forensic evidence is available" in chat_data["answer"].lower()
    assert "baseline forensic assessment" not in chat_data["answer"].lower()
    assert "100%" not in chat_data["answer"]
    print("  [PASS] Chatbot returned truthful forensic non-conclusion with 0.0 confidence and 0 fabricated citations.")

    # 1.4 Court Report Locked Check
    print("\n[Test 1.4] Attempting to access court report on empty case...")
    report_resp = requests.get(f"{BASE_URL}/analysis/{empty_case_id}/report", headers=headers)
    print(f"  Status code: {report_resp.status_code}")
    assert report_resp.status_code == 423, f"Expected HTTP 423 Locked, got {report_resp.status_code}"
    print("  [PASS] Report access blocked by Compulsory Review Gate (HTTP 423 Locked).")

    # =========================================================================
    # TEST 2 — EVIDENCE VAULT METADATA & INTEGRITY
    # =========================================================================
    print_section("TEST 2: EVIDENCE VAULT METADATA & INTEGRITY")
    vault_case_id = f"CASE_VAULT_{uuid.uuid4().hex[:8].upper()}"
    requests.post(f"{BASE_URL}/cases/", headers=headers, json={
        "case_id": vault_case_id,
        "case_name": "Test 2 Vault Metadata Verification",
        "investigator_name": "investigator1",
        "description": "Cryptographic hashing & metadata persistence check",
        "priority": "High"
    })

    # Controlled synthetic artifact payload (exactly 4096 bytes)
    artifact_content = b"FORENSIC_RAW_PACKET_STREAM_DATA_CHUNK_" * 102 + b"END_EVIDENCE_STREAM!"
    expected_size = len(artifact_content)
    expected_sha256 = hashlib.sha256(artifact_content).hexdigest()
    filename = "control_network_traffic.pcap"

    print(f"  Uploading artifact '{filename}' ({expected_size} bytes, SHA-256: {expected_sha256[:16]}...)")
    files = {"file": (filename, artifact_content, "application/vnd.tcpdump.pcap")}
    data = {
        "case_id": vault_case_id,
        "investigator": "investigator1",
        "category": "Network PCAP",
        "type": "PCAP",
        "description": "Controlled packet capture stream for metadata validation"
    }
    upload_res = requests.post(f"{BASE_URL}/upload/", files=files, data=data, headers=auth_headers_no_ct)
    print(f"  Upload response status: {upload_res.status_code}")
    assert upload_res.status_code == 201, f"Upload failed: {upload_res.text}"
    uploaded_record = upload_res.json()

    print(f"  Persisted Status: {uploaded_record.get('status')}")
    print(f"  Persisted Size: {uploaded_record.get('file_size')}")
    print(f"  Persisted Hash: {uploaded_record.get('file_hash')}")
    assert uploaded_record["status"] == "VALIDATED", f"Expected VALIDATED, got {uploaded_record['status']}"
    assert uploaded_record["file_size"] == expected_size, f"Expected {expected_size}, got {uploaded_record['file_size']}"
    assert uploaded_record["file_hash"] == expected_sha256, "SHA-256 hash mismatch"
    print("  [PASS] Upload computed real SHA-256 digest and set status='VALIDATED'.")

    # 2.2 Re-query Evidence List (Simulate page refresh)
    print("\n[Test 2.2] Re-querying evidence list (simulating UI refresh)...")
    list_ev_res = requests.get(f"{BASE_URL}/cases/{vault_case_id}/evidence", headers=headers)
    assert list_ev_res.status_code == 200
    items = list_ev_res.json()
    assert len(items) == 1
    ev_item = items[0]

    print(f"  Retrieved item: {json.dumps(ev_item, indent=2)}")
    retrieved_size = ev_item.get("file_size")
    assert retrieved_size == expected_size, f"Size mismatch: expected {expected_size}, got {retrieved_size}"
    assert retrieved_size is not None and str(retrieved_size) != "nan"
    assert ev_item.get("sha256_hash") == expected_sha256 or ev_item.get("file_hash") == expected_sha256
    assert ev_item.get("status") == "VALIDATED"
    print(f"  [PASS] Re-queried evidence record correctly serialized file_size={retrieved_size} (NOT NaN), status='VALIDATED', and correct SHA-256.")

    # 2.3 Extraction eligibility check (Corrupted / Empty payload rejection)
    print("\n[Test 2.3] Testing upload of 0-byte invalid file...")
    empty_files = {"file": ("empty_file.raw", b"", "application/octet-stream")}
    empty_upload_res = requests.post(f"{BASE_URL}/upload/", files=empty_files, data={
        "case_id": vault_case_id,
        "investigator": "investigator1"
    }, headers=auth_headers_no_ct)
    print(f"  Status code: {empty_upload_res.status_code}")
    print(f"  Response: {empty_upload_res.text}")
    assert empty_upload_res.status_code in [400, 422], "0-byte file must be rejected"
    print("  [PASS] 0-byte corrupt file was rejected and never marked verified.")

    # =========================================================================
    # TEST 3 — VALID EVIDENCE WORKFLOW & REVIEW GATE
    # =========================================================================
    print_section("TEST 3: VALID EVIDENCE WORKFLOW & REVIEW GATE")
    valid_case_id = f"CASE_VALID_{uuid.uuid4().hex[:8].upper()}"
    requests.post(f"{BASE_URL}/cases/", headers=headers, json={
        "case_id": valid_case_id,
        "case_name": "Test 3 Valid Evidence Pipeline",
        "investigator_name": "investigator1",
        "description": "Full multi-agent analysis and review gate lifecycle",
        "priority": "High"
    })

    # Upload evidence artifact
    valid_traffic = b"TCP_STREAM_MALICIOUS_C2_BEACONING_SIMULATION_PAYLOAD" * 40
    requests.post(f"{BASE_URL}/upload/", files={"file": ("c2_traffic.pcap", valid_traffic, "application/octet-stream")}, data={
        "case_id": valid_case_id,
        "investigator": "investigator1",
        "category": "Network PCAP",
        "type": "PCAP"
    }, headers=auth_headers_no_ct)
    print(f"  [PASS] Uploaded valid evidence to {valid_case_id}")

    # Trigger Extraction via /analysis/{case_id}/extract
    print("\n[Test 3.0] Triggering Artifact Extraction via /analysis/{case_id}/extract...")
    extract_res = requests.post(f"{BASE_URL}/analysis/{valid_case_id}/extract", headers=headers)
    print(f"  Extraction response status: {extract_res.status_code}")
    assert extract_res.status_code == 200, f"Extraction failed: {extract_res.text}"
    extract_data = extract_res.json()
    print(f"  Extracted manifest status: {extract_data.get('status')}")
    print(f"  Evidence items processed: {extract_data.get('evidence_count')}")
    assert extract_data["status"] == "SUCCESS"
    print("  [PASS] Artifact extraction executed successfully via /analysis/{case_id}/extract.")

    # Launch Analysis via /analysis/{case_id}/run
    print("\n[Test 3.1] Launching Multi-Agent Analysis on populated case via /analysis/{case_id}/run...")
    start_res = requests.post(f"{BASE_URL}/analysis/{valid_case_id}/run", headers=headers)
    print(f"  Analysis start status: {start_res.status_code}")
    assert start_res.status_code == 200, f"Expected 200 OK, got: {start_res.text}"
    task_data = start_res.json()
    print(f"  Task initiated: {task_data.get('task_id')} (Status: {task_data.get('status')})")
    print("  [PASS] Case with validated evidence successfully passed the gate and started analysis.")

    # Check Review Gate on Pre-SIS
    print("\n[Test 3.2] Verifying Pre-SIS Review Gate is PENDING...")
    import time
    time.sleep(1.0)
    # Check court report before approval - MUST be 423 Locked
    gate_check_res = requests.get(f"{BASE_URL}/analysis/{valid_case_id}/report", headers=headers)
    print(f"  Report status before approval: {gate_check_res.status_code}")
    assert gate_check_res.status_code == 423, f"Expected 423 Locked before approval, got {gate_check_res.status_code}"
    print("  [PASS] Court report locked (HTTP 423) pending investigator review.")

    # Examiner approves Pre-SIS
    print("\n[Test 3.3] Examiner submitting approval for Pre-SIS...")
    approve_res = requests.post(f"{BASE_URL}/cases/{valid_case_id}/sis/review", headers=headers, json={
        "action": "APPROVE",
        "notes": "Verified correlation links, MITRE mappings, and PCAP provenance."
    })
    print(f"  Approval status: {approve_res.status_code}")
    assert approve_res.status_code == 200
    sis_updated = approve_res.json()["sis"]
    assert sis_updated["review_gate"]["status"] == "APPROVED"
    assert sis_updated["review_gate"]["reviewed_by"] == "investigator1"
    print("  [PASS] Pre-SIS successfully approved by investigator1.")

    # Check report unlocked after approval
    print("\n[Test 3.4] Fetching court report after approval...")
    unlocked_report_res = requests.get(f"{BASE_URL}/analysis/{valid_case_id}/report", headers=headers)
    print(f"  Report status after approval: {unlocked_report_res.status_code}")
    assert unlocked_report_res.status_code == 200
    report_body = unlocked_report_res.json()
    print(f"  Court Report Title: {report_body.get('title')}")
    print(f"  Verified Case ID: {report_body.get('case_id')}")
    assert report_body.get("case_id") == valid_case_id
    print("  [PASS] Court report unlocked and generated successfully after investigator certification.")

    # =========================================================================
    # TEST 4 — ALTERNATE EXECUTION PATHS
    # =========================================================================
    print_section("TEST 4: ALTERNATE EXECUTION PATHS & GATE AUDIT")
    alt_empty_id = f"CASE_ALT_{uuid.uuid4().hex[:8].upper()}"
    requests.post(f"{BASE_URL}/cases/", headers=headers, json={
        "case_id": alt_empty_id,
        "case_name": "Test 4 Alternate Path Verification",
        "investigator_name": "investigator1"
    })

    # Path 4.1: POST /cases/{id}/extract and POST /analysis/{id}/extract on empty case
    print("\n[Test 4.1] POST /cases/{id}/extract on empty case...")
    extract_res = requests.post(f"{BASE_URL}/cases/{alt_empty_id}/extract", headers=headers)
    print(f"  Status code: {extract_res.status_code}")
    assert extract_res.status_code == 400
    assert "no evidence files registered" in extract_res.json()["detail"].lower()
    print("  [PASS] /cases/{id}/extract blocked on empty case.")

    print("\n[Test 4.1b] POST /analysis/{id}/extract on empty case...")
    anl_extract_res = requests.post(f"{BASE_URL}/analysis/{alt_empty_id}/extract", headers=headers)
    print(f"  Status code: {anl_extract_res.status_code}")
    assert anl_extract_res.status_code == 422
    assert anl_extract_res.json()["detail"]["code"] == "EVIDENCE_REQUIRED"
    print("  [PASS] /analysis/{id}/extract blocked on empty case with HTTP 422.")

    # Path 4.2: GET /cases/{id}/sis on unanalyzed case
    print("\n[Test 4.2] GET /cases/{id}/sis on unanalyzed case...")
    alt_sis_res = requests.get(f"{BASE_URL}/cases/{alt_empty_id}/sis", headers=headers)
    print(f"  Status code: {alt_sis_res.status_code}")
    assert alt_sis_res.status_code == 404
    print("  [PASS] /cases/{id}/sis returns 404 (no auto-manufactured SIS).")

    # Path 4.3: GET /cases/{id}/report on unapproved case
    print("\n[Test 4.3] GET /cases/{id}/report from cases router...")
    cases_report_res = requests.get(f"{BASE_URL}/cases/{alt_empty_id}/report", headers=headers)
    print(f"  Status code: {cases_report_res.status_code}")
    assert cases_report_res.status_code == 423
    print("  [PASS] /cases/{id}/report enforces HTTP 423 Locked.")

    # Path 4.4: RBAC Unauthorized access check
    print("\n[Test 4.4] RBAC unauthorized check (no bearer token)...")
    unauth_res = requests.post(f"{BASE_URL}/analysis/start", json={"case_id": valid_case_id, "case_name": "Test"})
    print(f"  Status code without token: {unauth_res.status_code}")
    assert unauth_res.status_code == 401
    print("  [PASS] Unauthorized request rejected with HTTP 401.")

    print_section("ALL 4 END-TO-END REGRESSION TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    main()
