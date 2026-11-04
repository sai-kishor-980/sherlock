"""
Test Suite for Evidence Validation, Gating & Truthful Reporting Controls.
Verifies:
1. Analysis Initiation Gate: Cases with 0 evidence return HTTP 422 Unprocessable Entity.
2. Truthful Chatbot Non-Conclusion: Empty cases return status="NO_EVIDENCE", confidence=0.0, and 0 citations.
3. Upload Integrity: POST /upload/ sets status="VALIDATED" with real cryptographic hash.
4. Evidence Serialization & Status: GET /evidence exposes complete file_size, sha256_hash, status="VALIDATED", name.
5. Populated Case Gate Pass: Validated case passes analysis initiation gate.
"""

import io
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from main import app
from app.db.connection import Base, get_db
from app.db.models.user import User
from app.db.models.case import Case
from app.db.models.evidence import Evidence
from app.db.models.case_assignment import CaseMember, CaseMemberResponsibility
from app.core.security import get_password_hash, create_access_token


@pytest.fixture
def evidence_test_env():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    db = TestingSessionLocal()

    pw_hash = get_password_hash("TestPass@2026")

    inv = User(
        user_id="U_INV_GATE",
        username="investigator_gate",
        email="gate@hmacfr.org",
        hashed_password=pw_hash,
        role="Investigator",
        token_version=1,
        is_active=True
    )
    db.add(inv)

    empty_case = Case(
        case_id="CASE_EMPTY_001",
        case_name="Empty Forensic Test Case",
        investigator_name="investigator_gate",
        priority="Medium",
        status="Active",
        vault_status="OPEN"
    )
    db.add(empty_case)
    db.commit()

    # Assign Lead Investigator responsibility so RBAC checks pass
    mbr = CaseMember(
        id="MBR_GATE_001",
        case_id="CASE_EMPTY_001",
        user_id="U_INV_GATE",
        assigned_by="U_INV_GATE"
    )
    db.add(mbr)
    db.commit()

    resp = CaseMemberResponsibility(
        case_member_id="MBR_GATE_001",
        responsibility_name="Lead Investigator"
    )
    db.add(resp)
    db.commit()

    token = create_access_token({
        "sub": "investigator_gate",
        "user_id": "U_INV_GATE",
        "id": "U_INV_GATE",
        "role": "Investigator",
        "ver": 1
    })
    headers = {"Authorization": f"Bearer {token}"}

    yield client, db, headers

    app.dependency_overrides.clear()


def test_empty_case_analysis_start_blocked_with_422(evidence_test_env):
    """
    POST /api/v1/analysis/start must return HTTP 422 Unprocessable Entity
    with code='EVIDENCE_REQUIRED' when called on a case with zero evidence.
    """
    client, db, headers = evidence_test_env

    payload = {
        "case_id": "CASE_EMPTY_001",
        "case_name": "Empty Forensic Test Case",
        "total_duration_seconds": 5
    }

    res = client.post("/api/v1/analysis/start", json=payload, headers=headers)
    assert res.status_code == 422, f"Expected 422 Unprocessable Entity, got {res.status_code}: {res.text}"
    detail = res.json().get("detail", {})
    assert detail.get("code") == "EVIDENCE_REQUIRED"
    assert "no validated forensic evidence" in detail.get("message", "").lower()


def test_empty_case_chatbot_returns_truthful_non_conclusion(evidence_test_env):
    """
    POST /api/v1/analysis/{case_id}/chat on an empty case must return
    status='NO_EVIDENCE', confidence=0.0, citations=[], and a clear non-conclusion message.
    It must NEVER fabricate 'Baseline Forensic Assessment (N/A)' or claim 100% confidence.
    """
    client, db, headers = evidence_test_env

    payload = {
        "query": "What was the initial access vector?"
    }

    res = client.post("/api/v1/analysis/CASE_EMPTY_001/chat", json=payload, headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert data["status"] == "NO_EVIDENCE"
    assert data["confidence"] == 0.0
    assert len(data["citations"]) == 0
    assert len(data["mitre_techniques"]) == 0
    assert "no validated forensic evidence is available" in data["answer"].lower()
    assert "baseline forensic assessment" not in data["answer"].lower()


def test_upload_sets_validated_status_and_correct_metadata(evidence_test_env):
    """
    POST /api/v1/upload/ must compute real SHA-256, set status='VALIDATED',
    and record accurate file size.
    """
    client, db, headers = evidence_test_env

    file_content = b"EVIDENCE_RAW_STREAM_FOR_CRYPTOGRAPHIC_HASHING_VERIFICATION"
    files = {"file": ("network_capture.pcap", io.BytesIO(file_content), "application/octet-stream")}
    data = {
        "case_id": "CASE_EMPTY_001",
        "investigator": "investigator_gate",
        "category": "Network",
        "type": "PCAP",
        "description": "Network traffic capture for validation test"
    }

    res = client.post("/api/v1/upload/", files=files, data=data, headers=headers)
    assert res.status_code == 201, f"Upload failed: {res.text}"
    record = res.json()

    assert record["status"] == "VALIDATED"
    assert record["file_size"] == len(file_content)
    assert record["file_hash"] is not None
    assert len(record["file_hash"]) == 64  # Valid SHA-256 hex string


def test_list_case_evidence_serializes_complete_fields(evidence_test_env):
    """
    GET /api/v1/cases/{id}/evidence must serialize complete metadata including
    file_size, sha256_hash, status, name without NaN or null discrepancies.
    """
    client, db, headers = evidence_test_env

    # Ingest evidence first
    file_content = b"EVIDENCE_RAW_STREAM_FOR_CRYPTOGRAPHIC_HASHING_VERIFICATION"
    files = {"file": ("network_capture.pcap", io.BytesIO(file_content), "application/octet-stream")}
    data = {
        "case_id": "CASE_EMPTY_001",
        "investigator": "investigator_gate",
        "category": "Network",
        "type": "PCAP",
        "description": "Network traffic capture for validation test"
    }
    upload_res = client.post("/api/v1/upload/", files=files, data=data, headers=headers)
    assert upload_res.status_code == 201

    # Query evidence list
    res = client.get("/api/v1/cases/CASE_EMPTY_001/evidence", headers=headers)
    assert res.status_code == 200
    items = res.json()
    assert len(items) >= 1

    item = items[0]
    # Check canonical fields
    assert "evidence_id" in item or "EvidenceID" in item
    assert "file_size" in item
    assert item["file_size"] > 0
    assert "sha256_hash" in item or "file_hash" in item
    assert item["status"] == "VALIDATED"
    assert item.get("name") == "network_capture.pcap" or item.get("original_filename") == "network_capture.pcap" or item.get("Filename") == "network_capture.pcap"


def test_populated_case_passes_analysis_initiation_gate(evidence_test_env):
    """
    POST /api/v1/analysis/start must succeed once validated evidence is present in the case.
    """
    client, db, headers = evidence_test_env

    # Add validated evidence to case
    ev = Evidence(
        evidence_id=f"EV_{uuid.uuid4().hex[:8]}",
        case_id="CASE_EMPTY_001",
        original_filename="sample_capture.pcap",
        stored_filename="sample_capture.pcap",
        category="Network",
        type="PCAP",
        extension="pcap",
        file_size=2048,
        storage_path="sample_capture.pcap",
        status="VALIDATED",
        file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    db.add(ev)
    db.commit()

    payload = {
        "case_id": "CASE_EMPTY_001",
        "case_name": "Empty Forensic Test Case",
        "total_duration_seconds": 5
    }

    res = client.post("/api/v1/analysis/start", json=payload, headers=headers)
    assert res.status_code == 200, f"Expected 200 OK after evidence upload, got: {res.text}"
    data = res.json()
    assert data["status"] == "running"
    assert data["case_id"] == "CASE_EMPTY_001"
