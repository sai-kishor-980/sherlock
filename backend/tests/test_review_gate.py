import pytest
from datetime import timedelta
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
from app.services.agent_barrier_service import AgentBarrierService
from app.services.synthesizer_service import ForensicSynthesizerService


def _setup_barrier_for_case(case_id: str):
    """Create valid findings for all five domains so the barrier is satisfied."""
    findings = []
    for domain in ["network", "memory", "disk", "logs", "registry"]:
        findings.append({
            "case_id": case_id,
            "domain": domain,
            "finding_id": f"FIND-{domain.upper()}-001",
            "classification": "BENIGN",
            "confidence": 0.80,
            "is_examination_status": False,
        })
    AgentBarrierService.evaluate_five_agent_barrier(case_id, findings)


@pytest.fixture
def test_env():
    import uuid
    import shutil
    from pathlib import Path

    unique_case_id = f"CASE_GATE_{uuid.uuid4().hex[:8]}"
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
        username="investigator1",
        email="inv@hmacfr.org",
        hashed_password=pw_hash,
        role="Investigator",
        token_version=1,
        is_active=True
    )
    db.add(inv)

    test_case = Case(
        case_id=unique_case_id,
        case_name="Review Gate Test Case",
        description="Validates HTTP 423 locked state and examiner approval workflow",
        priority="High",
        status="Active",
        vault_status="OPEN",
        investigator_name="investigator1"
    )
    db.add(test_case)
    db.commit()

    mbr = CaseMember(
        id="MBR_GATE_01",
        case_id=unique_case_id,
        user_id="U_INV_GATE",
        assigned_by="U_INV_GATE"
    )
    db.add(mbr)
    db.commit()

    resp = CaseMemberResponsibility(
        case_member_id="MBR_GATE_01",
        responsibility_name="Lead Investigator"
    )
    db.add(resp)
    db.commit()

    ev = Evidence(
        evidence_id=f"EV_{uuid.uuid4().hex[:8]}",
        case_id=unique_case_id,
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

    token = create_access_token(
        data={"sub": "investigator1", "id": "U_INV_GATE", "role": "Investigator", "ver": 1},
        expires_delta=timedelta(hours=1)
    )
    headers = {"Authorization": f"Bearer {token}"}

    yield client, headers, unique_case_id, db

    app.dependency_overrides.clear()
    db.close()
    # Cleanup test output dir
    out_dir = Path("sherf/backend/output/cases") / unique_case_id
    if out_dir.exists():
        shutil.rmtree(out_dir, ignore_errors=True)


def test_compulsory_review_gate_lock_and_lifecycle(test_env):
    client, headers, case_id, db = test_env

    # 1. Synthesize candidate Pre-SIS (status = PENDING)
    _setup_barrier_for_case(case_id)
    synth = ForensicSynthesizerService.synthesize_case(
        case_id=case_id,
        evidence_records=[{"evidence_id": "EV1", "original_filename": "sample_capture.pcap", "status": "VALIDATED"}]
    )
    assert synth["sis_state"]["review_gate"]["status"] == "PENDING"

    # 2. Attempt to fetch court report - MUST fail with HTTP 423 Locked
    locked_res = client.get(f"/api/v1/analysis/{case_id}/report", headers=headers)
    assert locked_res.status_code == 423
    assert "Outputs Locked" in locked_res.json()["detail"]

    # 3. Examiner reviews and approves Pre-SIS
    review_res = client.post(
        f"/api/v1/cases/{case_id}/sis/review",
        headers=headers,
        json={
            "action": "APPROVE",
            "notes": "All findings, MITRE ATT&CK techniques, and evidence links verified."
        }
    )
    assert review_res.status_code == 200
    assert review_res.json()["sis"]["review_gate"]["status"] == "APPROVED"

    # 4. Fetch court report now - MUST succeed with 200 OK
    unlocked_res = client.get(f"/api/v1/analysis/{case_id}/report", headers=headers)
    assert unlocked_res.status_code == 200
    report = unlocked_res.json()
    assert report is not None

    # 5. Examiner rejects with REJECT_REANALYZE loopback
    # First lock the vault to test automated unlocking
    lock_res = client.post(f"/api/v1/cases/{case_id}/vault/lock", headers=headers)
    assert lock_res.status_code == 200

    reject_res = client.post(
        f"/api/v1/cases/{case_id}/sis/review",
        headers=headers,
        json={
            "action": "REJECT_REANALYZE",
            "notes": "Supplemental memory dump required for root cause analysis."
        }
    )
    assert reject_res.status_code == 200
    assert reject_res.json()["sis"]["review_gate"]["status"] == "REJECTED"

    # 6. Court report must be locked again with HTTP 423
    relocked_res = client.get(f"/api/v1/analysis/{case_id}/report", headers=headers)
    assert relocked_res.status_code == 423

    # 7. Verify vault was automatically unlocked by loopback
    case_check = client.get(f"/api/v1/cases/{case_id}", headers=headers)
    assert case_check.status_code == 200
    assert case_check.json()["vault_status"] == "OPEN"
