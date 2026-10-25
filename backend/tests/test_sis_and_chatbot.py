"""
Automated Regression Tests for SIS State Lifecycle, Review Gate, and ChromaDB Chatbot
Covers:
- GET /api/v1/cases/{case_id}/sis
- POST /api/v1/cases/{case_id}/sis/review (Approve / Reject)
- GET & POST /api/v1/cases/models/colab-bridge
- POST /api/v1/analysis/{case_id}/chat (RAG retrieval)
"""

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
from app.core.security import get_password_hash, create_access_token


@pytest.fixture
def sis_test_env():
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
        user_id="U_INV_TEST",
        username="investigator1",
        email="inv@hmacfr.org",
        hashed_password=pw_hash,
        role="Investigator",
        token_version=1,
        is_active=True
    )
    db.add(inv)

    test_case = Case(
        case_id="Bharath_TES1",
        case_name="Test SIS Case",
        description="Case for testing SIS and Chatbot",
        priority="High",
        status="Active",
        investigator_name="investigator1"
    )
    db.add(test_case)
    db.commit()

    from app.db.models.case_assignment import CaseMember, CaseMemberResponsibility
    mbr = CaseMember(
        id="MBR_TEST_01",
        case_id="Bharath_TES1",
        user_id="U_INV_TEST",
        assigned_by="U_INV_TEST"
    )
    db.add(mbr)
    db.commit()

    resp = CaseMemberResponsibility(
        case_member_id="MBR_TEST_01",
        responsibility_name="Lead Investigator"
    )
    db.add(resp)
    db.commit()

    token = create_access_token(
        data={"sub": "investigator1", "id": "U_INV_TEST", "role": "Investigator", "ver": 1},
        expires_delta=timedelta(hours=1)
    )
    headers = {"Authorization": f"Bearer {token}"}

    yield client, db, headers

    app.dependency_overrides.clear()


def test_sis_state_lifecycle_and_review(sis_test_env):
    client, db, headers = sis_test_env

    # 1. Fetch initial SIS
    res = client.get("/api/v1/cases/Bharath_TES1/sis", headers=headers)
    assert res.status_code == 200, res.text
    sis = res.json()
    assert sis["case_id"] == "Bharath_TES1"
    assert "state_version" in sis
    assert "correlations" in sis
    assert "findings" in sis
    assert "review_gate" in sis or "investigation_status" in sis

    # 2. Reject and request re-analysis
    reject_res = client.post(
        "/api/v1/cases/Bharath_TES1/sis/review",
        json={"action": "REJECT", "notes": "Need deeper memory inspection"},
        headers=headers
    )
    assert reject_res.status_code == 200, reject_res.text
    reject_data = reject_res.json()
    assert reject_data["status"] == "SUCCESS"
    assert reject_data["sis"]["investigation_status"] == "REJECTED_LOOPBACK"
    assert reject_data["sis"]["review_gate"]["status"] == "REJECTED"

    # 3. Approve and lock SIS state
    approve_res = client.post(
        "/api/v1/cases/Bharath_TES1/sis/review",
        json={"action": "APPROVE", "notes": "Memory injection confirmed and cross-correlated"},
        headers=headers
    )
    assert approve_res.status_code == 200, approve_res.text
    approve_data = approve_res.json()
    assert approve_data["status"] == "SUCCESS"
    assert approve_data["sis"]["investigation_status"] == "APPROVED_LOCKED"
    assert approve_data["sis"]["review_gate"]["status"] == "APPROVED"
    assert approve_data["sis"]["review_gate"]["reviewed_by"] == "investigator1"

    # 4. Verify persistence on subsequent GET
    res2 = client.get("/api/v1/cases/Bharath_TES1/sis", headers=headers)
    assert res2.status_code == 200
    sis2 = res2.json()
    assert sis2["investigation_status"] == "APPROVED_LOCKED"
    assert sis2["review_gate"]["reviewed_by"] == "investigator1"


def test_colab_bridge_endpoint(sis_test_env):
    client, db, headers = sis_test_env

    # Check status
    res = client.get("/api/v1/cases/models/colab-bridge", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "colab_url" in data
    assert "is_connected" in data

    # Set new URL
    test_url = "https://forensics-test-bridge.trycloudflare.com"
    post_res = client.post(
        "/api/v1/cases/models/colab-bridge",
        json={"colab_url": test_url},
        headers=headers
    )
    assert post_res.status_code == 200
    assert post_res.json()["colab_url"] == test_url

    # Reset
    reset_res = client.post(
        "/api/v1/cases/models/colab-bridge",
        json={"colab_url": ""},
        headers=headers
    )
    assert reset_res.status_code == 200
    assert reset_res.json()["colab_url"] in [None, ""]


def test_case_chatbot_rag_endpoint(sis_test_env):
    client, db, headers = sis_test_env

    chat_payload = {
        "query": "Which process had suspicious executable memory injected?",
        "chat_history": []
    }
    res = client.post(
        "/api/v1/analysis/Bharath_TES1/chat",
        json=chat_payload,
        headers=headers
    )
    assert res.status_code == 200, res.text
    chat_resp = res.json()
    assert "answer" in chat_resp
    assert "citations" in chat_resp
    assert "confidence" in chat_resp
    assert len(chat_resp["answer"]) > 10
