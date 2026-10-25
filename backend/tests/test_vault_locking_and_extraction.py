"""
Test Suite for Evidence Vault Lifecycle & Ingestion Controls.
Verifies:
1. Ingestion while vault is OPEN succeeds.
2. Vault locking freezes evidence pool (vault_status == "LOCKED").
3. Upload while vault is LOCKED returns 400 Bad Request.
4. Evidence deletion while vault is LOCKED returns 400 Bad Request.
5. Vault unlock with logged reason succeeds and re-enables uploads and deletion.
6. Single-evidence artifact inspection returns structured artifact metadata.
"""

import io
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from main import app
from app.db.connection import get_db, SessionLocal
from app.db.models.user import User
from app.db.models.case import Case
from app.db.models.evidence import Evidence
from app.db.models.user_role import UserGlobalRole
from app.core.security import get_password_hash, create_access_token


client = TestClient(app)


def get_auth_headers(user: User):
    token = create_access_token({
        "sub": user.username,
        "user_id": user.user_id,
        "role": user.role,
        "ver": user.token_version or 1
    })
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def db_session():
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture(scope="module")
def test_investigator(db_session: Session):
    uid = f"USR-{uuid.uuid4().hex[:8]}"
    u = User(
        user_id=uid,
        username=f"vault_inv_{uuid.uuid4().hex[:4]}",
        email=f"vault_{uuid.uuid4().hex[:4]}@sherlock.test",
        hashed_password=get_password_hash("Password@123"),
        role="Investigator",
        is_active=True
    )
    db_session.add(u)
    db_session.flush()

    db_session.add(UserGlobalRole(
        id=f"UGR-{uuid.uuid4().hex[:8]}",
        user_id=uid,
        role_name="Investigator"
    ))
    db_session.commit()
    db_session.refresh(u)
    return u


def test_vault_lifecycle_open_lock_unlock(db_session: Session, test_investigator: User):
    headers = get_auth_headers(test_investigator)

    # 1. Create Case
    create_res = client.post(
        "/api/v1/cases/",
        json={
            "case_name": "Vault Security Test Case",
            "description": "Testing vault lock and upload controls",
            "priority": "High"
        },
        headers=headers
    )
    assert create_res.status_code in (200, 201), create_res.text
    case_data = create_res.json()
    case_id = case_data["case_id"]
    assert case_data.get("vault_status") == "OPEN"

    # 2. Upload Evidence while Vault is OPEN
    fake_file_content = b"TEST FORENSIC EVIDENCE CONTENT 01"
    upload_res1 = client.post(
        "/api/v1/upload/",
        data={
            "case_id": case_id,
            "investigator": test_investigator.username,
            "category": "PCAP",
            "type": "PCAP",
            "description": "Initial captured packets"
        },
        files={"file": ("capture1.pcap", io.BytesIO(fake_file_content), "application/octet-stream")},
        headers=headers
    )
    assert upload_res1.status_code in (200, 201), upload_res1.text
    ev1 = upload_res1.json()
    ev1_id = ev1["evidence_id"]

    # 3. Verify Evidence Artifact Inspector Endpoint
    art_res = client.get(
        f"/api/v1/cases/{case_id}/evidence/{ev1_id}/artifacts",
        headers=headers
    )
    assert art_res.status_code == 200, art_res.text
    art_data = art_res.json()
    assert art_data["status"] == "SUCCESS"
    assert art_data["evidence_id"] == ev1_id

    # 4. Lock Evidence Vault
    lock_res = client.post(
        f"/api/v1/cases/{case_id}/vault/lock",
        headers=headers
    )
    assert lock_res.status_code == 200, lock_res.text
    lock_data = lock_res.json()
    assert lock_data["vault_status"] == "LOCKED"
    assert lock_data["locked_by"] == test_investigator.username

    # 5. Attempt to Upload to LOCKED Vault (must return 400 Bad Request)
    upload_res2 = client.post(
        "/api/v1/upload/",
        data={
            "case_id": case_id,
            "investigator": test_investigator.username,
            "category": "Memory",
            "type": "Memory"
        },
        files={"file": ("memory_dump.raw", io.BytesIO(b"MEMORY DUMP BYTES"), "application/octet-stream")},
        headers=headers
    )
    assert upload_res2.status_code == 400, "Upload to locked vault must be rejected with 400"
    assert "LOCKED" in upload_res2.json()["detail"]

    # 6. Attempt to Delete Evidence from LOCKED Vault (must return 400 Bad Request)
    del_res1 = client.delete(
        f"/api/v1/cases/{case_id}/evidence/{ev1_id}",
        headers=headers
    )
    assert del_res1.status_code == 400, "Deletion from locked vault must be rejected with 400"
    assert "LOCKED" in del_res1.json()["detail"]

    # 7. Unlock Vault with Audited Reason
    unlock_res = client.post(
        f"/api/v1/cases/{case_id}/vault/unlock",
        json={"reason": "Insufficient evidence flagged by Multi-Agent correlation"},
        headers=headers
    )
    assert unlock_res.status_code == 200, unlock_res.text
    unlock_data = unlock_res.json()
    assert unlock_data["vault_status"] == "OPEN"

    # 8. Upload after Unlock succeeds
    upload_res3 = client.post(
        "/api/v1/upload/",
        data={
            "case_id": case_id,
            "investigator": test_investigator.username,
            "category": "Memory",
            "type": "Memory"
        },
        files={"file": ("memory_dump.raw", io.BytesIO(b"MEMORY DUMP BYTES"), "application/octet-stream")},
        headers=headers
    )
    assert upload_res3.status_code in (200, 201), upload_res3.text
    ev2 = upload_res3.json()
    ev2_id = ev2["evidence_id"]

    # 9. Delete Evidence from OPEN Vault succeeds
    del_res2 = client.delete(
        f"/api/v1/cases/{case_id}/evidence/{ev2_id}",
        headers=headers
    )
    assert del_res2.status_code == 200, del_res2.text
