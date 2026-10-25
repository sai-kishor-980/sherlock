"""
Comprehensive RBAC, Case Assignment, and Access Control Matrix Test Suite.
Verifies:
1. Case creation automatically assigns creator as Lead Investigator, Investigator, and Forensic Analyst.
2. GET /cases/{id}/my-permissions returns accurate responsibilities and granted permissions.
3. Protected Succession: Cannot remove or demote the only Lead Investigator (400 Bad Request).
4. IDOR Isolation: Users cannot read cases or evidence where they lack membership (403 Forbidden).
5. Granular Action Authorization: Assigning/removing members requires Lead or Admin (403 Forbidden for others).
6. Correlation execution requires analysis:run permission.
"""

import pytest
import uuid
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from main import app
from app.db.connection import get_db, SessionLocal
from app.db.models.user import User
from app.db.models.case import Case
from app.db.models.case_assignment import CaseMember, CaseMemberResponsibility
from app.db.models.user_role import UserGlobalRole
from app.core.security import get_password_hash, create_access_token
from app.services.rbac_service import RBACService


client = TestClient(app)


def create_test_user(db: Session, username: str, role_name: str = "Investigator"):
    uid = f"USR-{uuid.uuid4().hex[:8]}"
    u = User(
        user_id=uid,
        username=username,
        email=f"{username}@sherlock.test",
        hashed_password=get_password_hash("Password@123"),
        role="Investigator",
        is_active=True
    )
    db.add(u)
    db.flush()

    # Assign global role
    db.add(UserGlobalRole(
        id=f"UGR-{uuid.uuid4().hex[:8]}",
        user_id=uid,
        role_name=role_name
    ))
    db.commit()
    db.refresh(u)
    return u


def get_auth_headers(user: User):
    token = create_access_token({
        "sub": user.username,
        "user_id": user.user_id,
        "ver": user.token_version or 1
    })
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def test_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_1_case_creation_assigns_creator_default_responsibilities(test_db):
    user = create_test_user(test_db, f"lead_user_{uuid.uuid4().hex[:6]}")
    headers = get_auth_headers(user)

    case_payload = {
        "case_name": "Project Cyber Genesis",
        "description": "Genesis investigation",
        "priority": "High"
    }
    res = client.post("/api/v1/cases/", json=case_payload, headers=headers)
    assert res.status_code == 201
    case_data = res.json()
    case_id = case_data["case_id"]

    # Verify membership created in DB
    member = test_db.query(CaseMember).filter(CaseMember.case_id == case_id, CaseMember.user_id == user.user_id).first()
    assert member is not None

    resps = {r.responsibility_name for r in member.responsibilities}
    assert "Lead Investigator" in resps
    assert "Investigator" in resps
    assert "Forensic Analyst" in resps


def test_2_my_permissions_endpoint_resolution(test_db):
    user = create_test_user(test_db, f"perm_user_{uuid.uuid4().hex[:6]}")
    headers = get_auth_headers(user)

    # Create case
    c = client.post("/api/v1/cases/", json={"case_name": "Permission Check Case"}, headers=headers).json()
    case_id = c["case_id"]

    # Call my-permissions
    res = client.get(f"/api/v1/cases/{case_id}/my-permissions", headers=headers)
    assert res.status_code == 200
    pdata = res.json()
    assert pdata["case_id"] == case_id
    assert pdata["username"] == user.username
    assert pdata["is_lead"] is True
    assert pdata["is_creator"] is True
    assert "case:read" in pdata["permissions"]
    assert "case:assign_members" in pdata["permissions"]
    assert "analysis:run" in pdata["permissions"]


def test_3_protected_succession_cannot_remove_only_lead(test_db):
    user = create_test_user(test_db, f"solo_lead_{uuid.uuid4().hex[:6]}")
    headers = get_auth_headers(user)

    c = client.post("/api/v1/cases/", json={"case_name": "Protected Succession Case"}, headers=headers).json()
    case_id = c["case_id"]

    # Attempt to remove the only lead
    del_res = client.delete(f"/api/v1/cases/{case_id}/members/{user.user_id}", headers=headers)
    assert del_res.status_code == 400
    assert "Cannot remove the only Lead Investigator" in del_res.json()["detail"]

    # Attempt to demote the only lead
    demote_res = client.post(
        f"/api/v1/cases/{case_id}/members",
        json={"user_id": user.user_id, "responsibilities": ["Investigator"]},
        headers=headers
    )
    assert demote_res.status_code == 400
    assert "Cannot demote the only Lead Investigator" in demote_res.json()["detail"]


def test_4_protected_succession_allows_removal_when_second_lead_exists(test_db):
    lead1 = create_test_user(test_db, f"lead_one_{uuid.uuid4().hex[:6]}")
    lead2 = create_test_user(test_db, f"lead_two_{uuid.uuid4().hex[:6]}")
    h1 = get_auth_headers(lead1)

    c = client.post("/api/v1/cases/", json={"case_name": "Multi Lead Case"}, headers=h1).json()
    case_id = c["case_id"]

    # Assign lead2 as co-Lead Investigator
    assign_res = client.post(
        f"/api/v1/cases/{case_id}/members",
        json={"user_id": lead2.user_id, "responsibilities": ["Lead Investigator", "Investigator"]},
        headers=h1
    )
    assert assign_res.status_code == 200

    # Now remove lead1 should succeed because lead2 remains
    del_res = client.delete(f"/api/v1/cases/{case_id}/members/{lead1.user_id}", headers=h1)
    assert del_res.status_code == 200


def test_5_unassigned_user_idor_isolation(test_db):
    user_a = create_test_user(test_db, f"user_a_{uuid.uuid4().hex[:6]}")
    user_b = create_test_user(test_db, f"user_b_{uuid.uuid4().hex[:6]}")
    ha = get_auth_headers(user_a)
    hb = get_auth_headers(user_b)

    c = client.post("/api/v1/cases/", json={"case_name": "User A Private Case"}, headers=ha).json()
    case_id = c["case_id"]

    # User B attempts to access User A's case
    res = client.get(f"/api/v1/cases/{case_id}", headers=hb)
    assert res.status_code == 403

    # User B attempts to manage members
    assign_res = client.post(
        f"/api/v1/cases/{case_id}/members",
        json={"user_id": user_b.user_id, "responsibilities": ["Investigator"]},
        headers=hb
    )
    assert assign_res.status_code == 403


def test_6_hybrid_correlation_requires_analysis_run_permission(test_db):
    lead = create_test_user(test_db, f"lead_corr_{uuid.uuid4().hex[:6]}")
    auditor = create_test_user(test_db, f"auditor_corr_{uuid.uuid4().hex[:6]}")
    h_lead = get_auth_headers(lead)
    h_auditor = get_auth_headers(auditor)

    c = client.post("/api/v1/cases/", json={"case_name": "Correlation Perm Test"}, headers=h_lead).json()
    case_id = c["case_id"]

    # Assign auditor with only "Case Auditor" responsibility
    client.post(
        f"/api/v1/cases/{case_id}/members",
        json={"user_id": auditor.user_id, "responsibilities": ["Case Auditor"]},
        headers=h_lead
    )

    # Refresh auditor token version after assignment
    test_db.refresh(auditor)
    h_auditor_updated = get_auth_headers(auditor)

    # Auditor attempts to execute correlation -> 403
    corr_res = client.post(f"/api/v1/cases/{case_id}/correlation/run", headers=h_auditor_updated)
    assert corr_res.status_code == 403
    assert "Requires analysis:run permission" in corr_res.json()["detail"]
