"""
Stage 3 Workspace Shell & API Client Acceptance Test Suite.
Validates:
1. Endpoint alignment for case evidence: /api/v1/cases/{case_id}/evidence works correctly.
2. Rejection of legacy / fake dev_session_token (401 Unauthorized).
3. Multi-case workspace switching with strict RBAC segregation.
4. Prevention of IDOR cross-case access while switching active workspace cases.
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
from app.db.models.user_role import UserGlobalRole
from app.db.models.case_assignment import CaseMember, CaseMemberResponsibility
from app.core.security import get_password_hash, create_access_token


@pytest.fixture
def stage3_test_env():
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

    # 1. Investigator 1
    inv1 = User(
        user_id="U_INV_1",
        username="investigator1",
        email="inv1@hmacfr.org",
        hashed_password=pw_hash,
        role="Investigator",
        token_version=1,
        is_active=True
    )
    db.add(inv1)

    # 2. Investigator 2
    inv2 = User(
        user_id="U_INV_2",
        username="investigator2",
        email="inv2@hmacfr.org",
        hashed_password=pw_hash,
        role="Investigator",
        token_version=1,
        is_active=True
    )
    db.add(inv2)
    db.commit()

    yield {
        "db": db,
        "client": client,
        "session_factory": TestingSessionLocal
    }

    db.close()
    app.dependency_overrides.clear()


def make_jwt(username: str, role: str, user_id: str, ver: int = 1) -> str:
    return create_access_token(data={"sub": username, "role": role, "id": user_id, "ver": ver})


def test_dev_session_token_rejected(stage3_test_env):
    """Proves that fake dev_session_token is strictly rejected by backend."""
    client = stage3_test_env["client"]

    res = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer dev_session_token"})
    assert res.status_code == 401
    assert "Could not validate credentials" in res.json()["detail"]


def test_case_evidence_endpoint_alignment(stage3_test_env):
    """
    Validates /api/v1/cases/{case_id}/evidence matches the frontend API client
    and enforces RBAC authorization.
    """
    client = stage3_test_env["client"]
    db = stage3_test_env["db"]

    token1 = make_jwt("investigator1", "Investigator", "U_INV_1", ver=1)

    # Create Case Alpha
    res_case = client.post("/api/v1/cases/", json={
        "case_id": "CASE_STAGE3_ALPHA",
        "case_name": "Stage 3 Workspace Alpha",
        "investigator_name": "investigator1"
    }, headers={"Authorization": f"Bearer {token1}"})
    assert res_case.status_code == 201

    # Insert evidence for Case Alpha
    ev1 = Evidence(
        evidence_id="EV_ALPHA_01",
        case_id="CASE_STAGE3_ALPHA",
        original_filename="memory_dump.raw",
        stored_filename="EV_ALPHA_01_memory.raw",
        extension=".raw",
        file_size=1024,
        storage_path="/vault/EV_ALPHA_01_memory.raw",
        file_hash="a" * 64,
        hmac_signature="h" * 64,
        status="Stored"
    )
    db.add(ev1)
    db.commit()

    # 1. Fetch via corrected endpoint: /api/v1/cases/{case_id}/evidence
    res_ev = client.get("/api/v1/cases/CASE_STAGE3_ALPHA/evidence", headers={"Authorization": f"Bearer {token1}"})
    assert res_ev.status_code == 200
    items = res_ev.json()
    assert len(items) == 1
    assert items[0]["EvidenceID"] == "EV_ALPHA_01"
    assert items[0]["Filename"] == "memory_dump.raw"

    # 2. Confirm old mismatched endpoint /api/v1/evidence/case/{id} is not a valid evidence item
    res_old = client.get("/api/v1/evidence/case/CASE_STAGE3_ALPHA", headers={"Authorization": f"Bearer {token1}"})
    assert res_old.status_code == 404


def test_workspace_switching_and_access_segregation(stage3_test_env):
    """
    Validates that an investigator can switch between authorized cases,
    while unauthorized cases remain inaccessible regardless of UI state.
    """
    client = stage3_test_env["client"]
    token1 = make_jwt("investigator1", "Investigator", "U_INV_1", ver=1)
    token2 = make_jwt("investigator2", "Investigator", "U_INV_2", ver=1)

    # Investigator 1 creates Case 1
    res1 = client.post("/api/v1/cases/", json={
        "case_id": "CASE_WS_1",
        "case_name": "Workspace Case 1",
        "investigator_name": "investigator1"
    }, headers={"Authorization": f"Bearer {token1}"})
    assert res1.status_code == 201

    # Investigator 2 creates Case 2
    res2 = client.post("/api/v1/cases/", json={
        "case_id": "CASE_WS_2",
        "case_name": "Workspace Case 2",
        "investigator_name": "investigator2"
    }, headers={"Authorization": f"Bearer {token2}"})
    assert res2.status_code == 201

    # Investigator 1 lists accessible cases -> sees only Case 1
    res_list1 = client.get("/api/v1/cases/", headers={"Authorization": f"Bearer {token1}"})
    assert res_list1.status_code == 200
    c_ids1 = [c["case_id"] for c in res_list1.json()]
    assert "CASE_WS_1" in c_ids1
    assert "CASE_WS_2" not in c_ids1

    # Investigator 1 switching workspace to Case 1 -> Succeeds
    res_switch1 = client.get("/api/v1/cases/CASE_WS_1", headers={"Authorization": f"Bearer {token1}"})
    assert res_switch1.status_code == 200

    # Investigator 1 attempting to switch workspace to Case 2 -> Denied 403
    res_switch2 = client.get("/api/v1/cases/CASE_WS_2", headers={"Authorization": f"Bearer {token1}"})
    assert res_switch2.status_code == 403
    assert "Permission Denied" in res_switch2.json()["detail"]


def test_case_team_assignment_and_member_endpoints(stage3_test_env):
    """
    Validates Case Team assignment, member listing, and member removal.
    Confirms token_version is incremented on assignment/removal.
    """
    client = stage3_test_env["client"]
    db = stage3_test_env["db"]

    token1 = make_jwt("investigator1", "Investigator", "U_INV_1", ver=1)

    # 1. Investigator 1 creates Case
    res_case = client.post("/api/v1/cases/", json={
        "case_id": "CASE_TEAM_TEST",
        "case_name": "Team Collab Case",
        "investigator_name": "investigator1"
    }, headers={"Authorization": f"Bearer {token1}"})
    assert res_case.status_code == 201

    # 2. Get members - creator is Lead Investigator
    res_m = client.get("/api/v1/cases/CASE_TEAM_TEST/members", headers={"Authorization": f"Bearer {token1}"})
    assert res_m.status_code == 200
    members = res_m.json()
    assert len(members) == 1
    assert members[0]["user_id"] == "U_INV_1"
    assert "Lead Investigator" in members[0]["responsibilities"]

    # 3. Assign Investigator 2 as Forensic Analyst & Reviewer
    res_assign = client.post("/api/v1/cases/CASE_TEAM_TEST/members", json={
        "user_id": "U_INV_2",
        "responsibilities": ["Forensic Analyst", "Reviewer"]
    }, headers={"Authorization": f"Bearer {token1}"})
    assert res_assign.status_code == 200
    assigned_data = res_assign.json()
    assert assigned_data["user_id"] == "U_INV_2"
    assert "Forensic Analyst" in assigned_data["responsibilities"]
    assert "Reviewer" in assigned_data["responsibilities"]

    # 4. Confirm Investigator 2 token_version was incremented
    u2 = db.query(User).filter(User.user_id == "U_INV_2").first()
    db.refresh(u2)
    assert u2.token_version == 2

    # 5. Investigator 2 with new token_version=2 can view members and access case
    token2_new = make_jwt("investigator2", "Investigator", "U_INV_2", ver=2)
    res_m2 = client.get("/api/v1/cases/CASE_TEAM_TEST/members", headers={"Authorization": f"Bearer {token2_new}"})
    assert res_m2.status_code == 200
    assert len(res_m2.json()) == 2

    # 6. Remove Investigator 2 from case team
    res_del = client.delete("/api/v1/cases/CASE_TEAM_TEST/members/U_INV_2", headers={"Authorization": f"Bearer {token1}"})
    assert res_del.status_code == 200

    # Confirm list now has only 1 member
    res_m3 = client.get("/api/v1/cases/CASE_TEAM_TEST/members", headers={"Authorization": f"Bearer {token1}"})
    assert res_m3.status_code == 200
    assert len(res_m3.json()) == 1


def test_admin_audit_and_role_endpoints(stage3_test_env):
    """
    Validates Admin Center endpoints:
    1. /api/v1/audit/logs, /api/v1/audit/verify, /api/v1/audit/reconciliation
    2. /api/v1/auth/users/{user_id}/roles and global-roles
    3. Confirms non-admins are strictly forbidden.
    """
    client = stage3_test_env["client"]
    db = stage3_test_env["db"]

    # Create an Access Administrator
    pw_hash = get_password_hash("AdminPass@2026")
    admin_user = User(
        user_id="U_ADMIN_1",
        username="admin1",
        email="admin1@hmacfr.org",
        hashed_password=pw_hash,
        role="Admin",
        token_version=1,
        is_active=True
    )
    db.add(admin_user)
    db.add(UserGlobalRole(
        id="UGR_ADMIN_1",
        user_id="U_ADMIN_1",
        role_name="Platform Super Admin"
    ))
    db.commit()

    token_admin = make_jwt("admin1", "Admin", "U_ADMIN_1", ver=1)
    token_inv = make_jwt("investigator1", "Investigator", "U_INV_1", ver=1)

    # 1. Non-admin attempting audit logs -> 403 Forbidden
    res_audit_forbidden = client.get("/api/v1/audit/logs", headers={"Authorization": f"Bearer {token_inv}"})
    assert res_audit_forbidden.status_code == 403

    # 2. Admin accessing audit logs -> 200 OK
    res_audit_ok = client.get("/api/v1/audit/logs", headers={"Authorization": f"Bearer {token_admin}"})
    assert res_audit_ok.status_code == 200
    assert isinstance(res_audit_ok.json(), list)

    # 3. Admin running audit chain verify -> 200 OK
    res_verify = client.get("/api/v1/audit/verify", headers={"Authorization": f"Bearer {token_admin}"})
    assert res_verify.status_code == 200
    assert res_verify.json()["is_valid"] is True
    assert res_verify.json()["status"] == "VALID"

    # 4. Admin running audit reconciliation -> 200 OK
    res_recon = client.get("/api/v1/audit/reconciliation", headers={"Authorization": f"Bearer {token_admin}"})
    assert res_recon.status_code == 200
    recon_data = res_recon.json()
    assert "status" in recon_data
    assert "db_count" in recon_data
    assert "ledger_count" in recon_data

    # 5. User roles query
    res_roles = client.get("/api/v1/auth/users/U_INV_1/roles", headers={"Authorization": f"Bearer {token_admin}"})
    assert res_roles.status_code == 200
    assert "global_roles" in res_roles.json()

    # 6. Update user global roles
    res_update_roles = client.put("/api/v1/auth/users/U_INV_1/global-roles", json={
        "roles": ["Access Administrator"]
    }, headers={"Authorization": f"Bearer {token_admin}"})
    assert res_update_roles.status_code == 200
    assert "Access Administrator" in res_update_roles.json()["global_roles"]

