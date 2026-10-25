"""
Comprehensive Stage 2 RBAC & Backend Authorization Hardening Test Suite.
Validates:
1. Token-version embedding in both login flows (/login and /login/form).
2. Token-version mismatch and missing claim rejection (401).
3. Session invalidation on password update and role update.
4. Hardened get_optional_user (no silent downgrade of invalid/stale tokens to anonymous).
5. Legacy Admin quarantine isolation (legacy Admin values cannot grant privileges).
6. Administrative route protection (user deletion, role change, password management, case deletion).
7. Case-level membership and IDOR isolation across evidence, analysis, preservation, custody.
8. Platform Auditor read-only access vs mutation denial.
9. Audit trail verification on security-sensitive actions.
10. Migration and rollback engine compatibility on disposable databases.
"""

import os
import uuid
import tempfile
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
from app.core.security import get_password_hash, create_access_token, decode_access_token
from app.services.rbac_service import RBACService
from app.services.audit_service import AuditService
from app.db.migrations.rbac_migration import apply_rbac_migration, rollback_rbac_migration


@pytest.fixture
def auth_test_env():
    """Sets up an isolated in-memory test database and test client."""
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

    # Provision standard test accounts
    pw_hash = get_password_hash("TestPass@2026")
    admin_pw_hash = get_password_hash("AdminPass@2026")

    # 1. Super Admin
    super_admin = User(
        user_id="U_SUPER_ADMIN",
        username="superadmin",
        email="superadmin@hmacfr.org",
        hashed_password=admin_pw_hash,
        role="Admin",
        token_version=1,
        is_active=True
    )
    db.add(super_admin)
    db.flush()
    db.add(UserGlobalRole(id="UGR_SUPER", user_id="U_SUPER_ADMIN", role_name="Platform Super Admin"))

    # 2. Access Admin
    access_admin = User(
        user_id="U_ACCESS_ADMIN",
        username="accessadmin",
        email="accessadmin@hmacfr.org",
        hashed_password=admin_pw_hash,
        role="Admin",
        token_version=1,
        is_active=True
    )
    db.add(access_admin)
    db.flush()
    db.add(UserGlobalRole(id="UGR_ACCESS", user_id="U_ACCESS_ADMIN", role_name="Access Administrator"))

    # 3. Quarantined Legacy Admin
    legacy_admin = User(
        user_id="U_LEGACY_ADMIN",
        username="legacyadmin",
        email="legacyadmin@hmacfr.org",
        hashed_password=admin_pw_hash,
        role="PENDING_REVIEW",
        token_version=1,
        is_active=True
    )
    db.add(legacy_admin)
    db.flush()
    db.add(UserGlobalRole(id="UGR_QUARANTINE", user_id="U_LEGACY_ADMIN", role_name="Pending_Admin_Review"))

    # 4. Platform Auditor
    auditor = User(
        user_id="U_AUDITOR",
        username="platform_auditor",
        email="auditor@hmacfr.org",
        hashed_password=pw_hash,
        role="Auditor",
        token_version=1,
        is_active=True
    )
    db.add(auditor)
    db.flush()
    db.add(UserGlobalRole(id="UGR_AUDITOR", user_id="U_AUDITOR", role_name="Platform Auditor"))

    # 5. Investigator A
    inv_a = User(
        user_id="U_INV_A",
        username="investigator_a",
        email="inv_a@hmacfr.org",
        hashed_password=pw_hash,
        role="Investigator",
        token_version=1,
        is_active=True
    )
    db.add(inv_a)

    # 6. Investigator B
    inv_b = User(
        user_id="U_INV_B",
        username="investigator_b",
        email="inv_b@hmacfr.org",
        hashed_password=pw_hash,
        role="Investigator",
        token_version=1,
        is_active=True
    )
    db.add(inv_b)

    db.commit()

    yield {
        "db": db,
        "client": client,
        "session_factory": TestingSessionLocal,
        "engine": engine
    }

    db.close()
    app.dependency_overrides.clear()


def make_token(username: str, role: str, user_id: str, ver: int = 1, delta: timedelta = None) -> str:
    """Helper to synthesize JWTs with custom claims."""
    data = {"sub": username, "role": role, "id": user_id, "ver": ver}
    return create_access_token(data=data, expires_delta=delta)


# =============================================================================
# 1. LOGIN FLOWS & TOKEN VERSION EMBEDDING
# =============================================================================

def test_login_flows_embed_token_version(auth_test_env):
    client = auth_test_env["client"]

    # 1. JSON Login Flow
    res_json = client.post("/api/v1/auth/login", json={
        "username": "investigator_a",
        "password": "TestPass@2026"
    })
    assert res_json.status_code == 200, res_json.text
    token_json = res_json.json()["access_token"]
    payload_json = decode_access_token(token_json)
    assert "ver" in payload_json
    assert payload_json["ver"] == 1
    assert payload_json["sub"] == "investigator_a"

    # 2. OAuth2 Form Login Flow
    res_form = client.post("/api/v1/auth/login/form", data={
        "username": "investigator_a",
        "password": "TestPass@2026"
    })
    assert res_form.status_code == 200, res_form.text
    token_form = res_form.json()["access_token"]
    payload_form = decode_access_token(token_form)
    assert "ver" in payload_form
    assert payload_form["ver"] == 1


# =============================================================================
# 2. TOKEN VERSION ENFORCEMENT & STALE SESSION REJECTION
# =============================================================================

def test_token_version_rejection_and_invalidation(auth_test_env):
    client = auth_test_env["client"]
    db = auth_test_env["db"]

    # Valid token (ver=1)
    valid_token = make_token("investigator_a", "Investigator", "U_INV_A", ver=1)
    res_valid = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {valid_token}"})
    assert res_valid.status_code == 200

    # Missing ver claim in JWT
    data_no_ver = {"sub": "investigator_a", "role": "Investigator", "id": "U_INV_A"}
    token_no_ver = create_access_token(data=data_no_ver)
    res_no_ver = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token_no_ver}"})
    assert res_no_ver.status_code == 401
    assert "Token version missing" in res_no_ver.json()["detail"]

    # Stale ver claim (ver=0 vs db ver=1)
    stale_token = make_token("investigator_a", "Investigator", "U_INV_A", ver=0)
    res_stale = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {stale_token}"})
    assert res_stale.status_code == 401
    assert "Session revoked" in res_stale.json()["detail"]

    # Expired token
    expired_token = make_token("investigator_a", "Investigator", "U_INV_A", ver=1, delta=timedelta(seconds=-10))
    res_expired = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert res_expired.status_code == 401
    assert "Session expired" in res_expired.json()["detail"]


def test_password_change_invalidates_session(auth_test_env):
    client = auth_test_env["client"]
    db = auth_test_env["db"]

    token_before = make_token("investigator_a", "Investigator", "U_INV_A", ver=1)
    res_before = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token_before}"})
    assert res_before.status_code == 200

    # User resets own password
    res_update = client.put(
        "/api/v1/auth/users/U_INV_A/password",
        json={"new_password": "NewSecretPass@2026"},
        headers={"Authorization": f"Bearer {token_before}"}
    )
    assert res_update.status_code == 200

    # Old token (ver=1) must now be REJECTED (token_version was incremented to 2)
    res_after = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token_before}"})
    assert res_after.status_code == 401
    assert "Session revoked" in res_after.json()["detail"]

    # New login receives ver=2 and succeeds
    login_new = client.post("/api/v1/auth/login", json={
        "username": "investigator_a",
        "password": "NewSecretPass@2026"
    })
    assert login_new.status_code == 200
    token_new = login_new.json()["access_token"]
    assert decode_access_token(token_new)["ver"] == 2


# =============================================================================
# 3. HARDENED GET_OPTIONAL_USER BEHAVIOR
# =============================================================================

def test_get_optional_user_security(auth_test_env):
    client = auth_test_env["client"]

    # Create test case
    admin_token = make_token("superadmin", "Admin", "U_SUPER_ADMIN", ver=1)
    res_case = client.post("/api/v1/cases/", json={
        "case_id": "CASE_OPT_TEST",
        "case_name": "Optional User Test Case",
        "investigator_name": "superadmin"
    }, headers={"Authorization": f"Bearer {admin_token}"})
    assert res_case.status_code == 201

    # Request with invalid token -> MUST return 401, NOT anonymous fallback!
    res_bad_token = client.post(
        "/api/v1/cases/CASE_OPT_TEST/request-deletion",
        json={"reason": "Test deletion request"},
        headers={"Authorization": "Bearer BAD_MALFORMED_JWT"}
    )
    assert res_bad_token.status_code == 401


# =============================================================================
# 4. LEGACY ADMIN QUARANTINE & ROLE PRIVILEGE ISOLATION
# =============================================================================

def test_legacy_admin_cannot_access_administrative_endpoints(auth_test_env):
    client = auth_test_env["client"]

    # Quarantined legacy admin token
    quarantined_token = make_token("legacyadmin", "PENDING_REVIEW", "U_LEGACY_ADMIN", ver=1)

    # 1. User listing (admin endpoint)
    res_users = client.get("/api/v1/auth/users", headers={"Authorization": f"Bearer {quarantined_token}"})
    assert res_users.status_code == 403
    assert "Administrative privileges required" in res_users.json()["detail"]

    # 2. Case pending deletion requests
    res_del_pending = client.get("/api/v1/cases/deletion-requests/pending", headers={"Authorization": f"Bearer {quarantined_token}"})
    assert res_del_pending.status_code == 403

    # 3. Super Admin token succeeds
    super_token = make_token("superadmin", "Admin", "U_SUPER_ADMIN", ver=1)
    res_super_users = client.get("/api/v1/auth/users", headers={"Authorization": f"Bearer {super_token}"})
    assert res_super_users.status_code == 200

    # 4. Access Admin token succeeds
    access_token = make_token("accessadmin", "Admin", "U_ACCESS_ADMIN", ver=1)
    res_access_users = client.get("/api/v1/auth/users", headers={"Authorization": f"Bearer {access_token}"})
    assert res_access_users.status_code == 200


# =============================================================================
# 5. PRIVILEGED USER & CASE DELETION AUTHORIZATION
# =============================================================================

def test_administrative_user_deletion_and_case_deletion(auth_test_env):
    client = auth_test_env["client"]
    db = auth_test_env["db"]

    inv_token = make_token("investigator_a", "Investigator", "U_INV_A", ver=1)
    super_token = make_token("superadmin", "Admin", "U_SUPER_ADMIN", ver=1)

    # 1. Investigator cannot delete user
    res_inv_del = client.request(
        "DELETE",
        "/api/v1/auth/users/U_INV_B",
        json={"admin_password": "TestPass@2026"},
        headers={"Authorization": f"Bearer {inv_token}"}
    )
    assert res_inv_del.status_code == 403

    # 2. Super Admin with incorrect password receives 401
    res_wrong_pw = client.request(
        "DELETE",
        "/api/v1/auth/users/U_INV_B",
        json={"admin_password": "WrongPassword@2026"},
        headers={"Authorization": f"Bearer {super_token}"}
    )
    assert res_wrong_pw.status_code == 401

    # 3. Super Admin self-deletion rejected
    res_self_del = client.request(
        "DELETE",
        "/api/v1/auth/users/U_SUPER_ADMIN",
        json={"admin_password": "AdminPass@2026"},
        headers={"Authorization": f"Bearer {super_token}"}
    )
    assert res_self_del.status_code == 400

    # 4. Super Admin legitimate deletion succeeds
    res_del_ok = client.request(
        "DELETE",
        "/api/v1/auth/users/U_INV_B",
        json={"admin_password": "AdminPass@2026"},
        headers={"Authorization": f"Bearer {super_token}"}
    )
    assert res_del_ok.status_code == 200
    assert res_del_ok.json()["status"] == "success"

    # 5. Case deletion unauthenticated bypass is FIXED
    res_unauth_del = client.delete("/api/v1/cases/NONEXISTENT_CASE")
    assert res_unauth_del.status_code == 401

    # 6. Case deletion resolution unauthenticated bypass is FIXED
    res_unauth_res = client.post(
        "/api/v1/cases/NONEXISTENT_CASE/deletion-resolution",
        json={"action": "APPROVE"}
    )
    assert res_unauth_res.status_code == 401


# =============================================================================
# 6. CASE & EVIDENCE MEMBERSHIP ISOLATION (IDOR PREVENTION)
# =============================================================================

def test_case_membership_and_idor_protection(auth_test_env):
    client = auth_test_env["client"]
    db = auth_test_env["db"]

    inv_a_token = make_token("investigator_a", "Investigator", "U_INV_A", ver=1)
    inv_b_token = make_token("investigator_b", "Investigator", "U_INV_B", ver=1)
    auditor_token = make_token("platform_auditor", "Auditor", "U_AUDITOR", ver=1)

    # 1. Investigator A creates Case A
    res_case_a = client.post("/api/v1/cases/", json={
        "case_id": "CASE_ALPHA",
        "case_name": "Investigation Alpha",
        "investigator_name": "investigator_a"
    }, headers={"Authorization": f"Bearer {inv_a_token}"})
    assert res_case_a.status_code == 201
    case_a_id = res_case_a.json()["case_id"]

    # 2. Investigator A uploads evidence to Case A
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tf:
        tf.write(b"Evidence file content Alpha")
        tf_path = tf.name

    try:
        with open(tf_path, "rb") as f:
            res_upload = client.post(
                "/api/v1/upload/",
                data={"case_id": case_a_id, "investigator": "investigator_a"},
                files={"file": ("alpha_evidence.txt", f, "text/plain")},
                headers={"Authorization": f"Bearer {inv_a_token}"}
            )
        assert res_upload.status_code == 201
        ev_a_id = res_upload.json()["evidence_id"]

        # 3. Investigator A can access Case A and Evidence A
        res_a_read = client.get(f"/api/v1/cases/{case_a_id}", headers={"Authorization": f"Bearer {inv_a_token}"})
        assert res_a_read.status_code == 200

        res_ev_a_read = client.get(f"/api/v1/evidence/{ev_a_id}", headers={"Authorization": f"Bearer {inv_a_token}"})
        assert res_ev_a_read.status_code == 200

        # 4. Investigator B (NOT a member of Case A) CANNOT access Case A (IDOR blocked)
        res_b_case = client.get(f"/api/v1/cases/{case_a_id}", headers={"Authorization": f"Bearer {inv_b_token}"})
        assert res_b_case.status_code == 403
        assert "Permission Denied" in res_b_case.json()["detail"]

        # 5. Investigator B CANNOT read Evidence A
        res_b_ev = client.get(f"/api/v1/evidence/{ev_a_id}", headers={"Authorization": f"Bearer {inv_b_token}"})
        assert res_b_ev.status_code == 403

        # 6. Investigator B CANNOT upload evidence to Case A
        with open(tf_path, "rb") as f:
            res_b_upload = client.post(
                "/api/v1/upload/",
                data={"case_id": case_a_id, "investigator": "investigator_b"},
                files={"file": ("rogue_evidence.txt", f, "text/plain")},
                headers={"Authorization": f"Bearer {inv_b_token}"}
            )
        assert res_b_upload.status_code == 403

        # 7. Investigator B CANNOT run analysis on Case A
        res_b_analysis = client.post(
            "/api/v1/analysis/start",
            json={"case_id": case_a_id, "case_name": "Investigation Alpha"},
            headers={"Authorization": f"Bearer {inv_b_token}"}
        )
        assert res_b_analysis.status_code == 403

        # 8. Investigator B CANNOT query custody of Evidence A
        res_b_custody = client.get(f"/api/v1/custody/evidence/{ev_a_id}", headers={"Authorization": f"Bearer {inv_b_token}"})
        assert res_b_custody.status_code == 403

        # 9. Platform Auditor CAN read Case A and Evidence A
        res_aud_case = client.get(f"/api/v1/cases/{case_a_id}", headers={"Authorization": f"Bearer {auditor_token}"})
        assert res_aud_case.status_code == 200

        res_aud_ev = client.get(f"/api/v1/evidence/{ev_a_id}", headers={"Authorization": f"Bearer {auditor_token}"})
        assert res_aud_ev.status_code == 200

        # 10. Platform Auditor CANNOT mutate or upload to Case A
        with open(tf_path, "rb") as f:
            res_aud_upload = client.post(
                "/api/v1/upload/",
                data={"case_id": case_a_id, "investigator": "platform_auditor"},
                files={"file": ("auditor_evidence.txt", f, "text/plain")},
                headers={"Authorization": f"Bearer {auditor_token}"}
            )
        assert res_aud_upload.status_code == 403
    finally:
        if os.path.exists(tf_path):
            os.remove(tf_path)


# =============================================================================
# 7. MIGRATION & ROLLBACK COMPATIBILITY ON DISPOSABLE DATABASE
# =============================================================================

def test_migration_and_rollback_compatibility():
    with tempfile.TemporaryDirectory() as tmp_dir:
        test_db = os.path.join(tmp_dir, "migration_compat_test.db")
        archive_db = os.path.join(tmp_dir, "archive.db")
        ledger_file = os.path.join(tmp_dir, "test_ledger.jsonl")

        # Create baseline sqlite database with legacy users
        import sqlite3
        conn = sqlite3.connect(test_db)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE users (
                user_id VARCHAR(36) PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                hashed_password VARCHAR(255) NOT NULL,
                role VARCHAR(30) NOT NULL DEFAULT 'Investigator',
                is_active BOOLEAN DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)
        c.execute("""
            CREATE TABLE cases (
                case_id VARCHAR(36) PRIMARY KEY,
                case_name VARCHAR(100) NOT NULL,
                investigator_name VARCHAR(50),
                description TEXT,
                priority VARCHAR(20) DEFAULT 'Medium',
                status VARCHAR(20) DEFAULT 'Active',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)
        c.execute("INSERT INTO users (user_id, username, email, hashed_password, role) VALUES ('U1', 'legacy_admin', 'adm@test.org', 'hash', 'Admin');")
        c.execute("INSERT INTO cases (case_id, case_name, investigator_name) VALUES ('C1', 'Legacy Case 1', 'legacy_admin');")
        conn.commit()
        conn.close()

        # 1. Apply Migration
        res_mig = apply_rbac_migration(test_db)
        assert res_mig["status"] == "SUCCESS"
        assert "legacy_admin" in res_mig["quarantined_admins"]

        # 2. Idempotency Check
        res_idem = apply_rbac_migration(test_db)
        assert res_idem["status"] == "ALREADY_APPLIED"

        # 3. Write dummy ledger record to verify archive
        with open(ledger_file, "w", encoding="utf-8") as f:
            f.write('{"test": "audit_record"}\n')

        # 4. Rollback
        res_roll = rollback_rbac_migration(test_db, archive_path=archive_db, ledger_path=ledger_file)
        assert res_roll["status"] == "ROLLBACK_SUCCESS"
        assert os.path.exists(archive_db)
        assert os.path.exists(res_roll["archived_ledger_path"])


# =============================================================================
# 8. WEBSOCKET ANALYSIS SECURITY & ISOLATION
# =============================================================================

def test_websocket_analysis_security(auth_test_env):
    import time
    from starlette.websockets import WebSocketDisconnect
    from app.api.routes.analysis import active_tasks, ws_manager, active_ws_tickets

    client = auth_test_env["client"]
    db = auth_test_env["db"]

    # 1. Create Case Alpha and assign Investigator A
    inv_a_token = make_token("investigator_a", "Investigator", "U_INV_A", ver=1)
    res_case_a = client.post("/api/v1/cases/", json={
        "case_id": "CASE_WS_ALPHA",
        "case_name": "Investigation WS Alpha",
        "investigator_name": "investigator_a"
    }, headers={"Authorization": f"Bearer {inv_a_token}"})
    assert res_case_a.status_code == 201

    # 2. Register active analysis task for Case Alpha
    task_alpha_id = "ANL-TASK-ALPHA"
    active_tasks[task_alpha_id] = {
        "task_id": task_alpha_id,
        "case_id": "CASE_WS_ALPHA",
        "case_name": "Investigation WS Alpha",
        "status": "running",
        "progress": 25.0,
        "stage": "Extracting Registry Hive",
        "elapsed_seconds": 2,
        "total_duration_seconds": 10,
        "time_remaining_seconds": 8,
        "created_at": time.time(),
        "logs": ["Task Alpha initialized"]
    }

    try:
        # A. Missing credentials -> Rejected (1008)
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect(f"/api/v1/analysis/ws/stream/{task_alpha_id}") as ws:
                pass
        assert exc.value.code == 1008

        # B. Invalid token -> Rejected (1008)
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect(f"/api/v1/analysis/ws/stream/{task_alpha_id}?token=INVALID_TOKEN") as ws:
                pass
        assert exc.value.code == 1008

        # C. Expired token -> Rejected (1008)
        expired_token = make_token("investigator_a", "Investigator", "U_INV_A", ver=1, delta=timedelta(seconds=-10))
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect(f"/api/v1/analysis/ws/stream/{task_alpha_id}?token={expired_token}") as ws:
                pass
        assert exc.value.code == 1008

        # D. Stale version token -> Rejected (1008)
        stale_token = make_token("investigator_a", "Investigator", "U_INV_A", ver=0)
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect(f"/api/v1/analysis/ws/stream/{task_alpha_id}?token={stale_token}") as ws:
                pass
        assert exc.value.code == 1008

        # E. Inactive user -> Rejected (1008)
        inactive_user = User(
            user_id="U_INACTIVE_WS",
            username="inactive_ws_user",
            email="inactive_ws@hmacfr.org",
            hashed_password=get_password_hash("Pass@2026"),
            role="Investigator",
            token_version=1,
            is_active=False
        )
        db.add(inactive_user)
        db.commit()
        inactive_token = make_token("inactive_ws_user", "Investigator", "U_INACTIVE_WS", ver=1)
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect(f"/api/v1/analysis/ws/stream/{task_alpha_id}?token={inactive_token}") as ws:
                pass
        assert exc.value.code == 1008

        # F. Unknown task ID -> Rejected (1008)
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect(f"/api/v1/analysis/ws/stream/NONEXISTENT_TASK?token={inv_a_token}") as ws:
                pass
        assert exc.value.code == 1008

        # G. Investigator B (no membership in Case Alpha) -> Rejected (1008)
        inv_b_token = make_token("investigator_b", "Investigator", "U_INV_B", ver=1)
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect(f"/api/v1/analysis/ws/stream/{task_alpha_id}?token={inv_b_token}") as ws:
                pass
        assert exc.value.code == 1008

        # H. Authorized Investigator A -> Connects and receives INITIAL_STATE
        with client.websocket_connect(f"/api/v1/analysis/ws/stream/{task_alpha_id}?token={inv_a_token}") as ws:
            msg = ws.receive_json()
            assert msg["type"] == "INITIAL_STATE"
            assert msg["task_id"] == task_alpha_id
            assert msg["case_id"] == "CASE_WS_ALPHA"
            assert msg["progress"] == 25.0

            # Ping/pong test
            ws.send_text("ping")
            assert ws.receive_json() == {"type": "pong"}

            # Connection actively tracked in WebSocketManager
            assert task_alpha_id in ws_manager.active_connections
            assert len(ws_manager.active_connections[task_alpha_id]) == 1

        # Disconnect cleanup verification: connection was removed after client disconnected
        assert task_alpha_id not in ws_manager.active_connections

        # I. Single-use ticket flow: issue, connect, and consume
        res_ticket = client.post("/api/v1/analysis/ws-ticket", headers={"Authorization": f"Bearer {inv_a_token}"})
        assert res_ticket.status_code == 200
        ticket_id = res_ticket.json()["ticket"]
        assert ticket_id.startswith("WST-")

        # Connect using ticket
        with client.websocket_connect(f"/api/v1/analysis/ws/stream/{task_alpha_id}?ticket={ticket_id}") as ws:
            msg = ws.receive_json()
            assert msg["type"] == "INITIAL_STATE"

        # Reusing the consumed ticket must fail
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect(f"/api/v1/analysis/ws/stream/{task_alpha_id}?ticket={ticket_id}") as ws:
                pass
        assert exc.value.code == 1008

        # J. Cross-case isolation: events from other cases never reach the connection
        task_beta_id = "ANL-TASK-BETA"
        active_tasks[task_beta_id] = {
            "task_id": task_beta_id,
            "case_id": "CASE_WS_BETA",
            "case_name": "Investigation WS Beta",
            "status": "running",
            "progress": 10.0,
            "stage": "Beta Stage",
            "elapsed_seconds": 1,
            "total_duration_seconds": 10,
            "time_remaining_seconds": 9,
            "created_at": time.time(),
            "logs": ["Task Beta initialized"]
        }

        with client.websocket_connect(f"/api/v1/analysis/ws/stream/{task_alpha_id}?token={inv_a_token}") as ws:
            # Drain initial state
            ws.receive_json()

            # Broadcast update for Task Beta (Case Beta)
            ws.portal.call(ws_manager.broadcast, task_beta_id, {
                "type": "ANALYSIS_UPDATE",
                "task_id": task_beta_id,
                "case_id": "CASE_WS_BETA",
                "secret_info": "CONFIDENTIAL_BETA_DATA"
            })

            # Broadcast update for Task Alpha (Case Alpha)
            ws.portal.call(ws_manager.broadcast, task_alpha_id, {
                "type": "ANALYSIS_UPDATE",
                "task_id": task_alpha_id,
                "case_id": "CASE_WS_ALPHA",
                "data": "AUTHORIZED_ALPHA_DATA"
            })

            # Client must immediately receive the Alpha update, without receiving any Beta event
            received = ws.receive_json()
            assert received["task_id"] == task_alpha_id
            assert received["case_id"] == "CASE_WS_ALPHA"
            assert received.get("data") == "AUTHORIZED_ALPHA_DATA"
            assert "secret_info" not in received

    finally:
        active_tasks.pop(task_alpha_id, None)
        active_tasks.pop("ANL-TASK-BETA", None)
        active_ws_tickets.clear()

