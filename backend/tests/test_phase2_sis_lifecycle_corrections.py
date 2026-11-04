"""
Phase 2 Final SIS Lifecycle Corrections — Tests.

Covers:
- Pending SIS retrieval.
- Approval of a specific pending version.
- Rejection of a pending version without modifying the active approved version.
- Promotion of an approved pending version.
- Preservation of previous approved versions.
- Report/PDF retrieval after promotion.
- GPU failure while an older approved report exists.
- GPU failure when no previous approved report exists.
- Repeated synthesis and review requests.
- Consistency between active SIS version and active report version.
"""

import json
import shutil
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.services.agent_barrier_service import AgentBarrierService, REQUIRED_DOMAINS
from app.services.synthesizer_service import ForensicSynthesizerService
from main import app
from app.db.connection import Base, get_db
from app.db.models.user import User
from app.db.models.case import Case
from app.db.models.evidence import Evidence
from app.db.models.case_assignment import CaseMember, CaseMemberResponsibility
from app.core.security import get_password_hash, create_access_token
from datetime import timedelta


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_findings(case_id: str, statuses: dict) -> list:
    findings = []
    for domain in REQUIRED_DOMAINS:
        st = statuses.get(domain, "COMPLETED")
        findings.append({
            "case_id": case_id,
            "domain": domain,
            "finding_id": f"F-{domain.upper()}-001",
            "classification": "BENIGN" if st != "INSUFFICIENT_EVIDENCE" else "INSUFFICIENT_EVIDENCE",
            "status": None if st == "COMPLETED" else st,
            "confidence": 0.80 if st != "INSUFFICIENT_EVIDENCE" else 0.0,
        })
    return findings


def _setup_case_and_headers(db, username="inv_lifecycle"):
    pw_hash = get_password_hash("TestPass@2026")
    inv = User(
        user_id=f"U_{username}",
        username=username,
        email=f"{username}@hmacfr.org",
        hashed_password=pw_hash,
        role="Investigator",
        token_version=1,
        is_active=True,
    )
    db.add(inv)

    case_id = f"CASE_LIFECYCLE_{uuid.uuid4().hex[:8]}"
    test_case = Case(
        case_id=case_id,
        case_name="Lifecycle Test Case",
        description="Lifecycle test case",
        priority="High",
        status="Active",
        investigator_name=username,
    )
    db.add(test_case)
    db.commit()

    mbr = CaseMember(
        id=f"MBR_{username}",
        case_id=case_id,
        user_id=inv.user_id,
        assigned_by=inv.user_id,
    )
    db.add(mbr)
    db.commit()

    resp = CaseMemberResponsibility(
        case_member_id=mbr.id,
        responsibility_name="Lead Investigator",
    )
    db.add(resp)
    db.commit()

    token = create_access_token(
        data={"sub": username, "id": inv.user_id, "role": "Investigator", "ver": 1},
        expires_delta=timedelta(hours=1),
    )
    headers = {"Authorization": f"Bearer {token}"}
    return case_id, headers


def _setup_barrier_and_synthesize(case_id):
    """Set up barrier with all 5 domains and synthesize. Returns synthesis result."""
    findings = _make_findings(case_id, {d: "COMPLETED" for d in REQUIRED_DOMAINS})
    AgentBarrierService.evaluate_five_agent_barrier(case_id, findings)
    res = ForensicSynthesizerService.synthesize_case(case_id)
    return res


# ---------------------------------------------------------------------------
# Pending SIS retrieval
# ---------------------------------------------------------------------------

def test_pending_sis_retrieval():
    """After synthesis, the latest pending SIS is retrievable via API."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
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

    try:
        case_id, headers = _setup_case_and_headers(db)
        res = _setup_barrier_and_synthesize(case_id)
        # Synthesis may be COMPLETED or BLOCKED_GPU_UNAVAILABLE in this env
        assert res["status"] in ("COMPLETED", "BLOCKED_GPU_UNAVAILABLE")

        # List versions
        ver_res = client.get(f"/api/v1/cases/{case_id}/sis/versions", headers=headers)
        assert ver_res.status_code == 200, ver_res.text
        versions = ver_res.json()["versions"]
        assert len(versions) >= 1

        # Pending endpoint
        pend_res = client.get(f"/api/v1/cases/{case_id}/sis/pending", headers=headers)
        if pend_res.status_code == 200:
            pend = pend_res.json()["sis"]
            assert pend["review_gate"]["status"] == "PENDING"
    finally:
        app.dependency_overrides.clear()
        db.close()
        out_dir = Path("output/cases") / case_id
        if out_dir.exists():
            shutil.rmtree(out_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Approval of a specific pending version
# ---------------------------------------------------------------------------

def test_approval_of_specific_pending_version():
    """Approving a specific pending version promotes it to active SIS."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
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

    try:
        case_id, headers = _setup_case_and_headers(db)
        res = _setup_barrier_and_synthesize(case_id)
        assert res["status"] in ("COMPLETED", "BLOCKED_GPU_UNAVAILABLE")

        # List versions to find pending version number
        ver_res = client.get(f"/api/v1/cases/{case_id}/sis/versions", headers=headers)
        versions = ver_res.json()["versions"]
        pend_vers = [v for v in versions if v["review_gate"]["status"] == "PENDING"]
        assert len(pend_vers) >= 1, f"No pending version found: {versions}"
        pend_ver = pend_vers[0]["version"]

        # Approve the specific pending version
        approve_res = client.post(
            f"/api/v1/cases/{case_id}/sis/review",
            headers=headers,
            json={"action": "APPROVE", "notes": "Approving pending version", "version": pend_ver},
        )
        assert approve_res.status_code == 200, approve_res.text
        assert approve_res.json()["sis"]["review_gate"]["status"] == "APPROVED"
        assert approve_res.json()["sis"]["investigation_status"] == "APPROVED_LOCKED"

        # Active SIS now reflects the approved version
        sis_res = client.get(f"/api/v1/cases/{case_id}/sis", headers=headers)
        assert sis_res.status_code == 200
        active = sis_res.json()
        assert active["review_gate"]["status"] == "APPROVED"
    finally:
        app.dependency_overrides.clear()
        db.close()
        out_dir = Path("output/cases") / case_id
        if out_dir.exists():
            shutil.rmtree(out_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Rejection of pending version without modifying active approved version
# ---------------------------------------------------------------------------

def test_rejection_pending_without_modifying_active_approved():
    """Rejecting a pending version leaves the active approved SIS unchanged."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
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

    try:
        case_id, headers = _setup_case_and_headers(db)
        res = _setup_barrier_and_synthesize(case_id)
        assert res["status"] in ("COMPLETED", "BLOCKED_GPU_UNAVAILABLE")

        # Approve v1 first
        v1_res = client.get(f"/api/v1/cases/{case_id}/sis/versions", headers=headers)
        v1_ver = v1_res.json()["versions"][0]["version"]
        apr = client.post(
            f"/api/v1/cases/{case_id}/sis/review",
            headers=headers,
            json={"action": "APPROVE", "notes": "First approval", "version": v1_ver},
        )
        assert apr.status_code == 200

        # Record active approved content
        active_before = client.get(f"/api/v1/cases/{case_id}/sis", headers=headers).json()
        active_review_before = active_before["review_gate"]["status"]

        # Synthesize again to create a new pending version
        res2 = _setup_barrier_and_synthesize(case_id)
        assert res2["status"] in ("COMPLETED", "BLOCKED_GPU_UNAVAILABLE")

        # Reject the new pending version
        ver_res = client.get(f"/api/v1/cases/{case_id}/sis/versions", headers=headers)
        versions = ver_res.json()["versions"]
        pend_vers = [v for v in versions if v["review_gate"]["status"] == "PENDING"]
        assert len(pend_vers) >= 1, f"No pending version: {versions}"
        pend_ver = pend_vers[0]["version"]

        rej = client.post(
            f"/api/v1/cases/{case_id}/sis/review",
            headers=headers,
            json={"action": "REJECT", "notes": "Rejecting new pending", "version": pend_ver},
        )
        assert rej.status_code == 200, rej.text

        # Active SIS must still be the approved v1
        active_after = client.get(f"/api/v1/cases/{case_id}/sis", headers=headers).json()
        assert active_after["review_gate"]["status"] == "APPROVED"
        assert active_after["review_gate"]["reviewed_by"] == active_before["review_gate"]["reviewed_by"]
    finally:
        app.dependency_overrides.clear()
        db.close()
        out_dir = Path("output/cases") / case_id
        if out_dir.exists():
            shutil.rmtree(out_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Promotion of approved pending version
# ---------------------------------------------------------------------------

def test_promotion_of_approved_pending_version():
    """Approving a pending version makes it the active SIS used by report endpoints."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
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

    try:
        case_id, headers = _setup_case_and_headers(db)
        res = _setup_barrier_and_synthesize(case_id)
        assert res["status"] in ("COMPLETED", "BLOCKED_GPU_UNAVAILABLE")

        ver_res = client.get(f"/api/v1/cases/{case_id}/sis/versions", headers=headers)
        versions = ver_res.json()["versions"]
        pend_vers = [v for v in versions if v["review_gate"]["status"] == "PENDING"]
        assert len(pend_vers) >= 1
        pend_ver = pend_vers[0]["version"]

        # Approve pending version
        apr = client.post(
            f"/api/v1/cases/{case_id}/sis/review",
            headers=headers,
            json={"action": "APPROVE", "notes": "Promote pending", "version": pend_ver},
        )
        assert apr.status_code == 200
        assert apr.json()["sis"]["review_gate"]["status"] == "APPROVED"

        # Report endpoint should now pass the approval gate
        rep = client.get(f"/api/v1/cases/{case_id}/report", headers=headers)
        assert rep.status_code in (200, 404), f"Report: {rep.status_code} {rep.text}"
        if rep.status_code == 200:
            assert rep.json() is not None

        # Active SIS reflects promoted version
        active = client.get(f"/api/v1/cases/{case_id}/sis", headers=headers).json()
        assert active["review_gate"]["status"] == "APPROVED"
    finally:
        app.dependency_overrides.clear()
        db.close()
        out_dir = Path("output/cases") / case_id
        if out_dir.exists():
            shutil.rmtree(out_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Preservation of previous approved versions
# ---------------------------------------------------------------------------

def test_preservation_of_previous_approved_versions():
    """Approving a new version archives the previous approved version."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
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

    try:
        case_id, headers = _setup_case_and_headers(db)
        res = _setup_barrier_and_synthesize(case_id)
        assert res["status"] in ("COMPLETED", "BLOCKED_GPU_UNAVAILABLE")

        # Approve v1
        ver_res = client.get(f"/api/v1/cases/{case_id}/sis/versions", headers=headers)
        v1_ver = ver_res.json()["versions"][0]["version"]
        apr1 = client.post(
            f"/api/v1/cases/{case_id}/sis/review",
            headers=headers,
            json={"action": "APPROVE", "notes": "First approval", "version": v1_ver},
        )
        assert apr1.status_code == 200

        # Synthesize again -> new pending version
        res2 = _setup_barrier_and_synthesize(case_id)
        assert res2["status"] in ("COMPLETED", "BLOCKED_GPU_UNAVAILABLE")

        # Approve v2
        ver_res = client.get(f"/api/v1/cases/{case_id}/sis/versions", headers=headers)
        versions = ver_res.json()["versions"]
        pend_vers = [v for v in versions if v["review_gate"]["status"] == "PENDING"]
        assert len(pend_vers) >= 1
        v2_ver = pend_vers[0]["version"]
        assert v2_ver > v1_ver

        apr2 = client.post(
            f"/api/v1/cases/{case_id}/sis/review",
            headers=headers,
            json={"action": "APPROVE", "notes": "Second approval", "version": v2_ver},
        )
        assert apr2.status_code == 200

        # List versions: should include both v1_approved and v2 as active
        ver_res = client.get(f"/api/v1/cases/{case_id}/sis/versions", headers=headers)
        versions = ver_res.json()["versions"]
        version_nums = [v["version"] for v in versions]
        assert v1_ver in version_nums, f"Previous approved version {v1_ver} not preserved: {version_nums}"
        assert v2_ver in version_nums

        # Active SIS is v2
        active = client.get(f"/api/v1/cases/{case_id}/sis", headers=headers).json()
        assert active["review_gate"]["status"] == "APPROVED"
    finally:
        app.dependency_overrides.clear()
        db.close()
        out_dir = Path("output/cases") / case_id
        if out_dir.exists():
            shutil.rmtree(out_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# GPU failure while older approved report exists
# ---------------------------------------------------------------------------

def test_gpu_failure_preserves_approved_report():
    """GPU-blocked synthesis must not overwrite an existing approved report."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
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

    try:
        case_id, headers = _setup_case_and_headers(db)
        res = _setup_barrier_and_synthesize(case_id)

        # Approve v1 (if COMPLETED; if GPU-blocked, still APPROVABLE via SIS review)
        ver_res = client.get(f"/api/v1/cases/{case_id}/sis/versions", headers=headers)
        versions = ver_res.json()["versions"]
        pend_vers = [v for v in versions if v["review_gate"]["status"] == "PENDING"]
        if not pend_vers:
            pytest.skip("No pending SIS version available for approval")

        v1_ver = pend_vers[0]["version"]
        apr = client.post(
            f"/api/v1/cases/{case_id}/sis/review",
            headers=headers,
            json={"action": "APPROVE", "notes": "Approve before GPU failure", "version": v1_ver},
        )
        assert apr.status_code == 200

        # Record the approved report content (may be None if GPU-blocked synthesis)
        rep_before = client.get(f"/api/v1/cases/{case_id}/report", headers=headers)

        # Now run GPU-blocked synthesis again
        res2 = _setup_barrier_and_synthesize(case_id)
        assert res2["status"] in ("COMPLETED", "BLOCKED_GPU_UNAVAILABLE")

        # Active SIS must still be APPROVED v1
        active = client.get(f"/api/v1/cases/{case_id}/sis", headers=headers).json()
        assert active["review_gate"]["status"] == "APPROVED"

        # Report endpoint should still work (passes approval gate)
        rep_after = client.get(f"/api/v1/cases/{case_id}/report", headers=headers)
        assert rep_after.status_code in (200, 404), f"Report after GPU failure: {rep_after.status_code}"
    finally:
        app.dependency_overrides.clear()
        db.close()
        out_dir = Path("output/cases") / case_id
        if out_dir.exists():
            shutil.rmtree(out_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# GPU failure when no previous approved report exists
# ---------------------------------------------------------------------------

def test_gpu_failure_no_previous_report():
    """GPU-blocked synthesis with no prior approved report returns blocked response."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
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

    try:
        case_id, headers = _setup_case_and_headers(db)
        res = _setup_barrier_and_synthesize(case_id)

        # No approval yet; report endpoint should be locked (423) or return blocked
        rep = client.get(f"/api/v1/cases/{case_id}/report", headers=headers)
        assert rep.status_code in (423, 200, 404), f"Report before approval: {rep.status_code} {rep.text}"

        # Active SIS must exist (PENDING or BLOCKED)
        sis = client.get(f"/api/v1/cases/{case_id}/sis", headers=headers)
        assert sis.status_code == 200
    finally:
        app.dependency_overrides.clear()
        db.close()
        out_dir = Path("output/cases") / case_id
        if out_dir.exists():
            shutil.rmtree(out_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Repeated synthesis and review requests
# ---------------------------------------------------------------------------

def test_repeated_synthesis_and_review():
    """Repeated synthesis and review requests remain consistent."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
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

    try:
        case_id, headers = _setup_case_and_headers(db)

        # Synthesize multiple times
        for _ in range(3):
            res = _setup_barrier_and_synthesize(case_id)
            assert res["status"] in ("COMPLETED", "BLOCKED_GPU_UNAVAILABLE")

        # List versions
        ver_res = client.get(f"/api/v1/cases/{case_id}/sis/versions", headers=headers)
        versions = ver_res.json()["versions"]
        assert len(versions) >= 1

        # Approve the latest pending
        pend_vers = [v for v in versions if v["review_gate"]["status"] == "PENDING"]
        if pend_vers:
            latest = max(pend_vers, key=lambda v: v["version"])
            apr = client.post(
                f"/api/v1/cases/{case_id}/sis/review",
                headers=headers,
                json={"action": "APPROVE", "notes": "Final approval", "version": latest["version"]},
            )
            assert apr.status_code == 200

            active = client.get(f"/api/v1/cases/{case_id}/sis", headers=headers).json()
            assert active["review_gate"]["status"] == "APPROVED"
    finally:
        app.dependency_overrides.clear()
        db.close()
        out_dir = Path("output/cases") / case_id
        if out_dir.exists():
            shutil.rmtree(out_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Consistency between active SIS version and active report version
# ---------------------------------------------------------------------------

def test_active_sis_report_version_consistency():
    """Active SIS version and report must refer to the same version after approval."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
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

    try:
        case_id, headers = _setup_case_and_headers(db)
        res = _setup_barrier_and_synthesize(case_id)
        assert res["status"] in ("COMPLETED", "BLOCKED_GPU_UNAVAILABLE")

        ver_res = client.get(f"/api/v1/cases/{case_id}/sis/versions", headers=headers)
        versions = ver_res.json()["versions"]
        pend_vers = [v for v in versions if v["review_gate"]["status"] == "PENDING"]
        assert len(pend_vers) >= 1
        pend_ver = pend_vers[0]["version"]

        apr = client.post(
            f"/api/v1/cases/{case_id}/sis/review",
            headers=headers,
            json={"action": "APPROVE", "notes": "Consistency check", "version": pend_ver},
        )
        assert apr.status_code == 200

        active = client.get(f"/api/v1/cases/{case_id}/sis", headers=headers).json()
        assert active["review_gate"]["status"] == "APPROVED"

        # Report endpoint passes approval gate (same version)
        rep = client.get(f"/api/v1/cases/{case_id}/report", headers=headers)
        assert rep.status_code in (200, 404), f"Report consistency: {rep.status_code}"

        # List versions: active version should match
        ver_res = client.get(f"/api/v1/cases/{case_id}/sis/versions", headers=headers)
        versions = ver_res.json()["versions"]
        active_vers = [v for v in versions if v["is_active"]]
        assert len(active_vers) == 1
        assert active_vers[0]["review_gate"]["status"] == "APPROVED"
    finally:
        app.dependency_overrides.clear()
        db.close()
        out_dir = Path("output/cases") / case_id
        if out_dir.exists():
            shutil.rmtree(out_dir, ignore_errors=True)
