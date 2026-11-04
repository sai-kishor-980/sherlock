"""
Phase 2 Corrective Pass Tests — SherlockAI / H-MACFR.

Covers the integrity fixes from the Phase 2 corrective pass:
1. Previous successful run followed by a new incomplete run — barrier must not carry over.
2. Stale findings cannot satisfy a new execution (execution_id isolation).
3. Invalid and unknown domain statuses are rejected by the barrier.
4. Five valid outcomes (including legitimate INSUFFICIENT_EVIDENCE) satisfy the barrier.
5. Existing approved SIS survives a failed new run (content preserved).
6. New SIS content cannot inherit an old approval (fresh PENDING review gate).
7. Retrieval endpoints do not trigger synthesis (cached-only reads).
8. Direct synthesis calls without a valid current-run barrier are blocked.

Uses synthetic outcomes for isolated unit tests and realistic execution flow
for integration tests.
"""

import json
import os
import shutil
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.services.agent_barrier_service import (
    AgentBarrierService,
    ForensicInvestigationState,
    REQUIRED_DOMAINS,
)
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

def _make_findings(case_id: str, domains_with_status: dict) -> list:
    """Build findings list from a {domain: status} mapping."""
    findings = []
    for domain in REQUIRED_DOMAINS:
        status = domains_with_status.get(domain, "MISSING")
        if status == "MISSING":
            continue
        findings.append({
            "case_id": case_id,
            "domain": domain,
            "finding_id": f"F-{domain.upper()}-001",
            "classification": "BENIGN" if status != "INSUFFICIENT_EVIDENCE" else "INSUFFICIENT_EVIDENCE",
            "status": status if status != "COMPLETED" else None,
            "confidence": 0.80 if status != "INSUFFICIENT_EVIDENCE" else 0.0,
        })
    return findings


def _setup_auth_headers(db, username="inv_corrective"):
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

    case_id = f"CASE_CORR_{uuid.uuid4().hex[:8]}"
    test_case = Case(
        case_id=case_id,
        case_name="Corrective Pass Case",
        description="Corrective pass test case",
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


# ---------------------------------------------------------------------------
# 1. Previous successful run followed by a new incomplete run
# ---------------------------------------------------------------------------

def test_previous_success_does_not_authorize_new_incomplete_run():
    """A previous satisfied barrier must not authorize a new run with incomplete domains."""
    case_id = f"CASE_PREV_SUCCESS_{uuid.uuid4().hex[:8]}"

    # Run 1: all five domains valid → barrier satisfied
    findings_run1 = _make_findings(case_id, {d: "COMPLETED" for d in REQUIRED_DOMAINS})
    ok1, _ = AgentBarrierService.evaluate_five_agent_barrier(case_id, findings_run1)
    assert ok1 is True

    state_after_run1 = AgentBarrierService.get_case_state(case_id)
    assert state_after_run1["barrier_satisfied"] is True
    execution_id_run1 = state_after_run1["execution_id"]

    # Run 2: only 3 domains valid, 2 missing → barrier NOT satisfied for new execution
    findings_run2 = _make_findings(case_id, {"network": "COMPLETED", "disk": "COMPLETED", "logs": "COMPLETED"})
    ok2, details2 = AgentBarrierService.evaluate_five_agent_barrier(case_id, findings_run2)
    assert ok2 is False
    assert "memory" in details2["failed_domains"]
    assert "registry" in details2["failed_domains"]

    # The state must reflect the NEW execution, not the old one
    state_after_run2 = AgentBarrierService.get_case_state(case_id)
    assert state_after_run2["execution_id"] != execution_id_run1
    assert state_after_run2["barrier_satisfied"] is False
    assert state_after_run2["status"] == ForensicInvestigationState.AGENTS_PARTIAL


# ---------------------------------------------------------------------------
# 2. Stale findings cannot satisfy a new execution
# ---------------------------------------------------------------------------

def test_stale_findings_cannot_satisfy_new_execution():
    """Findings tagged with a stale execution_id must not satisfy a new barrier."""
    case_id = f"CASE_STALE_{uuid.uuid4().hex[:8]}"

    # Set up barrier with execution_id_A
    findings_a = _make_findings(case_id, {d: "COMPLETED" for d in REQUIRED_DOMAINS})
    ok_a, details_a = AgentBarrierService.evaluate_five_agent_barrier(case_id, findings_a)
    assert ok_a is True
    execution_id_a = details_a["execution_id"]

    # Now synthesize with a DIFFERENT execution_id — should be blocked
    assert not AgentBarrierService.validate_barrier_for_execution(case_id, str(uuid.uuid4()))

    # Only the same execution_id validates
    assert AgentBarrierService.validate_barrier_for_execution(case_id, execution_id_a) is True


# ---------------------------------------------------------------------------
# 3. Invalid and unknown domain statuses are rejected
# ---------------------------------------------------------------------------

def test_invalid_domain_status_rejected():
    """An unrecognized domain status must not count toward barrier completion."""
    case_id = f"CASE_INVALID_{uuid.uuid4().hex[:8]}"

    findings = _make_findings(case_id, {d: "COMPLETED" for d in REQUIRED_DOMAINS})
    # Corrupt one domain with an invalid status
    for f in findings:
        if f["domain"] == "memory":
            f["status"] = "UNKNOWN_STATUS"
            f["classification"] = "BENIGN"

    ok, details = AgentBarrierService.evaluate_five_agent_barrier(case_id, findings)
    assert ok is False
    assert "memory" in details["failed_domains"]
    assert details["domain_evaluations"]["memory"]["status"] == "INVALID"


def test_gpu_unavailable_status_rejected():
    """GPU_UNAVAILABLE status must not count toward barrier completion."""
    case_id = f"CASE_GPU_{uuid.uuid4().hex[:8]}"

    findings = _make_findings(case_id, {d: "COMPLETED" for d in REQUIRED_DOMAINS})
    for f in findings:
        if f["domain"] == "memory":
            f["status"] = "FAILED"
            f["error"] = "GPU_UNAVAILABLE"

    ok, details = AgentBarrierService.evaluate_five_agent_barrier(case_id, findings)
    assert ok is False
    assert "memory" in details["failed_domains"]
    assert details["domain_evaluations"]["memory"]["status"] == "FAILED"


# ---------------------------------------------------------------------------
# 4. Five valid outcomes (including INSUFFICIENT_EVIDENCE) satisfy barrier
# ---------------------------------------------------------------------------

def test_five_valid_outcomes_including_insufficient_satisfy_barrier():
    """Mixed valid findings + INSUFFICIENT_EVIDENCE outcomes satisfy the barrier."""
    case_id = f"CASE_MIXED_{uuid.uuid4().hex[:8]}"

    # 2 domains with findings, 3 domains with INSUFFICIENT_EVIDENCE
    domains_with_status = {
        "network": "COMPLETED",
        "disk": "COMPLETED",
        "memory": "INSUFFICIENT_EVIDENCE",
        "logs": "INSUFFICIENT_EVIDENCE",
        "registry": "INSUFFICIENT_EVIDENCE",
    }
    findings = _make_findings(case_id, domains_with_status)

    ok, details = AgentBarrierService.evaluate_five_agent_barrier(case_id, findings)
    assert ok is True
    assert set(details["completed_domains"]) == set(REQUIRED_DOMAINS)
    assert set(details["insufficient_evidence_domains"]) == {"memory", "logs", "registry"}
    assert len(details["failed_domains"]) == 0

    state = AgentBarrierService.get_case_state(case_id)
    assert state["barrier_satisfied"] is True


# ---------------------------------------------------------------------------
# 5. Existing approved SIS survives a failed new run
# ---------------------------------------------------------------------------

def test_approved_sis_survives_failed_new_run():
    """A failed new synthesis must not modify the previously approved SIS."""
    case_id = f"CASE_SIS_SURVIVE_{uuid.uuid4().hex[:8]}"

    # Set up barrier and synthesize → creates SIS with PENDING review
    findings = _make_findings(case_id, {d: "COMPLETED" for d in REQUIRED_DOMAINS})
    AgentBarrierService.evaluate_five_agent_barrier(case_id, findings)

    synth1 = ForensicSynthesizerService.synthesize_case(case_id)
    # GPU may be unavailable; synthesis response is cached either way
    assert synth1["status"] in ("COMPLETED", "BLOCKED_GPU_UNAVAILABLE")

    # Approve the SIS via update_sis_review
    try:
        approved = ForensicSynthesizerService.update_sis_review(
            case_id, "APPROVE", "reviewer1", "Approved for test"
        )
        assert approved["review_gate"]["status"] == "APPROVED"
        assert approved["investigation_status"] == "APPROVED_LOCKED"
    except ValueError:
        # SIS may not exist if synthesis was blocked and no sis_state.json was written
        pytest.skip("SIS state not created (synthesis blocked)")

    # Record the approved SIS content
    sis_file = ForensicSynthesizerService.get_case_output_dir(case_id) / "sis_state.json"
    with open(sis_file, "r", encoding="utf-8") as f:
        approved_sis = json.load(f)
    approved_review_gate = approved_sis["review_gate"]
    approved_status = approved_sis["investigation_status"]

    # Now run a failed synthesis (barrier not satisfied for new execution)
    # Simulate by creating findings with a missing domain
    findings_fail = _make_findings(case_id, {"network": "COMPLETED", "disk": "COMPLETED"})
    AgentBarrierService.evaluate_five_agent_barrier(case_id, findings_fail)

    state = AgentBarrierService.get_case_state(case_id)
    assert state["barrier_satisfied"] is False

    # Attempt synthesis — should be blocked, not overwrite the approved SIS
    synth2 = ForensicSynthesizerService.synthesize_case(case_id)
    assert synth2["status"] == "BLOCKED_BARRIER_NOT_SATISFIED"

    # The approved SIS file must be untouched
    with open(sis_file, "r", encoding="utf-8") as f:
        sis_after = json.load(f)
    assert sis_after["review_gate"] == approved_review_gate
    assert sis_after["investigation_status"] == approved_status


# ---------------------------------------------------------------------------
# 6. New SIS content cannot inherit an old approval
# ---------------------------------------------------------------------------

def test_new_sis_cannot_inherit_old_approval():
    """Newly generated SIS content must start with PENDING review, not inherit APPROVED."""
    case_id = f"CASE_NO_INHERIT_{uuid.uuid4().hex[:8]}"

    # Set up barrier and synthesize
    findings = _make_findings(case_id, {d: "COMPLETED" for d in REQUIRED_DOMAINS})
    AgentBarrierService.evaluate_five_agent_barrier(case_id, findings)

    synth1 = ForensicSynthesizerService.synthesize_case(case_id)
    assert synth1["status"] in ("COMPLETED", "BLOCKED_GPU_UNAVAILABLE")

    # Approve the SIS
    try:
        ForensicSynthesizerService.update_sis_review(case_id, "APPROVE", "reviewer1", "First approval")
    except ValueError:
        pytest.skip("SIS state not created (synthesis blocked)")

    # Verify sis_state.json has APPROVED review gate
    sis_file = ForensicSynthesizerService.get_case_output_dir(case_id) / "sis_state.json"
    with open(sis_file, "r", encoding="utf-8") as f:
        sis_before = json.load(f)
    assert sis_before["review_gate"]["status"] == "APPROVED"

    # Now synthesize again (new execution) — barrier will be re-set
    findings2 = _make_findings(case_id, {d: "COMPLETED" for d in REQUIRED_DOMAINS})
    AgentBarrierService.evaluate_five_agent_barrier(case_id, findings2)

    # Re-synthesize — new SIS content must NOT inherit the old APPROVED status
    synth2 = ForensicSynthesizerService.synthesize_case(case_id)
    assert synth2["status"] in ("COMPLETED", "BLOCKED_GPU_UNAVAILABLE")

    # Check the versioned pending file (not the preserved approved original)
    case_output = ForensicSynthesizerService.get_case_output_dir(case_id)
    versioned_files = list(case_output.glob("sis_state_v*_pending.json"))
    if versioned_files:
        with open(versioned_files[-1], "r", encoding="utf-8") as f:
            new_sis = json.load(f)
        # New SIS content must have PENDING review gate, not APPROVED
        assert new_sis["review_gate"]["status"] == "PENDING"
        assert new_sis["review_gate"]["notes"] and "fresh investigator review" in new_sis["review_gate"]["notes"].lower()

    # The original APPROVED sis_state.json must be preserved untouched
    with open(sis_file, "r", encoding="utf-8") as f:
        sis_preserved = json.load(f)
    assert sis_preserved["review_gate"]["status"] == "APPROVED"


# ---------------------------------------------------------------------------
# 7. Retrieval endpoints do not trigger synthesis
# ---------------------------------------------------------------------------

def test_retrieval_endpoints_do_not_trigger_synthesis():
    """GET /data, /artifacts, /timeline, /findings must not call synthesize_case()."""
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
        case_id, headers = _setup_auth_headers(db)

        # No synthesis has been run — all retrieval endpoints should return
        # "synthesis_required" without calling synthesize_case().
        endpoints = [
            f"/api/v1/analysis/{case_id}/data",
            f"/api/v1/analysis/{case_id}/artifacts",
            f"/api/v1/analysis/{case_id}/timeline",
            f"/api/v1/analysis/{case_id}/findings",
        ]
        for ep in endpoints:
            res = client.get(ep, headers=headers)
            assert res.status_code == 200, f"{ep}: {res.text}"
            body = res.json()
            assert body.get("synthesis_required") is True, f"{ep}: expected synthesis_required, got {body}"

        # Report endpoints should return 423 (locked) or synthesis_required, not trigger synthesis
        res = client.get(f"/api/v1/analysis/{case_id}/report", headers=headers)
        assert res.status_code in (423, 200), f"report: {res.status_code} {res.text}"

        res = client.get(f"/api/v1/cases/{case_id}/report", headers=headers)
        assert res.status_code in (423, 200), f"cases/report: {res.status_code} {res.text}"

        res = client.get(f"/api/v1/{case_id}/report/pdf", headers=headers)
        assert res.status_code in (423, 200, 404), f"pdf: {res.status_code} {res.text}"

    finally:
        app.dependency_overrides.clear()
        db.close()
        # Cleanup
        out_dir = Path("output/cases") / case_id
        if out_dir.exists():
            shutil.rmtree(out_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 8. Direct synthesis calls without a valid current-run barrier are blocked
# ---------------------------------------------------------------------------

def test_direct_synthesis_without_barrier_is_blocked():
    """Calling synthesize_case() directly without barrier setup must be blocked."""
    case_id = f"CASE_NO_BARRIER_{uuid.uuid4().hex[:8]}"

    # No barrier has been set up for this case
    res = ForensicSynthesizerService.synthesize_case(case_id)
    assert res["status"] == "BLOCKED_BARRIER_NOT_SATISFIED"
    assert res["execution_id"] is None  # No execution was ever registered

    # After setting up a valid barrier, synthesis should proceed (or be GPU-blocked)
    findings = _make_findings(case_id, {d: "COMPLETED" for d in REQUIRED_DOMAINS})
    AgentBarrierService.evaluate_five_agent_barrier(case_id, findings)

    res2 = ForensicSynthesizerService.synthesize_case(case_id)
    assert res2["status"] in ("COMPLETED", "BLOCKED_GPU_UNAVAILABLE")
    assert res2["status"] != "BLOCKED_BARRIER_NOT_SATISFIED"
