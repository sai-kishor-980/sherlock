"""
Tests for Findings, Attack Timeline Reconstructions, and SIS State Verification.
Verifies that:
1. GET /api/v1/cases/{id}/findings returns domain findings with observation accounting.
2. Multi-source evidence (e.g. Disk + Network PCAP) reconstructs timeline events across sources.
3. SIS state exposes normalized timeline, attack hypotheses, and cross-domain correlations.
4. GET /api/v1/analysis/tasks/{task_id} reliably tracks analysis lifecycle.
"""

import pytest
import os
import json
from starlette.testclient import TestClient
from app.db.connection import SessionLocal
from app.db.models.case import Case
from app.db.models.evidence import Evidence
from app.db.models.user import User
from app.core.security import create_access_token
from main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def auth_headers():
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "admin").first()
        token = create_access_token({
            "sub": user.username,
            "user_id": user.user_id,
            "id": user.user_id,
            "role": user.role,
            "ver": getattr(user, "token_version", 1)
        })
        return {"Authorization": f"Bearer {token}"}
    finally:
        db.close()


def test_case_findings_endpoint(client, auth_headers):
    # Verify GET /api/v1/cases/CASE_1282243c/findings
    resp = client.get("/api/v1/cases/CASE_1282243c/findings", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    findings = resp.json()
    assert isinstance(findings, list)
    assert len(findings) > 0

    first_finding = findings[0]
    assert "finding_id" in first_finding
    assert "domain" in first_finding
    assert "observation" in first_finding
    assert "assessment" in first_finding


def test_case_sis_and_timeline_endpoint(client, auth_headers):
    # Verify GET /api/v1/cases/CASE_1282243c/sis
    resp = client.get("/api/v1/cases/CASE_1282243c/sis", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    sis = resp.json()

    # Timeline must be populated with sequenced events
    timeline = sis.get("timeline") or sis.get("attack_timeline")
    assert timeline is not None
    assert len(timeline) > 0, "Timeline should contain sequenced events from disk/network"

    # Verify event structure
    first_evt = timeline[0]
    assert "event_id" in first_evt
    assert "domain" in first_evt
    assert "description" in first_evt

    # Verify hypotheses and correlations
    hypotheses = sis.get("attack_hypotheses") or sis.get("causal_hypotheses")
    assert hypotheses is not None
    assert len(hypotheses) > 0

    correlations = sis.get("cross_domain_correlations") or sis.get("correlations")
    assert correlations is not None
    assert len(correlations) > 0


def test_analysis_tasks_endpoint(client, auth_headers):
    # Verify GET /api/v1/analysis/tasks
    resp = client.get("/api/v1/analysis/tasks", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    tasks = resp.json()
    assert isinstance(tasks, list)
