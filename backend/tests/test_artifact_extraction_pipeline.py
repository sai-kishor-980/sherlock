import os
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from main import create_app
from app.db.connection import Base, get_db
from app.db.models.user import User
from app.db.models.case import Case
from app.db.models.evidence import Evidence
from app.db.models.case_assignment import CaseMember, CaseMemberResponsibility
from app.core.security import get_password_hash
from artifact_extraction.plugin_manager.detector import EvidenceDetector
from artifact_extraction.plugin_manager.registry import PluginRegistry


@pytest.fixture(scope="module")
def extraction_test_env():
    test_db_url = "sqlite:///./test_extraction.db"
    engine = create_engine(test_db_url, connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    app = create_app()

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    # Seed test users
    db = TestingSessionLocal()
    db.query(CaseMemberResponsibility).delete()
    db.query(CaseMember).delete()
    db.query(Evidence).delete()
    db.query(Case).delete()
    db.query(User).delete()
    db.commit()

    inv = User(
        user_id="USR-EXT-INV",
        username="extract_investigator",
        email="extract_inv@sherlock.ai",
        hashed_password=get_password_hash("Extract@2026"),
        role="Investigator",
        is_active=True
    )
    db.add(inv)
    db.commit()

    # Create Case
    test_case_id = "CASE_EXT_TEST_01"
    case = Case(
        case_id=test_case_id,
        case_name="Extraction Pipeline Verification Case",
        investigator_name=inv.username,
        status="Active",
        priority="High"
    )
    db.add(case)
    db.commit()

    # RBAC Assignment
    from app.services.rbac_service import RBACService
    RBACService.assign_case_creator(db=db, case_id=test_case_id, user_id=inv.user_id)

    # Create controlled synthetic evidence files on disk
    vault_dir = Path("sherf/backend/evidence_vault") / test_case_id / "General"
    vault_dir.mkdir(parents=True, exist_ok=True)

    evtx_path = vault_dir / "security_sample.evtx"
    evtx_path.write_bytes(b"ElfFile\x00" + b"\x00" * 512)

    pf_path = vault_dir / "CMD.EXE-12345678.pf"
    pf_path.write_bytes(b"\x1a\x00\x00\x00SCCA" + b"\x00" * 256)

    reg_path = vault_dir / "NTUSER.DAT"
    reg_path.write_bytes(b"regf\x01\x00\x00\x00" + b"\x00" * 512)

    # Register in DB with intentionally generic/varied categories to verify signature-based routing
    ev_evtx = Evidence(
        evidence_id="EVD-EVTX-01",
        case_id=test_case_id,
        original_filename="security_sample.evtx",
        stored_filename="security_sample.evtx",
        category="General",
        type="EVTX",
        extension=".evtx",
        storage_path=str(evtx_path.resolve()),
        status="VALIDATED",
        file_size=len(evtx_path.read_bytes()),
        file_hash="dummy_evtx_hash"
    )
    ev_pf = Evidence(
        evidence_id="EVD-PF-01",
        case_id=test_case_id,
        original_filename="CMD.EXE-12345678.pf",
        stored_filename="CMD.EXE-12345678.pf",
        category="Disk",
        type="PF",
        extension=".pf",
        storage_path=str(pf_path.resolve()),
        status="VALIDATED",
        file_size=len(pf_path.read_bytes()),
        file_hash="dummy_pf_hash"
    )
    ev_reg = Evidence(
        evidence_id="EVD-REG-01",
        case_id=test_case_id,
        original_filename="NTUSER.DAT",
        stored_filename="NTUSER.DAT",
        category="Registry",
        type="REG",
        extension=".dat",
        storage_path=str(reg_path.resolve()),
        status="VALIDATED",
        file_size=len(reg_path.read_bytes()),
        file_hash="dummy_reg_hash"
    )
    db.add_all([ev_evtx, ev_pf, ev_reg])
    db.commit()

    client = TestClient(app)
    # Login
    login_res = client.post("/api/v1/auth/login", json={"username": "extract_investigator", "password": "Extract@2026"})
    assert login_res.status_code == 200, f"Login failed: {login_res.text}"
    token = login_res.json()["access_token"]
    auth_headers = {"Authorization": f"Bearer {token}"}

    yield {
        "client": client,
        "headers": auth_headers,
        "case_id": test_case_id,
        "db": db
    }

    db.close()
    if os.path.exists("./test_extraction.db"):
        try:
            os.remove("./test_extraction.db")
        except Exception:
            pass


def test_evidence_detector_signature_routing():
    """Verify that EvidenceDetector maps genuine forensic artifact signatures accurately."""
    assert EvidenceDetector.detect("case/evidence/security.evtx") == "eventlog"
    assert EvidenceDetector.detect("case/evidence/CMD.EXE-1234.pf") == "prefetch"
    assert EvidenceDetector.detect("case/evidence/capture.pcap") == "pcap"
    assert EvidenceDetector.detect("case/evidence/capture.pcapng") == "pcap"
    assert EvidenceDetector.detect("case/evidence/NTUSER.DAT") == "registry"
    assert EvidenceDetector.detect("case/evidence/SAM") == "registry"
    assert EvidenceDetector.detect("case/evidence/SYSTEM") == "registry"
    assert EvidenceDetector.detect("case/evidence/memory.raw") == "memory"
    assert EvidenceDetector.detect("case/evidence/disk_image.raw") == "disk"


def test_manifest_endpoint_and_auto_synthesis(extraction_test_env):
    """
    Test extraction execution:
    1. POST /api/v1/analysis/{case_id}/extract succeeds.
    2. GET /api/v1/cases/{case_id}/manifest returns 200 with active agents and count.
    3. GET /api/v1/analysis/{case_id}/artifacts returns 200 with categories key populated.
    """
    client = extraction_test_env["client"]
    headers = extraction_test_env["headers"]
    case_id = extraction_test_env["case_id"]

    # Trigger extraction
    extract_res = client.post(f"/api/v1/analysis/{case_id}/extract", headers=headers)
    assert extract_res.status_code == 200, f"Extraction failed: {extract_res.text}"
    extract_body = extract_res.json()
    assert extract_body.get("status") == "SUCCESS"
    assert extract_body.get("evidence_count") == 3

    # Verify Manifest Endpoint
    manifest_res = client.get(f"/api/v1/cases/{case_id}/manifest", headers=headers)
    assert manifest_res.status_code == 200, f"Manifest route failed: {manifest_res.text}"
    manifest = manifest_res.json()
    assert manifest.get("case_id") == case_id
    assert "active_agents" in manifest
    assert "total_artifacts_extracted" in manifest
    assert manifest["total_artifacts_extracted"] >= 0

    # Verify Artifacts Endpoint has categories populated
    artifacts_res = client.get(f"/api/v1/analysis/{case_id}/artifacts", headers=headers)
    assert artifacts_res.status_code == 200, f"Artifacts route failed: {artifacts_res.text}"
    arts_body = artifacts_res.json()
    assert "summary" in arts_body
    assert "artifacts" in arts_body
    assert "categories" in arts_body, "Frontend ArtifactExplorerTable requires 'categories' key"
