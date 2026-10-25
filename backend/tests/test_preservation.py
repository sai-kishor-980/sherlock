"""
Integration Unit Tests for Evidence Preservation & Security Module.
"""

import tempfile
import uuid
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.connection import Base
from app.db.models import Case, Evidence
from app.db.schemas import EvidencePreserveInput
from app.services.preservation_service import EvidencePreservationService


def test_preservation_pipeline():
    # 1. Setup in-memory SQLite database
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()

    unique_id = uuid.uuid4().hex[:8]
    test_case_id = f"CASE_{unique_id}"
    test_evidence_id = f"EV_{unique_id}"

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        raw_evidence_file = tmp_path / "memory_dump.raw"
        raw_evidence_file.write_bytes(b"RAM Forensic Memory Payload 2026 Preservation Test")

        # 2. Insert Case & Evidence
        case_obj = Case(
            case_id=test_case_id,
            case_name="Test Memory Investigation",
            investigator_name="Agent Smith",
            status="Active"
        )
        db.add(case_obj)

        evidence_obj = Evidence(
            evidence_id=test_evidence_id,
            case_id=test_case_id,
            original_filename="memory_dump.raw",
            stored_filename="memory_dump.raw",
            category="Memory",
            type="BINARY",
            extension=".raw",
            file_size=len(raw_evidence_file.read_bytes()),
            storage_path=str(raw_evidence_file),
            status="UPLOADED"
        )
        db.add(evidence_obj)
        db.commit()

        # 3. Construct Handoff Payload
        handoff_input = EvidencePreserveInput(
            evidence_id=test_evidence_id,
            case_id=test_case_id,
            storage_path=str(raw_evidence_file),
            category="Memory",
            status="UPLOADED"
        )

        # 4. Execute Preservation Pipeline
        result = EvidencePreservationService.preserve_evidence_payload(
            db=db,
            payload=handoff_input,
            secret_key="preservation_master_key"
        )

        # 5. Assertions
        assert result.sha256 is not None and len(result.sha256) == 64
        assert result.md5 is not None and len(result.md5) == 32
        assert result.readonly_protected is True
        assert result.encrypted is True

        # Assert EVIDENCE_READY Event Payload
        ready_event = result.evidence_ready_event
        assert ready_event.event == "EVIDENCE_READY"
        assert ready_event.evidence_id == test_evidence_id
        assert ready_event.case_id == test_case_id
        assert ready_event.status == "READY_FOR_PROCESSING"

        # Assert CASE_UPLOAD_COMPLETE Event Payload
        assert result.case_complete_event is not None
        assert result.case_complete_event.event == "CASE_UPLOAD_COMPLETE"
        assert result.case_complete_event.case_id == test_case_id

    db.close()
    print("PRESERVATION PIPELINE TEST PASSED PERFECTLY!")


def test_case_completion_notification():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()

    case_id = f"CASE_COMPLETION_{uuid.uuid4().hex[:8]}"

    # Case registered with expected_evidence_count = 2
    case_obj = Case(
        case_id=case_id,
        case_name="Multi Evidence Case",
        investigator_name="Agent Smith",
        status="Active",
        expected_evidence_count=2
    )
    db.add(case_obj)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        f1 = tmp_path / "part1.raw"
        f2 = tmp_path / "part2.raw"
        f1.write_bytes(b"Part 1 Data")
        f2.write_bytes(b"Part 2 Data")

        ev1 = Evidence(
            evidence_id="EV_PART_1", case_id=case_id, original_filename="part1.raw", stored_filename="part1.raw",
            category="Memory", type="BINARY", extension=".raw", file_size=11, storage_path=str(f1), status="UPLOADED"
        )
        ev2 = Evidence(
            evidence_id="EV_PART_2", case_id=case_id, original_filename="part2.raw", stored_filename="part2.raw",
            category="Memory", type="BINARY", extension=".raw", file_size=11, storage_path=str(f2), status="UPLOADED"
        )
        db.add_all([ev1, ev2])
        db.commit()

        # Preserve Item 1: Should publish EVIDENCE_READY but NOT CASE_UPLOAD_COMPLETE
        res1 = EvidencePreservationService.preserve_evidence_payload(
            db=db,
            payload=EvidencePreserveInput(evidence_id="EV_PART_1", case_id=case_id, storage_path=str(f1), category="Memory")
        )
        assert res1.evidence_ready_event.event == "EVIDENCE_READY"
        assert res1.case_complete_event is None  # Case not complete yet

        # Preserve Item 2: Should publish EVIDENCE_READY AND CASE_UPLOAD_COMPLETE
        res2 = EvidencePreservationService.preserve_evidence_payload(
            db=db,
            payload=EvidencePreserveInput(evidence_id="EV_PART_2", case_id=case_id, storage_path=str(f2), category="Memory")
        )
        assert res2.evidence_ready_event.event == "EVIDENCE_READY"
        assert res2.case_complete_event is not None
        assert res2.case_complete_event.event == "CASE_UPLOAD_COMPLETE"
        assert res2.case_complete_event.case_id == case_id

        # Verify DB case status transitioned to CASE_UPLOAD_COMPLETE
        db.refresh(case_obj)
        assert case_obj.status == "CASE_UPLOAD_COMPLETE"

    db.close()
    print("CASE COMPLETION NOTIFICATION TEST PASSED PERFECTLY!")


def test_async_preservation_endpoint():
    from fastapi.testclient import TestClient
    from sqlalchemy.pool import StaticPool
    from main import app
    from app.db.connection import get_db

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

    from app.api.dependencies import get_current_user
    from app.db.models.user import User
    from app.services.rbac_service import RBACService

    mock_user = User(user_id="U_TEST", username="test_agent", email="test@hmacfr.org", hashed_password="pw", is_active=True, token_version=1)
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = lambda: mock_user
    client = TestClient(app)

    db = TestingSessionLocal()
    case_id = f"CASE_API_{uuid.uuid4().hex[:8]}"
    ev_id = f"EV_API_{uuid.uuid4().hex[:8]}"

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        raw_file = tmp_path / "api_payload.raw"
        raw_file.write_bytes(b"Async Endpoint Payload Data 2026")

        case_obj = Case(case_id=case_id, case_name="API Case Test", investigator_name="Agent Jones")
        ev_obj = Evidence(
            evidence_id=ev_id, case_id=case_id, original_filename="api_payload.raw",
            stored_filename="api_payload.raw", category="Memory", type="BINARY",
            extension=".raw", file_size=len(raw_file.read_bytes()), storage_path=str(raw_file), status="UPLOADED"
        )
        db.add(mock_user)
        db.add_all([case_obj, ev_obj])
        db.commit()
        RBACService.assign_case_creator(db, case_id, "U_TEST")

        # Call POST /api/v1/evidence/preserve
        payload = {
            "evidence_id": ev_id,
            "case_id": case_id,
            "storage_path": str(raw_file),
            "category": "Memory",
            "status": "UPLOADED"
        }
        response = client.post("/api/v1/preservation/preserve", json=payload)
        assert response.status_code == 200
        data = response.json()

        assert "evidence_ready_event" in data
        assert data["evidence_ready_event"]["event"] == "EVIDENCE_READY"
        assert data["evidence_ready_event"]["evidence_id"] == ev_id
        assert data["evidence_ready_event"]["status"] == "READY_FOR_PROCESSING"
        assert len(data["sha256"]) == 64
        assert len(data["md5"]) == 32
        assert data["readonly_protected"] is True
        assert data["encrypted"] is True

        # Test Streaming endpoint
        stream_res = client.get(f"/api/v1/preservation/stream/{ev_id}")
        assert stream_res.status_code == 200
        assert stream_res.content == b"Async Endpoint Payload Data 2026"

    db.close()
    app.dependency_overrides.clear()
    print("ASYNC PRESERVATION ENDPOINT TEST PASSED PERFECTLY!")


def test_batch_preservation_endpoint():
    from fastapi.testclient import TestClient
    from sqlalchemy.pool import StaticPool
    from main import app
    from app.db.connection import get_db

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

    from app.api.dependencies import get_current_user
    from app.db.models.user import User
    from app.services.rbac_service import RBACService

    mock_user = User(user_id="U_BATCH", username="batch_agent", email="batch@hmacfr.org", hashed_password="pw", is_active=True, token_version=1)
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = lambda: mock_user
    client = TestClient(app)

    db = TestingSessionLocal()
    case_id = f"CASE_BATCH_{uuid.uuid4().hex[:8]}"

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        f1 = tmp_path / "b1.raw"
        f2 = tmp_path / "b2.raw"
        f1.write_bytes(b"Batch 1 Data")
        f2.write_bytes(b"Batch 2 Data")

        case_obj = Case(case_id=case_id, case_name="Batch Case Test", investigator_name="Agent Mulder", expected_evidence_count=2)
        ev1 = Evidence(
            evidence_id="EV_B1", case_id=case_id, original_filename="b1.raw", stored_filename="b1.raw",
            category="Memory", type="BINARY", extension=".raw", file_size=12, storage_path=str(f1), status="UPLOADED"
        )
        ev2 = Evidence(
            evidence_id="EV_B2", case_id=case_id, original_filename="b2.raw", stored_filename="b2.raw",
            category="Memory", type="BINARY", extension=".raw", file_size=12, storage_path=str(f2), status="UPLOADED"
        )
        db.add(mock_user)
        db.add_all([case_obj, ev1, ev2])
        db.commit()
        RBACService.assign_case_creator(db, case_id, "U_BATCH")

        # Call POST /api/v1/preservation/preserve-case/{case_id}
        response = client.post(f"/api/v1/preservation/preserve-case/{case_id}")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2

        # The last item should contain CASE_UPLOAD_COMPLETE event
        last_item = data[-1]
        assert last_item["case_complete_event"] is not None
        assert last_item["case_complete_event"]["event"] == "CASE_UPLOAD_COMPLETE"
        assert last_item["case_complete_event"]["case_id"] == case_id

    db.close()
    app.dependency_overrides.clear()
    print("BATCH PRESERVATION ENDPOINT TEST PASSED PERFECTLY!")


if __name__ == "__main__":
    test_preservation_pipeline()
    test_case_completion_notification()
    test_async_preservation_endpoint()
    test_batch_preservation_endpoint()
    print("ALL PRESERVATION TESTS PASSED PERFECTLY!")
