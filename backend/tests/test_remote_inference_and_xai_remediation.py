import math
import os
import json
import uuid
import pytest
from unittest.mock import patch, MagicMock
from collections import Counter

from app.services.model_adapter_service import ModelAdapterService
from app.services.synthesizer_service import ForensicSynthesizerService


def test_model_adapter_token_configuration(monkeypatch):
    """
    Verifies that SHERLOCK_REMOTE_TOKEN can be configured and retrieved cleanly.
    """
    monkeypatch.setenv("SHERLOCK_REMOTE_TOKEN", "test-secret-token-xyz")
    token = ModelAdapterService.get_remote_token()
    assert token == "test-secret-token-xyz"

    ModelAdapterService.set_remote_token("custom-token-override")
    assert ModelAdapterService.get_remote_token() == "custom-token-override"


def test_safe_negative_assertion_parsing_not_malicious():
    """
    Verifies that natural language containing negative statements like
    'no malicious activity detected' is NEVER classified as MALICIOUS.
    """
    negative_text = "Thorough analysis of memory dump completed. There was no malicious activity detected across the system."
    result = ModelAdapterService.normalize_agent_output(negative_text, domain="memory", evidence_type="RAM Dump")

    assert result["classification"] == "BENIGN"
    assert result["risk_level"] == "LOW"
    assert result["contract_validated"] is True
    assert "no malicious" in result["reasoning"].lower()


def test_ambiguous_output_safely_falls_back_to_inconclusive():
    """
    Verifies that ambiguous model outputs without clear polarity or JSON schema
    fall back safely to INCONCLUSIVE rather than guessing MALICIOUS via substring matching.
    """
    ambiguous_text = "Inspected raw registry keys. Several entries point to software components without standard digital signatures."
    result = ModelAdapterService.normalize_agent_output(ambiguous_text, domain="registry", evidence_type="Registry Hive")

    assert result["classification"] == "INCONCLUSIVE"
    assert result["risk_level"] == "INFORMATIONAL"
    assert result["contract_validated"] is True
    assert result["schema_conforming"] is False


def test_clean_markdown_json_stripping_and_schema_validation():
    """
    Verifies that markdown-wrapped JSON code blocks (```json ... ```)
    are stripped and parsed accurately against the expected schema.
    """
    markdown_wrapped_json = (
        "Here is my forensic evaluation:\n"
        "```json\n"
        "{\n"
        '  "assessment": "SUSPICIOUS",\n'
        '  "risk_level": "HIGH",\n'
        '  "confidence": 0.88,\n'
        '  "observation": "Detected suspicious beaconing to external IP",\n'
        '  "reasoning": "Uncommon user agent generating recurring HTTP POST requests at fixed 30s intervals.",\n'
        '  "key_evidence": ["POST /beacon.php", "User-Agent: Mozilla/4.0 (compatible)"]\n'
        "}\n"
        "```"
    )
    result = ModelAdapterService.normalize_agent_output(markdown_wrapped_json, domain="network", evidence_type="PCAP")

    assert result["classification"] == "SUSPICIOUS"
    assert result["risk_level"] == "HIGH"
    assert result["confidence"] == 0.88
    assert "beaconing" in result["observation"].lower()
    assert len(result["key_evidence"]) == 2


def test_observation_accounting_bounded_batching():
    """
    Verifies that large observation lists are bounded into batches with
    accurate total, analyzed, and skipped observation accounting.
    """
    mock_events = [{"id": i, "desc": f"event {i}"} for i in range(125)]
    res = ModelAdapterService.analyze_domain_evidence(
        domain="logs",
        evidence_type="Event Log Stream",
        evidence_content=mock_events
    )

    accounting = res.get("observation_accounting", {})
    assert accounting["total_observations"] == 125
    assert accounting["analyzed_observations"] == 100  # 5 batches of 20 = 100 max
    assert accounting["skipped_observations"] == 25
    assert accounting["accounting_status"] == "PARTIAL"


def test_shannon_entropy_calculation_accuracy():
    """
    Verifies that Shannon Entropy is computed mathematically and accurately
    without synthesizing fake byte streams.
    """
    # Known test buffer: all zeros should have 0.0 entropy
    zero_bytes = b"\x00" * 256
    counts = Counter(zero_bytes)
    n = len(zero_bytes)
    entropy_zero = -sum((c / n) * math.log2(c / n) for c in counts.values())
    assert entropy_zero == 0.0

    # Known test buffer: 256 distinct bytes should have exactly 8.0 entropy
    uniform_bytes = bytes(range(256))
    counts = Counter(uniform_bytes)
    n = len(uniform_bytes)
    entropy_uniform = -sum((c / n) * math.log2(c / n) for c in counts.values())
    assert pytest.approx(entropy_uniform, 0.001) == 8.0



from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from main import app
from app.db.connection import Base, get_db
from app.db.models.user import User
from app.db.models.case import Case
from app.db.models.evidence import Evidence
from app.db.models.case_assignment import CaseMember, CaseMemberResponsibility
from app.core.security import get_password_hash, create_access_token


@pytest.fixture
def api_test_env():
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
    admin_user = User(
        user_id="U_LEAD_TEST",
        username="lead_investigator",
        email="lead@sherlock.ai",
        hashed_password=pw_hash,
        role="Investigator",
        token_version=1,
        is_active=True
    )
    db.add(admin_user)
    db.commit()
    db.refresh(admin_user)

    token = create_access_token({
        "sub": admin_user.username,
        "user_id": admin_user.user_id,
        "id": admin_user.user_id,
        "role": "Investigator",
        "ver": 1
    })
    headers = {"Authorization": f"Bearer {token}"}

    yield client, db, headers, admin_user

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


def test_hex_viewer_blocks_fake_bytes_and_returns_404_for_missing_clue(api_test_env):
    """
    Verifies that the Hex Viewer returns HTTP 404 for non-existent clues
    rather than synthesizing fake MZ headers or repeated dummy bytes.
    """
    client, db, headers, user = api_test_env
    case_id = f"CASE_HEX_{uuid.uuid4().hex[:6]}"
    case = Case(
        case_id=case_id,
        case_name="Hex Viewer Audit Case",
        status="Active",
        investigator_name=user.username
    )
    db.add(case)
    db.commit()

    mbr = CaseMember(id=f"MBR_{case_id}", case_id=case_id, user_id=user.user_id, assigned_by=user.user_id)
    db.add(mbr)
    db.commit()
    resp_obj = CaseMemberResponsibility(case_member_id=f"MBR_{case_id}", responsibility_name="Lead Investigator")
    db.add(resp_obj)
    db.commit()

    resp = client.get(
        f"/api/v1/cases/{case_id}/clues/NON_EXISTENT_CLUE_99999/hex?offset=0&length=128",
        headers=headers
    )
    assert resp.status_code == 404
    assert "Artifact bytes unavailable" in resp.json()["detail"]


def test_chatbot_rag_returns_extractive_records_when_gpu_offline(api_test_env):
    """
    Verifies that when the remote GPU is offline, the chatbot returns genuine
    extractive records with citations rather than canned substring responses.
    """
    client, db, headers, user = api_test_env
    case_id = f"CASE_CHAT_{uuid.uuid4().hex[:6]}"
    case = Case(
        case_id=case_id,
        case_name="Chatbot RAG Case",
        status="Active",
        investigator_name=user.username
    )
    db.add(case)
    db.commit()

    mbr = CaseMember(id=f"MBR_{case_id}", case_id=case_id, user_id=user.user_id, assigned_by=user.user_id)
    db.add(mbr)
    db.commit()
    resp_obj = CaseMemberResponsibility(case_member_id=f"MBR_{case_id}", responsibility_name="Lead Investigator")
    db.add(resp_obj)
    db.commit()

    # Ingest a piece of evidence so it is not an empty case
    ev = Evidence(
        evidence_id="EV-PCAP-001",
        case_id=case_id,
        original_filename="capture_traffic.pcap",
        stored_filename="capture_traffic.pcap",
        extension=".pcap",
        file_size=1024,
        storage_path="mock/capture_traffic.pcap",
        file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        status="VALIDATED",
        category="Network PCAP"
    )
    db.add(ev)
    db.commit()

    # Ensure remote GPU is marked offline
    ModelAdapterService.set_remote_gpu_url(None)

    # Set up the five-domain barrier and synthesize (will be BLOCKED_GPU_UNAVAILABLE
    # but writes sis_state.json so retrieval endpoints can read it).
    from app.services.agent_barrier_service import AgentBarrierService, REQUIRED_DOMAINS
    barrier_findings = []
    for domain in REQUIRED_DOMAINS:
        barrier_findings.append({
            "case_id": case_id,
            "domain": domain,
            "finding_id": f"F-{domain.upper()}-001",
            "classification": "BENIGN",
            "confidence": 0.80,
        })
    AgentBarrierService.evaluate_five_agent_barrier(case_id, barrier_findings)
    ForensicSynthesizerService.synthesize_case(case_id)

    resp = client.post(
        f"/api/v1/analysis/{case_id}/chat",
        headers=headers,
        json={"query": "Tell me about unauthorized external network connections"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "SUCCESS"
    assert "EXTRACTIVE FORENSIC CONTEXT — REMOTE GPU OFFLINE" in data["answer"]
    assert "LOCAL_EVIDENCE_GROUNDED_RAG" in data["execution_mode"]
    assert len(data["citations"]) > 0
    assert data["citations"][0]["file"] == "capture_traffic.pcap"
