"""
Unit Tests for StorageService and EvidenceVaultService.
"""

import uuid
from pathlib import Path
from app.services.storage_service import StorageService
from app.services.vault_service import EvidenceVaultService


def test_storage_service(tmp_path: Path):
    unique_case = f"test_case_{uuid.uuid4().hex[:8]}"
    stored_name, path = StorageService.store_evidence_file(unique_case, "Memory", "sample_test.raw", b"test bytes")
    assert Path(path).exists()
    assert stored_name == "sample_test.raw"


def test_vault_helper_services(tmp_path: Path):
    unique_case = f"test_vault_{uuid.uuid4().hex[:8]}"
    sample_file = tmp_path / "vault_sample.raw"
    sample_file.write_bytes(b"Evidence Vault Helper Test Payload")

    # 1. Save evidence
    saved_path = EvidenceVaultService.save_evidence(
        source_path=sample_file,
        case_id=unique_case,
        filename="vault_sample.raw",
        vault_type="readonly"
    )
    assert saved_path.exists()
    assert "readonly" in str(saved_path)

    # 2. Retrieve evidence
    retrieved_path = EvidenceVaultService.retrieve_evidence(
        case_id=unique_case,
        filename="vault_sample.raw",
        vault_type="readonly"
    )
    assert retrieved_path.exists()
    assert retrieved_path == saved_path

    # 3. Archive evidence
    archived_path = EvidenceVaultService.archive_evidence(
        case_id=unique_case,
        filename="vault_sample.raw",
        current_vault_type="readonly"
    )
    assert archived_path.exists()
    assert "archive" in str(archived_path)


if __name__ == "__main__":
    test_storage_service(Path("."))
    test_vault_helper_services(Path("."))
    print("ALL STORAGE TESTS PASSED PERFECTLY!")

