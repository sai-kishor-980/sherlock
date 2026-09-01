"""
Unit Tests for EvidenceEncryptionService.
"""

from pathlib import Path
from app.services.encryption_service import EvidenceEncryptionService


def test_encryption_service(tmp_path: Path):
    plain_content = b"HMACFR Top Secret Forensic Dump Payload"
    src_file = tmp_path / "plain_evidence.raw"
    enc_file = tmp_path / "enc_evidence.enc"
    dec_file = tmp_path / "dec_evidence.raw"

    src_file.write_bytes(plain_content)

    # 1. Test File Encryption
    assert EvidenceEncryptionService.encrypt_file(src_file, enc_file, secret_key="test_secret_key")
    assert enc_file.exists()
    assert enc_file.read_bytes() != plain_content

    # 2. Test File Decryption
    assert EvidenceEncryptionService.decrypt_file(enc_file, dec_file, secret_key="test_secret_key")
    assert dec_file.exists()
    assert dec_file.read_bytes() == plain_content

    # 3. Test Vault Encryption with Preserved Filename inside evidence_vault/encrypted/
    vault_path = EvidenceEncryptionService.encrypt_evidence_to_vault(
        source_path=src_file,
        case_id="CASE_TEST_ENC",
        original_filename="plain_evidence.raw"
    )
    assert vault_path.exists()
    assert vault_path.name == "plain_evidence.raw"
    assert "encrypted" in str(vault_path)


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        test_encryption_service(Path(tmpdir))
        print("ALL ENCRYPTION TESTS PASSED PERFECTLY!")

