"""
Unit Tests for AdvancedHashingService.
"""

from pathlib import Path
from app.services.hashing_service import AdvancedHashingService


def test_hashing_service(tmp_path: Path):
    sample_data = b"HMACFR Forensic Test Payload 2026"
    test_file = tmp_path / "test_evidence.raw"
    test_file.write_bytes(sample_data)

    # 1. Test Single Hash
    sha256_digest = AdvancedHashingService.calculate_file_hash(test_file, "sha256")
    assert len(sha256_digest) == 64

    # 2. Test Multi-Hash
    multi_digests = AdvancedHashingService.calculate_multi_hashes(test_file, {"sha256", "sha512", "md5"})
    assert "sha256" in multi_digests
    assert "sha512" in multi_digests
    assert "md5" in multi_digests

    # 3. Test Constant Time Verification
    assert AdvancedHashingService.verify_file_hash(test_file, sha256_digest, "sha256")

    # 4. Test HMAC Calculation & Verification
    hmac_sig = AdvancedHashingService.calculate_hmac(sample_data, secret_key="test_key")
    assert AdvancedHashingService.verify_hmac(sample_data, hmac_sig, secret_key="test_key")


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        test_hashing_service(Path(tmpdir))
        print("ALL HASHING TESTS PASSED PERFECTLY!")
