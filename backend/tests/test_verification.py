"""
Unit Tests for AdvancedVerificationService.
"""

from app.services.hashing_service import AdvancedHashingService


def test_integrity_hash_matching():
    content = b"Forensic Chain of Custody Sample Data"
    digest = AdvancedHashingService.calculate_bytes_hash(content, "sha256")
    hmac_sig = AdvancedHashingService.calculate_hmac(content)

    assert AdvancedHashingService.verify_hmac(content, hmac_sig)


def test_integrity_verification_service():
    import tempfile
    from pathlib import Path
    from app.services.integrity_service import IntegrityVerificationService, IntegrityVerificationError

    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "integrity_test.raw"
        content = b"Integrity Verification Test Payload 2026"
        test_file.write_bytes(content)

        original_hash = AdvancedHashingService.calculate_bytes_hash(content, "sha256")

        # 1. Matching Hash -> verified = True
        assert IntegrityVerificationService.verify_file_sha256(test_file, original_hash) is True

        # 2. Tampered / Mismatched Hash -> Move to Quarantine & Raise Exception
        bad_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        try:
            IntegrityVerificationService.verify_file_sha256(test_file, bad_hash)
            assert False, "Should have raised IntegrityVerificationError!"
        except IntegrityVerificationError as exc:
            assert "quarantine" in str(exc.quarantine_path).lower()


if __name__ == "__main__":
    test_integrity_hash_matching()
    test_integrity_verification_service()
    print("ALL VERIFICATION TESTS PASSED PERFECTLY!")

