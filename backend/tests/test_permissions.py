"""
Unit Tests for ReadOnlyProtectionService and Permission Utilities.
"""

from pathlib import Path
from app.services.readonly_service import ReadOnlyProtectionService


def test_readonly_protection(tmp_path: Path):
    test_file = tmp_path / "protected_evidence.raw"
    test_file.write_bytes(b"Read only permission test")

    # 1. Apply read-only
    assert ReadOnlyProtectionService.apply_readonly_protection(test_file)
    assert ReadOnlyProtectionService.check_readonly_status(test_file)

    # 2. Revoke read-only
    assert ReadOnlyProtectionService.revoke_readonly_protection(test_file)
    assert not ReadOnlyProtectionService.check_readonly_status(test_file)


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        test_readonly_protection(Path(tmpdir))
        print("ALL PERMISSION TESTS PASSED PERFECTLY!")
