"""
Unit Tests for Evidence Upload Service & Forensic File Extension Validation.
"""

from app.utils.validation_utils import is_allowed_extension


def test_allowed_extensions():
    # Standard Forensic Formats
    assert is_allowed_extension("memory.raw")
    assert is_allowed_extension("traffic.pcap")
    assert is_allowed_extension("events.evtx")

    # Forensic Disk Images & Split Segments
    assert is_allowed_extension("evidence_dump.E01")
    assert is_allowed_extension("disk_image.001")
    assert is_allowed_extension("disk_image.002")
    assert is_allowed_extension("encase_stream.s01")

    # Extensionless Forensic Hives & Dumps
    assert is_allowed_extension("SYSTEM")
    assert is_allowed_extension("SAM")
    assert is_allowed_extension("SECURITY")
    assert is_allowed_extension("SOFTWARE")
    assert is_allowed_extension("HIBERFIL")

    # VM & Memory Dumps
    assert is_allowed_extension("memory.dmp")
    assert is_allowed_extension("ram.vmem")
    assert is_allowed_extension("disk.vmdk")

    # Executable Blocklist Verification
    assert not is_allowed_extension("malicious.exe")
    assert not is_allowed_extension("script.vbs")
    assert not is_allowed_extension("payload.bat")


if __name__ == "__main__":
    test_allowed_extensions()
    print("ALL UPLOAD & FORENSIC FORMAT TESTS PASSED PERFECTLY!")
