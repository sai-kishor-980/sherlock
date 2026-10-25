"""
Validation Utility Functions for HMACFR Digital Forensics Platform.
Supports standard forensic image formats (.E01, .001, .DD, .RAW), memory dumps (.DMP, .VMEM),
system hives (SYSTEM, SAM, SECURITY, SOFTWARE), network captures, and media.
"""

import os
from typing import Set, Optional
from fastapi import UploadFile, HTTPException, status
from app.core.logger import log_error_event

BLOCKED_EXTENSIONS: Set[str] = {
    ".exe", ".bat", ".vbs", ".ps1", ".scr", ".cmd", ".msi", ".jar"
}

ALLOWED_EXTENSIONS: Set[str] = {
    # Forensic Disk Images & Raw Segments
    ".e01", ".e02", ".e03", ".e04", ".s01", ".l01", ".ad1", ".aff", ".aff4", ".ufdr",
    ".dd", ".raw", ".bin", ".img", ".001", ".002", ".003", ".004", ".005",
    # Memory & Virtual Machine Images
    ".dmp", ".mem", ".vmem", ".crash", ".vmdk", ".vhd", ".vhdx", ".vdi", ".qcow2",
    # System Artifacts, Registry & Network Traffic
    ".evtx", ".pcap", ".pcapng", ".dat", ".hive", ".db", ".sqlite", ".sqlite3", ".log", ".pf", ".lnk",
    # Images & Media
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tiff",
    ".mp3", ".wav", ".aac", ".mp4", ".avi", ".mov", ".mkv", ".flv",
    # Documents & Data Archives
    ".pdf", ".doc", ".docx", ".txt", ".csv", ".json", ".xml",
    ".zip", ".tar", ".gz", ".7z", ".rar"
}

def is_allowed_extension(filename: str) -> bool:
    """
    Validates if a filename extension is permitted for forensic ingestion.
    Supports forensic image formats (.e01, .001, .dd, .raw, etc.), numeric split segments,
    and extensionless forensic hives (SYSTEM, SAM, SECURITY, SOFTWARE, HIBERFIL).
    """
    if not filename:
        return False

    _, ext = os.path.splitext(filename)
    clean_ext = ext.lower().strip()

    if clean_ext in BLOCKED_EXTENSIONS:
        return False

    # Extensionless files (e.g. SYSTEM, SAM, SECURITY, SOFTWARE, HIBERFIL) are valid forensic artifacts
    if not clean_ext:
        return True

    # Numeric split segment files (e.g., .001, .002, .003, .004, .005)
    if clean_ext.startswith(".") and clean_ext[1:].isdigit():
        return True

    return clean_ext in ALLOWED_EXTENSIONS

def validate_upload_payload(
    file: Optional[UploadFile],
    case_id: Optional[str],
    investigator: Optional[str],
    content_bytes: Optional[bytes]
) -> None:
    """
    Validates mandatory upload payload requirements before storage.
    Raises HTTPException and logs error to logs/error.log if invalid.
    """
    # 1. Validate File existence
    if not file:
        err_msg = "Upload validation failed: File parameter is missing"
        log_error_event(err_msg)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File parameter is missing"
        )

    if not file.filename or not file.filename.strip():
        err_msg = "Upload validation failed: Original filename is missing or empty"
        log_error_event(err_msg)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Original filename is missing or empty"
        )

    # 2. Validate Allowed extension / forensic format
    if not is_allowed_extension(file.filename):
        _, ext = os.path.splitext(file.filename)
        err_msg = f"Upload validation failed for '{file.filename}': File extension '{ext}' is not permitted"
        log_error_event(err_msg)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File format '{ext or file.filename}' is not permitted. Supported forensic formats include .E01, .001, .RAW, .DD, .DMP, .VMDK, SYSTEM, SAM, etc."
        )

    # 3. Validate Required Fields
    if not case_id or not case_id.strip():
        err_msg = f"Upload validation failed for '{file.filename}': Required field 'case_id' is missing"
        log_error_event(err_msg)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Required field 'case_id' is missing"
        )

    if not investigator or not investigator.strip():
        err_msg = f"Upload validation failed for '{file.filename}': Required field 'investigator' is missing"
        log_error_event(err_msg)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Required field 'investigator' is missing"
        )

    # 4. Validate File Size > 0
    if content_bytes is None or len(content_bytes) == 0:
        err_msg = f"Upload validation failed for '{file.filename}': Uploaded file is empty (0 bytes)"
        log_error_event(err_msg)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty (0 bytes)"
        )
