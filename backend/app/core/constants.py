"""
HMACFR Application Constants.

Defines global constants for evidence classification, priority levels,
status enumeration, cryptographic defaults, and file permissions.
"""

from typing import Set, Tuple


# Evidence Categories
CATEGORY_MEMORY: str = "Memory"
CATEGORY_DISK: str = "Disk"
CATEGORY_REGISTRY: str = "Registry"
CATEGORY_LOGS: str = "Logs"
CATEGORY_BROWSER: str = "Browser"
CATEGORY_PCAP: str = "PCAP"
CATEGORY_MALWARE: str = "Malware"
CATEGORY_DOCUMENTS: str = "Documents"
CATEGORY_IMAGES: str = "Images"
CATEGORY_GENERAL: str = "General"

ALL_CATEGORIES: Set[str] = {
    CATEGORY_MEMORY,
    CATEGORY_DISK,
    CATEGORY_REGISTRY,
    CATEGORY_LOGS,
    CATEGORY_BROWSER,
    CATEGORY_PCAP,
    CATEGORY_MALWARE,
    CATEGORY_DOCUMENTS,
    CATEGORY_IMAGES,
    CATEGORY_GENERAL,
}

# Priority Levels
PRIORITY_LOW: str = "Low"
PRIORITY_MEDIUM: str = "Medium"
PRIORITY_HIGH: str = "High"
PRIORITY_CRITICAL: str = "Critical"

ALL_PRIORITIES: Set[str] = {
    PRIORITY_LOW,
    PRIORITY_MEDIUM,
    PRIORITY_HIGH,
    PRIORITY_CRITICAL,
}

# Case Statuses
STATUS_ACTIVE: str = "Active"
STATUS_PENDING: str = "Pending"
STATUS_CLOSED: str = "Closed"
STATUS_ARCHIVED: str = "Archived"

# Evidence Statuses
EVIDENCE_STATUS_UPLOADED: str = "Uploaded"
EVIDENCE_STATUS_ENCRYPTED: str = "Encrypted"
EVIDENCE_STATUS_READONLY: str = "ReadOnly"
EVIDENCE_STATUS_QUARANTINED: str = "Quarantined"
EVIDENCE_STATUS_ARCHIVED: str = "Archived"
EVIDENCE_STATUS_VERIFIED: str = "Verified"
EVIDENCE_STATUS_TAMPERED: str = "Tampered"

# Cryptographic Defaults
DEFAULT_HASH_ALGORITHM: str = "SHA256"
SUPPORTED_HASH_ALGORITHMS: Tuple[str, ...] = ("sha256", "sha512", "md5", "sha3_256", "blake2b")
DEFAULT_CHUNK_SIZE: int = 1024 * 1024  # 1 MB

# File Extension Permissions
ALLOWED_EVIDENCE_EXTENSIONS: Set[str] = {
    # Images
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tiff",
    # Audio & Video
    ".mp3", ".wav", ".aac", ".mp4", ".avi", ".mov", ".mkv", ".flv",
    # Documents & Data
    ".pdf", ".doc", ".docx", ".txt", ".csv", ".json", ".xml", ".log",
    # Archives & Forensic Dumps
    ".zip", ".tar", ".gz", ".7z", ".rar", ".dd", ".raw", ".bin", ".img", ".evtx", ".pcap"
}
