"""
Domain Exception Hierarchy for HMACFR.
Provides structured application and domain exceptions.
"""

class HMACFRError(Exception):
    """Base exception class for HMACFR framework."""
    def __init__(self, message: str, details: str = None):
        super().__init__(message)
        self.message = message
        self.details = details


class CaseNotFoundError(HMACFRError):
    """Raised when a case entity is not found."""
    pass


class EvidenceNotFoundError(HMACFRError):
    """Raised when an evidence entity or file artifact is not found."""
    pass


class IntegrityCheckError(HMACFRError):
    """Raised when evidence fails post-preservation integrity verification."""
    pass


class StorageVaultError(HMACFRError):
    """Raised when evidence vault operation or path safety check fails."""
    pass


class EncryptionError(HMACFRError):
    """Raised when payload encryption or key derivation fails."""
    pass
