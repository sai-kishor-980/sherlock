"""
Centralized Logging Infrastructure for HMACFR using RotatingFileHandler.

Configures 4 centralized rotating log files:
- application.log: General backend operations.
- audit.log: Evidence preservation actions and chain of custody audit trails.
- events.log: Published event notifications (EVIDENCE_READY, CASE_UPLOAD_COMPLETE).
- error.log: Exceptions and error traces.
"""

import os
import logging
from logging.handlers import RotatingFileHandler
from app.core.config import settings

# Ensure logs directory exists
os.makedirs(settings.LOGS_DIR, exist_ok=True)


def _create_rotating_logger(name: str, filename: str, level: int = logging.INFO) -> logging.Logger:
    """Helper to configure rotating file logger with 5 MB max file size and 5 backup files."""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    if not logger.handlers:
        log_path = os.path.join(settings.LOGS_DIR, filename)
        handler = RotatingFileHandler(
            log_path, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger


# Centralized Loggers
app_logger = _create_rotating_logger("app_logger", "application.log")
audit_logger = _create_rotating_logger("audit_logger", "audit.log")
events_logger = _create_rotating_logger("events_logger", "events.log")
error_logger = _create_rotating_logger("error_logger", "error.log", level=logging.ERROR)


def log_app_event(message: str) -> None:
    """Log general backend operation to logs/application.log."""
    app_logger.info(message)


def log_audit_event(evidence_id: str, action: str, details: str = "") -> None:
    """Log evidence preservation action / custody audit to logs/audit.log."""
    msg = f"EvidenceID: {evidence_id} | Action: {action}"
    if details:
        msg += f" | Details: {details}"
    audit_logger.info(msg)


def log_published_event(event_type: str, case_id: str, details: str = "") -> None:
    """Log published event notification to logs/events.log."""
    msg = f"EventType: {event_type} | CaseID: {case_id}"
    if details:
        msg += f" | Details: {details}"
    events_logger.info(msg)


def log_error_event(error_msg: str, exc_info: bool = False) -> None:
    """Log error exception details to logs/error.log."""
    error_logger.error(error_msg, exc_info=exc_info)


# Specialized Helper Wrappers for Backward Compatibility
def log_upload_event(case_id: str, filename: str, status: str = "Uploaded") -> None:
    """Log upload event to logs/application.log."""
    log_app_event(f"Case: {case_id} | Filename: {filename} | Status: {status}")


def log_hashing_event(evidence_id: str, algorithm: str, hash_value: str) -> None:
    """Log hashing action to logs/audit.log."""
    log_audit_event(evidence_id, f"Hashing ({algorithm})", f"Hash: {hash_value}")


def log_encryption_event(evidence_id: str, action: str, status: str) -> None:
    """Log encryption action to logs/audit.log."""
    log_audit_event(evidence_id, f"Encryption ({action})", f"Status: {status}")


def log_verification_event(evidence_id: str, is_valid: bool, status: str) -> None:
    """Log verification audit to logs/audit.log."""
    log_audit_event(evidence_id, "Verification Audit", f"Valid: {is_valid} | Status: {status}")


def log_custody_event(evidence_id: str, action: str, performed_by: str) -> None:
    """Log custody / event action to logs/events.log or logs/audit.log."""
    if "Published" in action or "Event" in action:
        log_published_event(action, evidence_id, f"PerformedBy: {performed_by}")
    else:
        log_audit_event(evidence_id, action, f"PerformedBy: {performed_by}")
