"""
File Permission & Read-Only Utilities for HMACFR.

Enforces digital forensic write-protection on evidence files across Windows and POSIX operating systems.
"""

import os
import stat
from pathlib import Path
from typing import Union
from app.core.logger import log_error_event


def set_readonly_flag(filepath: Union[str, Path]) -> bool:
    """
    Sets the read-only attribute on a file across POSIX and Windows operating systems.
    Enforces forensic immutability to prevent file modification after preservation.

    :param filepath: Path to target file.
    :return: True if read-only flag was successfully set, False otherwise.
    """
    path = Path(filepath) if isinstance(filepath, str) else filepath
    if not path.is_file():
        log_error_event(f"Cannot set read-only flag: File '{path}' does not exist.")
        return False
    try:
        current_mode = path.stat().st_mode
        # POSIX: Revoke write permissions for owner, group, and others; enforce S_IREAD
        readonly_mode = (current_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)) | stat.S_IREAD
        path.chmod(readonly_mode)

        # Windows explicit read-only attribute setting
        if os.name == "nt":
            os.chmod(str(path), stat.S_IREAD)
        return True
    except Exception as exc:
        log_error_event(f"Failed to set read-only flag on '{path}': {str(exc)}", exc_info=True)
        return False


def is_readonly_flag_set(filepath: Union[str, Path]) -> bool:
    """
    Checks if a file has write access revoked (is read-only).

    :param filepath: Path to target file.
    :return: True if file is write-protected, False if writable or missing.
    """
    path = Path(filepath) if isinstance(filepath, str) else filepath
    if not path.is_file():
        return False
    mode = path.stat().st_mode
    # Check if user write bit (S_IWUSR) is cleared
    return not bool(mode & stat.S_IWUSR)


def remove_readonly_flag(filepath: Union[str, Path]) -> bool:
    """
    Restores write permission to a file for authorized administrative file operations.

    :param filepath: Path to target file.
    :return: True if write permissions were restored, False otherwise.
    """
    path = Path(filepath) if isinstance(filepath, str) else filepath
    if not path.is_file():
        return False
    try:
        current_mode = path.stat().st_mode
        writable_mode = current_mode | stat.S_IWUSR
        path.chmod(writable_mode)
        return True
    except Exception as exc:
        log_error_event(f"Failed to remove read-only flag on '{path}': {str(exc)}", exc_info=True)
        return False
