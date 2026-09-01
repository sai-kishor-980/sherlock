"""
Forensic Metadata Utilities for HMACFR.

Provides metadata extraction functions for file size, extension, timestamps, and header inspection.
"""

from pathlib import Path
from typing import Dict, Any, Union
from datetime import datetime, timezone


def extract_file_metadata(filepath: Union[str, Path]) -> Dict[str, Any]:
    """
    Extracts structural filesystem metadata for an evidence file.

    :param filepath: Path to evidence file on disk.
    :return: Dictionary containing filename, size, timestamps, and extension.
    """
    path = Path(filepath) if isinstance(filepath, str) else filepath
    if not path.is_file():
        raise FileNotFoundError(f"File not found for metadata extraction: {path}")

    stat_info = path.stat()
    return {
        "filename": path.name,
        "extension": path.suffix.lower(),
        "file_size": stat_info.st_size,
        "created_at": datetime.fromtimestamp(stat_info.st_ctime, tz=timezone.utc).isoformat(),
        "modified_at": datetime.fromtimestamp(stat_info.st_mtime, tz=timezone.utc).isoformat(),
        "accessed_at": datetime.fromtimestamp(stat_info.st_atime, tz=timezone.utc).isoformat(),
    }
