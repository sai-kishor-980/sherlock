"""
Cryptographic Hash Utilities for HMACFR.

Provides helper functions for hash digest validation, formatting, and algorithm matching.
"""

import re
from typing import Optional


HASH_PATTERNS = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
    "sha512": re.compile(r"^[a-fA-F0-9]{128}$"),
}


def is_valid_hex_hash(hash_str: str, algorithm: str = "sha256") -> bool:
    """
    Validates whether a string is a valid hexadecimal representation of a given hash algorithm.
    """
    if not hash_str or not isinstance(hash_str, str):
        return False
    clean_algo = algorithm.lower().strip()
    pattern = HASH_PATTERNS.get(clean_algo)
    if pattern:
        return bool(pattern.match(hash_str.strip()))
    # Generic hex string fallback (even length, hex chars only)
    return bool(re.match(r"^[a-fA-F0-9]+$", hash_str.strip())) and len(hash_str.strip()) % 2 == 0


def normalize_hash(hash_str: str) -> str:
    """
    Strips whitespace and converts hash string to lowercase hex format.
    """
    return hash_str.strip().lower() if hash_str else ""
