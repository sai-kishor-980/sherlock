"""
Cryptographic Key Management Utilities for HMACFR.

Provides symmetric key derivation (PBKDF2HMAC), random nonce/salt generation,
and secure key encoding functions.
"""

import os
import secrets
from typing import Tuple
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from app.core.config import settings


def generate_secure_key(length: int = 32) -> bytes:
    """
    Generates a cryptographically strong random key of specified byte length (default 32 bytes for AES-256).
    """
    return secrets.token_bytes(length)


def generate_random_salt(length: int = 16) -> bytes:
    """
    Generates a random salt buffer for key derivation.
    """
    return os.urandom(length)


def derive_key_from_password(
    password: str, salt: bytes, iterations: int = 100_000, key_length: int = 32
) -> bytes:
    """
    Derives a 256-bit symmetric encryption key from a master secret/password using PBKDF2-HMAC-SHA256.

    :param password: Input password string or master secret.
    :param salt: Random 16-byte salt buffer.
    :param iterations: Number of PBKDF2 iterations (default 100,000).
    :param key_length: Derived key length in bytes (default 32 for AES-256).
    :return: Derived raw key bytes.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))
