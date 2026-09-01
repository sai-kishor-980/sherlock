"""
Advanced Cryptographic Hashing Service for HMACFR Layer 1 Evidence Preservation.

Provides multi-algorithm streaming hash computation, HMAC verification,
and integrity validation for forensic evidence files.
"""

import hashlib
import hmac
from pathlib import Path
from typing import Dict, Union, Set, Optional, Any
from app.core.config import settings
from app.core.logger import log_error_event


class AdvancedHashingService:
    """
    Service responsible for multi-algorithm cryptographic hashing and HMAC signature validation
    over forensic evidence files and memory buffers.
    """

    SUPPORTED_ALGORITHMS: Set[str] = {
        "sha256", "sha512", "md5", "sha3_256", "blake2b"
    }

    CHUNK_SIZE: int = 1024 * 1024  # 1 MB chunk size for high performance streaming I/O

    @classmethod
    def get_hash_object(cls, algorithm: str) -> Any:
        """
        Instantiates and returns a hashlib hash object for the specified algorithm name.

        :param algorithm: Name of the hashing algorithm (e.g., 'sha256', 'sha512').
        :return: Initialized hashlib hash object.
        :raises ValueError: If the specified algorithm is not supported.
        """
        algo_clean = algorithm.lower().strip()
        if algo_clean not in cls.SUPPORTED_ALGORITHMS:
            err_msg = f"Unsupported hash algorithm '{algorithm}'. Supported: {sorted(cls.SUPPORTED_ALGORITHMS)}"
            log_error_event(err_msg)
            raise ValueError(err_msg)
        return getattr(hashlib, algo_clean)()

    @classmethod
    def calculate_bytes_hash(cls, content: bytes, algorithm: str = "sha256") -> str:
        """
        Calculates cryptographic hash digest for binary memory content.

        :param content: Raw bytes buffer to hash.
        :param algorithm: Algorithm to use for hashing (default 'sha256').
        :return: Hexadecimal hash digest string.
        """
        hasher = cls.get_hash_object(algorithm)
        hasher.update(content)
        return hasher.hexdigest()

    @classmethod
    def calculate_file_hash(cls, filepath: Union[str, Path], algorithm: str = "sha256") -> str:
        """
        Calculates cryptographic hash digest for a file on disk using chunked streaming I/O.

        :param filepath: Path to target file (Path object or string).
        :param algorithm: Algorithm to use for hashing (default 'sha256').
        :return: Hexadecimal hash digest string.
        :raises FileNotFoundError: If file does not exist.
        :raises IOError: If reading the file fails.
        """
        path = Path(filepath) if isinstance(filepath, str) else filepath
        if not path.is_file():
            err_msg = f"File not found for hash calculation: {path}"
            log_error_event(err_msg)
            raise FileNotFoundError(err_msg)

        hasher = cls.get_hash_object(algorithm)
        try:
            with path.open("rb") as f:
                while chunk := f.read(cls.CHUNK_SIZE):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as exc:
            err_msg = f"Failed to compute {algorithm} hash for file '{path}': {str(exc)}"
            log_error_event(err_msg, exc_info=True)
            raise IOError(err_msg) from exc

    @classmethod
    def calculate_multi_hashes(
        cls, filepath: Union[str, Path], algorithms: Optional[Set[str]] = None
    ) -> Dict[str, str]:
        """
        Computes multiple hash digests simultaneously in a single streaming pass over the file on disk.

        :param filepath: Path to target file.
        :param algorithms: Set of algorithm names to compute (default SHA-256, SHA-512, MD5).
        :return: Dictionary mapping algorithm names to their computed hex digests.
        """
        path = Path(filepath) if isinstance(filepath, str) else filepath
        if not path.is_file():
            err_msg = f"File not found for multi-hash calculation: {path}"
            log_error_event(err_msg)
            raise FileNotFoundError(err_msg)

        target_algos = algorithms or {"sha256", "sha512", "md5"}
        hashers = {algo: cls.get_hash_object(algo) for algo in target_algos}

        try:
            with path.open("rb") as f:
                while chunk := f.read(cls.CHUNK_SIZE):
                    for hasher in hashers.values():
                        hasher.update(chunk)
            return {algo: hasher.hexdigest() for algo, hasher in hashers.items()}
        except Exception as exc:
            err_msg = f"Failed to compute multi-hashes for file '{path}': {str(exc)}"
            log_error_event(err_msg, exc_info=True)
            raise IOError(err_msg) from exc

    @classmethod
    def verify_file_hash(
        cls, filepath: Union[str, Path], expected_hash: str, algorithm: str = "sha256"
    ) -> bool:
        """
        Verifies whether a file matches an expected hash digest using constant-time comparison.

        :param filepath: Path to file on disk.
        :param expected_hash: Expected hash digest string.
        :param algorithm: Hashing algorithm used (default 'sha256').
        :return: True if current file hash matches expected_hash, False otherwise.
        """
        current_hash = cls.calculate_file_hash(filepath, algorithm)
        return hmac.compare_digest(current_hash.lower(), expected_hash.lower())

    @classmethod
    def calculate_hmac(
        cls, content: bytes, secret_key: Optional[str] = None, algorithm: str = "sha256"
    ) -> str:
        """
        Generates an HMAC signature for data bytes using specified key and hash algorithm.

        :param content: Raw data bytes.
        :param secret_key: Optional secret key; defaults to settings.SECRET_KEY.
        :param algorithm: Underlying hash algorithm (default 'sha256').
        :return: Hexadecimal HMAC signature.
        """
        key = (secret_key or settings.SECRET_KEY).encode("utf-8")
        digestmod = getattr(hashlib, algorithm.lower().strip())
        return hmac.new(key, content, digestmod).hexdigest()

    @classmethod
    def verify_hmac(
        cls, content: bytes, expected_hmac: str, secret_key: Optional[str] = None, algorithm: str = "sha256"
    ) -> bool:
        """
        Verifies HMAC signature against calculated HMAC for given content in constant time.

        :param content: Raw data bytes.
        :param expected_hmac: Expected HMAC signature string.
        :param secret_key: Optional secret key; defaults to settings.SECRET_KEY.
        :param algorithm: Underlying hash algorithm (default 'sha256').
        :return: True if signature matches, False otherwise.
        """
        calculated = cls.calculate_hmac(content, secret_key, algorithm)
        return hmac.compare_digest(calculated.lower(), expected_hmac.lower())

    @classmethod
    def compute_evidence_hashes(cls, storage_path: Union[str, Path]) -> Dict[str, str]:
        """
        Computes SHA-256 and MD5 hashes for an evidence file using streaming chunked file reads.
        Avoids loading entire files into memory and verifies file can be rehashed later.

        :param storage_path: File path received from Person A.
        :return: Dictionary containing {"sha256": "...", "md5": "..."}.
        :raises FileNotFoundError: If file does not exist.
        :raises IOError: If reading file fails or rehash verification fails.
        """
        path = Path(storage_path) if isinstance(storage_path, str) else storage_path
        if not path.is_file():
            err_msg = f"File not found for streaming hash calculation: '{path}'"
            log_error_event(err_msg)
            raise FileNotFoundError(err_msg)

        sha256_hasher = hashlib.sha256()
        md5_hasher = hashlib.md5()

        try:
            with path.open("rb") as f:
                while chunk := f.read(cls.CHUNK_SIZE):
                    sha256_hasher.update(chunk)
                    md5_hasher.update(chunk)

            sha256_hex = sha256_hasher.hexdigest()
            md5_hex = md5_hasher.hexdigest()

            # Verify file can be rehashed later
            rehash_sha256_ok = cls.verify_file_hash(path, sha256_hex, "sha256")
            rehash_md5_ok = cls.verify_file_hash(path, md5_hex, "md5")

            if not (rehash_sha256_ok and rehash_md5_ok):
                err_msg = f"Rehash verification failed for file '{path}'"
                log_error_event(err_msg)
                raise IOError(err_msg)

            return {
                "sha256": sha256_hex,
                "md5": md5_hex
            }
        except Exception as exc:
            err_msg = f"Error performing streaming hashing on '{path}': {str(exc)}"
            log_error_event(err_msg, exc_info=True)
            raise IOError(err_msg) from exc


def calculate_sha256(content: bytes) -> str:
    """Calculates SHA256 checksum for given binary content."""
    return AdvancedHashingService.calculate_bytes_hash(content, "sha256")


def calculate_file_sha256(filepath: Union[str, Path]) -> str:
    """Calculates SHA256 checksum for a file on disk."""
    return AdvancedHashingService.calculate_file_hash(filepath, "sha256")


