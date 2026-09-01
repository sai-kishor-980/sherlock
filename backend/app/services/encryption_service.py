"""
Evidence Encryption Service for HMACFR Layer 1 Preservation.

Provides AES-256-GCM authenticated symmetric payload encryption and decryption
for evidence payloads at rest.
"""

import os
from pathlib import Path
from typing import Union, Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.core.config import settings
from app.core.logger import log_error_event, log_encryption_event
from app.utils.crypto_utils import derive_key_from_password, generate_random_salt


class EvidenceEncryptionService:
    """
    Service managing AES-256-GCM symmetric encryption and decryption for evidence files.
    """

    NONCE_SIZE: int = 12  # 96-bit nonce for AES-GCM
    SALT_SIZE: int = 16   # 128-bit salt for PBKDF2

    @classmethod
    def get_encryption_key(cls, secret_key: Optional[str] = None, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Derives a 256-bit AES encryption key and returns (derived_key, salt).
        """
        master_password = secret_key or getattr(settings, "ENCRYPTION_SECRET_KEY", settings.SECRET_KEY)
        salt_buf = salt or generate_random_salt(cls.SALT_SIZE)
        derived_key = derive_key_from_password(master_password, salt_buf)
        return derived_key, salt_buf

    @classmethod
    def encrypt_bytes(cls, content: bytes, secret_key: Optional[str] = None) -> bytes:
        """
        Encrypts in-memory raw bytes using AES-256-GCM.
        Returns payload layout: [SALT (16B)] + [NONCE (12B)] + [CIPHERTEXT WITH TAG].
        """
        key, salt = cls.get_encryption_key(secret_key)
        aesgcm = AESGCM(key)
        nonce = os.urandom(cls.NONCE_SIZE)
        ciphertext = aesgcm.encrypt(nonce, content, None)
        return salt + nonce + ciphertext

    @classmethod
    def decrypt_bytes(cls, payload: bytes, secret_key: Optional[str] = None) -> bytes:
        """
        Decrypts payload encrypted with encrypt_bytes.
        """
        min_size = cls.SALT_SIZE + cls.NONCE_SIZE + 16  # Salt + Nonce + Tag (16B min)
        if len(payload) < min_size:
            err_msg = "Invalid encrypted payload size."
            log_error_event(err_msg)
            raise ValueError(err_msg)

        salt = payload[:cls.SALT_SIZE]
        nonce = payload[cls.SALT_SIZE:cls.SALT_SIZE + cls.NONCE_SIZE]
        ciphertext = payload[cls.SALT_SIZE + cls.NONCE_SIZE:]

        master_password = secret_key or getattr(settings, "ENCRYPTION_SECRET_KEY", settings.SECRET_KEY)
        key = derive_key_from_password(master_password, salt)
        aesgcm = AESGCM(key)

        try:
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as exc:
            err_msg = "Decryption failed: Ciphertext tag mismatch or wrong secret key."
            log_error_event(err_msg, exc_info=True)
            raise ValueError(err_msg) from exc

    @classmethod
    def encrypt_file(
        cls, source_path: Union[str, Path], dest_path: Union[str, Path], secret_key: Optional[str] = None
    ) -> bool:
        """
        Encrypts an evidence file on disk and writes ciphertext to target destination.
        """
        src = Path(source_path) if isinstance(source_path, str) else source_path
        dst = Path(dest_path) if isinstance(dest_path, str) else dest_path

        if not src.is_file():
            log_error_event(f"Encryption failed: Source file '{src}' does not exist.")
            return False

        try:
            content = src.read_bytes()
            encrypted_payload = cls.encrypt_bytes(content, secret_key)
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(encrypted_payload)
            log_encryption_event(str(src.name), "Encrypt", "Success")
            return True
        except Exception as exc:
            log_error_event(f"Failed to encrypt file '{src}': {str(exc)}", exc_info=True)
            return False

    @classmethod
    def decrypt_file(
        cls, source_path: Union[str, Path], dest_path: Union[str, Path], secret_key: Optional[str] = None
    ) -> bool:
        """
        Decrypts an encrypted evidence file on disk and restores original content to target destination.
        """
        src = Path(source_path) if isinstance(source_path, str) else source_path
        dst = Path(dest_path) if isinstance(dest_path, str) else dest_path

        if not src.is_file():
            log_error_event(f"Decryption failed: Source file '{src}' does not exist.")
            return False

        try:
            encrypted_payload = src.read_bytes()
            plain_content = cls.decrypt_bytes(encrypted_payload, secret_key)
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(plain_content)
            log_encryption_event(str(src.name), "Decrypt", "Success")
            return True
        except Exception as exc:
            log_error_event(f"Failed to decrypt file '{src}': {str(exc)}", exc_info=True)
            return False

    @classmethod
    def encrypt_evidence_to_vault(
        cls, source_path: Union[str, Path], case_id: str, original_filename: str, secret_key: Optional[str] = None
    ) -> Path:
        """
        Encrypts uploaded evidence after hashing, preserving original filename,
        and storing inside evidence_vault/encrypted/<case_id>/<original_filename>.

        Uses AES-256-GCM authenticated encryption and configurable keys from environment variables (ENCRYPTION_SECRET_KEY).

        :param source_path: Source evidence path.
        :param case_id: Case unique identifier.
        :param original_filename: Original filename to preserve.
        :param secret_key: Optional secret key override (defaults to settings.ENCRYPTION_SECRET_KEY from env).
        :return: Path object to encrypted file inside evidence_vault/encrypted/.
        """
        src = Path(source_path) if isinstance(source_path, str) else source_path
        if not src.is_file():
            err_msg = f"Source evidence file '{src}' does not exist for encryption."
            log_error_event(err_msg)
            raise FileNotFoundError(err_msg)

        vault_encrypted_dir = Path(settings.EVIDENCE_VAULT_DIR) / "encrypted" / case_id
        vault_encrypted_dir.mkdir(parents=True, exist_ok=True)

        target_encrypted_path = vault_encrypted_dir / original_filename

        master_key = secret_key or getattr(settings, "ENCRYPTION_SECRET_KEY", settings.SECRET_KEY)
        success = cls.encrypt_file(src, target_encrypted_path, master_key)

        if not success:
            err_msg = f"AES-256 authenticated encryption failed for '{original_filename}'"
            log_error_event(err_msg)
            raise IOError(err_msg)

        log_encryption_event(original_filename, "AES-256-GCM Encrypt Vault Deposit", "Success")
        return target_encrypted_path

