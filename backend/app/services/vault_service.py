"""
Evidence Vault Management Service for HMACFR Layer 1 Security.

Manages secure evidence isolation, path traversal verification, quarantine handling,
failed preservation handling, and subfolder vault structures
(temp, encrypted, readonly, quarantine, archive, failed, keys).
"""

import shutil
from pathlib import Path
from typing import Union, Dict, Any
from app.core.config import settings
from app.core.logger import log_error_event, log_custody_event
from app.services.readonly_service import ReadOnlyProtectionService


class EvidenceVaultService:
    """
    Service managing structural integrity, path traversal safety, and file lifecycle inside the Evidence Vault.
    """

    VAULT_SUBDIRS = ["temp", "encrypted", "readonly", "quarantine", "archive", "failed", "keys"]

    @classmethod
    def get_vault_root(cls) -> Path:
        """Returns resolved absolute Path to EVIDENCE_VAULT_DIR."""
        return Path(settings.EVIDENCE_VAULT_DIR).resolve()

    @classmethod
    def ensure_vault_structure(cls) -> None:
        """Ensures all standard subdirectories exist in the evidence vault."""
        root = cls.get_vault_root()
        root.mkdir(parents=True, exist_ok=True)
        for subdir in cls.VAULT_SUBDIRS:
            (root / subdir).mkdir(parents=True, exist_ok=True)

    @classmethod
    def is_safe_vault_path(cls, filepath: Union[str, Path]) -> bool:
        """
        Validates that a path resides strictly within EVIDENCE_VAULT_DIR to prevent path traversal attacks.

        :param filepath: Path to evaluate.
        :return: True if safely inside evidence vault, False if outside.
        """
        try:
            target = Path(filepath).resolve()
            vault_root = cls.get_vault_root()
            return vault_root in target.parents or target == vault_root
        except Exception as exc:
            log_error_event(f"Path safety evaluation error on '{filepath}': {str(exc)}")
            return False

    @classmethod
    def deposit_to_readonly_vault(cls, source_path: Union[str, Path], case_id: str, filename: str) -> Path:
        """
        Moves evidence file to readonly vault folder and sets filesystem read-only flag.

        :param source_path: Source file path.
        :param case_id: Case identifier string.
        :param filename: Stored filename.
        :return: Destination Path inside readonly vault.
        """
        cls.ensure_vault_structure()
        src = Path(source_path).resolve()
        vault_readonly_dir = cls.get_vault_root() / "readonly" / case_id
        vault_readonly_dir.mkdir(parents=True, exist_ok=True)

        target_path = (vault_readonly_dir / filename).resolve()
        if src == target_path:
            ReadOnlyProtectionService.apply_readonly_protection(target_path)
            return target_path

        ReadOnlyProtectionService.revoke_readonly_protection(src)

        if target_path.exists():
            ReadOnlyProtectionService.revoke_readonly_protection(target_path)
            try:
                target_path.unlink()
            except Exception:
                pass

        try:
            shutil.move(str(src), str(target_path))
        except (PermissionError, OSError):
            shutil.copy2(str(src), str(target_path))
            try:
                src.unlink()
            except Exception:
                pass

        ReadOnlyProtectionService.apply_readonly_protection(target_path)
        return target_path

    @classmethod
    def quarantine_evidence(cls, filepath: Union[str, Path], reason: str = "Integrity compromise") -> Path:
        """
        Moves a suspected tampered or compromised evidence file to the quarantine vault (quarantine/).

        :param filepath: Path to compromised file.
        :param reason: Explanation string.
        :return: Destination Path inside quarantine vault.
        """
        cls.ensure_vault_structure()
        src = Path(filepath).resolve()
        quarantine_dir = cls.get_vault_root() / "quarantine"
        quarantine_dir.mkdir(parents=True, exist_ok=True)

        dest = (quarantine_dir / src.name).resolve()
        if src == dest:
            ReadOnlyProtectionService.apply_readonly_protection(dest)
            return dest

        if dest.exists():
            ReadOnlyProtectionService.revoke_readonly_protection(dest)
            try:
                dest.unlink()
            except Exception:
                pass

        if src.exists():
            ReadOnlyProtectionService.revoke_readonly_protection(src)
            try:
                shutil.move(str(src), str(dest))
            except (PermissionError, OSError):
                shutil.copy2(str(src), str(dest))
                try:
                    src.unlink()
                except Exception:
                    pass
            ReadOnlyProtectionService.apply_readonly_protection(dest)
            log_error_event(f"Integrity check failed: Evidence file '{src.name}' moved to QUARANTINE. Reason: {reason}")
        return dest

    @classmethod
    def handle_preservation_failure(
        cls, filepath: Union[str, Path], case_id: str, reason: str = "Preservation pipeline error"
    ) -> Path:
        """
        Relocates an evidence file that encountered a preservation pipeline failure to the 'failed/' vault directory.

        :param filepath: Path to evidence file.
        :param case_id: Case identifier string.
        :param reason: Explanation string.
        :return: Destination Path inside failed vault.
        """
        cls.ensure_vault_structure()
        src = Path(filepath).resolve()
        failed_dir = cls.get_vault_root() / "failed" / case_id
        failed_dir.mkdir(parents=True, exist_ok=True)

        dest = (failed_dir / src.name).resolve()
        if src == dest:
            return dest

        if dest.exists():
            ReadOnlyProtectionService.revoke_readonly_protection(dest)
            try:
                dest.unlink()
            except Exception:
                pass

        if src.exists():
            ReadOnlyProtectionService.revoke_readonly_protection(src)
            try:
                shutil.move(str(src), str(dest))
            except (PermissionError, OSError):
                shutil.copy2(str(src), str(dest))
                try:
                    src.unlink()
                except Exception:
                    pass
            log_error_event(f"Preservation failure for '{src.name}'. File moved to 'failed/{case_id}/'. Reason: {reason}")
        return dest

    @classmethod
    def save_evidence(
        cls, source_path: Union[str, Path], case_id: str, filename: str, vault_type: str = "readonly"
    ) -> Path:
        """
        Helper service to save evidence into evidence_vault/<vault_type>/<case_id>/<filename>.
        Creates directories automatically, applies read-only protection, and logs the operation.

        :param source_path: Source file path.
        :param case_id: Case identifier.
        :param filename: Preserved evidence filename.
        :param vault_type: Target subfolder ('readonly', 'encrypted', 'quarantine', 'failed', 'archive', etc.).
        :return: Absolute Path to stored file inside Evidence Vault.
        """
        cls.ensure_vault_structure()
        src = Path(source_path).resolve()
        if not src.is_file():
            err_msg = f"Save evidence failed: Source file '{src}' does not exist."
            log_error_event(err_msg)
            raise FileNotFoundError(err_msg)

        target_dir = cls.get_vault_root() / vault_type / case_id
        target_dir.mkdir(parents=True, exist_ok=True)

        target_path = (target_dir / filename).resolve()
        if src == target_path:
            ReadOnlyProtectionService.apply_readonly_protection(target_path)
            return target_path

        ReadOnlyProtectionService.revoke_readonly_protection(src)

        if target_path.exists():
            ReadOnlyProtectionService.revoke_readonly_protection(target_path)
            try:
                target_path.unlink()
            except Exception:
                pass

        try:
            shutil.move(str(src), str(target_path))
        except (PermissionError, OSError):
            shutil.copy2(str(src), str(target_path))
            try:
                src.unlink()
            except Exception:
                pass

        ReadOnlyProtectionService.apply_readonly_protection(target_path)

        log_custody_event(filename, f"Vault Save ({vault_type})", f"Vault Service -> {case_id}")
        return target_path

    @classmethod
    def retrieve_evidence(
        cls, case_id: str, filename: str, vault_type: str = "readonly"
    ) -> Path:
        """
        Helper service to retrieve evidence path from evidence_vault/<vault_type>/<case_id>/<filename>.
        Verifies path safety and logs retrieval.

        :param case_id: Case identifier.
        :param filename: Evidence filename.
        :param vault_type: Vault subfolder ('readonly', 'encrypted', 'archive', etc.).
        :return: Absolute Path to evidence file.
        :raises FileNotFoundError: If evidence file is missing.
        """
        cls.ensure_vault_structure()
        target_path = (cls.get_vault_root() / vault_type / case_id / filename).resolve()
        
        if not cls.is_safe_vault_path(target_path) or not target_path.is_file():
            err_msg = f"Retrieve evidence failed: File '{target_path}' not found or path unsafe."
            log_error_event(err_msg)
            raise FileNotFoundError(err_msg)

        log_custody_event(filename, f"Vault Retrieve ({vault_type})", f"Vault Service <- {case_id}")
        return target_path

    @classmethod
    def archive_evidence(
        cls, case_id: str, filename: str, current_vault_type: str = "readonly"
    ) -> Path:
        """
        Helper service to relocate evidence from current vault subfolder to evidence_vault/archive/<case_id>/<filename>.
        Applies read-only protection and logs the archive operation.

        :param case_id: Case identifier.
        :param filename: Evidence filename.
        :param current_vault_type: Current vault subfolder (default 'readonly').
        :return: Absolute Path to archived file.
        """
        cls.ensure_vault_structure()
        src_path = (cls.get_vault_root() / current_vault_type / case_id / filename).resolve()
        if not src_path.is_file():
            err_msg = f"Archive evidence failed: Source file '{src_path}' does not exist."
            log_error_event(err_msg)
            raise FileNotFoundError(err_msg)

        archive_dir = cls.get_vault_root() / "archive" / case_id
        archive_dir.mkdir(parents=True, exist_ok=True)
        dest_path = (archive_dir / filename).resolve()
        if src_path == dest_path:
            ReadOnlyProtectionService.apply_readonly_protection(dest_path)
            return dest_path

        ReadOnlyProtectionService.revoke_readonly_protection(src_path)
        if dest_path.exists():
            ReadOnlyProtectionService.revoke_readonly_protection(dest_path)
            try:
                dest_path.unlink()
            except Exception:
                pass

        try:
            shutil.move(str(src_path), str(dest_path))
        except (PermissionError, OSError):
            shutil.copy2(str(src_path), str(dest_path))
            try:
                src_path.unlink()
            except Exception:
                pass

        ReadOnlyProtectionService.apply_readonly_protection(dest_path)

        log_custody_event(filename, "Vault Archive", f"Vault Service -> archive/{case_id}")
        return dest_path
