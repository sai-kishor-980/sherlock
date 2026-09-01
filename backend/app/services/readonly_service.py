"""
Read-Only Protection Service for HMACFR Layer 1 Preservation.

Manages filesystem write-protection, evidence immutability checks, and read-only status enforcement.
"""

from pathlib import Path
from typing import Union
from app.utils.permission_utils import set_readonly_flag, is_readonly_flag_set, remove_readonly_flag
from app.core.logger import log_error_event


class ReadOnlyProtectionService:
    """
    Service responsible for applying and auditing filesystem write-protection on evidence files.
    """

    @classmethod
    def apply_readonly_protection(cls, filepath: Union[str, Path]) -> bool:
        """
        Enforces read-only permissions on a stored evidence file.

        :param filepath: Path to evidence file.
        :return: True if read-only protection was successfully applied, False otherwise.
        """
        path = Path(filepath) if isinstance(filepath, str) else filepath
        return set_readonly_flag(path)

    @classmethod
    def check_readonly_status(cls, filepath: Union[str, Path]) -> bool:
        """
        Audits whether an evidence file is write-protected.

        :param filepath: Path to evidence file.
        :return: True if write-protected, False otherwise.
        """
        path = Path(filepath) if isinstance(filepath, str) else filepath
        return is_readonly_flag_set(path)

    @classmethod
    def revoke_readonly_protection(cls, filepath: Union[str, Path]) -> bool:
        """
        Restores write access to an evidence file for authorized maintenance operations.

        :param filepath: Path to evidence file.
        :return: True if write access was restored, False otherwise.
        """
        path = Path(filepath) if isinstance(filepath, str) else filepath
        return remove_readonly_flag(path)

    @classmethod
    def protect_and_deposit_to_readonly_vault(
        cls, source_path: Union[str, Path], case_id: str, filename: str
    ) -> Path:
        """
        Relocates evidence file into evidence_vault/readonly/<case_id>/<filename>
        and enforces OS-level read-only permissions so no file can be modified after preservation.

        :param source_path: Path to source evidence file.
        :param case_id: Case unique identifier.
        :param filename: Target filename.
        :return: Destination Path in evidence_vault/readonly/.
        """
        from app.services.vault_service import EvidenceVaultService
        return EvidenceVaultService.deposit_to_readonly_vault(source_path, case_id, filename)

