import os
import shutil
from typing import List, Tuple
from app.core.config import settings
from app.utils.file_utils import sanitize_filename

STANDARD_CATEGORIES: List[str] = [
    "Memory",
    "Disk",
    "Registry",
    "Logs",
    "Browser",
    "PCAP",
    "Malware",
    "Documents",
    "Images"
]

class StorageService:
    @staticmethod
    def get_or_create_category_directory(case_id: str, category: str = None) -> str:
        """
        Constructs and ensures the existence of EvidenceVault/{case_id}/{category}/
        If folder exists -> reuses it. If not -> creates it.
        """
        clean_case_id = sanitize_filename(case_id)
        clean_category = sanitize_filename(category) if category else "General"
        
        formatted_category = clean_category.capitalize()
        target_dir = os.path.join(settings.EVIDENCE_VAULT_DIR, clean_case_id, formatted_category)
        os.makedirs(target_dir, exist_ok=True)
        return target_dir

    @staticmethod
    def init_case_directory_structure(case_id: str) -> str:
        """
        Pre-creates all standard evidence subdirectories for a given case.
        """
        clean_case_id = sanitize_filename(case_id)
        case_root_dir = os.path.join(settings.EVIDENCE_VAULT_DIR, clean_case_id)
        os.makedirs(case_root_dir, exist_ok=True)

        for category in STANDARD_CATEGORIES:
            cat_dir = os.path.join(case_root_dir, category)
            os.makedirs(cat_dir, exist_ok=True)

        return case_root_dir

    @staticmethod
    def resolve_unique_filename(target_directory: str, filename: str) -> Tuple[str, str]:
        """
        Resolves duplicate filenames.
        If 'memory.raw' exists in target_directory, renames to 'memory_1.raw', 'memory_2.raw', etc.
        Returns Tuple[unique_stored_filename, full_target_path]
        """
        safe_name = sanitize_filename(filename)
        base_name, extension = os.path.splitext(safe_name)
        
        stored_filename = safe_name
        target_path = os.path.join(target_directory, stored_filename)

        counter = 1
        while os.path.exists(target_path):
            stored_filename = f"{base_name}_{counter}{extension}"
            target_path = os.path.join(target_directory, stored_filename)
            counter += 1

        return stored_filename, target_path

    @staticmethod
    def store_evidence_file(case_id: str, category: str, original_filename: str, content: bytes) -> Tuple[str, str]:
        """
        Stores an uploaded evidence file:
        1. Ensures EvidenceVault/{case_id}/{category}/ folder exists.
        2. Renames duplicate filenames automatically (e.g. memory.raw -> memory_1.raw).
        3. Writes content to target location.
        4. Returns (stored_filename, storage_path).
        """
        target_dir = StorageService.get_or_create_category_directory(case_id, category)
        stored_filename, target_path = StorageService.resolve_unique_filename(target_dir, original_filename)

        with open(target_path, "wb") as f:
            f.write(content)

        return stored_filename, target_path

    @staticmethod
    def save_to_uploads(filename: str, content: bytes) -> str:
        os.makedirs(settings.UPLOADS_DIR, exist_ok=True)
        filepath = os.path.join(settings.UPLOADS_DIR, filename)
        with open(filepath, "wb") as f:
            f.write(content)
        return filepath

    @staticmethod
    def move_to_vault(source_path: str, case_id: str, category: str, filename: str) -> Tuple[str, str]:
        """
        Moves a file from a temporary location to the evidence vault with duplicate renaming.
        Returns Tuple[stored_filename, target_path]
        """
        target_dir = StorageService.get_or_create_category_directory(case_id, category)
        stored_filename, target_path = StorageService.resolve_unique_filename(target_dir, filename)
        if os.path.abspath(source_path) == os.path.abspath(target_path):
            return stored_filename, target_path

        try:
            shutil.move(source_path, target_path)
        except (PermissionError, OSError):
            shutil.copy2(source_path, target_path)
            try:
                os.unlink(source_path)
            except Exception:
                pass
        return stored_filename, target_path
