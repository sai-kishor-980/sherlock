import datetime
import hashlib
import json
import os
import re
from pathlib import Path
import pytsk3

from ..base_extractor import BaseExtractor


def sanitize_filename(name: str) -> str:
    """
    Sanitizes a filename to ensure it is valid on the host Windows filesystem.
    """
    clean = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name)
    clean = clean.strip()
    return clean if clean else "unnamed_artifact"


def format_timestamp(ts):
    """
    Converts a POSIX timestamp to an ISO 8601 UTC string.
    """
    if not ts or ts <= 0:
        return None
    try:
        return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).isoformat()
    except Exception:
        return None


class FilesystemExtractor(BaseExtractor):
    """
    Generic Filesystem & Volume File Extractor.

    Works across all filesystem types (FAT12/16/32, NTFS, exFAT, ext2/3/4).
    Catalogues the complete directory tree, recovers allocated and deleted/unallocated files,
    computes cryptographic hashes (SHA-256 and MD5), and extracts file contents to host storage.
    """

    MAX_EXTRACT_SIZE = 50 * 1024 * 1024  # 50MB max per file extraction

    def extract(self):
        fs_output_dir = self.create_output_directory("filesystem")
        extracted_files_dir = self.create_output_directory("extracted_files")
        analyzed_dir = self.output_dir / "analyzed"
        analyzed_dir.mkdir(parents=True, exist_ok=True)

        partition_info = {
            "start_sector": self.partition.start,
            "length_sectors": self.partition.len,
            "description": (
                self.partition.desc.decode("utf-8", errors="replace")
                if isinstance(self.partition.desc, bytes)
                else str(self.partition.desc)
            ),
            "filesystem_type": str(getattr(self.filesystem.fs.info, "ftype", "Unknown")),
            "block_size": getattr(self.filesystem.fs.info, "block_size", 512),
        }

        all_objects = []
        deleted_objects = []
        extracted_count = 0
        visited_inodes = set()

        try:
            root_dir = self.filesystem.open_directory("/")
            self._walk_directory(
                dir_obj=root_dir,
                current_path="/",
                all_objects=all_objects,
                deleted_objects=deleted_objects,
                extracted_files_dir=extracted_files_dir,
                visited_inodes=visited_inodes
            )
        except Exception as exc:
            self.log(f"Error opening root directory: {exc}")

        # Compute counts and metrics
        total_objects = len(all_objects)
        allocated_count = sum(1 for obj in all_objects if obj.get("status") == "ALLOCATED")
        deleted_count = len(deleted_objects)
        extracted_count = sum(1 for obj in all_objects if obj.get("extracted_to"))

        inventory_data = {
            "partition": partition_info,
            "total_objects": total_objects,
            "allocated_count": allocated_count,
            "deleted_count": deleted_count,
            "extracted_files_count": extracted_count,
            "objects": all_objects
        }

        deleted_data = {
            "partition": partition_info,
            "total_deleted": deleted_count,
            "deleted_files": deleted_objects
        }

        summary_data = {
            "partition": partition_info,
            "total_objects": total_objects,
            "allocated_count": allocated_count,
            "deleted_count": deleted_count,
            "extracted_files_count": extracted_count,
            "total_size_bytes": sum(obj.get("size", 0) for obj in all_objects),
            "artifacts_summary": [
                {
                    "name": obj.get("name"),
                    "path": obj.get("path"),
                    "status": obj.get("status"),
                    "size": obj.get("size"),
                    "sha256": obj.get("sha256"),
                    "extracted_to": obj.get("extracted_to")
                }
                for obj in all_objects if obj.get("type") == "File"
            ]
        }

        # Write to filesystem/
        self._write_json(fs_output_dir / "filesystem_inventory.json", inventory_data)
        self._write_json(fs_output_dir / "deleted_files.json", deleted_data)
        self._write_json(fs_output_dir / "disk_summary.json", summary_data)

        # Mirror key artifacts to analyzed/ for downstream analyzers and Supervisor
        self._write_json(analyzed_dir / "filesystem_inventory.json", inventory_data)
        self._write_json(analyzed_dir / "deleted_files.json", deleted_data)
        self._write_json(analyzed_dir / "disk_summary.json", summary_data)

        status = "SUCCESS" if total_objects > 0 else "SKIPPED"
        message = (
            f"Cataloged {total_objects} objects ({deleted_count} deleted). "
            f"Extracted {extracted_count} file(s) with SHA-256 hashes."
        )

        result = self.build_result(
            artifact="Filesystem",
            status=status,
            files=extracted_count,
            message=message
        )
        result["partition"] = partition_info
        result["total_objects"] = total_objects
        result["deleted_count"] = deleted_count
        return result

    def _walk_directory(
        self,
        dir_obj,
        current_path,
        all_objects,
        deleted_objects,
        extracted_files_dir,
        visited_inodes
    ):
        """
        Recursively walks pytsk3 directory entries, recording metadata, computing hashes,
        and extracting file bytes to the host filesystem.
        """
        for entry in dir_obj:
            try:
                raw_name = entry.info.name.name
                if raw_name in (b".", b".."):
                    continue

                safe_name = raw_name.decode("utf-8", errors="replace")
                full_path = current_path + ("/" if current_path != "/" else "") + safe_name

                meta = entry.info.meta
                meta_flags = meta.flags if meta else 0
                name_flags = entry.info.name.flags

                is_allocated = bool(meta_flags & pytsk3.TSK_FS_META_FLAG_ALLOC) if meta else True
                if name_flags == pytsk3.TSK_FS_NAME_FLAG_UNALLOC:
                    is_allocated = False

                status = "ALLOCATED" if is_allocated else "DELETED"
                inode = meta.addr if meta else None
                size = meta.size if meta else 0

                entry_type = "Unknown"
                if meta:
                    if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                        entry_type = "Directory"
                    elif meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                        entry_type = "File"
                    elif meta.type == pytsk3.TSK_FS_META_TYPE_VIRT:
                        entry_type = "Virtual"
                elif "volume label" in safe_name.lower():
                    entry_type = "VolumeLabel"

                # Extract timestamps
                mtime = format_timestamp(getattr(meta, "mtime", None))
                crtime = format_timestamp(getattr(meta, "crtime", None) or getattr(meta, "ctime", None))
                atime = format_timestamp(getattr(meta, "atime", None))

                record = {
                    "name": safe_name,
                    "path": full_path,
                    "type": entry_type,
                    "status": status,
                    "inode": inode,
                    "size": size,
                    "created": crtime,
                    "modified": mtime,
                    "accessed": atime,
                    "sha256": None,
                    "md5": None,
                    "extracted_to": None
                }

                # Attempt to extract file bytes and compute hashes for files
                if entry_type in ("File", "Virtual") and size > 0 and size <= self.MAX_EXTRACT_SIZE:
                    extracted_path, sha256_hash, md5_hash = self._extract_file_bytes(
                        entry, safe_name, inode, size, extracted_files_dir
                    )
                    record["sha256"] = sha256_hash
                    record["md5"] = md5_hash
                    record["extracted_to"] = str(extracted_path) if extracted_path else None

                all_objects.append(record)
                if not is_allocated or status == "DELETED":
                    deleted_objects.append(record)

                # Recursively walk subdirectories
                if entry_type == "Directory":
                    if inode and inode in visited_inodes:
                        continue
                    if inode:
                        visited_inodes.add(inode)

                    # Do not recurse into virtual metadata like $OrphanFiles if empty
                    if not safe_name.startswith("$"):
                        try:
                            sub_dir = entry.as_directory()
                            self._walk_directory(
                                dir_obj=sub_dir,
                                current_path=full_path,
                                all_objects=all_objects,
                                deleted_objects=deleted_objects,
                                extracted_files_dir=extracted_files_dir,
                                visited_inodes=visited_inodes
                            )
                        except Exception as sub_err:
                            self.log(f"Error accessing subdirectory {full_path}: {sub_err}")

            except Exception as item_err:
                self.log(f"Error processing entry: {item_err}")
                continue

    def _extract_file_bytes(self, entry, name, inode, size, destination_dir):
        """
        Reads file data directly from pytsk3, writes to host disk, and computes hashes.
        """
        try:
            sanitized = sanitize_filename(name)
            prefix = f"inode_{inode}_" if inode is not None else ""
            out_filename = f"{prefix}{sanitized}"
            dest_file = destination_dir / out_filename

            sha256_hash = hashlib.sha256()
            md5_hash = hashlib.md5()

            offset = 0
            chunk_size = 64 * 1024  # 64KB chunks

            with open(dest_file, "wb") as f_out:
                while offset < size:
                    read_len = min(chunk_size, size - offset)
                    chunk = entry.read_random(offset, read_len)
                    if not chunk:
                        break
                    f_out.write(chunk)
                    sha256_hash.update(chunk)
                    md5_hash.update(chunk)
                    offset += len(chunk)

            return dest_file, sha256_hash.hexdigest(), md5_hash.hexdigest()

        except Exception as exc:
            self.log(f"Failed to extract bytes for {name}: {exc}")
            return None, None, None

    def _write_json(self, file_path: Path, data: dict):
        """
        Helper method to write UTF-8 JSON safely.
        """
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
