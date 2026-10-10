from pathlib import Path
from datetime import datetime, timezone

from ..base_analyzer import BaseAnalyzer

try:
    import LnkParse3
    LNK_AVAILABLE = True
except ImportError:
    LNK_AVAILABLE = False


class LNKAnalyzer(BaseAnalyzer):
    """
    Windows LNK forensic analyzer.

    Parses extracted .lnk files and produces:
        - lnk_analysis.json
        - lnk_summary.json
        - lnk_errors.json

    The analyzer is designed to tolerate differences between
    LnkParse3 versions and malformed LNK files.
    """

    def analyze(self):

        print("\n[*] Running LNK Analyzer...")

        if not self.extracted_data_dir.exists():

            self.write_json(
                "lnk_summary.json",
                {
                    "artifact": "LNK",
                    "status": "no_artifacts_found",
                    "statistics": {
                        "lnk_files_found": 0,
                        "lnk_files_parsed": 0,
                        "parse_errors": 0
                    },
                    "parser": {
                        "lnk_library_installed": LNK_AVAILABLE
                    }
                }
            )

            return

        if not LNK_AVAILABLE:

            print("  [-] LnkParse3 is not installed.")

            self.write_json(
                "lnk_summary.json",
                {
                    "artifact": "LNK",
                    "status": "parser_unavailable",
                    "statistics": {
                        "lnk_files_found": 0,
                        "lnk_files_parsed": 0,
                        "parse_errors": 0
                    },
                    "parser": {
                        "lnk_library_installed": False
                    }
                }
            )

            return

        lnk_records = []
        errors = []

        files_found = 0

        # ==========================================================
        # FIND LNK FILES
        # ==========================================================

        for lnk_file in self.extracted_data_dir.rglob("*"):

            if not lnk_file.is_file():
                continue

            if lnk_file.suffix.lower() != ".lnk":
                continue

            files_found += 1

            try:

                record = self._parse_lnk(lnk_file)

                lnk_records.append(record)

            except Exception as exc:

                errors.append(
                    {
                        "source_file": lnk_file.name,
                        "source_path": self._relative_path(lnk_file),
                        "stage": "parsing",
                        "error": str(exc)
                    }
                )

        # ==========================================================
        # ANALYSIS OUTPUT
        # ==========================================================

        if lnk_records:

            self.write_json(
                "lnk_analysis.json",
                lnk_records
            )

            print(
                f"  [+] Successfully parsed "
                f"{len(lnk_records)} LNK files."
            )

        else:

            print(
                "  [-] No LNK files were successfully parsed."
            )

        # ==========================================================
        # SUMMARY
        # ==========================================================

        summary = {
            "artifact": "LNK",

            "status": (
                "completed"
                if lnk_records and not errors
                else "completed_with_errors"
                if lnk_records
                else "failed"
            ),

            "statistics": {
                "lnk_files_found": files_found,
                "lnk_files_parsed": len(lnk_records),
                "parse_errors": len(errors)
            },

            "parser": {
                "library": "LnkParse3",
                "lnk_library_installed": True
            },

            "capabilities": {
                "header": True,
                "target_information": True,
                "link_information": True,
                "volume_information": True,
                "description": True,
                "working_directory": True,
                "command_arguments": True,
                "icon_location": True,
                "timestamps": True,
                "metadata": True
            },

            "errors": {
                "count": len(errors),
                "available": bool(errors)
            }
        }

        self.write_json(
            "lnk_summary.json",
            summary
        )

        # ==========================================================
        # ERROR OUTPUT
        # ==========================================================

        if errors:

            self.write_json(
                "lnk_errors.json",
                errors
            )

            print(
                f"  [!] {len(errors)} LNK parsing errors."
            )

        print("[+] LNK Analysis Complete.")

    # ==============================================================
    # PARSE ONE LNK
    # ==============================================================

    def _parse_lnk(self, lnk_file):

        # IMPORTANT:
        # LnkParse3 expects a file-like object, not a string path.

        with open(lnk_file, "rb") as file_handle:

            lnk = LnkParse3.lnk_file(file_handle)

            record = {

                "artifact_type": "Windows LNK",

                "source_file": lnk_file.name,

                "source_path": self._relative_path(
                    lnk_file
                ),

                "file_size": lnk_file.stat().st_size,

                "header": self._extract_header(lnk),

                "target": self._extract_target(lnk),

                "link_info": self._extract_object(
                    lnk,
                    "link_info"
                ),

                "volume_info": self._extract_object(
                    lnk,
                    "volume_info"
                ),

                "description": self._safe_get(
                    lnk,
                    "description"
                ),

                "working_directory": self._safe_get(
                    lnk,
                    "working_dir"
                ),

                "arguments": self._safe_get(
                    lnk,
                    "arguments"
                ),

                "icon_location": self._safe_get(
                    lnk,
                    "icon_location"
                ),

                "timestamps": self._extract_timestamps(
                    lnk
                )
            }

            return self._normalize_value(record)

    # ==============================================================
    # HEADER
    # ==============================================================

    def _extract_header(self, lnk):

        header = self._safe_get(
            lnk,
            "header"
        )

        if header is None:
            return None

        return self._extract_object(
            header
        )

    # ==============================================================
    # TARGET
    # ==============================================================

    def _extract_target(self, lnk):

        target = self._safe_get(
            lnk,
            "target"
        )

        if target is None:
            return None

        return self._extract_object(
            target
        )

    # ==============================================================
    # OBJECT EXTRACTION
    # ==============================================================

    def _extract_object(self, obj, attribute=None):

        if attribute is not None:

            obj = self._safe_get(
                obj,
                attribute
            )

        if obj is None:
            return None

        # Primitive values
        if isinstance(
            obj,
            (str, int, float, bool)
        ):
            return obj

        # Bytes
        if isinstance(obj, bytes):
            return obj.hex()

        # Dictionary
        if isinstance(obj, dict):

            return {
                str(key): self._normalize_value(
                    value
                )
                for key, value in obj.items()
            }

        # List / tuple
        if isinstance(
            obj,
            (list, tuple)
        ):

            return [
                self._normalize_value(
                    value
                )
                for value in obj
            ]

        # Try object attributes
        result = {}

        try:

            for name in dir(obj):

                if name.startswith("_"):
                    continue

                try:

                    value = getattr(
                        obj,
                        name
                    )

                except Exception:
                    continue

                if callable(value):
                    continue

                if isinstance(
                    value,
                    (
                        str,
                        int,
                        float,
                        bool,
                        bytes,
                        dict,
                        list,
                        tuple
                    )
                ):

                    result[name] = (
                        self._normalize_value(
                            value
                        )
                    )

            if result:
                return result

        except Exception:
            pass

        return str(obj)

    # ==============================================================
    # TIMESTAMPS
    # ==============================================================

    def _extract_timestamps(self, lnk):

        timestamps = {}

        possible_fields = {

            "creation_time": [
                "creation_time",
                "creation",
                "target_creation_time"
            ],

            "access_time": [
                "access_time",
                "access",
                "target_access_time"
            ],

            "modified_time": [
                "modified_time",
                "modified",
                "target_modified_time"
            ]
        }

        for output_name, candidates in possible_fields.items():

            for field_name in candidates:

                value = self._safe_get(
                    lnk,
                    field_name
                )

                if value is not None:

                    timestamps[
                        output_name
                    ] = self._normalize_value(
                        value
                    )

                    break

        return timestamps

    # ==============================================================
    # SAFE ATTRIBUTE ACCESS
    # ==============================================================

    def _safe_get(self, obj, attribute):

        if obj is None:
            return None

        try:

            if hasattr(obj, attribute):

                value = getattr(
                    obj,
                    attribute
                )

                if callable(value):

                    try:
                        value = value()
                    except TypeError:
                        return None

                return value

        except Exception:
            pass

        return None

    # ==============================================================
    # NORMALIZE JSON VALUES
    # ==============================================================

    def _normalize_value(self, value):

        if value is None:
            return None

        if isinstance(
            value,
            (str, int, float, bool)
        ):
            return value

        if isinstance(value, bytes):
            return value.hex()

        if isinstance(value, datetime):

            if value.tzinfo is None:

                value = value.replace(
                    tzinfo=timezone.utc
                )

            return value.isoformat()

        if isinstance(value, dict):

            return {
                str(key): self._normalize_value(
                    val
                )
                for key, val in value.items()
            }

        if isinstance(
            value,
            (list, tuple)
        ):

            return [
                self._normalize_value(
                    item
                )
                for item in value
            ]

        return self._extract_object(
            value
        )

    # ==============================================================
    # RELATIVE PATH
    # ==============================================================

    def _relative_path(self, path):

        try:

            return str(
                path.relative_to(
                    self.extracted_data_dir
                )
            )

        except ValueError:

            return str(path)