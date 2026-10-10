from pathlib import Path
from datetime import datetime, timezone

from ..base_analyzer import BaseAnalyzer


class PrefetchAnalyzer(BaseAnalyzer):
    """
    Windows Prefetch forensic analyzer.

    Supports basic parsing of uncompressed Windows Prefetch files.

    Extracts:
        - Prefetch version
        - Executable name
        - Prefetch hash
        - File size
        - Run count where the version/layout supports it
        - Last execution timestamps where available
        - Referenced strings
        - Basic volume information where identifiable

    Compressed Prefetch files are detected and reported rather than
    incorrectly parsed.

    Outputs:
        prefetch_analysis.json
        prefetch_summary.json
        prefetch_errors.json
    """

    SUPPORTED_EXTENSION = ".pf"

    # ----------------------------------------------------------
    # PREFETCH VERSIONS
    # ----------------------------------------------------------

    VERSION_MAP = {
        17: "Windows 7",
        23: "Windows 8 / 8.1",
        26: "Windows 10",
        30: "Windows 10 / 11",
        31: "Windows 11",
    }

    def analyze(self):

        print("\n[*] Running Prefetch Analyzer...")

        records = []
        errors = []

        files_found = 0
        files_parsed = 0
        compressed_files = 0

        if not self.extracted_data_dir.exists():

            errors.append({
                "stage": "initialization",
                "error": (
                    "Extracted Prefetch directory "
                    "does not exist."
                )
            })

            self._write_outputs(
                records,
                errors,
                files_found,
                files_parsed,
                compressed_files
            )

            return

        # ------------------------------------------------------
        # FIND PREFETCH FILES
        # ------------------------------------------------------

        for prefetch_file in self.extracted_data_dir.rglob("*"):

            if not prefetch_file.is_file():
                continue

            if prefetch_file.suffix.lower() != self.SUPPORTED_EXTENSION:
                continue

            files_found += 1

            try:

                record = self._parse_prefetch_file(
                    prefetch_file
                )

                records.append(record)

                if record.get("compressed"):
                    compressed_files += 1
                elif record.get("parse_status") == "parsed":
                    files_parsed += 1

            except Exception as exc:

                errors.append({
                    "source_file": prefetch_file.name,
                    "source_path": self._relative_path(
                        prefetch_file
                    ),
                    "stage": "parsing",
                    "error": str(exc)
                })

        self._write_outputs(
            records,
            errors,
            files_found,
            files_parsed,
            compressed_files
        )

    # ==========================================================
    # PARSE PREFETCH
    # ==========================================================

    def _parse_prefetch_file(self, prefetch_file):

        with open(prefetch_file, "rb") as f:
            data = f.read()

        record = {
            "artifact_type": "Windows Prefetch",
            "source_file": prefetch_file.name,
            "source_path": self._relative_path(prefetch_file),
            "file_size": len(data),
            "compressed": False,
            "parse_status": "unknown",
        }

        # ------------------------------------------------------
        # EMPTY / TOO SMALL
        # ------------------------------------------------------

        if len(data) < 16:

            record["parse_status"] = "invalid"

            record["error"] = (
                "Prefetch file is too small "
                "to contain a valid header."
            )

            return record

        # ------------------------------------------------------
        # COMPRESSED PREFETCH
        # ------------------------------------------------------
        #
        # Windows compressed Prefetch files commonly begin
        # with the MAM compression signature.
        #
        # MAM = 0x4D414D
        #
        # We detect it but do not attempt unsafe decompression.
        # ------------------------------------------------------

        if data[:3] == b"MAM":

            record["compressed"] = True

            record["compression"] = "MAM"

            record["parse_status"] = (
                "compressed_not_decompressed"
            )

            record["analysis_note"] = (
                "Prefetch file is compressed. "
                "Header-level forensic parsing requires "
                "MAM decompression."
            )

            return record

        # ------------------------------------------------------
        # VERSION
        # ------------------------------------------------------

        version = int.from_bytes(
            data[0:4],
            byteorder="little",
            signed=False
        )

        record["version"] = version

        record["windows_version"] = (
            self.VERSION_MAP.get(
                version,
                "Unknown / unsupported Prefetch version"
            )
        )

        # ------------------------------------------------------
        # SIGNATURE
        # ------------------------------------------------------

        signature = data[4:8]

        try:
            signature_text = signature.decode(
                "ascii",
                errors="ignore"
            )
        except Exception:
            signature_text = ""

        record["signature"] = signature_text

        if signature != b"SCCA":

            record["parse_status"] = "invalid"

            record["error"] = (
                "Invalid Prefetch signature. "
                "Expected SCCA."
            )

            return record

        # ------------------------------------------------------
        # EXECUTABLE NAME
        # ------------------------------------------------------

        executable_name = self._extract_executable_name(
            data
        )

        record["executable_name"] = executable_name

        # ------------------------------------------------------
        # PREFETCH HASH
        # ------------------------------------------------------

        if len(data) >= 0x50:

            record["prefetch_hash"] = (
                data[0x4C:0x50].hex().upper()
            )

        # ------------------------------------------------------
        # RUN COUNT
        # ------------------------------------------------------

        run_count = self._extract_run_count(
            data,
            version
        )

        if run_count is not None:
            record["run_count"] = run_count

        # ------------------------------------------------------
        # LAST EXECUTION TIMES
        # ------------------------------------------------------

        timestamps = self._extract_execution_times(
            data,
            version
        )

        if timestamps:

            record["last_execution_times"] = timestamps

            record["last_execution_time"] = (
                timestamps[0]
            )

        # ------------------------------------------------------
        # UNICODE STRINGS
        # ------------------------------------------------------

        strings = self._extract_unicode_strings(
            data
        )

        if strings:

            record["referenced_strings"] = strings[:200]

            record["referenced_string_count"] = (
                len(strings)
            )

        # ------------------------------------------------------
        # FILE REFERENCES
        # ------------------------------------------------------

        referenced_files = []

        for value in strings:

            lower_value = value.lower()

            if (
                "\\" in value
                or "/" in value
            ):

                if (
                    lower_value.endswith(
                        (
                            ".exe",
                            ".dll",
                            ".sys",
                            ".bat",
                            ".cmd",
                            ".ps1",
                            ".txt",
                            ".doc",
                            ".docx",
                            ".pdf",
                            ".zip"
                        )
                    )
                ):

                    referenced_files.append(value)

        if referenced_files:

            record["referenced_files"] = (
                list(dict.fromkeys(referenced_files))
            )

        # ------------------------------------------------------
        # STATUS
        # ------------------------------------------------------

        record["parse_status"] = "parsed"

        return record

    # ==========================================================
    # EXECUTABLE NAME
    # ==========================================================

    def _extract_executable_name(self, data):

        # Prefetch executable name is normally stored at
        # offset 0x10 as a UTF-16LE string.

        name_offset = 0x10
        name_length = 60

        if len(data) < name_offset + name_length:
            return None

        raw_name = data[
            name_offset:
            name_offset + name_length
        ]

        try:

            name = raw_name.decode(
                "utf-16le",
                errors="ignore"
            )

            return name.split("\x00")[0].strip()

        except Exception:

            return None

    # ==========================================================
    # RUN COUNT
    # ==========================================================

    def _extract_run_count(
        self,
        data,
        version
    ):

        """
        Extract the Prefetch execution count where the
        known header layout provides it.

        Older Prefetch versions commonly store the count
        around offset 0x90.

        Newer versions may use different layouts.
        We therefore avoid pretending an unknown offset
        is valid.
        """

        if version in (17, 23):

            offset = 0x90

        elif version in (26, 30, 31):

            # Windows 10/11 layouts generally retain the
            # execution counter around this region, but
            # different builds can vary.
            offset = 0xD0

        else:

            return None

        if len(data) < offset + 4:
            return None

        value = int.from_bytes(
            data[offset:offset + 4],
            byteorder="little",
            signed=False
        )

        # Sanity check.
        if value > 1000000:
            return None

        return value

    # ==========================================================
    # EXECUTION TIMESTAMPS
    # ==========================================================

    def _extract_execution_times(
        self,
        data,
        version
    ):

        """
        Extract FILETIME values from the Prefetch header.

        Windows 10/11 Prefetch can contain multiple execution
        timestamps.
        """

        timestamps = []

        # Common timestamp region.
        offset = 0x80

        # Number of timestamps varies by version.
        if version in (17, 23):

            count = 1

        elif version in (26, 30, 31):

            count = 8

        else:

            count = 1

        for index in range(count):

            timestamp_offset = (
                offset + (index * 8)
            )

            if len(data) < timestamp_offset + 8:
                break

            raw_timestamp = data[
                timestamp_offset:
                timestamp_offset + 8
            ]

            value = int.from_bytes(
                raw_timestamp,
                byteorder="little",
                signed=False
            )

            if value == 0:
                continue

            try:

                timestamp = self._filetime_to_iso(
                    value
                )

                if timestamp:
                    timestamps.append(timestamp)

            except Exception:
                continue

        return timestamps

    # ==========================================================
    # FILETIME
    # ==========================================================

    def _filetime_to_iso(self, filetime):

        # FILETIME is 100-nanosecond intervals since
        # January 1, 1601 UTC.

        if filetime <= 0:
            return None

        unix_epoch_offset = 116444736000000000

        unix_100ns = (
            filetime - unix_epoch_offset
        )

        if unix_100ns <= 0:
            return None

        seconds = unix_100ns / 10000000

        try:

            dt = datetime.fromtimestamp(
                seconds,
                tz=timezone.utc
            )

            # Sanity check.
            if dt.year < 2000 or dt.year > 2100:
                return None

            return dt.isoformat()

        except Exception:

            return None

    # ==========================================================
    # UNICODE STRING EXTRACTION
    # ==========================================================

    def _extract_unicode_strings(self, data):

        strings = []

        current = bytearray()

        # Minimum UTF-16 string length.
        minimum_length = 4

        index = 0

        while index + 1 < len(data):

            pair = data[index:index + 2]

            # Printable ASCII range represented as UTF-16LE.
            if (
                pair[0] >= 0x20
                and pair[0] <= 0x7E
                and pair[1] == 0x00
            ):

                current.extend(pair)

            else:

                if len(current) >= minimum_length:

                    try:

                        value = current.decode(
                            "utf-16le",
                            errors="ignore"
                        ).strip()

                        if value:
                            strings.append(value)

                    except Exception:
                        pass

                current = bytearray()

            index += 2

        # Final string.
        if len(current) >= minimum_length:

            try:

                value = current.decode(
                    "utf-16le",
                    errors="ignore"
                ).strip()

                if value:
                    strings.append(value)

            except Exception:
                pass

        # Remove duplicates while preserving order.
        return list(dict.fromkeys(strings))

    # ==========================================================
    # RELATIVE PATH
    # ==========================================================

    def _relative_path(self, path):

        try:

            return str(
                path.relative_to(
                    self.extracted_data_dir
                )
            )

        except ValueError:

            return str(path)

    # ==========================================================
    # OUTPUT
    # ==========================================================

    def _write_outputs(
        self,
        records,
        errors,
        files_found,
        files_parsed,
        compressed_files
    ):

        # ------------------------------------------------------
        # ANALYSIS
        # ------------------------------------------------------

        if records:

            self.write_json(
                "prefetch_analysis.json",
                records
            )

        # ------------------------------------------------------
        # ERRORS
        # ------------------------------------------------------

        if errors:

            self.write_json(
                "prefetch_errors.json",
                errors
            )

        # ------------------------------------------------------
        # STATUS
        # ------------------------------------------------------

        if files_found == 0:

            status = "no_artifacts_found"

        elif files_parsed > 0 and errors:

            status = "completed_with_errors"

        elif files_parsed > 0:

            status = "completed"

        elif compressed_files == files_found:

            status = "compressed_not_supported"

        elif errors:

            status = "failed"

        else:

            status = "no_artifacts_parsed"

        # ------------------------------------------------------
        # SUMMARY
        # ------------------------------------------------------

        summary = {

            "artifact": "Prefetch",

            "status": status,

            "statistics": {

                "prefetch_files_found": files_found,

                "prefetch_files_parsed": files_parsed,

                "compressed_files": compressed_files,

                "parse_errors": len(errors)
            },

            "capabilities": {

                "prefetch_file_detection": True,

                "header_parsing": True,

                "executable_identification": (
                    files_parsed > 0
                ),

                "prefetch_version": (
                    files_parsed > 0
                ),

                "prefetch_hash": (
                    files_parsed > 0
                ),

                "execution_count": (
                    files_parsed > 0
                ),

                "last_execution_time": (
                    files_parsed > 0
                ),

                "unicode_string_extraction": (
                    files_parsed > 0
                ),

                "referenced_file_detection": (
                    files_parsed > 0
                ),

                "compressed_prefetch": (
                    compressed_files > 0
                )
            },

            "parser": {

                "external_library_required": False,

                "parser_type": (
                    "Built-in Prefetch parser"
                )
            },

            "errors": {

                "count": len(errors),

                "available": bool(errors)
            }
        }

        self.write_json(
            "prefetch_summary.json",
            summary
        )

        # ------------------------------------------------------
        # CONSOLE
        # ------------------------------------------------------

        print(
            f"  [+] Prefetch files found: "
            f"{files_found}"
        )

        print(
            f"  [+] Prefetch files parsed: "
            f"{files_parsed}"
        )

        print(
            f"  [+] Compressed files: "
            f"{compressed_files}"
        )

        print(
            f"  [!] Parse errors: "
            f"{len(errors)}"
        )

        print(
            "  [+] Prefetch summary written."
        )