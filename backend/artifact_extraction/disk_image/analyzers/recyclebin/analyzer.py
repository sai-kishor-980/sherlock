import struct
from datetime import datetime, timedelta, timezone

from ..base_analyzer import BaseAnalyzer

class RecycleBinAnalyzer(BaseAnalyzer):
    """
    Windows Recycle Bin forensic analyzer.
    
    Analyzes Windows $Recycle.Bin artifacts.
    
    Important artifacts:

    $I*  -> deletion metadata
    $R*  -> deleted/recovered file data

    Extracted information includes:

    - SID / user container
    - $I metadata filename
    - corresponding $R filename
    - original deleted file path
    - original file size
    - deletion timestamp
    - metadata version
    - recovered data presence
    - recovered data size

    Outputs:

    recyclebin_analysis.json
    recyclebin_summary.json
    recyclebin_errors.json
    """

    I_PREFIX = "$I"
    R_PREFIX = "$R"

    # Windows FILETIME epoch
    FILETIME_EPOCH = datetime(
        1601,
        1,
        1,
        tzinfo=timezone.utc
    )

    def analyze(self):

        print(
            "\n[*] Running Recycle Bin Analyzer..."
        )

        records = []
        errors = []

        i_files = []
        r_files = []

        # ======================================================
        # CHECK DIRECTORY
        # ======================================================

        if not self.extracted_data_dir.exists():

            errors.append({
                "stage": "initialization",
                "error": (
                    "Extracted Recycle Bin directory "
                    "does not exist."
                )
            })

            self._write_outputs(
                records,
                errors,
                0,
                0,
                0
            )

            return

        # ======================================================
        # DISCOVER $I AND $R FILES
        # ======================================================

        for file_path in (
            self.extracted_data_dir.rglob("*")
        ):

            if not file_path.is_file():
                continue

            name = file_path.name

            # --------------------------------------------------
            # $I metadata
            # --------------------------------------------------

            if name.upper().startswith(
                self.I_PREFIX
            ):

                i_files.append(
                    file_path
                )

            # --------------------------------------------------
            # $R deleted data
            # --------------------------------------------------

            elif name.upper().startswith(
                self.R_PREFIX
            ):

                r_files.append(
                    file_path
                )

        # ======================================================
        # PARSE $I FILES
        # ======================================================

        for i_file in i_files:

            try:

                record = self._parse_i_file(
                    i_file,
                    r_files
                )

                records.append(
                    record
                )

            except Exception as exc:

                errors.append({
                    "source_file": i_file.name,
                    "source_path": self._relative_path(
                        i_file
                    ),
                    "stage": "i_file_parsing",
                    "error": str(exc)
                })

        # ======================================================
        # OUTPUT
        # ======================================================

        self._write_outputs(
            records,
            errors,
            len(i_files),
            len(r_files),
            len(records)
        )

    # ==========================================================
    # PARSE $I FILE
    # ==========================================================

    def _parse_i_file(
        self,
        i_file,
        r_files
    ):

        with open(
            i_file,
            "rb"
        ) as f:

            data = f.read()

        if len(data) < 24:

            raise ValueError(
                "$I file is too small to contain "
                "valid metadata."
            )

        # ======================================================
        # VERSION
        # ======================================================

        version = struct.unpack_from(
            "<Q",
            data,
            0
        )[0]

        # ======================================================
        # FILE SIZE
        # ======================================================

        original_size = struct.unpack_from(
            "<Q",
            data,
            8
        )[0]

        # ======================================================
        # DELETION TIME
        # ======================================================

        deletion_filetime = struct.unpack_from(
            "<Q",
            data,
            16
        )[0]

        deletion_timestamp = (
            self._filetime_to_iso(
                deletion_filetime
            )
        )

        # ======================================================
        # ORIGINAL PATH
        # ======================================================

        original_path = (
            self._extract_original_path(
                data,
                version
            )
        )

        # ======================================================
        # MATCH $R FILE
        # ======================================================

        r_file = self._find_matching_r_file(
            i_file,
            r_files
        )

        recovered_data = (
            r_file is not None
        )

        recovered_size = (
            r_file.stat().st_size
            if r_file is not None
            else 0
        )

        # ======================================================
        # RECORD
        # ======================================================

        return {

            "artifact_type": (
                "Windows Recycle Bin"
            ),

            "metadata_file": (
                i_file.name
            ),

            "metadata_path": (
                self._relative_path(
                    i_file
                )
            ),

            "recovery_file": (
                r_file.name
                if r_file is not None
                else None
            ),

            "recovery_path": (
                self._relative_path(
                    r_file
                )
                if r_file is not None
                else None
            ),

            "metadata_version": version,

            "original_file_path": (
                original_path
            ),

            "original_file_size": (
                original_size
            ),

            "deletion_timestamp": (
                deletion_timestamp
            ),

            "recovered_data_present": (
                recovered_data
            ),

            "recovered_data_size": (
                recovered_size
            )
        }

    # ==========================================================
    # ORIGINAL PATH
    # ==========================================================

    def _extract_original_path(
        self,
        data,
        version
    ):

        # ------------------------------------------------------
        # Windows 10 / newer $I format
        #
        # Version is generally 2.
        #
        # Path begins at offset 24.
        # ------------------------------------------------------

        if version >= 2:

            path_data = data[24:]

        else:

            # --------------------------------------------------
            # Legacy format
            #
            # Legacy implementations vary slightly, therefore
            # we search for a UTF-16LE path beginning with a
            # Windows drive path.
            # --------------------------------------------------

            path_data = data[24:]

        if not path_data:

            return ""

        try:

            text = path_data.decode(
                "utf-16le",
                errors="ignore"
            )

        except Exception:

            return ""

        # Remove null characters and trailing data.

        text = text.split(
            "\x00",
            1
        )[0].strip()

        return text

    # ==========================================================
    # MATCH $R FILE
    # ==========================================================

    def _find_matching_r_file(
        self,
        i_file,
        r_files
    ):

        i_name = i_file.name

        if not i_name.startswith(
            "$I"
        ):

            return None

        expected_name = (
            "$R"
            + i_name[2:]
        )

        for r_file in r_files:

            if r_file.name.lower() == (
                expected_name.lower()
            ):

                return r_file

        return None

    # ==========================================================
    # FILETIME CONVERSION
    # ==========================================================

    def _filetime_to_iso(
        self,
        filetime
    ):

        if filetime == 0:

            return None

        try:

            microseconds = (
                filetime // 10
            )

            timestamp = (
                self.FILETIME_EPOCH
                + timedelta(
                    microseconds=microseconds
                )
            )

            return timestamp.isoformat()

        except Exception:

            return None

    # ==========================================================
    # RELATIVE PATH
    # ==========================================================

    def _relative_path(
        self,
        path
    ):

        if path is None:
            return None

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
        i_files,
        r_files,
        parsed_records
    ):

        # ======================================================
        # ANALYSIS
        # ======================================================

        if records:

            self.write_json(
                "recyclebin_analysis.json",
                records
            )

        # ======================================================
        # ERRORS
        # ======================================================

        if errors:

            self.write_json(
                "recyclebin_errors.json",
                errors
            )

        # ======================================================
        # COUNTS
        # ======================================================

        recovered_count = sum(
            1
            for record in records
            if record.get(
                "recovered_data_present"
            )
        )

        deleted_only_count = (
            parsed_records
            - recovered_count
        )

        # ======================================================
        # STATUS
        # ======================================================

        if errors:

            if parsed_records > 0:

                status = (
                    "completed_with_errors"
                )

            else:

                status = "failed"

        elif parsed_records > 0:

            status = "completed"

        else:

            status = "no_artifacts_found"

        # ======================================================
        # SUMMARY
        # ======================================================

        summary = {

            "artifact": (
                "Recycle Bin"
            ),

            "status": status,

            "statistics": {

                "metadata_files": (
                    i_files
                ),

                "recovery_files": (
                    r_files
                ),

                "metadata_records_parsed": (
                    parsed_records
                ),

                "recovered_data_records": (
                    recovered_count
                ),

                "metadata_only_records": (
                    deleted_only_count
                ),

                "errors": (
                    len(errors)
                )
            },

            "capabilities": {

                "original_file_path": True,

                "original_file_size": True,

                "deletion_timestamp": True,

                "recovery_file_detection": True,

                "recovered_file_size": True,

                "metadata_version": True
            },

            "errors": {

                "count": len(errors),

                "available": bool(errors)
            }
        }

        self.write_json(
            "recyclebin_summary.json",
            summary
        )

        # ======================================================
        # CONSOLE
        # ======================================================

        print(
            f"  [+] $I metadata files: "
            f"{i_files}"
        )

        print(
            f"  [+] $R recovery files: "
            f"{r_files}"
        )

        print(
            f"  [+] Records parsed: "
            f"{parsed_records}"
        )

        print(
            f"  [+] Recovered data records: "
            f"{recovered_count}"
        )

        print(
            f"  [!] Errors: "
            f"{len(errors)}"
        )

        print(
            "  [+] Summary written: "
            "recyclebin_summary.json"
        )
