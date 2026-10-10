from pathlib import Path

from ..base_analyzer import BaseAnalyzer

class MFTAnalyzer(BaseAnalyzer):
    """
    Windows NTFS Master File Table analyzer.
    Performs lightweight structural analysis of the extracted
    $MFT file.

    Current capabilities:

        - Locate extracted $MFT
        - Validate MFT record signatures
        - Count MFT records
        - Count active / inactive records
        - Extract basic record metadata
        - Preserve parsing errors
        - Generate summary statistics

    Outputs:

        mft_analysis.json
        mft_errors.json
        mft_summary.json

    Note:
        Full NTFS attribute parsing can be added later as an
        advanced MFT analysis stage.
    """

    RECORD_SIZE = 1024
    FILE_SIGNATURE = b"FILE"

    def analyze(self):

        print("\n[*] Running MFT Analyzer...")

        errors = []

        mft_file = self._find_mft_file()

        if mft_file is None:

            errors.append({
                "stage": "discovery",
                "error": "Extracted $MFT file not found."
            })

            self._write_outputs(
                [],
                errors,
                0,
                0,
                0,
                0
            )

            return

        try:

            (
                records,
                total_records,
                valid_records,
                active_records,
                inactive_records
            ) = self._parse_mft(
                mft_file,
                errors
            )

        except Exception as exc:

            errors.append({
                "stage": "mft_analysis",
                "file": str(mft_file),
                "error": str(exc)
            })

            records = []
            total_records = 0
            valid_records = 0
            active_records = 0
            inactive_records = 0

        self._write_outputs(
            records,
            errors,
            total_records,
            valid_records,
            active_records,
            inactive_records
        )

    # ==========================================================
    # FIND MFT
    # ==========================================================

    def _find_mft_file(self):

        # First try the expected filename.

        direct_path = (
            self.extracted_data_dir / "$MFT"
        )

        if direct_path.exists():

            return direct_path

        # Fallback recursive search.

        for file_path in (
            self.extracted_data_dir.rglob("*")
        ):

            if not file_path.is_file():
                continue

            if file_path.name.lower() == "$mft":

                return file_path

        return None

    # ==========================================================
    # PARSE MFT
    # ==========================================================

    def _parse_mft(
        self,
        mft_file,
        errors
    ):

        records = []

        total_records = 0
        valid_records = 0
        active_records = 0
        inactive_records = 0

        file_size = (
            mft_file.stat().st_size
        )

        estimated_records = (
            file_size // self.RECORD_SIZE
        )

        with open(
            mft_file,
            "rb"
        ) as f:

            record_number = 0

            while True:

                offset = (
                    record_number
                    * self.RECORD_SIZE
                )

                data = f.read(
                    self.RECORD_SIZE
                )

                if not data:

                    break

                record_number += 1
                total_records += 1

                # --------------------------------------------------
                # Incomplete final record
                # --------------------------------------------------

                if len(data) < self.RECORD_SIZE:

                    errors.append({
                        "record_number": record_number - 1,
                        "stage": "record_read",
                        "error": (
                            "Incomplete MFT record."
                        )
                    })

                    break

                # --------------------------------------------------
                # Signature
                # --------------------------------------------------

                signature = data[
                    0:4
                ]

                if signature != self.FILE_SIGNATURE:

                    continue

                valid_records += 1

                # --------------------------------------------------
                # Flags
                #
                # Offset 22 = flags
                # 0x01 = in use
                # 0x02 = directory
                # --------------------------------------------------

                flags = int.from_bytes(
                    data[22:24],
                    byteorder="little"
                )

                in_use = bool(
                    flags & 0x01
                )

                is_directory = bool(
                    flags & 0x02
                )

                if in_use:

                    active_records += 1

                else:

                    inactive_records += 1

                # --------------------------------------------------
                # Record number
                # --------------------------------------------------

                sequence_number = int.from_bytes(
                    data[16:18],
                    byteorder="little"
                )

                # --------------------------------------------------
                # First attribute offset
                # --------------------------------------------------

                first_attribute_offset = int.from_bytes(
                    data[20:22],
                    byteorder="little"
                )

                record = {

                    "record_number": (
                        record_number - 1
                    ),

                    "offset": offset,

                    "signature": (
                        signature.decode(
                            "ascii",
                            errors="ignore"
                        )
                    ),

                    "sequence_number": (
                        sequence_number
                    ),

                    "flags": flags,

                    "in_use": in_use,

                    "is_directory": (
                        is_directory
                    ),

                    "first_attribute_offset": (
                        first_attribute_offset
                    )
                }

                records.append(record)

        return (
            records,
            total_records,
            valid_records,
            active_records,
            inactive_records
        )

    # ==========================================================
    # OUTPUT
    # ==========================================================

    def _write_outputs(
        self,
        records,
        errors,
        total_records,
        valid_records,
        active_records,
        inactive_records
    ):

        # ======================================================
        # MAIN ANALYSIS
        # ======================================================

        if records:

            self.write_json(
                "mft_analysis.json",
                records
            )

        # ======================================================
        # ERRORS
        # ======================================================

        if errors:

            self.write_json(
                "mft_errors.json",
                errors
            )

        # ======================================================
        # STATUS
        # ======================================================

        if errors:

            if valid_records > 0:

                status = "completed_with_errors"

            else:

                status = "failed"

        elif valid_records > 0:

            status = "completed"

        else:

            status = "no_valid_records"

        # ======================================================
        # SUMMARY
        # ======================================================

        summary = {

            "artifact": "MFT",

            "status": status,

            "statistics": {

                "records_processed": (
                    total_records
                ),

                "valid_mft_records": (
                    valid_records
                ),

                "active_records": (
                    active_records
                ),

                "inactive_records": (
                    inactive_records
                ),

                "errors": (
                    len(errors)
                )
            },

            "record_structure": {

                "record_size_bytes": (
                    self.RECORD_SIZE
                ),

                "signature": "FILE",

                "in_use_flag": "0x01",

                "directory_flag": "0x02"
            },

            "capabilities": {

                "record_validation": True,

                "record_number": True,

                "sequence_number": True,

                "active_inactive_state": True,

                "directory_detection": True,

                "attribute_parsing": False,

                "filename_extraction": False,

                "timestamp_extraction": False,

                "full_ntfs_metadata": False
            },

            "errors": {

                "count": len(errors),

                "available": bool(errors)
            }
        }

        self.write_json(
            "mft_summary.json",
            summary
        )

        # ======================================================
        # CONSOLE
        # ======================================================

        print(
            f"  [+] Records processed: "
            f"{total_records}"
        )

        print(
            f"  [+] Valid MFT records: "
            f"{valid_records}"
        )

        print(
            f"  [+] Active records: "
            f"{active_records}"
        )

        print(
            f"  [+] Inactive records: "
            f"{inactive_records}"
        )

        print(
            f"  [!] Errors: "
            f"{len(errors)}"
        )

        print(
            "  [+] Summary written: "
            "mft_summary.json"
        )
