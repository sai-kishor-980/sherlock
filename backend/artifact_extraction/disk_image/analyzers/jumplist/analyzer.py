import re
from datetime import datetime, timezone

from ..base_analyzer import BaseAnalyzer

try:
    import olefile
    OLEFILE_AVAILABLE = True
except ImportError:
    OLEFILE_AVAILABLE = False
class JumpListAnalyzer(BaseAnalyzer):
    """
    Analyzes Windows Jump List artifacts.
    Supported:
        - *.automaticDestinations-ms
        - *.customDestinations-ms

    Outputs:
        jumplist_automatic.json
        jumplist_custom.json
        jumplist_errors.json
        jumplist_summary.json

    Note:
        AutomaticDestinations OLE containers are inspected and
        their DestList stream is detected. Full DestList entry
        decoding can be added as an advanced analysis stage.
    """

    AUTOMATIC_PATTERN = re.compile(
        r"^[0-9a-fA-F]{16}\.automaticDestinations-ms$",
        re.IGNORECASE
    )

    CUSTOM_PATTERN = re.compile(
        r"^[0-9a-fA-F]{16}\.customDestinations-ms$",
        re.IGNORECASE
    )

    def analyze(self):

        print(
            "\n[*] Running Windows Jump List Analyzer..."
        )

        automatic_records = []
        custom_records = []
        errors = []

        automatic_files = 0
        custom_files = 0
        parsed_automatic = 0
        identified_custom = 0

        if not self.extracted_data_dir.exists():

            errors.append({
                "stage": "initialization",
                "error": (
                    "Extracted Jump List directory "
                    "does not exist."
                )
            })

            self._write_outputs(
                automatic_records,
                custom_records,
                errors,
                automatic_files,
                custom_files,
                parsed_automatic,
                identified_custom
            )

            return

        # ======================================================
        # DEPENDENCY CHECK
        # ======================================================

        if not OLEFILE_AVAILABLE:

            errors.append({
                "stage": "dependency",
                "error": (
                    "olefile is not installed. "
                    "AutomaticDestinations cannot be inspected."
                )
            })

        # ======================================================
        # SEARCH
        # ======================================================

        for jump_file in self.extracted_data_dir.rglob("*"):

            if not jump_file.is_file():
                continue

            name = jump_file.name

            # --------------------------------------------------
            # Automatic Destinations
            # --------------------------------------------------

            if self.AUTOMATIC_PATTERN.match(name):

                automatic_files += 1

                if not OLEFILE_AVAILABLE:

                    continue

                try:

                    record = self._parse_automatic(
                        jump_file
                    )

                    automatic_records.append(
                        record
                    )

                    if record.get(
                        "parse_status"
                    ) == "parsed":

                        parsed_automatic += 1

                except Exception as exc:

                    errors.append({
                        "file": str(jump_file),
                        "type": "automatic",
                        "stage": "parsing",
                        "error": str(exc)
                    })

            # --------------------------------------------------
            # Custom Destinations
            # --------------------------------------------------

            elif self.CUSTOM_PATTERN.match(name):

                custom_files += 1

                try:

                    record = self._parse_custom(
                        jump_file
                    )

                    custom_records.append(
                        record
                    )

                    identified_custom += 1

                except Exception as exc:

                    errors.append({
                        "file": str(jump_file),
                        "type": "custom",
                        "stage": "parsing",
                        "error": str(exc)
                    })

        # ======================================================
        # OUTPUT
        # ======================================================

        self._write_outputs(
            automatic_records,
            custom_records,
            errors,
            automatic_files,
            custom_files,
            parsed_automatic,
            identified_custom
        )

    # ==========================================================
    # AUTOMATIC DESTINATIONS
    # ==========================================================

    def _parse_automatic(self, jump_file):

        app_id = jump_file.name.split(
            "."
        )[0]

        stat = jump_file.stat()

        record = {

            "source_file": jump_file.name,

            "source_path": str(
                jump_file.relative_to(
                    self.extracted_data_dir
                )
            ),

            "type": "AutomaticDestinations",

            "app_id": app_id,

            "file_size": stat.st_size,

            "filesystem_modified_time": (
                self._file_time(
                    stat.st_mtime
                )
            ),

            "destlist_present": False,

            "destlist_size": 0,

            "streams": []
        }

        # ------------------------------------------------------
        # Verify OLE
        # ------------------------------------------------------

        if not olefile.isOleFile(
            str(jump_file)
        ):

            record["parse_status"] = (
                "not_an_ole_file"
            )

            return record

        # ------------------------------------------------------
        # Read OLE streams
        # ------------------------------------------------------

        with olefile.OleFileIO(
            str(jump_file)
        ) as ole:

            for stream_path in ole.listdir(
                streams=True,
                storages=False
            ):

                stream_name = "/".join(
                    stream_path
                )

                try:

                    stream_size = (
                        ole.get_size(
                            stream_path
                        )
                    )

                except Exception:

                    stream_size = None

                stream_record = {
                    "name": stream_name,
                    "size": stream_size
                }

                # --------------------------------------------------
                # DestList
                # --------------------------------------------------

                if stream_name.lower() == "destlist":

                    record[
                        "destlist_present"
                    ] = True

                    record[
                        "destlist_size"
                    ] = stream_size or 0

                    try:

                        destlist_data = (
                            ole.open(
                                stream_path
                            ).read()
                        )

                        stream_record[
                            "bytes_read"
                        ] = len(
                            destlist_data
                        )

                        stream_record[
                            "header_hex"
                        ] = (
                            destlist_data[
                                :16
                            ].hex()
                        )

                    except Exception as exc:

                        stream_record[
                            "read_error"
                        ] = str(exc)

                record[
                    "streams"
                ].append(
                    stream_record
                )

        record["parse_status"] = "parsed"

        return record

    # ==========================================================
    # CUSTOM DESTINATIONS
    # ==========================================================

    def _parse_custom(self, jump_file):

        app_id = jump_file.name.split(
            "."
        )[0]

        stat = jump_file.stat()

        return {

            "source_file": jump_file.name,

            "source_path": str(
                jump_file.relative_to(
                    self.extracted_data_dir
                )
            ),

            "type": "CustomDestinations",

            "app_id": app_id,

            "file_size": stat.st_size,

            "filesystem_modified_time": (
                self._file_time(
                    stat.st_mtime
                )
            ),

            "parse_status": "identified"
        }

    # ==========================================================
    # OUTPUT
    # ==========================================================

    def _write_outputs(
        self,
        automatic_records,
        custom_records,
        errors,
        automatic_files,
        custom_files,
        parsed_automatic,
        identified_custom
    ):

        if automatic_records:

            self.write_json(
                "jumplist_automatic.json",
                automatic_records
            )

        if custom_records:

            self.write_json(
                "jumplist_custom.json",
                custom_records
            )

        if errors:

            self.write_json(
                "jumplist_errors.json",
                errors
            )

        # ======================================================
        # SUMMARY
        # ======================================================

        total_files = (
            automatic_files
            + custom_files
        )

        summary = {

            "artifact": "Jump Lists",

            "status": (
                "completed_with_errors"
                if errors
                else (
                    "completed"
                    if total_files
                    else "no_artifacts_found"
                )
            ),

            "statistics": {

                "automatic_files_found": (
                    automatic_files
                ),

                "automatic_files_parsed": (
                    parsed_automatic
                ),

                "custom_files_found": (
                    custom_files
                ),

                "custom_files_identified": (
                    identified_custom
                ),

                "total_files_found": (
                    total_files
                ),

                "errors": len(errors)
            },

            "parser": {

                "olefile_available": (
                    OLEFILE_AVAILABLE
                ),

                "automatic_destinations": (
                    OLEFILE_AVAILABLE
                ),

                "custom_destinations": True
            },

            "analysis_capabilities": {

                "automatic_container_inspection": True,

                "destlist_detection": True,

                "destlist_entry_decoding": False,

                "custom_destination_entry_decoding": False
            }
        }

        self.write_json(
            "jumplist_summary.json",
            summary
        )

        print(
            f"  [+] Automatic files: "
            f"{automatic_files}"
        )

        print(
            f"  [+] Custom files: "
            f"{custom_files}"
        )

        print(
            f"  [+] Automatic parsed: "
            f"{parsed_automatic}"
        )

        print(
            f"  [!] Errors: "
            f"{len(errors)}"
        )

    # ==========================================================
    # TIME
    # ==========================================================

    @staticmethod
    def _file_time(timestamp):

        try:

            return datetime.fromtimestamp(
                timestamp,
                tz=timezone.utc
            ).isoformat()

        except Exception:

            return None
