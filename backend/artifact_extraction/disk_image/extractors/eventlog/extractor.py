from pathlib import Path

from ..base_extractor import BaseExtractor

class EventLogExtractor(BaseExtractor):
    """
    Extract Windows Event Log (.evtx) evidence.
    The extractor preserves only EVTX files rather than copying
    unrelated files from the Windows Event Log directory.
    """

    EVENTLOG_PATH = "/Windows/System32/winevt/Logs"

    SUPPORTED_EXTENSION = ".evtx"

    def extract(self):

        output_dir = self.create_output_directory(
            "event_logs"
        )

        copied_files = 0
        discovered_files = 0
        errors = []

        if not self.filesystem.exists(
            self.EVENTLOG_PATH
        ):

            return self.build_result(
                artifact="Event Logs",
                status="SKIPPED",
                files=0,
                message=(
                    "Windows Event Log directory "
                    "not found."
                )
            )

        # ======================================================
        # Recursively find EVTX files
        # ======================================================

        (
            copied_files,
            discovered_files,
            errors
        ) = self._extract_evtx_files(
            source_directory=self.EVENTLOG_PATH,
            destination_directory=output_dir,
            errors=errors
        )

        # ======================================================
        # Status
        # ======================================================

        if copied_files > 0:

            status = "SUCCESS"

        elif discovered_files > 0:

            status = "FAILED"

        else:

            status = "SKIPPED"

        message = (
            f"{copied_files} EVTX file(s) extracted."
        )

        if errors:

            message += (
                f" {len(errors)} extraction error(s) recorded."
            )

        result = self.build_result(
            artifact="Event Logs",
            status=status,
            files=copied_files,
            message=message
        )

        result["discovered_files"] = discovered_files
        result["errors"] = errors

        return result

    # ==========================================================
    # RECURSIVE EVTX EXTRACTION
    # ==========================================================

    def _extract_evtx_files(
        self,
        source_directory,
        destination_directory,
        errors
    ):

        copied_files = 0
        discovered_files = 0

        try:

            entries = self.filesystem.list_directory(
                source_directory
            )

        except Exception as exc:

            errors.append({
                "directory": source_directory,
                "stage": "directory_listing",
                "error": str(exc)
            })

            return (
                copied_files,
                discovered_files,
                errors
            )

        for entry in entries:

            name = entry.get("name")
            entry_type = entry.get("type")

            if not name:
                continue

            source_path = (
                f"{source_directory}/{name}"
            )

            destination_path = (
                destination_directory / name
            )

            # --------------------------------------------------
            # Directory
            # --------------------------------------------------

            if entry_type == "Directory":

                (
                    copied,
                    discovered,
                    errors
                ) = self._extract_evtx_files(
                    source_directory=source_path,
                    destination_directory=destination_path,
                    errors=errors
                )

                copied_files += copied
                discovered_files += discovered

                continue

            # --------------------------------------------------
            # File
            # --------------------------------------------------

            if entry_type != "File":
                continue

            if Path(name).suffix.lower() != self.SUPPORTED_EXTENSION:
                continue

            discovered_files += 1

            try:

                self.filesystem.copy_file(
                    source_path,
                    str(destination_path)
                )

                copied_files += 1

            except Exception as exc:

                errors.append({
                    "source_file": source_path,
                    "stage": "copy",
                    "error": str(exc)
                })

        return (
            copied_files,
            discovered_files,
            errors
        )