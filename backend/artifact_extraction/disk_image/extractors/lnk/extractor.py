from pathlib import Path

from ..base_extractor import BaseExtractor

class LnkExtractor(BaseExtractor):
    """
    Extract Windows Shortcut (.lnk) artifacts.

    ```
    Searches the Windows Recent directory for .lnk files
    and preserves only those files for analysis.
    """

    RECENT_PATH = (
        "/Users/{user}/AppData/Roaming/"
        "Microsoft/Windows/Recent"
    )

    SUPPORTED_EXTENSION = ".lnk"

    def extract(self):

        output_dir = self.create_output_directory(
            "lnk"
        )

        copied_files = 0
        discovered_files = 0
        errors = []

        for user in self.users:

            recent_path = self.RECENT_PATH.format(
                user=user
            )

            if not self.filesystem.exists(
                recent_path
            ):
                continue

            (
                copied,
                discovered,
                extraction_errors
            ) = self._extract_lnk_files(
                source_directory=recent_path,
                destination_directory=(
                    output_dir / user / "Recent"
                ),
                errors=errors
            )

            copied_files += copied
            discovered_files += discovered
            errors.extend(extraction_errors)

        # ======================================================
        # STATUS
        # ======================================================

        if copied_files:

            status = "SUCCESS"

        elif discovered_files:

            status = "FAILED"

        else:

            status = "SKIPPED"

        message = (
            f"{copied_files} LNK file(s) extracted."
        )

        if errors:

            message += (
                f" {len(errors)} extraction error(s) recorded."
            )

        result = self.build_result(
            artifact="LNK",
            status=status,
            files=copied_files,
            message=message
        )

        result["discovered_files"] = discovered_files
        result["errors"] = errors

        return result

    # ==========================================================
    # RECURSIVE SEARCH
    # ==========================================================

    def _extract_lnk_files(
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

        destination_directory.mkdir(
            parents=True,
            exist_ok=True
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
                ) = self._extract_lnk_files(
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

            # --------------------------------------------------
            # Only .lnk files
            # --------------------------------------------------

            if Path(name).suffix.lower() != (
                self.SUPPORTED_EXTENSION
            ):
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
