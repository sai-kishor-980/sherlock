from pathlib import Path

from ..base_extractor import BaseExtractor

class JumpListExtractor(BaseExtractor):
    """
    Extract Windows Jump List artifacts.
    Supported artifacts:
        - *.automaticDestinations-ms
        - *.customDestinations-ms

    The extractor preserves only Jump List files rather than
    copying unrelated files from the Recent directory.
    """

    RECENT_PATH = (
        "/Users/{user}/AppData/Roaming/"
        "Microsoft/Windows/Recent"
    )

    AUTOMATIC_DIR = "AutomaticDestinations"
    CUSTOM_DIR = "CustomDestinations"

    AUTOMATIC_SUFFIX = ".automaticdestinations-ms"
    CUSTOM_SUFFIX = ".customdestinations-ms"

    def extract(self):

        output_dir = self.create_output_directory(
            "jump_lists"
        )

        copied_files = 0
        discovered_files = 0
        errors = []

        for user in self.users:

            recent_path = self.RECENT_PATH.format(
                user=user
            )

            # ==================================================
            # AutomaticDestinations
            # ==================================================

            automatic_path = (
                f"{recent_path}/{self.AUTOMATIC_DIR}"
            )

            if self.filesystem.exists(automatic_path):

                (
                    copied,
                    discovered,
                    extraction_errors
                ) = self._extract_jump_lists(
                    source_directory=automatic_path,
                    destination_directory=(
                        output_dir
                        / user
                        / self.AUTOMATIC_DIR
                    ),
                    suffix=self.AUTOMATIC_SUFFIX
                )

                copied_files += copied
                discovered_files += discovered
                errors.extend(extraction_errors)

            # ==================================================
            # CustomDestinations
            # ==================================================

            custom_path = (
                f"{recent_path}/{self.CUSTOM_DIR}"
            )

            if self.filesystem.exists(custom_path):

                (
                    copied,
                    discovered,
                    extraction_errors
                ) = self._extract_jump_lists(
                    source_directory=custom_path,
                    destination_directory=(
                        output_dir
                        / user
                        / self.CUSTOM_DIR
                    ),
                    suffix=self.CUSTOM_SUFFIX
                )

                copied_files += copied
                discovered_files += discovered
                errors.extend(extraction_errors)

        # ======================================================
        # Status
        # ======================================================

        if copied_files:

            status = "SUCCESS"

        elif discovered_files:

            status = "FAILED"

        else:

            status = "SKIPPED"

        message = (
            f"{copied_files} Jump List file(s) extracted."
        )

        if errors:

            message += (
                f" {len(errors)} extraction error(s) recorded."
            )

        result = self.build_result(
            artifact="Jump Lists",
            status=status,
            files=copied_files,
            message=message
        )

        result["discovered_files"] = discovered_files
        result["errors"] = errors

        return result

    # ==========================================================
    # JUMP LIST FILE EXTRACTION
    # ==========================================================

    def _extract_jump_lists(
        self,
        source_directory,
        destination_directory,
        suffix
    ):

        copied_files = 0
        discovered_files = 0
        errors = []

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
            # Only files
            # --------------------------------------------------

            if entry_type != "File":
                continue

            # --------------------------------------------------
            # Only Jump List format
            # --------------------------------------------------

            if not name.lower().endswith(suffix):
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
