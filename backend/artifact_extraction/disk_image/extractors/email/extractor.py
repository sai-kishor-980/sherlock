from pathlib import Path

from ..base_extractor import BaseExtractor

class EmailExtractor(BaseExtractor):
    """
    Extract email artifacts for all discovered users.

    Currently targeted evidence:
    - EML
    - MSG
    - MBOX
    - PST / OST (detected and copied, but not parsed by the
      current analyzer)

    Sources:
    - Microsoft Outlook
    - Mozilla Thunderbird
    - Windows Mail
    """

    OUTLOOK_PATH = (
        "/Users/{user}/AppData/Local/Microsoft/Outlook"
    )

    THUNDERBIRD_PATH = (
        "/Users/{user}/AppData/Roaming/Thunderbird/Profiles"
    )

    WINDOWS_MAIL_PATH = (
        "/Users/{user}/AppData/Local/Microsoft/Windows Mail"
    )

    SUPPORTED_FILES = {
        ".eml",
        ".msg",
        ".mbox",
    }

    DETECTED_BUT_UNSUPPORTED = {
        ".pst",
        ".ost",
    }

    def extract(self):

        output_dir = self.create_output_directory("email")

        copied_files = 0
        discovered_files = 0

        supported_files = 0
        unsupported_files = 0

        errors = []

        for user in self.users:

            # ==================================================
            # Outlook
            # ==================================================

            outlook_dir = self.OUTLOOK_PATH.format(
                user=user
            )

            if self.filesystem.exists(outlook_dir):

                copied, discovered, unsupported, extraction_errors = (
                    self._extract_directory_files(
                        source_directory=outlook_dir,
                        destination_directory=(
                            output_dir / user / "Outlook"
                        ),
                        user=user,
                        source_type="Outlook"
                    )
                )

                copied_files += copied
                discovered_files += discovered
                unsupported_files += unsupported
                errors.extend(extraction_errors)

            # ==================================================
            # Thunderbird
            # ==================================================

            thunderbird_dir = self.THUNDERBIRD_PATH.format(
                user=user
            )

            if self.filesystem.exists(thunderbird_dir):

                copied, discovered, unsupported, extraction_errors = (
                    self._extract_directory_files(
                        source_directory=thunderbird_dir,
                        destination_directory=(
                            output_dir / user / "Thunderbird"
                        ),
                        user=user,
                        source_type="Thunderbird"
                    )
                )

                copied_files += copied
                discovered_files += discovered
                unsupported_files += unsupported
                errors.extend(extraction_errors)

            # ==================================================
            # Windows Mail
            # ==================================================

            windows_mail_dir = self.WINDOWS_MAIL_PATH.format(
                user=user
            )

            if self.filesystem.exists(windows_mail_dir):

                copied, discovered, unsupported, extraction_errors = (
                    self._extract_directory_files(
                        source_directory=windows_mail_dir,
                        destination_directory=(
                            output_dir / user / "WindowsMail"
                        ),
                        user=user,
                        source_type="WindowsMail"
                    )
                )

                copied_files += copied
                discovered_files += discovered
                unsupported_files += unsupported
                errors.extend(extraction_errors)

        # ======================================================
        # Status
        # ======================================================

        if copied_files > 0:
            status = "SUCCESS"

        elif unsupported_files > 0:
            status = "PARTIAL"

        else:
            status = "SKIPPED"

        message = (
            f"{copied_files} supported email file(s) extracted."
        )

        if unsupported_files:
            message += (
                f" {unsupported_files} PST/OST file(s) detected "
                "but not parsed by the current analyzer."
            )

        if errors:
            message += (
                f" {len(errors)} extraction error(s) recorded."
            )

        result = self.build_result(
            artifact="Email",
            status=status,
            files=copied_files,
            message=message
        )

        result["discovered_files"] = discovered_files
        result["supported_files"] = copied_files
        result["unsupported_files"] = unsupported_files
        result["errors"] = errors

        return result

    # ==========================================================
    # DIRECTORY WALK
    # ==========================================================

    def _extract_directory_files(
        self,
        source_directory,
        destination_directory,
        user,
        source_type
    ):

        copied_files = 0
        discovered_files = 0
        unsupported_files = 0

        errors = []

        try:

            entries = self.filesystem.list_directory(
                source_directory
            )

        except Exception as exc:

            return (
                0,
                0,
                0,
                [{
                    "user": user,
                    "source": source_type,
                    "stage": "directory_listing",
                    "error": str(exc)
                }]
            )

        # We need recursive traversal because Thunderbird and
        # Windows Mail may contain nested directories.

        copied_files, discovered_files, unsupported_files, errors = (
            self._walk_directory(
                source_directory=source_directory,
                destination_directory=destination_directory,
                user=user,
                source_type=source_type,
                errors=errors
            )
        )

        return (
            copied_files,
            discovered_files,
            unsupported_files,
            errors
        )

    # ==========================================================
    # RECURSIVE WALK
    # ==========================================================

    def _walk_directory(
        self,
        source_directory,
        destination_directory,
        user,
        source_type,
        errors
    ):

        copied_files = 0
        discovered_files = 0
        unsupported_files = 0

        try:

            entries = self.filesystem.list_directory(
                source_directory
            )

        except Exception as exc:

            errors.append({
                "user": user,
                "source": source_type,
                "directory": source_directory,
                "stage": "directory_listing",
                "error": str(exc)
            })

            return (
                0,
                0,
                0,
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
                    unsupported,
                    errors
                ) = self._walk_directory(
                    source_directory=source_path,
                    destination_directory=destination_path,
                    user=user,
                    source_type=source_type,
                    errors=errors
                )

                copied_files += copied
                discovered_files += discovered
                unsupported_files += unsupported

                continue

            # --------------------------------------------------
            # File
            # --------------------------------------------------

            if entry_type != "File":
                continue

            suffix = Path(name).suffix.lower()

            # --------------------------------------------------
            # Supported email file
            # --------------------------------------------------

            if suffix in self.SUPPORTED_FILES:

                discovered_files += 1

                try:

                    self.filesystem.copy_file(
                        source_path,
                        str(destination_path)
                    )

                    copied_files += 1

                except Exception as exc:

                    errors.append({
                        "user": user,
                        "source": source_type,
                        "file": source_path,
                        "stage": "copy",
                        "error": str(exc)
                    })

            # --------------------------------------------------
            # PST / OST
            # --------------------------------------------------

            elif suffix in self.DETECTED_BUT_UNSUPPORTED:

                discovered_files += 1
                unsupported_files += 1

                # Copy them so the evidence is preserved for
                # future PST/OST analysis.

                try:

                    self.filesystem.copy_file(
                        source_path,
                        str(destination_path)
                    )

                    copied_files += 1

                except Exception as exc:

                    errors.append({
                        "user": user,
                        "source": source_type,
                        "file": source_path,
                        "stage": "copy",
                        "error": str(exc)
                    })

        return (
            copied_files,
            discovered_files,
            unsupported_files,
            errors
        )
