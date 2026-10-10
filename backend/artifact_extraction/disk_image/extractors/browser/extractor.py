from pathlib import Path

from ..base_extractor import BaseExtractor

class BrowserExtractor(BaseExtractor):
    """
    Extract relevant browser forensic databases for all discovered users.

    Supported browsers:
    - Google Chrome
    - Microsoft Edge
    - Mozilla Firefox
    - Brave Browser
    - Opera

    Only databases required by BrowserAnalyzer are copied.
    Entire browser profile directories are intentionally NOT copied.
    """

    CHROMIUM_BROWSERS = {
        "Chrome": "/Users/{user}/AppData/Local/Google/Chrome/User Data",
        "Edge": "/Users/{user}/AppData/Local/Microsoft/Edge/User Data",
        "Brave": "/Users/{user}/AppData/Local/BraveSoftware/Brave-Browser/User Data",
        "Opera": "/Users/{user}/AppData/Roaming/Opera Software/Opera Stable",
    }

    FIREFOX_ROOT = (
        "/Users/{user}/AppData/Roaming/Mozilla/Firefox/Profiles"
    )

    CHROMIUM_DATABASES = {
        "History",
        "Cookies",
        "Web Data",
    }

    FIREFOX_DATABASES = {
        "places.sqlite",
        "cookies.sqlite",
    }

    def extract(self):
        output_dir = self.create_output_directory("browser")

        copied_files = 0
        discovered_files = 0
        errors = []

        users_processed = []

        for user in self.users:

            users_processed.append(user)

            # ==================================================
            # Chromium-based browsers
            # ==================================================

            for browser, root_template in self.CHROMIUM_BROWSERS.items():

                root_path = root_template.format(user=user)

                if not self.filesystem.exists(root_path):
                    continue

                try:
                    copied, discovered, browser_errors = (
                        self._extract_chromium_databases(
                            user=user,
                            browser=browser,
                            root_path=root_path,
                            output_dir=output_dir
                        )
                    )

                    copied_files += copied
                    discovered_files += discovered
                    errors.extend(browser_errors)

                except Exception as exc:

                    errors.append({
                        "user": user,
                        "browser": browser,
                        "stage": "extraction",
                        "error": str(exc)
                    })

            # ==================================================
            # Firefox
            # ==================================================

            firefox_root = self.FIREFOX_ROOT.format(
                user=user
            )

            if self.filesystem.exists(firefox_root):

                try:

                    copied, discovered, firefox_errors = (
                        self._extract_firefox_databases(
                            user=user,
                            root_path=firefox_root,
                            output_dir=output_dir
                        )
                    )

                    copied_files += copied
                    discovered_files += discovered
                    errors.extend(firefox_errors)

                except Exception as exc:

                    errors.append({
                        "user": user,
                        "browser": "Firefox",
                        "stage": "extraction",
                        "error": str(exc)
                    })

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
            f"{copied_files} browser database file(s) copied "
            f"from {len(users_processed)} user profile(s)."
        )

        if errors:
            message += f" {len(errors)} extraction error(s) recorded."

        result = self.build_result(
            artifact="Browser",
            status=status,
            files=copied_files,
            message=message
        )

        # Preserve useful metadata for the analyzer / collector.
        result["users"] = users_processed
        result["discovered_files"] = discovered_files
        result["errors"] = errors

        return result

    # ==========================================================
    # CHROMIUM EXTRACTION
    # ==========================================================

    def _extract_chromium_databases(
        self,
        user,
        browser,
        root_path,
        output_dir
    ):
        copied_files = 0
        discovered_files = 0
        errors = []

        # Chromium can contain multiple profiles:
        #
        # User Data/
        #   History
        #   Cookies
        #   Web Data
        #
        #   Default/
        #       History
        #       Cookies
        #       Web Data
        #
        #   Profile 1/
        #       History
        #       ...

        directories_to_check = [root_path]

        try:

            for entry in self.filesystem.list_directory(
                root_path
            ):

                if entry.get("type") != "Directory":
                    continue

                profile_name = entry.get("name")

                if not profile_name:
                    continue

                profile_path = (
                    f"{root_path}/{profile_name}"
                )

                directories_to_check.append(
                    profile_path
                )

        except Exception as exc:

            errors.append({
                "user": user,
                "browser": browser,
                "stage": "profile_discovery",
                "error": str(exc)
            })

        for profile_path in directories_to_check:

            for database_name in self.CHROMIUM_DATABASES:

                source_path = (
                    f"{profile_path}/{database_name}"
                )

                if not self.filesystem.exists(
                    source_path
                ):
                    continue

                discovered_files += 1

                try:

                    relative_profile = (
                        Path(profile_path).name
                    )

                    destination = (
                        output_dir
                        / user
                        / browser
                        / relative_profile
                        / database_name
                    )

                    self.filesystem.copy_file(
                        source_path,
                        str(destination)
                    )

                    copied_files += 1

                except Exception as exc:

                    errors.append({
                        "user": user,
                        "browser": browser,
                        "database": database_name,
                        "source": source_path,
                        "stage": "copy",
                        "error": str(exc)
                    })

        return (
            copied_files,
            discovered_files,
            errors
        )

    # ==========================================================
    # FIREFOX EXTRACTION
    # ==========================================================

    def _extract_firefox_databases(
        self,
        user,
        root_path,
        output_dir
    ):
        copied_files = 0
        discovered_files = 0
        errors = []

        try:

            profiles = self.filesystem.list_directory(
                root_path
            )

        except Exception as exc:

            return (
                0,
                0,
                [{
                    "user": user,
                    "browser": "Firefox",
                    "stage": "profile_discovery",
                    "error": str(exc)
                }]
            )

        for entry in profiles:

            if entry.get("type") != "Directory":
                continue

            profile_name = entry.get("name")

            if not profile_name:
                continue

            profile_path = (
                f"{root_path}/{profile_name}"
            )

            for database_name in self.FIREFOX_DATABASES:

                source_path = (
                    f"{profile_path}/{database_name}"
                )

                if not self.filesystem.exists(
                    source_path
                ):
                    continue

                discovered_files += 1

                try:

                    destination = (
                        output_dir
                        / user
                        / "Firefox"
                        / profile_name
                        / database_name
                    )

                    self.filesystem.copy_file(
                        source_path,
                        str(destination)
                    )

                    copied_files += 1

                except Exception as exc:

                    errors.append({
                        "user": user,
                        "browser": "Firefox",
                        "profile": profile_name,
                        "database": database_name,
                        "source": source_path,
                        "stage": "copy",
                        "error": str(exc)
                    })

        return (
            copied_files,
            discovered_files,
            errors
        )
