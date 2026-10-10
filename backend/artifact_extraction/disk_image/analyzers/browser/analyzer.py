import json
import shutil
import sqlite3
import tempfile

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from ..base_analyzer import BaseAnalyzer

# ==============================================================

# TIMESTAMP HELPERS

# ==============================================================

def webkit_to_iso(timestamp):
    """
    Convert Chromium/WebKit timestamp.
    WebKit:
        microseconds since 1601-01-01 UTC
    """

    if timestamp in (None, 0):
        return None

    try:
        seconds = (
            timestamp / 1_000_000
        ) - 11644473600

        if seconds < 0:
            return None

        return datetime.fromtimestamp(
                seconds,
            tz=timezone.utc
        ).isoformat()

    except Exception:
        return str(timestamp)

def firefox_time_to_iso(timestamp):
    """
    Convert Firefox PRTime.

    Firefox:
        microseconds since 1970-01-01 UTC
    """

    if timestamp in (None, 0):
        return None

    try:

        seconds = timestamp / 1_000_000

        return datetime.fromtimestamp(
            seconds,
            tz=timezone.utc
        ).isoformat()

    except Exception:
        return str(timestamp)

# ==============================================================

# ANALYZER

# ==============================================================

class BrowserAnalyzer(BaseAnalyzer):
    """
    Analyze extracted browser SQLite databases.

    Produces:
        browser_history.json
        browser_cookies.json
        browser_downloads.json
        browser_autofill.json
        browser_errors.json
        browser_summary.json

    Supported:
        Chromium-based browsers:
            Chrome
            Edge
            Brave
            Opera

        Firefox:
            places.sqlite
            cookies.sqlite
    """

    CHROMIUM_DATABASES = {
        "history",
        "cookies",
        "web data",
    }

    FIREFOX_DATABASES = {
        "places.sqlite",
        "cookies.sqlite",
    }

    def analyze(self):

        print(
            "\n[*] Running Browser Analyzer..."
        )

        history_records = []
        cookie_records = []
        download_records = []
        autofill_records = []
        errors = []

        if not self.extracted_data_dir.exists():

            error = {
                "stage": "initialization",
                "error": (
                    "Extracted browser directory "
                    "does not exist."
                )
            }

            errors.append(error)

            self._write_outputs(
                history_records,
                cookie_records,
                download_records,
                autofill_records,
                errors
            )

            return

        # ======================================================
        # Temporary working directory
        # ======================================================

        with tempfile.TemporaryDirectory() as temp_dir:

            temp_path = Path(temp_dir)

            for file_path in self.extracted_data_dir.rglob("*"):

                if not file_path.is_file():
                    continue

                filename = file_path.name.lower()

                relative_path = (
                    file_path.relative_to(
                        self.extracted_data_dir
                    )
                )

                # Expected structure:
                #
                # user/
                #   browser/
                #       profile/
                #           database
                #
                user_name = (
                    relative_path.parts[0]
                    if len(relative_path.parts) >= 1
                    else "Unknown"
                )

                browser_name = (
                    relative_path.parts[1]
                    if len(relative_path.parts) >= 2
                    else "Unknown"
                )

                profile_name = (
                    relative_path.parts[2]
                    if len(relative_path.parts) >= 3
                    else "Unknown"
                )

                # --------------------------------------------------
                # Copy database into temporary working location.
                # --------------------------------------------------

                temp_db = (
                    temp_path
                    / f"{len(history_records)}_"
                    f"{len(cookie_records)}_"
                    f"{file_path.name}"
                )

                try:

                    shutil.copy2(
                        file_path,
                        temp_db
                    )

                except Exception as exc:

                    errors.append({
                        "user": user_name,
                        "browser": browser_name,
                        "profile": profile_name,
                        "database": file_path.name,
                        "stage": "temporary_copy",
                        "error": str(exc)
                    })

                    continue

                # --------------------------------------------------
                # Chromium
                # --------------------------------------------------

                if filename in self.CHROMIUM_DATABASES:

                    self._parse_chromium_db(
                        db_path=temp_db,
                        user=user_name,
                        browser=browser_name,
                        profile=profile_name,
                        db_type=filename,
                        history=history_records,
                        cookies=cookie_records,
                        downloads=download_records,
                        autofill=autofill_records,
                        errors=errors
                    )

                # --------------------------------------------------
                # Firefox
                # --------------------------------------------------

                elif filename in self.FIREFOX_DATABASES:

                    self._parse_firefox_db(
                        db_path=temp_db,
                        user=user_name,
                        browser=browser_name,
                        profile=profile_name,
                        db_type=filename,
                        history=history_records,
                        cookies=cookie_records,
                        downloads=download_records,
                        errors=errors
                    )

        # ======================================================
        # Final outputs
        # ======================================================

        self._write_outputs(
            history_records,
            cookie_records,
            download_records,
            autofill_records,
            errors
        )

    # ==========================================================
    # CHROMIUM
    # ==========================================================

    def _parse_chromium_db(
        self,
        db_path,
        user,
        browser,
        profile,
        db_type,
        history,
        cookies,
        downloads,
        autofill,
        errors
    ):

        conn = None

        try:

            conn = sqlite3.connect(
                f"file:{db_path}?mode=ro",
                uri=True
            )

            cursor = conn.cursor()

            # --------------------------------------------------
            # HISTORY
            # --------------------------------------------------

            if db_type == "history":

                self._extract_chromium_history(
                    cursor,
                    user,
                    browser,
                    profile,
                    history,
                    errors
                )

                self._extract_chromium_downloads(
                    cursor,
                    user,
                    browser,
                    profile,
                    downloads,
                    errors
                )

            # --------------------------------------------------
            # COOKIES
            # --------------------------------------------------

            elif db_type == "cookies":

                self._extract_chromium_cookies(
                    cursor,
                    user,
                    browser,
                    profile,
                    cookies,
                    errors
                )

            # --------------------------------------------------
            # WEB DATA
            # --------------------------------------------------

            elif db_type == "web data":

                self._extract_chromium_autofill(
                    cursor,
                    user,
                    browser,
                    profile,
                    autofill,
                    errors
                )

        except Exception as exc:

            errors.append({
                "user": user,
                "browser": browser,
                "profile": profile,
                "database": db_type,
                "stage": "database_open",
                "error": str(exc)
            })

        finally:

            if conn:

                try:
                    conn.close()
                except Exception:
                    pass

    # ==========================================================
    # CHROMIUM HISTORY
    # ==========================================================

    def _extract_chromium_history(
        self,
        cursor,
        user,
        browser,
        profile,
        history,
        errors
    ):

        try:

            cursor.execute(
                """
                SELECT
                    url,
                    title,
                    visit_count,
                    typed_count,
                    last_visit_time
                FROM urls
                """
            )

            for row in cursor.fetchall():

                history.append({
                    "user": user,
                    "browser": browser,
                    "profile": profile,
                    "url": row[0],
                    "title": row[1],
                    "visit_count": row[2],
                    "typed_count": row[3],
                    "last_visit_time": webkit_to_iso(row[4])
                })

        except Exception as exc:

            errors.append({
                "user": user,
                "browser": browser,
                "profile": profile,
                "database": "History",
                "artifact": "history",
                "stage": "query",
                "error": str(exc)
            })

    # ==========================================================
    # CHROMIUM DOWNLOADS
    # ==========================================================

    def _extract_chromium_downloads(
        self,
        cursor,
        user,
        browser,
        profile,
        downloads,
        errors
    ):

        try:

            cursor.execute(
                """
                SELECT
                    current_path,
                    target_path,
                    start_time,
                    end_time,
                    total_bytes,
                    site_url
                FROM downloads
                """
            )

            for row in cursor.fetchall():

                downloads.append({
                    "user": user,
                    "browser": browser,
                    "profile": profile,
                    "current_path": row[0],
                    "target_path": row[1],
                    "start_time": webkit_to_iso(row[2]),
                    "end_time": webkit_to_iso(row[3]),
                    "total_bytes": row[4],
                    "site_url": row[5]
                })

        except Exception as exc:

            errors.append({
                "user": user,
                "browser": browser,
                "profile": profile,
                "database": "History",
                "artifact": "downloads",
                "stage": "query",
                "error": str(exc)
            })

    # ==========================================================
    # CHROMIUM COOKIES
    # ==========================================================

    def _extract_chromium_cookies(
        self,
        cursor,
        user,
        browser,
        profile,
        cookies,
        errors
    ):

        try:

            cursor.execute(
                """
                SELECT
                    host_key,
                    name,
                    path,
                    creation_utc,
                    expires_utc,
                    is_secure,
                    is_httponly
                FROM cookies
                """
            )

            for row in cursor.fetchall():

                cookies.append({
                    "user": user,
                    "browser": browser,
                    "profile": profile,
                    "host": row[0],
                    "name": row[1],
                    "path": row[2],
                    "creation_time": webkit_to_iso(row[3]),
                    "expires_time": webkit_to_iso(row[4]),
                    "is_secure": bool(row[5]),
                    "is_httponly": bool(row[6])
                })

        except Exception as exc:

            errors.append({
                "user": user,
                "browser": browser,
                "profile": profile,
                "database": "Cookies",
                "artifact": "cookies",
                "stage": "query",
                "error": str(exc)
            })

    # ==========================================================
    # CHROMIUM AUTOFILL
    # ==========================================================

    def _extract_chromium_autofill(
        self,
        cursor,
        user,
        browser,
        profile,
        autofill,
        errors
    ):

        try:

            cursor.execute(
                """
                SELECT
                    name,
                    value,
                    count,
                    date_created,
                    date_last_used
                FROM autofill
                """
            )

            for row in cursor.fetchall():

                autofill.append({
                    "user": user,
                    "browser": browser,
                    "profile": profile,
                    "field_name": row[0],
                    "value": row[1],
                    "count": row[2],
                    "date_created": webkit_to_iso(row[3]),
                    "date_last_used": webkit_to_iso(row[4])
                })

        except Exception as exc:

            errors.append({
                "user": user,
                "browser": browser,
                "profile": profile,
                "database": "Web Data",
                "artifact": "autofill",
                "stage": "query",
                "error": str(exc)
            })

    # ==========================================================
    # FIREFOX
    # ==========================================================

    def _parse_firefox_db(
        self,
        db_path,
        user,
        browser,
        profile,
        db_type,
        history,
        cookies,
        downloads,
        errors
    ):

        conn = None

        try:

            conn = sqlite3.connect(
                f"file:{db_path}?mode=ro",
                uri=True
            )

            cursor = conn.cursor()

            if db_type == "places.sqlite":

                self._extract_firefox_history(
                    cursor,
                    user,
                    browser,
                    profile,
                    history,
                    errors
                )

                self._extract_firefox_downloads(
                    cursor,
                    user,
                    browser,
                    profile,
                    downloads,
                    errors
                )

            elif db_type == "cookies.sqlite":

                self._extract_firefox_cookies(
                    cursor,
                    user,
                    browser,
                    profile,
                    cookies,
                    errors
                )

        except Exception as exc:

            errors.append({
                "user": user,
                "browser": browser,
                "profile": profile,
                "database": db_type,
                "stage": "database_open",
                "error": str(exc)
            })

        finally:

            if conn:

                try:
                    conn.close()
                except Exception:
                    pass

    # ==========================================================
    # FIREFOX HISTORY
    # ==========================================================

    def _extract_firefox_history(
        self,
        cursor,
        user,
        browser,
        profile,
        history,
        errors
    ):

        try:

            cursor.execute(
                """
                SELECT
                    url,
                    title,
                    visit_count,
                    last_visit_date
                FROM moz_places
                WHERE url IS NOT NULL
                """
            )

            for row in cursor.fetchall():

                history.append({
                    "user": user,
                    "browser": browser,
                    "profile": profile,
                    "url": row[0],
                    "title": row[1],
                    "visit_count": row[2],
                    "typed_count": 0,
                    "last_visit_time": firefox_time_to_iso(
                        row[3]
                    )
                })

        except Exception as exc:

            errors.append({
                "user": user,
                "browser": browser,
                "profile": profile,
                "database": "places.sqlite",
                "artifact": "history",
                "stage": "query",
                "error": str(exc)
            })

    # ==========================================================
    # FIREFOX DOWNLOADS
    # ==========================================================

    def _extract_firefox_downloads(
        self,
        cursor,
        user,
        browser,
        profile,
        downloads,
        errors
    ):

        try:

            cursor.execute(
                """
                SELECT
                    content,
                    place_id,
                    dateAdded
                FROM moz_annos
                WHERE anno_attribute_id IN (
                    SELECT id
                    FROM moz_anno_attributes
                    WHERE name = 'downloads/destinationFileURI'
                )
                """
            )

            for row in cursor.fetchall():

                downloads.append({
                    "user": user,
                    "browser": browser,
                    "profile": profile,
                    "target_path": row[0],
                    "place_id": row[1],
                    "start_time": firefox_time_to_iso(
                        row[2]
                    )
                })

        except Exception as exc:

            errors.append({
                "user": user,
                "browser": browser,
                "profile": profile,
                "database": "places.sqlite",
                "artifact": "downloads",
                "stage": "query",
                "error": str(exc)
            })

    # ==========================================================
    # FIREFOX COOKIES
    # ==========================================================

    def _extract_firefox_cookies(
        self,
        cursor,
        user,
        browser,
        profile,
        cookies,
        errors
    ):

        try:

            cursor.execute(
                """
                SELECT
                    host,
                    name,
                    path,
                    creationTime,
                    expiry,
                    isSecure,
                    isHttpOnly
                FROM moz_cookies
                """
            )

            for row in cursor.fetchall():

                cookies.append({
                    "user": user,
                    "browser": browser,
                    "profile": profile,
                    "host": row[0],
                    "name": row[1],
                    "path": row[2],
                    "creation_time": firefox_time_to_iso(
                        row[3]
                    ),
                    "expires_time": firefox_time_to_iso(
                        row[4] * 1_000_000
                        if row[4]
                        else None
                    ),
                    "is_secure": bool(row[5]),
                    "is_httponly": bool(row[6])
                })

        except Exception as exc:

            errors.append({
                "user": user,
                "browser": browser,
                "profile": profile,
                "database": "cookies.sqlite",
                "artifact": "cookies",
                "stage": "query",
                "error": str(exc)
            })

    # ==========================================================
    # OUTPUTS
    # ==========================================================

    def _write_outputs(
        self,
        history,
        cookies,
        downloads,
        autofill,
        errors
    ):

        if history:
            self.write_json(
                "browser_history.json",
                history
            )

        if cookies:
            self.write_json(
                "browser_cookies.json",
                cookies
            )

        if downloads:
            self.write_json(
                "browser_downloads.json",
                downloads
            )

        if autofill:
            self.write_json(
                "browser_autofill.json",
                autofill
            )

        if errors:
            self.write_json(
                "browser_errors.json",
                errors
            )

        summary = self._build_summary(
            history,
            cookies,
            downloads,
            autofill,
            errors
        )

        self.write_json(
            "browser_summary.json",
            summary
        )

        print(
            f"  [+] History: {len(history)}"
        )

        print(
            f"  [+] Cookies: {len(cookies)}"
        )

        print(
            f"  [+] Downloads: {len(downloads)}"
        )

        print(
            f"  [+] Autofill: {len(autofill)}"
        )

        print(
            f"  [!] Errors: {len(errors)}"
        )

    # ==========================================================
    # SUMMARY
    # ==========================================================

    def _build_summary(
        self,
        history,
        cookies,
        downloads,
        autofill,
        errors
    ):

        users = set()
        browsers = set()

        user_statistics = {}
        browser_statistics = {}

        for collection_name, records in (
            ("history", history),
            ("cookies", cookies),
            ("downloads", downloads),
            ("autofill", autofill)
        ):

            for record in records:

                user = record.get(
                    "user",
                    "Unknown"
                )

                browser = record.get(
                    "browser",
                    "Unknown"
                )

                users.add(user)
                browsers.add(browser)

                user_statistics.setdefault(
                    user,
                    {
                        "history": 0,
                        "cookies": 0,
                        "downloads": 0,
                        "autofill": 0
                    }
                )

                browser_statistics.setdefault(
                    browser,
                    {
                        "history": 0,
                        "cookies": 0,
                        "downloads": 0,
                        "autofill": 0
                    }
                )

                user_statistics[user][
                    collection_name
                ] += 1

                browser_statistics[browser][
                    collection_name
                ] += 1

        if errors:

            status = (
                "completed_with_errors"
                if (
                    history
                    or cookies
                    or downloads
                    or autofill
                )
                else "failed"
            )

        elif (
            history
            or cookies
            or downloads
            or autofill
        ):

            status = "completed"

        else:

            status = "no_artifacts_found"

        return {
            "artifact": "Browser",

            "status": status,

            "statistics": {
                "history": len(history),
                "cookies": len(cookies),
                "downloads": len(downloads),
                "autofill": len(autofill)
            },

            "users": sorted(users),

            "browsers": sorted(browsers),

            "user_statistics": user_statistics,

            "browser_statistics": browser_statistics,

            "errors": {
                "count": len(errors),
                "available": bool(errors)
            }
        }
