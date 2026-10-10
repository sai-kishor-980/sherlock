from pathlib import Path

from ..base_analyzer import BaseAnalyzer

# ==============================================================

# Optional Registry Parser

# ==============================================================

try:
    from regipy.registry import RegistryHive
    REGIPY_AVAILABLE = True
except ImportError:
    REGIPY_AVAILABLE = False

class RegistryAnalyzer(BaseAnalyzer):
    """
    Windows Registry forensic analyzer.
    Current analysis modules:

        1. Installed Software
        2. USB Devices
        3. Run Keys / Persistence
        4. Recent Documents

    Input:

        Extracted registry hives

    Outputs:

        installed_software.json
        usb_devices.json
        run_keys.json
        recent_files.json
        registry_summary.json
        registry_errors.json
    """

    # ==========================================================
    # ENTRY POINT
    # ==========================================================

    def analyze(self):

        print(
            "\n[*] Running Registry Analyzer..."
        )

        if not self.extracted_data_dir.exists():

            self._write_summary(
                status="NO_DATA",
                statistics={
                    "hives_found": 0,
                    "hives_processed": 0,
                    "installed_software": 0,
                    "usb_devices": 0,
                    "run_keys": 0,
                    "recent_files": 0,
                    "errors": 1
                },
                errors=[
                    {
                        "stage": "initialization",
                        "error": (
                            "Extracted registry directory "
                            "does not exist."
                        )
                    }
                ]
            )

            return

        # ======================================================
        # LIBRARY CHECK
        # ======================================================

        if not REGIPY_AVAILABLE:

            print(
                "  [-] Regipy is not installed."
            )

            self._write_summary(
                status="PARSER_UNAVAILABLE",
                statistics={
                    "hives_found": 0,
                    "hives_processed": 0,
                    "installed_software": 0,
                    "usb_devices": 0,
                    "run_keys": 0,
                    "recent_files": 0,
                    "errors": 1
                },
                errors=[
                    {
                        "stage": "initialization",
                        "error": (
                            "regipy library is not installed."
                        )
                    }
                ]
            )

            return

        # ======================================================
        # DISCOVER HIVES
        # ======================================================

        hives = [
            file
            for file in self.extracted_data_dir.iterdir()
            if file.is_file()
        ]

        # ======================================================
        # RESULT CONTAINERS
        # ======================================================

        installed_software = []
        usb_devices = []
        run_keys = []
        recent_files = []

        errors = []

        processed_hives = 0

        # ======================================================
        # SOFTWARE HIVE
        # ======================================================

        software_hive = (
            self.extracted_data_dir / "SOFTWARE"
        )

        if software_hive.exists():

            print(
                "  -> Parsing Installed Software..."
            )

            try:

                records = (
                    self._parse_installed_software(
                        software_hive
                    )
                )

                installed_software.extend(
                    records
                )

                processed_hives += 1

            except Exception as exc:

                errors.append({
                    "hive": "SOFTWARE",
                    "artifact": "installed_software",
                    "error": str(exc)
                })

        # ======================================================
        # USB DEVICES
        # ======================================================

        system_hive = (
            self.extracted_data_dir / "SYSTEM"
        )

        if system_hive.exists():

            print(
                "  -> Parsing USB Devices..."
            )

            try:

                records = (
                    self._parse_usb_devices(
                        system_hive
                    )
                )

                usb_devices.extend(
                    records
                )

                processed_hives += 1

            except Exception as exc:

                errors.append({
                    "hive": "SYSTEM",
                    "artifact": "usb_devices",
                    "error": str(exc)
                })

        # ======================================================
        # RUN KEYS + RECENT FILES
        # ======================================================

        for hive_path in self.extracted_data_dir.glob(
            "*_NTUSER.DAT"
        ):

            print(
                f"  -> Parsing {hive_path.name}..."
            )

            # --------------------------------------------------
            # Run Keys
            # --------------------------------------------------

            try:

                records = (
                    self._extract_run_keys(
                        hive_path
                    )
                )

                run_keys.extend(
                    records
                )

            except Exception as exc:

                errors.append({
                    "hive": hive_path.name,
                    "artifact": "run_keys",
                    "error": str(exc)
                })

            # --------------------------------------------------
            # Recent Documents
            # --------------------------------------------------

            try:

                records = (
                    self._extract_recent_files(
                        hive_path
                    )
                )

                recent_files.extend(
                    records
                )

            except Exception as exc:

                errors.append({
                    "hive": hive_path.name,
                    "artifact": "recent_files",
                    "error": str(exc)
                })

            processed_hives += 1

        # ======================================================
        # SOFTWARE RUN KEYS
        # ======================================================

        if software_hive.exists():

            try:

                records = (
                    self._extract_run_keys(
                        software_hive
                    )
                )

                run_keys.extend(
                    records
                )

            except Exception as exc:

                errors.append({
                    "hive": "SOFTWARE",
                    "artifact": "run_keys",
                    "error": str(exc)
                })

        # ======================================================
        # WRITE ARTIFACT OUTPUTS
        # ======================================================

        if installed_software:

            self.write_json(
                "installed_software.json",
                installed_software
            )

        if usb_devices:

            self.write_json(
                "usb_devices.json",
                usb_devices
            )

        if run_keys:

            self.write_json(
                "run_keys.json",
                run_keys
            )

        if recent_files:

            self.write_json(
                "recent_files.json",
                recent_files
            )

        # ======================================================
        # SUMMARY
        # ======================================================

        if errors:

            status = (
                "COMPLETED_WITH_ERRORS"
                if processed_hives > 0
                else "FAILED"
            )

        elif processed_hives > 0:

            status = "SUCCESS"

        else:

            status = "NO_ARTIFACTS"

        summary = {

            "artifact": "Windows Registry",

            "status": status,

            "parser": {
                "library": "regipy",
                "available": REGIPY_AVAILABLE
            },

            "statistics": {

                "hives_found": len(hives),

                "hives_processed": (
                    processed_hives
                ),

                "installed_software": (
                    len(installed_software)
                ),

                "usb_devices": (
                    len(usb_devices)
                ),

                "run_keys": (
                    len(run_keys)
                ),

                "recent_files": (
                    len(recent_files)
                ),

                "errors": len(errors)
            },

            "capabilities": {

                "installed_software": True,

                "usb_devices": True,

                "persistence_run_keys": True,

                "recent_documents": True,

                "user_hive_analysis": True,

                "system_hive_analysis": True,

                "amcache_analysis": False,

                "shellbags_analysis": False,

                "userassist_analysis": False,

                "bam_analysis": False,

                "services_analysis": False
            }
        }

        self.write_json(
            "registry_summary.json",
            summary
        )

        # ======================================================
        # ERRORS
        # ======================================================

        if errors:

            self.write_json(
                "registry_errors.json",
                errors
            )

        # ======================================================
        # CONSOLE
        # ======================================================

        print(
            "\n[+] Registry Analysis Complete."
        )

        print(
            f"    Installed Software : "
            f"{len(installed_software)}"
        )

        print(
            f"    USB Devices        : "
            f"{len(usb_devices)}"
        )

        print(
            f"    Run Keys            : "
            f"{len(run_keys)}"
        )

        print(
            f"    Recent Files        : "
            f"{len(recent_files)}"
        )

        print(
            f"    Errors              : "
            f"{len(errors)}"
        )

    # ==========================================================
    # INSTALLED SOFTWARE
    # ==========================================================

    def _parse_installed_software(
        self,
        hive_path
    ):

        hive = RegistryHive(
            str(hive_path)
        )

        uninstall_keys = (
            self._find_uninstall_keys(
                hive.root
            )
        )

        software = []

        for uninstall in uninstall_keys:

            for program in uninstall.iter_subkeys():

                entry = {
                    "source_hive": hive_path.name,
                    "registry_key": program.name,
                    "values": {}
                }

                try:

                    for value in program.iter_values():

                        entry["values"][
                            value.name
                        ] = self._normalize(
                            value.value
                        )

                    if entry["values"]:

                        software.append(
                            entry
                        )

                except Exception:
                    continue

        return software

    # ==========================================================
    # FIND UNINSTALL KEYS
    # ==========================================================

    def _find_uninstall_keys(
        self,
        key,
        path="",
        results=None
    ):

        if results is None:
            results = []

        current = (
            f"{path}\\{key.name}"
            if path
            else key.name
        )

        normalized = current.lower()

        targets = [
            (
                r"microsoft\windows\currentversion"
                r"\uninstall"
            ),
            (
                r"wow6432node\microsoft\windows"
                r"\currentversion\uninstall"
            )
        ]

        for target in targets:

            if normalized.endswith(
                target.lower()
            ):

                results.append(key)

        try:

            for subkey in key.iter_subkeys():

                self._find_uninstall_keys(
                    subkey,
                    current,
                    results
                )

        except Exception:
            pass

        return results

    # ==========================================================
    # USB DEVICES
    # ==========================================================

    def _parse_usb_devices(
        self,
        hive_path
    ):

        hive = RegistryHive(
            str(hive_path)
        )

        usbstor_keys = (
            self._find_usbstor_key(
                hive.root
            )
        )

        devices = []

        for usbstor in usbstor_keys:

            try:

                for device_type in (
                    usbstor.iter_subkeys()
                ):

                    for device in (
                        device_type.iter_subkeys()
                    ):

                        values = {}

                        try:

                            for value in (
                                device.iter_values()
                            ):

                                values[
                                    value.name
                                ] = self._normalize(
                                    value.value
                                )

                        except Exception:
                            pass

                        devices.append({

                            "source_hive": (
                                hive_path.name
                            ),

                            "device_type": (
                                device_type.name
                            ),

                            "serial_number": (
                                device.name
                            ),

                            "values": values
                        })

            except Exception:
                continue

        return devices

    # ==========================================================
    # FIND USBSTOR
    # ==========================================================

    def _find_usbstor_key(
        self,
        key,
        path="",
        result=None
    ):

        if result is None:
            result = []

        current = (
            f"{path}\\{key.name}"
            if path
            else key.name
        )

        target = (
            r"controlset001\enum\usbstor"
        )

        if current.lower().endswith(
            target
        ):

            result.append(key)

        try:

            for subkey in key.iter_subkeys():

                self._find_usbstor_key(
                    subkey,
                    current,
                    result
                )

        except Exception:
            pass

        return result

    # ==========================================================
    # RUN KEYS
    # ==========================================================

    def _extract_run_keys(
        self,
        hive_path
    ):

        hive = RegistryHive(
            str(hive_path)
        )

        keys = (
            self._find_run_keys(
                hive.root
            )
        )

        output = []

        for key in keys:

            try:

                for value in key.iter_values():

                    output.append({

                        "source_hive": (
                            hive_path.name
                        ),

                        "registry_key": (
                            key.name
                        ),

                        "name": (
                            value.name
                        ),

                        "command": (
                            self._normalize(
                                value.value
                            )
                        )
                    })

            except Exception:
                continue

        return output

    # ==========================================================
    # FIND RUN KEYS
    # ==========================================================

    def _find_run_keys(
        self,
        key,
        path="",
        results=None
    ):

        if results is None:
            results = []

        current = (
            f"{path}\\{key.name}"
            if path
            else key.name
        )

        targets = [

            r"microsoft\windows"
            r"\currentversion\run",

            r"microsoft\windows"
            r"\currentversion\runonce",

            r"software\microsoft\windows"
            r"\currentversion\run",

            r"software\microsoft\windows"
            r"\currentversion\runonce"
        ]

        normalized = current.lower()

        for target in targets:

            if normalized.endswith(
                target
            ):

                results.append(key)

        try:

            for subkey in key.iter_subkeys():

                self._find_run_keys(
                    subkey,
                    current,
                    results
                )

        except Exception:
            pass

        return results

    # ==========================================================
    # RECENT FILES
    # ==========================================================

    def _extract_recent_files(
        self,
        hive_path
    ):

        hive = RegistryHive(
            str(hive_path)
        )

        recent_keys = (
            self._find_recentdocs(
                hive.root
            )
        )

        recent_files = []

        for key in recent_keys:

            try:

                for value in key.iter_values():

                    recent_files.append({

                        "source_hive": (
                            hive_path.name
                        ),

                        "registry_key": (
                            key.name
                        ),

                        "value_name": (
                            value.name
                        ),

                        "data": (
                            self._normalize(
                                value.value
                            )
                        )
                    })

            except Exception:
                continue

        return recent_files

    # ==========================================================
    # FIND RECENTDOCS
    # ==========================================================

    def _find_recentdocs(
        self,
        key,
        path="",
        results=None
    ):

        if results is None:
            results = []

        current = (
            f"{path}\\{key.name}"
            if path
            else key.name
        )

        target = (
            r"software\microsoft\windows"
            r"\currentversion\explorer\recentdocs"
        )

        if current.lower().endswith(
            target
        ):

            results.append(key)

        try:

            for subkey in key.iter_subkeys():

                self._find_recentdocs(
                    subkey,
                    current,
                    results
                )

        except Exception:
            pass

        return results

    # ==========================================================
    # NORMALIZE REGISTRY VALUES
    # ==========================================================

    def _normalize(
        self,
        value
    ):

        if value is None:
            return None

        if isinstance(
            value,
            (
                str,
                int,
                float,
                bool
            )
        ):

            return value

        if isinstance(
            value,
            bytes
        ):

            return value.hex()

        if isinstance(
            value,
            dict
        ):

            return {
                str(key): self._normalize(
                    val
                )
                for key, val in value.items()
            }

        if isinstance(
            value,
            (list, tuple)
        ):

            return [
                self._normalize(
                    item
                )
                for item in value
            ]

        return str(value)

    # ==========================================================
    # SUMMARY
    # ==========================================================

    def _write_summary(
        self,
        status,
        statistics,
        errors
    ):

        summary = {

            "artifact": (
                "Windows Registry"
            ),

            "status": status,

            "parser": {
                "library": "regipy",
                "available": REGIPY_AVAILABLE
            },

            "statistics": statistics
        }

        self.write_json(
            "registry_summary.json",
            summary
        )

        if errors:

            self.write_json(
                "registry_errors.json",
                errors
            )
