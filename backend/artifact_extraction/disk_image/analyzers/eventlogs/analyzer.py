import json
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

from ..base_analyzer import BaseAnalyzer

try:
    import Evtx.Evtx as evtx
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False

class EventLogsAnalyzer(BaseAnalyzer):
    """Analyze Windows Event Log (.evtx) evidence.
    High-value categories currently supported:
    - Logon events:
        4624, 4625, 4672, 4634
    - Process creation:
        4688, Sysmon Event 1
    - Service installation:
        7045
    - PowerShell:
        4104
    - RDP:
        21, 22, 25
    Outputs:
        security_logons.json
        process_creations.json
        services_installed.json
        powershell_activity.json
        rdp_sessions.json
        eventlogs_errors.json
        eventlogs_summary.json
    """

    LOGON_EVENTS = {
        4624,
        4625,
        4672,
        4634
    }

    PROCESS_CREATION_EVENTS = {
        4688,
        1
    }

    SERVICE_EVENTS = {
        7045
    }

    POWERSHELL_EVENTS = {
        4104
    }

    RDP_EVENTS = {
        21,
        22,
        25
    }

    def analyze(self):

        print(
            "\n[*] Running Windows Event Logs Analyzer..."
        )

        logons = []
        process_creations = []
        services = []
        powershell_scripts = []
        rdp_sessions = []

        errors = []

        processed_files = 0
        total_records = 0

        event_id_counter = Counter()
        provider_counter = Counter()

        if not self.extracted_data_dir.exists():

            errors.append({
                "stage": "initialization",
                "error": (
                    "Extracted event log directory "
                    "does not exist."
                )
            })

            self._write_outputs(
                logons,
                process_creations,
                services,
                powershell_scripts,
                rdp_sessions,
                errors,
                processed_files,
                total_records,
                event_id_counter,
                provider_counter
            )

            return

        # ======================================================
        # EVTX LIBRARY CHECK
        # ======================================================

        if not EVTX_AVAILABLE:

            errors.append({
                "stage": "dependency",
                "error": (
                    "python-evtx / Evtx library is not installed."
                )
            })

            self._write_outputs(
                logons,
                process_creations,
                services,
                powershell_scripts,
                rdp_sessions,
                errors,
                processed_files,
                total_records,
                event_id_counter,
                provider_counter
            )

            return

        # ======================================================
        # PROCESS EVTX FILES
        # ======================================================

        for evtx_file in self.extracted_data_dir.rglob(
            "*.evtx"
        ):

            if not evtx_file.is_file():
                continue

            processed_files += 1

            (
                records,
                file_errors
            ) = self._parse_evtx_file(
                evtx_file,
                logons,
                process_creations,
                services,
                powershell_scripts,
                rdp_sessions,
                event_id_counter,
                provider_counter
            )

            total_records += records
            errors.extend(file_errors)

        # ======================================================
        # WRITE OUTPUTS
        # ======================================================

        self._write_outputs(
            logons,
            process_creations,
            services,
            powershell_scripts,
            rdp_sessions,
            errors,
            processed_files,
            total_records,
            event_id_counter,
            provider_counter
        )

    # ==========================================================
    # EVTX PARSER
    # ==========================================================

    def _parse_evtx_file(
        self,
        evtx_file,
        logons,
        process_creations,
        services,
        powershell_scripts,
        rdp_sessions,
        event_id_counter,
        provider_counter
    ):

        processed_records = 0
        errors = []

        try:

            with evtx.Evtx(
                str(evtx_file)
            ) as log:

                for record in log.records():

                    processed_records += 1

                    try:

                        xml_str = record.xml()

                        root = ET.fromstring(
                            xml_str
                        )

                        # ------------------------------------------
                        # Namespace handling
                        # ------------------------------------------

                        ns = ""

                        if root.tag.startswith("{"):

                            ns = (
                                root.tag.split("}")[0]
                                + "}"
                            )

                        system = root.find(
                            f"{ns}System"
                        )

                        if system is None:
                            continue

                        # ------------------------------------------
                        # Event ID
                        # ------------------------------------------

                        event_id_elem = system.find(
                            f"{ns}EventID"
                        )

                        event_id = 0

                        if (
                            event_id_elem is not None
                            and event_id_elem.text
                        ):

                            try:

                                event_id = int(
                                    event_id_elem.text
                                )

                            except ValueError:

                                event_id = 0

                        event_id_counter[
                            str(event_id)
                        ] += 1

                        # ------------------------------------------
                        # Timestamp
                        # ------------------------------------------

                        time_elem = system.find(
                            f"{ns}TimeCreated"
                        )

                        timestamp = None

                        if time_elem is not None:

                            timestamp = (
                                time_elem.attrib.get(
                                    "SystemTime"
                                )
                            )

                        # ------------------------------------------
                        # Provider
                        # ------------------------------------------

                        provider_elem = system.find(
                            f"{ns}Provider"
                        )

                        provider = ""

                        if provider_elem is not None:

                            provider = (
                                provider_elem.attrib.get(
                                    "Name",
                                    ""
                                )
                            )

                        if provider:

                            provider_counter[
                                provider
                            ] += 1

                        # ------------------------------------------
                        # Channel
                        # ------------------------------------------

                        channel_elem = system.find(
                            f"{ns}Channel"
                        )

                        channel = ""

                        if channel_elem is not None:

                            channel = (
                                channel_elem.text or ""
                            )

                        # ------------------------------------------
                        # Event Data
                        # ------------------------------------------

                        event_data = (
                            self._extract_event_data(
                                root,
                                ns
                            )
                        )

                        # ------------------------------------------
                        # Logon Events
                        # ------------------------------------------

                        if event_id in self.LOGON_EVENTS:

                            logons.append({

                                "file": evtx_file.name,

                                "timestamp": timestamp,

                                "event_id": event_id,

                                "provider": provider,

                                "channel": channel,

                                "target_username": (
                                    event_data.get(
                                        "TargetUserName",
                                        event_data.get(
                                            "SubjectUserName",
                                            ""
                                        )
                                    )
                                ),

                                "target_domain": (
                                    event_data.get(
                                        "TargetDomainName",
                                        event_data.get(
                                            "SubjectDomainName",
                                            ""
                                        )
                                    )
                                ),

                                "logon_type": (
                                    event_data.get(
                                        "LogonType",
                                        ""
                                    )
                                ),

                                "ip_address": (
                                    event_data.get(
                                        "IpAddress",
                                        event_data.get(
                                            "WorkstationName",
                                            ""
                                        )
                                    )
                                ),

                                "workstation": (
                                    event_data.get(
                                        "WorkstationName",
                                        ""
                                    )
                                )
                            })

                        # ------------------------------------------
                        # Process Creation
                        # ------------------------------------------

                        elif (
                            event_id
                            in self.PROCESS_CREATION_EVENTS
                        ):

                            process_creations.append({

                                "file": evtx_file.name,

                                "timestamp": timestamp,

                                "event_id": event_id,

                                "provider": provider,

                                "channel": channel,

                                "new_process": (
                                    event_data.get(
                                        "NewProcessName",
                                        event_data.get(
                                            "Image",
                                            ""
                                        )
                                    )
                                ),

                                "parent_process": (
                                    event_data.get(
                                        "ParentProcessName",
                                        event_data.get(
                                            "ParentImage",
                                            ""
                                        )
                                    )
                                ),

                                "command_line": (
                                    event_data.get(
                                        "CommandLine",
                                        ""
                                    )
                                ),

                                "user": (
                                    event_data.get(
                                        "TargetUserName",
                                        event_data.get(
                                            "User",
                                            ""
                                        )
                                    )
                                )
                            })

                        # ------------------------------------------
                        # Service Installation
                        # ------------------------------------------

                        elif event_id in self.SERVICE_EVENTS:

                            services.append({

                                "file": evtx_file.name,

                                "timestamp": timestamp,

                                "event_id": event_id,

                                "provider": provider,

                                "channel": channel,

                                "service_name": (
                                    event_data.get(
                                        "ServiceName",
                                        ""
                                    )
                                ),

                                "image_path": (
                                    event_data.get(
                                        "ImagePath",
                                        ""
                                    )
                                ),

                                "service_type": (
                                    event_data.get(
                                        "ServiceType",
                                        ""
                                    )
                                ),

                                "start_type": (
                                    event_data.get(
                                        "StartType",
                                        ""
                                    )
                                ),

                                "user": (
                                    event_data.get(
                                        "AccountName",
                                        ""
                                    )
                                )
                            })

                        # ------------------------------------------
                        # PowerShell
                        # ------------------------------------------

                        elif (
                            event_id
                            in self.POWERSHELL_EVENTS
                        ):

                            powershell_scripts.append({

                                "file": evtx_file.name,

                                "timestamp": timestamp,

                                "event_id": event_id,

                                "provider": provider,

                                "channel": channel,

                                "script_block_text": (
                                    event_data.get(
                                        "ScriptBlockText",
                                        ""
                                    )[:5000]
                                ),

                                "script_path": (
                                    event_data.get(
                                        "Path",
                                        ""
                                    )
                                ),

                                "user": (
                                    event_data.get(
                                        "User",
                                        ""
                                    )
                                )
                            })

                        # ------------------------------------------
                        # RDP
                        # ------------------------------------------

                        elif event_id in self.RDP_EVENTS:

                            rdp_sessions.append({

                                "file": evtx_file.name,

                                "timestamp": timestamp,

                                "event_id": event_id,

                                "provider": provider,

                                "channel": channel,

                                "user": (
                                    event_data.get(
                                        "User",
                                        ""
                                    )
                                ),

                                "session_id": (
                                    event_data.get(
                                        "SessionID",
                                        ""
                                    )
                                ),

                                "source_ip": (
                                    event_data.get(
                                        "ClientIP",
                                        ""
                                    )
                                )
                            })

                    except Exception as exc:

                        errors.append({
                            "file": evtx_file.name,
                            "record": processed_records,
                            "stage": "record_parsing",
                            "error": str(exc)
                        })

        except Exception as exc:

            errors.append({
                "file": evtx_file.name,
                "stage": "evtx_open",
                "error": str(exc)
            })

        return (
            processed_records,
            errors
        )

    # ==========================================================
    # EVENT DATA EXTRACTION
    # ==========================================================

    @staticmethod
    def _extract_event_data(
        root,
        namespace
    ):

        event_data = {}

        event_data_node = root.find(
            f"{namespace}EventData"
        )

        if event_data_node is None:
            return event_data

        for data in event_data_node.findall(
            f"{namespace}Data"
        ):

            name = data.attrib.get(
                "Name"
            )

            text = data.text or ""

            if name:
                event_data[name] = text

        return event_data

    # ==========================================================
    # OUTPUT
    # ==========================================================

    def _write_outputs(
        self,
        logons,
        process_creations,
        services,
        powershell_scripts,
        rdp_sessions,
        errors,
        processed_files,
        total_records,
        event_id_counter,
        provider_counter
    ):

        if logons:

            self.write_json(
                "security_logons.json",
                logons
            )

        if process_creations:

            self.write_json(
                "process_creations.json",
                process_creations
            )

        if services:

            self.write_json(
                "services_installed.json",
                services
            )

        if powershell_scripts:

            self.write_json(
                "powershell_activity.json",
                powershell_scripts
            )

        if rdp_sessions:

            self.write_json(
                "rdp_sessions.json",
                rdp_sessions
            )

        if errors:

            self.write_json(
                "eventlogs_errors.json",
                errors
            )

        # ======================================================
        # STATUS
        # ======================================================

        extracted_events = (
            len(logons)
            + len(process_creations)
            + len(services)
            + len(powershell_scripts)
            + len(rdp_sessions)
        )

        if errors:

            if extracted_events > 0:
                status = "completed_with_errors"
            else:
                status = "failed"

        elif processed_files > 0:

            status = "completed"

        else:

            status = "no_artifacts_found"

        # ======================================================
        # SUMMARY
        # ======================================================

        summary = {

            "artifact": "Event Logs",

            "status": status,

            "statistics": {

                "evtx_files_processed": (
                    processed_files
                ),

                "total_records_processed": (
                    total_records
                ),

                "security_logons": (
                    len(logons)
                ),

                "process_creations": (
                    len(process_creations)
                ),

                "services_installed": (
                    len(services)
                ),

                "powershell_events": (
                    len(powershell_scripts)
                ),

                "rdp_events": (
                    len(rdp_sessions)
                ),

                "errors": (
                    len(errors)
                )
            },

            "event_categories": {

                "logon_events": [
                    4624,
                    4625,
                    4672,
                    4634
                ],

                "process_creation": [
                    4688,
                    1
                ],

                "service_installation": [
                    7045
                ],

                "powershell": [
                    4104
                ],

                "rdp": [
                    21,
                    22,
                    25
                ]
            },

            "event_id_distribution": dict(
                event_id_counter
            ),

            "provider_distribution": dict(
                provider_counter
            ),

            "parser": {
                "evtx_library_available": (
                    EVTX_AVAILABLE
                )
            },

            "errors": {
                "count": len(errors),
                "available": bool(errors)
            }
        }

        self.write_json(
            "eventlogs_summary.json",
            summary
        )

        # ======================================================
        # CONSOLE
        # ======================================================

        print(
            f"  [+] EVTX files: {processed_files}"
        )

        print(
            f"  [+] Records processed: {total_records}"
        )

        print(
            f"  [+] Logons: {len(logons)}"
        )

        print(
            f"  [+] Process creations: "
            f"{len(process_creations)}"
        )

        print(
            f"  [+] Services: {len(services)}"
        )

        print(
            f"  [+] PowerShell: "
            f"{len(powershell_scripts)}"
        )

        print(
            f"  [+] RDP: {len(rdp_sessions)}"
        )

        print(
            f"  [!] Errors: {len(errors)}"
        )
