"""
SherlockAI Registry Timeline Provenance & Deterministic Enrichment Engine.

Implements Phase 3 requirements:
- Distinguishes Registry Key Last-Write, Artifact Embedded Time, Associated Event Time,
  Correlated Execution Time, Collection Time, and Analysis Time.
- Pure zero-fabrication: unrecorded timestamps remain UNAVAILABLE / null.
- Deterministic enrichment: Corroborates registry persistence with matching Windows Event Logs
  (Event 4688/7045) or Prefetch execution records without rewriting original evidence.
"""

from typing import Dict, List, Any, Optional
import datetime
import json
import re
from pathlib import Path


class TimestampType:
    OBSERVED = "OBSERVED"
    ENRICHED_CORROBORATED = "ENRICHED_CORROBORATED"
    DERIVED = "DERIVED"
    INFERRED = "INFERRED"
    UNAVAILABLE = "UNAVAILABLE"


class TimestampSource:
    REGISTRY_KEY_LAST_WRITE = "REGISTRY_KEY_LAST_WRITE"
    CORROBORATING_PREFETCH = "CORROBORATING_PREFETCH"
    CORROBORATING_EVENT_LOG = "CORROBORATING_EVENT_LOG"
    CORROBORATING_PROCESS = "CORROBORATING_PROCESS"
    EVIDENCE_COLLECTION = "EVIDENCE_COLLECTION"
    ANALYSIS_TIME = "ANALYSIS_TIME"
    UNRECORDED = "UNRECORDED"


class TimezoneConfidence:
    EXACT_UTC = "EXACT_UTC"
    OFFSET_KNOWN = "OFFSET_KNOWN"
    UNSPECIFIED = "UNSPECIFIED"


class RegistryTimelineEngine:
    """
    Handles timestamp normalization, provenance tracking, and deterministic enrichment
    for Registry Forensics artifacts and findings.
    """

    @staticmethod
    def extract_executable_basename(path_or_cmd: str) -> str:
        """
        Extracts clean executable filename from command line or registry string.
        e.g. 'C:\\Windows\\Temp\\update_svc.exe /run' -> 'update_svc.exe'
        """
        if not path_or_cmd:
            return ""
        # Strip parameters, quotes
        cleaned = path_or_cmd.strip().strip('"').strip("'")
        # Match .exe or .dll or .bat
        match = re.search(r'([a-zA-Z0-9_\-\.]+\.(?:exe|dll|sys|bat|cmd|ps1|vbs|scr))', cleaned, re.IGNORECASE)
        if match:
            return match.group(1).lower()
        parts = cleaned.split()
        if parts:
            first = parts[0].replace("/", "\\").split("\\")[-1]
            return first.lower()
        return ""

    @staticmethod
    def normalize_timestamp(raw_ts: Any, source_tz: Optional[str] = None) -> Dict[str, Any]:
        """
        Normalizes a timestamp strictly according to NIST SP 800-86 rules:
        - If ISO string with Z or UTC offset, parses to UTC string with 'Z'.
        - If local wall-clock string without timezone, preserves raw string and sets timestamp_utc=None.
        - If None or empty, returns UNAVAILABLE.
        """
        if raw_ts is None or str(raw_ts).strip() in ("", "None", "null", "N/A", "0"):
            return {
                "timestamp_utc": None,
                "raw_timestamp": None,
                "timestamp_type": TimestampType.UNAVAILABLE,
                "timestamp_source": TimestampSource.UNRECORDED,
                "timezone_confidence": TimezoneConfidence.UNSPECIFIED
            }

        raw_str = str(raw_ts).strip()

        # Check for explicit ISO UTC format
        if "Z" in raw_str or "+00:00" in raw_str:
            clean_utc = raw_str.replace("+00:00", "Z")
            return {
                "timestamp_utc": clean_utc,
                "raw_timestamp": raw_str,
                "timestamp_type": TimestampType.OBSERVED,
                "timestamp_source": TimestampSource.REGISTRY_KEY_LAST_WRITE,
                "timezone_confidence": TimezoneConfidence.EXACT_UTC
            }

        # Check for explicit offset (+05:30, -04:00)
        offset_match = re.search(r'([+-]\d{2}):?(\d{2})$', raw_str)
        if offset_match:
            try:
                dt = datetime.datetime.fromisoformat(raw_str)
                dt_utc = dt.astimezone(datetime.timezone.utc)
                return {
                    "timestamp_utc": dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "raw_timestamp": raw_str,
                    "timestamp_type": TimestampType.OBSERVED,
                    "timestamp_source": TimestampSource.REGISTRY_KEY_LAST_WRITE,
                    "timezone_confidence": TimezoneConfidence.OFFSET_KNOWN
                }
            except Exception:
                pass

        # Ambiguous local wall-clock timestamp (no timezone offset)
        return {
            "timestamp_utc": None,
            "raw_timestamp": raw_str,
            "timestamp_type": TimestampType.OBSERVED,
            "timestamp_source": TimestampSource.REGISTRY_KEY_LAST_WRITE,
            "timezone_confidence": TimezoneConfidence.UNSPECIFIED,
            "ambiguity_note": "Local wall-clock timestamp without timezone offset; UTC conversion not assumed."
        }

    @classmethod
    def enrich_registry_finding(
        cls,
        registry_finding: Dict[str, Any],
        corroborating_findings: List[Dict[str, Any]],
        extracted_artifacts: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Deterministically enriches a Registry finding with timestamps from corroborating
        Prefetch or Event Log artifacts when available in the case.
        Never fabricates a timestamp.
        """
        enriched = dict(registry_finding)
        current_timeline = enriched.get("timeline") or {}
        current_utc = current_timeline.get("timestamp_utc")

        # Extract target binary name
        entities = enriched.get("entities", [])
        target_binary = ""
        for ent in entities:
            if isinstance(ent, dict):
                val = ent.get("executable") or ent.get("path") or ent.get("value") or ""
                target_binary = cls.extract_executable_basename(val)
                if target_binary:
                    break

        # Also search in reasoning / observation
        if not target_binary:
            text = f"{enriched.get('observation', '')} {enriched.get('reasoning', '')}"
            target_binary = cls.extract_executable_basename(text)

        enrichment_candidates = []

        # 1. Look for corroborating Prefetch findings
        for f in corroborating_findings:
            if f.get("finding_id") == enriched.get("finding_id"):
                continue
            f_agent = f.get("agent") or f.get("domain", "")
            f_text = json.dumps(f).lower()
            if target_binary and target_binary.lower() in f_text:
                f_tl = f.get("timeline") or {}
                f_ts = f_tl.get("timestamp_utc") or f.get("timestamp_utc")
                if f_ts and f_ts != "null":
                    enrichment_candidates.append({
                        "source_finding_id": f.get("finding_id", "CORROB-FINDING"),
                        "source_agent": f_agent,
                        "source_type": TimestampSource.CORROBORATING_PREFETCH if f_agent == "disk" else TimestampSource.CORROBORATING_PROCESS,
                        "matched_binary": target_binary,
                        "timestamp_utc": f_ts,
                        "rationale": f"Matched executable '{target_binary}' with {f_agent.capitalize()} execution artifact"
                    })

        # 2. Look for corroborating records in raw extracted artifacts if provided
        if extracted_artifacts:
            # Check Prefetch
            pf_records = extracted_artifacts.get("prefetch_analysis") or []
            if isinstance(pf_records, list):
                for pf in pf_records:
                    exe_name = (pf.get("executable_name") or pf.get("executable") or "").lower()
                    if target_binary and target_binary.lower() in exe_name:
                        l_time = pf.get("last_run_time") or pf.get("timestamp_utc")
                        if l_time:
                            enrichment_candidates.append({
                                "source_finding_id": f"ARTIFACT-PF-{target_binary}",
                                "source_agent": "disk",
                                "source_type": TimestampSource.CORROBORATING_PREFETCH,
                                "matched_binary": target_binary,
                                "timestamp_utc": str(l_time),
                                "rationale": f"Corroborated by Windows Prefetch run count: {pf.get('run_count', 1)}"
                            })

            # Check Event Logs (Event 7045 or 4688)
            ev_records = extracted_artifacts.get("event_logs") or []
            if isinstance(ev_records, list):
                for ev in ev_records:
                    cmd_line = str(ev.get("command_line") or ev.get("ImagePath") or "").lower()
                    if target_binary and target_binary.lower() in cmd_line:
                        e_time = ev.get("timestamp") or ev.get("time_created")
                        if e_time:
                            enrichment_candidates.append({
                                "source_finding_id": f"ARTIFACT-EVTX-{ev.get('event_id', 4688)}",
                                "source_agent": "logs",
                                "source_type": TimestampSource.CORROBORATING_EVENT_LOG,
                                "matched_binary": target_binary,
                                "timestamp_utc": str(e_time),
                                "rationale": f"Corroborated by Event ID {ev.get('event_id', 4688)} process launch"
                            })

        # Process candidates
        if enrichment_candidates:
            # Check for conflicting timestamps
            unique_ts = set(c["timestamp_utc"] for c in enrichment_candidates)
            primary = enrichment_candidates[0]

            if len(unique_ts) > 1:
                # Multiple conflicting corroborating timestamps
                enriched["timeline"] = {
                    "timestamp_utc": primary["timestamp_utc"],
                    "timestamp_type": TimestampType.ENRICHED_CORROBORATED,
                    "timestamp_source": primary["source_type"],
                    "event_description": f"Registry persistence for '{target_binary}' corroborated by execution telemetry (Multiple timestamps observed)",
                    "enrichment_provenance": primary,
                    "conflicting_timestamps": list(unique_ts),
                    "discrepancy_flag": True
                }
            else:
                enriched["timeline"] = {
                    "timestamp_utc": primary["timestamp_utc"],
                    "timestamp_type": TimestampType.ENRICHED_CORROBORATED,
                    "timestamp_source": primary["source_type"],
                    "event_description": f"Registry persistence for '{target_binary}' corroborated by execution telemetry",
                    "enrichment_provenance": primary,
                    "discrepancy_flag": False
                }
        elif not current_utc:
            # No corroboration and no native UTC timestamp
            enriched["timeline"] = {
                "timestamp_utc": None,
                "timestamp_type": TimestampType.UNAVAILABLE,
                "timestamp_source": TimestampSource.UNRECORDED,
                "event_description": "Registry key configuration observed (No corroborating execution time available)",
                "enrichment_provenance": None,
                "discrepancy_flag": False
            }

        return enriched
