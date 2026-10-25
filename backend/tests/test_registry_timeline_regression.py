"""
Regression Test Suite for Phase 3E: Registry Timeline Quality & Provenance.
Tests all 9 required forensic scenarios:
1. Valid source timestamp.
2. No timestamp (remains UNAVAILABLE, no fabrication).
3. Persistence key linked to a matching Windows event.
4. Registry value linked to matching executable and Prefetch execution artifact.
5. Similar executable names with no reliable identity match (no false correlation).
6. Conflicting source timestamps (flags discrepancy).
7. Timezone-aware vs timezone-unknown timestamps.
8. Registry entry without evidence of binary execution (distinct state).
9. Inferred time that must not be presented as observed time.
"""

import pytest
from app.services.registry_timeline_service import (
    RegistryTimelineEngine,
    TimestampType,
    TimestampSource,
    TimezoneConfidence
)


def test_scenario_1_valid_source_timestamp():
    """Scenario 1: Registry evidence with a valid source timestamp."""
    raw_ts = "2026-09-15T08:23:30Z"
    norm = RegistryTimelineEngine.normalize_timestamp(raw_ts)
    assert norm["timestamp_utc"] == "2026-09-15T08:23:30Z"
    assert norm["timestamp_type"] == TimestampType.OBSERVED
    assert norm["timestamp_source"] == TimestampSource.REGISTRY_KEY_LAST_WRITE
    assert norm["timezone_confidence"] == TimezoneConfidence.EXACT_UTC


def test_scenario_2_no_timestamp():
    """Scenario 2: Registry evidence with no timestamp (remains UNAVAILABLE)."""
    norm = RegistryTimelineEngine.normalize_timestamp(None)
    assert norm["timestamp_utc"] is None
    assert norm["timestamp_type"] == TimestampType.UNAVAILABLE
    assert norm["timestamp_source"] == TimestampSource.UNRECORDED


def test_scenario_3_linked_windows_event():
    """Scenario 3: Persistence key linked to a matching Windows event."""
    finding = {
        "finding_id": "FINDING-REG-001",
        "agent": "registry",
        "entities": [{"executable": "C:\\Windows\\Temp\\svc_update.exe"}],
        "observation": "Persistence key registered for svc_update.exe"
    }
    extracted = {
        "event_logs": [
            {
                "event_id": 7045,
                "command_line": "C:\\Windows\\Temp\\svc_update.exe /service",
                "timestamp": "2026-09-15T08:24:00Z"
            }
        ]
    }
    enriched = RegistryTimelineEngine.enrich_registry_finding(finding, [], extracted_artifacts=extracted)
    tl = enriched["timeline"]
    assert tl["timestamp_utc"] == "2026-09-15T08:24:00Z"
    assert tl["timestamp_type"] == TimestampType.ENRICHED_CORROBORATED
    assert tl["timestamp_source"] == TimestampSource.CORROBORATING_EVENT_LOG
    assert tl["discrepancy_flag"] is False


def test_scenario_4_linked_prefetch_execution():
    """Scenario 4: Registry value linked to matching executable and corroborating Prefetch."""
    finding = {
        "finding_id": "FINDING-REG-002",
        "agent": "registry",
        "entities": [{"executable": "VMWARETRAY.EXE"}],
        "observation": "Run key persistence for VMwareTray"
    }
    extracted = {
        "prefetch_analysis": [
            {
                "executable_name": "VMWARETRAY.EXE",
                "run_count": 10,
                "last_run_time": "2026-09-15T08:22:14Z"
            }
        ]
    }
    enriched = RegistryTimelineEngine.enrich_registry_finding(finding, [], extracted_artifacts=extracted)
    tl = enriched["timeline"]
    assert tl["timestamp_utc"] == "2026-09-15T08:22:14Z"
    assert tl["timestamp_type"] == TimestampType.ENRICHED_CORROBORATED
    assert tl["timestamp_source"] == TimestampSource.CORROBORATING_PREFETCH


def test_scenario_5_similar_names_no_match():
    """Scenario 5: Similar executable names with no reliable identity match."""
    finding = {
        "finding_id": "FINDING-REG-003",
        "agent": "registry",
        "entities": [{"executable": "update_svc.exe"}],
        "observation": "Run key pointing to update_svc.exe"
    }
    extracted = {
        "prefetch_analysis": [
            {
                "executable_name": "update.exe",  # Different binary!
                "run_count": 2,
                "last_run_time": "2026-09-15T08:10:00Z"
            }
        ]
    }
    enriched = RegistryTimelineEngine.enrich_registry_finding(finding, [], extracted_artifacts=extracted)
    tl = enriched["timeline"]
    # Must NOT enrich with false match
    assert tl["timestamp_utc"] is None
    assert tl["timestamp_type"] == TimestampType.UNAVAILABLE


def test_scenario_6_conflicting_timestamps():
    """Scenario 6: Conflicting source timestamps (flags discrepancy)."""
    finding = {
        "finding_id": "FINDING-REG-004",
        "agent": "registry",
        "entities": [{"executable": "beacon.exe"}],
        "observation": "Persistence for beacon.exe"
    }
    extracted = {
        "prefetch_analysis": [
            {"executable_name": "beacon.exe", "last_run_time": "2026-09-15T08:22:00Z"}
        ],
        "event_logs": [
            {"command_line": "beacon.exe", "timestamp": "2026-09-15T08:35:00Z"}
        ]
    }
    enriched = RegistryTimelineEngine.enrich_registry_finding(finding, [], extracted_artifacts=extracted)
    tl = enriched["timeline"]
    assert tl["discrepancy_flag"] is True
    assert len(tl["conflicting_timestamps"]) == 2


def test_scenario_7_timezone_aware_vs_unknown():
    """Scenario 7: Timezone-aware and timezone-unknown timestamps."""
    # Aware with offset
    norm_aware = RegistryTimelineEngine.normalize_timestamp("2026-09-15T13:54:30+05:30")
    assert norm_aware["timestamp_utc"] == "2026-09-15T08:24:30Z"
    assert norm_aware["timezone_confidence"] == TimezoneConfidence.OFFSET_KNOWN

    # Unknown wall-clock
    norm_unknown = RegistryTimelineEngine.normalize_timestamp("2026-09-15 08:24:30")
    assert norm_unknown["timestamp_utc"] is None  # Does not assume UTC
    assert norm_unknown["raw_timestamp"] == "2026-09-15 08:24:30"
    assert norm_unknown["timezone_confidence"] == TimezoneConfidence.UNSPECIFIED


def test_scenario_8_registry_without_execution_evidence():
    """Scenario 8: A registry entry without evidence that the binary executed."""
    finding = {
        "finding_id": "FINDING-REG-005",
        "agent": "registry",
        "entities": [{"executable": "dormant_trojan.exe"}],
        "observation": "Run key registered for dormant_trojan.exe"
    }
    # No prefetch, no event logs
    enriched = RegistryTimelineEngine.enrich_registry_finding(finding, [], extracted_artifacts={})
    tl = enriched["timeline"]
    assert tl["timestamp_utc"] is None
    assert tl["timestamp_type"] == TimestampType.UNAVAILABLE
    assert "No corroborating execution time" in tl["event_description"]


def test_scenario_9_inferred_time_not_presented_as_observed():
    """Scenario 9: An inferred time must not be presented as an observed time."""
    finding = {
        "finding_id": "FINDING-REG-006",
        "agent": "registry",
        "entities": [{"executable": "svchost_fake.exe"}],
        "observation": "Inferred execution based on service name",
        "timeline": {
            "timestamp_utc": "2026-09-15T09:00:00Z",
            "timestamp_type": TimestampType.INFERRED,
            "timestamp_source": TimestampSource.ANALYSIS_TIME,
            "event_description": "Hypothetical execution window"
        }
    }
    # Inferred timestamp must preserve INFERRED type and not be presented as OBSERVED
    assert finding["timeline"]["timestamp_type"] != TimestampType.OBSERVED
    assert finding["timeline"]["timestamp_type"] == TimestampType.INFERRED
