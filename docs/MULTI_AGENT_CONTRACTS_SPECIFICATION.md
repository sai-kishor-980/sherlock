# 📋 Multi-Agent Output Contracts & Schema Specification

**Framework**: Hierarchical Multi-Agent Cognitive Forensic Reconstruction Framework (H-MACFR)  
**Location**: `output/cases/<CASE_ID>/extracted_artifacts/<domain>/<contract_file>.json`

This specification defines the 42 formal JSON contract schemas produced during artifact extraction and consumed by the specialized domain agents and supervisor.

---

## 1. Supervisor Orchestration Manifest

**File**: `output/cases/<CASE_ID>/supervisor_manifest.json`  
**Purpose**: Certifies case orchestration completeness across all 5 domain agents.

```json
{
  "orchestrator": "Supervisor Multi-Agent (Qwen Powered)",
  "case_id": "CASE_1cb3833e",
  "orchestration_timestamp": "2026-10-27T16:14:00Z",
  "active_agents": {
    "network": {
      "agent": "Network Agent",
      "lead": "Pranay",
      "total_expected": 9,
      "extracted_count": 9,
      "status": "COMPLETED",
      "files": ["network_summary.json", "dns_analysis.json", "network_connections.json", ...]
    },
    "memory": {
      "agent": "Memory Agent",
      "lead": "Bharath",
      "total_expected": 10,
      "extracted_count": 1,
      "status": "COMPLETED",
      "files": ["memory_processes.json"]
    },
    "disk": {
      "agent": "Disk Agent",
      "lead": "Aswith",
      "total_expected": 11,
      "extracted_count": 0,
      "status": "READY",
      "files": []
    },
    "logs": {
      "agent": "Log Agent",
      "lead": "Sanhith",
      "total_expected": 6,
      "extracted_count": 0,
      "status": "READY",
      "files": []
    },
    "registry": {
      "agent": "Registry Agent",
      "lead": "Kishor",
      "total_expected": 6,
      "extracted_count": 0,
      "status": "READY",
      "files": []
    }
  },
  "total_artifacts_extracted": 10
}
```

---

## 2. Network Forensics Contracts (Agent: Pranay)

Directory: `extracted_artifacts/network/`

| Contract File | Primary Schema Fields | Description |
| :--- | :--- | :--- |
| `network_summary.json` | `packet_count`, `duration_seconds`, `protocols`, `top_talkers` | Overview of packet traffic, captured bandwidth, and active IP conversations. |
| `dns_analysis.json` | `dns_query`, `resolved_ips`, `query_type`, `ttl`, `entropy_score` | DNS resolutions, domain names queried, and suspicious DGA/entropy analysis. |
| `network_connections.json` | `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `bytes_sent` | TCP/UDP socket connections and conversation matrices. |
| `browser_history.json` | `url`, `title`, `visit_count`, `last_visit_time`, `browser` | Extracted Chrome/Firefox/Edge navigation history records. |
| `browser_cookies.json` | `host_key`, `name`, `path`, `creation_utc`, `is_secure` | Extracted session cookies and tracking tokens. |
| `browser_downloads.json` | `target_path`, `tab_url`, `start_time`, `received_bytes` | Downloaded files carved from browser cache databases. |
| `email_messages.json` | `message_id`, `from`, `to`, `subject`, `date`, `headers` | Email communication metadata carved from `.eml`, `.msg`, `.mbox`. |
| `email_attachments.json` | `filename`, `content_type`, `file_size`, `sha256` | Carved email attachments and payload checksums. |
| `email_summary.json` | `total_emails`, `senders_count`, `recipients_count`, `suspicious_count` | Aggregated statistical summary of analyzed email streams. |

---

## 3. Memory Forensics Contracts (Agent: Bharath)

Directory: `extracted_artifacts/memory/`

| Contract File | Primary Schema Fields | Description |
| :--- | :--- | :--- |
| `memory_processes.json` | `pid`, `ppid`, `process_name`, `create_time`, `threads`, `handles` | Active and hidden process enumeration (`windows.pslist`, `psscan`). |
| `injected_code.json` | `pid`, `process_name`, `vad_base`, `protection`, `disasm_preview` | VAD allocations with `EXECUTE_READWRITE` flags and injected shellcode (`malfind`). |
| `dll_modules.json` | `pid`, `process_name`, `dll_path`, `load_address`, `size` | Loaded dynamic link libraries, unlinked modules, and DLL hollowing indicators. |
| `network_sockets.json` | `pid`, `protocol`, `local_addr`, `foreign_addr`, `state` | Open TCP/UDP listening endpoints and active sockets carved from RAM (`netscan`). |
| `kernel_drivers.json` | `driver_name`, `service_key`, `base_address`, `driver_size` | Loaded kernel drivers and potential rootkit components (`modules`). |
| `memory_handles.json` | `pid`, `handle_type`, `handle_name`, `granted_access` | Mutexes, named pipes, and registry key handles locked by active processes. |
| `cmdline_history.json` | `pid`, `process_name`, `command_line` | Full execution command line arguments recovered from process environment blocks. |
| `privilege_tokens.json` | `pid`, `user_sid`, `privileges_held`, `privileges_enabled` | Security token privileges (e.g. `SeDebugPrivilege`, `SeImpersonatePrivilege`). |
| `yara_matches.json` | `rule_name`, `namespace`, `matched_string`, `offset` | In-memory signature hits matching threat intelligence signatures. |
| `memory_summary.json` | `os_profile`, `analyzed_at`, `suspicious_process_count`, `injections_count` | High-level synthesis of RAM triage findings. |

---

## 4. Disk & Filesystem Contracts (Agent: Aswith)

Directory: `extracted_artifacts/disk/`

| Contract File | Primary Schema Fields | Description |
| :--- | :--- | :--- |
| `execution_prefetch.json` | `executable_name`, `run_count`, `last_run_utc`, `referenced_files` | Windows Prefetch (`.pf`) artifacts validating binary execution frequency. |
| `mft_timeline.json` | `record_number`, `file_name`, `si_created`, `fn_created`, `file_size` | Master File Table records with timestomping detection flags. |
| `lnk_shortcuts.json` | `lnk_name`, `target_path`, `working_directory`, `drive_type`, `mac_address` | Carved `.lnk` shell links pointing to external or staging storage devices. |
| `jumplists.json` | `app_id`, `destination_path`, `accessed_timestamp` | Recent application destinations carved from `AutomaticDestinations-ms`. |
| `recycle_bin.json` | `original_path`, `deleted_timestamp`, `file_size`, `user_sid` | Files recovered from `$Recycle.Bin` (`$I` and `$R` records). |
| `usn_journal.json` | `usn`, `file_name`, `reason_flags`, `timestamp` | NTFS Update Sequence Number change journal entries. |
| `file_carving.json` | `carved_filename`, `offset`, `size`, `magic_bytes`, `md5` | Raw carved documents, executables, or compressed archives. |
| `directory_tree.json` | `path`, `is_directory`, `created`, `modified`, `permissions` | Hierarchical reconstruction of the target filesystem root. |
| `timestomp_anomalies.json`| `file_name`, `si_mtime`, `fn_mtime`, `delta_seconds` | Files where `$STANDARD_INFORMATION` differs from `$FILE_NAME` timestamps. |
| `volume_shadow_copies.json`| `shadow_id`, `volume_name`, `creation_time` | Identified VSS snapshots containing historical disk backups. |
| `disk_summary.json` | `total_files`, `executable_count`, `deleted_files_count`, `anomalies` | Statistical overview of disk analysis results. |

---

## 5. Security Event Log Contracts (Agent: Sanhith)

Directory: `extracted_artifacts/logs/`

| Contract File | Primary Schema Fields | Description |
| :--- | :--- | :--- |
| `security_logons.json` | `event_id`, `timestamp`, `user_name`, `logon_type`, `src_ip`, `status` | EID 4624 (Logon) and 4625 (Failed Logon) tracking credential abuse. |
| `process_creations.json` | `event_id`, `timestamp`, `parent_process`, `image`, `command_line`, `user` | EID 4688 and Sysmon EID 1 execution records. |
| `services_installed.json` | `event_id`, `timestamp`, `service_name`, `service_file_name`, `service_type`| EID 7045 and 4697 documenting persistence through service installation. |
| `powershell_activity.json`| `event_id`, `timestamp`, `script_block_text`, `user_id` | EID 4104 capturing de-obfuscated script blocks and command arguments. |
| `rdp_sessions.json` | `event_id`, `timestamp`, `client_name`, `client_ip`, `user_name` | TerminalServices-LocalSessionManager and RemoteConnectionManager events. |
| `eventlogs_summary.json` | `log_sources`, `total_events_parsed`, `critical_events_count` | Summary of parsed event log telemetry. |

---

## 6. Windows Registry Contracts (Agent: Kishor)

Directory: `extracted_artifacts/registry/`

| Contract File | Primary Schema Fields | Description |
| :--- | :--- | :--- |
| `installed_software.json` | `display_name`, `display_version`, `install_date`, `uninstall_string` | Programs registered under `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`. |
| `usb_devices.json` | `device_name`, `serial_number`, `vendor_id`, `first_install_time`, `last_arrival` | Historical record of connected USB flash drives (`Enum\USBSTOR`). |
| `run_keys.json` | `hive`, `key_path`, `value_name`, `value_data` | Autostart persistence entries (`Run`, `RunOnce`, `StartupApproved`). |
| `recent_files.json` | `mru_order`, `file_name`, `accessed_timestamp`, `extension` | Recently accessed files extracted from `RecentDocs` and `UserAssist`. |
| `registry_summary.json` | `hives_parsed`, `total_keys_inspected`, `persistence_entries_count` | Synthesis of offline hive analysis. |
| `registry_errors.json` | `hive_path`, `error_type`, `message`, `offset` | Diagnostics of corrupted or unreadable hive sectors. |
