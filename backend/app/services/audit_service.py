"""
Audit Service for HMACFR.
Implements dual-store immutable audit logging, cryptographic hash chaining (HMAC + previous row hash),
and crash recovery reconciliation between SQLite and the external audit ledger.
"""

import os
import json
import hmac
import hashlib
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.core.config import settings
from app.core.logger import log_app_event, log_error_event
from app.db.models.audit_log import SystemAuditLog


GENESIS_HASH = "0" * 64


class AuditTamperException(Exception):
    """Raised when an audit log hash chain breakage or signature mismatch is detected."""
    pass


class AuditService:
    @staticmethod
    def get_ledger_file_path() -> str:
        os.makedirs(settings.LOGS_DIR, exist_ok=True)
        return os.path.join(settings.LOGS_DIR, "audit_ledger.jsonl")

    @staticmethod
    def _compute_hashes(
        timestamp_str: str,
        user_id: Optional[str],
        username: Optional[str],
        action: str,
        target_resource: str,
        resource_id: Optional[str],
        case_id: Optional[str],
        details: Optional[str],
        previous_hash: str
    ) -> Tuple[str, str]:
        """Calculates row SHA-256 hash and HMAC signature."""
        data_string = f"{timestamp_str}|{user_id or ''}|{username or ''}|{action}|{target_resource}|{resource_id or ''}|{case_id or ''}|{details or ''}|{previous_hash}"
        row_hash = hashlib.sha256(data_string.encode("utf-8")).hexdigest()
        
        secret = (getattr(settings, "ENCRYPTION_SECRET_KEY", None) or getattr(settings, "SECRET_KEY", "default-hmacfr-key")).encode("utf-8")
        signature = hmac.new(secret, row_hash.encode("utf-8"), hashlib.sha256).hexdigest()
        return row_hash, signature

    @classmethod
    def record_event(
        cls,
        db: Session,
        action: str,
        target_resource: str,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        resource_id: Optional[str] = None,
        case_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[Any] = None
    ) -> SystemAuditLog:
        """
        Records an audit event to SQLite and concurrently appends to the external JSONL ledger.
        """
        # 1. Fetch previous hash from latest log in DB
        latest_entry = db.query(SystemAuditLog).order_by(desc(SystemAuditLog.sequence_id)).first()
        previous_hash = latest_entry.row_hash if latest_entry else GENESIS_HASH

        now = datetime.utcnow()
        timestamp_str = now.isoformat()
        details_str = json.dumps(details) if isinstance(details, (dict, list)) else (str(details) if details is not None else None)

        # 2. Compute cryptographic chain
        row_hash, signature = cls._compute_hashes(
            timestamp_str=timestamp_str,
            user_id=user_id,
            username=username,
            action=action,
            target_resource=target_resource,
            resource_id=resource_id,
            case_id=case_id,
            details=details_str,
            previous_hash=previous_hash
        )

        # 3. Create SQLite log record
        audit_entry = SystemAuditLog(
            timestamp=now,
            user_id=user_id,
            username=username,
            action=action,
            target_resource=target_resource,
            resource_id=resource_id,
            case_id=case_id,
            ip_address=ip_address,
            details=details_str,
            previous_hash=previous_hash,
            row_hash=row_hash,
            hmac_signature=signature
        )
        db.add(audit_entry)
        db.commit()
        db.refresh(audit_entry)

        # 4. Mirror to external append-only ledger
        cls._append_to_ledger(audit_entry)

        return audit_entry

    @classmethod
    def _append_to_ledger(cls, entry: SystemAuditLog):
        """Atomically appends record to the external audit_ledger.jsonl file."""
        ledger_path = cls.get_ledger_file_path()
        record_dict = {
            "sequence_id": entry.sequence_id,
            "log_id": entry.log_id,
            "timestamp": entry.timestamp.isoformat() if hasattr(entry.timestamp, "isoformat") else str(entry.timestamp),
            "user_id": entry.user_id,
            "username": entry.username,
            "action": entry.action,
            "target_resource": entry.target_resource,
            "resource_id": entry.resource_id,
            "case_id": entry.case_id,
            "ip_address": entry.ip_address,
            "details": entry.details,
            "previous_hash": entry.previous_hash,
            "row_hash": entry.row_hash,
            "hmac_signature": entry.hmac_signature
        }
        try:
            with open(ledger_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record_dict) + "\n")
                f.flush()
        except Exception as e:
            log_error_event(f"Failed to append audit record {entry.log_id} to external ledger: {e}")

    @classmethod
    def verify_chain_integrity(cls, db: Session) -> Tuple[bool, List[str]]:
        """
        Verifies the cryptographic hash chain and HMAC signatures across all SQLite audit rows.
        Returns (is_valid, list_of_issues).
        """
        issues = []
        rows = db.query(SystemAuditLog).order_by(SystemAuditLog.sequence_id.asc()).all()
        expected_prev_hash = GENESIS_HASH

        for row in rows:
            # Check previous_hash chain link
            if row.previous_hash != expected_prev_hash:
                issues.append(
                    f"Chain break at sequence {row.sequence_id} (log_id={row.log_id}): "
                    f"expected previous_hash '{expected_prev_hash}', found '{row.previous_hash}'."
                )

            # Recompute and verify row_hash and HMAC signature
            ts_str = row.timestamp.isoformat() if hasattr(row.timestamp, "isoformat") else str(row.timestamp)
            calc_hash, calc_sig = cls._compute_hashes(
                timestamp_str=ts_str,
                user_id=row.user_id,
                username=row.username,
                action=row.action,
                target_resource=row.target_resource,
                resource_id=row.resource_id,
                case_id=row.case_id,
                details=row.details,
                previous_hash=row.previous_hash
            )

            if row.row_hash != calc_hash:
                issues.append(
                    f"Row hash mismatch at sequence {row.sequence_id} (log_id={row.log_id}): "
                    f"stored '{row.row_hash}', computed '{calc_hash}'."
                )

            if row.hmac_signature != calc_sig:
                issues.append(
                    f"HMAC signature mismatch at sequence {row.sequence_id} (log_id={row.log_id})."
                )

            expected_prev_hash = row.row_hash

        return len(issues) == 0, issues

    @classmethod
    def reconcile_audit_stores(cls, db: Session) -> Dict[str, Any]:
        """
        Startup crash-recovery and dual-store reconciliation.
        1. Compares SQLite audit entries against external JSONL ledger entries.
        2. Heals process crash gaps by appending missing committed SQLite rows to JSONL.
        3. Detects tampering; if suspicious mismatches exist, flags them without silent overwrites.
        """
        ledger_path = cls.get_ledger_file_path()
        ledger_records = []
        if os.path.exists(ledger_path):
            with open(ledger_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            ledger_records.append(json.loads(line))
                        except Exception:
                            pass

        db_rows = db.query(SystemAuditLog).order_by(SystemAuditLog.sequence_id.asc()).all()

        ledger_seqs = {r.get("sequence_id"): r for r in ledger_records if "sequence_id" in r}
        db_seqs = {r.sequence_id: r for r in db_rows}

        synced_count = 0
        anomalies = []

        # 1. Recover crash gaps: DB has committed rows missing from JSONL file
        for seq_id, db_row in db_seqs.items():
            if seq_id not in ledger_seqs:
                # Process crash between DB commit and file write -> Safe to heal by appending
                cls._append_to_ledger(db_row)
                synced_count += 1
            else:
                # Compare row_hash between DB and ledger
                ledger_hash = ledger_seqs[seq_id].get("row_hash")
                if ledger_hash != db_row.row_hash:
                    anomalies.append(
                        f"Tamper Mismatch at sequence {seq_id}: DB row_hash '{db_row.row_hash}' != Ledger row_hash '{ledger_hash}'."
                    )

        # 2. Check for orphaned ledger lines (present in JSONL but missing in DB)
        for seq_id in ledger_seqs:
            if seq_id not in db_seqs:
                anomalies.append(f"Orphaned ledger record at sequence {seq_id} (exists in JSONL but missing in database).")

        # 3. Check chain integrity in DB
        chain_valid, chain_issues = cls.verify_chain_integrity(db)
        if not chain_valid:
            anomalies.extend(chain_issues)

        is_tampered = len(anomalies) > 0
        status_msg = "HEALTHY"
        if is_tampered:
            status_msg = "TAMPER_ALERT"
            log_error_event(f"AUDIT STORE RECONCILIATION DETECTED ANOMALIES: {anomalies}")

        return {
            "status": status_msg,
            "db_count": len(db_rows),
            "ledger_count": len(ledger_records) + synced_count,
            "synced_crash_gaps": synced_count,
            "is_tampered": is_tampered,
            "anomalies": anomalies
        }
