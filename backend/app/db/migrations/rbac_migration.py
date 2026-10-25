"""
RBAC Foundation & Safe Migration Engine for HMACFR.
Executes non-destructive additive DDL migrations, attaches audit triggers,
reconciles legacy users under the quarantine policy, and provides safe rollback.
"""

import os
import sqlite3
import uuid
from datetime import datetime
from typing import Dict, Any, List

MIGRATION_VERSION_CODE = "V1_RBAC_FOUNDATION"
MIGRATION_DESCRIPTION = "Initial Defense-in-Depth RBAC schema, audit triggers, and case membership"


def apply_rbac_migration(db_path: str) -> Dict[str, Any]:
    """
    Applies additive RBAC migration to target SQLite database file.
    Does NOT drop or truncate any existing tables or columns.
    """
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Target database not found: {db_path}")

    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    try:
        c.execute("PRAGMA foreign_keys = ON;")
        c.execute("BEGIN TRANSACTION;")

        # 1. Schema Versions Table
        c.execute("""
            CREATE TABLE IF NOT EXISTS schema_versions (
                version_id INTEGER PRIMARY KEY AUTOINCREMENT,
                version_code VARCHAR(50) NOT NULL UNIQUE,
                applied_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                description TEXT NOT NULL
            );
        """)

        # Check if already applied
        c.execute("SELECT version_code FROM schema_versions WHERE version_code = ?;", (MIGRATION_VERSION_CODE,))
        if c.fetchone():
            conn.commit()
            conn.close()
            return {"status": "ALREADY_APPLIED", "version": MIGRATION_VERSION_CODE}

        # 2. Add token_version to users if missing
        c.execute("PRAGMA table_info(users);")
        user_cols = [r[1] for r in c.fetchall()]
        if "token_version" not in user_cols:
            c.execute("ALTER TABLE users ADD COLUMN token_version INTEGER DEFAULT 1 NOT NULL;")

        # 3. Create user_global_roles Table
        c.execute("""
            CREATE TABLE IF NOT EXISTS user_global_roles (
                id VARCHAR(36) PRIMARY KEY,
                user_id VARCHAR(36) NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                role_name VARCHAR(50) NOT NULL,
                assigned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                assigned_by VARCHAR(36) REFERENCES users(user_id),
                UNIQUE(user_id, role_name)
            );
        """)

        # 4. Create case_members Table
        c.execute("""
            CREATE TABLE IF NOT EXISTS case_members (
                id VARCHAR(36) PRIMARY KEY,
                case_id VARCHAR(36) NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
                user_id VARCHAR(36) NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                assigned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                assigned_by VARCHAR(36) REFERENCES users(user_id),
                UNIQUE(case_id, user_id)
            );
        """)

        # 5. Create case_member_responsibilities Table
        c.execute("""
            CREATE TABLE IF NOT EXISTS case_member_responsibilities (
                id VARCHAR(36) PRIMARY KEY,
                case_member_id VARCHAR(36) NOT NULL REFERENCES case_members(id) ON DELETE CASCADE,
                responsibility_name VARCHAR(50) NOT NULL,
                granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(case_member_id, responsibility_name)
            );
        """)

        # 6. Create system_audit_logs Table
        c.execute("""
            CREATE TABLE IF NOT EXISTS system_audit_logs (
                sequence_id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_id VARCHAR(36) NOT NULL UNIQUE,
                timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                user_id VARCHAR(36),
                username VARCHAR(50),
                action VARCHAR(100) NOT NULL,
                target_resource VARCHAR(100) NOT NULL,
                resource_id VARCHAR(100),
                case_id VARCHAR(36),
                ip_address VARCHAR(45),
                details TEXT,
                previous_hash VARCHAR(64) NOT NULL,
                row_hash VARCHAR(64) NOT NULL,
                hmac_signature VARCHAR(64) NOT NULL
            );
        """)

        # 7. Create SQLite Immutability Triggers
        c.execute("""
            CREATE TRIGGER IF NOT EXISTS trg_prevent_audit_update
            BEFORE UPDATE ON system_audit_logs
            BEGIN
                SELECT RAISE(ABORT, 'CRITICAL SECURITY VIOLATION: system_audit_logs entries are immutable and cannot be updated.');
            END;
        """)

        c.execute("""
            CREATE TRIGGER IF NOT EXISTS trg_prevent_audit_delete
            BEFORE DELETE ON system_audit_logs
            BEGIN
                SELECT RAISE(ABORT, 'CRITICAL SECURITY VIOLATION: system_audit_logs entries are immutable and cannot be deleted.');
            END;
        """)

        # 8. Reconcile Legacy Users (Fix #2: Staged Review & Quarantine Policy)
        c.execute("SELECT user_id, username, role FROM users;")
        existing_users = c.fetchall()

        quarantined_admins = []
        migrated_auditors = []

        for uid, uname, urole in existing_users:
            urole_clean = (urole or "").strip()
            if urole_clean.upper() == "ADMIN":
                # Do NOT grant Super Admin or Access Admin automatically!
                # Quarantine in Pending_Admin_Review and isolate legacy role
                c.execute("""
                    INSERT OR IGNORE INTO user_global_roles (id, user_id, role_name, assigned_at)
                    VALUES (?, ?, 'Pending_Admin_Review', CURRENT_TIMESTAMP);
                """, (f"UGR_{uuid.uuid4().hex[:12]}", uid))
                c.execute("UPDATE users SET role = 'PENDING_REVIEW', token_version = token_version + 1 WHERE user_id = ?;", (uid,))
                quarantined_admins.append(uname)
            elif urole_clean.upper() in ["LEAD_AUDITOR", "AUDITOR"]:
                c.execute("""
                    INSERT OR IGNORE INTO user_global_roles (id, user_id, role_name, assigned_at)
                    VALUES (?, ?, 'Platform Auditor', CURRENT_TIMESTAMP);
                """, (f"UGR_{uuid.uuid4().hex[:12]}", uid))
                migrated_auditors.append(uname)

        # 9. Reconcile Legacy Cases
        c.execute("SELECT case_id, case_name, investigator_name FROM cases;")
        existing_cases = c.fetchall()

        user_dict = {u[1]: u[0] for u in existing_users}  # username -> user_id
        assigned_cases = []
        unassigned_cases = []

        for cid, cname, inv_name in existing_cases:
            if inv_name and inv_name in user_dict:
                matched_uid = user_dict[inv_name]
                member_id = f"MBR_{uuid.uuid4().hex[:12]}"
                c.execute("""
                    INSERT OR IGNORE INTO case_members (id, case_id, user_id, assigned_at)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP);
                """, (member_id, cid, matched_uid))
                
                # Fetch actual member_id if it existed
                c.execute("SELECT id FROM case_members WHERE case_id = ? AND user_id = ?;", (cid, matched_uid))
                actual_member_id = c.fetchone()[0]

                # Grant baseline responsibilities
                for resp in ["Lead Investigator", "Investigator", "Forensic Analyst"]:
                    c.execute("""
                        INSERT OR IGNORE INTO case_member_responsibilities (id, case_member_id, responsibility_name, granted_at)
                        VALUES (?, ?, ?, CURRENT_TIMESTAMP);
                    """, (f"RES_{uuid.uuid4().hex[:12]}", actual_member_id, resp))
                
                assigned_cases.append(cid)
            else:
                unassigned_cases.append(cid)

        # 10. Record Migration Version
        c.execute("""
            INSERT INTO schema_versions (version_code, description, applied_at)
            VALUES (?, ?, CURRENT_TIMESTAMP);
        """, (MIGRATION_VERSION_CODE, MIGRATION_DESCRIPTION))

        # 11. Transaction Safety Checks: Run BEFORE Commit (Fix #1)
        c.execute("PRAGMA foreign_key_check;")
        fk_errors = c.fetchall()
        if fk_errors:
            conn.rollback()
            conn.close()
            raise RuntimeError(f"Foreign Key constraint violation detected during migration: {fk_errors}")

        c.execute("PRAGMA integrity_check;")
        integrity_res = c.fetchall()
        if integrity_res != [("ok",)]:
            conn.rollback()
            conn.close()
            raise RuntimeError(f"Database integrity check failed during migration: {integrity_res}")

        # Commit only after all integrity and foreign key checks pass 100%
        conn.commit()
        conn.close()

        return {
            "status": "SUCCESS",
            "version": MIGRATION_VERSION_CODE,
            "quarantined_admins": quarantined_admins,
            "migrated_auditors": migrated_auditors,
            "assigned_cases": assigned_cases,
            "unassigned_cases": unassigned_cases,
            "fk_errors": fk_errors,
            "integrity_check": integrity_res
        }


    except Exception as e:
        conn.rollback()
        conn.close()
        raise e


def rollback_rbac_migration(db_path: str, archive_path: str, ledger_path: str = None) -> Dict[str, Any]:
    """
    Non-destructive rollback procedure (Fix #1 & Fix #3):
    1. Exports all post-migration data in RBAC tables to archive_path before reverting.
    2. Archives external JSONL ledger if present and verifies hash without modifying the original.
    3. Drops triggers and RBAC tables without destroying original business tables or records.
    """
    import shutil
    import hashlib

    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Database not found: {db_path}")

    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    try:
        c.execute("BEGIN TRANSACTION;")

        # 1. Export post-migration data to archive SQLite database
        arch_conn = sqlite3.connect(archive_path)
        arch_c = arch_conn.cursor()

        tables_to_archive = [
            "user_global_roles",
            "case_members",
            "case_member_responsibilities",
            "system_audit_logs",
            "schema_versions"
        ]

        archived_counts = {}
        for tbl in tables_to_archive:
            # Check if table exists in source
            c.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{tbl}';")
            if c.fetchone():
                c.execute(f"PRAGMA table_info('{tbl}');")
                cols = [f"'{col[1]}'" for col in c.fetchall()]
                cols_str = ", ".join(cols)

                # Get table DDL
                c.execute(f"SELECT sql FROM sqlite_master WHERE type='table' AND name='{tbl}';")
                create_sql = c.fetchone()[0]
                arch_c.execute(create_sql)

                c.execute(f"SELECT * FROM '{tbl}';")
                rows = c.fetchall()
                if rows:
                    placeholders = ", ".join(["?"] * len(rows[0]))
                    arch_c.executemany(f"INSERT INTO '{tbl}' VALUES ({placeholders})", rows)
                archived_counts[tbl] = len(rows)

        arch_conn.commit()
        arch_conn.close()

        # 2. Archive external JSONL ledger if present (Fix #3)
        archived_ledger_path = None
        ledger_hash = None
        if ledger_path and os.path.exists(ledger_path):
            archived_ledger_path = archive_path.replace(".db", "_audit_ledger.jsonl")
            shutil.copy2(ledger_path, archived_ledger_path)
            with open(ledger_path, "rb") as f:
                src_hash = hashlib.sha256(f.read()).hexdigest()
            with open(archived_ledger_path, "rb") as f:
                dest_hash = hashlib.sha256(f.read()).hexdigest()
            if src_hash != dest_hash:
                raise RuntimeError("External audit ledger archive hash verification failed!")
            ledger_hash = dest_hash

        # 3. Drop triggers
        c.execute("DROP TRIGGER IF EXISTS trg_prevent_audit_update;")
        c.execute("DROP TRIGGER IF EXISTS trg_prevent_audit_delete;")


        # 3. Drop RBAC tables in foreign-key dependency order
        c.execute("DROP TABLE IF EXISTS case_member_responsibilities;")
        c.execute("DROP TABLE IF EXISTS case_members;")
        c.execute("DROP TABLE IF EXISTS user_global_roles;")
        c.execute("DROP TABLE IF EXISTS system_audit_logs;")
        c.execute("DROP TABLE IF EXISTS schema_versions;")

        conn.commit()
        conn.close()

        return {
            "status": "ROLLBACK_SUCCESS",
            "archive_path": archive_path,
            "archived_ledger_path": archived_ledger_path,
            "ledger_hash": ledger_hash,
            "archived_counts": archived_counts
        }


    except Exception as e:
        conn.rollback()
        conn.close()
        raise e
