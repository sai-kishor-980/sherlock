# HMACFR Database Schema Specification

The HMACFR platform uses relational database models managed via SQLAlchemy and SQLite/PostgreSQL.

---

## Entity Relationship Diagram Overview

```
 ┌──────────────────────┐          ┌──────────────────────┐
 │        cases         │ 1      * │       evidence       │
 ├──────────────────────┼──────────┼──────────────────────┤
 │ PK case_id           │          │ PK evidence_id       │
 │    case_name         │          │ FK case_id           │
 │    investigator_name │          │    original_filename │
 │    description       │          │    stored_filename   │
 │    priority          │          │    category          │
 │    status            │          │    storage_path      │
 │    created_at        │          │    file_hash         │
 │    updated_at        │          │    hmac_signature    │
 └──────────────────────┘          └──────────┬───────────┘
                                              │ 1
                                              │
                                              │ *
                                   ┌──────────┴───────────┐
                                   │   chain_of_custody   │
                                   ├──────────────────────┤
                                   │ PK log_id            │
                                   │ FK evidence_id       │
                                   │    action            │
                                   │    performed_by      │
                                   │    timestamp         │
                                   │    remarks           │
                                   └──────────────────────┘
```
