"""
HMACFR Database Inspector Utility.
Prints all tables, schemas, and records inside hmacfr.db cleanly in the terminal.
"""

import sqlite3
import os
from pathlib import Path

db_path = Path(__file__).parent / "hmacfr.db"

if not db_path.exists():
    print(f"Database file not found at: {db_path}")
    exit(1)

conn = sqlite3.connect(str(db_path))
cursor = conn.cursor()

print("==================================================================")
print(f"  HMACFR SQLite Database Inspector ({db_path.name})")
print("==================================================================")

# Get all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = [row[0] for row in cursor.fetchall() if not row[0].startswith("sqlite_")]

for table in tables:
    print(f"\n📋 TABLE: {table.upper()}")
    print("-" * 66)
    
    # Get column names
    cursor.execute(f"PRAGMA table_info({table});")
    columns = [col[1] for col in cursor.fetchall()]
    print(" | ".join(columns))
    print("-" * 66)

    # Get rows
    cursor.execute(f"SELECT * FROM {table};")
    rows = cursor.fetchall()
    
    if not rows:
        print("  (Table is empty)")
    else:
        for row in rows:
            print(" | ".join(str(val) for val in row))

conn.close()
print("\n==================================================================")
