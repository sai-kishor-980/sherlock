import sqlite3

conn = sqlite3.connect('sherf/backend/hmacfr.db')
c = conn.cursor()
c.execute("UPDATE evidence SET status = 'VALIDATED' WHERE status = 'Uploaded' OR status IS NULL")
conn.commit()
print(f"Updated {c.rowcount} evidence rows to VALIDATED.")
c.execute("SELECT evidence_id, original_filename, status FROM evidence LIMIT 5")
for r in c.fetchall():
    print(r)
conn.close()

