import sqlite3

def verify_live_db():
    conn = sqlite3.connect('hmacfr.db')
    c = conn.cursor()

    # 1. Integrity and Foreign Keys
    integrity = c.execute('PRAGMA integrity_check;').fetchall()
    fk = c.execute('PRAGMA foreign_key_check;').fetchall()
    assert integrity == [('ok',)], f'Integrity failed: {integrity}'
    assert fk == [], f'FK violations: {fk}'
    print('[PASS] Integrity check:', integrity)
    print('[PASS] Foreign key check:', fk)

    # 2. Schema Versions
    v = c.execute('SELECT version_code, description, applied_at FROM schema_versions;').fetchall()
    print('[PASS] Schema versions:', v)
    assert len(v) >= 1 and v[0][0] == 'V1_RBAC_FOUNDATION'

    # 3. Tables check
    tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()]
    required_tables = [
        'users', 'cases', 'evidence', 'chain_of_custody',
        'user_global_roles', 'case_members', 'case_member_responsibilities',
        'system_audit_logs', 'schema_versions'
    ]
    for t in required_tables:
        assert t in tables, f'Missing table: {t}'
    print('[PASS] All required tables present:', len(tables))

    # 4. Triggers check
    triggers = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='trigger';").fetchall()]
    assert 'trg_prevent_audit_update' in triggers
    assert 'trg_prevent_audit_delete' in triggers
    print('[PASS] Audit triggers present:', triggers)

    # 5. User Global Roles
    roles = c.execute('SELECT user_id, role_name FROM user_global_roles;').fetchall()
    print('[PASS] User global roles:', roles)
    assert ('USR_c6cd642be2ac', 'Platform Super Admin') in roles
    assert ('USR_c6cd642be2ac', 'Access Administrator') in roles

    # 6. Users table check
    users = c.execute('SELECT user_id, username, role, token_version FROM users;').fetchall()
    print('[PASS] Users in DB:', users)
    admin_user = [u for u in users if u[1] == 'admin'][0]
    assert admin_user[2] == 'Admin'
    assert admin_user[3] >= 2

    # 7. Immutability triggers execution test
    c.execute('BEGIN TRANSACTION;')
    c.execute(
        "INSERT INTO system_audit_logs (log_id, action, target_resource, previous_hash, row_hash, hmac_signature) "
        "VALUES (?, ?, ?, ?, ?, ?);",
        ('TEST_LOG', 'TEST', 'test', '0' * 64, '0' * 64, '0' * 64)
    )

    try:
        c.execute("UPDATE system_audit_logs SET action = ? WHERE log_id = ?;", ('MUTATED', 'TEST_LOG'))
        assert False, 'Audit update trigger failed to abort!'
    except sqlite3.DatabaseError as e:
        assert 'CRITICAL SECURITY VIOLATION' in str(e)
        print('[PASS] Immutability trigger prevented UPDATE successfully')

    try:
        c.execute("DELETE FROM system_audit_logs WHERE log_id = ?;", ('TEST_LOG',))
        assert False, 'Audit delete trigger failed to abort!'
    except sqlite3.DatabaseError as e:
        assert 'CRITICAL SECURITY VIOLATION' in str(e)
        print('[PASS] Immutability trigger prevented DELETE successfully')

    conn.rollback()
    conn.close()
    print('\n*** ALL LIVE DATABASE VERIFICATIONS PASSED 100% ***')

if __name__ == '__main__':
    verify_live_db()
