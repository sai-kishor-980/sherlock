# HMACFR Chain of Custody Standard Operating Procedure

The **Chain of Custody** protocol records every transfer, inspection, hash calculation, encryption event, and verification audit performed on digital evidence.

## Audit Log Guarantees
1. **Immutability**: Log entries are appended with UTC timestamps and investigator identities.
2. **Cryptographic Linking**: Every evidence record binds an initial SHA-256 hash digest and HMAC signature upon upload.
3. **Audit Trail**: Every action (Upload, Verification, Encryption, ReadOnly Locking, Relocation) creates an explicit entry in `chain_of_custody` and `logs/custody.log`.
