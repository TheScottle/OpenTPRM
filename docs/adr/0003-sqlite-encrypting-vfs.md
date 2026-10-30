# ADR-003: SQLite encrypting VFS

## Status

Accepted

## Context

OpenTPRM requires encryption at rest for the system-of-record database without cgo. Spec §11.5 requires AES-256-XTS with a 64-byte key set by PRAGMA immediately after open (never in the DSN).

## Decision

- Module: `github.com/ncruces/go-sqlite3` **v0.36.0**
- VFS: `github.com/ncruces/go-sqlite3/vfs/xts` (registers VFS name `xts`)
- Key: 64-byte random DEK from the keyring; applied via `PRAGMA hexkey='...'` in the `driver.Open` connection-init callback (every pooled conn), never via URI `key`/`hexkey` parameters.
- PRAGMA after open (same init callback): `secure_delete=ON`, `foreign_keys=ON`, `temp_store=MEMORY`, WAL mode.
- Pool: `SetMaxOpenConns(1)` / `SetMaxIdleConns(1)` — SQLite XTS single-writer.

## Fallbacks (documented downgrade only)

1. `vfs/adiantum` from the same project
2. Plain SQLite + host LUKS volume (operator handbook)

## Consequences

XTS provides confidentiality, not tamper detection. Integrity relies on AEAD field/blob encryption, signed decision records, hash-chained audit log, and signed backups.
