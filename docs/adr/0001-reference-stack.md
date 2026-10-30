# ADR-001: Reference stack

## Status

Accepted

## Context

OpenTPRM must run as one self-hosted, security-first TPRM container with a minimal dependency tree, no interpreter, and offline-capable builds (free sources only).

## Decision

- Language: Go (toolchain directive `go1.27.3` or later supported release), `CGO_ENABLED=0`.
- Single static binary `opentprm` in a distroless/static nonroot image.
- Server-rendered UI via `html/template` with first-party CSS/JS only.
- Database: SQLite via `ncruces/go-sqlite3` with AES-XTS VFS (see ADR-003).
- Authorization: Cedar via `cedar-go`.
- Questionnaire logic: CEL via `cel.dev/cel-go`.
- Agent interface: official `modelcontextprotocol/go-sdk` (stateless MCP 2026-07-28).

## Consequences

Python/FastAPI and Node were rejected for supply-chain and runtime surface. All other dependencies need their own ADR and must be MIT/BSD/Apache-2.0/ISC/MPL-2.0.
