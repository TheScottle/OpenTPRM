# OpenTPRM Threat Model (stub — M0)

## Assets

- Third-party inventory, assessments, evidence originals, findings, risk decisions
- Audit log integrity
- Master key / KEKs / per-vendor data keys
- Agent OAuth grants and session cookies
- Client-Confidential and Privileged content

## Trust boundaries

1. Reverse proxy / host network → Listener A (internal) / Listener B (portal)
2. Workforce IdP → OIDC client
3. Local LLM agent hosts → MCP / agent REST (Agent Gateway)
4. Sandbox child process (no network) ← untrusted file bytes
5. Egress allow-list → IdP, SMTP, registered inference, connectors

## Priority threats (M0 focus)

| ID | Threat | Mitigations |
| --- | --- | --- |
| T-01 | Container escape / privilege | nonroot, cap_drop ALL, seccomp, read-only root, SEC-CTN-006 |
| T-02 | Data access while sealed | Sealed mode: data endpoints 503 (AT-10) |
| T-03 | Audit tampering | Hash chain + `opentprm audit verify` (AT-11) |
| T-04 | Authz bypass | Cedar default-deny; matrix harness |
| T-05 | Secret leakage | Secrets only from `/run/secrets`; never env |

This document is updated every milestone.
