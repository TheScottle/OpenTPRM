# OpenTPRM remaining work (M0→M9)

Ordered by security-first milestone. Each slice lists concrete file targets and exit tests. Do not claim a milestone complete unless its exit gate truly passes.

**Progress snapshot (this branch):** M0 auth packages include session/CSRF/OIDC/bootstrap/break-glass plus a limited WebAuthn enroll/login/step-up path (Ed25519 challenge signing; full WebAuthn attestation still open). Production refuses TLS-less boot, missing master key, and `identity.allow_dev_headers`. M1 inventory covers INV-001–009 (tags + typed custom fields, next-action-due from renewal/reassessment/evidence/remediation) with HTTP AT-01 intake submit E2E and expanded SEC-AZ-004 matrix for M1 routes; intake UI queues still open. M2 questionnaire template/version/publish store + Core/Lite/Intake seeds with STD-006 provenance landed; OSCAL/XLSX import and offline zip packaging remain. M5: Idempotency-Key middleware + vendor ETags present; oapi-codegen and replacing remaining empty catalog handlers still open.

## M0 — Secure skeleton (auth essentials still open)

**Done (foundation):** sealed start + keyring, TLS listeners, Cedar PDP, hash-chained audit, Dockerfile/compose scaffold, AT-10/AT-11/SEC-CTN-006/SEC-AZ-004 harnesses; session/CSRF/OIDC-claim/bootstrap/break-glass unit layers; limited WebAuthn enroll/login/step-up; production config refusals (TLS, master key, allow_dev_headers).

| Slice | File targets | Exit tests |
| --- | --- | --- |
| Session store + CSRF | `internal/authn/session.go`, `session_store.go`, `csrf.go`, wire in `internal/http/server.go` / `routes.go` | `TestSEC_AN_004_*`, `TestSEC_WEB_CSRF_*` |
| Bootstrap + break-glass | `internal/authn/bootstrap.go`, `breakglass.go`; `opentprm init` token → DB; enroll first admins | `TestOPS_003_*`, `TestSOD_8_BreakGlass_*` |
| WebAuthn challenges | `internal/authn/webauthn.go` (challenge TTL/single-use); credential table already in `001_init.sql` | `TestSEC_AN_003_StepUp_*`, `TestSEC_AN_006_*` |
| WebAuthn enroll/login (limited) | `webauthn.go` CredentialStore + `/api/v1/auth/webauthn/*` | `TestSEC_AN_006_WebAuthnEnrollLoginStepUp` |
| OIDC SSO client | `internal/authn/oidc.go`; config under `deploy/config.example.yaml` | `TestSEC_AN_001_*` (nonce/iss/aud validation unit) |
| Authz context from session | Replace sole reliance on `X-OpenTPRM-*` in `routes.go` with cookie session → `authz.Context` (dev headers only behind non-prod flag) | `TestSEC_AZ_001_MiddlewareOrder_*`, `TestSEC_AZ_001_ProductionDevHeadersRefused` |
| Production insecure refuse | `internal/config/config.go` Validate | `TestOPS_001_ProductionRefusesInsecure` |
| SEC-SC-006 CI | `.github/workflows/ci.yml` SBOM/govulncheck/license allow-list | CI job green on PR |

**Not claimed complete until:** full WebAuthn attestation/CTAP enroll UI, OIDC against Keycloak fixture, CSRF on every mutating cookie route, full SC-006 gate.

## M1 — Inventory and intake

**Done (partial):** vendor create/list, intake create/submit + tiering, assessment create/transition, shred tombstone; INV-001–009 store coverage; nested contacts/engagements/history/fourth-party/CSV import; custom fields; AT-01 HTTP E2E; expanded authz matrix rows for M1 routes.

| Slice | File targets | Exit tests |
| --- | --- | --- |
| Vendor CRUD + INV-001 fields | `internal/store/models.go`, `inventory.go`; handlers in `handlers_domain.go` | `TestINV_001_*`, `TestINV_006_*` |
| Contacts + fourth parties | store methods + `/vendors/{id}/contacts`, `/fourth-party-links` | `TestINV_004_*`, `TestINV_005_*` |
| Duplicate detect + merge + history | `MergeVendors`, `object_history`, `:merge` route | `TestINV_002_*`, `TestINV_007_*` |
| Engagements full model | `CreateEngagement`/`Update`/`List` matching `002_inventory.sql` | `TestINV_003_*`, `TestINV_009_*` |
| Tags + custom fields (INV-006) | `custom_fields.go`, migration `006_custom_fields.sql` | `TestINV_006_TagsAndCustomFields` |
| Next action due (INV-009) | `next_action.go` RecalculateNextActionDue | `TestINV_009_NextActionDueEarliest` |
| Bulk CSV import quarantine | `internal/store/import_csv.go` (no formula eval) | `TestINV_008_*` |
| Route authz matrix M1 | expand `matrix_test.go` for all M1 routes × roles | SEC-AZ-004 covers M1 |
| Intake E2E + UI queues | handlers + minimal templates | `TestAT_01_IntakeSubmitHTTPE2E`; ASM-001 already present |

**Not claimed complete until:** intake UI queue screens, every M1 route exercised in an HTTP authz matrix (store/Cedar matrix expanded; UI still missing).

## M2 — Questionnaires

**Done (partial):** template/version/publish store API; Core/Lite/Intake seeds with STD-006 provenance validation; QST SOD publish tests.

| Slice | Targets | Exit |
| --- | --- | --- |
| Template authoring API/UI | store + handlers + `web/templates` | AT-07 (API publish done; UI open) |
| Modules/assembly, Lite/Intake/overlays seeds | `testdata/seed/`, publish path | `TestQST_PublishAndSTD006Seeds` |
| OSCAL + generic CSV/XLSX import | `internal/domain/questionnaire/import_*.go` | AT-15 |
| Offline packages | expand `offline.go` + real zip packaging | offline round-trip |
| QST-011 limits | size/count caps | `TestQST_011_*` |

## M3 — Evidence sandbox

| Slice | Targets | Exit |
| --- | --- | --- |
| Chunked uploads | `/uploads` sessions + `:complete` | EVD upload tests |
| Landlock/seccomp + Wasm PDFium | `internal/sandbox/`, `opentprm sandbox` | AT-08/AT-09 + no-network |
| Blob round-trip + safe viewer | `internal/blob/`, evidence pages | EVD viewer tests |
| SOC schemas + fuzz corpora | `api/schemas/`, `testdata/fuzz/` | schema validate + fuzz |

## M4 — Risk / contracts / ops

| Slice | Targets | Exit |
| --- | --- | --- |
| Findings/remediation, risk register | store + handlers | FND/RSK tests |
| Contracts/obligations/clients | migrations + API | CON tests |
| Monitoring + offboarding | domain + API | MON/OFF tests |
| Reports/exports/markings | export pipeline | RPT + step-up for bulk |
| Retention/legal hold + backup CLI | `internal/backup/`, `opentprm backup\|restore` | ARC/AT-14 + restore verify |

## M5 — OpenAPI contract

**Done (partial):** expanded OpenAPI catalog; vendor ETags; Idempotency-Key middleware with replay header.

| Slice | Targets | Exit |
| --- | --- | --- |
| Complete OpenAPI §10.2 | `api/openapi.yaml` | schema lint |
| oapi-codegen stubs | generated server types | compile |
| ETags / Idempotency / cursors | middleware + store row_version | contract tests (idempotency covered in AT-01 HTTP) |
| Replace empty/501 handlers | `handlers_domain.go` | no 501 on catalog paths |

## M6 — OAuth AS + MCP

| Slice | Targets | Exit |
| --- | --- | --- |
| Real AS (fosite or ADR alt) | `internal/authn/as.go`, PKCE/DPoP/mTLS | OAuth conformance smoke |
| MCP SDK conformance + Tasks | `internal/mcp/` | AT-03 + MCP tests |
| Budgets/kill switches persisted | settings/DB | AI budget tests |
| Change-request approval UI | templates + step-up | AT-05/AT-06 |

## M7 — AI registries and evals

| Slice | Targets | Exit |
| --- | --- | --- |
| Model/endpoint registries | admin API | AI registry tests |
| Inference jobs + eval harness | `internal/ai/`, `evals/` | AT-04 + eval CI |
| AI labels/logging | audit + response headers | AI label tests |

## M8 — Listener B / portal

| Slice | Targets | Exit |
| --- | --- | --- |
| Portal flows | `internal/portal/`, Listener B | POR tests |
| Magic-link + passkey/TOTP | authn portal namespace | POR-002 |
| Anti-automation + DAST hardening | rate limits, headers | ZAP baseline |

## M9 — UI, NFR, release

| Slice | Targets | Exit |
| --- | --- | --- |
| Real UI (`html/template`) | `web/templates`, `web/static` | smoke screenshots |
| NFR tests | load/latency budgets | NFR suite |
| SBOM/cosign/SLSA + handbook/threat model | CI + `docs/` | TST-001–010 gates |

## Cross-cutting (always open until M9)

- `web/templates` empty → real UI
- Dev `X-OpenTPRM-*` headers → session/OIDC/DPoP only in production
- Store incomplete vs migrations → close field gaps per milestone
- `api/schemas` and `evals/` empty → fill in M3/M7
- Traceability: keep `docs/traceability/MUST-map.md` updated as tests land
