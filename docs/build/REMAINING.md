# OpenTPRM remaining work (M0→M9)

Ordered by security-first milestone. Each slice lists concrete file targets and exit tests. Do not claim a milestone complete unless its exit gate truly passes.

**Progress snapshot (this branch):** M0 auth packages include session/CSRF/OIDC/bootstrap/break-glass plus a limited WebAuthn enroll/login/step-up path (Ed25519 challenge signing; full WebAuthn attestation still open). Production refuses TLS-less boot, missing master key, and `identity.allow_dev_headers`. M1 inventory covers INV-001–009 (tags + typed custom fields, next-action-due from renewal/reassessment/evidence/remediation) with HTTP AT-01 intake submit E2E and expanded SEC-AZ-004 matrix for M1 routes; intake UI queues still open. M2: template/version/publish + Core/Lite/Intake seeds; **signed offline zip packages (AT-07 round-trip)**; **OSCAL catalog → skeleton + CSV/XLSX column-mapping imports**; **QST-011 archive/formula limits**; **instance/response/review/scoring store+HTTP + AT-15 delta HTTP E2E**. M3: **chunked upload sessions + `:complete` → encrypted blob + quarantine evidence**; blob Get round-trip; sandbox path allow-list / empty-env; **Landlock/seccomp probe + child hooks (degraded OK in CI)**; **evidence page text storage + safe viewer stubs**; **SOC review JSON Schema (`api/schemas/soc-review-v1.json`)**; **ValidateUpload fuzz stub + seed corpus**. M4: **finding status transitions + remediation plans**; **risk register persistence**; **contracts clause defaults + obligations/clients flow-down**; **monitoring dispositions**; **offboarding checklist**; **legal-hold + retention helpers (blocks shred)**; **`opentprm backup` / `restore --verify-only` (ARC-013)**; **`/agent/call` wired through Agent Gateway**; **exceptions create/list + SOD-2 approve with signed decision**; **reports/exports with GEN-012 markings + sensitive step-up**. M5: Idempotency-Key middleware + vendor ETags; **store-backed findings/contracts/monitoring/suggestions/change-requests/agent-clients/models**; expanded OpenAPI (exceptions/reports/exports). oapi-codegen still open. M6 start: **opaque hashed OAuth access tokens + DPoP header presence stub**; **MCP Tasks extension stubs**; **gateway budgets (AI-032)**. M9 start: **analyst home + vendors list `web/templates` (html/template, CSP-safe CSS)**.

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

**Done (partial):** vendor create/list, intake create/submit + tiering, assessment create/transition, shred tombstone; INV-001–009 store coverage; nested contacts/engagements/history/fourth-party/CSV import; custom fields; AT-01 HTTP E2E; expanded authz matrix rows for M1 routes; **vendors list UI template**.

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
| Intake E2E + UI queues | handlers + minimal templates | `TestAT_01_IntakeSubmitHTTPE2E`; ASM-001 already present; intake UI queues still open |

**Not claimed complete until:** intake UI queue screens, every M1 route exercised in an HTTP authz matrix (store/Cedar matrix expanded; intake UI still missing).

## M2 — Questionnaires

**Done (partial):** template/version/publish store API; Core/Lite/Intake seeds with STD-006 provenance; QST SOD publish tests; **signed offline zip Pack/Unpack + AT-07**; **OSCAL catalog import + CSV/XLSX mapping imports**; **QST-011 limits**; **instances/responses/reviews/scoring + AT-15 delta HTTP**.

| Slice | Targets | Exit |
| --- | --- | --- |
| Template authoring API/UI | store + handlers + `web/templates` | AT-07 (API publish + offline zip done; UI open) |
| Modules/assembly, Lite/Intake/overlays seeds | `testdata/seed/`, publish path | `TestQST_PublishAndSTD006Seeds` |
| OSCAL + generic CSV/XLSX import | `import_oscal.go`, `import_tabular.go` | `TestImportOSCALCatalog`, `TestImportCSV*`, `TestImportXLSXHappyPath` |
| Offline packages | `offline.go` PackZip/UnpackZip | `TestOfflineZipRoundTripAndLockedCell`, `TestAT_07_*` |
| QST-011 limits | `limits.go` + import path | `TestQST_011_*` |
| Instances/responses/review/scoring API | `store/instances.go` + handlers | `TestQST_InstanceResponseReviewAndAT15Delta`, `TestAT_15_DeltaInstanceHTTPE2E` |
| Answer library + delta HTTP | delta wired on create + `:delta` | AT-15 HTTP done; answer library table/UI open |

## M3 — Evidence sandbox

**Done (partial):** magic/quarantine/AT-08 validation; detectors; **chunked upload sessions + complete → blob + quarantine**; blob Get round-trip; sandbox path allow-list + empty-env network forbid; **Landlock probe + ApplyChildHooks (degraded without ABI)**; **evidence_pages + SanitizeViewerText stubs**; **SOC review schema embed**; **FuzzValidateUpload stub + `testdata/fuzz/ValidateUpload` seeds**.

| Slice | Targets | Exit |
| --- | --- | --- |
| Chunked uploads | `store/uploads.go`, `/uploads` + `:complete` | `TestEVD_ChunkedUploadCompleteQuarantine` |
| Landlock/seccomp + Wasm PDFium | `internal/sandbox/isolation_*.go`, `opentprm sandbox` | probe/hooks tests; real Wasm PDFium still open |
| Blob round-trip + safe viewer | `internal/blob/` Get/Put; `evidence/viewer.go` + pages API | `TestBlobRoundTrip`; `TestSanitizeViewerText*`; page stubs |
| SOC schemas + fuzz corpora | `api/schemas/soc-review-v1.json`; `FuzzValidateUpload` | `TestSOCReviewSchemaEmbedded`; fuzz stub present; expand corpora / CI fuzz job still open |

## M4 — Risk / contracts / ops

**Done (partial):** finding transitions + remediation plans; risk register persist/list; clients/requirements flow-down → obligations; contract clause defaults; monitoring dispositions; offboarding checklist; legal holds + retention helpers (shred blocked); backup CLI + ARC-013 verify-only drill; `/agent/call` via gateway; **exceptions create/list + SOD-2 + signed approve path**; **reports/exports with GEN-012 markings + sensitive step-up gate**.

| Slice | Targets | Exit |
| --- | --- | --- |
| Findings/remediation, risk register | `domain/finding`, `store/risk_lifecycle.go`, handlers `:transition` / remediation / `/risk-register` | `TestFND_*`, `TestFND_RSK_*` |
| Contracts/obligations/clients | `domain/contract`, obligations/clients APIs | `TestCON_*` |
| Monitoring + offboarding | `domain/monitoring`, `domain/offboarding`, disposition + checklist APIs | `TestMON_*`, `TestOFF_*` |
| Reports/exports/markings | `domain/reporting`, `store/exports.go`, `/reports/{type}`, `/exports` | `TestGEN_012_*`, `TestRPT_*`, `TestRPT_EXC_ReportsExportsExceptionsHTTP` |
| Retention/legal hold + backup CLI | `store/retention.go`, `internal/backup/`, `opentprm backup\|restore --verify-only` | `TestARC_002_*`, `TestARC_013_*`, AT-14 (hold-aware) |
| Exceptions signed decisions | `store/exceptions.go` create/list/approve + SOD-2 | `TestEXC_CreateListApprove_SOD2`, HTTP path; exception UI still open |
| Full restore write path | `opentprm restore` without `--verify-only` | still refused (verify-only only) |
| Committee PDF / second approver on bulk | PDF pack + dual-control | still open |

## M5 — OpenAPI contract

**Done (partial):** expanded OpenAPI catalog (instances, evidence pages/SOC, catalog POSTs, M4 risk/contracts/offboarding/legal-hold paths, **exceptions/reports/exports**); vendor ETags; Idempotency-Key middleware with replay header; **store-backed catalog handlers**; `/agent/tools` + **`/agent/call` via gateway**.

| Slice | Targets | Exit |
| --- | --- | --- |
| Complete OpenAPI §10.2 | `api/openapi.yaml` | schema lint (expanded; full §10.2 still open) |
| oapi-codegen stubs | generated server types | still open |
| ETags / Idempotency / cursors | middleware + store row_version | contract tests (idempotency covered in AT-01 HTTP) |
| Replace empty/501 handlers | `handlers_domain.go` + `store/catalog.go` | catalog paths store-backed; `/agent/call` gateway-backed |

## M6 — OAuth AS + MCP

**Done (partial):** PRM + AS metadata; **opaque 256-bit access tokens stored hashed**; **DPoP header presence stub on issue/verify**; **`/oauth/token` client_credentials stub**; **MCP Tasks `tasks/get|update|cancel` stubs (principal-bound)**; **gateway budget tracker wired into Call (AI-032)**.

| Slice | Targets | Exit |
| --- | --- | --- |
| Real AS (fosite or ADR alt) | `internal/authn/as.go`, PKCE/DPoP/mTLS | `TestAI_023_*`; full PKCE authorize UI / fosite / proof verify still open |
| MCP SDK conformance + Tasks | `internal/mcp/` | AT-03 + `TestAI_005_TasksExtensionStubs`; full SDK conformance still open |
| Budgets/kill switches persisted | gateway budgets in-memory; DB counters open | `TestAI_032_BudgetWiredOnGateway` |
| Change-request approval UI | templates + step-up | AT-05/AT-06 still open |

## M7 — AI registries and evals

| Slice | Targets | Exit |
| --- | --- | --- |
| Model/endpoint registries | admin API (list/create store-backed start) | AI registry tests |
| Inference jobs + eval harness | `internal/ai/`, `evals/` | AT-04 + eval CI |
| AI labels/logging | audit + response headers | AI label tests |

## M8 — Listener B / portal

| Slice | Targets | Exit |
| --- | --- | --- |
| Portal flows | `internal/portal/`, Listener B | POR tests |
| Magic-link + passkey/TOTP | authn portal namespace | POR-002 |
| Anti-automation + DAST hardening | rate limits, headers | ZAP baseline |

## M9 — UI, NFR, release

**Done (partial):** **analyst home + vendors list via `html/template` + `/static/app.css` (CSP-safe, no inline JS)**.

| Slice | Targets | Exit |
| --- | --- | --- |
| Real UI (`html/template`) | `web/templates`, `web/static` | `TestUI_AnalystHomeAndVendors`; more screens / screenshots still open |
| NFR tests | load/latency budgets | NFR suite |
| SBOM/cosign/SLSA + handbook/threat model | CI + `docs/` | TST-001–010 gates |

## Cross-cutting (always open until M9)

- Dev `X-OpenTPRM-*` headers → session/OIDC/DPoP only in production
- Store incomplete vs migrations → close field gaps per milestone
- `evals/` empty → fill in M7; `api/schemas` started (SOC review)
- Traceability: keep `docs/traceability/MUST-map.md` updated as tests land
- oapi-codegen + full OpenAPI §10.2 still open
