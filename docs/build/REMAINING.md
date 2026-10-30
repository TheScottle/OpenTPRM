# OpenTPRM remaining work (M0→M9)

Ordered by security-first milestone. Each slice lists concrete file targets and exit tests. Do not claim a milestone complete unless its exit gate truly passes.

**Progress snapshot (live-prep):** **First-login docs + `/bootstrap` UI + `POST /api/v1/auth/bootstrap`** (OPS-003 HTTP consume); handbook **workflows.md**; Unraid cross-links; CGO-free test/build/smoke (`init` + sealed/unsealed `/health/*`). Prior gap close: exception UI; OIDC PKCE fake IdP; marked ZIP (ADR-0004); admin/agent-grants stubs; portal rate limit + honeypot; NFR ready smoke.

## Recovered WIP (`cursor/opentprm-recover-wip-ebfc`)

Parallel-agent / finish-gaps uncommitted work was collected from `cursor/opentprm-unraid-ebfc` WIP plus prior stashes and landed on main (Unraid pack under `deploy/unraid/` kept intact). Feature branches were cleaned after live-prep merge.

| Item | Landed | Still open |
| --- | --- | --- |
| Agent grants list/revoke API + HTML | yes | — |
| Exceptions / admin keys+backups HTML + nav | yes | admin action APIs beyond stubs |
| Portal `RateLimiter` + login honeypot | yes | broader anti-automation / ZAP |
| OIDC auth-code+PKCE client + fake-IdP unit + handbook | yes | HTTP `/auth/oidc/*` → session bridge |
| SQLite XTS hexkey on every pool conn + `MaxOpenConns(1)` | yes | — |
| NFR concurrent ready + auth smoke | yes | vegeta/k6 |
| ADR-0004 pdfcpu re-eval; marked ZIP retained | yes | slim PDF pack if size budget allows |

## M0 — Secure skeleton (auth essentials still open)

**Done (foundation):** sealed start + keyring, TLS listeners, Cedar PDP, hash-chained audit, Dockerfile/compose scaffold, AT-10/AT-11/SEC-CTN-006/SEC-AZ-004 harnesses; session/CSRF/OIDC-claim/bootstrap/break-glass unit layers; **OIDC auth-code+PKCE client against fake IdP** (`TestSEC_AN_001_OIDCAuthCodePKCEAgainstFakeIdP`) + Keycloak config notes in handbook; WebAuthn enroll/login/step-up with **COSE key metadata + webauthncose verify** (full CTAP attestation UI still open); production config refusals (TLS, master key, allow_dev_headers); **OPS-004 demo seed refuse** + **richer Sterling & Vance graph (dev-only)**.

| Slice | File targets | Exit tests |
| --- | --- | --- |
| Session store + CSRF | `internal/authn/session.go`, `session_store.go`, `csrf.go`, wire in `internal/http/server.go` / `routes.go` | `TestSEC_AN_004_*`, `TestSEC_WEB_CSRF_*` |
| Bootstrap + break-glass | `bootstrap.go`; `opentprm init` → DB; **`POST /api/v1/auth/bootstrap` + `/bootstrap` UI**; break-glass registry | `TestOPS_003_*`, `TestOPS_003_BootstrapHTTPConsume`, `TestSOD_8_BreakGlass_*` |
| WebAuthn challenges | `internal/authn/webauthn.go` (challenge TTL/single-use); credential table already in `001_init.sql` | `TestSEC_AN_003_StepUp_*`, `TestSEC_AN_006_*` |
| WebAuthn enroll/login + COSE | `webauthn.go` CredentialStore + COSE meta migration `009_*`; `/api/v1/auth/webauthn/*` | `TestSEC_AN_006_WebAuthnEnrollLoginStepUp`, `TestSEC_AN_006_WebAuthnCOSEPublicKeyEnrollAssert` |
| OIDC SSO client | `internal/authn/oidc.go`, `oidc_client.go`; Keycloak notes in `docs/handbook/operator.md` | `TestSEC_AN_001_OIDCClaimValidation`, `TestSEC_AN_001_OIDCAuthCodePKCEAgainstFakeIdP` |
| Authz context from session | Replace sole reliance on `X-OpenTPRM-*` in `routes.go` with cookie session → `authz.Context` (dev headers only behind non-prod flag) | `TestSEC_AZ_001_MiddlewareOrder_*`, `TestSEC_AZ_001_ProductionDevHeadersRefused` |
| Production insecure refuse | `internal/config/config.go` Validate | `TestOPS_001_ProductionRefusesInsecure` |
| Demo seed refuse (OPS-004) | `internal/seed/demo.go`, `demo_graph.go`, `cmd/opentprm` serve | `TestOPS_004_DemoSeedRefusedInProduction`, `TestOPS_004_RicherSterlingVanceDemoGraphDevOnly` |
| SEC-SC-006 CI | `.github/workflows/ci.yml` SBOM/govulncheck/license allow-list | CI job green on PR |

**Not claimed complete until:** full WebAuthn attestation/CTAP enroll UI, live Keycloak fixture in CI, CSRF on every mutating cookie route, full SC-006 gate.

## M1 — Inventory and intake

**Done (partial):** vendor create/list, intake create/submit + tiering, assessment create/transition, shred tombstone; INV-001–009 store coverage; nested contacts/engagements/history/fourth-party/CSV import; custom fields; AT-01 HTTP E2E; expanded authz matrix rows for M1 routes; **vendors list UI template**; **intake analyst queue HTML (`/intakes`)**.

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
| Intake E2E + UI queues | handlers + `web/templates/intakes.tmpl` | `TestAT_01_IntakeSubmitHTTPE2E`; `TestUI_IntakeAnalystQueue` |

**Not claimed complete until:** every M1 route exercised in an HTTP authz matrix (store/Cedar matrix expanded); richer intake triage actions in UI.

## M2 — Questionnaires

**Done (partial):** template/version/publish store API; Core/Lite/Intake seeds with STD-006 provenance; QST SOD publish tests; **signed offline zip Pack/Unpack + AT-07**; **OSCAL catalog import + CSV/XLSX mapping imports**; **QST-011 limits**; **instances/responses/reviews/scoring + AT-15 delta HTTP**; **answer library store+HTTP + HTML UI**.

| Slice | Targets | Exit |
| --- | --- | --- |
| Template authoring API/UI | store + handlers + `web/templates` | AT-07 (API publish + offline zip done; UI open) |
| Modules/assembly, Lite/Intake/overlays seeds | `testdata/seed/`, publish path | `TestQST_PublishAndSTD006Seeds` |
| OSCAL + generic CSV/XLSX import | `import_oscal.go`, `import_tabular.go` | `TestImportOSCALCatalog`, `TestImportCSV*`, `TestImportXLSXHappyPath` |
| Offline packages | `offline.go` PackZip/UnpackZip | `TestOfflineZipRoundTripAndLockedCell`, `TestAT_07_*` |
| QST-011 limits | `limits.go` + import path | `TestQST_011_*` |
| Instances/responses/review/scoring API | `store/instances.go` + handlers | `TestQST_InstanceResponseReviewAndAT15Delta`, `TestAT_15_DeltaInstanceHTTPE2E` |
| Answer library + delta HTTP + UI | delta wired; `answer_library` store+HTTP; `web/templates/answer_library.tmpl` | `TestQST_035_AnswerLibrary`, `TestQST_035_AnswerLibraryHTTP`, `TestUI_AnswerLibraryPage` |

## M3 — Evidence sandbox

**Done (partial):** magic/quarantine/AT-08 validation; detectors; **chunked upload sessions + complete → blob + quarantine**; blob Get round-trip; sandbox path allow-list + empty-env network forbid; **Landlock probe + ApplyChildHooks (degraded without ABI)**; **evidence_pages + SanitizeViewerText stubs**; **SOC review schema embed**; **FuzzValidateUpload stub + `testdata/fuzz/ValidateUpload` seeds**; **TXT/JSON extract + PDF page-count stub**; **ADR-0004 defers go-pdfium wazero**.

| Slice | Targets | Exit |
| --- | --- | --- |
| Chunked uploads | `store/uploads.go`, `/uploads` + `:complete` | `TestEVD_ChunkedUploadCompleteQuarantine` |
| Landlock/seccomp + Wasm PDFium | `isolation_*.go`, `policy.go`, `extract.go`, `pdf_pages.go`, ADR-0004 | probe/hooks + TXT/JSON extract + PDF page-count stub; real Wasm PDFium deferred |
| Blob round-trip + safe viewer | `viewer.go` HTML + pages `/text` `/html` APIs | `TestBlobRoundTrip`; `TestSanitizeViewerText*`; `TestRenderViewerHTMLSafe`; `TestEVD_EvidencePageHTMLViewer` |
| SOC schemas + fuzz corpora | `api/schemas/soc-review-v1.json`; `FuzzValidateUpload` | `TestSOCReviewSchemaEmbedded`; fuzz stub present; expand corpora / CI fuzz job still open |

## M4 — Risk / contracts / ops

**Done (partial):** finding transitions + remediation plans; risk register persist/list; clients/requirements flow-down → obligations; contract clause defaults; monitoring dispositions; offboarding checklist; legal holds + retention helpers (shred blocked); backup CLI + ARC-013 verify-only drill; `/agent/call` via gateway; **exceptions create/list + SOD-2 + signed approve path + HTML UI**; **reports/exports with GEN-012 markings + sensitive step-up gate**; **committee/export marked text ZIP packs** (pdfcpu PDF deferred again after Apache-2.0/CGO-free re-check — 29MiB module).

| Slice | Targets | Exit |
| --- | --- | --- |
| Findings/remediation, risk register | `domain/finding`, `store/risk_lifecycle.go`, handlers `:transition` / remediation / `/risk-register` | `TestFND_*`, `TestFND_RSK_*` |
| Contracts/obligations/clients | `domain/contract`, obligations/clients APIs | `TestCON_*` |
| Monitoring + offboarding | `domain/monitoring`, `domain/offboarding`, disposition + checklist APIs | `TestMON_*`, `TestOFF_*` |
| Reports/exports/markings | `domain/reporting`, `store/exports.go`, `/reports/{type}`, `/exports` | `TestGEN_012_*`, `TestRPT_*`, `TestRPT_EXC_ReportsExportsExceptionsHTTP` |
| Retention/legal hold + backup CLI | `store/retention.go`, `internal/backup/`, `opentprm backup\|restore --verify-only` | `TestARC_002_*`, `TestARC_013_*`, AT-14 (hold-aware) |
| Exceptions signed decisions + UI | `store/exceptions.go` + `web/templates/exceptions.tmpl` | `TestEXC_CreateListApprove_SOD2`, HTTP path; `TestUI_ExceptionListApprove` |
| Full restore write path | `opentprm restore` without `--verify-only` | still refused (verify-only only) |
| Committee pack / second approver on bulk | `/exports/{id}:approve` SOD + marked ZIP (`?format=zip`, `:bundle`) | `TestRPT_004_ExportSecondApprover*`, `TestRPT_002_CommitteeMarkedZipPack`; pdfcpu PDF pack deferred (ADR-0004) |

## M5 — OpenAPI contract

**Done (partial):** expanded OpenAPI catalog toward §10.2 (**tasks, soc-reviews alias, audit-events, admin keys/backups, me/agent-grants, metrics, webauthn auth, export bundle, suggestion accept**); vendor ETags; Idempotency-Key middleware with replay header; **store-backed catalog handlers**; `/agent/tools` + **`/agent/call` via gateway**; **mux registration contract smoke**; **admin keys/backups HTML stubs**; **/me agent-grants list+revoke UI/API**.

| Slice | Targets | Exit |
| --- | --- | --- |
| Complete OpenAPI §10.2 | `api/openapi.yaml` (expanded; questionnaire `:send`/clarifications etc. still thin) | `TestOpenAPI_RoutesHaveMuxRegistrationSmoke`; full §10.2 still open |
| oapi-codegen stubs | generated server types | still open (contract smoke substitutes) |
| ETags / Idempotency / cursors | middleware + store row_version | contract tests (idempotency covered in AT-01 HTTP) |
| Replace empty/501 handlers | `handlers_domain.go` + `store/catalog.go` | catalog paths store-backed; `/agent/call` gateway-backed; admin/me HTML stubs landed |

## M6 — OAuth AS + MCP

**Done (partial):** PRM + AS metadata; **opaque 256-bit access tokens stored hashed**; **PKCE S256 + auth codes**; **DPoP proof parse/verify (go-jose)**; **`/oauth/authorize` + `/oauth/token` (client_credentials + authorization_code + refresh_token)**; **refresh rotate + reuse detect**; **mTLS client-cred stub**; **MCP initialize/discover + Tasks + conformance tests**; **gateway budget tracker (AI-032)**; **change-request approval HTML + API `:approve`/`:reject` with step-up**; **AT-06 stale ETag + SOD dual-control**.

| Slice | Targets | Exit |
| --- | --- | --- |
| Real AS (fosite or ADR alt) | `internal/authn/as.go`, `pkce.go`, `dpop.go`, `refresh.go`, `mtls.go` | `TestAI_023_*`, `TestOAuth_PKCEAuthorizeCodeAndToken`, `TestOAuth_RefreshRotateAndReuseDetect`, `TestOAuth_MTLSClientCredentialsStub`; fosite / production mTLS still open |
| MCP SDK conformance + Tasks | `internal/mcp/` | AT-03 + `TestAI_005_TasksExtensionStubs` + `TestMCP_InitializeAndDiscoverConformance`; full SDK suite still open |
| Budgets/kill switches persisted | gateway budgets in-memory; DB counters open | `TestAI_032_BudgetWiredOnGateway` |
| Change-request approval UI | `web/templates/change_requests.tmpl` + step-up + AT-06 | `TestAT_05_ChangeRequestApprovalUI`, `TestAT_06_StaleChangeRequestHTTP`, `TestAT_06_DecideChangeRequestStaleAndSOD` |

## M7 — AI registries and evals

**Done (partial):** **model-endpoint HTTP CRUD**; **suggestions-only AI job stub with ai_call_logs writes**; **evals harness (AT-04 zero tolerance)**; **suggestion accept with citation verify**.

| Slice | Targets | Exit |
| --- | --- | --- |
| Model/endpoint registries | admin API CRUD store-backed | `TestAI_ModelEndpointHTTPCRUD` |
| Inference jobs + eval harness | `internal/ai/jobs.go`, `evals/` | `TestAI_JobStubCreatesSuggestionsOnly`, `TestAT_04_EvalHarnessInjectionZeroTolerance`, `TestAI_CallLogWrites` |
| AI labels/logging + citations | `ai_call_logs`, suggestion `:accept` | `TestAI_AcceptRequiresVerifiedCitations`, `TestAI_AcceptSuggestionCitationPath`, `TestAI_SuggestionAcceptCitationHTTP` |
| Broader eval CI / model activation gate in deploy | CI job + more fixtures | still open |

## M8 — Listener B / portal

**Done (partial):** **portal listener wiring when enabled**; **magic-link issue/consume stub**; **passkey enroll + TOTP enroll/verify stubs**; **questionnaire list scoped by vendor_id**; **anti-automation: per-IP/email rate limit + honeypot field**.

| Slice | Targets | Exit |
| --- | --- | --- |
| Portal flows | `internal/portal/`, Listener B in `ListenAndServeTLS` | `TestPortalEnabledWiresListener`, `TestPOR_*` |
| Magic-link + passkey/TOTP | `magiclink.go`, `mfa.go` | `TestPOR_002_MagicLinkIssueConsume`, `TestPOR_002_PasskeyEnrollStub`, `TestPOR_002_TOTPEnrollVerifyStub`; full WebAuthn attestation still open |
| Anti-automation + DAST hardening | `ratelimit.go` + honeypot on login | `TestPOR_005_LoginHoneypotAndRateLimit`; ZAP baseline still open |

## M9 — UI, NFR, release

**Done (partial):** **analyst home + vendors + intakes + exceptions + answer-library + change-requests + agent-grants + admin stubs via `html/template` + `/static/app.css`**; **CycloneDX SBOM (`make sbom` + CI)**; **gosec CI step**; **SLSA provenance stub (`make provenance-stub`, `docs/build/SLSA-PROVENANCE.md`)**; **multi-arch buildx note in handbook**; **cosign verify placeholder (`scripts/cosign-verify.sh`)**; **NFR-001 ready latency + concurrent ready + authenticated /me smoke**.

| Slice | Targets | Exit |
| --- | --- | --- |
| Real UI (`html/template`) | `web/templates`, `web/static` | `TestUI_AnalystHomeAndVendors`, `TestUI_IntakeAnalystQueue`, `TestUI_AnswerLibraryPage`, `TestUI_ExceptionListApprove`, `TestUI_AdminKeysBackupsAndAgentGrantsRevoke`, `TestAT_05_ChangeRequestApprovalUI`; more screens / screenshots still open |
| NFR tests | httptest `/health/ready` p95 + concurrent ready + auth API | `TestNFR_001_HealthReadyLatencySmoke`, `TestNFR_001_ConcurrentReadyAndAuthenticatedAPISmoke`; vegeta/k6 still open |
| SBOM/cosign/SLSA + handbook/threat model | CI + `docs/` | CycloneDX + gosec + provenance stub + cosign placeholder; signed attestations + TST-001–010 still open |

## Cross-cutting (always open until M9)

- Dev `X-OpenTPRM-*` headers → session/OIDC/DPoP only in production
- Store incomplete vs migrations → close field gaps per milestone
- `evals/` harness started (AT-04); expand fixtures and CI gate
- Traceability: keep `docs/traceability/MUST-map.md` updated as tests land
- oapi-codegen + remaining thin §10.2 questionnaire/instance subpaths still open
- OPS-004 richer demo graph landed (store apply wiring in `cmd` still optional)
- Full PDF text extract deferred (ADR-0004); pdfcpu committee PDF deferred (license/CGO OK; module size)
