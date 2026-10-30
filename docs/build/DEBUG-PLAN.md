# OpenTPRM debug plan (first live test)

Owner: **plan → investigate → fix blockers → ship**. Branch: `cursor/opentprm-debug-ebfc`.

## Status legend

| Tag | Meaning |
|-----|---------|
| **BLOCKER** | Breaks first live test / first login / core smoke |
| **HIGH** | Breaks a documented workflow under real sessions |
| **MED** | Incomplete link / opaque error / polish for later |
| **OK** | Wired and exercised |
| **DEFERRED** | Known open; not required for first live test |

---

## 1. End-to-end workflows (`workflows.md` + `first-login.md`)

### First login

| Step | Route / surface | Store / deps | Status |
|------|-----------------|--------------|--------|
| `init` → master key, TLS, bootstrap token | CLI `opentprm init` | `authn.RegisterBootstrapToken`, `data/bootstrap.token` 0400 | OK |
| Sealed vs ready | `/health/live`, `/health/ready` | keyring + DB ping | OK |
| Bootstrap UI | `GET /bootstrap` | `bootstrap.tmpl` | **BLOCKER**: inline `<script>` vs CSP `script-src 'self'` (`server.go` CSP; `web/embed.go` claims no inline scripts) |
| Bootstrap API | `POST /api/v1/auth/bootstrap` | `ConsumeBootstrapToken` | **BLOCKER**: browser `fetch` sends `Origin: https://host:8443`; `CheckOriginRejectsCrossSite` compares without port → **403** (`session.go`; smoke repro) |
| WebAuthn enroll/login | `/api/v1/auth/webauthn/*` | challenges + credentials + sessions | OK (API path); CTAP UI DEFERRED |
| Session cookie | `__Host-otp_s` | `SessionStore` | OK create; roles reloaded on `LookupByID` from `users` |
| CSRF | middleware + header | hash in DB | **HIGH**: forms lack token; plaintext not recoverable after lookup; form field unused |
| Step-up | login/step-up finish → `RecordStepUp` | in-memory `StepUpAt` only | **BLOCKER/HIGH**: not persisted → next request `StepUpFresh()` false (`store.go` LookupByID / sessions schema) |
| OIDC optional | client in `authn/oidc_client.go` | — | **DEFERRED**: no HTTP `/auth/oidc/*` → session bridge |

### Vendor intake → tier

| Step | HTTP | Store | UI | Status |
|------|------|-------|-----|--------|
| Create/list vendors | `POST/GET /api/v1/vendors` | `CreateVendor`/`ListVendors` | `/vendors` | OK |
| Engagements | `POST /vendors/{id}/engagements` | `CreateEngagement` | API only | OK |
| Intake create | `POST /api/v1/intakes` | `CreateIntake` FK → engagements | `/intakes` list | **HIGH**: missing `engagement_id` → opaque **500** FK (smoke); should be **400** |
| Submit + tier | `POST /intakes/{id}:submit` | `UpdateIntake` + `intake.ComputeTier` | — | OK |
| CSV import | `POST /vendors:import` | `import_csv` | — | OK |

### Assessment / questionnaire / evidence

| Step | Status |
|------|--------|
| Assessments create/transition | OK |
| Templates / instances / answer-library | OK (+ `/answer-library` UI) |
| Offline zip Pack/Unpack | OK (domain) |
| Chunked upload → complete → quarantine + blob | OK (smoke tiny upload) |
| Page viewer text/HTML | OK APIs |
| Sandbox extract → pages auto-fill | **MED/DEFERRED**: extract exists; no HTTP `:extract` glue for live path |
| Evidence blob download | **DEFERRED**: list/pages/soc-review only in OpenAPI |

### Findings → risk → exception → CR

| Step | Status |
|------|--------|
| Findings / risk-register / monitoring | OK APIs |
| Exceptions list/approve + UI | OK API; **HIGH** UI POST needs CSRF when cookie session |
| Change requests + step-up | API OK with `X-OpenTPRM-StepUp`; **BLOCKER** real step-up persistence |
| Exports / marked ZIP | OK |

### Agent MCP

| Step | Status |
|------|--------|
| `/mcp`, OAuth AS, gateway budgets | OK partial |
| Suggestions / accept citations | OK |
| CR human decide UI | linked; blocked by step-up + CSRF |
| T4 / lethal trifecta | OK blocked (`gateway` TierT4) |
| Agent grants list/revoke | OK |

### Portal / Unraid

| Step | Status |
|------|--------|
| Portal off by default; Listener B isolation | OK |
| Unraid mounts `/data` `/backup` `/run/secrets` | OK in pack |
| Portal magic-link / MFA stubs | DEFERRED until enabled |

### OpenAPI ↔ mux

| Check | Status |
|-------|--------|
| OpenAPI paths registered | OK (`TestOpenAPI_RoutesHaveMuxRegistrationSmoke`) |
| Thin/stub admin keys-backups HTML | MED (stubs intentional) |
| OIDC paths in OpenAPI | absent (matches deferred bridge) |

### Nav dead links

| Link | Status |
|------|--------|
| Home, vendors, intakes, exceptions, answer-library, CRs, agent-grants, openapi.json | OK |
| Admin keys/backups | **MED**: routes exist; not in nav |

---

## 2. Auth connections (detail)

```text
init → bootstrap.token + DB hash
  → POST /auth/bootstrap → users (sec + sys admin)
  → WebAuthn enroll begin/finish
  → login begin/finish → session cookie + csrf_token (once)
  → middleware: Origin + CSRF on mutating methods
  → step-up begin/finish → RecordStepUp (AAL bump)
  → optional OIDC (unit only)
```

**Sealed:** no master key → only `/health/*`; APIs 503. **Ready:** key + DB.

Findings: Origin:port, CSP/bootstrap JS, StepUpAt persistence, CSRF form path.

---

## 3. File / evidence management

```text
POST /uploads (JSON session | raw body)
  → PUT /uploads/{id} chunks
  → POST /uploads/{id}:complete
  → ValidateUpload → blob.Put → evidence quarantined
  → PUT pages / GET text|html viewer
```

Offline zip + export bundles + backup verify-only: OK. Full restore write: DEFERRED. Upload without engagement can quarantine without evidence row (intentional legacy path).

---

## 4. Agent path

MCP/OAuth/gateway → suggest_* → human accept / CR approve. T4 blocked. Lethal-trifecta posture: suggestions-only + dual authz — OK for first test.

---

## 5. Portal vs internal / Unraid

Listener A `:8443` vs B `:9443`; portal `enabled: false`. Config paths match compose binds. No code bug found in mount mapping.

---

## 6. Data integrity

| Item | Status |
|------|--------|
| Intake → engagement FK | Enforced; poor error mapping |
| Migrations forward-only | OK |
| SQLite XTS hexkey every conn + MaxOpenConns(1) | OK |
| Idempotency-Key | OK (AT-01) |
| ETags / CR stale | OK (AT-06) |
| Step-up column | **missing** |

---

## 7. Cross-cutting

| Item | Status |
|------|--------|
| Problem+JSON errors | OK |
| Authz 404 vs 403 restricted | OK (`authorize`) |
| Classification on evidence/exports | partial OK |
| Dev headers refused in production | OK |

---

## Prioritized findings (pre-fix)

### Blockers

1. **Origin ignores non-default port** — `internal/authn/session.go` `CheckOriginRejectsCrossSite`; middleware strips port then compares full Origin URL → bootstrap/UI fetch **403** on `:8443` / `:18443`. Smoke: `Origin: https://127.0.0.1:18443` → 403.
2. **Bootstrap inline script vs CSP** — `web/templates/bootstrap.tmpl` inline `<script>`; `setSecurityHeaders` `script-src 'self'`; no `web/static/*.js`.
3. **Step-up not durable** — `RecordStepUp` sets in-memory `StepUpAt`; sessions table has no `step_up_at`; `LookupByID` never restores it → CR/export step-up gates fail after cookie round-trip.

### High

4. **CSRF on HTML forms** — middleware only `X-CSRF-Token`; `CSRFFormField` unused; templates have no hidden token; plaintext CSRF only at login response.
5. **Intake without engagement** — `handlers_domain.go` create path returns 500 on FK; validate `engagement_id` → 400.

### Medium / deferred

6. Nav lacks `/admin/keys` `/admin/backups`.
7. No HTTP evidence extract/download wiring.
8. OIDC HTTP session bridge; full CTAP UI; portal ZAP; vegeta/k6; full restore write; pdfium (ADR-0004).

---

## Investigation notes

- `CGO_ENABLED=0 go test ./...`, `go vet ./...`, `go build` — green before fixes (cached).
- Smoke (`init` + `serve` + APIs): ready OK; bootstrap+Origin **403**; intake sans engagement **500**; vendor/engagement/intake+upload **OK**.

---

## Fix plan (Phase 3)

1. Fix Origin host/port comparison (parse Origin URL; compare hostname; allow matching request host:port).
2. Move bootstrap JS to `web/static/bootstrap.js`; template references `/static/bootstrap.js`.
3. Migration `010_session_step_up.sql`; persist/load `step_up_at` in SessionStore.
4. CSRF: accept form field; `IssueCSRF` rotate for UI renders; hidden inputs on mutating forms.
5. Validate intake `engagement_id` (and engagement existence) before insert → 400.
6. Tests for Origin:port, bootstrap static JS, step-up round-trip, intake 400.
7. Update this plan (resolved vs deferred) + handbook if flows change.

---

## Resolved vs deferred

| ID | Finding | Outcome |
|----|---------|---------|
| B1 | Origin:port | **resolved** — `CheckOriginRejectsCrossSite` parses Origin URL; middleware passes full `r.Host`; tests + smoke 201 with `Origin: https://127.0.0.1:18444` |
| B2 | Bootstrap CSP/JS | **resolved** — `web/static/bootstrap.js`; template loads `/static/bootstrap.js` |
| B3 | StepUpAt persistence | **resolved** — migration `010_session_step_up.sql`; `RecordStepUp` / `LookupByID`; `TestSEC_AN_003_StepUpPersistsAcrossLookup` |
| H4 | CSRF forms | **resolved** — middleware accepts `csrf_token` form field; `IssueCSRF` on exception/CR/agent-grant UI; hidden inputs in templates |
| H5 | Intake engagement_id | **resolved** — store validates existence → handler **400**; AT-01 covers missing eng |
| D1 | OIDC HTTP → session bridge | **deferred** |
| D2 | Full CTAP/WebAuthn attestation UI | **deferred** |
| D3 | Evidence sandbox extract HTTP glue / blob download | **deferred** |
| D4 | Admin keys/backups in nav | **deferred** (routes exist) |
| D5 | Full restore write path | **deferred** (verify-only OK) |
| D6 | Portal ZAP / broader anti-automation | **deferred** |
| D7 | vegeta/k6 NFR | **deferred** |
| D8 | pdfium Wasm / pdfcpu pack (ADR-0004) | **deferred** |

Post-fix: `CGO_ENABLED=0 go test ./...`, `go vet`, `go build` green; smoke bootstrap+Origin **201**, intake sans eng **400**.
