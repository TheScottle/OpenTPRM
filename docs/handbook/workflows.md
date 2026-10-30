# Core analyst workflows

Operator map of the third-party lifecycle as implemented in OpenTPRM today (REST + analyst HTML + MCP). Agents **suggest**; humans **decide**.

**Auth:** All analyst UI and `/api/v1/*` (including OpenAPI) require a session from `/login` (email + password). Use `/admin/users` to create workforce accounts. CSRF is required on HTML form posts.

## Lifecycle overview

```text
Vendor intake → tier → assessment → questionnaire / evidence
    → findings / risk → exception / approval
    → (optional) agent MCP suggest vs human decide
    → offboarding
```

Portal (vendor) path is separate and **off by default**. Backup/restore drill: see end of this page and [operator.md](operator.md).

## 1. Vendor intake → tier

| Step | UI / API | Notes |
|------|----------|-------|
| Create / list / edit vendors | `/vendors` (forms) · `POST/GET /api/v1/vendors` | HTML create, status/name edit, add engagement |
| CSV import (quarantine) | `POST /api/v1/vendors:import` | No formula eval |
| Intake record | `/intakes` (forms) · `POST /api/v1/intakes` | Create draft from engagement; missing/unknown engagement → **400** |
| Submit + tier | `/intakes` Submit · `POST /api/v1/intakes/{id}:submit` | Inherent-risk tiering drives diligence scope |

Duplicate detect / merge and next-action due live on the inventory store (`:merge`, history). Prefer the intake queue for first-pass triage.

## 2. Assessment

| Step | API | Notes |
|------|-----|-------|
| Create assessment | `POST /api/v1/assessments` | Bound to vendor / engagement |
| Transition state | `POST /api/v1/assessments/{id}:transition` | Workflow states under ASM-* |

Assessments collect questionnaire instances and evidence under one diligence effort.

## 3. Questionnaire + evidence

| Step | Surface | Notes |
|------|---------|-------|
| Templates / publish | `/api/v1/questionnaire-templates` | Core/Lite/Intake seeds (NIST-mapped only) |
| Instances / responses / review | `/api/v1/questionnaire-instances` | Scoring + delta (AT-15) |
| Answer library | `/answer-library` (upsert form) · `/api/v1/answer-library` | Reuse prior answers |
| Offline pack | domain offline zip | Signed pack/unpack for offline completion |
| Evidence upload | `/api/v1/uploads` → `:complete` | Chunked → blob + quarantine |
| Viewer | evidence page text/HTML APIs | Sanitized viewer; sandbox extract |

Never paste licensed questionnaire text into seeds or prompts (STD-* policy).

## 4. Findings → risk

| Step | API | Notes |
|------|-----|-------|
| Findings | `POST/GET /api/v1/findings` · `:transition` | Remediation plans attached |
| Risk register | `/api/v1/risk-register` | Residual risk decisions |
| Monitoring | `/api/v1/monitoring/...` | Signal dispositions |

Findings can originate from human review or from **accepted** AI suggestions with verified citations.

## 5. Exception / approval

| Step | UI / API | Notes |
|------|----------|-------|
| Exception list / create | `/exceptions` (create form) · `/api/v1/exceptions` | SOD: requester ≠ approver |
| Approve | UI + `POST /api/v1/exceptions/{id}:approve` | Signed decision path |
| Change requests | `/change-requests` | Dual-control; WebAuthn **step-up** on decide |
| Exports / committee packs | `/api/v1/exports` | Markings; sensitive bulk export needs step-up |

Security Administrators do **not** approve risk exceptions they should not own; role SoD is enforced in policy + tests.

## 6. Agent MCP: suggest vs human decide

| Actor | Allowed | Forbidden |
|-------|---------|-----------|
| MCP / agent tools | Read + **suggest_*** (`suggest_finding`, `suggest_soc_review_fields`, `suggest_diligence_report`, …) with `dry_run` | Approve, delete, admin, unrestricted export |
| Human (workforce) | Accept suggestion (citations verified), approve CR/exception, final risk disposition | Blind-trust of model output |

Surfaces:

- MCP: `/mcp` (initialize / `tools/list` / `tools/call`) under OAuth + budgets when enabled
- REST helper: `/api/v1/agent/tools`, `/api/v1/agent/call`
- Grants: `/me/agent-grants` (list/revoke)
- Kill switches: Security Admin can suspend a client or set global AI off (see operator handbook)

AI assist stays **suggestions-only** until a named human accepts.

## 7. Offboarding

| Step | API | Notes |
|------|-----|-------|
| Start checklist | `POST /api/v1/offboarding` | Engagement / vendor exit |
| Items | `/api/v1/offboarding/{id}/items` | Access revoke, data return, shred awareness |
| Legal hold | `/api/v1/legal-holds` | Blocks shred while hold active |

Crypto-shred / retention helpers respect holds; run audit verify after destructive ops drills.

## Portal vendor path (optional)

Listener B / portal is **disabled** until intentionally enabled behind a reverse proxy with `trusted_proxies`.

Typical vendor flow (when on):

1. Magic-link issue/consume for vendor contact email
2. Passkey or TOTP enroll (stubs → hardening)
3. Vendor-scoped questionnaire list / respond
4. Anti-automation: rate limit + honeypot on login

Do not expose portal on Unraid Bridge without a trusted edge proxy.

## Backup / restore drill

Pointer only — details in [operator.md](operator.md):

```bash
opentprm backup --config /etc/opentprm/config.yaml
opentprm restore --verify-only --config /etc/opentprm/config.yaml   # quarterly drill
opentprm audit verify --config /etc/opentprm/config.yaml
```

Online snapshot + age encryption + signed manifest. Prefer verify-only drills before any write restore. Unraid backup dir: `/mnt/user/appdata/opentprm/backup` → `/backup`.

## First-login cross-link

Before running analyst workflows on a new instance, complete [first-login.md](first-login.md) (bootstrap token → admin passwords → `/login` → optional passkey → create users).
