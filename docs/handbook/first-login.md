# First login (live test)

Owner path from a fresh `opentprm init` to an authenticated Listener A on port **8443**.

## What URL to open

| Environment | URL |
|-------------|-----|
| Unraid (Bridge) | `https://<UNRAID-LAN-IP>:8443` |
| Local smoke | `https://127.0.0.1:8443` |

TLS uses the self-signed cert from `init` unless you replaced it.

| Path | Purpose |
|------|---------|
| `/health/live` | Process up → `{"status":"ok"}` (public) |
| `/health/ready` | Unsealed + DB → `ready`; sealed → **503** (public) |
| `/bootstrap` | One-time first-admin enrollment (**only while** bootstrap token is unused) |
| `/login` | Email + password sign-in (public) |
| `/` and other UI | **Require session** — anonymous visitors redirect to `/login` |

## Sealed vs ready

- **Sealed:** master key missing. Only health answers; data APIs **503**.
- **Ready:** key loaded, encrypted SQLite open. Proceed to bootstrap or login.

## Bootstrap (OPS-003)

`opentprm init` creates master key, TLS material, encrypted DB, and a one-time bootstrap token (`data/bootstrap.token`, mode **0400**, TTL **1 hour**).

1. Confirm `/health/ready` is `ready`.
2. Open `/bootstrap`.
3. Paste the bootstrap token.
4. Enter **two different** emails and **two passwords** (each ≥ **15** characters, Argon2id):
   - Security Administrator
   - System Administrator
5. Submit. API: `POST /api/v1/auth/bootstrap` with  
   `{ token, security_admin_email, system_admin_email, security_admin_password, system_admin_password }` → **201**.
6. Open `/login` and sign in with either admin email + password.
7. Optional: enroll a passkey (session required) via  
   `POST /api/v1/auth/webauthn/enroll/begin` then `/finish` for step-up on approvals/exports.

After bootstrap succeeds, `/bootstrap` redirects to `/login`.

## Day-to-day authentication

- **Primary:** email + password → `__Host-otp_s` session cookie + CSRF token.
- **Step-up:** WebAuthn passkey within 5 minutes for change-request decisions, sensitive exports, and similar gates. Password login alone does **not** satisfy step-up.
- **Logout:** `/logout` or `POST /api/v1/auth/logout`.
- Anonymous UI/API access is refused (HTML → login redirect; JSON → **401**). OpenAPI is authenticated-only.

Dev-only shortcut (never production): `mode: development` may honor `X-OpenTPRM-User` / `X-OpenTPRM-Roles` for API smoke.

## Create more users

1. Sign in as Security or System Administrator.
2. Open **Users** (`/admin/users`) or call `POST /api/v1/users`.
3. Assign roles (`risk_analyst`, `approver`, `auditor`, …). Granting `security_administrator` or `system_administrator` requires a **second** distinct admin’s email + password (SOD-3).
4. New users sign in at `/login`. If no password was supplied at create time, a one-time temporary password is returned once.

## OIDC (optional)

Workforce SSO (authorization code + PKCE) remains available for later IdP wiring. Leave `identity.oidc.issuer` empty for the first live test when using local passwords.

## Unraid notes

See [`deploy/unraid/README-UNRAID.md`](../../deploy/unraid/README-UNRAID.md). Capture the bootstrap token once, complete `/bootstrap` within the hour, then use `/login`.
