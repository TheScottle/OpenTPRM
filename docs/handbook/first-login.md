# First login (live test)

This is the Owner path from a fresh `opentprm init` to an unsealed, ready Listener A on port **8443**.

## What URL to open

| Environment | URL |
|-------------|-----|
| Unraid (Bridge) | `https://<UNRAID-LAN-IP>:8443` |
| Local smoke | `https://127.0.0.1:8443` (or whatever `server.internal.listen` / `public_base_url` say) |

TLS uses the self-signed cert from `init` unless you replaced it. Expect a browser warning until you trust that cert (or terminate TLS at a reverse proxy later).

Useful paths after the container is up:

| Path | Purpose |
|------|---------|
| `/health/live` | Process up → `{"status":"ok"}` |
| `/health/ready` | Unsealed + DB → `{"status":"ready"}`; sealed → **503** `{"status":"sealed"}` |
| `/bootstrap` | One-time first-admin enrollment form |
| `/` | Analyst home (after you have a session / roles) |

## Sealed vs ready

- **Sealed:** master key file missing or unreadable. Only health endpoints answer; data APIs return **503**. Fix: place `master.key` at the configured `keys.master_key_file` (Unraid: `/run/secrets/opentprm_master_key`) and restart.
- **Ready:** key loaded, encrypted SQLite open, migrations applied. `/health/ready` returns **200** `{"status":"ready"}`.

## Bootstrap token (OPS-003)

`opentprm init` creates:

1. Master key (`0400`)
2. Self-signed TLS material
3. Encrypted DB + hashed bootstrap token in DB
4. Plaintext token file `data/bootstrap.token` (**mode 0400**, **TTL 1 hour**)

On Unraid, capture the token from `install.sh` / one-shot `init` container stdout **or** read the host file once:

```bash
sudo cat /mnt/user/appdata/opentprm/data/bootstrap.token
```

Treat it like a break-glass secret. It is **single-use**: after successful consume it cannot be reused. If the hour expires before you enroll, re-init is not automatic — prefer completing enroll within the window on a fresh install.

## Enroll first Security Admin + System Admin

1. Confirm `/health/ready` is `ready`.
2. Open `https://<host>:8443/bootstrap`.
3. Paste the bootstrap token.
4. Enter **two different** emails:
   - Security Administrator (keys, agents, policy, audit)
   - System Administrator (platform ops)
5. Submit. API: `POST /api/v1/auth/bootstrap` with JSON  
   `{ "token", "security_admin_email", "system_admin_email" }` → **201** and two `user_id`s.
6. **Passkey enroll** for each returned id via  
   `POST /api/v1/auth/webauthn/enroll/begin` then `/enroll/finish`  
   (COSE / public-key metadata path). Full browser CTAP attestation UI is still maturing; the API path is what live tests should exercise first.
7. Subsequent login: `/auth/webauthn/login/begin` + `/finish` (session cookie).

Dev-only shortcut (never production): `mode: development` may honor `X-OpenTPRM-User` / `X-OpenTPRM-Roles` headers for API smoke. Production refuses insecure identity shortcuts.

## OIDC (optional)

Workforce SSO is **authorization code + PKCE** only. Leave `identity.oidc.issuer` empty for the first live test if you are using local passkeys only.

When ready (Keycloak sketch):

1. Confidential/public client; Standard flow ON; Implicit OFF.
2. Redirect: `https://<listener-a>/api/v1/auth/oidc/callback`
3. PKCE S256; store client secret in a **file** secret (`identity.oidc.client_secret_file`), never env.
4. Require MFA in the IdP; map `amr`/`acr` to `identity.oidc.require_amr`.
5. Map groups with `identity.oidc.group_role_map`.

See [operator.md](operator.md) for the full Keycloak checklist. HTTP session bridge for OIDC is still closing; passkey bootstrap remains the first-login path.

## Unraid path notes

Full pack: [`deploy/unraid/README-UNRAID.md`](../../deploy/unraid/README-UNRAID.md).

1. `bash deploy/unraid/install.sh` (or manual `init` one-shot) under `/mnt/user/appdata/opentprm/`.
2. Secrets as **host files** mode `0400` — never Unraid Variables for keys (OPS-002).
3. Deploy CA template / Compose; Bridge; port **8443**; Privileged OFF; UID **65532**.
4. Open `https://[IP]:8443` → check ready → `/bootstrap`.
5. Keep vendor portal **off** until a reverse proxy + `trusted_proxies` are configured.

## Production secrets checklist

- [ ] `master.key` and TLS private key mode `0400`, mounted at `/run/secrets/...`
- [ ] No `OPENTPRM_MASTER_KEY` / `OPENTPRM_TLS_KEY` / `OPENTPRM_OIDC_SECRET` environment variables
- [ ] `mode: production` with TLS paths set; `server.public_base_url` = real LAN/public URL
- [ ] Listener A not exposed beyond the intended admin network
- [ ] Portal disabled until proxy + trusted proxies are ready
- [ ] Bootstrap token wiped after enroll (file deleted; DB row already `used=1`)

## Smoke (local)

```bash
CGO_ENABLED=0 go build -o opentprm ./cmd/opentprm
tmpdir=$(mktemp -d)
./opentprm init --data "$tmpdir/data" --master-key "$tmpdir/secrets/master.key" --tls-dir "$tmpdir/secrets"
# Point a small config at those paths, listen 127.0.0.1:8443, then:
./opentprm serve --config /path/to/config.yaml
curl -sk https://127.0.0.1:8443/health/ready   # expect ready
curl -sk https://127.0.0.1:8443/bootstrap      # expect HTML form
```

Self-signed TLS is expected; use `-k` / trust the printed fingerprint from `init`.
