# OpenTPRM Operator Handbook

## Quick start (development)

```bash
opentprm init --data ./data --master-key ./secrets/master.key --tls-dir ./secrets
# Write a development config pointing at those paths, then:
opentprm serve --config ./deploy/config.example.yaml
```

## Production checklist

1. Place master key and TLS material under Docker/Podman secrets (`/run/secrets/...`).
2. Never put secrets in environment variables (OPS-002).
3. Bind Listener A to an internal interface only.
4. Keep vendor portal disabled until a reverse proxy and trusted_proxies are configured.
5. Mirror egress allow-list in host firewall.
6. Run `opentprm audit verify` after restore drills.
7. Confirm SEC-CTN-006 self-test passes in the container.

## Bootstrap

`opentprm init` creates a one-time bootstrap token (mode 0400, 1 hour) used to enroll the first Security Administrator and System Administrator with passkeys.

## Workforce SSO (OIDC / Keycloak)

OpenTPRM uses **authorization code + PKCE** only (SEC-AN-001). No implicit flow.

### Keycloak (self-hosted) sketch

1. Create realm (e.g. `firm`) and confidential or public client `opentprm`.
2. Valid redirect URI: `https://<listener-a>/api/v1/auth/oidc/callback` (exact match).
3. Capability config: Standard flow ON; Implicit flow OFF; Direct access grants OFF for workforce SSO.
4. Client authentication: confidential clients store the secret in `identity.oidc.client_secret_file` (Docker/Podman secret — never env).
5. Advanced → PKCE Code Challenge Method: **S256** (required).
6. Authentication flow: require MFA (OTP / WebAuthn). Map MFA into `acr` (e.g. `phr`) and/or `amr` (`otp`, `mfa`) and set `identity.oidc.require_amr` accordingly.
7. Issuer URL in config: `https://<keycloak>/realms/firm` (Keycloak paths `/protocol/openid-connect/auth|token|certs`).
8. Group → role mapping via `identity.oidc.group_role_map` (or SCIM later).

Unit coverage: `TestSEC_AN_001_OIDCAuthCodePKCEAgainstFakeIdP` drives a fake IdP httptest with Keycloak-shaped paths.

## Backup and restore

- `opentprm backup` — online snapshot + age encryption + signed manifest
- `opentprm restore --verify-only` — quarterly drill without touching live data

## Kill switches

Security Administrators can suspend an agent client or set global AI off; both take effect in under 5 seconds.

## Multi-arch container images

Prefer `docker buildx` (or Podman with qemu-user-static) so amd64 and arm64 images share one manifest. From the repo root:

```bash
docker buildx create --use --name opentprm 2>/dev/null || true
docker buildx build --platform linux/amd64,linux/arm64 \
  -t opentprm:local -f deploy/Dockerfile --load .
```

Omit `--load` and use `--push` when publishing to a registry. See `docs/build/SLSA-PROVENANCE.md` for SBOM + unsigned provenance stubs (`make sbom`, `make provenance-stub`) and the cosign verify placeholder (`make cosign-verify` / `scripts/cosign-verify.sh`).

## Unraid

Unraid uses host path mounts under `/mnt/user/appdata/opentprm/` instead of named Docker volumes. Secrets are still files (mounted at `/run/secrets/...`); never Unraid Variables for keys (OPS-002).

1. On the Unraid host, build locally (preferred when no registry is configured):

   ```bash
   docker build -t opentprm:local -f deploy/Dockerfile .
   ```

2. Bootstrap once with `bash deploy/unraid/install.sh`, or a one-shot `opentprm init` container writing into appdata `data/` and `secrets/`. Tighten `master.key` and `tls.key` to mode `0400`.

3. Deploy via Community Applications / Docker UI using `deploy/unraid/opentprm.xml`, or Compose Manager with `deploy/unraid/docker-compose.unraid.yml`.

4. Network: Bridge. Port: `8443`. Privileged: OFF. Extra params include `--read-only`, `--cap-drop=ALL`, `--security-opt no-new-privileges`, and tmpfs `/tmp`. The process runs as UID/GID **65532** (not PUID/PGID).

5. WebUI: `https://[IP]:8443`. Portal stays off by default.

Full steps: [`deploy/unraid/README-UNRAID.md`](../../deploy/unraid/README-UNRAID.md).
