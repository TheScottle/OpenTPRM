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
