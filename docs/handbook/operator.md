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
