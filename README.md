# OpenTPRM

Self-hosted, security-first **Third-Party Risk Management** platform. One hardened container: TPRM application + REST + MCP for local LLM agents under human authority.

## Status

Greenfield implementation following the OpenTPRM system description & build specification (`docs/spec/`). Milestones M0–M9 are scaffolded with exit-gate tests for the security foundation, inventory/intake, questionnaires, evidence pipeline, risk lifecycle, REST/MCP surfaces, AI governance, vendor portal (off by default), and release hardening.

## Build

Requires Go 1.24+ (CI uses 1.27).

```bash
CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 go build -o opentprm ./cmd/opentprm
./opentprm init --data ./data --master-key ./secrets/master.key --tls-dir ./secrets
```

## Operator docs

- [`docs/handbook/operator.md`](docs/handbook/operator.md) — checklist, OIDC, backup, Unraid summary
- [`docs/handbook/first-login.md`](docs/handbook/first-login.md) — bootstrap token, first admins + passkeys, sealed vs ready, `:8443`
- [`docs/handbook/workflows.md`](docs/handbook/workflows.md) — intake → assessment → evidence → risk → exception → MCP suggest vs decide → offboarding

## Deploy

- Docker Compose (generic): [`deploy/compose.yaml`](deploy/compose.yaml)
- **Unraid**: step-by-step guide, CA template, and appdata helper in [`deploy/unraid/README-UNRAID.md`](deploy/unraid/README-UNRAID.md) (first login: [`docs/handbook/first-login.md`](docs/handbook/first-login.md))

## License

Unlicense (public domain). Seed content is Owner-authored and mapped only to free NIST sources — no paid questionnaire standards are bundled.
