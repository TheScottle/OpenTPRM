# OpenTPRM

Self-hosted, security-first **Third-Party Risk Management** platform. One hardened container: TPRM application + REST + MCP for local LLM agents under human authority.

## Status

Greenfield implementation following the OpenTPRM system description & build specification (`docs/spec/`). Milestones M0–M9 are scaffolded with exit-gate tests for the security foundation, inventory/intake, questionnaires, evidence pipeline, risk lifecycle, REST/MCP surfaces, AI governance, vendor portal (off by default), and release hardening.

## Build

Requires Go 1.24+ (CI uses 1.27).

```bash
go test ./...
go build -o opentprm ./cmd/opentprm
./opentprm init --data ./data --master-key ./secrets/master.key --tls-dir ./secrets
```

## License

Unlicense (public domain). Seed content is Owner-authored and mapped only to free NIST sources — no paid questionnaire standards are bundled.
