# SLSA / build provenance (stub)

OpenTPRM aims for **SLSA Build L3**-aligned provenance without paid SaaS. This document is the stub until a full in-toto attestation pipeline is wired in CI.

## Current posture

| Control | Status |
| --- | --- |
| Reproducible Go build flags (`-trimpath`, stamped version) | Makefile `build` |
| CycloneDX SBOM | `make sbom` + CI job |
| gosec + govulncheck | CI |
| Multi-arch container images | Documented `docker buildx` in Operator Handbook (not yet gated in CI) |
| Cosign keyless / key-based verify | Placeholder script `scripts/cosign-verify.sh` |
| in-toto / SLSA provenance attestation | Stub target `make provenance-stub` writes a local predicate JSON |

## Provenance stub schema

`make provenance-stub` emits `dist/opentprm.provenance.stub.json` with:

- `builder.id` — local / GitHub Actions runner identity placeholder
- `buildType` — `https://opentprm.local/slsa/buildTypes/go-binary/v1`
- `invocation` — git commit SHA + Makefile target
- `materials` — go.mod / go.sum digests when available
- `metadata.buildFinishedOn` — UTC timestamp

This is **not** a signed SLSA attestation. Treat it as a CI artifact shape to replace with `slsa-github-generator` or a self-hosted cosign+in-toto flow.

## Verification (no paid services)

```bash
make sbom
make provenance-stub
./scripts/cosign-verify.sh dist/opentprm.cdx.json   # placeholder; exits 0 with guidance
```

When cosign and a public key or keyless identity are configured locally:

```bash
COSIGN_EXPERIMENTAL=0 cosign verify --key cosign.pub ghcr.io/example/opentprm:tag
```

Do not require Sigstore Rekor or GitHub-hosted OIDC for developer laptops; key-based verify is the default offline path.
