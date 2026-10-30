#!/usr/bin/env bash
# Emit a local SLSA-shaped provenance stub (unsigned). See docs/build/SLSA-PROVENANCE.md.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "${ROOT}/dist"
COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
FINISHED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
GOMOD_DIGEST=""
GOSUM_DIGEST=""
if [[ -f "${ROOT}/go.mod" ]]; then
  GOMOD_DIGEST="$(sha256sum "${ROOT}/go.mod" | awk '{print $1}')"
fi
if [[ -f "${ROOT}/go.sum" ]]; then
  GOSUM_DIGEST="$(sha256sum "${ROOT}/go.sum" | awk '{print $1}')"
fi
OUT="${ROOT}/dist/opentprm.provenance.stub.json"
cat >"${OUT}" <<EOF
{
  "_comment": "UNSIGNED SLSA Build provenance stub — not an attestation",
  "builder": {"id": "https://opentprm.local/builders/makefile@v1"},
  "buildType": "https://opentprm.local/slsa/buildTypes/go-binary/v1",
  "invocation": {
    "configSource": {"uri": "git+https://github.com/TheScottle/OpenTPRM", "digest": {"sha1": "${COMMIT}"}},
    "parameters": {"target": "provenance-stub"}
  },
  "metadata": {"buildFinishedOn": "${FINISHED}", "completeness": {"parameters": true, "environment": false}},
  "materials": [
    {"uri": "file://go.mod", "digest": {"sha256": "${GOMOD_DIGEST}"}},
    {"uri": "file://go.sum", "digest": {"sha256": "${GOSUM_DIGEST}"}}
  ]
}
EOF
echo "wrote ${OUT}"
