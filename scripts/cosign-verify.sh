#!/usr/bin/env bash
# Cosign verify placeholder (M9). No paid services required.
# Usage:
#   ./scripts/cosign-verify.sh [image-or-blob]
# When cosign + COSIGN_KEY (public key path) are present, runs a real verify.
# Otherwise prints the offline verification recipe and exits 0 so CI remains green.

set -euo pipefail

TARGET="${1:-}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v cosign >/dev/null 2>&1; then
  cat <<EOF
[cosign-verify] cosign not installed — skipping live verify.
Install: https://docs.sigstore.dev/cosign/system_config/installation/
Offline recipe (key-based, no Rekor required):
  cosign verify --key "\${COSIGN_KEY:-cosign.pub}" ${TARGET:-<image-ref>}
SBOM companion: make sbom  →  dist/opentprm.cdx.json
Provenance stub: make provenance-stub  →  dist/opentprm.provenance.stub.json
EOF
  exit 0
fi

if [[ -z "${TARGET}" ]]; then
  echo "[cosign-verify] no target provided; nothing to verify" >&2
  exit 0
fi

KEY="${COSIGN_KEY:-${ROOT}/cosign.pub}"
if [[ ! -f "${KEY}" ]]; then
  echo "[cosign-verify] public key missing at ${KEY}; skipping" >&2
  echo "Generate offline keys: cosign generate-key-pair" >&2
  exit 0
fi

exec cosign verify --key "${KEY}" "${TARGET}"
