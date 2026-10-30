#!/usr/bin/env bash
# OpenTPRM Unraid appdata bootstrap helper.
# Run on the Unraid host (as root) once before the first container start.
#
# Usage:
#   bash deploy/unraid/install.sh
#   APPDATA=/mnt/user/appdata/opentprm bash deploy/unraid/install.sh
#   SKIP_INIT=1 bash deploy/unraid/install.sh   # dirs + config only
#
set -euo pipefail

APPDATA="${APPDATA:-/mnt/user/appdata/opentprm}"
IMAGE="${IMAGE:-opentprm:local}"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
UID_APP=65532
GID_APP=65532

echo "==> Creating appdata layout under ${APPDATA}"
mkdir -p "${APPDATA}/data" "${APPDATA}/backup" "${APPDATA}/config" "${APPDATA}/secrets"

if [[ ! -f "${APPDATA}/config/config.yaml" ]]; then
  cp "${REPO_ROOT}/deploy/unraid/config.unraid.yaml" "${APPDATA}/config/config.yaml"
  echo "    wrote config/config.yaml from config.unraid.yaml"
else
  echo "    config/config.yaml already present — leaving unchanged"
fi

chown -R "${UID_APP}:${GID_APP}" "${APPDATA}/data" "${APPDATA}/backup" "${APPDATA}/config" "${APPDATA}/secrets"
chmod 0700 "${APPDATA}/data" "${APPDATA}/backup" "${APPDATA}/secrets"
chmod 0750 "${APPDATA}/config"

if [[ "${SKIP_INIT:-0}" == "1" ]]; then
  echo "==> SKIP_INIT=1 — not running opentprm init"
  echo "    Place master.key / tls.crt / tls.key in ${APPDATA}/secrets (mode 0400) yourself."
  exit 0
fi

if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
  echo "==> Image ${IMAGE} not found — building from ${REPO_ROOT}"
  docker build -t "${IMAGE}" -f "${REPO_ROOT}/deploy/Dockerfile" "${REPO_ROOT}"
fi

NEED_INIT=0
for f in master.key tls.crt tls.key; do
  if [[ ! -f "${APPDATA}/secrets/${f}" ]]; then
    NEED_INIT=1
  fi
done

if [[ "${NEED_INIT}" -eq 0 ]]; then
  echo "==> Secrets already present in ${APPDATA}/secrets — skipping init"
  chmod 0400 "${APPDATA}/secrets/master.key" "${APPDATA}/secrets/tls.key" || true
  chmod 0440 "${APPDATA}/secrets/tls.crt" || true
  exit 0
fi

echo "==> Running one-shot opentprm init (secrets + data bootstrap)"
# Write into a temp dir inside the mounted secrets/data volumes, then tighten perms.
docker run --rm \
  --user "${UID_APP}:${GID_APP}" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  -v "${APPDATA}/data:/data" \
  -v "${APPDATA}/secrets:/secrets" \
  "${IMAGE}" \
  init --data /data --master-key /secrets/master.key --tls-dir /secrets

chmod 0400 "${APPDATA}/secrets/master.key" "${APPDATA}/secrets/tls.key"
chmod 0440 "${APPDATA}/secrets/tls.crt"
chown -R "${UID_APP}:${GID_APP}" "${APPDATA}/data" "${APPDATA}/secrets"

echo "==> Bootstrap complete"
echo "    Secrets: ${APPDATA}/secrets (mode 0400 for private material)"
echo "    Next: start the stack with docker-compose.unraid.yml or the CA template."
echo "    WebUI: https://<unraid-ip>:8443"
echo "    Reminder: never put keys in Unraid Variables (OPS-002)."
