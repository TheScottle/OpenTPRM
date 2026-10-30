# OpenTPRM on Unraid

Self-hosted OpenTPRM using Unraid appdata bind mounts and host-file secrets (Docker secrets pattern). **Never** put master keys, TLS private keys, or OIDC client secrets in Unraid *Variables* — that violates OPS-002 and the process will refuse to start if those env names are set.

## Layout

| Host path | Container path | Notes |
|-----------|----------------|-------|
| `/mnt/user/appdata/opentprm/data` | `/data` | rw, mode `0700`, owner `65532:65532` |
| `/mnt/user/appdata/opentprm/backup` | `/backup` | rw, mode `0700`, owner `65532:65532` |
| `/mnt/user/appdata/opentprm/config/config.yaml` | `/etc/opentprm/config.yaml` | ro |
| `/mnt/user/appdata/opentprm/secrets/master.key` | `/run/secrets/opentprm_master_key` | ro, mode `0400` |
| `/mnt/user/appdata/opentprm/secrets/tls.crt` | `/run/secrets/opentprm_tls_cert` | ro |
| `/mnt/user/appdata/opentprm/secrets/tls.key` | `/run/secrets/opentprm_tls_key` | ro, mode `0400` |

UID/GID **65532** is the distroless `nonroot` user baked into the image. Unraid **PUID/PGID** Variables are **not** used — chown the appdata tree to `65532:65532` instead.

## Image strategy (prefer local build)

There is no required public registry. On the Unraid host:

```bash
# Clone or sync the repo somewhere durable, e.g. /mnt/user/appdata/opentprm/src
cd /mnt/user/appdata/opentprm/src
docker build -t opentprm:local -f deploy/Dockerfile .
```

If you later publish to GHCR, point the CA template / compose `image:` at that tag; until then keep `opentprm:local`.

Optional multi-arch (Unraid hosts are usually amd64):

```bash
docker buildx build --platform linux/amd64 -t opentprm:local -f deploy/Dockerfile --load .
```

## One-shot bootstrap (`install.sh`)

From a clone of this repo on the Unraid host (as root):

```bash
bash deploy/unraid/install.sh
```

That creates the appdata dirs, copies `config.unraid.yaml` → `config/config.yaml` if missing, builds the image when needed, and runs a one-shot container:

```text
opentprm init --data /data --master-key /secrets/master.key --tls-dir /secrets
```

Then tightens secret file modes to `0400`.

### Manual init (Docker UI Console / CLI)

If you prefer not to use `install.sh`:

```bash
mkdir -p /mnt/user/appdata/opentprm/{data,backup,config,secrets}
cp deploy/unraid/config.unraid.yaml /mnt/user/appdata/opentprm/config/config.yaml
chown -R 65532:65532 /mnt/user/appdata/opentprm
chmod 0700 /mnt/user/appdata/opentprm/{data,backup,secrets}

docker run --rm \
  --user 65532:65532 \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  -v /mnt/user/appdata/opentprm/data:/data \
  -v /mnt/user/appdata/opentprm/secrets:/secrets \
  opentprm:local \
  init --data /data --master-key /secrets/master.key --tls-dir /secrets

chmod 0400 /mnt/user/appdata/opentprm/secrets/master.key \
           /mnt/user/appdata/opentprm/secrets/tls.key
```

`init` prints a one-time bootstrap token (mode `0400`, 1 hour) used to enroll the first Security Administrator and System Administrator with passkeys. Capture it from the container logs/stdout (or `data/bootstrap.token` on the host). After the app is running and `/health/ready` returns `ready`, open `https://[IP]:8443/bootstrap` (or `POST /api/v1/auth/bootstrap`). Full first-login walkthrough: [`docs/handbook/first-login.md`](../../docs/handbook/first-login.md).

## Option A — Community Applications / Docker UI template

1. Build `opentprm:local` (see above) and run bootstrap once.
2. Apps → Docker → Add Container, or import `deploy/unraid/opentprm.xml` as a custom template (`/boot/config/plugins/dockerMan/templates-user/`).
3. Confirm settings:
   - **Network Type:** Bridge
   - **Port:** host `8443` → container `8443` (TCP)
   - **Privileged:** OFF
   - Path mappings as in the table above (secrets as **Path**, not Variable)
   - **Extra Parameters** (already in the XML):  
     `--read-only --cap-drop=ALL --security-opt no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,nodev,size=512m --init --user 65532:65532 --pids-limit 256`
4. Do **not** add Variables named `OPENTPRM_MASTER_KEY`, `OPENTPRM_TLS_KEY`, or `OPENTPRM_OIDC_SECRET`.
5. Optional non-secret Variable: `OPENTPRM_MODE=production`.
6. Apply / Start. WebUI: `https://[IP]:8443` → check `/health/ready`, then `/bootstrap` ([first-login.md](../../docs/handbook/first-login.md)).

## Option B — Docker Compose Manager

1. Build image + bootstrap as above.
2. Point Compose Manager at `deploy/unraid/docker-compose.unraid.yml` (or copy it under appdata and adjust paths).
3. `docker compose -f deploy/unraid/docker-compose.unraid.yml up -d`

Compose uses Unraid **bridge** networking, read-only rootfs, `cap_drop: ALL`, `no-new-privileges`, and tmpfs `/tmp`.

## Config notes

- Example production file: `config.unraid.yaml` (portal **off** by default, listen `0.0.0.0:8443`).
- After first start, set `server.public_base_url` to your LAN URL (e.g. `https://192.168.1.50:8443`).
- Keep the vendor portal disabled until a reverse proxy and `trusted_proxies` are configured.
- Operator checklist: [`docs/handbook/operator.md`](../../docs/handbook/operator.md).
- First login / sealed vs ready: [`docs/handbook/first-login.md`](../../docs/handbook/first-login.md).
- Analyst workflows: [`docs/handbook/workflows.md`](../../docs/handbook/workflows.md).

## Hardening checklist

- [ ] Privileged OFF
- [ ] `--cap-drop=ALL` and `no-new-privileges`
- [ ] Read-only root filesystem + tmpfs `/tmp`
- [ ] Secrets only as host files mode `0400` under appdata
- [ ] No secret Unraid Variables (OPS-002)
- [ ] Appdata owned by `65532:65532`
- [ ] Portal remains disabled unless intentionally exposed behind a trusted proxy
