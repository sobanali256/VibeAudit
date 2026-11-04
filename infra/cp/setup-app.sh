#!/usr/bin/env bash
# VM 1: Node + pnpm, Postgres (local only), docker CLI (no daemon), Caddy (HTTPS via sslip.io),
# service users, worker SSH key for VM 2, and the web/worker systemd units. Safe to rerun.
# Run as root:  ssh vibe-cp 'bash -s' < infra/cp/setup-app.sh
#
# Three users, so one compromise doesn't hand over the others' powers:
#   vibedeploy  builds releases (runs pnpm install scripts); owns /opt/vibeaudit/app; no secrets.
#   vibeweb     runs the internet-facing Next app; gets only /etc/vibeaudit/web.env;
#               can't read the worker's ssh key, the proxy dir, or use docker.
#   vibeaudit   runs the worker; holds the VM 2 docker key; writes proxy state.
set -euo pipefail

PUBLIC_IP="${PUBLIC_IP:-108.61.149.76}"
SBX_VPC_IP="${SBX_VPC_IP:-10.1.96.3}"
CP_VPC_IP="${CP_VPC_IP:-10.1.96.4}"
DOMAIN="${DOMAIN:-${PUBLIC_IP//./-}.sslip.io}"
PNPM_VERSION="${PNPM_VERSION:-11.20.0}"
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -y -qq nodejs postgresql caddy ca-certificates curl gnupg jq >/dev/null

# --- docker CLI only (worker drives VM 2's daemon over ssh; no dockerd on VM 1) ---
if [ ! -f /etc/apt/keyrings/docker.asc ]; then
  install -d -m 755 /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
fi
. /etc/os-release
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update -qq
apt-get install -y -qq --no-install-recommends docker-ce-cli >/dev/null

# --- users ---------------------------------------------------------------------
getent group vibeaudit >/dev/null || groupadd --system vibeaudit
id vibeaudit >/dev/null 2>&1 || useradd --system --create-home --home-dir /home/vibeaudit --shell /usr/sbin/nologin -g vibeaudit vibeaudit
id vibedeploy >/dev/null 2>&1 || useradd --system --create-home --home-dir /home/vibedeploy --shell /usr/sbin/nologin -U vibedeploy
id vibeweb >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin -U vibeweb
chmod 750 /home/vibeaudit
install -d -m 755 -o vibedeploy -g vibedeploy /opt/vibeaudit/app /opt/vibeaudit/app/releases
# Older layout had releases owned by vibeaudit.
chown -R vibedeploy:vibedeploy /opt/vibeaudit/app
pkill -u vibeaudit -f 'ssh .*-L 9999' 2>/dev/null || true   # stray test tunnel from setup

# pnpm, pinned to the repo's packageManager version. Not via corepack: Ubuntu's corepack
# build crashes loading pnpm 11 (ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING). Fetch the npm
# tarball, verify its sha512 against the registry's integrity field, run it with node.
if [ "$(cd / && /usr/local/bin/pnpm --version 2>/dev/null)" != "$PNPM_VERSION" ]; then
  tmp=$(mktemp -d)
  meta=$(curl -fsS "https://registry.npmjs.org/pnpm/${PNPM_VERSION}")
  url=$(jq -r .dist.tarball <<<"$meta"); want=$(jq -r .dist.integrity <<<"$meta")
  curl -fsS -o "$tmp/pnpm.tgz" "$url"
  got="sha512-$(openssl dgst -sha512 -binary "$tmp/pnpm.tgz" | base64 -w0)"
  [ "$got" = "$want" ] || { echo "pnpm tarball integrity mismatch" >&2; exit 1; }
  rm -rf /opt/vibeaudit/pnpm && install -d /opt/vibeaudit/pnpm
  tar -xzf "$tmp/pnpm.tgz" -C /opt/vibeaudit/pnpm --strip-components=1
  rm -rf "$tmp"
  printf '#!/bin/sh\nexec /usr/bin/node /opt/vibeaudit/pnpm/bin/pnpm.cjs "$@"\n' > /usr/local/bin/pnpm
  chmod 755 /usr/local/bin/pnpm
fi

# --- worker -> VM 2 ssh key (only vibeaudit can read it). On VM 2 it's `restrict`ed,
#     pinned to VM 1's VPC IP and forced to `docker system dial-stdio`. ---
install -d -m 700 -o vibeaudit -g vibeaudit /home/vibeaudit/.ssh
[ -f /home/vibeaudit/.ssh/id_ed25519 ] || sudo -u vibeaudit ssh-keygen -q -t ed25519 -N '' -C vibeaudit-worker -f /home/vibeaudit/.ssh/id_ed25519
cat > /home/vibeaudit/.ssh/config <<EOF
Host ${SBX_VPC_IP}
    User root
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
    StrictHostKeyChecking yes
    UpdateHostKeys no
    ServerAliveInterval 15
EOF
chown vibeaudit:vibeaudit /home/vibeaudit/.ssh/config; chmod 600 /home/vibeaudit/.ssh/config

# --- Postgres: loopback only, dedicated role; password never on a command line ---
PG_CONF_DIR=$(ls -d /etc/postgresql/*/main | sort -V | tail -1)
sed -i "s/^#\?listen_addresses.*/listen_addresses = 'localhost'/" "$PG_CONF_DIR/postgresql.conf"
systemctl enable --now postgresql >/dev/null 2>&1
systemctl restart postgresql
if ! grep -q '^DATABASE_URL=' /etc/vibeaudit/env; then
  PGPASS=$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)
  # Password goes in on stdin (alphanumeric, so safe inside quotes), never in argv.
  { printf '\\set pw \x27%s\x27\n' "$PGPASS"; cat <<'SQL'
SELECT 'CREATE ROLE vibeaudit LOGIN' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vibeaudit')\gexec
ALTER ROLE vibeaudit PASSWORD :'pw';
SELECT 'CREATE DATABASE vibeaudit OWNER vibeaudit' WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'vibeaudit')\gexec
SQL
  } | sudo -u postgres psql -q -v ON_ERROR_STOP=1
  echo "DATABASE_URL=postgres://vibeaudit:${PGPASS}@127.0.0.1:5432/vibeaudit" >> /etc/vibeaudit/env
  unset PGPASS
fi
grep -q '^SANDBOX_DOCKER_HOST=' /etc/vibeaudit/env || echo "SANDBOX_DOCKER_HOST=ssh://root@${SBX_VPC_IP}" >> /etc/vibeaudit/env
grep -q '^SANDBOX_PROXY_URL=' /etc/vibeaudit/env || echo "SANDBOX_PROXY_URL=http://${CP_VPC_IP}:8080" >> /etc/vibeaudit/env
chmod 600 /etc/vibeaudit/env; chown root:root /etc/vibeaudit/env

# Web gets its own, narrower role (vibeaudit_web): it can read audits/events, create audits
# and answer approvals, write but never read test keys, and run no DDL. The table grants are
# applied by migrate() (packages/db WEB_GRANTS) on every worker start, so restart the worker
# after this creates the role. Owns nothing, so it can't ALTER/DROP anything.
if ! grep -q '^DATABASE_URL=postgres://vibeaudit_web:' /etc/vibeaudit/web.env 2>/dev/null; then
  WEBPASS=$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)
  { printf '\\set pw \x27%s\x27\n' "$WEBPASS"; cat <<'SQL'
SELECT 'CREATE ROLE vibeaudit_web LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vibeaudit_web')\gexec
ALTER ROLE vibeaudit_web PASSWORD :'pw';
ALTER ROLE vibeaudit_web SET statement_timeout = '15s';
ALTER ROLE vibeaudit_web CONNECTION LIMIT 20;
SQL
  } | sudo -u postgres psql -q -v ON_ERROR_STOP=1
  sudo -u postgres psql -q -v ON_ERROR_STOP=1 -d vibeaudit -c 'REVOKE CREATE ON SCHEMA public FROM PUBLIC'
  echo "DATABASE_URL=postgres://vibeaudit_web:${WEBPASS}@127.0.0.1:5432/vibeaudit" > /etc/vibeaudit/web.env
  unset WEBPASS
fi
chmod 600 /etc/vibeaudit/web.env; chown root:root /etc/vibeaudit/web.env

# --- Caddy: HTTPS for the sslip.io name; admin API on a root-only unix socket ---
install -d -m 750 -o caddy -g caddy /run/caddy
cat > /etc/caddy/Caddyfile <<EOF
{
	admin unix//run/caddy/admin.sock
}

${DOMAIN} {
	# Compress HTML/JS/CSS/JSON only: text/event-stream (SSE progress) must not be buffered.
	encode zstd gzip {
		match {
			header Content-Type text/html*
			header Content-Type text/css*
			header Content-Type text/javascript*
			header Content-Type application/javascript*
			header Content-Type application/json*
			header Content-Type image/svg+xml*
		}
	}
	reverse_proxy 127.0.0.1:3000 {
		flush_interval -1
	}
	header {
		Strict-Transport-Security "max-age=31536000"
		X-Content-Type-Options "nosniff"
		Referrer-Policy "no-referrer"
		X-Frame-Options "DENY"
		-Server
		-X-Powered-By
	}
}
EOF
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1 | tail -2
# The packaged unit reloads via the admin API; point it at the socket.
mkdir -p /etc/systemd/system/caddy.service.d
cat > /etc/systemd/system/caddy.service.d/10-vibeaudit.conf <<'EOF'
[Service]
RuntimeDirectory=caddy
RuntimeDirectoryMode=0750
ExecReload=
ExecReload=/usr/bin/caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --address unix//run/caddy/admin.sock --force
EOF
systemctl daemon-reload
systemctl enable caddy >/dev/null 2>&1
systemctl restart caddy

# --- systemd units (started by deploy.sh once a release exists) ---
COMMON_HARDENING='NoNewPrivileges=yes
ProtectSystem=strict
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallFilter=@system-service
SystemCallArchitectures=native
UMask=0027'

cat > /etc/systemd/system/vibeaudit-web.service <<EOF
[Unit]
Description=VibeAudit web (Next.js)
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
User=vibeweb
Group=vibeweb
WorkingDirectory=/opt/vibeaudit/app/current/apps/web
EnvironmentFile=/etc/vibeaudit/web.env
Environment=NODE_ENV=production HOSTNAME=127.0.0.1 PORT=3000 NEXT_TELEMETRY_DISABLED=1
ExecStart=/opt/vibeaudit/app/current/apps/web/node_modules/.bin/next start -H 127.0.0.1 -p 3000
Restart=on-failure
RestartSec=3
${COMMON_HARDENING}
ProtectHome=yes
# Only the Next cache is writable; compiled server code stays read-only.
ReadWritePaths=/opt/vibeaudit/app/current/apps/web/.next/cache
InaccessiblePaths=-/var/lib/vibeaudit -/etc/vibeaudit -/usr/bin/docker -/run/caddy
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
MemoryMax=1500M
TasksMax=256

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/vibeaudit-worker.service <<EOF
[Unit]
Description=VibeAudit audit worker
After=network-online.target postgresql.service vibeaudit-proxy.service
Wants=network-online.target

[Service]
User=vibeaudit
Group=vibeaudit
WorkingDirectory=/opt/vibeaudit/app/current/apps/worker
EnvironmentFile=/etc/vibeaudit/env
Environment=NODE_ENV=production DOCKER_CONFIG=/tmp/docker
ExecStart=/opt/vibeaudit/app/current/apps/worker/node_modules/.bin/tsx src/index.ts
Restart=on-failure
RestartSec=5
${COMMON_HARDENING}
ProtectHome=read-only
ReadWritePaths=/var/lib/vibeaudit/proxy
InaccessiblePaths=-/run/caddy
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
MemoryMax=1G

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload

echo "domain: https://${DOMAIN}"
echo "worker pubkey: $(cat /home/vibeaudit/.ssh/id_ed25519.pub)"
node --version; (cd / && sudo -u vibedeploy -H /usr/local/bin/pnpm --version)
