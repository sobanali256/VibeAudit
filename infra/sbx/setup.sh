#!/usr/bin/env bash
# VM 2 (sandbox host): Docker + gVisor + egress lock + host firewall. Safe to rerun.
# Run as root:  ssh vibe-sbx 'bash -s' < infra/sbx/setup.sh
# (firewall.sh must already be at /usr/local/sbin/vibeaudit-sbx-firewall; see install.sh)
set -euo pipefail

CP_VPC_IP="${CP_VPC_IP:-10.1.96.4}"
VPC_IF="${VPC_IF:-enp8s0}"
PUB_IF="${PUB_IF:-enp1s0}"
export DEBIAN_FRONTEND=noninteractive

# Fail before touching ufw if the NIC names are wrong (a wrong name would drop all SSH).
ip link show "$PUB_IF" >/dev/null
ip link show "$VPC_IF" >/dev/null

# --- Docker (Ubuntu archive) -------------------------------------------------
apt-get update -qq
apt-get install -y -qq docker.io docker-buildx curl gnupg ca-certificates >/dev/null

# --- gVisor ----------------------------------------------------------------
if [ ! -f /usr/share/keyrings/gvisor-archive-keyring.gpg ]; then
  curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
fi
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
  > /etc/apt/sources.list.d/gvisor.list
apt-get update -qq
apt-get install -y -qq runsc >/dev/null

# --- Docker daemon config ----------------------------------------------------
# - runsc is the DEFAULT runtime, so a container started without --runtime still lands in
#   gVisor. BuildKit RUN steps do NOT: they run under runc on the host kernel. Never
#   `docker build` anything repo-controlled here; repo code only ever runs via `docker run`.
# - --overlay2=root:memory: the container rootfs overlay lives in sandbox memory, so writes
#   count against --memory instead of filling the host disk (default overlay is host-file
#   backed and unbounded: 1.5 GB written under a 512m cap in testing). The audit workspace
#   gets its own size-capped volume from the worker.
# - All container networks come from 172.30.0.0/15; the egress lock keys on that range.
# - "dns" points container upstream DNS at TEST-NET-1 (unroutable), so Docker's embedded
#   resolver can't forward external queries (a DNS exfil channel). External names resolve
#   only via the HTTP proxy. Under runsc the embedded resolver doesn't answer at all, so
#   the worker wires container-to-container names with --add-host.
# - "ip": published ports (we don't publish any) would bind to localhost only.
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<'EOF'
{
  "default-runtime": "runsc",
  "runtimes": { "runsc": { "path": "/usr/bin/runsc", "runtimeArgs": ["--overlay2=root:memory"] } },
  "bip": "172.31.255.1/24",
  "default-address-pools": [{ "base": "172.30.0.0/16", "size": 24 }],
  "dns": ["192.0.2.1"],
  "icc": false,
  "ip": "127.0.0.1",
  "ipv6": false,
  "userland-proxy": false,
  "no-new-privileges": true,
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" }
}
EOF

# --- Egress lock runs as part of docker's own start: if it fails, docker fails (closed). ---
# Older layout used a separate unit; remove it.
if [ -f /etc/systemd/system/vibeaudit-sbx-firewall.service ]; then
  systemctl disable vibeaudit-sbx-firewall >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/vibeaudit-sbx-firewall.service
fi
mkdir -p /etc/systemd/system/docker.service.d
cat > /etc/systemd/system/docker.service.d/10-vibeaudit-firewall.conf <<EOF
[Service]
Environment=CP_VPC_IP=${CP_VPC_IP}
ExecStartPost=/usr/local/sbin/vibeaudit-sbx-firewall
EOF

systemctl daemon-reload
systemctl enable docker >/dev/null 2>&1
systemctl restart docker

# --- Size-capped workspace filesystem ----------------------------------------
# The worker only has Docker-API access to this host (the ssh key is forced to
# `docker system dial-stdio`), so it cannot set a disk quota itself. We give it a fixed-size
# ext4 on a loop image, mounted at WS_MOUNT, and the worker bind-mounts a per-audit subdir.
# With one audit at a time this caps a single audit's on-disk workspace (a hostile install
# that tries to fill the disk hits ENOSPC inside its own fs, not the host's). 1000:1000 is
# the in-container audit user. rootfs writes are already bounded by --overlay2=root:memory.
WS_SIZE_GB="${WS_SIZE_GB:-12}"
WS_IMG=/srv/vibeaudit/ws.img
WS_MOUNT=/srv/vibeaudit/ws
install -d -m 755 /srv/vibeaudit
if [ ! -f "$WS_IMG" ]; then
  fallocate -l "${WS_SIZE_GB}G" "$WS_IMG" || dd if=/dev/zero of="$WS_IMG" bs=1M count=$((WS_SIZE_GB*1024))
  mkfs.ext4 -q -m 0 -O ^has_journal "$WS_IMG"   # no journal: it's scratch, destroyed per audit
fi
install -d -m 755 "$WS_MOUNT"
grep -q "$WS_IMG" /etc/fstab || echo "$WS_IMG $WS_MOUNT ext4 loop,nosuid,nodev,noexec,noatime 0 0" >> /etc/fstab
mountpoint -q "$WS_MOUNT" || mount "$WS_MOUNT"
# The audit user owns the contents; the worker makes/removes per-audit subdirs via a container.
chown 1000:1000 "$WS_MOUNT"; chmod 1770 "$WS_MOUNT"

# --- Host ufw: SSH only on the public NIC (Vultr fw limits it to the admin IP) and
#     from VM 1 over the VPC. Nothing else inbound. Add new rules before deleting old.
ufw allow in on "$PUB_IF" to any port 22 proto tcp comment 'admin ssh (Vultr fw restricts source)' >/dev/null
ufw allow in on "$VPC_IF" from "$CP_VPC_IP" to any port 22 proto tcp comment 'worker ssh from VM1' >/dev/null
# Only drop the old catch-all once the replacement rule is confirmed present.
if ufw status | grep -q "22/tcp on $PUB_IF .*ALLOW"; then
  ufw --force delete allow 22/tcp >/dev/null 2>&1 || true
fi
ufw --force enable >/dev/null

docker info --format 'docker {{.ServerVersion}} default-runtime={{.DefaultRuntime}} cgroup={{.CgroupVersion}}'
runsc --version | head -1
iptables -C DOCKER-USER -j VIBEAUDIT-EGRESS && iptables -C INPUT -j VIBEAUDIT-INPUT && echo "egress lock: present"
