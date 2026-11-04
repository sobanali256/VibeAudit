#!/usr/bin/env bash
# VM 1: mitmproxy egress proxy + its OS-level egress guard + ufw. Safe to rerun.
# Run from the repo root on your machine:  infra/cp/install-proxy.sh  (copies files, runs this)
set -euo pipefail

CP_VPC_IP="${CP_VPC_IP:-10.1.96.4}"
SBX_VPC_IP="${SBX_VPC_IP:-10.1.96.3}"
VPC_IF="${VPC_IF:-enp8s0}"
PUB_IF="${PUB_IF:-enp1s0}"
MITM_VERSION="${MITM_VERSION:-12.3.1}"
SRC="${SRC:-/tmp/vibeaudit-proxy}"   # where install-proxy.sh uploaded the files
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -y -qq python3-venv >/dev/null

# Dedicated, login-less user. The iptables guard below keys on its uid.
id vibeproxy >/dev/null 2>&1 || useradd --system --home-dir /var/lib/vibeaudit/proxy --shell /usr/sbin/nologin vibeproxy
# Group the worker will join to write state.json / read events.jsonl.
getent group vibeaudit >/dev/null || groupadd --system vibeaudit
usermod -aG vibeaudit vibeproxy   # to traverse /var/lib/vibeaudit (750 root:vibeaudit)

install -d -m 750 -o root -g vibeaudit /var/lib/vibeaudit
install -d -m 2770 -o vibeproxy -g vibeaudit /var/lib/vibeaudit/proxy
install -d -m 700 -o vibeproxy -g vibeproxy /var/lib/vibeaudit/proxy/mitm   # CA private key lives here
install -d -m 755 /opt/vibeaudit
install -m 644 "$SRC/vibeaudit_proxy.py" /opt/vibeaudit/vibeaudit_proxy.py

if [ ! -x /opt/vibeaudit/mitm/bin/mitmdump ] || ! /opt/vibeaudit/mitm/bin/mitmdump --version 2>/dev/null | grep -q "Mitmproxy: ${MITM_VERSION}"; then
  python3 -m venv /opt/vibeaudit/mitm
  /opt/vibeaudit/mitm/bin/pip install -q --disable-pip-version-check "mitmproxy==${MITM_VERSION}"
fi

# Generate the CA once (mitmdump writes it on first start), then publish only the PUBLIC cert.
if [ ! -f /var/lib/vibeaudit/proxy/mitm/mitmproxy-ca.pem ]; then
  sudo -u vibeproxy timeout 15 /opt/vibeaudit/mitm/bin/mitmdump --set confdir=/var/lib/vibeaudit/proxy/mitm \
    --listen-host 127.0.0.1 --listen-port 18080 >/dev/null 2>&1 || true
fi
install -m 644 /var/lib/vibeaudit/proxy/mitm/mitmproxy-ca-cert.pem /opt/vibeaudit/proxy-ca-cert.pem

# --- OS egress guard for the proxy user ------------------------------------
# The sandbox steers what the proxy connects to, so the proxy itself must never be able to
# reach VM 1's own services, the VPC, or cloud metadata. Only the local stub resolver and
# public addresses are reachable for uid vibeproxy.
cat > /usr/local/sbin/vibeaudit-proxy-guard <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
U=vibeproxy
for IPT in "iptables -w" "ip6tables -w"; do
  $IPT -N VIBEAUDIT-PROXY-OUT 2>/dev/null || true
  $IPT -F VIBEAUDIT-PROXY-OUT
done
# Replies on connections the proxy accepted (sandbox -> 10.1.96.4:8080) are ESTABLISHED;
# NEW connections to private ranges are rejected below, so this can't be used to reach them.
for IPT in "iptables -w" "ip6tables -w"; do
  $IPT -A VIBEAUDIT-PROXY-OUT -m owner --uid-owner $U -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
done
iptables -w -A VIBEAUDIT-PROXY-OUT -m owner --uid-owner $U -d 127.0.0.53 -p udp --dport 53 -j RETURN
iptables -w -A VIBEAUDIT-PROXY-OUT -m owner --uid-owner $U -d 127.0.0.53 -p tcp --dport 53 -j RETURN
iptables -w -A VIBEAUDIT-PROXY-OUT -m owner --uid-owner $U -o lo -j REJECT
for net in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.168.0.0/16 198.18.0.0/15 224.0.0.0/3; do
  iptables -w -A VIBEAUDIT-PROXY-OUT -m owner --uid-owner $U -d $net -j REJECT
done
ip6tables -w -A VIBEAUDIT-PROXY-OUT -m owner --uid-owner $U -o lo -j REJECT
for net in ::/128 ::1/128 ::ffff:0:0/96 fc00::/7 fe80::/10 ff00::/8 64:ff9b::/96; do
  ip6tables -w -A VIBEAUDIT-PROXY-OUT -m owner --uid-owner $U -d $net -j REJECT
done
for IPT in "iptables -w" "ip6tables -w"; do
  $IPT -C OUTPUT -j VIBEAUDIT-PROXY-OUT 2>/dev/null || $IPT -I OUTPUT 1 -j VIBEAUDIT-PROXY-OUT
done
# Cap concurrent sandbox connections to the proxy (memory DoS on VM 1).
iptables -w -N VIBEAUDIT-PROXY-IN 2>/dev/null || true
iptables -w -F VIBEAUDIT-PROXY-IN
iptables -w -A VIBEAUDIT-PROXY-IN -p tcp --dport 8080 --syn -m connlimit --connlimit-above 256 --connlimit-mask 32 -j REJECT --reject-with tcp-reset
iptables -w -C INPUT -j VIBEAUDIT-PROXY-IN 2>/dev/null || iptables -w -I INPUT 1 -j VIBEAUDIT-PROXY-IN
echo "vibeaudit-proxy-guard: applied"
EOF
chmod 755 /usr/local/sbin/vibeaudit-proxy-guard

cat > /etc/systemd/system/vibeaudit-proxy-guard.service <<'EOF'
[Unit]
Description=VibeAudit: block the egress proxy user from private/loopback/metadata addresses
After=network-pre.target ufw.service
Before=vibeaudit-proxy.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/vibeaudit-proxy-guard

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/vibeaudit-proxy.service <<EOF
[Unit]
Description=VibeAudit egress proxy (mitmproxy)
After=network-online.target vibeaudit-proxy-guard.service
Wants=network-online.target
Requires=vibeaudit-proxy-guard.service

[Service]
User=vibeproxy
Group=vibeaudit
UMask=0007
Environment=VIBEAUDIT_SANDBOX_IP=${SBX_VPC_IP}
ExecStart=/opt/vibeaudit/mitm/bin/mitmdump --quiet \\
  --set confdir=/var/lib/vibeaudit/proxy/mitm \\
  --listen-host ${CP_VPC_IP} --listen-port 8080 \\
  --set connection_strategy=lazy \\
  --set ssl_insecure=false \\
  --set block_global=true \\
  --set rawtcp=false \\
  --set body_size_limit=16m \\
  -s /opt/vibeaudit/vibeaudit_proxy.py
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/vibeaudit/proxy
CapabilityBoundingSet=
AmbientCapabilities=
# iptables can't police unix sockets: hide everything the proxy has no business reaching.
InaccessiblePaths=-/etc/vibeaudit -/var/run/postgresql -/run/postgresql -/var/run/docker.sock -/home
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=no
SystemCallFilter=@system-service
SystemCallArchitectures=native
MemoryMax=1G
TasksMax=512

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable vibeaudit-proxy-guard vibeaudit-proxy >/dev/null 2>&1
systemctl restart vibeaudit-proxy-guard
systemctl restart vibeaudit-proxy

# --- ufw: web on 80/443, proxy only from VM 2 over the VPC, ssh only on the public NIC ---
ufw allow 80/tcp comment 'caddy http (ACME + redirect)' >/dev/null
ufw allow 443/tcp comment 'caddy https' >/dev/null
ufw allow in on "$VPC_IF" from "$SBX_VPC_IP" to "$CP_VPC_IP" port 8080 proto tcp comment 'egress proxy for sandboxes' >/dev/null
ufw allow in on "$PUB_IF" to any port 22 proto tcp comment 'admin ssh (Vultr fw restricts source)' >/dev/null
ufw --force delete allow 22/tcp >/dev/null 2>&1 || true
ufw --force enable >/dev/null

sleep 2
systemctl is-active vibeaudit-proxy
ss -ltnp | grep ':8080 ' || { journalctl -u vibeaudit-proxy -n 30 --no-pager; exit 1; }
