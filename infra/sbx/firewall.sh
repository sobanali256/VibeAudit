#!/usr/bin/env bash
# Sandbox egress lock. Installed as /usr/local/sbin/vibeaudit-sbx-firewall and run as an
# ExecStartPost of docker.service, so if it fails, docker fails (fail closed). Idempotent,
# and each chain is replaced atomically (iptables-restore --noflush), so a rerun never
# leaves an empty (= open) chain, not even briefly.
#
# Rules key on the container-side INTERFACES (docker0, br-*), not on source addresses:
# a process that can forge source IPs (anything under runc, e.g. BuildKit RUN steps) must
# not be able to slip past a "-s POOL" match. Anything arriving from a container bridge may
# reach exactly:
#   - other containers (same audit network; Docker's per-bridge isolation separates networks)
#   - the egress proxy on VM 1, tcp CP_VPC_IP:8080
# Everything else is logged (prefix VIBEAUDIT-DROP, rate limited; feeds the containment
# log) and rejected. Containers can't open connections to this host at all.
set -euo pipefail

CP_VPC_IP="${CP_VPC_IP:-10.1.96.4}"
PROXY_PORT="${PROXY_PORT:-8080}"
POOL="172.30.0.0/15"         # docker0 (bip 172.31.255.0/24) + audit networks (172.30.0.0/16)
BRIDGE_NETS="172.30.0.0/16"  # user-defined networks
DOCKER0_NET="172.31.255.0/24"

# Strict reverse-path filtering: drop packets whose source couldn't be routed back out
# the interface they came in on (a second layer against spoofing).
sysctl -q -w net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1

# DOCKER-USER is created by dockerd. Wait for it briefly; never "succeed" without it.
for _ in $(seq 1 20); do iptables -w -n -L DOCKER-USER >/dev/null 2>&1 && break; sleep 0.5; done
iptables -w -n -L DOCKER-USER >/dev/null

iptables-restore -w --noflush <<EOF
*filter
:VIBEAUDIT-EGRESS - [0:0]
:VIBEAUDIT-INPUT - [0:0]
-A VIBEAUDIT-EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
-A VIBEAUDIT-EGRESS -i docker0 ! -s ${DOCKER0_NET} -j DROP
-A VIBEAUDIT-EGRESS -i br-+ ! -s ${BRIDGE_NETS} -j DROP
-A VIBEAUDIT-EGRESS -i br-+ -o br-+ -s ${POOL} -d ${POOL} -j RETURN
-A VIBEAUDIT-EGRESS -i docker0 -o docker0 -s ${POOL} -d ${POOL} -j RETURN
-A VIBEAUDIT-EGRESS -i br-+ -d ${CP_VPC_IP}/32 -p tcp --dport ${PROXY_PORT} -j RETURN
-A VIBEAUDIT-EGRESS -i docker0 -d ${CP_VPC_IP}/32 -p tcp --dport ${PROXY_PORT} -j RETURN
-A VIBEAUDIT-EGRESS -o br-+ -j DROP
-A VIBEAUDIT-EGRESS -o docker0 -j DROP
-A VIBEAUDIT-EGRESS -i br-+ -m limit --limit 30/min --limit-burst 60 -j LOG --log-prefix "VIBEAUDIT-DROP egress " --log-level 4
-A VIBEAUDIT-EGRESS -i docker0 -m limit --limit 30/min --limit-burst 60 -j LOG --log-prefix "VIBEAUDIT-DROP egress " --log-level 4
-A VIBEAUDIT-EGRESS -i br-+ -p tcp -j REJECT --reject-with tcp-reset
-A VIBEAUDIT-EGRESS -i docker0 -p tcp -j REJECT --reject-with tcp-reset
-A VIBEAUDIT-EGRESS -i br-+ -j REJECT --reject-with icmp-admin-prohibited
-A VIBEAUDIT-EGRESS -i docker0 -j REJECT --reject-with icmp-admin-prohibited
-A VIBEAUDIT-EGRESS -s ${POOL} -j DROP
-A VIBEAUDIT-INPUT -i br-+ -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
-A VIBEAUDIT-INPUT -i docker0 -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
-A VIBEAUDIT-INPUT -i br-+ -m limit --limit 30/min --limit-burst 60 -j LOG --log-prefix "VIBEAUDIT-DROP host " --log-level 4
-A VIBEAUDIT-INPUT -i docker0 -m limit --limit 30/min --limit-burst 60 -j LOG --log-prefix "VIBEAUDIT-DROP host " --log-level 4
-A VIBEAUDIT-INPUT -i br-+ -j DROP
-A VIBEAUDIT-INPUT -i docker0 -j DROP
-A VIBEAUDIT-INPUT -s ${POOL} -j DROP
COMMIT
EOF

iptables -w -C DOCKER-USER -j VIBEAUDIT-EGRESS 2>/dev/null || iptables -w -I DOCKER-USER 1 -j VIBEAUDIT-EGRESS
iptables -w -C INPUT -j VIBEAUDIT-INPUT 2>/dev/null || iptables -w -I INPUT 1 -j VIBEAUDIT-INPUT

# IPv6: containers have none (daemon "ipv6": false); refuse forwarding anyway.
ip6tables -w -P FORWARD DROP

echo "vibeaudit-sbx-firewall: applied (proxy ${CP_VPC_IP}:${PROXY_PORT})"
