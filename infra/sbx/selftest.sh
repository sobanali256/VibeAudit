#!/usr/bin/env bash
# Containment self-test for VM 2. Run as root on vibe-sbx:  ssh vibe-sbx 'bash -s' < infra/sbx/selftest.sh
# Prints PASS/FAIL per check and exits non-zero if any check fails. Leaves nothing behind.
set -uo pipefail

CP_VPC_IP="${CP_VPC_IP:-10.1.96.4}"
PUB_IP="$(ip -4 -o addr show enp1s0 | awk '{print $4}' | cut -d/ -f1)"
NET="vibeaudit-selftest-$$"
CURL=curlimages/curl:8.17.0
BB=busybox:1.37
PY=python:3.13-alpine
fails=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1  ($2)"; fails=$((fails+1)); }
cleanup() { docker rm -f "$NET-peer" "$NET-sink" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; }
trap cleanup EXIT

for img in $CURL $BB $PY; do docker image inspect "$img" >/dev/null 2>&1 || docker pull -q "$img" >/dev/null; done

# --- preconditions -----------------------------------------------------------
[ "$(docker info -f '{{.DefaultRuntime}}')" = runsc ] && pass "default runtime is runsc" || fail "default runtime is runsc" "$(docker info -f '{{.DefaultRuntime}}')"
iptables -C DOCKER-USER -j VIBEAUDIT-EGRESS 2>/dev/null && iptables -C INPUT -j VIBEAUDIT-INPUT 2>/dev/null \
  && pass "egress/input chains hooked" || fail "egress/input chains hooked" "missing jump"

docker network create "$NET" >/dev/null
GW=$(docker network inspect -f '{{(index .IPAM.Config 0).Gateway}}' "$NET")
docker run -d --name "$NET-peer" --network "$NET" $BB sh -c 'mkdir /w; echo peer-ok >/w/index.html; httpd -f -p 8000 -h /w' >/dev/null
sleep 1
PEER=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NET-peer")

c() { docker run --rm --network "$NET" --cap-drop ALL --user 65534:65534 "$@"; }
blocked() { # name, url
  local out; out=$(c $CURL -sS -m 5 -o /dev/null -w '%{http_code}' "$2" 2>&1)
  case "$out" in *000*) pass "blocked: $1";; *) fail "blocked: $1" "$out";; esac
}

# --- egress (runsc) ------------------------------------------------------------
blocked "internet 1.1.1.1:443"            https://1.1.1.1
blocked "cloud metadata"                  http://169.254.169.254/v1.json
blocked "VM1 ssh"                         telnet://$CP_VPC_IP:22
blocked "VM1 postgres"                    telnet://$CP_VPC_IP:5432
blocked "host sshd via gateway"           telnet://$GW:22
blocked "host public IP"                  telnet://$PUB_IP:22
out=$(c $BB nslookup -timeout=3 example.com 2>&1); case "$out" in *Address*example*|*"Name:"*example*) fail "external DNS" "$out";; *) pass "blocked: external DNS";; esac
out=$(c $BB wget -qO- -T 4 "http://$PEER:8000/" 2>&1); [ "$out" = peer-ok ] && pass "same-network peer reachable by IP" || fail "same-network peer reachable" "$out"
out=$(c --add-host "app:$PEER" $BB wget -qO- -T 4 http://app:8000/ 2>&1); [ "$out" = peer-ok ] && pass "peer via --add-host" || fail "peer via --add-host" "$out"
out=$(docker run --rm $CURL -sS -m 5 -o /dev/null -w '%{http_code}' https://1.1.1.1 2>&1); case "$out" in *000*) pass "blocked: default bridge internet";; *) fail "default bridge internet" "$out";; esac
before=$(iptables -nvxL VIBEAUDIT-EGRESS | awk -v ip="$CP_VPC_IP" '$0 ~ ip && /dpt:8080/ {s+=$1} END {print s+0}')
c $CURL -sS -m 4 -o /dev/null "http://$CP_VPC_IP:8080/" >/dev/null 2>&1
after=$(iptables -nvxL VIBEAUDIT-EGRESS | awk -v ip="$CP_VPC_IP" '$0 ~ ip && /dpt:8080/ {s+=$1} END {print s+0}')
[ "$after" -gt "$before" ] && pass "proxy port passes VM2 lock" || fail "proxy port passes VM2 lock" "counter $before->$after"

# --- spoofed source under runc (worst case: host-kernel raw sockets) -------------
docker run -d --name "$NET-sink" --runtime runc --network "$NET" $BB sleep 60 >/dev/null
spoof_before=$(iptables -nvxL VIBEAUDIT-EGRESS | awk '/DROP/ && /br-\+/ && /!172.30/ {s+=$1} END {print s+0}')
docker run --rm --runtime runc --network "$NET" $PY python3 -c '
import socket,struct
s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW)
src=socket.inet_aton("203.0.113.9"); dst=socket.inet_aton("192.0.2.55")
udp=struct.pack("!HHHH",40000,53,8,0)
ip=struct.pack("!BBHHHBBH4s4s",0x45,0,28,1,0,64,17,0,src,dst)
for _ in range(5): s.sendto(ip+udp,("192.0.2.55",0))
' 2>/dev/null
sleep 1
spoof_after=$(iptables -nvxL VIBEAUDIT-EGRESS | awk '/DROP/ && /br-\+/ && /!172.30/ {s+=$1} END {print s+0}')
[ "$spoof_after" -ge $((spoof_before+5)) ] && pass "spoofed-source packets dropped (runc raw socket)" || fail "spoofed source dropped" "drop counter $spoof_before->$spoof_after"

# --- resource abuse (runsc) --------------------------------------------------------
cid=$(docker run -d --pids-limit 512 --memory 512m --cpus 1 --cap-drop ALL --security-opt no-new-privileges --user 65534:65534 $BB sleep 120)
sleep 1; docker exec -d "$cid" sh -c 'b(){ b|b& }; b' 2>/dev/null
sleep 6
load=$(cut -d' ' -f1 /proc/loadavg)
st=$(docker inspect -f '{{.State.Status}}' "$cid"); docker rm -f "$cid" >/dev/null
if journalctl -k --since -30s --no-pager | grep -q "fork rejected by pids controller"; then
  pass "fork bomb hit pids limit (container: $st, host load $load)"
else
  fail "fork bomb hit pids limit" "no pids rejection logged; container $st"
fi

d0=$(df --output=used -m / | tail -1)
out=$(timeout 90 docker run --rm --memory 512m $BB sh -c 'dd if=/dev/urandom of=/big bs=1M count=1500 2>/dev/null; echo wrote' 2>&1)
d1=$(df --output=used -m / | tail -1)
[ $((d1-d0)) -lt 200 ] && [ "$out" != wrote ] && pass "rootfs write bounded by memory cap (host disk +$((d1-d0))MB)" \
  || fail "rootfs write bounded" "host disk +$((d1-d0))MB, out=$out"

echo "---"; [ $fails -eq 0 ] && echo "ALL PASS" || echo "$fails FAILED"
exit $fails
