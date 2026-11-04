#!/usr/bin/env bash
# Run from the repo root on your machine. Sets up VM 1's app host and authorizes the
# worker's key on VM 2 (`restrict`, VPC source only, forced to `docker system dial-stdio`).
set -euo pipefail
cd "$(dirname "$0")/../.."
CP_VPC_IP="${CP_VPC_IP:-10.1.96.4}"
SBX_VPC_IP="${SBX_VPC_IP:-10.1.96.3}"

ssh vibe-cp 'bash -s' < infra/cp/setup-app.sh

pub=$(ssh vibe-cp 'cat /home/vibeaudit/.ssh/id_ed25519.pub')
case "$pub" in ssh-ed25519\ *) ;; *) echo "unexpected pubkey: $pub" >&2; exit 1;; esac
keyb64=$(cut -d' ' -f2 <<<"$pub")
line="restrict,from=\"${CP_VPC_IP}\",command=\"docker system dial-stdio\" ${pub}"
# Replace any existing line for this key (so option changes apply on rerun), then append.
ssh vibe-sbx "f=/root/.ssh/authorized_keys; grep -vF '${keyb64}' \$f > \$f.new || true; echo '${line}' >> \$f.new; chmod 600 \$f.new; mv \$f.new \$f"

# Pin VM 2's host key for the worker: scan over the VPC from VM 1, compare with the key
# read over our already-trusted admin ssh, and only then install it.
want=$(ssh vibe-sbx "cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub")
scanned=$(ssh vibe-cp "ssh-keyscan -T 5 -t ed25519 ${SBX_VPC_IP} 2>/dev/null | grep -v '^#' | head -1")
[ "$(cut -d' ' -f2,3 <<<"$scanned")" = "$want" ] || { echo "VM 2 host key mismatch over VPC! not trusting it" >&2; exit 1; }
ssh vibe-cp "printf '%s\n' '${scanned}' > /home/vibeaudit/.ssh/known_hosts && chown vibeaudit:vibeaudit /home/vibeaudit/.ssh/known_hosts && chmod 644 /home/vibeaudit/.ssh/known_hosts && rm -f /home/vibeaudit/.ssh/known_hosts.old"

ssh vibe-cp "cd / && sudo -u vibeaudit docker -H ssh://root@${SBX_VPC_IP} info --format 'worker -> VM2 docker {{.ServerVersion}} runtime={{.DefaultRuntime}}'"
