#!/usr/bin/env bash
# Run from the repo root on your machine. Uploads the proxy files to VM 1 and runs setup,
# then copies the proxy CA's PUBLIC cert to VM 2 for mounting into sandboxes.
set -euo pipefail
cd "$(dirname "$0")/../.."

ssh vibe-cp 'rm -rf /tmp/vibeaudit-proxy && install -d -m 700 /tmp/vibeaudit-proxy'
scp -q infra/cp/proxy/vibeaudit_proxy.py vibe-cp:/tmp/vibeaudit-proxy/
ssh vibe-cp 'bash -s' < infra/cp/setup-proxy.sh

# Public cert only. The CA private key never leaves /var/lib/vibeaudit/proxy/mitm on VM 1.
ssh vibe-cp 'cat /opt/vibeaudit/proxy-ca-cert.pem' | ssh vibe-sbx 'install -d -m 755 /opt/vibeaudit && cat > /opt/vibeaudit/proxy-ca-cert.pem && chmod 644 /opt/vibeaudit/proxy-ca-cert.pem && openssl x509 -noout -subject -enddate -in /opt/vibeaudit/proxy-ca-cert.pem'
