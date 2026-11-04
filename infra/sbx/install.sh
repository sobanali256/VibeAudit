#!/usr/bin/env bash
# Run from the repo root on your machine. Provisions VM 2 (sandbox host). Safe to rerun.
set -euo pipefail
cd "$(dirname "$0")/../.."

scp -q infra/sbx/firewall.sh vibe-sbx:/usr/local/sbin/vibeaudit-sbx-firewall
ssh vibe-sbx 'chmod 755 /usr/local/sbin/vibeaudit-sbx-firewall'
ssh vibe-sbx 'bash -s' < infra/sbx/setup.sh
