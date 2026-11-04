#!/usr/bin/env bash
# Deploy the committed HEAD to VM 1. Run from the repo root:  bash infra/deploy.sh
#   DEPLOY_WORKER=1 bash infra/deploy.sh   # also (re)start the worker
# Ships `git archive HEAD` (tracked files only; never private/, .env or demos/), builds a new
# release on VM 1 as `vibedeploy` (no secrets, no ssh keys), flips `current`, restarts, and
# rolls back to the previous release if the health check fails.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! git diff --quiet HEAD -- apps packages package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json; then
  echo "uncommitted app changes; commit first (deploy ships HEAD only)" >&2; exit 1
fi
SHA=$(git rev-parse --short=12 HEAD)
REL="/opt/vibeaudit/app/releases/${SHA}-$(date -u +%Y%m%d%H%M%S)"

git archive --format=tar HEAD apps packages package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json .nvmrc \
  | ssh vibe-cp "install -d -o vibedeploy -g vibedeploy '$REL.tmp' && cd / && sudo -u vibedeploy tar -x -C '$REL.tmp'"

ssh vibe-cp "REL='$REL' DEPLOY_WORKER='${DEPLOY_WORKER:-0}' bash -s" <<'EOF'
set -euo pipefail
exec 9>/opt/vibeaudit/app/.deploy.lock
flock -n 9 || { echo "another deploy is running" >&2; exit 1; }
trap 'rm -rf "$REL.tmp"' EXIT
LOG=$(mktemp -p "$REL.tmp" build.XXXXXX.log)
chown vibedeploy "$LOG"

cd "$REL.tmp"
sudo -u vibedeploy -H env CI=1 NEXT_TELEMETRY_DISABLED=1 pnpm install --frozen-lockfile --reporter=silent >"$LOG" 2>&1 \
  || { tail -40 "$LOG"; exit 1; }
sudo -u vibedeploy -H env NEXT_TELEMETRY_DISABLED=1 pnpm --filter @vibeaudit/web build >>"$LOG" 2>&1 \
  || { tail -40 "$LOG"; exit 1; }
rm -f "$LOG"
# The web (vibeweb) may write only the Next cache.
install -d -o vibeweb -g vibeweb -m 750 "$REL.tmp/apps/web/.next/cache"
chown -R vibeweb:vibeweb "$REL.tmp/apps/web/.next/cache"
mv "$REL.tmp" "$REL"

prev=$(readlink -f /opt/vibeaudit/app/current 2>/dev/null || true)
flip() { ln -sfn "$1" /opt/vibeaudit/app/current.new && mv -T /opt/vibeaudit/app/current.new /opt/vibeaudit/app/current; }
restart() {
  systemctl enable vibeaudit-web >/dev/null 2>&1; systemctl restart vibeaudit-web
  if [ "$DEPLOY_WORKER" = 1 ]; then systemctl enable vibeaudit-worker >/dev/null 2>&1; systemctl restart vibeaudit-worker; fi
}
healthy() { for _ in $(seq 1 30); do curl -fs -o /dev/null http://127.0.0.1:3000/ && return 0; sleep 1; done; return 1; }

flip "$REL"; restart
if ! healthy; then
  echo "web did not come up on the new release:"; journalctl -u vibeaudit-web -n 30 --no-pager
  if [ -n "$prev" ] && [ -d "$prev" ]; then echo "rolling back to $prev"; flip "$prev"; restart; fi
  exit 1
fi
echo "web healthy"

# Keep the 3 newest finished releases; never the live one, never in-progress .tmp dirs.
cur=$(readlink -f /opt/vibeaudit/app/current)
ls -1dt /opt/vibeaudit/app/releases/*/ | sed 's#/$##' | grep -v '\.tmp$' | tail -n +4 | while read -r d; do
  [ "$d" = "$cur" ] || rm -rf "$d"
done
EOF
echo "deployed $SHA"
