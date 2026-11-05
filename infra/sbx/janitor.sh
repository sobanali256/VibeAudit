#!/usr/bin/env bash
# Sandbox janitor: the backstop for audits whose worker-side teardown never ran (worker crash,
# VM 1 reboot, a hung Docker call). Installed as /usr/local/sbin/vibeaudit-sbx-janitor and run
# every 5 minutes by vibeaudit-sbx-janitor.timer.
#
#   vibeaudit-sbx-janitor             one sweep (what the timer runs)
#   vibeaudit-sbx-janitor --install   write + enable the systemd service and timer
#   vibeaudit-sbx-janitor --dry-run   print what a sweep would remove
#
# What it removes (only things carrying the worker's `vibeaudit.audit` label, or a workspace
# dir named like an audit id):
#   - audit containers created more than CONTAINER_MAX_AGE ago (default 30 min = JANITOR_MAX_AGE_MS).
#     No stage runs that long (stage caps <= 6 min, whole audit 20 min).
#   - audit networks created more than IDLE_MAX_AGE ago (default 90 min), with anything still
#     attached. A network legitimately lives through the approval wait (up to 30 min) plus the
#     audit itself (20 min), so it gets a longer leash than a container.
#   - workspace dirs under WS_ROOT whose ctime is older than IDLE_MAX_AGE and that no audit
#     container still uses. ctime, not mtime: repo code can set mtime into the future with
#     `touch -d`, but it can't set ctime, and it can only bump it while its container runs.
#
# Runs as root on VM 2 and never reads repo-controlled content: it only lists Docker objects by
# label and top-level directory names (`rm -rf` doesn't follow symlinks inside them).
set -euo pipefail

LABEL=vibeaudit.audit
WS_ROOT="${WS_ROOT:-/srv/vibeaudit/ws}"
CONTAINER_MAX_AGE="${CONTAINER_MAX_AGE:-1800}"  # seconds
IDLE_MAX_AGE="${IDLE_MAX_AGE:-5400}"            # seconds
SELF=/usr/local/sbin/vibeaudit-sbx-janitor

if [ "${1:-}" = "--install" ]; then
  cat > /etc/systemd/system/vibeaudit-sbx-janitor.service <<EOF
[Unit]
Description=VibeAudit sandbox janitor (remove stale audit containers, networks, workspaces)
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=$SELF
TimeoutStartSec=10min
EOF
  cat > /etc/systemd/system/vibeaudit-sbx-janitor.timer <<'EOF'
[Unit]
Description=Run the VibeAudit sandbox janitor every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now vibeaudit-sbx-janitor.timer >/dev/null 2>&1
  echo "janitor timer: $(systemctl is-active vibeaudit-sbx-janitor.timer)"
  exit 0
fi

DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

# One sweep at a time (a slow sweep must not overlap the next timer tick).
exec 9>/run/vibeaudit-sbx-janitor.lock
flock -n 9 || { echo "janitor: another sweep is running"; exit 0; }

now=$(date +%s)
act() { # description, command...
  local what="$1"; shift
  if [ $DRY = 1 ]; then echo "would remove $what"; return 0; fi
  if "$@" >/dev/null 2>&1; then echo "removed $what"; else echo "failed to remove $what" >&2; fi
  return 0
}
age_of() { # JSON-quoted RFC 3339 timestamp -> seconds ago; -1 if unparseable (never removed:
  # a format surprise must not make everything look stale, which is how a first version of this
  # script read a minute-old network as 20 hours old).
  local ts="${1//\"/}" t
  [[ "$ts" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+(Z|[+-][0-9:]+)$ ]] || { echo -1; return; }
  t=$(date -d "$ts" +%s 2>/dev/null) || { echo -1; return; }
  echo $((now - t))
}

# --- containers -----------------------------------------------------------------
docker ps -aq --no-trunc --filter "label=$LABEL" | while read -r cid; do
  [ -n "$cid" ] || continue
  # {{json}}: a timestamp in one RFC 3339 token; "|" because none of these fields can hold one.
  info=$(docker inspect -f "{{json .Created}}|{{index .Config.Labels \"$LABEL\"}}|{{.Name}}" "$cid" 2>/dev/null) || continue
  IFS='|' read -r created audit name <<<"$info"
  age=$(age_of "$created")
  if [ "$age" -gt "$CONTAINER_MAX_AGE" ]; then act "container $name (audit $audit, ${age}s old)" docker rm -f "$cid"; fi
done

# --- networks -------------------------------------------------------------------
docker network ls -q --no-trunc --filter "label=$LABEL" | while read -r nid; do
  [ -n "$nid" ] || continue
  info=$(docker network inspect -f '{{json .Created}}|{{.Name}}' "$nid" 2>/dev/null) || continue
  IFS='|' read -r created name <<<"$info"
  age=$(age_of "$created")
  if [ "$age" -le "$IDLE_MAX_AGE" ]; then continue; fi
  for cid in $(docker network inspect -f '{{range $k, $v := .Containers}}{{$k}} {{end}}' "$nid" 2>/dev/null); do
    act "container $cid (on stale network $name)" docker rm -f "$cid"
  done
  act "network $name (${age}s old)" docker network rm "$nid"
done

# --- workspaces -----------------------------------------------------------------
if [ -d "$WS_ROOT" ]; then
  idle_min=$(( (IDLE_MAX_AGE + 59) / 60 ))
  find "$WS_ROOT" -mindepth 1 -maxdepth 1 -type d -cmin +"$idle_min" -printf '%f\n' | while read -r d; do
    # Audit ids only (AUDIT_ID_RE); leaves lost+found and anything else alone.
    if ! [[ "$d" =~ ^[A-Za-z0-9_-]{1,64}$ ]]; then continue; fi
    # Still in use by a live container of that audit: leave it for the next sweep.
    # A docker error must read as "in use" (skip), not as "no containers" (delete).
    ids=$(docker ps -aq --filter "label=$LABEL=$d") || continue
    if [ -n "$ids" ]; then continue; fi
    act "workspace $WS_ROOT/$d" rm -rf --one-file-system -- "${WS_ROOT:?}/$d"
  done
fi

echo "janitor sweep done"
