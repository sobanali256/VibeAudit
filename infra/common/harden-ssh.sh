#!/usr/bin/env bash
# Key-only SSH. Safe to rerun. Run as root on each VM.
# sshd takes the FIRST value it sees for each keyword, and sshd_config includes
# sshd_config.d/*.conf before its own lines, so a 00- drop-in beats both
# 50-cloud-init.conf (PasswordAuthentication yes) and the main file (PermitRootLogin yes).
set -euo pipefail

if [ ! -s /root/.ssh/authorized_keys ]; then
  echo "refusing: /root/.ssh/authorized_keys is empty, this would lock you out" >&2
  exit 1
fi

cat > /etc/ssh/sshd_config.d/00-vibeaudit-hardening.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
EOF
chmod 644 /etc/ssh/sshd_config.d/00-vibeaudit-hardening.conf

sshd -t
systemctl try-reload-or-restart ssh
sshd -T | grep -iE '^(passwordauthentication|permitrootlogin|kbdinteractiveauthentication) '
