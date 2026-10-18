#!/usr/bin/env bash
# Install the RalX hub on Linux (Ubuntu/Debian) as a systemd service running
# as its own unprivileged user. Agents on the same machine must run as a
# different user without sudo, or the account boundary means nothing.
#
#   sudo bash install.sh ./ralx-linux [https://ralx.example.com]
set -euo pipefail
BIN="${1:?path to the ralx linux binary}"
ORIGIN="${2:-}"
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }

id ralx >/dev/null 2>&1 || useradd --system --home /var/lib/ralx --shell /usr/sbin/nologin ralx
install -m 0755 -o root -g root "$BIN" /usr/local/bin/ralx
install -d -m 0700 -o ralx -g ralx /var/lib/ralx
if [ -n "$ORIGIN" ] && [ ! -f /var/lib/ralx/config.yaml ]; then
  # An internet-reachable VPS/tunnel origin goes in internet_origins, which
  # serves only OAuth/mcp/agent-REST/approve; sensitive admin stays on the local
  # admin pipe. A trusted tailnet/LAN origin can be moved to public_origins by
  # hand to allow full admin there.
  printf 'internet_origins:\n  - %s\n' "$ORIGIN" > /var/lib/ralx/config.yaml
  chown ralx:ralx /var/lib/ralx/config.yaml
  chmod 0600 /var/lib/ralx/config.yaml
fi
install -m 0644 "$(dirname "$0")/ralx.service" /etc/systemd/system/ralx.service
systemctl daemon-reload
systemctl enable --now ralx
sleep 1
curl -fsS http://127.0.0.1:7317/healthz && echo
echo "RalX is running. Owner commands: sudo -u ralx RALX_ADMIN_PIPE=/run/ralx/admin.sock ralx admin ..."
echo "First passkey: sudo -u ralx RALX_ADMIN_PIPE=/run/ralx/admin.sock ralx admin setup-link --origin $ORIGIN"
