#!/usr/bin/env bash
# install.sh — deploy webTraffik on a Linux host (no Go/make required)
#
# Usage:
#   1. scp the correct binary alongside this script AND firewall.sh + nftables.conf:
#        scp dist/webtraffik_linux_amd64 user@host:webtraffik
#        scp install.sh firewall.sh nftables.conf user@host:
#   2. On the remote host:
#        sudo bash install.sh [BINARY]
#
#   BINARY defaults to ./webtraffik if not specified.
#   Run with sudo or as root.

set -euo pipefail

BINARY_SRC="${1:-./webtraffik}"
INSTALL_BIN="/usr/local/bin/webtraffik"
DATA_DIR="/var/lib/webtraffik"
SERVICE_FILE="/etc/systemd/system/webtraffik.service"
SERVICE_USER="webtraffik"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Sanity checks ─────────────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
  echo "error: run this script as root (sudo bash install.sh)" >&2
  exit 1
fi

if [[ ! -f "$BINARY_SRC" ]]; then
  echo "error: binary not found: $BINARY_SRC" >&2
  echo "       scp the correct dist binary to this host first, then re-run." >&2
  exit 1
fi

if ! command -v systemctl &>/dev/null; then
  echo "error: systemd not found — this script requires a systemd-based Linux host" >&2
  exit 1
fi

# ── Create system user ────────────────────────────────────────────────────────

if id "$SERVICE_USER" &>/dev/null; then
  echo "user '$SERVICE_USER' already exists — skipping"
else
  useradd --system --no-create-home \
          --home "$DATA_DIR" \
          --shell /usr/sbin/nologin \
          "$SERVICE_USER"
  echo "created system user: $SERVICE_USER"
fi

# ── Data directory ────────────────────────────────────────────────────────────

install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 755 "$DATA_DIR"
echo "data directory: $DATA_DIR"

# ── Install binary ────────────────────────────────────────────────────────────

install -m 755 "$BINARY_SRC" "$INSTALL_BIN"
echo "installed binary: $INSTALL_BIN"

# ── Write systemd service unit ────────────────────────────────────────────────

cat > "$SERVICE_FILE" <<'EOF'
[Unit]
Description=webTraffik — real-time HTTP traffic world map
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=webtraffik
Group=webtraffik

ExecStart=/usr/local/bin/webtraffik
WorkingDirectory=/var/lib/webtraffik

AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

Restart=on-failure
RestartSec=5s

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/webtraffik

StandardOutput=journal
StandardError=journal
SyslogIdentifier=webtraffik

[Install]
WantedBy=multi-user.target
EOF

echo "wrote service unit: $SERVICE_FILE"

# ── Firewall ──────────────────────────────────────────────────────────────────

FIREWALL_SH="${SCRIPT_DIR}/firewall.sh"
if [[ -f "$FIREWALL_SH" ]]; then
  echo ""
  echo "── Configuring firewall ──────────────────────────────────────────────────"
  bash "$FIREWALL_SH"
else
  echo "warning: firewall.sh not found alongside install.sh — skipping firewall setup" >&2
  echo "         Copy firewall.sh and nftables.conf next to install.sh and re-run to apply." >&2
fi

# ── Enable and restart (or start) services ────────────────────────────────────

echo ""
echo "── Starting services ─────────────────────────────────────────────────────"

systemctl daemon-reload
systemctl enable webtraffik.service

if systemctl is-active --quiet webtraffik.service; then
  systemctl restart webtraffik.service
  echo "  webtraffik : restarted"
else
  systemctl start webtraffik.service
  echo "  webtraffik : started"
fi

echo ""
echo "webTraffik installed and running."
echo "  status    : systemctl status webtraffik"
echo "  logs      : journalctl -u webtraffik -f"
echo "  dashboard : http://$(hostname -I | awk '{print $1}'):8999"
