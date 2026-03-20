#!/usr/bin/env bash
# firewall.sh — install and activate the webTraffik nftables ruleset
#
# Usage (standalone):
#   sudo bash firewall.sh
#
# Called automatically by install.sh during deployment.
# Safe to re-run: it replaces the ruleset atomically and restarts nftables.

set -euo pipefail

CONF_DIR="/etc/nftables.d"
CONF_OUT="${CONF_DIR}/webtraffik.conf"
MAIN_CONF="/etc/nftables.conf"

# ── Locate the template ───────────────────────────────────────────────────────
# Look next to this script first, then fall back to the current directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE=""
for candidate in "${SCRIPT_DIR}/nftables.conf" "./nftables.conf"; do
    if [[ -f "$candidate" ]]; then
        TEMPLATE="$candidate"
        break
    fi
done

if [[ -z "$TEMPLATE" ]]; then
    echo "error: nftables.conf template not found" >&2
    exit 1
fi

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "error: firewall.sh must be run as root" >&2
    exit 1
fi

# ── Dependency check ──────────────────────────────────────────────────────────
if ! command -v nft &>/dev/null; then
    echo "error: nft not found — install nftables first:" >&2
    echo "       apt-get install nftables   # Debian/Ubuntu" >&2
    echo "       dnf install nftables       # RHEL/Fedora" >&2
    exit 1
fi

# ── Auto-detect primary interface and subnet ──────────────────────────────────
# Use the interface that carries the default route.
IFACE=$(ip route show default | awk '/^default/ {print $5; exit}')
if [[ -z "$IFACE" ]]; then
    echo "error: could not determine default route interface" >&2
    exit 1
fi

# Derive the CIDR subnet for that interface (e.g. 192.168.4.0/24).
# 'ip route show' lists connected routes; match the one for our interface
# that is NOT the default route (i.e. a prefix route, not 0.0.0.0/0).
SUBNET=$(ip route show dev "$IFACE" \
    | awk '$1 ~ /^[0-9]+\.[0-9]+/ {print $1; exit}')

if [[ -z "$SUBNET" ]]; then
    echo "error: could not determine subnet for interface $IFACE" >&2
    exit 1
fi

echo "  primary interface : $IFACE"
echo "  management subnet : $SUBNET"

# ── Build the capture-port nft set literal ────────────────────────────────────
# Matches the capturePorts slice in main.go.
CAPTURE_PORTS="80, 8080, 8000, 8008, 8081, 8088, 8090, 8888, \
3000, 3001, 3128, 4000, 4200, 5000, 5001, 9000, 9090"

# ── Substitute tokens and write the live config ───────────────────────────────
mkdir -p "$CONF_DIR"

sed \
    -e "s|__SUBNET__|${SUBNET}|g" \
    -e "s|__CAPTURE_PORTS__|${CAPTURE_PORTS}|g" \
    "$TEMPLATE" > "$CONF_OUT"

echo "  wrote ruleset     : $CONF_OUT"

# ── Ensure /etc/nftables.conf includes our drop-in directory ──────────────────
# Most distros ship a /etc/nftables.conf that only loads itself.
# We append an include directive if it isn't already there.
if [[ -f "$MAIN_CONF" ]]; then
    if ! grep -qF "nftables.d" "$MAIN_CONF"; then
        echo '' >> "$MAIN_CONF"
        echo 'include "/etc/nftables.d/*.conf"' >> "$MAIN_CONF"
        echo "  updated           : $MAIN_CONF (added include for nftables.d/)"
    fi
else
    # No main conf at all — create a minimal one.
    printf '#!/usr/sbin/nft -f\nflush ruleset\ninclude "/etc/nftables.d/*.conf"\n' \
        > "$MAIN_CONF"
    echo "  created           : $MAIN_CONF"
fi

# ── Validate the generated ruleset before applying ────────────────────────────
if ! nft -c -f "$CONF_OUT" 2>/dev/null; then
    echo "error: nft syntax check failed — ruleset NOT applied" >&2
    echo "       check $CONF_OUT" >&2
    exit 1
fi

# ── Apply atomically ──────────────────────────────────────────────────────────
nft -f "$CONF_OUT"
echo "  ruleset applied"

# ── Enable + restart (or start) nftables service ─────────────────────────────
systemctl enable nftables.service 2>/dev/null || true

if systemctl is-active --quiet nftables.service; then
    systemctl restart nftables.service
    echo "  nftables          : restarted"
else
    systemctl start nftables.service
    echo "  nftables          : started"
fi

echo ""
echo "Firewall active.  Management access restricted to ${SUBNET}."
echo "Capture ports open to the internet."
echo "Run 'nft list ruleset' to inspect."
