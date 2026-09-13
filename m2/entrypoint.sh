#!/bin/bash
set -euo pipefail

log() { echo "[$(hostname)] $*"; }

# --- vulnerable PHP upload app as the unprivileged wwwrun user -----------------
su -s /bin/sh wwwrun -c "php -S 0.0.0.0:80 -t /var/www/html" &
log "jumpweb (php upload app) running on TCP/80"

# --- firewall (SYN-drop guard + router/SNAT to m3) ----------------------------
/usr/local/bin/fw-m2.sh
/usr/local/bin/fwlog.sh FW-ACCEPT-APP FW-ACCEPT-OTH FW-BLOCK-SYN FW-BLOCK-ICMP FW-BLOCK-UDP FW-BLOCK &

# reverse-path route so forwarded attacker traffic can return via m1
ip route replace 10.10.10.0/24 via 10.20.20.2 2>/dev/null || true

trap 'kill $(jobs -p) 2>/dev/null' TERM INT
wait