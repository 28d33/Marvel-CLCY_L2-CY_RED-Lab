#!/bin/bash
set -euo pipefail

log() { echo "[$(hostname)] $*"; }

# --- PingSweeper web app: real listener on 8080 (unprivileged user), root
#    socat front-ends expose 80/443/8443 to the same app -----------------------------
su -s /bin/sh webapp -c "python3 /srv/www/pingsvc.py 8080" &
sleep 1
socat TCP4-LISTEN:80,fork,reuseaddr TCP4:127.0.0.1:8080 &
socat TCP4-LISTEN:443,fork,reuseaddr TCP4:127.0.0.1:8080 &
socat TCP4-LISTEN:8443,fork,reuseaddr TCP4:127.0.0.1:8080 &
log "pingsweeper running on 8080 (front-ends on 80/443/8443)"

# --- DNS: authoritative zone for ipvlab.lab (passive recon) --------------------
named -g -u named -c /etc/bind/named.conf 2>&1 &
log "named serving ipvlab.lab on TCP/UDP 53"

# --- firewall (IPS: services open; scanner behaviour = auto-blacklist 120s) ---
/usr/local/bin/fw-m1.sh
/usr/local/bin/fwlog.sh FW-ACCEPT-NEW FW-SCAN-GATE FW-BLACKLIST FW-BLOCK &

trap 'kill $(jobs -p) 2>/dev/null' TERM INT
wait