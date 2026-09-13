#!/bin/bash
set -euo pipefail

log() { echo "[$(hostname)] $*"; }

export LANG=C.UTF-8

# --- MariaDB ---------------------------------------------------------------
/usr/sbin/mariadbd --user=mysql --datadir=/var/lib/mysql \
  --socket=/run/mysqld/mysqld.sock --port=3306 --bind-address=127.0.0.1 \
  >/var/log/mysql.log 2>&1 &
log "mariadb starting"

# --- Apache / DVWA ---------------------------------------------------------
apache2ctl -D FOREGROUND &
log "apache/dvwa starting"

# --- SSH (ONLY ssh box in the whole lab: brute-force target + DVWA tunnel) ---
mkdir -p /run/sshd
/usr/sbin/sshd -D -e &
log "sshd starting"

# --- firewall ---------------------------------------------------------------
/usr/local/bin/fw-m3.sh

# --- stream logs to the compose output ---------------------------------------
touch /var/log/apache2/access.log /var/log/apache2/error.log
tail -F /var/log/mysql.log /var/log/apache2/access.log /var/log/apache2/error.log &
/usr/local/bin/fwlog.sh FW-ACCEPT-APP FW-ACCEPT-OTH FW-BLOCK-SYN FW-BLOCK-ICMP FW-BLOCK-UDP FW-BLOCK &

trap 'kill $(jobs -p) 2>/dev/null' TERM INT
wait