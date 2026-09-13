#!/bin/sh
chains="$@"
[ -z "$chains" ] && chains="FW-ACCEPT-NEW FW-BLOCK"

while true; do
  sleep 10
  out=""
  for c in $chains; do
    cnt=$(iptables -L "$c" -nvx 2>/dev/null | awk 'NR==3 && $1 ~ /^[0-9]+$/ {printf "pkts=%s bytes=%s", $1, $2}')
    [ -n "$cnt" ] && out="$out $c[$cnt]"
  done
  echo "[$(date -u +%H:%M:%S)][$(hostname)][FWLOG]$out"
  for c in $chains; do iptables -Z "$c" 2>/dev/null; done
done