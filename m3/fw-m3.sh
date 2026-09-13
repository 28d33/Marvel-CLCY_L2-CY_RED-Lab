#!/bin/sh
set -e

log() { echo "[$(hostname)][FW] $*"; }

iface() { ip -o -4 addr show 2>/dev/null | awk -v ip="$1" '$4 ~ ip"\\/" {print $2; exit}'; }

EXT_IF=$(iface 10.30.30.3)   # internal_vulnerable (faces m2)
[ -n "$EXT_IF" ] || { log "ERROR: could not detect interface"; exit 1; }
log "interface: $EXT_IF (internal_vulnerable)"

iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

iptables -N FW-ACCEPT-APP
iptables -A FW-ACCEPT-APP -j LOG --log-prefix "IPVLAB[m3] ACCEPT-APP " --log-level 6
iptables -A FW-ACCEPT-APP -j ACCEPT

iptables -N FW-ACCEPT-OTH
iptables -A FW-ACCEPT-OTH -j LOG --log-prefix "IPVLAB[m3] ACCEPT-OTH " --log-level 7
iptables -A FW-ACCEPT-OTH -j ACCEPT

iptables -N FW-BLOCK-SYN
iptables -A FW-BLOCK-SYN -j LOG --log-prefix "IPVLAB[m3] BLOCK-SYN " --log-level 4
iptables -A FW-BLOCK-SYN -j DROP

iptables -N FW-BLOCK-ICMP
iptables -A FW-BLOCK-ICMP -j LOG --log-prefix "IPVLAB[m3] BLOCK-ICMP " --log-level 4
iptables -A FW-BLOCK-ICMP -j DROP

iptables -N FW-BLOCK-UDP
iptables -A FW-BLOCK-UDP -j LOG --log-prefix "IPVLAB[m3] BLOCK-UDP " --log-level 4
iptables -A FW-BLOCK-UDP -j DROP

iptables -N FW-BLOCK
iptables -A FW-BLOCK -j LOG --log-prefix "IPVLAB[m3] BLOCK " --log-level 4
iptables -A FW-BLOCK -j DROP

iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j FW-ACCEPT-OTH
iptables -A INPUT -p tcp -m multiport --dports 22,80 -j FW-ACCEPT-APP
iptables -A INPUT -p icmp --icmp-type echo-request -j FW-BLOCK-ICMP
iptables -A INPUT -p tcp --tcp-flags ALL SYN -j FW-BLOCK-SYN
iptables -A INPUT -p udp -j FW-BLOCK-UDP
iptables -A INPUT -p icmp -j FW-BLOCK-ICMP
iptables -A INPUT -p tcp -j FW-ACCEPT-OTH
iptables -A INPUT -j FW-BLOCK

log "ruleset installed: only 22,80 allowed inbound on $EXT_IF"
iptables -L INPUT -n --line-numbers | tail -11