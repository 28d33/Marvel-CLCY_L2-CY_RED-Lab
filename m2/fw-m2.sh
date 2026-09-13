#!/bin/sh
set -e

log() { echo "[$(hostname)][FW] $*"; }

iface() { ip -o -4 addr show 2>/dev/null | awk -v ip="$1" '$4 ~ ip"\\/" {print $2; exit}'; }

# m2: EXT = public_internal (10.20.20.3, faces m1) - guarded side
#      INT = internal_vulnerable (10.30.30.2, faces m3) - trusted side
EXT_IF=$(iface 10.20.20.3)
INT_IF=$(iface 10.30.30.2)
[ -n "$EXT_IF" ] && [ -n "$INT_IF" ] || { log "ERROR: could not detect interfaces"; exit 1; }
log "interfaces: EXT=$EXT_IF(public_internal) INT=$INT_IF(internal_vulnerable)"

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
iptables -A FW-ACCEPT-APP -j LOG --log-prefix "IPVLAB[m2] ACCEPT-APP " --log-level 6
iptables -A FW-ACCEPT-APP -j ACCEPT

iptables -N FW-ACCEPT-OTH
iptables -A FW-ACCEPT-OTH -j LOG --log-prefix "IPVLAB[m2] ACCEPT-OTH " --log-level 7
iptables -A FW-ACCEPT-OTH -j ACCEPT

iptables -N FW-BLOCK-SYN
iptables -A FW-BLOCK-SYN -j LOG --log-prefix "IPVLAB[m2] BLOCK-SYN " --log-level 4
iptables -A FW-BLOCK-SYN -j DROP

iptables -N FW-BLOCK-ICMP
iptables -A FW-BLOCK-ICMP -j LOG --log-prefix "IPVLAB[m2] BLOCK-ICMP " --log-level 4
iptables -A FW-BLOCK-ICMP -j DROP

iptables -N FW-BLOCK-UDP
iptables -A FW-BLOCK-UDP -j LOG --log-prefix "IPVLAB[m2] BLOCK-UDP " --log-level 4
iptables -A FW-BLOCK-UDP -j DROP

iptables -N FW-BLOCK
iptables -A FW-BLOCK -j LOG --log-prefix "IPVLAB[m2] BLOCK " --log-level 4
iptables -A FW-BLOCK -j DROP

# ---------------------------------------------------------------- INPUT
# only the upload web app is exposed on the guarded side (10.20.20.0/24)
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -i "$INT_IF" -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j FW-ACCEPT-OTH
iptables -A INPUT -p tcp --dport 80 -j FW-ACCEPT-APP
iptables -A INPUT -p icmp --icmp-type echo-request -j FW-BLOCK-ICMP
iptables -A INPUT -p tcp --tcp-flags ALL SYN -j FW-BLOCK-SYN
iptables -A INPUT -p udp -j FW-BLOCK-UDP
iptables -A INPUT -p icmp -j FW-BLOCK-ICMP
iptables -A INPUT -p tcp -j FW-ACCEPT-OTH
iptables -A INPUT -j FW-BLOCK

# ---------------------------------------------------------------- FORWARD
# forwarded traffic toward m3 (10.30.30.x) is SNATed to THIS box, so m3 only
# ever sees the "m2" hop; ports 22+80 (ssh brute-force target + DVWA).
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j FW-ACCEPT-OTH
iptables -A FORWARD -m conntrack --ctstate INVALID -j FW-BLOCK
iptables -A FORWARD -i "$INT_IF" -o "$EXT_IF" -j FW-ACCEPT-OTH
iptables -A FORWARD -i "$EXT_IF" -o "$INT_IF" -p tcp -m multiport --dports 22,80 -m conntrack --ctstate NEW -j FW-ACCEPT-APP
iptables -A FORWARD -i "$EXT_IF" -o "$INT_IF" -p icmp --icmp-type echo-request -j FW-BLOCK-ICMP
iptables -A FORWARD -i "$EXT_IF" -o "$INT_IF" -p tcp --tcp-flags ALL SYN -j FW-BLOCK-SYN
iptables -A FORWARD -i "$EXT_IF" -o "$INT_IF" -p udp -j FW-BLOCK-UDP
iptables -A FORWARD -i "$EXT_IF" -o "$INT_IF" -p icmp -j FW-BLOCK-ICMP
iptables -A FORWARD -i "$EXT_IF" -o "$INT_IF" -p tcp -j FW-ACCEPT-OTH
iptables -A FORWARD -i "$EXT_IF" -o "$INT_IF" -j FW-BLOCK
iptables -t nat -A POSTROUTING -o "$INT_IF" -j MASQUERADE

log "ruleset installed. $EXT_IF guarded (only :80), $INT_IF trusted/SNATed."
iptables -L INPUT -n --line-numbers | tail -11
iptables -L FORWARD -n --line-numbers | tail -12