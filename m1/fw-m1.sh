#!/bin/sh
set -e

log() { echo "[$(hostname)][FW] $*"; }

iface() { ip -o -4 addr show 2>/dev/null | awk -v ip="$1" '$4 ~ ip"\\/" {print $2; exit}'; }

# m1: EXT = attacker_public (10.10.10.2, faces the attacker), INT = public_internal (10.20.20.2)
EXT_IF=$(iface 10.10.10.2)
INT_IF=$(iface 10.20.20.2)
[ -n "$EXT_IF" ] && [ -n "$INT_IF" ] || { log "ERROR: could not detect interfaces"; exit 1; }
log "interfaces: EXT=$EXT_IF(attacker_public) INT=$INT_IF(public_internal)"

iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT   # "m1 may only originate to m2" is enforced below

# the open services (no knock anymore: this is an IPS, not a port-knocker)
SVC="80,443,8080,8443"

iptables -N FW-ACCEPT-NEW    # a NEW connection to an open service = answered
iptables -N FW-SCAN-GATE     # the IPS: classify NEW SYNs and hostile-flag probes
iptables -N FW-BLACKLIST     # source behaves like a scanner -> BL 120s, host reads dead
iptables -N FW-BLOCK         # everything else reads "closed"

# --- FW-ACCEPT-NEW -----------------------------------------------------------
iptables -A FW-ACCEPT-NEW -m conntrack --ctstate NEW -j LOG --log-prefix "IPVLAB[m1] OPEN-APP " --log-level 6
iptables -A FW-ACCEPT-NEW -j ACCEPT

# --- FW-BLACKLIST: mark the scanner, then drop it for the next 120s -------------
iptables -A FW-BLACKLIST -m recent --name BL --set -j LOG --log-prefix "IPVLAB[m1] IPS-BLACKLIST " --log-level 6
iptables -A FW-BLACKLIST -j DROP

# --- FW-SCAN-GATE: the actual IPS. A human client (curl/browser) NEVER trips it;
#     default nmap behaviour trips within a few packets --------------------------
#     NOTE: app ports (80,443,8080,8443) are ACCEPTED earlier in INPUT, so this
#     chain only ever sees packets to NON-service ports: any NEW SYN here is a
#     probe, any NEW non-SYN (NULL/XMAS/FIN/bare-ACK) here is a crafted scan flag.
#   (1) hostile-flag probes: NULL (-sN) / XMAS (-sX) / FIN (-sF) / bare-ACK (-sA).
#       No real client opens a connection that way. 2 such probes in 10s = scanner.
iptables -A FW-SCAN-GATE -p tcp ! --syn -m conntrack --ctstate NEW,INVALID -m recent --name HOSTILE --update --seconds 10 --hitcount 2 -j FW-BLACKLIST
iptables -A FW-SCAN-GATE -p tcp ! --syn -m conntrack --ctstate NEW,INVALID -m recent --name HOSTILE --set -j FW-BLOCK
#   (2) NEW SYN to a NON-service port (probing a closed port). A port sweep:
#       5 such SYNs in 60s from one source = scanner.
iptables -A FW-SCAN-GATE -p tcp --syn -m conntrack --ctstate NEW -m recent --name SWEEP --update --seconds 60 --hitcount 5 -j FW-BLACKLIST
iptables -A FW-SCAN-GATE -p tcp --syn -m conntrack --ctstate NEW -m recent --name SWEEP --set -j FW-BLOCK
#   (3) anything else that reached here reads "closed"
iptables -A FW-SCAN-GATE -j FW-BLOCK

# --- FW-BLOCK: closes the door for everything that is not an open service --------
iptables -A FW-BLOCK -p tcp -j REJECT --reject-with tcp-reset
iptables -A FW-BLOCK -j DROP

# --- INPUT -----------------------------------------------------------------------
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -m recent --name BL --rcheck --seconds 120 -j DROP   # a blacklisted source reads dead
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -j ACCEPT
# services are OPEN by default (no knock)
iptables -A INPUT -p tcp -m multiport --dports "$SVC" -m conntrack --ctstate NEW -j FW-ACCEPT-NEW
# everything else TCP goes through the IPS scan detector
iptables -A INPUT -p tcp -j FW-SCAN-GATE
iptables -A INPUT -j FW-BLOCK

# --- hop limit: m1 may originate traffic only to m2 (10.20.20.0/24), never m3 -----
iptables -A OUTPUT -d 10.30.30.0/24 -j LOG --log-prefix "IPVLAB[m1] NO-M3 " --log-level 4
iptables -A OUTPUT -d 10.30.30.0/24 -j REJECT --reject-with icmp-net-unreachable

# --- router transit (attacker -> m1 -> m2 -> m3); the IPS blacklist cuts FORWARD too
ip route replace 10.30.30.0/24 via 10.20.20.3 dev "$INT_IF"
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m recent --name BL --rcheck --seconds 120 -j DROP
iptables -A FORWARD -i "$EXT_IF" -o "$INT_IF" -d 10.30.30.0/24 -p tcp -m multiport --dports 22,80 -j FW-ACCEPT-NEW
iptables -A FORWARD -i "$EXT_IF" -o "$INT_IF" -j FW-ACCEPT-NEW
iptables -A FORWARD -i "$INT_IF" -o "$EXT_IF" -j FW-ACCEPT-NEW
iptables -A FORWARD -j FW-BLOCK
iptables -t nat -A POSTROUTING -o "$INT_IF" -j MASQUERADE

log "IPS ONLINE: services $SVC open; SYN sweep / NULL / XMAS / FIN probes blacklisted 120s"
iptables -L INPUT -n --line-numbers | head -12
iptables -L FORWARD -n --line-numbers | tail -5