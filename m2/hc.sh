#!/bin/sh
wget -q -T 5 -O /dev/null http://127.0.0.1/ || exit 1
iptables -S | grep -q "FW-BLOCK-SYN" || exit 1
exit 0