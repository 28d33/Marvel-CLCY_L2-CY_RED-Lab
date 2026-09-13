#!/bin/sh
mariadb-admin ping --socket=/run/mysqld/mysqld.sock >/dev/null 2>&1 || exit 1
wget -q -T 5 -O /dev/null http://127.0.0.1/ || exit 1
exit 0