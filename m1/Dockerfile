FROM alpine:3.20

RUN apk add --no-cache --update \
      bash \
      iproute2 \
      iptables \
      busybox-extras \
      python3 \
      openssl \
      curl \
      socat \
      ca-certificates \
      libcap \
      bind \
      bind-tools \
  && rm -rf /var/cache/apk/*

# lab user (all boxes) + unprivileged web-app user the PingSweeper runs as
RUN adduser -D -s /bin/bash marvel_lab \
 && adduser -D -S -H -s /sbin/nologin webapp \
 && echo 'marvel_lab:marvel' | chpasswd

# the ping tool calls /bin/busybox ping; the web user needs CAP_NET_RAW to send ICMP
RUN PY="/usr/bin/python3" \
 && setcap cap_net_raw+ep /bin/busybox \
 && chmod u+s /bin/bash   # SUID bash: root shell via  Bash -p

# PingSweeper web app (command-injection lab) + self-signed cert for the TLS copy
RUN mkdir -p /srv/www \
 && openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout /srv/www/key.pem -out /srv/www/cert.pem \
      -days 3650 -subj "/CN=ipvlab-m1" \
 >/dev/null 2>&1
COPY pingsvc.py /srv/www/pingsvc.py
RUN chmod +x /srv/www/pingsvc.py && chown -R webapp:nogroup /srv/www

# authoritative DNS for the ipvlab.lab lab domain (passive recon), zone transfer left open
COPY named.conf /etc/bind/named.conf
COPY ipvlab.lab.zone /var/named/ipvlab.lab.zone
RUN mkdir -p /run/named /var/named && chown -R named:named /run/named /var/named

COPY entrypoint.sh fw-m1.sh fwlog.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/fw-m1.sh /usr/local/bin/fwlog.sh

EXPOSE 53 80 443 8080 8443 44444
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]