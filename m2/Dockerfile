FROM alpine:3.20

RUN apk add --no-cache --update \
      bash \
      iproute2 \
      iptables \
      busybox-extras \
      curl \
      socat \
      ca-certificates \
      libcap \
      php \
      python3 \
  && rm -rf /var/cache/apk/*

# the PHP process user (runs the vulnerable upload app) + lab user
RUN adduser -D -S -H -s /sbin/nologin wwwrun \
 && adduser -D -s /bin/bash marvel_lab \
 && echo 'marvel_lab:marvel' | chpasswd

# capability escalation hook: wwwrun's shell can switch to root via python3
RUN PY="$(readlink -f /usr/bin/python3)" \
 && setcap cap_setuid,cap_setgid=ep "$PY"

# vulnerable PHP web app (unrestricted file upload -> remote code execution)
RUN mkdir -p /var/www/html/uploads
COPY www/index.php www/upload.php /var/www/html/
RUN chown -R wwwrun:nogroup /var/www/html && chmod 0770 /var/www/html/uploads

# hint left by the "admin" after the m3 migration: SSH brute-force challenge
COPY hint.txt /root/hint.txt

COPY entrypoint.sh fw-m2.sh fwlog.sh hc.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/fw-m2.sh /usr/local/bin/fwlog.sh /usr/local/bin/hc.sh

EXPOSE 80
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]