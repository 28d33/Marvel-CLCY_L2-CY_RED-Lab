# debian:bookworm-slim is used here (instead of Alpine) because DVWA + MariaDB +
# Apache/PHP are far more stable on glibc; m1/m2 (the "many" machines) are Alpine.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl wget git procps \
      iproute2 iptables inetutils-ping \
      openssh-server openssh-client sudo netcat-openbsd \
      mariadb-server mariadb-client \
      apache2 libapache2-mod-php php php-mysql php-gd php-xml \
      php-mbstring php-curl \
 && rm -rf /var/lib/apt/lists/*

# DVWA source
RUN git clone --depth=1 https://github.com/digininja/DVWA.git /opt/DVWA

# --- SSH: the ONLY ssh in the whole lab; `marvel` is the brute-force target ---->
# password was set by the "admin" in the message left on m2: 5 chars from abcde12345!@#$
RUN useradd -m -s /bin/bash marvel \
 && echo 'marvel:aaa12' | chpasswd \
 && useradd -m -s /bin/bash marvel_lab \
 && echo 'marvel_lab:marvel' | chpasswd \
 && ssh-keygen -A \
 && sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
 && sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
 && echo 'AllowUsers marvel' >> /etc/ssh/sshd_config \
 && echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config \
 && sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
 && echo '# m3 sshd: password auth ON so hydra can brute-force marvel; use -L to tunnel to DVWA' >> /etc/ssh/sshd_config

# --- DVWA configuration ----------------------------------------------------------
# DB creds + security level come from the environment at runtime (getenv in
# config.inc.php.dist), so the container only needs the file copied in place.
RUN cp /opt/DVWA/config/config.inc.php.dist /opt/DVWA/config/config.inc.php \
 && printf 'ServerName localhost\n' > /etc/apache2/conf-available/servername.conf \
 && a2enconf servername >/dev/null \
 && a2enmod rewrite headers >/dev/null \
 && sed -i 's#DocumentRoot .*#DocumentRoot /opt/DVWA#' /etc/apache2/sites-available/000-default.conf
COPY apache-dvwa.conf /etc/apache2/conf-available/dvwa.conf
RUN a2enconf dvwa >/dev/null \
 && mkdir -p /var/lib/php/sessions && chown -R www-data:www-data /var/lib/php/sessions

# --- MariaDB: datadir is pre-seeded by the bookworm package; just own it ------
RUN mkdir -p /run/mysqld \
 && chown -R mysql:mysql /var/lib/mysql /run/mysqld

COPY dvwa-seed.sql /opt/dvwa-seed.sql
RUN set -e; \
  mariadbd --user=mysql --datadir=/var/lib/mysql --socket=/run/mysqld/mysqld.sock \
    --skip-networking=0 --bind-address=127.0.0.1 >/tmp/mysql-build.log 2>&1 & \
  for i in $(seq 1 60); do mariadb-admin ping --socket=/run/mysqld/mysqld.sock >/dev/null 2>&1 && break; sleep 1; done; \
  mariadb --socket=/run/mysqld/mysqld.sock -uroot -e \
    "CREATE DATABASE IF NOT EXISTS dvwa CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci; \
     CREATE USER IF NOT EXISTS 'dvwa'@'%' IDENTIFIED BY 'p@ssw0rd'; \
     CREATE USER IF NOT EXISTS 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd'; \
     GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'%'; \
     GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost'; \
     FLUSH PRIVILEGES;"; \
  mariadb --socket=/run/mysqld/mysqld.sock -uroot dvwa < /opt/dvwa-seed.sql; \
  mariadb-admin --socket=/run/mysqld/mysqld.sock -uroot shutdown

COPY entrypoint.sh fw-m3.sh fwlog.sh hc.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/fw-m3.sh /usr/local/bin/fwlog.sh /usr/local/bin/hc.sh

EXPOSE 22 80
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]