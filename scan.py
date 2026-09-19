#!/usr/bin/env python3
"""Residential fleet scanner. Runs on a clean-IP box (GitHub Actions runner).

Stage 1  masscan  -> open ports across a shard of residential ranges
Stage 2  probe    -> classify each open port: open proxy / router panel / other
Stage 3  verify   -> for proxies, PROVE traffic exits through them

Usage:
  scan.py --ranges ranges.txt --shard 0/20 --rate 20000 --mode proxy --out out/
"""
import argparse, asyncio, ipaddress, json, os, re, subprocess, sys, time, random
from collections import Counter

PORTS_PROXY  = "3128,1080,8118,8080,8000,8888,1081,9050,8081,8118"
PORTS_ROUTER = "80,8080,8000,8443,81,8081,8888,7547"

# strict router signatures: (name, [regex]) - must match in first 8KB
ROUTER_SIGS = [
 ("MikroTik",   [r"RouterOS", r"webfig", r"mikrotik"]),
 ("OpenWrt",    [r"LuCI", r"cgi-bin/luci", r"openwrt"]),
 ("TP-Link",    [r"TP-?LINK", r"Archer\s*C?\d", r"tl-wr", r"tplinkwifi"]),
 ("D-Link",     [r"D-?Link", r"DSL-\d{3,}", r"DIR-\d{3,}", r"dlink\.com"]),
 ("Huawei",     [r"Huawei", r"HiLink", r"HG8\d{3}", r"EchoLife"]),
 ("ZTE",        [r"ZXHN", r"ZTE\s*Corporation", r"zxic"]),
 ("Tenda",      [r"Tenda", r"tendacn"]),
 ("Netgear",    [r"NETGEAR", r"Nighthawk", r"Genie\b", r"orbi"]),
 ("ASUS",       [r"ASUSWRT", r"RT-AC\d", r"RT-AX\d", r"asus\.com"]),
 ("AVM Fritz",  [r"FRITZ!Box", r"fritz\.box", r"\bAVM\b"]),
 ("Ubiquiti",   [r"AirOS", r"UniFi", r"EdgeOS", r"airMAX", r"ubnt"]),
 ("Zyxel",      [r"ZyXEL", r"ZyWALL", r"Keenetic"]),
 ("Sagemcom",   [r"Sagemcom", r"\bSagem\b"]),
 ("Technicolor",[r"Technicolor", r"THOMSON"]),
 ("ARRIS",      [r"ARRIS", r"Touchstone", r"Surfboard"]),
 ("Nokia",      [r"Nokia", r"Alcatel", r"\bONT\b"]),
 ("Mercusys",   [r"Mercusys"]),
 ("TOTOLINK",   [r"TOTOLINK"]),
 ("Cambium",    [r"Cambium", r"ePMP"]),
 ("Grandstream",[r"Grandstream"]),
 ("Mimosa",     [r"Mimosa Networks"]),
 ("Teltonika",  [r"Teltonika", r"RUT\d"]),
 ("Cisco",      [r"Cisco", r"Linksys", r"RV\d{3}"]),
 ("Intelbras",  [r"Intelbras", r"WRN\d"]),
 ("DrayTek",    [r"DrayTek", r"Vigor"]),
 ("Ruckus",     [r"Ruckus", r"ZoneDirector"]),
 ("EnGenius",   [r"EnGenius"]),
 ("TRENDnet",   [r"TRENDnet"]),
 ("LevelOne",   [r"LevelOne"]),
 ("Edimax",     [r"Edimax"]),
 ("Dovado",     [r"Dovado"]),
]
COMPILED = [(n, [re.compile(r, re.I) for r in rs]) for n, rs in ROUTER_SIGS]

NOT_ROUTER = [re.compile(r, re.I) for r in [
 r"cPanel Login", r"Plesk", r"Grafana", r"Moodle", r"WordPress", r"phpMyAdmin",
 r"Apache HTTP Server Test Page", r"nginx", r"Apache2 Ubuntu", r"IIS Windows",
 r"Just a moment", r"Cloudflare", r"Welcome to nginx", r"Tomcat", r"Jenkins",
 r"GitLab", r"Kubernetes", r"DirectAdmin", r"Webmin", r"cPanel", r"WHM",
 r"Palo Alto", r"FortiGate", r"OpenVPN", r"pfSense", r"OPNsense", r"Sophos",
]]


def shard_ranges(path, idx, count):
    out = []
    with open(path) as f:
        for i, line in enumerate(f):
            if i % count == idx:
                out.append(line.split("\t")[0].strip())
    return [r for r in out if r]


def run_masscan(ranges, ports, rate, outfile, iface):
    with open(outfile + ".ranges", "w") as f:
        f.write("\n".join(ranges) + "\n")
    cmd = ["sudo", "masscan", "-iL", outfile + ".ranges", "-p", ports,
           "--rate", str(rate), "--wait", "3", "--open-only",
           "-oL", outfile, "--retries", "1"]
    if iface:
        cmd += ["-e", iface]
    print("[masscan]", " ".join(cmd), flush=True)
    t0 = time.time()
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        print("[masscan] FAILED rc=%s\n%s\n%s" % (p.returncode, p.stdout[-2000:], p.stderr[-2000:]), flush=True)
        return None
    print(f"[masscan] done in {time.time()-t0:.0f}s", flush=True)
    found = []
    for line in open(outfile):
        line = line.strip()
        if not line or line.startswith("#"): continue
        parts = line.split()
        if len(parts) >= 4:
            found.append((parts[3], int(parts[2])))
    return found


async def read_http(host, port, timeout=6, path="/", scheme=None):
    """Return (status, headers, body) or None."""
    if scheme is None:
        scheme = "https" if port in (443, 8443, 2083, 2087) else "http"
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except Exception:
        return None
    try:
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
               "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126 Safari/537.36\r\n"
               "Accept: */*\r\nConnection: close\r\n\r\n")
        w.write(req.encode())
        await asyncio.wait_for(w.drain(), timeout=timeout)
        data = await asyncio.wait_for(r.read(16000), timeout=timeout)
    except Exception:
        data = b""
    finally:
        try: w.close()
        except Exception: pass
    if not data:
        return None
    txt = data.decode("utf-8", "ignore")
    head, _, body = txt.partition("\r\n\r\n")
    m = re.match(r"HTTP/\d\.\d\s+(\d+)", head)
    status = int(m.group(1)) if m else 0
    return status, head, body


async def test_http_proxy(ip, port, timeout=8):
    """Prove it forwards: ask for our own IP through it."""
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    except Exception:
        return None
    try:
        req = ("GET http://api.ipify.org/ HTTP/1.1\r\nHost: api.ipify.org\r\n"
               "User-Agent: curl/8.0\r\nConnection: close\r\n\r\n")
        w.write(req.encode()); await asyncio.wait_for(w.drain(), timeout=timeout)
        data = await asyncio.wait_for(r.read(4000), timeout=timeout)
    except Exception:
        data = b""
    finally:
        try: w.close()
        except Exception: pass
    if not data: return None
    t = data.decode("utf-8", "ignore")
    body = t.split("\r\n\r\n", 1)[-1].strip()
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", body):
        return {"exit_ip": body, "transparent": body == ip, "via": "http"}
    return None


async def test_socks5(ip, port, timeout=8):
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    except Exception:
        return None
    try:
        w.write(bytes([5, 1, 0])); await asyncio.wait_for(w.drain(), timeout=timeout)
        rep = await asyncio.wait_for(r.read(2), timeout=timeout)
        if len(rep) < 2 or rep[1] != 0: return None
        host = b"api.ipify.org"
        w.write(bytes([5, 1, 0, 3, len(host)]) + host + (80).to_bytes(2, "big"))
        await asyncio.wait_for(w.drain(), timeout=timeout)
        rep = await asyncio.wait_for(r.read(10), timeout=timeout)
        if len(rep) < 2 or rep[1] != 0: return None
        w.write(b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n")
        await asyncio.wait_for(w.drain(), timeout=timeout)
        data = await asyncio.wait_for(r.read(4000), timeout=timeout)
    except Exception:
        data = b""
    finally:
        try: w.close()
        except Exception: pass
    if not data: return None
    body = data.decode("utf-8", "ignore").split("\r\n\r\n", 1)[-1].strip()
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", body):
        return {"exit_ip": body, "transparent": body == ip, "via": "socks5"}
    return None


async def probe_one(ip, port, sem, mode):
    async with sem:
        res = {"ip": ip, "port": port}
        # proxy ports: try proxy protocols first
        if port in (3128, 8118, 8080, 8000, 8888, 8081, 1080, 1081, 9050):
            p = None
            if port in (1080, 1081, 9050):
                p = await test_socks5(ip, port)
            if not p:
                p = await test_http_proxy(ip, port)
            if p:
                res.update(p); res["kind"] = "proxy"
                return res
        # router / web panel
        for scheme in ("http", "https"):
            r = await read_http(ip, port, scheme=scheme)
            if not r: continue
            status, head, body = r
            blob = body[:8000]
            title = ""
            tm = re.search(r"<title[^>]*>(.*?)</title>", blob, re.I | re.S)
            if tm: title = re.sub(r"\s+", " ", tm.group(1))[:90]
            if any(p_.search(title) for p_ in NOT_ROUTER):
                res.update({"kind": "not-router", "status": status, "title": title}); return res
            fp = None
            for name, pats in COMPILED:
                if any(pa.search(blob) or pa.search(title) for pa in pats):
                    fp = name; break
            if fp:
                res.update({"kind": "router", "fp": fp, "status": status, "title": title,
                            "scheme": scheme, "snippet": blob[:600]})
            else:
                res.update({"kind": "web", "status": status, "title": title, "scheme": scheme})
            return res
        return None


async def probe_all(found, mode, conc=800):
    sem = asyncio.Semaphore(conc)
    tasks = [asyncio.create_task(probe_one(ip, port, sem, mode)) for ip, port in found]
    out = []
    for k, t in enumerate(asyncio.as_completed(tasks), 1):
        try: r = await t
        except Exception: r = None
        if r: out.append(r)
        if k % 2000 == 0:
            c = Counter(x.get("kind") for x in out)
            print(f"  probed {k}/{len(tasks)} :: {dict(c)}", flush=True)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ranges", required=True)
    ap.add_argument("--shard", default="0/1")
    ap.add_argument("--rate", type=int, default=20000)
    ap.add_argument("--mode", default="proxy", choices=["proxy", "router", "both"])
    ap.add_argument("--out", default="out")
    ap.add_argument("--iface", default="")
    ap.add_argument("--limit-ranges", type=int, default=0)
    args = ap.parse_args()

    i, n = (int(x) for x in args.shard.split("/"))
    os.makedirs(args.out, exist_ok=True)
    ranges = shard_ranges(args.ranges, i, n)
    if args.limit_ranges: ranges = ranges[:args.limit_ranges]
    ips = sum(ipaddress.ip_network(r, strict=False).num_addresses for r in ranges)
    ports = {"proxy": PORTS_PROXY, "router": PORTS_ROUTER,
             "both": "3128,1080,8118,8080,8000,8888,1081,9050,8081,80,8443,81"}[args.mode]
    print(f"[*] shard {i}/{n}: {len(ranges)} ranges, {ips:,} IPs, ports {ports}", flush=True)

    t0 = time.time()
    found = run_masscan(ranges, ports, args.rate, f"{args.out}/masscan-{i}.txt", args.iface)
    if found is None:
        print("[!] masscan failed"); sys.exit(2)
    print(f"[*] masscan: {len(found):,} open ports in {time.time()-t0:.0f}s", flush=True)

    if not found:
        json.dump([], open(f"{args.out}/results-{i}.json", "w")); return

    results = asyncio.run(probe_all(found, args.mode))
    proxies = [r for r in results if r.get("kind") == "proxy"]
    routers = [r for r in results if r.get("kind") == "router"]
    json.dump(results, open(f"{args.out}/results-{i}.json", "w"), indent=1)
    json.dump(proxies, open(f"{args.out}/proxies-{i}.json", "w"), indent=1)
    json.dump(routers, open(f"{args.out}/routers-{i}.json", "w"), indent=1)

    print(f"\n=== shard {i} done in {time.time()-t0:.0f}s ===")
    print("  kinds:", dict(Counter(r.get("kind") for r in results)))
    print(f"  OPEN PROXIES: {len(proxies)}   ROUTER PANELS: {len(routers)}")
    for p in proxies[:15]:
        print(f"   PROXY {p['ip']}:{p['port']} via={p['via']} exit={p['exit_ip']} transparent={p['transparent']}")
    for r in routers[:15]:
        print(f"   ROUTER {r['ip']}:{r['port']} {r['fp']} [{r.get('title','')[:45]}]")


if __name__ == "__main__":
    main()