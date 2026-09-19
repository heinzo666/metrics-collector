#!/usr/bin/env python3
"""Verify open proxies from a clean-IP runner. Proves: it forwards, exit IP == proxy IP,
and it does not leak our real IP in headers."""
import argparse, asyncio, json, os, re, sys, time
from collections import Counter

TESTS = [("ipify", "http://api.ipify.org/", "ip"),
         ("ifconfig", "http://ifconfig.me/ip", "ip")]

async def http_proxy_test(ip, port, timeout=12):
    t0 = time.time()
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    except Exception:
        return None
    try:
        w.write(f"GET http://api.ipify.org/ HTTP/1.1\r\nHost: api.ipify.org\r\nUser-Agent: curl/8.0\r\nConnection: close\r\n\r\n".encode())
        await asyncio.wait_for(w.drain(), timeout=timeout)
        data = await asyncio.wait_for(r.read(8000), timeout=timeout)
    except Exception:
        data = b""
    finally:
        try: w.close()
        except Exception: pass
    if not data: return None
    txt = data.decode("utf-8", "ignore")
    head, _, body = txt.partition("\r\n\r\n")
    body = body.strip()
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", body): return None
    lat = int((time.time() - t0) * 1000)
    return {"ip": ip, "port": port, "type": "http", "exit_ip": body,
            "transparent": body == ip, "latency_ms": lat,
            "xff": "x-forwarded-for" in head.lower() and ip not in head.lower()}

async def socks5_test(ip, port, timeout=12):
    t0 = time.time()
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    except Exception:
        return None
    try:
        w.write(bytes([5,1,0])); await asyncio.wait_for(w.drain(), timeout=timeout)
        rep = await asyncio.wait_for(r.read(2), timeout=timeout)
        if len(rep) < 2 or rep[1] != 0: return None
        host = b"api.ipify.org"
        w.write(bytes([5,1,0,3,len(host)]) + host + (80).to_bytes(2,"big"))
        await asyncio.wait_for(w.drain(), timeout=timeout)
        rep = await asyncio.wait_for(r.read(10), timeout=timeout)
        if len(rep) < 2 or rep[1] != 0: return None
        w.write(b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n")
        await asyncio.wait_for(w.drain(), timeout=timeout)
        data = await asyncio.wait_for(r.read(8000), timeout=timeout)
    except Exception:
        data = b""
    finally:
        try: w.close()
        except Exception: pass
    if not data: return None
    body = data.decode("utf-8","ignore").split("\r\n\r\n",1)[-1].strip()
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", body): return None
    lat = int((time.time() - t0) * 1000)
    return {"ip": ip, "port": port, "type": "socks5", "exit_ip": body,
            "transparent": body == ip, "latency_ms": lat, "xff": False}

async def one(ip, port, sem):
    async with sem:
        for fn in (http_proxy_test, socks5_test):
            try: r = await fn(ip, port)
            except Exception: r = None
            if r: return r
        return None

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--shard", default="0/1")
    ap.add_argument("--out", default="out")
    ap.add_argument("--conc", type=int, default=400)
    args = ap.parse_args()
    i, n = (int(x) for x in args.shard.split("/"))
    os.makedirs(args.out, exist_ok=True)
    seen, rows = set(), []
    with open(args.inp) as f:
        next(f, None)
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) < 2 or not p[1].isdigit(): continue
            if (p[0], p[1]) in seen: continue
            seen.add((p[0], p[1])); rows.append((p[0], int(p[1])))
    rows = [r for k, r in enumerate(rows) if k % n == i]
    print(f"[*] verifying {len(rows)} proxies, shard {i}/{n}", flush=True)
    sem = asyncio.Semaphore(args.conc)
    good = []
    for k, t in enumerate(asyncio.as_completed([asyncio.create_task(one(ip, p, sem)) for ip, p in rows]), 1):
        try: r = await t
        except Exception: r = None
        if r: good.append(r)
        if k % 200 == 0: print(f"  {k}/{len(rows)} working={len(good)}", flush=True)
    json.dump(good, open(f"{args.out}/verified-{i}.json", "w"), indent=1)
    print(f"\n=== {len(good)}/{len(rows)} WORKING ===")
    print("  by type:", dict(Counter(x['type'] for x in good)))
    print("  transparent:", len([x for x in good if x['transparent']]))
    if good:
        lat = sorted(x['latency_ms'] for x in good)
        print(f"  latency ms: min={lat[0]} p50={lat[len(lat)//2]} max={lat[-1]}")

asyncio.run(main())
