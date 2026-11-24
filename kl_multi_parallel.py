#!/usr/bin/env python3
"""KL-MultiParallel — standalone tool by Kontenlaris.Studio
Scan BANYAK IP secara PARALEL (port + banner, read-only) dan query BANYAK DNS
resolver secara PARALEL (banding jawaban antar resolver = cek propagasi DNS).
Stdlib only. Detection only, no exploitation. Targets must be your own (--yes).
"""
import argparse, base64, concurrent.futures as cf, datetime, json, socket, struct, sys, time, urllib.request
VERSION = "5.5.0"
KIND_PORTS = {"web": "80,443,8080,8443", "mail": "25,110,143,465,587,993,995",
              "iot": "1883,8883,5683,502,102", "game": "25565,27015,7777,19132"}
PRESETS = {"cepat": {"workers": 100, "timeout": 1.5}, "dalam": {"workers": 30, "timeout": 5},
           "senyap": {"workers": 5, "timeout": 4}}
TIMEOUT = {"v": 3.0}

RESOLVERS = {"Google": "8.8.8.8", "Cloudflare": "1.1.1.1", "Quad9": "9.9.9.9",
             "OpenDNS": "208.67.222.222", "AdGuard": "94.140.14.14"}
QTYPES = {"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "TXT": 16, "CNAME": 5, "SOA": 6}

def build_query(name, qtype):
    tid = 0x4B4C
    hdr = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.rstrip(".").split(".")) + b"\x00"
    return hdr + qname + struct.pack(">HH", qtype, 1)

def parse_name(data, off):
    labels, jumped, end = [], False, off
    while True:
        ln = data[off]
        if ln == 0:
            if not jumped: end = off + 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", data[off:off+2])[0] & 0x3FFF
            if not jumped: end = off + 2
            off, jumped = ptr, True
            continue
        labels.append(data[off+1:off+1+ln].decode(errors="replace")); off += 1 + ln
    return ".".join(labels), end

def parse_answers(data):
    qd, an = struct.unpack(">HH", data[4:8])
    off = 12
    for _ in range(qd):
        _, off = parse_name(data, off); off += 4
    out = []
    for _ in range(an):
        _, off = parse_name(data, off)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[off:off+10]); off += 10
        rd = data[off:off+rdlen]
        if rtype == 1 and rdlen == 4: out.append(socket.inet_ntoa(rd))
        elif rtype == 28 and rdlen == 16: out.append(socket.inet_ntop(socket.AF_INET6, rd))
        elif rtype in (2, 5): out.append(parse_name(data, off)[0])
        elif rtype == 15: out.append(f"{struct.unpack('>H', rd[:2])[0]} {parse_name(data, off+2)[0]}")
        elif rtype == 16: out.append(b"".join(rd[i+1:i+1+rd[i]] for i in range(0, rdlen, rd[i]+1) if i < rdlen).decode(errors="replace"))
        else: out.append(rd.hex()[:40])
        off += rdlen
    return sorted(out)

def dns_one(args):
    name, rname, rip, qt = args
    rport = 53
    if ":" in rip: rip, rport = rip.rsplit(":", 1); rport = int(rport)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4)
        s.sendto(build_query(name, QTYPES[qt]), (rip, rport))
        data, _ = s.recvfrom(4096); s.close()
        return (rname, qt, parse_answers(data))
    except Exception as e:
        return (rname, qt, [f"ERR:{type(e).__name__}"])

def scan_one(args):
    host, port = args
    t0 = time.time()
    try:
        s = socket.create_connection((host, port), timeout=TIMEOUT["v"])
        s.settimeout(1.5); banner = ""
        try: banner = s.recv(80).decode(errors="replace").strip()
        except Exception: pass  # audit:allow — banner kosong/timeout memang normal untuk port terbuka tanpa banner; me-log tiap port = spam
        s.close()
        return (host, port, "OPEN", banner, round((time.time()-t0)*1000))
    except Exception:
        return (host, port, "closed", "", round((time.time()-t0)*1000))

def main():
    ap = argparse.ArgumentParser(description="Multi-parallel IP scanner + multi-DNS comparator — KL-Exploit-Lab by Kontenlaris.Studio")
    ap.add_argument("--targets", help="IP/host dipisah koma, mis. 127.0.0.1,192.168.1.1")
    ap.add_argument("--file", help="file berisi 1 target per baris")
    ap.add_argument("--ports", default="22,80,443,3306,6379,8080", help="port dipisah koma")
    ap.add_argument("--domain", help="domain untuk multi-DNS (mis. example.com)")
    ap.add_argument("--resolvers", help="resolver kustom Nama=ip[:port] dipisah koma (menimpa bawaan)")
    ap.add_argument("--records", default="A,AAAA,MX,NS,TXT", help="record DNS dipisah koma")
    ap.add_argument("--workers", type=int, default=50, help="thread paralel (maks 200)")
    ap.add_argument("--json", help="simpan laporan ke file JSON")
    ap.add_argument("--yes", action="store_true", help="konfirmasi: target milik saya / lab saya")
    ap.add_argument("--kind", choices=list(KIND_PORTS), help="v5.5 default pintar: jenis target menentukan port bawaan")
    ap.add_argument("--preset", choices=list(PRESETS), help="v5.5 preset: cepat/dalam/senyap")
    ap.add_argument("--merge", help="v5.5 gabung+dedup dengan laporan JSON lama")
    ap.add_argument("--template", choices=["client", "personal", "github"], help="v5.5 templat laporan Markdown")
    ap.add_argument("--report", help="nama file laporan Markdown (pakai --template)")
    ap.add_argument("--qr-share", action="store_true", help="v5.5 hasilkan kode bagikan + URL gambar QR untuk ringkasan")
    ap.add_argument("--plain", action="store_true", help="v5.5 mode aksesibilitas: teks polos ramah pembaca layar")
    ap.add_argument("--no-selfcheck", action="store_true", help="lewati cek-diri awal v5.5")
    a = ap.parse_args()
    print(f"KL-MultiParallel v{VERSION} — by Kontenlaris.Studio")
    if a.preset:
        TIMEOUT["v"] = PRESETS[a.preset]["timeout"]
        if not a.workers or a.workers == 50: a.workers = PRESETS[a.preset]["workers"]
        print(f"[PRESET] {a.preset}: workers={a.workers} timeout={TIMEOUT['v']}s")
    if a.kind and not any(x in sys.argv for x in ("--ports",)):
        a.ports = KIND_PORTS[a.kind]; print(f"[KIND] {a.kind}: port bawaan {a.ports}")
    if not a.no_selfcheck:
        print("[SELF-CHECK] versi", VERSION)
        try:
            socket.getaddrinfo("example.com", 443); print("[SELF-CHECK] DNS sistem: OK")
        except Exception: print("[SELF-CHECK] DNS sistem: GAGAL (cek koneksi)")
        try:
            r = urllib.request.urlopen("http://example.com", timeout=5)
            srv = r.headers.get("Date")
            print("[SELF-CHECK] jam server contoh:", srv or "?")
        except Exception: print("[SELF-CHECK] HTTP contoh: tidak terjangkau (scan lokal tetap jalan)")
    if not a.yes:
        print("[STOP] Wajib --yes: konfirmasi semua target milik Anda / lab Anda."); return 2
    targets = []
    if a.targets: targets += [t.strip() for t in a.targets.split(",") if t.strip()]
    if a.file: targets += [l.strip() for l in open(a.file) if l.strip() and not l.startswith("#")]
    ports = [int(p) for p in a.ports.split(",") if p.strip()]
    workers = min(max(a.workers, 1), 200)
    report = {"scan": [], "dns": {}}
    if targets:
        jobs = [(h, p) for h in targets for p in ports]
        print(f"[SCAN] {len(targets)} target x {len(ports)} port = {len(jobs)} cek, {workers} thread paralel...")
        t0 = time.time()
        done = 0; tstart = time.time()
        with cf.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(scan_one, j) for j in jobs]
            for fu in cf.as_completed(futs):
                host, port, st, banner, ms = fu.result(); done += 1
                if st == "OPEN":
                    print(f"[FOUND] {host}:{port} OPEN {ms}ms {banner[:50]}")
                    report["scan"].append({"host": host, "port": port, "banner": banner})
                if done % 10 == 0 or done == len(jobs):
                    el = time.time() - tstart; eta = el / done * (len(jobs) - done) if done else 0
                    bar = "#" * int(30 * done / len(jobs))
                    print(f"[PROGRES] [{bar:<30}] {done}/{len(jobs)} ({100*done//len(jobs)}%) ETA {eta:.0f}s")
        print(f"[SCAN] selesai {time.time()-t0:.1f}s — {len(report['scan'])} port terbuka")
    if a.domain:
        recs = [r.strip().upper() for r in a.records.split(",") if r.strip().upper() in QTYPES]
        resolvers = RESOLVERS
        if a.resolvers:
            resolvers = dict(kv.split("=", 1) for kv in a.resolvers.split(",") if "=" in kv)
        jobs = [(a.domain, rn, rip, qt) for rn, rip in resolvers.items() for qt in recs]
        print(f"[DNS] {a.domain}: {len(resolvers)} resolver x {len(recs)} record = {len(jobs)} query paralel...")
        with cf.ThreadPoolExecutor(max_workers=workers) as ex:
            results = list(ex.map(dns_one, jobs))
        for qt in recs:
            per = {rn: ans for rn, q, ans in results if q == qt}
            report["dns"][qt] = per
            uniq = {tuple(v) for v in per.values()}
            flag = "[OK] semua resolver sama (propagasi kompak)" if len(uniq) == 1 else "[FOUND] jawaban resolver BERBEDA (propagasi belum kompak / split DNS)"
            print(f"  {qt}: {flag}")
            for rn, ans in per.items(): print(f"    {rn:11} -> {', '.join(ans) if ans else '(kosong)'}")
    if a.merge:
        try:
            old = json.load(open(a.merge))
            seen = {(x["host"], x["port"]) for x in report["scan"]}
            for x in old.get("scan", []):
                if (x["host"], x["port"]) not in seen: report["scan"].append(x); seen.add((x["host"], x["port"]))
            for k, v in old.get("dns", {}).items(): report["dns"].setdefault(k, v)
            print(f"[MERGE] digabung+dedup dgn {a.merge}: total {len(report['scan'])} temuan unik")
        except Exception as e: print(f"[MERGE] gagal: {e}")
    if a.json:
        json.dump(report, open(a.json, "w"), indent=1); print(f"[OK] laporan JSON: {a.json}")
    if a.report:
        tpl = a.template or "personal"
        head = {"client": "# Security Audit Report\nPrepared by Kontenlaris.Studio (KL-MultiParallel)", "personal": "# Catatan Scan Pribadi — KL-MultiParallel by Kontenlaris.Studio", "github": "## Scan Report (KL-MultiParallel)\n"}[tpl]
        lines = [head, "", f"Open findings: {len(report['scan'])}"] + [f"- {x['host']}:{x['port']} {x['banner'][:40]}" for x in report["scan"]] + [f"- DNS {k}: {len(v)} resolver" for k, v in report["dns"].items()]
        open(a.report, "w").write("\n".join(lines) + "\n"); print(f"[OK] laporan {tpl}: {a.report}")
    if a.qr_share:
        payload = base64.urlsafe_b64encode(json.dumps(report).encode()).decode()
        code = "KLMP55:" + payload[:120]
        import urllib.parse
        url = "https://api.qrserver.com/v1/create-qr-code/?size=240x240&data=" + urllib.parse.quote(code)
        print("[QR-SHARE] kode bagikan (tempel di Termux lain / buka URL QR):"); print(code); print(url)
    return 0

if __name__ == "__main__":
    sys.exit(main())
