#!/usr/bin/env python3
"""KL-MultiParallel — KL-Exploit-Lab by Kontenlaris.Studio
Scan BANYAK IP secara PARALEL (port + banner, read-only) dan query BANYAK DNS
resolver secara PARALEL (banding jawaban antar resolver = cek propagasi DNS).
Stdlib only. Detection only, no exploitation. Targets must be your own (--yes).
"""
import argparse, concurrent.futures as cf, json, socket, struct, sys, time

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
        s = socket.create_connection((host, port), timeout=3)
        s.settimeout(1.5); banner = ""
        try: banner = s.recv(80).decode(errors="replace").strip()
        except Exception: pass
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
    a = ap.parse_args()
    print("KL-MultiParallel — KL-Exploit-Lab by Kontenlaris.Studio")
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
        with cf.ThreadPoolExecutor(max_workers=workers) as ex:
            for host, port, st, banner, ms in ex.map(scan_one, jobs):
                if st == "OPEN":
                    print(f"[FOUND] {host}:{port} OPEN {ms}ms {banner[:50]}")
                    report["scan"].append({"host": host, "port": port, "banner": banner})
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
    if a.json:
        json.dump(report, open(a.json, "w"), indent=1); print(f"[OK] laporan JSON: {a.json}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
