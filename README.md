# KL-MultiParallel — by Kontenlaris.Studio
Standalone tool (separate project, not part of KL-Exploit-Lab). Free & open source (MIT).

Scan MANY IPs in PARALLEL (ports + banners, read-only, up to 200 threads) and query MANY DNS resolvers in PARALLEL (Google 8.8.8.8, Cloudflare 1.1.1.1, Quad9 9.9.9.9, OpenDNS, AdGuard — or custom `--resolvers Name=ip[:port]`), comparing answers per record (A/AAAA/MX/NS/TXT/CNAME/SOA) to spot DNS propagation differences. JSON report supported. Pure Python stdlib, zero dependencies, Termux & Linux. Detection only; network scanning requires `--yes` (you confirm the targets are yours / your lab).

## Install & use
```bash
git clone https://github.com/kontenlaris-studio/kl-multi-parallel.git
cd kl-multi-parallel
python3 kl_multi_parallel.py --targets 192.168.1.1,192.168.1.2 --ports 22,80,443 --domain example.com --yes
python3 kl_multi_parallel.py --domain example.com --records A,MX,NS --yes
```
Bahasa Indonesia: tool mandiri untuk scan multi-IP paralel + multi-DNS paralel, gratis, khusus Termux & Linux, mode deteksi aman saja.
MIT License — Kontenlaris.Studio
