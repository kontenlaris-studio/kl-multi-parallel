# ROADMAP — KL-MultiParallel by Kontenlaris.Studio
36+ planned updates, all parallel & detection-only (ownership confirmation `--yes` always required).

## v1.1 — Wider targets
1. CIDR ranges (192.168.1.0/24) & IPv6 targets
2. Parallel reverse DNS for every open IP
3. Import targets from CSV/JSON scan files

## v1.2 — Deeper DNS
4. DoH/DoT resolvers (works when UDP 53 is blocked)
5. DNSSEC & TTL checks across resolvers
6. Parallel subdomain mapping (built-in wordlist, own domains)
7. Split-horizon DNS detection

## v1.3 — Smarter output
8. Color HTML report + single comparison table
9. Banner service fingerprinting matched to CVE (detection only)
10. Diff mode: compare two scans, mark changes

## v2.0 — Heavy duty
11. Resume/checkpoint for very large scans
12. Adaptive speed (threads auto-tune to network response)
13. Scheduled periodic scans + change alerts
14. Export to Nmap XML & CSV

## v3.0 — Distribution class
15. Termux cluster mode: split one job across many phones, merge results
16. Local agent & API (POST /scan, GET /dns)
17. Local web dashboard (nothing uploaded)
18. Plugin system (drop-in .py modules in plugins/)
19. Saved target profiles (1-word recall)
20. Visual network map export (PNG/SVG)
21. Battery/data saver mode (charge + WiFi only)
22. Completion notifications to your own Telegram/WhatsApp
23. UI in 5 languages (ID/EN/ES/PT/AR)
24. pip package + Termux .deb release

## v4.0 — Platform class
25. Multi-city parallel probes (consenting agents), per-location comparison
26. AI result summarizer (10-line verdict, ID/EN)
27. Risk scoring 0-100 per target with reasons, no exploitation
28. Per-target history book, searchable by date
29. Signed audit evidence (SHA-256 hash + timestamp) for client pentest reports
30. KL-Exploit-Lab integration: findings suggest the right follow-up tool
31. Community plugin marketplace (1-command plugin install)
32. Headless mode via config file & schedule (servers/VPS)
33. Cross-device sync via the user's own private Git repo
34. Safe own-server load test with hard limits & auto-stop
35. Parallel traceroute route-leak detection
36. Built-in training lab & guided learning mode

## v5.0 — Ecosystem class
37. Unified multi-protocol sweep: TCP + UDP + BLE + MQTT checked in one parallel pass
38. Network digital twin: simulate fixes on a model built from scan results before touching the real network
39. Auto remediation guides: per-finding step-by-step fix instructions (guidance only, never auto-changes)
40. Post-quantum readiness: detect TLS setups lacking quantum-safe migration paths
41. Offline intelligence pack: local CVE/service database, synced on demand, scans fully offline
42. Autonomous audit planner: findings decide the next safe checks automatically (with user approval per step)
43. Voice control in Termux (Indonesian & English commands)
44. Public status page generator for your own services from periodic scans
45. Anycast & latency world map: resolver/route answers compared across regions
46. Free-testnet hash anchoring of audit evidence (optional, no real funds)
47. Team mode: shared read-only report links on local network, role-based access
48. One-command full ecosystem run: MultiParallel + all KL-Exploit-Lab tools chained into a single signed report
