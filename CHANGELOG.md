# HackBot Changelog

## v3.0.0 (2026) — Alexander Thiele
Complete modernization of HackBot 2.15.
GitHub: https://github.com/Thielander/hackbot2

### Security fixes
- Added `use strict; use warnings;` — all variables now lexically scoped
- All `open()` calls converted to 3-argument form (prevents injection)
- DNS scan: uses list-form `open('-|', ...)` instead of backtick — no shell injection
- X11 scan: wrapped `sysread` in `alarm()` — **fixes known hang bug from v2.x**
- Input validation hardened throughout
- Host input sanitized: strips `https://`, trailing slashes, path components

### New scan modules
- `-H` HTTPS/TLS: version, cipher, certificate CN, expiry, SANs, issuer, self-signed detection
- `-e` Email security: SPF strength, DMARC policy, DKIM selector scan (16 selectors), MTA-STS
- `-g` Geolocation via ip-api.com (country, city, ISP, AS)
- `-n` OS detection: SSH/FTP/HTTP banners, ping TTL, port inference, Nmap (with/without root)
- `-p` Port scan (27 ports: standard services + 3000, 5173, 8000, 8080, 8888, 18789)
- `-b` Subdomain scanner: crt.sh CT logs + DNS brute-force (158 names) + AXFR; wildcard DNS filter
- `-w s` Security headers + cookie flags (Secure/HttpOnly/SameSite) + CORS policy check
- `-w d` Disclosure scan: ~150 paths — .env, git, Docker, Kubernetes, backups, admin panels, API docs
- DNSBL expanded: SpamCop + Spamhaus ZEN + Barracuda + SORBS + Blocklist.de
- HTTP: detects HTTP→HTTP redirect (no HTTPS), automatic HTTPS fallback in all web checks
- HTTP: flags dangerous OPTIONS methods, PHP/version header exposure
- HTTP: Apache/nginx version advisories (EOL detection)

### fingerprint.db
- Deduplicated: 55 → 46 entries
- Merged 4 duplicate fingerprint groups (combined descriptions)
- Fixed typo: `OvenVMS 7.1` → `OpenVMS 7.1`

### Whois
- Replaced hardcoded IP range lists with IANA referral lookup (`whois.iana.org`)
- Correctly resolves RIPE/ARIN/APNIC/LACNIC for any public IP

### Code improvements
- Replaced `Getopt::Std` with `Getopt::Long` (long options, better validation)
- Whois refactored into `_whois_query` + `_print_whois_fields` helpers
- Range handling rewritten with `ip_to_long` / `long_to_ip`
- Removed obsolete checks: Nimda worm, IIS IDA/Unicode/PROPFIND/ISAPI (2001-era)
- Consistent `alarm()` timeouts on all blocking reads
- Chunked Transfer-Encoding decoder for correct body parsing
- SNI support in all SSL connections (fixes Cloudflare and multi-domain hosts)
- `_ssl_read` loop for complete SSL response reads
- `_fetch_page` helper: HTTPS-first with automatic HTTP fallback
- `--json` output report
- `--color` / `--no-color` terminal output control
- `-T <secs>` configurable connection timeout
- `--help` long-form option

### Repository
- `Makefile`: `install` / `uninstall` / `check` targets
- `install.sh` one-shot installer with dependency check
- `disclosure.db` new database
- `.gitignore`

---

## v2.15 (2002) — Marco van Berkum et al.
See original CHANGES file for full history.

Key additions in 2.x series: loglevel system, CIDR support, proxy support,
whois (RIPE/ARIN/APNIC), spamcop check, identd full scan, telnet fingerprinting,
CGI scanner, X11 check, range scanning, output file option.

Original authors:
- Marco van Berkum
- Kristian Vlaardingerbroek
- Pepijn Vissers
- Herman Poortermans
