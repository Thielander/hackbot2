# HackBot2

A modernized network security scanner, based on the classic HackBot by Marco van Berkum (2000–2002).

> **For authorized security testing only.** Only scan systems you own or have explicit written permission to test.

## What it does

| Flag | Scan |
|------|------|
| `-s` | SSH banner & version |
| `-f` | FTP anonymous login + writeable directory |
| `-m` | SMTP open relay / VRFY / EXPN |
| `-d` | DNS BIND version |
| `-H` | HTTPS/TLS version, cipher suite, certificate details, expiry |
| `-e` | Email security: SPF / DKIM / DMARC / MTA-STS |
| `-p` | Port scan (27 common ports) |
| `-g` | Geolocation (country, city, ISP, AS) |
| `-n` | OS detection (HTTP headers, SSH/FTP banners, Nmap, TTL) |
| `-b` | Subdomain scan (crt.sh CT logs + brute-force + AXFR) |
| `-S` | DNSBL spam check (5 blacklists) |
| `-r` | Whois (RIPE / ARIN / APNIC via IANA referral) |
| `-i` | Identd scan |
| `-t` | Telnet OS fingerprint |
| `-X` | X11 open access check |
| `-w a` | Full web scan: version + CGI + security headers + cookies + CORS + disclosure |
| `-w s` | Security headers + cookie flags + CORS policy |
| `-w c` | CGI vulnerability scan (326 entries) |
| `-w d` | Disclosure scan: robots.txt, .env, config files, admin panels, backups, ... |
| `-A` | All scans |

## Requirements

- Perl 5.10+
- Core modules (ship with Perl): `IO::Socket::INET`, `Getopt::Long`, `JSON::PP`, `Term::ANSIColor`, `FindBin`
- Optional for HTTPS/TLS scanning: `IO::Socket::SSL`

```bash
# Debian / Ubuntu / Raspberry Pi OS
sudo apt install libio-socket-ssl-perl

# or via CPAN
sudo cpan IO::Socket::SSL
```

- Optional for full OS fingerprinting: `nmap` (without root: `-sV` banner scan; with root: `-O` TCP/IP stack)

```bash
sudo apt install nmap
```

## Installation

```bash
git clone https://github.com/Thielander/hackbot2.git
cd hackbot2
sudo make install
```

Or without make:
```bash
sudo bash install.sh
```

Installs `hackbot2` to `/usr/local/bin/` and the databases to `/usr/local/etc/hackbot2/`.

## Usage

```bash
# Full scan
hackbot2 -A example.com

# Web + TLS + email security
hackbot2 -w a -H -e example.com

# Subdomain discovery
hackbot2 -b example.com

# Port scan + geolocation + OS detection + JSON output
hackbot2 -p -g -n -j example.com

# Scan a /24 range
hackbot2 -s -f -p 192.168.1.0/24

# Read targets from file, verbose output
hackbot2 -A -l v -F targets.txt

# Slow CGI scan (1s delay, less conspicuous)
hackbot2 -w c -z 1 example.com

# Accepts URLs with path or protocol prefix
hackbot2 -A https://example.com/some/path
```

## Output

Results are written to `output.<host>` by default. Use `-O <file>` to specify a path.

Add `-j` to also generate `output.<host>.json`.

Log levels: `-l c` critical (default) · `-l v` verbose · `-l d` debug

## Check your setup

```bash
make check
```

## Databases

| File | Entries | Purpose |
|------|---------|---------|
| `cgi.db` | 326 | CGI vulnerability paths (`-w c`) |
| `fingerprint.db` | 46 | Telnet OS fingerprints (`-t`) |
| `disclosure.db` | ~150 | Common sensitive files and paths (`-w d`) |

Custom database paths via environment variables:
```bash
HACKBOT_DB=/path/to/cgi.db HACKBOT_FPDB=/path/to/fingerprint.db hackbot2 -A example.com
```

## Credits

Originally written by *(addresses are from 2000–2002 and likely no longer active)*:

- **Marco van Berkum** — m.v.berkum@obit.nl
- **Kristian Vlaardingerbroek** — kris@obit.nl
- **Pepijn Vissers** — zoef@zoefdehaas.nl
- **Herman Poortermans** — herman@ofzo.nl

Modified and extended by **Alexander Thiele**, 2026.  
GitHub: https://github.com/Thielander/hackbot2

## License

GNU Lesser General Public License v2.1 — see [LICENSE](LICENSE).
