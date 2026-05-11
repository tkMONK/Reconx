# ReconX v1.0

> Active & Passive Reconnaissance Tool written in Go

ReconX is a single-binary domain reconnaissance tool that aggregates DNS records, WHOIS data, subdomain enumeration, SSL/TLS analysis, email security posture, web technology fingerprinting, Geo-IP/ASN lookup, and Wayback Machine history into a structured JSON report — all in one run.

---

## Features

| Module | Type | Description |
|---|---|---|
| DNS Reconnaissance | Passive | Queries A, AAAA, NS, MX, TXT, SOA, CNAME, SRV, CAA, PTR, HINFO records |
| WHOIS Lookup | Passive | Follows IANA referrals to the authoritative registrar WHOIS server |
| Zone Transfer Check | Active | Attempts AXFR on every discovered NS record |
| Subdomain Enumeration | Passive + Active | Queries 10 sources concurrently (see below) |
| SSL/TLS Analysis | Passive | Certificate details, SANs, cipher suite, protocol version, expiry warnings |
| Email Security Recon | Passive | SPF, DMARC, DKIM (common selectors), BIMI, MX security notes |
| Web Technology Discovery | Active | HTTP headers, security header audit (score/6), technology fingerprinting, robots.txt, sitemap.xml |
| Geo-IP & ASN Lookup | Passive | Country, region, city, ISP, org, ASN via ip-api.com / ipapi.co |
| Wayback Machine URLs | Passive | Retrieves up to 200 historical URLs from the CDX API |

### Subdomain Sources

crt.sh · SecurityTrails · HackerTarget · RapidDNS · AlienVault OTX · CertSpotter · AnubisDB · C99 · Wayback URLs · BufferOver

All sources run concurrently via goroutines and results are deduplicated before export.

### Security Header Audit

ReconX grades the target on six critical headers and returns a score out of 6:

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`
- `Permissions-Policy`

---

## Installation

### Prerequisites

- Go 1.21 or later

### Build from source

```bash
git clone https://github.com/tkMONK/Reconx.git
cd Reconx
go mod init Reconx
go mod tidy
go build -o reconx main.go
```

## Usage

```
./reconx [flag]
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `-h --help`  |  | usage of ./reconx 
| `-d <domain>` | _(prompted)_ | Target domain, e.g. `example.com` |
| `-o <path>` | `recon_results/<domain>_<timestamp>.json` | Custom JSON output path |
| `-passive` | `false` | Skip active modules (zone transfer & web recon) |
| `-json-only` | `false` | Suppress all terminal output; write JSON only |
| `-version` | — | Print version and exit |

### Examples

```bash
# Interactive (prompts for domain)
./reconx

# Full scan
./reconx -d example.com

# Passive only (no active probing)
./reconx -d example.com -passive

# CI/pipeline usage — silent, structured output
./reconx -d example.com -json-only -o ./results/example.json

# Print version
./reconx -version
```

If `-d` is omitted, ReconX prompts interactively. URL schemes (`https://`, `http://`) and trailing slashes are stripped automatically. Domains are validated against a basic regex; an unusual format produces a warning but does not abort the scan.

---

## Output

ReconX writes two files to `recon_results/` (created if absent):

| File | Contents |
|---|---|
| `<domain>_<timestamp>.json` | Full structured report (all modules) |
| `<domain>_subdomains.txt` | Flat list of unique subdomains, one per line |

### JSON Schema (top-level fields)

```json
{
  "target": "example.com",
  "timestamp": "2025-08-01 12:00:00",
  "dns_records": [...],
  "whois": "...",
  "zone_transfers": [...],
  "subdomains": [...],
  "all_subdomains_unique": [...],
  "ssl_info": { ... },
  "geoip": { ... },
  "web_info": { ... },
  "email_recon": { ... },
  "wayback_urls": [...]
}
```

`zone_transfers` and `web_info` are omitted when running with `-passive`.

---

## Architecture

```
main()
 ├── runDNSRecon()         → []DNSRecord
 ├── runWHOIS()            → string
 ├── runEmailRecon()       → *EmailRecon
 ├── runSSLRecon()         → *SSLInfo
 ├── runGeoIP()            → *GeoIPInfo
 ├── runWayback()          → []string
 ├── runSubdomainEnum()    → []SubdomainSource  (10 goroutines, concurrent)
 ├── runZoneTransfers()    → []ZoneTransferResult  [active only]
 ├── runWebRecon()         → *WebInfo              [active only]
 └── exportJSON() + exportSubdomainsTxt()
```

The HTTP client is shared across all modules. It uses a 15-second timeout, skips TLS verification (intentional for misconfigured targets), caps response bodies at 5 MB, and does not blindly follow more than 5 redirects.

DNS queries use the system resolver (`/etc/resolv.conf`) with a fallback to Google (`8.8.8.8`) and Cloudflare (`1.1.1.1`) on port 53, with a 5-second per-query timeout.

---

## Ethical & Legal Notice

ReconX is intended for **authorized security assessments, bug bounty programs, and research on infrastructure you own or have explicit permission to test**.

- Zone transfer attempts (AXFR) are active probes — they send packets to nameservers.
- Web recon fetches live HTTP responses from the target.
- Always obtain written authorization before scanning third-party systems.

The `-passive` flag limits ReconX to purely passive, read-only queries against public APIs and DNS resolvers if you need a lower-impact mode.

---

## License

MIT — see `LICENSE` for details.
