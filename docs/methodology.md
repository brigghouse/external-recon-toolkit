# Assessment Methodology

**Brighouse Security Labs — External Recon Toolkit**

---

## Philosophy

This toolkit follows a **passive-first, evidence-based** approach. Every check is designed to:

1. Retrieve only what is publicly accessible without authentication
2. Use a single, identifiable User-Agent (`BrighouseSec-External-Recon/1.0`)
3. Avoid any behaviour that could be interpreted as intrusive or aggressive
4. Attach evidence to every finding so clients can verify results independently

---

## Domain Doctor Methodology

### DNS Record Collection

All DNS queries are performed using the system's configured resolver via `dnspython`. Queries are made for:

- `A` — IPv4 address records
- `AAAA` — IPv6 address records
- `MX` — Mail exchange records
- `NS` — Nameserver records
- `TXT` — Text records (SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI all live here or in subdomain TXT records)
- `CAA` — Certification Authority Authorisation

### SPF Analysis

The tool looks for TXT records beginning with `v=spf1`. It then inspects the final mechanism:

| Mechanism | Assessment | Severity |
|-----------|-----------|----------|
| `-all` | Hardfail — strong enforcement | Info |
| `~all` | Softfail — partial enforcement | Low |
| `?all` | Neutral — no enforcement | Medium |
| `+all` | Pass all — dangerously permissive | High |
| Missing | No SPF record | High |
| Multiple | Only one SPF record is valid | Medium |

### DMARC Analysis

The tool queries `_dmarc.<domain>` for a TXT record beginning `v=DMARC1`. It inspects the `p=` tag:

| Policy | Assessment | Severity |
|--------|-----------|----------|
| `p=reject` | Full enforcement | Info |
| `p=quarantine` | Partial enforcement | Low |
| `p=none` | Monitoring only | Medium |
| Missing | No DMARC record | High |

### DKIM Passive Check

The tool queries `<selector>._domainkey.<domain>` for each of 9 common selector names. This is a purely passive DNS lookup — no keys are validated, no email is sent. Selectors checked: `default`, `google`, `selector1`, `selector2`, `s1`, `s2`, `k1`, `smtp`, `mail`.

### MTA-STS

Two checks are performed:
1. TXT record at `_mta-sts.<domain>` — checked for `v=STSv1`
2. Policy file at `https://mta-sts.<domain>/.well-known/mta-sts.txt` — checked for HTTP 200 response

### Risk Scoring

Risk is scored additively:

| Severity | Points |
|----------|--------|
| High | 25 |
| Medium | 12 |
| Low | 5 |
| Info | 0 |

Total is capped at 100. Trust Posture thresholds: Strong (≤15), Reasonable (≤35), Needs Attention (≤60), Weak (>60).

---

## Web Surface Auditor Methodology

### Requests Made

The tool makes the minimum set of requests necessary:

1. `GET <target URL>` — primary HTTPS request
2. `GET http://<host>` with redirect disabled — redirect check
3. `GET /robots.txt`
4. `GET /sitemap.xml`
5. `GET /.well-known/security.txt`
6. `GET /security.txt`

No other paths are requested.

### TLS Certificate

The TLS certificate is retrieved using Python's `ssl` standard library by opening a raw socket connection to port 443 and calling `getpeercert()`. Only metadata is captured (subject, issuer, expiry). No cryptographic validation beyond the standard handshake is performed.

### Security Headers

Each recommended security header is checked for presence in the response. Where present, the value is recorded. Missing headers are flagged at Medium severity (HSTS, X-Content-Type-Options, X-Frame-Options) or Low severity (all others).

### Cookie Flags

The tool inspects `Set-Cookie` response headers for the `Secure`, `HttpOnly`, and `SameSite` flags. Cookies missing `Secure` are flagged Medium; those missing `HttpOnly` or `SameSite` only are flagged Low.

### Risky Path Hints

Path keywords (admin, staging, dev, test, backup, debug, old, private) are flagged only if they appear in the content of robots.txt, sitemap.xml, or the page's link tags. No paths are actively requested based on these keywords.

### Launch Readiness Thresholds

| Score | Label |
|-------|-------|
| ≤10 | Ready |
| ≤30 | Minor Issues |
| ≤55 | Needs Fixes Before Launch |
| >55 | High Risk Exposure |

---

## Passive Asset Mapper Methodology

### Discovery Approach

| Source | Method |
|--------|--------|
| Certificate Transparency | HTTP GET to `crt.sh/?q=%.domain&output=json` |
| DNS records | MX and NS record lookup for root domain |
| sitemap.xml | HTTP GET to `https://domain/sitemap.xml`, URL extraction |
| robots.txt | HTTP GET to `https://domain/robots.txt`, URL extraction |
| User-provided | Hosts read from `--input-file` |

All discovered hostnames are filtered to the target registered domain to avoid accidental enumeration of third-party infrastructure.

### Per-Host Probing

For each discovered host:
1. DNS A and AAAA lookups
2. HTTPS GET request (single request, follows redirects)
3. Fallback HTTP GET if HTTPS is unreachable

Requests are rate-limited with a 0.4-second delay between hosts. No concurrent requests are made.

### External Debris Score

The score reflects surface complexity, not risk per se. Factors:

- Total asset count (max 30 points)
- Dead DNS entries (5 points each)
- Sensitive-looking subdomains (+8 each)
- Parked pages (+3 each)

Capped at 100. Labels: Clean (≤15), Manageable (≤40), Messy (≤65), High Debris (>65).

---

_Brighouse Security Labs — External Recon Toolkit_
