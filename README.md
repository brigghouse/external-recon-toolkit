# External Recon Toolkit

**Brighouse Security Labs — Passive External Security Review Toolkit**

A suite of three focused, non-intrusive Python tools for auditing the external security posture of domains and websites. Designed for authorised security assessments of businesses, SaaS products, and web properties.

---

## Responsible Use Notice

> This toolkit is intended for **authorised security reviews only**.  
> Do not use it against systems you do not own or do not have explicit written permission to assess.

This toolkit performs passive reconnaissance and lightweight HTTP checks only. It does not exploit vulnerabilities, brute-force paths or credentials, or conduct port scanning. All HTTP requests identify themselves with the `BrighouseSec-External-Recon/1.0` User-Agent header.

See [`docs/responsible-use.md`](docs/responsible-use.md) for the full responsible use policy.

---

## What This Toolkit Does

| Tool | Purpose |
|------|---------|
| `bsl_domain_doctor.py` | DNS and email security hygiene auditor (SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI, CAA) |
| `bsl_web_surface_auditor.py` | Web surface security checker (security headers, TLS, cookies, security.txt, disclosure files) |
| `bsl_passive_asset_mapper.py` | Passive external asset mapper (Certificate Transparency, DNS, sitemap, robots.txt) |

Each tool produces a risk score, a plain-English label, and optional Markdown, JSON, and CSV report exports.

---

## What This Toolkit Does Not Do

- Port scanning  
- Directory or path brute-forcing  
- Credential or authentication testing  
- Subdomain brute-forcing with wordlists  
- Vulnerability exploitation  
- Payload injection or fuzzing  
- Aggressive or concurrent scanning  
- Any active intrusion technique  

---

## Installation

**Requirements:** Python 3.11 or later.

```bash
# 1. Clone the repository
git clone https://github.com/brighousesecurity/external-recon-toolkit.git
cd external-recon-toolkit

# 2. Create and activate a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate       # macOS / Linux
.venv\Scripts\activate          # Windows

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Tool 1 — Domain Doctor

Audits DNS records and email authentication configuration for a domain.

```bash
# Basic audit (terminal output)
python tools/bsl_domain_doctor.py example.com

# Export Markdown and JSON reports
python tools/bsl_domain_doctor.py example.com --markdown --json

# Specify a custom output path
python tools/bsl_domain_doctor.py example.com --output reports/example_com

# Quiet mode (JSON one-liner to stdout — useful for scripting)
python tools/bsl_domain_doctor.py example.com --quiet
```

**Checks performed:**
- A, AAAA, MX, NS, TXT, CAA records
- SPF record presence and policy strength (+all / ~all / -all / missing)
- DMARC policy (none / quarantine / reject)
- DKIM selectors — passive DNS probe across 17 common and provider-specific selectors (including IONOS, Google, Microsoft, Zoho, Proton Mail)
- MTA-STS (TXT record and policy file reachability)
- TLS-RPT record
- BIMI record
- MX provider identification

**Output — Trust Posture labels:**

| Label | Meaning |
|-------|---------|
| Strong | Low risk — strong controls in place |
| Reasonable | Minor gaps — low priority remediation |
| Needs Attention | Material issues — remediation recommended |
| Weak | Significant gaps — prompt action required |

---

### Tool 2 — Web Surface Auditor

Checks the security hygiene of a website's public HTTP/S surface.

```bash
# Basic audit
python tools/bsl_web_surface_auditor.py https://example.com

# Export reports
python tools/bsl_web_surface_auditor.py https://example.com --markdown --json

# Custom output path
python tools/bsl_web_surface_auditor.py https://example.com --output reports/example_web

# Quiet mode
python tools/bsl_web_surface_auditor.py https://example.com --quiet
```

**Checks performed:**
- HTTPS availability and HTTP→HTTPS redirect enforcement
- TLS certificate: issuer, subject, expiry, days remaining
- Security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, CORP, COOP, COEP
- Server and X-Powered-By header disclosure
- Cookie flags: Secure, HttpOnly, SameSite
- robots.txt, sitemap.xml availability
- security.txt (RFC 9116)
- Technology hints from response headers (Cloudflare, Vercel, nginx, WordPress, and others)

**Output — Launch Readiness verdicts:**

| Verdict | Meaning |
|---------|---------|
| Launch Ready | Strong posture — no critical gaps |
| Minor Issues | Low-severity gaps — can launch with notes |
| Needs Fixes Before Launch | Material issues — address before go-live |
| Not Ready to Launch | Significant gaps — remediation required |

---

### Tool 3 — Passive Asset Mapper

Discovers and enumerates the external asset footprint of a root domain using passive sources only.

```bash
# Basic discovery
python tools/bsl_passive_asset_mapper.py example.com

# Export reports (Markdown, JSON, CSV)
python tools/bsl_passive_asset_mapper.py example.com --markdown --json --csv

# Add extra hosts from a file
python tools/bsl_passive_asset_mapper.py example.com --input-file extra_hosts.txt

# Custom output path
python tools/bsl_passive_asset_mapper.py example.com --output reports/example_assets

# Quiet mode
python tools/bsl_passive_asset_mapper.py example.com --quiet
```

**Discovery sources:**
- Subdomains from Certificate Transparency logs (crt.sh)
- Hostnames from DNS MX and NS records
- URLs from sitemap.xml
- URL hints in robots.txt
- User-provided hosts via `--input-file`

**Per-host checks:**
- DNS resolution (A / AAAA)
- HTTPS and HTTP availability
- HTTP status code and redirect target
- Page title
- Platform hints from response headers
- Semantic flags: staging, dev, test, admin, old, backup, dead DNS, parked page

**Output — External Debris Score:**

| Category | Meaning |
|----------|---------|
| Clean | Asset footprint is well-managed |
| Manageable | Some loose assets — low priority review |
| Needs Review | Material loose assets — review recommended |
| Significant Exposure | Substantial unmanaged footprint |

---

## Example Reports

See the [`examples/`](examples/) directory for sample outputs:

- [`examples/brighousesec_domain_doctor_example.md`](examples/brighousesec_domain_doctor_example.md)
- [`examples/brighousesec_web_surface_example.md`](examples/brighousesec_web_surface_example.md)
- [`examples/brighousesec_asset_map_example.md`](examples/brighousesec_asset_map_example.md)

---

## Scoring Model

Each tool calculates a risk score (0–100, higher = more risk) by summing weighted severity findings:

| Severity | Weight |
|----------|--------|
| High | 25 points |
| Medium | 12 points |
| Low | 5 points |
| Info | 0 points |

Scores are capped at 100. The score maps to a plain-English label specific to each tool (Trust Posture, Launch Readiness, or External Debris Score).

See [`docs/scoring-model.md`](docs/scoring-model.md) for full details.

---

## Methodology

The toolkit follows a passive, non-intrusive methodology aligned with common external security review practice. All checks are performed using publicly available data sources: DNS records, HTTP response headers, and Certificate Transparency logs.

See [`docs/methodology.md`](docs/methodology.md) for a full description of the assessment approach.

---

## About Brighouse Security Labs

Brighouse Security Labs is a boutique security consultancy focused on external security assessments, web application reviews, and practical remediation guidance for businesses, SaaS products, and web agencies.

We believe security should be clearly communicated and actionable — accessible to clients without a dedicated security team, and rigorous enough to stand behind in a professional context.

**Website:** https://brighouse.security *(placeholder)*  
**Contact:** hello@brighouse.security *(placeholder)*

---

## CV / Portfolio Note

This toolkit was developed as a working demonstration of applied external security review methodology. It covers DNS and email security analysis, passive web surface assessment, and asset discovery using Certificate Transparency — areas directly relevant to external reconnaissance and security hygiene work.

The codebase is intentionally documented and structured to reflect professional practice: responsible use policy, scoring rationale, methodology documentation, and example outputs are all included.

---

## Licence

MIT — see [LICENSE](LICENSE) for full terms.

This software is provided for authorised security review use only. The authors accept no liability for misuse.
