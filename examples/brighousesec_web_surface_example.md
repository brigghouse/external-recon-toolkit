# Web Surface Audit Report — https://brighousesec.com

| Field | Value |
|-------|-------|
| Generated | 2026-05-15 18:37 UTC |
| Tool | BSL Web Surface Auditor v1.0.0 — Brighouse Security Labs |
| Final URL | https://brighousesec.com/ |
| Status Code | 200 |
| Launch Readiness | **Minor Issues** |
| Risk Score | **25/100** |

---

## Client Friendly Summary

The website at https://brighousesec.com has a solid foundation but a small number of best-practice security settings are missing. These are low-effort fixes that will strengthen the overall posture without requiring significant development work.

---

## HTTPS & Redirect Check

- HTTPS Available: **Yes**
- HTTP→HTTPS Redirect: **Yes**
- Final Resolved URL: `https://brighousesec.com/`
- Final Status Code: `200`

---

## TLS Certificate

- Subject:    `brighousesec.com`
- Issuer:     `Let's Encrypt`
- Expiry:     `2026-07-19`
- Days Left:  `65`

---

## Technology Hints (from headers)

- Netlify

---

## Findings

| # | Check | Severity | Finding |
|---|-------|----------|---------|
| 1 | HTTPS Available | Info | HTTPS is available. |
| 2 | HTTP→HTTPS Redirect | Info | HTTP correctly redirects to HTTPS. |
| 3 | TLS Certificate | Info | TLS certificate valid. Expires 2026-07-19 (65 day(s) remaining). Issuer: Let's Encrypt. |
| 4 | Server Header | Low | Server header present: 'Netlify'. May disclose software version. |
| 5 | X-Powered-By Header | Info | X-Powered-By header not present. |
| 6 | Strict-Transport-Security | Info | Present: max-age=31536000 |
| 7 | Content-Security-Policy | Info | Present: default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data: https:; script-src  |
| 8 | X-Frame-Options | Info | Present: DENY |
| 9 | X-Content-Type-Options | Info | Present: nosniff |
| 10 | Referrer-Policy | Info | Present: strict-origin-when-cross-origin |
| 11 | Permissions-Policy | Info | Present: camera=(), microphone=(), geolocation=() |
| 12 | Cross-Origin-Opener-Policy | Low | Missing. Isolates browsing context from cross-origin windows. |
| 13 | Cross-Origin-Resource-Policy | Low | Missing. Restricts who may embed resources. |
| 14 | Cross-Origin-Embedder-Policy | Low | Missing. Prevents loading unapproved cross-origin resources. |
| 15 | Cookies | Info | No Set-Cookie headers detected in the response. |
| 16 | robots.txt | Info | robots.txt found. No obviously sensitive path hints detected. |
| 17 | sitemap.xml | Info | sitemap.xml found. |
| 18 | security.txt | Low | No security.txt found at /.well-known/security.txt or /security.txt. |

---

## Evidence

### HTTPS Available
```
https://brighousesec.com
```

### HTTP→HTTPS Redirect
```
HTTP status: 301
```

### TLS Certificate
```
Subject: brighousesec.com
Issuer: Let's Encrypt
Expiry: 2026-07-19
Days remaining: 65
```

### Server Header
```
Netlify
```

### X-Powered-By Header
_No raw evidence captured._

### Strict-Transport-Security
```
max-age=31536000
```

### Content-Security-Policy
```
default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data: https:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com; connect-src 'self' https://formspree.io; form-action 'self' https://formspree.io;
```

### X-Frame-Options
```
DENY
```

### X-Content-Type-Options
```
nosniff
```

### Referrer-Policy
```
strict-origin-when-cross-origin
```

### Permissions-Policy
```
camera=(), microphone=(), geolocation=()
```

### Cross-Origin-Opener-Policy
_No raw evidence captured._

### Cross-Origin-Resource-Policy
_No raw evidence captured._

### Cross-Origin-Embedder-Policy
_No raw evidence captured._

### Cookies
_No raw evidence captured._

### robots.txt
```
User-agent: *
Allow: /

Sitemap: https://brighousesec.com/sitemap.xml
```

### sitemap.xml
```
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://brighousesec.com/</loc>
    <priority>1.0</priority>
  </url>
</urlset>
```

### security.txt
_No raw evidence captured._

---

## Recommendations

**4. Server Header (Low):** Configure your web server to suppress or genericise the Server header. Avoid version disclosure.

**12. Cross-Origin-Opener-Policy (Low):** Add the Cross-Origin-Opener-Policy header. Isolates browsing context from cross-origin windows.

**13. Cross-Origin-Resource-Policy (Low):** Add the Cross-Origin-Resource-Policy header. Restricts who may embed resources.

**14. Cross-Origin-Embedder-Policy (Low):** Add the Cross-Origin-Embedder-Policy header. Prevents loading unapproved cross-origin resources.

**18. security.txt (Low):** Add a security.txt file as per RFC 9116. It helps security researchers report vulnerabilities responsibly.

---

## Retest Checklist

- [ ] **HTTPS Available** — Info
- [ ] **HTTP→HTTPS Redirect** — Info
- [ ] **TLS Certificate** — Info
- [ ] **Server Header** — Low
- [ ] **X-Powered-By Header** — Info
- [ ] **Strict-Transport-Security** — Info
- [ ] **Content-Security-Policy** — Info
- [ ] **X-Frame-Options** — Info
- [ ] **X-Content-Type-Options** — Info
- [ ] **Referrer-Policy** — Info
- [ ] **Permissions-Policy** — Info
- [ ] **Cross-Origin-Opener-Policy** — Low
- [ ] **Cross-Origin-Resource-Policy** — Low
- [ ] **Cross-Origin-Embedder-Policy** — Low
- [ ] **Cookies** — Info
- [ ] **robots.txt** — Info
- [ ] **sitemap.xml** — Info
- [ ] **security.txt** — Low

---

_Report generated by BSL Web Surface Auditor — Brighouse Security Labs._  
_For authorised use only. Do not distribute without client consent._