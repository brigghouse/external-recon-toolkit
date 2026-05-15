#!/usr/bin/env python3
"""
bsl_web_surface_auditor.py — Brighouse Security Labs
=====================================================
Safe web surface security hygiene checker for one website.

Checks HTTPS, redirects, security headers, cookies, robots.txt,
sitemap.xml, security.txt, TLS certificate metadata, and technology hints.

Only the following paths are requested (no brute forcing):
  - Input URL + HTTP version to test redirect
  - /robots.txt
  - /sitemap.xml
  - /.well-known/security.txt
  - /security.txt

Usage:
    python tools/bsl_web_surface_auditor.py https://example.com
    python tools/bsl_web_surface_auditor.py https://example.com --markdown --output reports/example
    python tools/bsl_web_surface_auditor.py https://example.com --json --quiet

AUTHORISED USE ONLY. See docs/responsible-use.md for policy.
"""

from __future__ import annotations

import datetime
import json
import re
import socket
import ssl
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
import typer
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

__version__ = "1.0.0"
USER_AGENT  = "BrighouseSec-External-Recon/1.0"
TIMEOUT     = 12  # seconds

# Security headers to check and their relevance notes
SECURITY_HEADERS: Dict[str, str] = {
    "Strict-Transport-Security":     "Enforces HTTPS for future visits (HSTS).",
    "Content-Security-Policy":       "Controls which resources may be loaded.",
    "X-Frame-Options":               "Prevents clickjacking via iframes.",
    "X-Content-Type-Options":        "Stops MIME-type sniffing.",
    "Referrer-Policy":               "Controls referrer information sent to third parties.",
    "Permissions-Policy":            "Restricts access to browser APIs.",
    "Cross-Origin-Opener-Policy":    "Isolates browsing context from cross-origin windows.",
    "Cross-Origin-Resource-Policy":  "Restricts who may embed resources.",
    "Cross-Origin-Embedder-Policy":  "Prevents loading unapproved cross-origin resources.",
}

# Technology hints inferred purely from response headers (no active probing)
TECH_HINTS: List[Tuple[str, str]] = [
    ("CF-Ray",             "Cloudflare"),
    ("X-Vercel-Id",        "Vercel"),
    ("X-NF-Request-Id",    "Netlify"),
    ("X-Shopify-Stage",    "Shopify"),
    ("X-Powered-By",       ""),          # value used directly
    ("Server",             ""),          # value used directly
    ("X-Generator",        ""),
    ("X-WP-Total",         "WordPress"),
    ("X-WP-TotalPages",    "WordPress"),
]

# Risky path keywords — only flagged if found inside robots.txt, sitemap, or page links
RISKY_KEYWORDS = [
    "admin", "staging", "test", "backup", "dev",
    "debug", "old", "private",
]

RESPONSIBLE_USE = (
    "[bold yellow]⚠  Responsible Use Notice[/bold yellow]\n"
    "This toolkit is intended for authorised security reviews only.\n"
    "Do not use it against systems you do not own or do not have "
    "explicit written permission to assess."
)

app = typer.Typer(
    name="bsl-web-surface-auditor",
    help="BSL Web Surface Auditor — website security hygiene checker.",
    add_completion=False,
)
console = Console()


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _get(url: str, allow_redirects: bool = True, verify: bool = True) -> Optional[requests.Response]:
    """
    Perform a safe GET request with a fixed User-Agent and timeout.
    Returns None on any network or connection error.
    """
    try:
        return requests.get(
            url,
            timeout=TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=allow_redirects,
            verify=verify,
        )
    except requests.RequestException:
        return None


def _head(url: str) -> Optional[requests.Response]:
    try:
        return requests.head(
            url,
            timeout=TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=True,
        )
    except requests.RequestException:
        return None


# ---------------------------------------------------------------------------
# TLS certificate inspection
# ---------------------------------------------------------------------------

def check_tls_cert(hostname: str, port: int = 443) -> Dict[str, Any]:
    """
    Connect to hostname:port and retrieve certificate metadata.
    No validation of certificate chain — metadata only.
    """
    result: Dict[str, Any] = {
        "reachable": False,
        "issuer":     None,
        "subject":    None,
        "expiry":     None,
        "days_left":  None,
        "severity":   "Info",
        "finding":    "TLS certificate could not be retrieved.",
        "recommendation": "Ensure HTTPS is active and the certificate is valid.",
    }
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((hostname, port), timeout=TIMEOUT),
            server_hostname=hostname,
        ) as conn:
            cert = conn.getpeercert()

        result["reachable"] = True

        # Subject CN
        subject_dict = dict(x[0] for x in cert.get("subject", []))
        result["subject"] = subject_dict.get("commonName", "Unknown")

        # Issuer O
        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
        result["issuer"] = issuer_dict.get("organizationName", "Unknown")

        # Expiry
        raw_expiry = cert.get("notAfter")
        if raw_expiry:
            expiry_dt = datetime.datetime.strptime(raw_expiry, "%b %d %H:%M:%S %Y %Z")
            result["expiry"]    = expiry_dt.strftime("%Y-%m-%d")
            days_left           = (expiry_dt - datetime.datetime.utcnow()).days
            result["days_left"] = days_left

            if days_left < 0:
                result["severity"]       = "High"
                result["finding"]        = f"TLS certificate EXPIRED {abs(days_left)} day(s) ago."
                result["recommendation"] = "Renew the TLS certificate immediately."
            elif days_left < 14:
                result["severity"]       = "High"
                result["finding"]        = f"TLS certificate expires in {days_left} day(s)."
                result["recommendation"] = "Renew the certificate within the next few days."
            elif days_left < 30:
                result["severity"]       = "Medium"
                result["finding"]        = f"TLS certificate expires in {days_left} day(s)."
                result["recommendation"] = "Plan certificate renewal within the next two weeks."
            else:
                result["severity"] = "Info"
                result["finding"]  = (
                    f"TLS certificate valid. Expires {result['expiry']} "
                    f"({days_left} day(s) remaining). Issuer: {result['issuer']}."
                )
                result["recommendation"] = "No action required. Monitor for upcoming expiry."
    except ssl.SSLCertVerificationError as e:
        result["severity"]       = "High"
        result["finding"]        = f"TLS certificate validation error: {e}"
        result["recommendation"] = "Investigate the certificate chain — it may be self-signed or misconfigured."
    except (socket.timeout, ConnectionRefusedError, OSError):
        result["severity"]       = "High"
        result["finding"]        = "HTTPS port (443) not reachable."
        result["recommendation"] = "Ensure HTTPS is correctly configured and the server is accepting connections."
    except Exception as exc:  # noqa: BLE001
        result["finding"] = f"TLS check error: {exc}"

    return result


# ---------------------------------------------------------------------------
# Security header analysis
# ---------------------------------------------------------------------------

def analyse_headers(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Check for the presence and basic quality of recommended security headers.
    Returns a list of finding dicts.
    """
    findings = []

    # --- Server header leakage ---
    server = headers.get("Server", "")
    if server:
        findings.append({
            "check": "Server Header",
            "severity": "Low",
            "finding": f"Server header present: '{server}'. May disclose software version.",
            "evidence": server,
            "recommendation": (
                "Configure your web server to suppress or genericise the Server header. "
                "Avoid version disclosure."
            ),
        })
    else:
        findings.append({
            "check": "Server Header",
            "severity": "Info",
            "finding": "Server header is not present or suppressed. Good.",
            "evidence": "",
            "recommendation": "No action required.",
        })

    # --- X-Powered-By leakage ---
    xpb = headers.get("X-Powered-By", "")
    if xpb:
        findings.append({
            "check": "X-Powered-By Header",
            "severity": "Low",
            "finding": f"X-Powered-By header present: '{xpb}'. Discloses technology stack.",
            "evidence": xpb,
            "recommendation": "Remove or suppress the X-Powered-By header in your server / framework config.",
        })
    else:
        findings.append({
            "check": "X-Powered-By Header",
            "severity": "Info",
            "finding": "X-Powered-By header not present.",
            "evidence": "",
            "recommendation": "No action required.",
        })

    # --- Recommended security headers ---
    for header, purpose in SECURITY_HEADERS.items():
        present = header in headers or header.lower() in {h.lower() for h in headers}
        if present:
            # Get the actual value (case-insensitive)
            value = headers.get(header) or next(
                (v for k, v in headers.items() if k.lower() == header.lower()), "")
            findings.append({
                "check": header,
                "severity": "Info",
                "finding": f"Present: {value[:120]}",
                "evidence": value,
                "recommendation": "No action required. Review value for correctness.",
            })
        else:
            # Determine severity by importance
            if header in ("Strict-Transport-Security", "X-Content-Type-Options",
                          "X-Frame-Options"):
                sev = "Medium"
            else:
                sev = "Low"
            findings.append({
                "check": header,
                "severity": sev,
                "finding": f"Missing. {purpose}",
                "evidence": "",
                "recommendation": f"Add the {header} header. {purpose}",
            })

    return findings


# ---------------------------------------------------------------------------
# Cookie flag analysis
# ---------------------------------------------------------------------------

def analyse_cookies(response: requests.Response) -> List[Dict[str, Any]]:
    """
    Inspect Set-Cookie headers for missing Secure, HttpOnly, and SameSite flags.
    """
    findings = []
    set_cookie_headers = response.headers.getlist("Set-Cookie") if hasattr(
        response.headers, "getlist") else []

    # requests' Response.headers is a CaseInsensitiveDict that doesn't support getlist;
    # access the raw header list from the underlying urllib3 response.
    raw_headers = response.raw.headers.getlist("Set-Cookie") if (
        response.raw and hasattr(response.raw.headers, "getlist")) else []

    if not raw_headers:
        # Fallback: try iterating headers items for multiple Set-Cookie
        raw_headers = [v for k, v in response.headers.items()
                       if k.lower() == "set-cookie"]

    if not raw_headers:
        findings.append({
            "check": "Cookies",
            "severity": "Info",
            "finding": "No Set-Cookie headers detected in the response.",
            "evidence": "",
            "recommendation": "If this application uses sessions, verify cookies are set correctly on authenticated pages.",
        })
        return findings

    for i, cookie in enumerate(raw_headers, 1):
        cookie_lower = cookie.lower()
        issues = []

        if "secure" not in cookie_lower:
            issues.append("missing Secure flag")
        if "httponly" not in cookie_lower:
            issues.append("missing HttpOnly flag")
        if "samesite" not in cookie_lower:
            issues.append("missing SameSite attribute")

        # Extract cookie name
        name_part = cookie.split(";")[0].split("=")[0].strip()

        if issues:
            findings.append({
                "check": f"Cookie: {name_part}",
                "severity": "Medium" if "missing Secure flag" in issues else "Low",
                "finding": f"Cookie '{name_part}' has issues: {', '.join(issues)}.",
                "evidence": cookie[:200],
                "recommendation": (
                    f"Add the missing flags to the '{name_part}' cookie: "
                    "Secure; HttpOnly; SameSite=Strict (or Lax)."
                ),
            })
        else:
            findings.append({
                "check": f"Cookie: {name_part}",
                "severity": "Info",
                "finding": f"Cookie '{name_part}' has Secure, HttpOnly, and SameSite flags set.",
                "evidence": cookie[:200],
                "recommendation": "No action required.",
            })

    return findings


# ---------------------------------------------------------------------------
# robots.txt / sitemap.xml / security.txt checks
# ---------------------------------------------------------------------------

def check_robots(base_url: str) -> Dict[str, Any]:
    """
    Fetch /robots.txt and flag any paths that look sensitive.
    No paths beyond /robots.txt are requested here.
    """
    url = urljoin(base_url, "/robots.txt")
    resp = _get(url)
    if not resp or resp.status_code != 200:
        return {
            "found": False, "url": url, "status": resp.status_code if resp else None,
            "content": None, "risky_hints": [],
            "severity": "Info",
            "finding": "robots.txt not found or returned non-200.",
            "evidence": url,
            "recommendation": "A robots.txt is not mandatory, but can signal which paths are being hidden.",
        }
    content = resp.text[:2000]
    risky = [kw for kw in RISKY_KEYWORDS if kw in content.lower()]
    severity = "Low" if risky else "Info"
    return {
        "found": True, "url": url, "status": 200,
        "content": content, "risky_hints": risky,
        "severity": severity,
        "finding": (
            f"robots.txt found. Potentially sensitive path hints: {', '.join(risky)}."
            if risky else "robots.txt found. No obviously sensitive path hints detected."
        ),
        "evidence": content[:500],
        "recommendation": (
            f"Review whether paths like {risky} should be discoverable via robots.txt."
            if risky else "Review robots.txt contents and remove any confidential path hints."
        ),
    }


def check_sitemap(base_url: str) -> Dict[str, Any]:
    url = urljoin(base_url, "/sitemap.xml")
    resp = _get(url)
    if not resp or resp.status_code != 200:
        return {
            "found": False, "url": url,
            "severity": "Info",
            "finding": "sitemap.xml not found (optional).",
            "evidence": url,
            "recommendation": "A sitemap.xml is recommended for SEO but not a security requirement.",
        }
    risky = [kw for kw in RISKY_KEYWORDS if kw in resp.text.lower()]
    return {
        "found": True, "url": url,
        "severity": "Low" if risky else "Info",
        "finding": (
            f"sitemap.xml found. Potentially sensitive path hints: {', '.join(risky)}."
            if risky else "sitemap.xml found."
        ),
        "evidence": resp.text[:500],
        "recommendation": (
            f"Ensure paths like {risky} in the sitemap are intentionally public."
            if risky else "No action required."
        ),
    }


def check_security_txt(base_url: str) -> Dict[str, Any]:
    """
    Check for security.txt at both canonical locations.
    """
    for path in ["/.well-known/security.txt", "/security.txt"]:
        url = urljoin(base_url, path)
        resp = _get(url)
        if resp and resp.status_code == 200 and "contact" in resp.text.lower():
            return {
                "found": True, "url": url,
                "severity": "Info",
                "finding": f"security.txt found at {url}.",
                "evidence": resp.text[:400],
                "recommendation": "Ensure security.txt is kept up to date with valid contact details and expiry.",
            }
    return {
        "found": False, "url": None,
        "severity": "Low",
        "finding": "No security.txt found at /.well-known/security.txt or /security.txt.",
        "evidence": "",
        "recommendation": (
            "Add a security.txt file as per RFC 9116. "
            "It helps security researchers report vulnerabilities responsibly."
        ),
    }


# ---------------------------------------------------------------------------
# Technology detection (headers only)
# ---------------------------------------------------------------------------

def detect_technologies(headers: Dict[str, str]) -> List[str]:
    """
    Infer technology stack from response headers only.
    Returns a list of human-readable technology labels.
    """
    found = set()
    headers_lower = {k.lower(): v for k, v in headers.items()}

    header_tech_map = {
        "cf-ray":                "Cloudflare",
        "x-vercel-id":           "Vercel",
        "x-nf-request-id":       "Netlify",
        "x-shopify-stage":       "Shopify",
        "x-shopify-request-id":  "Shopify",
    }
    for h, tech in header_tech_map.items():
        if h in headers_lower:
            found.add(tech)

    server = headers_lower.get("server", "").lower()
    if "nginx"   in server: found.add("nginx")
    if "apache"  in server: found.add("Apache")
    if "cloudflare" in server: found.add("Cloudflare")
    if "vercel"  in server: found.add("Vercel")

    xpb = headers_lower.get("x-powered-by", "").lower()
    if "express"    in xpb: found.add("Express.js")
    if "php"        in xpb: found.add("PHP")
    if "next.js"    in xpb: found.add("Next.js")
    if "wordpress"  in xpb: found.add("WordPress")
    if "asp.net"    in xpb: found.add("ASP.NET")

    xgen = headers_lower.get("x-generator", "").lower()
    if "wordpress" in xgen: found.add("WordPress")

    return sorted(found)


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS = {"High": 25, "Medium": 12, "Low": 5, "Info": 0}


def calculate_score(findings: List[Dict[str, Any]]) -> int:
    return min(sum(SEVERITY_WEIGHTS.get(f.get("severity", "Info"), 0)
                   for f in findings), 100)


def launch_readiness_label(score: int) -> str:
    if score <= 10:  return "Ready"
    if score <= 30:  return "Minor Issues"
    if score <= 55:  return "Needs Fixes Before Launch"
    return "High Risk Exposure"


def client_friendly_summary(url: str, score: int, label: str,
                             findings: List[Dict[str, Any]]) -> str:
    highs   = [f for f in findings if f["severity"] == "High"]
    mediums = [f for f in findings if f["severity"] == "Medium"]

    if label == "Ready":
        body = (
            f"The website at {url} is well-configured from a security standpoint. "
            "Core security headers are present, HTTPS is correctly enforced, "
            "and no significant issues were identified. "
            "We recommend periodic re-testing as the site evolves."
        )
    elif label == "Minor Issues":
        body = (
            f"The website at {url} has a solid foundation but a small number of "
            "best-practice security settings are missing. "
            "These are low-effort fixes that will strengthen the overall posture "
            "without requiring significant development work."
        )
    elif label == "Needs Fixes Before Launch":
        body = (
            f"The website at {url} has a number of security gaps that should be "
            "addressed before going live or before a production release. "
            f"There are {len(mediums)} medium-severity and {len(highs)} high-severity item(s) "
            "that need attention. These are largely configuration changes."
        )
    else:
        body = (
            f"The website at {url} has significant security exposure that requires "
            "prompt attention. "
            f"{len(highs)} high-severity issue(s) were identified. "
            "We recommend pausing any planned launch or promotion until these items "
            "have been resolved and re-tested."
        )

    return body


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

def build_markdown(url: str, data: Dict[str, Any]) -> str:
    score   = data["score"]
    label   = data["label"]
    now     = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        f"# Web Surface Audit Report — {url}",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Generated | {now} |",
        f"| Tool | BSL Web Surface Auditor v{__version__} — Brighouse Security Labs |",
        f"| Final URL | {data.get('final_url', url)} |",
        f"| Status Code | {data.get('status_code', 'N/A')} |",
        f"| Launch Readiness | **{label}** |",
        f"| Risk Score | **{score}/100** |",
        "",
        "---",
        "",
        "## Client Friendly Summary",
        "",
        data.get("client_summary", ""),
        "",
        "---",
        "",
        "## HTTPS & Redirect Check",
        "",
        f"- HTTPS Available: **{'Yes' if data.get('https_available') else 'No'}**",
        f"- HTTP→HTTPS Redirect: **{'Yes' if data.get('http_redirects') else 'No'}**",
        f"- Final Resolved URL: `{data.get('final_url', 'N/A')}`",
        f"- Final Status Code: `{data.get('status_code', 'N/A')}`",
        "",
        "---",
        "",
        "## TLS Certificate",
        "",
    ]

    cert = data.get("tls_cert", {})
    lines += [
        f"- Subject:    `{cert.get('subject', 'N/A')}`",
        f"- Issuer:     `{cert.get('issuer', 'N/A')}`",
        f"- Expiry:     `{cert.get('expiry', 'N/A')}`",
        f"- Days Left:  `{cert.get('days_left', 'N/A')}`",
        "",
        "---",
        "",
        "## Technology Hints (from headers)",
        "",
    ]
    techs = data.get("technologies", [])
    if techs:
        lines += [f"- {t}" for t in techs]
    else:
        lines.append("- None identified from headers.")
    lines.append("")

    lines += [
        "---",
        "",
        "## Findings",
        "",
        "| # | Check | Severity | Finding |",
        "|---|-------|----------|---------|",
    ]
    for i, f in enumerate(data["findings"], 1):
        lines.append(f"| {i} | {f['check']} | {f['severity']} | {f['finding']} |")
    lines.append("")

    lines += ["---", "", "## Evidence", ""]
    for f in data["findings"]:
        lines.append(f"### {f['check']}")
        ev = f.get("evidence", "").strip()
        if ev:
            lines.append(f"```\n{ev}\n```")
        else:
            lines.append("_No raw evidence captured._")
        lines.append("")

    lines += ["---", "", "## Recommendations", ""]
    for i, f in enumerate(data["findings"], 1):
        if f["severity"] in ("High", "Medium", "Low"):
            lines.append(f"**{i}. {f['check']} ({f['severity']}):** {f['recommendation']}")
            lines.append("")

    lines += ["---", "", "## Retest Checklist", ""]
    for f in data["findings"]:
        lines.append(f"- [ ] **{f['check']}** — {f['severity']}")
    lines.append("")

    lines += [
        "---",
        "",
        "_Report generated by BSL Web Surface Auditor — Brighouse Security Labs._  ",
        "_For authorised use only. Do not distribute without client consent._",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Core audit runner
# ---------------------------------------------------------------------------

def run_audit(url: str) -> Dict[str, Any]:
    """
    Perform the full web surface audit for *url*.
    Requests made:
      1. GET url (follows redirects)
      2. GET http:// version to detect redirect
      3. GET /robots.txt
      4. GET /sitemap.xml
      5. GET /.well-known/security.txt
      6. GET /security.txt
    """
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    findings: List[Dict[str, Any]] = []

    # --- HTTPS availability ---
    resp_https = _get(url)
    https_available = resp_https is not None and resp_https.url.startswith("https://")

    findings.append({
        "check": "HTTPS Available",
        "severity": "High" if not https_available else "Info",
        "finding": "HTTPS is available." if https_available else "HTTPS does not appear to be available.",
        "evidence": url,
        "recommendation": (
            "No action required." if https_available
            else "Enable HTTPS with a valid TLS certificate."
        ),
    })

    # --- HTTP → HTTPS redirect ---
    http_url = url.replace("https://", "http://", 1).replace("http://", "http://", 1)
    if not http_url.startswith("http://"):
        http_url = "http://" + parsed.netloc + parsed.path

    resp_http = _get(http_url, allow_redirects=False)
    http_redirects = (resp_http is not None and
                      resp_http.status_code in (301, 302, 307, 308) and
                      "https" in resp_http.headers.get("Location", "").lower())

    findings.append({
        "check": "HTTP→HTTPS Redirect",
        "severity": "Medium" if (https_available and not http_redirects) else "Info",
        "finding": (
            "HTTP correctly redirects to HTTPS."
            if http_redirects else
            "HTTP does not redirect to HTTPS."
            if https_available else
            "HTTP redirect check skipped — HTTPS not available."
        ),
        "evidence": f"HTTP status: {resp_http.status_code if resp_http else 'N/A'}",
        "recommendation": (
            "No action required."
            if http_redirects else
            "Configure a permanent 301 redirect from HTTP to HTTPS."
        ),
    })

    # Final resolved URL + status code
    final_url   = resp_https.url  if resp_https else url
    status_code = resp_https.status_code if resp_https else None

    # --- TLS certificate ---
    tls_cert = check_tls_cert(hostname)
    findings.append({
        "check": "TLS Certificate",
        "severity": tls_cert["severity"],
        "finding": tls_cert["finding"],
        "evidence": (
            f"Subject: {tls_cert['subject']}\n"
            f"Issuer: {tls_cert['issuer']}\n"
            f"Expiry: {tls_cert['expiry']}\n"
            f"Days remaining: {tls_cert['days_left']}"
        ),
        "recommendation": tls_cert["recommendation"],
    })

    # --- Headers (from HTTPS response) ---
    headers: Dict[str, str] = dict(resp_https.headers) if resp_https else {}
    header_findings = analyse_headers(headers)
    findings.extend(header_findings)

    # --- Cookies ---
    if resp_https:
        cookie_findings = analyse_cookies(resp_https)
        findings.extend(cookie_findings)

    # --- robots.txt ---
    robots = check_robots(final_url)
    findings.append({
        "check": "robots.txt",
        "severity": robots["severity"],
        "finding": robots["finding"],
        "evidence": robots["evidence"],
        "recommendation": robots["recommendation"],
    })

    # --- sitemap.xml ---
    sitemap = check_sitemap(final_url)
    findings.append({
        "check": "sitemap.xml",
        "severity": sitemap["severity"],
        "finding": sitemap["finding"],
        "evidence": sitemap["evidence"],
        "recommendation": sitemap["recommendation"],
    })

    # --- security.txt ---
    sec_txt = check_security_txt(final_url)
    findings.append({
        "check": "security.txt",
        "severity": sec_txt["severity"],
        "finding": sec_txt["finding"],
        "evidence": sec_txt["evidence"],
        "recommendation": sec_txt["recommendation"],
    })

    # --- Technology detection ---
    technologies = detect_technologies(headers)

    score  = calculate_score(findings)
    label  = launch_readiness_label(score)
    c_sum  = client_friendly_summary(url, score, label, findings)

    return {
        "url":             url,
        "final_url":       final_url,
        "status_code":     status_code,
        "https_available": https_available,
        "http_redirects":  http_redirects,
        "tls_cert":        tls_cert,
        "technologies":    technologies,
        "findings":        findings,
        "score":           score,
        "label":           label,
        "client_summary":  c_sum,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@app.command()
def main(
    url: str = typer.Argument(..., help="Target URL to audit (e.g. https://example.com)"),
    output: Optional[str] = typer.Option(
        None, "--output", "-o",
        help="Base path for output files (without extension).",
    ),
    json_flag: bool  = typer.Option(False, "--json",     help="Export results as JSON."),
    markdown_flag: bool = typer.Option(False, "--markdown", help="Export results as Markdown."),
    quiet: bool      = typer.Option(False, "--quiet", "-q",
                                    help="Suppress banner output. Prints JSON summary to stdout."),
) -> None:
    """
    BSL Web Surface Auditor — website security hygiene checker.

    Checks HTTPS, security headers, cookies, TLS certificate, robots.txt,
    sitemap.xml, security.txt, and technology hints.
    """
    # Normalise URL
    if not url.startswith("http"):
        url = "https://" + url

    if not quiet:
        console.print(Panel(RESPONSIBLE_USE, border_style="yellow", expand=False))
        console.print()
        console.rule("[bold cyan]BSL Web Surface Auditor[/bold cyan] — Brighouse Security Labs")
        console.print(f"\n  Target: [bold]{url}[/bold]\n")

    with console.status(f"[cyan]Auditing {url}...[/cyan]", spinner="dots"):
        data = run_audit(url)

    score = data["score"]
    label = data["label"]

    if not quiet:
        # --- main findings table ---
        table = Table(
            title=f"[bold]Web Surface Audit — {url}[/bold]",
            show_header=True,
            header_style="bold magenta",
            show_lines=True,
        )
        table.add_column("Check",    style="cyan", no_wrap=True, min_width=32)
        table.add_column("Severity", justify="center", min_width=9)
        table.add_column("Finding")

        sev_colour = {"High": "red", "Medium": "yellow", "Low": "blue", "Info": "green"}
        for f in data["findings"]:
            col = sev_colour.get(f["severity"], "white")
            table.add_row(
                f["check"],
                f"[{col}]{f['severity']}[/{col}]",
                f["finding"],
            )
        console.print(table)
        console.print()

        label_colour = {
            "Ready": "green",
            "Minor Issues": "cyan",
            "Needs Fixes Before Launch": "yellow",
            "High Risk Exposure": "red",
        }.get(label, "white")

        console.print(f"  Launch Readiness : [{label_colour}][bold]{label}[/bold][/{label_colour}]")
        console.print(f"  Risk Score       : [bold]{score}/100[/bold]")
        console.print(f"  Final URL        : {data['final_url']}")
        console.print(f"  Technologies     : {', '.join(data['technologies']) or 'None identified'}")
        console.print()
        console.print(Panel(
            data["client_summary"],
            title="[bold]Client Friendly Summary[/bold]",
            border_style="cyan",
            expand=False,
        ))
        console.print()

    base = output or f"reports/{urlparse(url).hostname}_web_surface"

    if markdown_flag or output:
        md_path = Path(f"{base}.md")
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(build_markdown(url, data), encoding="utf-8")
        if not quiet:
            console.print(f"  [green]✓[/green] Markdown saved → {md_path}")

    if json_flag or output:
        json_path = Path(f"{base}.json")
        json_path.parent.mkdir(parents=True, exist_ok=True)
        export = {k: data[k] for k in
                  ("url", "final_url", "status_code", "https_available",
                   "http_redirects", "tls_cert", "technologies",
                   "findings", "score", "label", "client_summary")}
        json_path.write_text(json.dumps(export, indent=2), encoding="utf-8")
        if not quiet:
            console.print(f"  [green]✓[/green] JSON saved     → {json_path}")

    if quiet:
        print(json.dumps({"url": data["url"], "score": score, "label": label}))


if __name__ == "__main__":
    app()
