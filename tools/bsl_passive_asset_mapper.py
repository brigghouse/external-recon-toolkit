#!/usr/bin/env python3
"""
bsl_passive_asset_mapper.py — Brighouse Security Labs
======================================================
Passive external asset mapper for a root domain.

Discovery sources (no brute forcing, no wordlists):
  1. Certificate Transparency via crt.sh public API
  2. DNS records for the root domain
  3. sitemap.xml links from the root website
  4. robots.txt path hints from the root website
  5. Optional: user-provided extra hosts via --input-file

Per-host checks (lightweight only):
  - DNS resolution (A / AAAA)
  - HTTP availability
  - HTTPS availability
  - Status code + redirect target
  - Page title (from HTML)
  - Basic platform hints from response headers
  - Semantic flags (staging / dev / test / admin / old / backup)

Usage:
    python tools/bsl_passive_asset_mapper.py example.com
    python tools/bsl_passive_asset_mapper.py example.com --markdown --json --output reports/example
    python tools/bsl_passive_asset_mapper.py example.com --input-file extra_hosts.txt --quiet

AUTHORISED USE ONLY. See docs/responsible-use.md for policy.
"""

from __future__ import annotations

import csv
import datetime
import ipaddress
import json
import re
import socket
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import dns.exception
import dns.resolver
import requests
import tldextract
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
TIMEOUT     = 10   # seconds per HTTP / DNS request
RATE_DELAY  = 0.4  # seconds between sequential host checks

CRT_SH_URL  = "https://crt.sh/?q=%.{domain}&output=json"

# Semantic flag patterns matched against hostnames
RISK_PATTERNS: Dict[str, str] = {
    "staging": "Looks like staging",
    "stage":   "Looks like staging",
    "test":    "Looks like test",
    "dev":     "Looks like dev",
    "develop": "Looks like dev",
    "admin":   "Looks like admin",
    "old":     "Looks like old",
    "backup":  "Looks like backup",
    "bak":     "Looks like backup",
    "uat":     "Looks like UAT",
    "demo":    "Looks like demo",
    "debug":   "Looks like debug",
}

PARKED_PHRASES = [
    "domain for sale", "buy this domain", "parked",
    "under construction", "coming soon",
]

RESPONSIBLE_USE = (
    "[bold yellow]⚠  Responsible Use Notice[/bold yellow]\n"
    "This toolkit is intended for authorised security reviews only.\n"
    "Do not use it against systems you do not own or do not have "
    "explicit written permission to assess."
)

app = typer.Typer(
    name="bsl-passive-asset-mapper",
    help="BSL Passive Asset Mapper — external asset discovery for a root domain.",
    add_completion=False,
)
console = Console()


# ---------------------------------------------------------------------------
# DNS helpers
# ---------------------------------------------------------------------------

def _resolve(domain: str, rtype: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(domain, rtype, lifetime=TIMEOUT)
        return [r.to_text().strip('"') for r in answers]
    except Exception:  # noqa: BLE001
        return []


def resolve_a(host: str) -> List[str]:  return _resolve(host, "A")
def resolve_aaaa(host: str) -> List[str]: return _resolve(host, "AAAA")


def host_resolves(host: str) -> bool:
    """Return True if the host has at least one A or AAAA record."""
    return bool(resolve_a(host) or resolve_aaaa(host))


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _get(url: str, allow_redirects: bool = True) -> Optional[requests.Response]:
    try:
        return requests.get(
            url, timeout=TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=allow_redirects,
            verify=False,   # we're passively mapping — cert validation is separate concern
        )
    except requests.RequestException:
        return None


def extract_title(html: str) -> Optional[str]:
    """Extract the <title> tag text from HTML."""
    try:
        soup = BeautifulSoup(html, "html.parser")
        tag = soup.find("title")
        return tag.get_text(strip=True)[:120] if tag else None
    except Exception:  # noqa: BLE001
        return None


def detect_platform(headers: Dict[str, str]) -> Optional[str]:
    """Infer hosting platform / tech from response headers."""
    h = {k.lower(): v.lower() for k, v in headers.items()}
    if "cf-ray"            in h: return "Cloudflare"
    if "x-vercel-id"       in h: return "Vercel"
    if "x-nf-request-id"   in h: return "Netlify"
    if "x-shopify-stage"   in h: return "Shopify"
    srv = h.get("server", "")
    if "nginx"   in srv: return "nginx"
    if "apache"  in srv: return "Apache"
    if "cloudflare" in srv: return "Cloudflare"
    xpb = h.get("x-powered-by", "")
    if "express"   in xpb: return "Express.js"
    if "php"       in xpb: return "PHP"
    if "wordpress" in xpb: return "WordPress"
    return None


def is_parked(html: str) -> bool:
    low = html.lower()
    return any(phrase in low for phrase in PARKED_PHRASES)


# ---------------------------------------------------------------------------
# Discovery: crt.sh
# ---------------------------------------------------------------------------

def discover_via_crt_sh(domain: str) -> Set[str]:
    """
    Query the crt.sh Certificate Transparency log aggregator for subdomains.
    Returns a set of unique hostnames (lower-cased, deduplicated).
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    found: Set[str] = set()
    try:
        resp = requests.get(
            url, timeout=20,
            headers={"User-Agent": USER_AGENT},
        )
        if resp.status_code != 200:
            return found
        entries = resp.json()
        for entry in entries:
            # common_name and name_value may contain wildcards; skip those
            for field in ("common_name", "name_value"):
                value = entry.get(field, "")
                for name in value.split("\n"):
                    name = name.strip().lstrip("*.")
                    if name and not name.startswith("*") and "." in name:
                        # Only include names that belong to the target domain
                        extracted = tldextract.extract(name)
                        if extracted.registered_domain == tldextract.extract(domain).registered_domain:
                            found.add(name.lower())
    except Exception:  # noqa: BLE001
        pass
    return found


# ---------------------------------------------------------------------------
# Discovery: DNS records of root domain
# ---------------------------------------------------------------------------

def discover_via_dns(domain: str) -> Set[str]:
    """
    Pull hostnames from MX, NS, and CNAME records of the root domain.
    Only adds names that belong to the same registered domain.
    """
    found: Set[str] = set()
    root_rd = tldextract.extract(domain).registered_domain

    for rtype in ("MX", "NS"):
        for record in _resolve(domain, rtype):
            # MX records: "10 mail.example.com", NS: "ns1.example.com."
            parts = record.split()
            host  = parts[-1].rstrip(".")
            ext   = tldextract.extract(host)
            if ext.registered_domain == root_rd:
                found.add(host.lower())

    return found


# ---------------------------------------------------------------------------
# Discovery: sitemap.xml
# ---------------------------------------------------------------------------

def discover_via_sitemap(domain: str) -> Set[str]:
    """
    Fetch /sitemap.xml and extract unique hostnames from URLs within it.
    """
    found: Set[str] = set()
    url = f"https://{domain}/sitemap.xml"
    resp = _get(url)
    if not resp or resp.status_code != 200:
        return found

    root_rd = tldextract.extract(domain).registered_domain
    # Find all URLs in the sitemap
    for match in re.findall(r"https?://([^/<\s\"']+)", resp.text):
        ext = tldextract.extract(match)
        if ext.registered_domain == root_rd:
            found.add(match.lower())
    return found


# ---------------------------------------------------------------------------
# Discovery: robots.txt
# ---------------------------------------------------------------------------

def discover_via_robots(domain: str) -> Set[str]:
    """
    Fetch /robots.txt and collect any full URLs mentioned.
    Only adds subdomains of the same registered domain.
    """
    found: Set[str] = set()
    url = f"https://{domain}/robots.txt"
    resp = _get(url)
    if not resp or resp.status_code != 200:
        return found

    root_rd = tldextract.extract(domain).registered_domain
    for match in re.findall(r"https?://([^/<\s\"']+)", resp.text):
        ext = tldextract.extract(match)
        if ext.registered_domain == root_rd:
            found.add(match.lower())
    return found


# ---------------------------------------------------------------------------
# Per-host probe
# ---------------------------------------------------------------------------

def probe_host(host: str) -> Dict[str, Any]:
    """
    Lightly probe a discovered host for availability and surface metadata.
    Performs DNS lookups and a single HTTPS (then fallback HTTP) request.
    """
    result: Dict[str, Any] = {
        "host":         host,
        "resolves":     False,
        "a_records":    [],
        "aaaa_records": [],
        "http_ok":      False,
        "https_ok":     False,
        "status_code":  None,
        "redirect_to":  None,
        "title":        None,
        "platform":     None,
        "flags":        [],
        "dead_dns":     False,
        "parked":       False,
    }

    # --- DNS ---
    a    = resolve_a(host)
    aaaa = resolve_aaaa(host)
    result["a_records"]    = a
    result["aaaa_records"] = aaaa
    result["resolves"]     = bool(a or aaaa)

    if not result["resolves"]:
        result["dead_dns"] = True
        result["flags"].append("dead DNS")
        return result

    # --- Semantic flags from hostname ---
    host_lower = host.lower()
    for pattern, label in RISK_PATTERNS.items():
        if pattern in host_lower:
            result["flags"].append(label)
            break  # one flag is enough per host

    # --- HTTPS probe ---
    resp = _get(f"https://{host}", allow_redirects=True)
    if resp:
        result["https_ok"]    = True
        result["status_code"] = resp.status_code
        # Capture final redirect destination if it changed
        if resp.url != f"https://{host}/" and resp.url != f"https://{host}":
            result["redirect_to"] = resp.url
        result["title"]    = extract_title(resp.text) if resp.text else None
        result["platform"] = detect_platform(dict(resp.headers))
        if resp.text and is_parked(resp.text):
            result["parked"] = True
            result["flags"].append("parked-looking page")
    else:
        # Fallback to HTTP
        resp_http = _get(f"http://{host}", allow_redirects=True)
        if resp_http:
            result["http_ok"]     = True
            result["status_code"] = resp_http.status_code
            if resp_http.url != f"http://{host}/" and resp_http.url != f"http://{host}":
                result["redirect_to"] = resp_http.url
            result["title"]    = extract_title(resp_http.text) if resp_http.text else None
            result["platform"] = detect_platform(dict(resp_http.headers))

    if not result["https_ok"] and not result["http_ok"]:
        result["flags"].append("unknown asset")

    return result


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def calculate_debris_score(assets: List[Dict[str, Any]], total_discovered: int) -> int:
    """
    External Debris Score: 0–100 representing how messy the external surface is.
    Factors:
      - Number of discovered assets
      - Dead DNS entries
      - Sensitive-looking subdomains (staging, dev, admin, etc.)
      - Parked pages
    """
    score = 0

    # Volume: more assets = more debris
    score += min(total_discovered * 3, 30)

    for a in assets:
        if a.get("dead_dns"):                         score += 5
        if a.get("parked"):                           score += 3
        flags = a.get("flags", [])
        if any(kw in str(flags) for kw in
               ["staging", "dev", "test", "admin", "backup", "old"]):
            score += 8

    return min(score, 100)


def debris_label(score: int) -> str:
    if score <= 15:  return "Clean"
    if score <= 40:  return "Manageable"
    if score <= 65:  return "Messy"
    return "High Debris"


def priority_review_list(assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Return the top 5 assets most deserving of manual review.
    Priority: sensitive flags > dead DNS > unknown asset > alive assets.
    """
    sensitive_flags = {"Looks like staging", "Looks like dev", "Looks like admin",
                       "Looks like test", "Looks like backup", "Looks like old"}

    def sort_key(a: Dict[str, Any]) -> int:
        flags = set(a.get("flags", []))
        if flags & sensitive_flags:   return 0
        if a.get("dead_dns"):         return 1
        if "unknown asset" in flags:  return 2
        return 3

    ranked = sorted(assets, key=sort_key)
    return ranked[:5]


# ---------------------------------------------------------------------------
# Markdown / CSV report builders
# ---------------------------------------------------------------------------

def build_markdown(domain: str, data: Dict[str, Any]) -> str:
    score  = data["debris_score"]
    label  = data["debris_label"]
    now    = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    assets = data["assets"]

    lines = [
        f"# Passive Asset Map — {domain}",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Generated | {now} |",
        f"| Tool | BSL Passive Asset Mapper v{__version__} — Brighouse Security Labs |",
        f"| Root Domain | {domain} |",
        f"| Assets Discovered | {len(assets)} |",
        f"| External Debris Score | **{score}/100** |",
        f"| Debris Category | **{label}** |",
        "",
        "---",
        "",
        "## Asset Inventory",
        "",
        "| Host | Resolves | HTTPS | HTTP | Status | Redirect | Title | Platform | Flags |",
        "|------|----------|-------|------|--------|----------|-------|----------|-------|",
    ]
    for a in assets:
        lines.append(
            f"| `{a['host']}` "
            f"| {'✅' if a['resolves'] else '❌'} "
            f"| {'✅' if a['https_ok'] else '❌'} "
            f"| {'✅' if a['http_ok'] else '❌'} "
            f"| {a.get('status_code') or '—'} "
            f"| {a.get('redirect_to') or '—'} "
            f"| {a.get('title') or '—'} "
            f"| {a.get('platform') or '—'} "
            f"| {', '.join(a.get('flags', [])) or '—'} |"
        )
    lines.append("")

    lines += [
        "---",
        "",
        "## Priority Review List",
        "",
        "The following assets are the highest priority for manual review:",
        "",
        "| # | Host | Reason |",
        "|---|------|--------|",
    ]
    for i, a in enumerate(data.get("priority_list", []), 1):
        reason = ", ".join(a.get("flags", [])) or "Alive asset — verify ownership and purpose"
        lines.append(f"| {i} | `{a['host']}` | {reason} |")
    lines.append("")

    lines += [
        "---",
        "",
        "## Discovery Sources",
        "",
    ]
    for source, hosts in data.get("sources", {}).items():
        lines.append(f"### {source}")
        if hosts:
            lines.extend(f"- `{h}`" for h in sorted(hosts))
        else:
            lines.append("- _No assets discovered from this source._")
        lines.append("")

    lines += [
        "---",
        "",
        "_Report generated by BSL Passive Asset Mapper — Brighouse Security Labs._  ",
        "_For authorised use only. Do not distribute without client consent._",
    ]
    return "\n".join(lines)


def build_csv(assets: List[Dict[str, Any]]) -> str:
    import io
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=[
        "host", "resolves", "a_records", "aaaa_records",
        "https_ok", "http_ok", "status_code", "redirect_to",
        "title", "platform", "flags", "dead_dns", "parked",
    ])
    writer.writeheader()
    for a in assets:
        row = dict(a)
        row["a_records"]    = "; ".join(a.get("a_records", []))
        row["aaaa_records"]  = "; ".join(a.get("aaaa_records", []))
        row["flags"]         = "; ".join(a.get("flags", []))
        writer.writerow(row)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Core audit runner
# ---------------------------------------------------------------------------

def run_audit(domain: str, extra_hosts: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Discover and lightly probe all externally visible assets for *domain*.
    Returns structured data ready for terminal output and file export.
    """
    # Normalise domain
    domain = domain.lower().strip().lstrip("http://").lstrip("https://").rstrip("/")

    discovered: Dict[str, Set[str]] = {
        "Certificate Transparency (crt.sh)": set(),
        "DNS Records":                        set(),
        "sitemap.xml":                        set(),
        "robots.txt":                         set(),
        "User-Provided":                      set(),
    }

    console.log("[cyan]Querying crt.sh (Certificate Transparency)...[/cyan]")
    discovered["Certificate Transparency (crt.sh)"] = discover_via_crt_sh(domain)

    console.log("[cyan]Checking DNS records...[/cyan]")
    discovered["DNS Records"] = discover_via_dns(domain)

    console.log("[cyan]Checking sitemap.xml...[/cyan]")
    discovered["sitemap.xml"] = discover_via_sitemap(domain)

    console.log("[cyan]Checking robots.txt...[/cyan]")
    discovered["robots.txt"] = discover_via_robots(domain)

    # Always include the root domain
    all_hosts: Set[str] = {domain}
    for hosts in discovered.values():
        all_hosts.update(hosts)

    if extra_hosts:
        for h in extra_hosts:
            h = h.strip().lower()
            if h:
                all_hosts.add(h)
                discovered["User-Provided"].add(h)

    total_discovered = len(all_hosts)
    console.log(f"[green]{total_discovered} unique host(s) to probe.[/green]")

    # --- Per-host probing ---
    assets: List[Dict[str, Any]] = []
    for i, host in enumerate(sorted(all_hosts), 1):
        console.log(f"  [{i}/{total_discovered}] Probing: {host}")
        result = probe_host(host)
        assets.append(result)
        time.sleep(RATE_DELAY)  # polite rate limiting

    debris_score = calculate_debris_score(assets, total_discovered)
    d_label      = debris_label(debris_score)
    priority     = priority_review_list(assets)

    # Convert sets to sorted lists for JSON serialisation
    sources_serialisable = {k: sorted(v) for k, v in discovered.items()}

    return {
        "domain":        domain,
        "assets":        assets,
        "sources":       sources_serialisable,
        "debris_score":  debris_score,
        "debris_label":  d_label,
        "priority_list": priority,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@app.command()
def main(
    domain: str = typer.Argument(..., help="Root domain to map (e.g. example.com)"),
    input_file: Optional[str] = typer.Option(
        None, "--input-file", "-i",
        help="Path to a newline-separated list of additional hostnames to include.",
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o",
        help="Base path for output files (without extension).",
    ),
    json_flag: bool     = typer.Option(False, "--json",     help="Export results as JSON."),
    markdown_flag: bool = typer.Option(False, "--markdown", help="Export results as Markdown."),
    csv_flag: bool      = typer.Option(False, "--csv",      help="Export results as CSV."),
    quiet: bool         = typer.Option(False, "--quiet", "-q",
                                       help="Suppress banner output. Prints JSON summary to stdout."),
) -> None:
    """
    BSL Passive Asset Mapper — discovers external assets via Certificate Transparency,
    DNS records, sitemap.xml, and robots.txt hints.
    No brute-forcing. No port scanning. No wordlists.
    """
    if not quiet:
        console.print(Panel(RESPONSIBLE_USE, border_style="yellow", expand=False))
        console.print()
        console.rule("[bold cyan]BSL Passive Asset Mapper[/bold cyan] — Brighouse Security Labs")
        console.print(f"\n  Target: [bold]{domain}[/bold]\n")

    # Load optional extra hosts
    extra_hosts: List[str] = []
    if input_file:
        try:
            extra_hosts = Path(input_file).read_text().splitlines()
        except OSError as e:
            console.print(f"[red]Could not read input file: {e}[/red]")

    # Suppress urllib3 InsecureRequestWarning since we use verify=False for mapping
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    data = run_audit(domain, extra_hosts=extra_hosts)

    assets      = data["assets"]
    d_score     = data["debris_score"]
    d_label     = data["debris_label"]
    priority    = data["priority_list"]

    if not quiet:
        # --- asset inventory table ---
        table = Table(
            title=f"[bold]External Asset Inventory — {domain}[/bold]",
            show_header=True,
            header_style="bold magenta",
            show_lines=True,
        )
        table.add_column("Host",      style="cyan",   no_wrap=True)
        table.add_column("DNS",       justify="center")
        table.add_column("HTTPS",     justify="center")
        table.add_column("HTTP",      justify="center")
        table.add_column("Status",    justify="center")
        table.add_column("Platform",  style="dim")
        table.add_column("Flags",     style="yellow")

        for a in assets:
            dns_ok  = "[green]✓[/green]" if a["resolves"] else "[red]✗[/red]"
            https_s = "[green]✓[/green]" if a["https_ok"] else "[red]✗[/red]"
            http_s  = "[green]✓[/green]" if a["http_ok"]  else "[red]✗[/red]"
            status  = str(a.get("status_code") or "—")
            flags   = ", ".join(a.get("flags", [])) or "—"
            table.add_row(
                a["host"], dns_ok, https_s, http_s,
                status, a.get("platform") or "—", flags,
            )
        console.print(table)
        console.print()

        debris_colour = {
            "Clean": "green", "Manageable": "cyan",
            "Messy": "yellow", "High Debris": "red",
        }.get(d_label, "white")

        console.print(f"  External Debris Score : [{debris_colour}][bold]{d_score}/100[/bold][/{debris_colour}]")
        console.print(f"  Debris Category       : [{debris_colour}]{d_label}[/{debris_colour}]")
        console.print(f"  Total Assets          : {len(assets)}")
        console.print()

        # --- priority list ---
        pri_table = Table(
            title="[bold]Priority Review List (Top 5)[/bold]",
            show_header=True,
            header_style="bold yellow",
            show_lines=True,
        )
        pri_table.add_column("#",      justify="right", width=3)
        pri_table.add_column("Host",   style="cyan")
        pri_table.add_column("Reason", style="yellow")

        for i, a in enumerate(priority, 1):
            reason = ", ".join(a.get("flags", [])) or "Alive asset — verify ownership"
            pri_table.add_row(str(i), a["host"], reason)
        console.print(pri_table)
        console.print()

    base = output or f"reports/{domain}_asset_map"

    if markdown_flag or output:
        md_path = Path(f"{base}.md")
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(build_markdown(domain, data), encoding="utf-8")
        if not quiet:
            console.print(f"  [green]✓[/green] Markdown saved → {md_path}")

    if json_flag or output:
        json_path = Path(f"{base}.json")
        json_path.parent.mkdir(parents=True, exist_ok=True)
        export = {k: data[k] for k in
                  ("domain", "debris_score", "debris_label", "assets",
                   "sources", "priority_list")}
        json_path.write_text(json.dumps(export, indent=2, default=list), encoding="utf-8")
        if not quiet:
            console.print(f"  [green]✓[/green] JSON saved     → {json_path}")

    if csv_flag:
        csv_path = Path(f"{base}.csv")
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        csv_path.write_text(build_csv(assets), encoding="utf-8")
        if not quiet:
            console.print(f"  [green]✓[/green] CSV saved      → {csv_path}")

    if quiet:
        print(json.dumps({
            "domain":       data["domain"],
            "asset_count":  len(assets),
            "debris_score": d_score,
            "debris_label": d_label,
        }))


if __name__ == "__main__":
    app()
