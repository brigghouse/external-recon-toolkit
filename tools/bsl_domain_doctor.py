#!/usr/bin/env python3
"""
bsl_domain_doctor.py — Brighouse Security Labs
================================================
Domain, DNS, and email security hygiene auditor.

Checks A, AAAA, MX, NS, TXT, SPF, DMARC, DKIM (passive), CAA,
MTA-STS, TLS-RPT, and BIMI records for a given domain.

Usage:
    python tools/bsl_domain_doctor.py example.com
    python tools/bsl_domain_doctor.py example.com --markdown --output reports/example
    python tools/bsl_domain_doctor.py example.com --json --quiet

AUTHORISED USE ONLY. See docs/responsible-use.md for policy.
"""

from __future__ import annotations

import datetime
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import dns.exception
import dns.resolver
import requests
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

__version__ = "1.0.0"
USER_AGENT = "BrighouseSec-External-Recon/1.0"
TIMEOUT = 10  # seconds for DNS and HTTP calls

# Common DKIM selectors to check passively via DNS.
# Includes selectors for major providers (Google, Microsoft, IONOS, Zoho, Proton Mail)
# plus generic names used by various platforms.
DKIM_SELECTORS: List[str] = [
    "default",
    "google",
    "selector1",
    "selector2",
    "s1",
    "s2",
    "s1-ionos",
    "s2-ionos",
    "s42582890",
    "k1",
    "smtp",
    "mail",
    "zoho",
    "protonmail",
    "protonmail2",
    "protonmail3",
]

# MX hostname keyword → friendly provider name
MX_PROVIDERS: Dict[str, str] = {
    "google":             "Google Workspace",
    "googlemail":         "Google Workspace",
    "outlook":            "Microsoft 365",
    "protection.outlook": "Microsoft 365",
    "ionos":              "IONOS",
    "zoho":               "Zoho Mail",
    "fastmail":           "Fastmail",
    "protonmail":         "Proton Mail",
    "proton.me":          "Proton Mail",
}

# Risk weight per severity band (used to compute overall score)
SEVERITY_WEIGHTS: Dict[str, int] = {
    "High":   25,
    "Medium": 12,
    "Low":     5,
    "Info":    0,
}

RESPONSIBLE_USE = (
    "[bold yellow]⚠  Responsible Use Notice[/bold yellow]\n"
    "This toolkit is intended for authorised security reviews only.\n"
    "Do not use it against systems you do not own or do not have "
    "explicit written permission to assess."
)

# ---------------------------------------------------------------------------
# Typer app + Rich console
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="bsl-domain-doctor",
    help="BSL Domain Doctor — DNS & email security hygiene auditor.",
    add_completion=False,
)
console = Console()


# ---------------------------------------------------------------------------
# DNS helpers
# ---------------------------------------------------------------------------

def _resolve(domain: str, rtype: str) -> List[str]:
    """
    Resolve DNS records of *rtype* for *domain*.
    Returns a list of string representations (empty list on any error).
    """
    try:
        answers = dns.resolver.resolve(domain, rtype, lifetime=TIMEOUT)
        return [r.to_text().strip('"') for r in answers]
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.exception.Timeout,
        dns.resolver.NoNameservers,
        dns.exception.DNSException,
    ):
        return []
    except Exception:  # noqa: BLE001
        return []


def get_a_records(domain: str)    -> List[str]: return _resolve(domain, "A")
def get_aaaa_records(domain: str) -> List[str]: return _resolve(domain, "AAAA")
def get_mx_records(domain: str)   -> List[str]: return _resolve(domain, "MX")
def get_ns_records(domain: str)   -> List[str]: return _resolve(domain, "NS")
def get_txt_records(domain: str)  -> List[str]: return _resolve(domain, "TXT")
def get_caa_records(domain: str)  -> List[str]: return _resolve(domain, "CAA")


# ---------------------------------------------------------------------------
# SPF analysis
# ---------------------------------------------------------------------------

def analyse_spf(txt_records: List[str]) -> Dict[str, Any]:
    """
    Inspect TXT records for SPF and assess policy strength.
    Returns a finding dict compatible with the findings list.
    """
    spf_records = [r for r in txt_records if r.lower().startswith("v=spf1")]

    base: Dict[str, Any] = {
        "found": False,
        "records": spf_records,
        "multiple": False,
        "policy": None,
    }

    if not spf_records:
        return {**base, "severity": "High",
                "finding": "No SPF record found.",
                "recommendation": (
                    "Publish an SPF record to authorise legitimate sending mail servers. "
                    "Example: v=spf1 include:_spf.google.com -all")}

    base["found"] = True

    if len(spf_records) > 1:
        base["multiple"] = True
        return {**base, "severity": "Medium",
                "finding": f"Multiple SPF records found ({len(spf_records)}). "
                           "Only one SPF record is valid per RFC 7208.",
                "recommendation": "Merge all SPF directives into a single TXT record."}

    spf = spf_records[0].lower()

    if "+all" in spf:
        return {**base, "policy": "+all", "severity": "High",
                "finding": "SPF uses +all (pass all) — any server may send mail as this domain.",
                "recommendation": "Replace +all with -all or ~all immediately."}
    if "~all" in spf:
        return {**base, "policy": "~all", "severity": "Low",
                "finding": "SPF uses ~all (softfail). Unauthorised senders are delivered but flagged.",
                "recommendation": "Upgrade to -all once all sending sources are confirmed."}
    if "-all" in spf:
        return {**base, "policy": "-all", "severity": "Info",
                "finding": "SPF uses -all (hardfail). Strong policy in place.",
                "recommendation": "Keep the SPF record updated as sending infrastructure changes."}
    if "?all" in spf:
        return {**base, "policy": "?all", "severity": "Medium",
                "finding": "SPF uses ?all (neutral). No enforcement is applied.",
                "recommendation": "Upgrade to ~all or -all."}

    return {**base, "policy": "unknown", "severity": "Low",
            "finding": "SPF record found but no explicit 'all' mechanism detected.",
            "recommendation": "Add an explicit -all or ~all qualifier."}


# ---------------------------------------------------------------------------
# DMARC analysis
# ---------------------------------------------------------------------------

def analyse_dmarc(domain: str) -> Dict[str, Any]:
    """
    Look up _dmarc.<domain> and assess the DMARC policy strength.
    """
    records = get_txt_records(f"_dmarc.{domain}")
    dmarc_records = [r for r in records if r.lower().startswith("v=dmarc1")]

    if not dmarc_records:
        return {
            "found": False, "record": None, "policy": None,
            "severity": "High",
            "finding": "No DMARC record found.",
            "recommendation": (
                "Publish a DMARC record at _dmarc.{domain}. "
                "Start with p=none and an rua= reporting address to monitor, "
                "then progress to p=quarantine and p=reject."
            ),
        }

    record = dmarc_records[0]
    match = re.search(r"\bp=(\w+)", record, re.IGNORECASE)
    policy = match.group(1).lower() if match else "unknown"

    if policy == "none":
        sev, note, rec = ("Medium",
                          "DMARC policy is p=none (monitoring only). No enforcement is applied.",
                          "Review rua aggregate reports, then progress to p=quarantine or p=reject.")
    elif policy == "quarantine":
        sev, note, rec = ("Low",
                          "DMARC policy is p=quarantine. Failing mail is sent to junk/spam.",
                          "Consider upgrading to p=reject once mail flows are stable.")
    elif policy == "reject":
        sev, note, rec = ("Info",
                          "DMARC policy is p=reject. Full enforcement in place.",
                          "Ensure rua/ruf reporting addresses are monitored.")
    else:
        sev, note, rec = ("Medium",
                          f"DMARC record found but policy value is unexpected: {policy}.",
                          "Review the DMARC record for correctness.")

    return {"found": True, "record": record, "policy": policy,
            "severity": sev, "finding": note, "recommendation": rec}


# ---------------------------------------------------------------------------
# DKIM passive check
# ---------------------------------------------------------------------------

def check_dkim(domain: str) -> List[Dict[str, Any]]:
    """
    Passively probe common DKIM selector sub-domains via TXT DNS lookups.
    No brute-forcing — only a fixed list of well-known selectors.
    """
    results = []
    for selector in DKIM_SELECTORS:
        lookup = f"{selector}._domainkey.{domain}"
        records = get_txt_records(lookup)
        # A DKIM record contains 'v=DKIM1' or at minimum a 'p=' public key field
        found = any("v=dkim1" in r.lower() or ("p=" in r.lower() and "v=" in r.lower())
                    for r in records)
        results.append({
            "selector": selector,
            "lookup": lookup,
            "found": found,
            "record": records[0][:120] if found and records else None,
        })
    return results


# ---------------------------------------------------------------------------
# MTA-STS check
# ---------------------------------------------------------------------------

def check_mta_sts(domain: str) -> Dict[str, Any]:
    """
    Check for MTA-STS by looking up the TXT record and fetching the policy file.
    """
    txt_records = get_txt_records(f"_mta-sts.{domain}")
    txt_found = any("v=sts1" in r.lower() for r in txt_records)

    policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    policy_reachable = False
    try:
        resp = requests.get(policy_url, timeout=TIMEOUT,
                            headers={"User-Agent": USER_AGENT}, allow_redirects=True)
        policy_reachable = resp.status_code == 200
    except requests.RequestException:
        pass

    configured = txt_found and policy_reachable
    return {
        "txt_found": txt_found,
        "txt_records": txt_records,
        "policy_reachable": policy_reachable,
        "policy_url": policy_url,
        "severity": "Info" if configured else "Low",
        "finding": ("MTA-STS configured — TXT record and policy file both present."
                    if configured else "MTA-STS not fully configured."),
        "recommendation": (
            "No action required. Periodically verify the policy file is accessible."
            if configured else
            "Implement MTA-STS to enforce TLS for inbound SMTP. "
            "Publish a _mta-sts TXT record and host the mta-sts.txt policy file."
        ),
    }


# ---------------------------------------------------------------------------
# TLS-RPT check
# ---------------------------------------------------------------------------

def check_tls_rpt(domain: str) -> Dict[str, Any]:
    records = get_txt_records(f"_smtp._tls.{domain}")
    found = any("v=tlsrpt1" in r.lower() for r in records)
    return {
        "found": found, "records": records,
        "severity": "Info" if found else "Low",
        "finding": "TLS-RPT record found." if found else "No TLS-RPT record found.",
        "recommendation": (
            "No action required."
            if found else
            "Add a TLS-RPT record at _smtp._tls.<domain> with a rua= mailto address "
            "to receive SMTP TLS failure reports."
        ),
    }


# ---------------------------------------------------------------------------
# BIMI check
# ---------------------------------------------------------------------------

def check_bimi(domain: str) -> Dict[str, Any]:
    records = get_txt_records(f"default._bimi.{domain}")
    found = any("v=bimi1" in r.lower() for r in records)
    return {
        "found": found, "records": records,
        "severity": "Info",
        "finding": "BIMI record found." if found else "No BIMI record (optional brand indicator).",
        "recommendation": (
            "No action required."
            if found else
            "BIMI is optional but boosts brand trust in supported email clients. "
            "Requires p=reject DMARC and a verified SVG logo."
        ),
    }


# ---------------------------------------------------------------------------
# CAA analysis
# ---------------------------------------------------------------------------

def analyse_caa(caa_records: List[str]) -> Dict[str, Any]:
    found = bool(caa_records)
    return {
        "found": found, "records": caa_records,
        "severity": "Info" if found else "Low",
        "finding": ("CAA records restrict certificate issuance to authorised CAs."
                    if found else "No CAA records found."),
        "recommendation": (
            "Keep CAA records updated as your CA strategy evolves."
            if found else
            "Add CAA records to limit which Certificate Authorities may issue "
            "TLS certificates for this domain. Example: 0 issue \"letsencrypt.org\""
        ),
    }


# ---------------------------------------------------------------------------
# MX provider detection
# ---------------------------------------------------------------------------

def detect_mx_provider(mx_records: List[str]) -> str:
    haystack = " ".join(mx_records).lower()
    for keyword, label in MX_PROVIDERS.items():
        if keyword in haystack:
            return label
    if mx_records:
        return "Unknown / Self-hosted"
    return "No MX records"


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def calculate_risk_score(findings: List[Dict[str, Any]]) -> int:
    """Sum severity weights; cap at 100. Higher = more risk."""
    return min(sum(SEVERITY_WEIGHTS.get(f.get("severity", "Info"), 0)
                   for f in findings), 100)


def trust_posture_label(score: int) -> str:
    if score <= 15:   return "Strong"
    if score <= 35:   return "Reasonable"
    if score <= 60:   return "Needs Attention"
    return "Weak"


# ---------------------------------------------------------------------------
# Markdown report builder
# ---------------------------------------------------------------------------

def build_markdown(domain: str, data: Dict[str, Any]) -> str:
    score   = data["score"]
    posture = data["posture"]
    now     = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        f"# Domain Doctor Report — {domain}",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Generated | {now} |",
        f"| Tool | BSL Domain Doctor v{__version__} — Brighouse Security Labs |",
        f"| Trust Posture | **{posture}** |",
        f"| Risk Score | **{score}/100** |",
        f"| MX Provider | {data['mx_provider']} |",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"This report summarises the external DNS and email security posture for **{domain}**. "
        "It is produced as part of an authorised external security review.",
        "",
        f"The domain received a risk score of **{score}/100** (higher = more risk) with "
        f"a trust posture of **{posture}**.",
        "",
        "---",
        "",
        "## DNS Overview",
        "",
    ]

    for rtype, records in data.get("dns_records", {}).items():
        lines.append(f"### {rtype} Records")
        if records:
            lines.extend(f"- `{r}`" for r in records)
        else:
            lines.append("- _None found_")
        lines.append("")

    lines += [
        "---",
        "",
        "## Email Authentication Review",
        "",
        f"**Detected MX Provider:** {data['mx_provider']}",
        "",
        "### DKIM Selector Probe (Passive)",
        "",
        "| Selector | Lookup | Found |",
        "|----------|--------|-------|",
    ]
    for d in data.get("dkim_results", []):
        tick = "✅ Yes" if d["found"] else "❌ No"
        lines.append(f"| `{d['selector']}` | `{d['lookup']}` | {tick} |")
    lines.append("")

    lines += [
        "---",
        "",
        "## Findings",
        "",
        "| # | Check | Severity | Summary |",
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
    remediation_severities = {"High", "Medium", "Low"}
    for i, f in enumerate(data["findings"], 1):
        if f["severity"] in remediation_severities:
            lines.append(f"**{i}. {f['check']} ({f['severity']}):** {f['recommendation']}")
            lines.append("")

    lines += ["---", "", "## Retest Checklist", ""]
    for f in data["findings"]:
        lines.append(f"- [ ] Verify fix for: **{f['check']}** _{f['severity']}_")
    lines.append("")

    lines += [
        "---",
        "",
        "_Report generated by BSL Domain Doctor — Brighouse Security Labs._  ",
        "_For authorised use only. Do not distribute without client consent._",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Core audit runner
# ---------------------------------------------------------------------------

def run_audit(domain: str) -> Dict[str, Any]:
    """
    Execute all DNS and email security checks for *domain*.
    Returns a structured dict suitable for terminal display and export.
    """
    findings: List[Dict[str, Any]] = []
    dns_records: Dict[str, List[str]] = {}

    # --- A records ---
    a = get_a_records(domain)
    dns_records["A"] = a
    findings.append({
        "check": "A Records",
        "severity": "Info",
        "finding": f"{len(a)} A record(s) found." if a else "No A records found.",
        "evidence": "\n".join(a),
        "recommendation": "Confirm A records point to expected hosting infrastructure.",
    })

    # --- AAAA records ---
    aaaa = get_aaaa_records(domain)
    dns_records["AAAA"] = aaaa
    findings.append({
        "check": "AAAA Records",
        "severity": "Info",
        "finding": f"{len(aaaa)} AAAA (IPv6) record(s) found." if aaaa else "No IPv6 AAAA records.",
        "evidence": "\n".join(aaaa),
        "recommendation": "Ensure AAAA records are accurate if IPv6 is in use.",
    })

    # --- MX records ---
    mx = get_mx_records(domain)
    dns_records["MX"] = mx
    findings.append({
        "check": "MX Records",
        "severity": "High" if not mx else "Info",
        "finding": (f"{len(mx)} MX record(s) found." if mx
                    else "No MX records found — mail delivery may not be configured."),
        "evidence": "\n".join(mx),
        "recommendation": ("Confirm MX records are correct and tested."
                           if mx else "Configure MX records with your mail provider."),
    })

    # --- NS records ---
    ns = get_ns_records(domain)
    dns_records["NS"] = ns
    findings.append({
        "check": "NS Records",
        "severity": "Info",
        "finding": f"{len(ns)} NS record(s) found." if ns else "No NS records found.",
        "evidence": "\n".join(ns),
        "recommendation": "Ensure nameservers are intentional and DNSSEC is considered.",
    })

    # --- TXT (all, for reference) ---
    txt = get_txt_records(domain)
    dns_records["TXT"] = txt

    # --- SPF ---
    spf_result = analyse_spf(txt)
    findings.append({
        "check": "SPF Record",
        "severity": spf_result["severity"],
        "finding": spf_result["finding"],
        "evidence": "\n".join(spf_result["records"]),
        "recommendation": spf_result["recommendation"],
    })

    # --- DMARC ---
    dmarc_result = analyse_dmarc(domain)
    findings.append({
        "check": "DMARC Record",
        "severity": dmarc_result["severity"],
        "finding": dmarc_result["finding"],
        "evidence": dmarc_result.get("record") or "",
        "recommendation": dmarc_result["recommendation"],
    })

    # --- DKIM (passive) ---
    dkim_results = check_dkim(domain)
    dkim_found = [r["selector"] for r in dkim_results if r["found"]]
    findings.append({
        "check": "DKIM Selectors (Passive)",
        "severity": "Low" if not dkim_found else "Info",
        "finding": (
            f"DKIM records found for: {', '.join(dkim_found)}."
            if dkim_found else
            "No DKIM records found for the selectors checked. "
            "DKIM may still be configured using a provider-specific selector not included "
            "in this check. Verify with the mail provider."
        ),
        "evidence": "\n".join(
            f"{r['lookup']} → {'FOUND' if r['found'] else 'not found'}"
            for r in dkim_results
        ),
        "recommendation": (
            "Ensure all active DKIM selectors are documented and rotated periodically."
            if dkim_found else
            "Confirm DKIM is enabled in your mail provider. "
            "Contact the provider for the correct selector name."
        ),
    })

    # --- CAA ---
    caa = get_caa_records(domain)
    dns_records["CAA"] = caa
    caa_result = analyse_caa(caa)
    findings.append({
        "check": "CAA Records",
        "severity": caa_result["severity"],
        "finding": caa_result["finding"],
        "evidence": "\n".join(caa),
        "recommendation": caa_result["recommendation"],
    })

    # --- MTA-STS ---
    mta = check_mta_sts(domain)
    findings.append({
        "check": "MTA-STS",
        "severity": mta["severity"],
        "finding": mta["finding"],
        "evidence": (
            f"TXT records: {mta['txt_records']}\n"
            f"Policy URL: {mta['policy_url']}\n"
            f"Policy reachable: {mta['policy_reachable']}"
        ),
        "recommendation": mta["recommendation"],
    })

    # --- TLS-RPT ---
    tls_rpt = check_tls_rpt(domain)
    findings.append({
        "check": "TLS-RPT",
        "severity": tls_rpt["severity"],
        "finding": tls_rpt["finding"],
        "evidence": "\n".join(tls_rpt["records"]),
        "recommendation": tls_rpt["recommendation"],
    })

    # --- BIMI ---
    bimi = check_bimi(domain)
    findings.append({
        "check": "BIMI",
        "severity": bimi["severity"],
        "finding": bimi["finding"],
        "evidence": "\n".join(bimi["records"]),
        "recommendation": bimi["recommendation"],
    })

    score   = calculate_risk_score(findings)
    posture = trust_posture_label(score)

    return {
        "domain":       domain,
        "dns_records":  dns_records,
        "findings":     findings,
        "dkim_results": dkim_results,
        "mx_provider":  detect_mx_provider(mx),
        "score":        score,
        "posture":      posture,
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

@app.command()
def main(
    domain: str = typer.Argument(..., help="Target domain to audit (e.g. example.com)"),
    output: Optional[str] = typer.Option(
        None, "--output", "-o",
        help="Base path for output files (without extension). "
             "Defaults to reports/<domain>_domain_doctor.",
    ),
    json_flag: bool = typer.Option(False, "--json", help="Export results as JSON."),
    markdown_flag: bool = typer.Option(False, "--markdown", help="Export results as Markdown."),
    quiet: bool = typer.Option(False, "--quiet", "-q",
                               help="Suppress banner and decorative output. "
                                    "Prints a one-line JSON summary to stdout."),
) -> None:
    """
    BSL Domain Doctor — DNS & email security hygiene auditor.

    Audits SPF, DMARC, DKIM (passive), MTA-STS, TLS-RPT, BIMI, CAA,
    and core DNS records. Produces a risk score and Trust Posture label.
    """
    if not quiet:
        console.print(Panel(RESPONSIBLE_USE, border_style="yellow", expand=False))
        console.print()
        console.rule("[bold cyan]BSL Domain Doctor[/bold cyan] — Brighouse Security Labs")
        console.print(f"\n  Target: [bold]{domain}[/bold]\n")

    with console.status(f"[cyan]Auditing {domain}...[/cyan]", spinner="dots"):
        data = run_audit(domain)

    score   = data["score"]
    posture = data["posture"]

    if not quiet:
        # --- findings table ---
        table = Table(
            title=f"[bold]Domain Doctor — {domain}[/bold]",
            show_header=True,
            header_style="bold magenta",
            show_lines=True,
        )
        table.add_column("Check",    style="cyan",  no_wrap=True, min_width=28)
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

        posture_colour = {
            "Strong": "green", "Reasonable": "cyan",
            "Needs Attention": "yellow", "Weak": "red",
        }.get(posture, "white")

        console.print(f"  Trust Posture : [{posture_colour}][bold]{posture}[/bold][/{posture_colour}]")
        console.print(f"  Risk Score    : [bold]{score}/100[/bold]  (higher = more risk)")
        console.print(f"  MX Provider   : {data['mx_provider']}")
        console.print()

    # --- export ---
    base = output or f"reports/{domain}_domain_doctor"

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
                  ("domain", "score", "posture", "mx_provider", "findings",
                   "dns_records", "dkim_results")}
        json_path.write_text(json.dumps(export, indent=2), encoding="utf-8")
        if not quiet:
            console.print(f"  [green]✓[/green] JSON saved     → {json_path}")

    if quiet:
        # Machine-readable one-liner for scripting
        print(json.dumps({"domain": data["domain"],
                          "score": score, "posture": posture,
                          "mx_provider": data["mx_provider"]}))


if __name__ == "__main__":
    app()
