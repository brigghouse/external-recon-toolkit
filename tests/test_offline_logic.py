"""Offline unit tests: pure analysis/scoring logic, no network or DNS access."""

import bsl_domain_doctor as dd
import bsl_passive_asset_mapper as pam
import bsl_web_surface_auditor as wsa


# --- Domain Doctor -----------------------------------------------------------
def test_spf_missing():
    r = dd.analyse_spf(["google-site-verification=abc"])
    assert r["found"] is False and r["severity"] == "High"


def test_spf_policies():
    assert dd.analyse_spf(["v=spf1 include:_spf.google.com -all"])["policy"] == "-all"
    assert dd.analyse_spf(["v=spf1 include:_spf.google.com -all"])["severity"] == "Info"
    assert dd.analyse_spf(["v=spf1 ~all"])["severity"] == "Low"
    assert dd.analyse_spf(["v=spf1 ?all"])["severity"] == "Medium"
    assert dd.analyse_spf(["v=spf1 +all"])["severity"] == "High"


def test_spf_multiple_records_flagged():
    r = dd.analyse_spf(["v=spf1 -all", "v=spf1 ~all"])
    assert r["multiple"] is True and r["severity"] == "Medium"


def test_caa():
    assert dd.analyse_caa([])["severity"] == "Low"
    assert dd.analyse_caa(['0 issue "letsencrypt.org"'])["severity"] == "Info"


def test_mx_provider():
    assert dd.detect_mx_provider([]) == "No MX records"
    assert dd.detect_mx_provider(["mail.selfhosted.example"]) == "Unknown / Self-hosted"


def test_risk_score_capped_and_labels():
    assert dd.calculate_risk_score([{"severity": "High"}] * 50) == 100
    assert dd.calculate_risk_score([{"severity": "Info"}]) == 0
    assert dd.trust_posture_label(0) == "Strong"
    assert dd.trust_posture_label(30) == "Reasonable"
    assert dd.trust_posture_label(50) == "Needs Attention"
    assert dd.trust_posture_label(99) == "Weak"


# --- Web Surface Auditor -----------------------------------------------------
def test_header_analysis_flags_server_disclosure():
    findings = wsa.analyse_headers({"Server": "Apache/2.4.1"})
    server = next(f for f in findings if f["check"] == "Server Header")
    assert server["severity"] == "Low"
    clean = wsa.analyse_headers({})
    assert next(f for f in clean if f["check"] == "Server Header")["severity"] == "Info"


def test_web_score_and_labels():
    assert wsa.calculate_score([{"severity": "High"}] * 50) == 100
    assert wsa.launch_readiness_label(0) == "Ready"
    assert wsa.launch_readiness_label(20) == "Minor Issues"
    assert wsa.launch_readiness_label(40) == "Needs Fixes Before Launch"
    assert wsa.launch_readiness_label(90) == "High Risk Exposure"


# --- Passive Asset Mapper ----------------------------------------------------
def test_title_and_platform_detection():
    assert pam.extract_title("<html><title> Hello </title></html>") == "Hello"
    assert pam.extract_title("<html></html>") is None
    assert pam.detect_platform({"CF-Ray": "1"}) == "Cloudflare"
    assert pam.detect_platform({"Server": "nginx/1.25"}) == "nginx"
    assert pam.detect_platform({}) is None


def test_debris_score_and_labels():
    assert pam.calculate_debris_score([], 0) == 0
    assets = [{"dead_dns": True, "parked": True, "flags": ["staging"]}] * 10
    assert pam.calculate_debris_score(assets, 10) == 100
    assert pam.debris_label(0) == "Clean"
    assert pam.debris_label(30) == "Manageable"
    assert pam.debris_label(50) == "Messy"
    assert pam.debris_label(90) == "High Debris"
