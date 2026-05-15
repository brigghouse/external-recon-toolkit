# Scoring Model

**Brighouse Security Labs — External Recon Toolkit**

---

## Overview

Each tool produces a numeric risk score from **0 to 100** and a human-readable label. Higher scores indicate greater security exposure. The scores are intentionally simple and additive — they are designed to communicate severity clearly to non-technical stakeholders, not to replace expert judgement.

---

## Severity Bands

All findings are assigned one of four severity levels:

| Severity | Description |
|----------|-------------|
| **High** | Significant security gap. Likely to result in meaningful risk if unaddressed. Immediate attention recommended. |
| **Medium** | Noteworthy gap or misconfiguration. Should be addressed within the sprint or review cycle. |
| **Low** | Best-practice gap. Relatively low impact but worth fixing for a mature security posture. |
| **Info** | Informational. No action required. Confirms something is in place or provides context. |

---

## Score Calculation

Each finding contributes to the cumulative risk score:

| Severity | Points Added |
|----------|-------------|
| High | +25 |
| Medium | +12 |
| Low | +5 |
| Info | +0 |

The total is capped at **100**. A perfect score (0) would require all checks to return Info-level findings.

---

## Domain Doctor — Trust Posture

| Score Range | Trust Posture Label | Interpretation |
|-------------|--------------------|-|
| 0 – 15 | **Strong** | Email authentication and DNS configuration is well-maintained. |
| 16 – 35 | **Reasonable** | Core controls are present; some best-practice gaps remain. |
| 36 – 60 | **Needs Attention** | Multiple gaps that present real exposure. A remediation plan is recommended. |
| 61 – 100 | **Weak** | Significant exposure. Prompt remediation required. |

---

## Web Surface Auditor — Launch Readiness

| Score Range | Launch Readiness Label | Interpretation |
|-------------|------------------------|----------------|
| 0 – 10 | **Ready** | Security configuration meets best practice. Suitable for production. |
| 11 – 30 | **Minor Issues** | Small number of best-practice gaps. Low risk, but worth fixing. |
| 31 – 55 | **Needs Fixes Before Launch** | Several configuration gaps that should be resolved before going live. |
| 56 – 100 | **High Risk Exposure** | Significant security gaps. Do not launch without remediation. |

---

## Passive Asset Mapper — External Debris Score

The External Debris Score measures surface clutter rather than exploitability. Factors:

| Factor | Contribution |
|--------|-------------|
| Asset volume (per asset) | +3 pts, max 30 |
| Dead DNS entry | +5 pts each |
| Sensitive-looking hostname (staging / dev / admin etc.) | +8 pts each |
| Parked-looking page | +3 pts each |

| Score Range | Label | Interpretation |
|-------------|-------|----------------|
| 0 – 15 | **Clean** | Minimal external footprint. Surface is well-managed. |
| 16 – 40 | **Manageable** | Moderate footprint. Ownership is likely tracked. |
| 41 – 65 | **Messy** | Significant clutter. Several assets warrant manual review. |
| 66 – 100 | **High Debris** | Large, unmanaged surface. Asset ownership and hygiene review recommended. |

---

## Limitations

Scores are a communication aid, not a definitive risk measurement. They do not account for:

- The criticality of the specific application
- Whether identified gaps are intentional or temporary
- Compensating controls in place at the network or application layer
- Threat modelling context specific to the client

Always combine automated scores with professional judgement and client context.

---

_Brighouse Security Labs — External Recon Toolkit_
