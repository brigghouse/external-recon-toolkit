# Responsible Use Policy

**Brighouse Security Labs — External Recon Toolkit**

---

## Overview

This toolkit is provided for use by security professionals conducting **authorised external security reviews** only.

By using this software you confirm that:

1. You have **explicit written permission** from the owner of any system you target.
2. You are operating within the scope agreed with your client.
3. You understand and accept the terms in the [LICENSE](../LICENSE) file.

---

## Authorised Use Cases

- External security snapshots as part of a contracted engagement
- Pre-launch security reviews for your own websites and domains
- Ongoing hygiene checks for domains and services you own and operate
- Security awareness assessments commissioned by the asset owner

---

## Prohibited Use

Do not use this toolkit to:

- Assess systems you do not own and have not received **explicit written permission** to test
- Conduct reconnaissance as a precursor to unauthorised access
- Map or enumerate assets belonging to third parties without engagement agreement
- Circumvent security controls of any kind
- Collect information for malicious purposes

Unauthorised use of this toolkit against third-party systems may violate laws including but not limited to:

- Computer Misuse Act 1990 (UK)
- Computer Fraud and Abuse Act (US)
- Equivalent legislation in your jurisdiction

---

## Technical Safety Boundaries

This toolkit is deliberately constrained to passive, low-impact checks:

| Technique | Included |
|-----------|----------|
| DNS record lookups | ✅ Yes |
| Passive Certificate Transparency queries (crt.sh) | ✅ Yes |
| HTTP GET requests to known public endpoints | ✅ Yes |
| TLS certificate metadata inspection | ✅ Yes |
| Security header analysis | ✅ Yes |
| robots.txt / sitemap.xml / security.txt fetches | ✅ Yes |
| Port scanning | ❌ No |
| Directory or path brute forcing | ❌ No |
| Credential attacks | ❌ No |
| Subdomain brute forcing | ❌ No |
| Exploitation or payload injection | ❌ No |
| Aggressive or multi-threaded scanning | ❌ No |

---

## Responsible Disclosure

If you discover a significant vulnerability during an authorised review, follow responsible disclosure practices:

1. Document the finding clearly in your report.
2. Notify the asset owner privately.
3. Agree a reasonable remediation timeline before any public disclosure.
4. Reference the client's security.txt contact if available.

---

## Questions

If you have questions about the appropriate use of this toolkit, contact:  
sales@brighousesec.com

---

_Brighouse Security Labs — External Recon Toolkit_
