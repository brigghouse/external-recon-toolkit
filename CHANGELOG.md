# Changelog

All notable changes to this project will be documented in this file.

---

## [Unreleased]

### Added

- Offline unit tests (`tests/`) for SPF/CAA/MX analysis, header analysis, scoring and label thresholds, title/platform detection and debris scoring.
- CI now runs the test suite in addition to syntax and `--help` smoke checks.

### Fixed

- Clone URL and contact details in the README and responsible-use policy.

---

## [v1.0.0] — 2026-05-15

Initial public release.

### Added

- **BSL Domain Doctor** (`tools/bsl_domain_doctor.py`) — DNS and email security hygiene auditor covering SPF, DMARC, DKIM (passive, 17 selectors including IONOS-specific), MTA-STS, TLS-RPT, BIMI, and CAA records. Produces Trust Posture labels and risk scores.
- **BSL Web Surface Auditor** (`tools/bsl_web_surface_auditor.py`) — Web surface security checker covering HTTPS enforcement, TLS certificate validity, security headers, cookie flags, security.txt, and technology disclosure. Produces Launch Readiness verdicts and risk scores.
- **BSL Passive Asset Mapper** (`tools/bsl_passive_asset_mapper.py`) — Passive external asset discovery using Certificate Transparency logs (crt.sh), DNS MX/NS records, sitemap.xml, and robots.txt. Produces External Debris Scores and a Priority Review List.
- Markdown, JSON, and CSV report export options across all three tools.
- `docs/responsible-use.md` — Responsible use and legal boundary policy.
- `docs/scoring-model.md` — Full explanation of the risk scoring methodology.
- `docs/methodology.md` — Assessment methodology documentation.
- `examples/` — Example output reports for all three tools.
- `requirements.txt` — Pinned Python dependencies (Python 3.11+).
- `.gitignore` — Excludes virtual environments, generated reports, credentials, and IDE files.
- `LICENSE` — MIT licence, Copyright (c) 2026 Brighouse Security Labs.
- `.github/workflows/python-checks.yml` — GitHub Actions CI: syntax compilation and `--help` smoke tests for all three tools.
