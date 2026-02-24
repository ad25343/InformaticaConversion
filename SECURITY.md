# Security Policy

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

If you discover a security issue in this project, report it privately:

1. Open a [GitHub Security Advisory](https://github.com/ad25343/InformaticaConversion/security/advisories/new) on this repository.
2. Alternatively, contact the maintainer directly via GitHub: [@ad25343](https://github.com/ad25343).

Include as much detail as you can:
- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept (without active exploitation)
- Any relevant log output or error messages
- The version or commit where you observed the issue

You will receive an acknowledgement within **72 hours** and a resolution update within **14 days** for confirmed issues.

---

## Scope

The following are **in scope** for this policy:

| Area | Examples |
|------|---------|
| Input handling | XXE injection, Zip Slip, path traversal via uploaded files |
| Authentication | Brute force, session fixation, auth bypass |
| Dependency CVEs | Vulnerabilities in pinned packages in `requirements.txt` |
| Secrets exposure | Hardcoded credentials in source code or generated output |
| Rate limiting | Endpoints that could be abused to incur API costs |
| Generated code | Security issues Claude introduces into PySpark/dbt/Python output |

The following are **out of scope**:

- Findings already covered by automated scanning (CVEs flagged in CI `pip-audit` runs)
- Social engineering of maintainers
- Issues requiring physical access to the host machine
- Denial of service via the Claude API itself (report to [Anthropic](https://www.anthropic.com/security))

---

## Current Security Architecture

Key protections implemented in this version:

| Threat | Mitigation |
|--------|-----------|
| XXE injection | `safe_xml_parser()` — DTD loading and entity resolution disabled on every lxml parse |
| Zip Slip | `safe_zip_extract()` — entry paths normalised with `posixpath.normpath` and checked against virtual root |
| Zip Bomb | `safe_zip_extract()` — total extracted bytes and entry count capped by env-configurable limits |
| Upload abuse | `validate_upload_size()` — HTTP 413 on every upload stream; configurable via `MAX_UPLOAD_MB` |
| Credentials in XML | `scan_xml_for_secrets()` — scans uploaded Informatica XML for plaintext passwords before processing |
| Rate limiting | `slowapi` — `POST /api/jobs`, `POST /api/jobs/zip`, `POST /login` rate-limited per IP |
| Insecure generated code | Step 8 security scan — bandit (Python), YAML regex scan, Claude review; CRITICAL gate blocks pipeline |
| Secrets in generated tests | Step 10 test files re-scanned; findings merged into Step 8 security report |
| Default credentials | Startup warnings logged if `SECRET_KEY` or `APP_PASSWORD` are not set |
| Session security | `httponly` + `samesite=lax` cookies; `secure` flag enabled when `HTTPS=true` |

---

## Disclosure Timeline

| Day | Action |
|-----|--------|
| 0 | Report received |
| 1–3 | Acknowledgement sent to reporter |
| 1–7 | Issue assessed and severity assigned |
| 7–14 | Fix developed and reviewed |
| 14 | Fix released; reporter notified |
| 14+ | Public disclosure (coordinated with reporter) |

For CRITICAL findings we aim for a fix within **7 days**.

---

## Supported Versions

Only the latest release on the `main` branch receives security fixes. Older commits are not patched.
