"""
STEP 8a — Generated Code Security Scan Agent

Responsibilities
----------------
1. Run bandit static analysis on every Python / PySpark file produced by Step 7.
2. Ask Claude to perform a security-focused review of ALL generated files
   (Python, PySpark, dbt SQL, and config YAML) checking for:
     - Hardcoded credentials / secrets
     - SQL injection patterns
     - Insecure connection strings (plaintext passwords, no TLS)
     - World-readable file paths
     - Unsafe use of eval / exec
     - Insecure deserialization
3. Return a consolidated SecurityScanReport.

Why both bandit AND Claude?
- bandit is fast, deterministic, and covers well-known Python CVE patterns (B-codes).
- Claude catches stack-specific patterns bandit cannot: dbt Jinja injection,
  plaintext passwords in YAML, insecure Spark config flags, etc.

The SecurityScanReport is stored on the job and surfaced in the UI alongside
the Step 8 code quality review report.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Optional

import anthropic

from ..models.schemas import (
    ConversionOutput,
    SecurityFinding,
    SecurityScanReport,
)
from ..security import scan_python_with_bandit, scan_yaml_for_secrets

log = logging.getLogger("conversion.security_agent")

MODEL = os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-5-20250929")

# ── File-type routing ────────────────────────────────────────────────────────
# bandit only handles Python; YAML gets a dedicated regex scan; everything goes to Claude
_BANDIT_EXTENSIONS = {".py"}
_YAML_EXTENSIONS   = {".yaml", ".yml"}
_CLAUDE_SKIP_EXTENSIONS = {".pyc", ".pyo"}  # binary — never sent to Claude

# ── Claude security review prompt ───────────────────────────────────────────

_SECURITY_SYSTEM = """You are an expert application security engineer specialising
in data engineering workloads (PySpark, dbt, Python ETL, YAML config).

Your task: identify security vulnerabilities in auto-generated code produced by an
Informatica-to-modern-stack converter. The code was machine-generated — it may
inherit bad patterns from the original Informatica mapping definitions.

Be precise and concrete. Flag ONLY real issues, not style preferences.
Do not flag placeholder values that are clearly meant to be replaced (e.g. <YOUR_PASSWORD>).
"""

_SECURITY_PROMPT = """Review the following auto-generated {stack} files for security issues.

## Files to review
{files_section}

---

Check for ALL of the following and report each finding separately:

**Credentials & Secrets**
- Hardcoded passwords, API keys, tokens, or secrets in any file
- Connection strings with embedded credentials
- YAML / config files with plaintext secrets

**Injection Vulnerabilities**
- SQL injection: f-string or concatenation used to build SQL from variables
- dbt Jinja: unsafe use of `{{{{ var() }}}}` or raw SQL interpolation
- Shell injection: subprocess calls with user-controlled input

**Insecure Connections**
- JDBC/ODBC URLs without SSL/TLS parameters
- `ssl=false` or `verify=False` in connection configs
- Spark config disabling SSL (e.g. `spark.ssl.enabled=false`)

**Unsafe Code Patterns**
- Use of `eval()`, `exec()`, or `pickle` on external data
- `assert` statements used as security guards

**File & Path Security**
- World-readable output file paths (e.g. `/tmp/`, `/var/tmp/`)
- Paths constructed from unvalidated variables

Return ONLY a JSON object in this exact format:
{{
  "findings": [
    {{
      "filename": "the file where the issue was found",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "test_name": "short descriptive name (e.g. hardcoded_password)",
      "text": "clear description of the issue",
      "code": "the specific line or snippet (≤ 120 chars)",
      "line": null
    }}
  ],
  "summary": "1-3 sentence overall assessment",
  "recommendation": "APPROVED|REVIEW_RECOMMENDED|REQUIRES_FIXES"
}}

Rules:
- "APPROVED" → no significant issues found
- "REVIEW_RECOMMENDED" → LOW/MEDIUM findings only, human should glance over
- "REQUIRES_FIXES" → any HIGH or CRITICAL finding

If no issues are found return an empty findings list and "APPROVED".
"""


# ── Public entry point ───────────────────────────────────────────────────────

async def scan(
    conversion: ConversionOutput,
    mapping_name: Optional[str] = None,
) -> SecurityScanReport:
    """
    Run bandit + Claude security review on all generated files.

    Parameters
    ----------
    conversion  : ConversionOutput from Step 7 (conversion_agent).
    mapping_name: Human-readable name for logging / report label.

    Returns
    -------
    SecurityScanReport
    """
    name  = mapping_name or conversion.mapping_name
    stack = conversion.target_stack.value if hasattr(conversion.target_stack, "value") \
            else str(conversion.target_stack)

    all_findings: list[SecurityFinding] = []
    skipped_files: list[str] = []
    bandit_error: Optional[str] = None
    ran_bandit = False

    # ── 1. bandit scan (Python files only) ──────────────────────────────────
    log.info("security_agent: starting bandit scan for job mapping=%s", name)

    for filename, code in conversion.files.items():
        ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if ext not in _BANDIT_EXTENSIONS:
            continue

        result = scan_python_with_bandit(code, filename=filename)
        ran_bandit = True

        if result.get("error"):
            bandit_error = result["error"]
            log.warning("bandit error for %s: %s", filename, bandit_error)

        for f in result.get("findings", []):
            all_findings.append(SecurityFinding(
                source="bandit",
                test_id=f.get("test_id"),
                test_name=f.get("test_name"),
                severity=f.get("severity", "LOW"),
                confidence=f.get("confidence", ""),
                line=f.get("line"),
                filename=filename,
                text=f.get("text", ""),
                code=f.get("code", ""),
            ))

    log.info("security_agent: bandit finished, %d findings so far", len(all_findings))

    # ── 1b. YAML secrets scan (regex, fast, no subprocess) ──────────────────
    for filename, code in conversion.files.items():
        ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if ext not in _YAML_EXTENSIONS:
            continue
        yaml_findings = scan_yaml_for_secrets(code, filename=filename)
        for f in yaml_findings:
            all_findings.append(SecurityFinding(
                source="yaml_scan",
                test_name="plaintext_secret_in_yaml",
                severity=f.get("severity", "HIGH"),
                filename=filename,
                line=f.get("line"),
                text=f.get("message", ""),
                code=f.get("value_preview", ""),
            ))

    # ── 2. Claude security review (all files) ───────────────────────────────
    files_to_review: dict[str, str] = {
        fname: code
        for fname, code in conversion.files.items()
        if not any(fname.lower().endswith(skip) for skip in _CLAUDE_SKIP_EXTENSIONS)
    }

    claude_summary: Optional[str] = None
    claude_recommendation = "APPROVED"

    if files_to_review:
        files_section = _build_files_section(files_to_review)
        prompt = _SECURITY_PROMPT.format(stack=stack, files_section=files_section)

        try:
            client = anthropic.Anthropic()
            response = client.messages.create(
                model=MODEL,
                max_tokens=2048,
                system=_SECURITY_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = response.content[0].text.strip()
            parsed = _extract_json(raw)

            for f in parsed.get("findings", []):
                sev = f.get("severity", "LOW").upper()
                all_findings.append(SecurityFinding(
                    source="claude",
                    test_name=f.get("test_name"),
                    severity=sev,
                    filename=f.get("filename"),
                    text=f.get("text", ""),
                    code=(f.get("code") or "")[:200],
                    line=f.get("line"),
                ))

            claude_summary = parsed.get("summary")
            claude_recommendation = parsed.get("recommendation", "APPROVED")
            log.info("security_agent: Claude found %d additional findings", len(parsed.get("findings", [])))

        except Exception as exc:
            claude_summary = f"Claude security review could not complete: {exc}"
            log.warning("security_agent: Claude review error: %s", exc)

    # ── 3. Aggregate severity counts ─────────────────────────────────────────
    critical_count = sum(1 for f in all_findings if f.severity == "CRITICAL")
    high_count     = sum(1 for f in all_findings if f.severity == "HIGH")
    medium_count   = sum(1 for f in all_findings if f.severity == "MEDIUM")
    low_count      = sum(1 for f in all_findings if f.severity == "LOW")

    # ── 4. Final recommendation — most severe wins ────────────────────────────
    if critical_count > 0 or high_count > 0:
        recommendation = "REQUIRES_FIXES"
    elif medium_count > 0 or claude_recommendation == "REVIEW_RECOMMENDED":
        recommendation = "REVIEW_RECOMMENDED"
    else:
        recommendation = "APPROVED"

    log.info(
        "security_agent: done — critical=%d high=%d medium=%d low=%d recommendation=%s",
        critical_count, high_count, medium_count, low_count, recommendation,
    )

    return SecurityScanReport(
        mapping_name=name,
        target_stack=stack,
        ran_bandit=ran_bandit,
        bandit_error=bandit_error,
        findings=all_findings,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        recommendation=recommendation,
        claude_summary=claude_summary,
        skipped_files=skipped_files,
    )


# ── Helpers ──────────────────────────────────────────────────────────────────

def _build_files_section(files: dict[str, str]) -> str:
    """Format all files for the Claude prompt (truncated if very large)."""
    MAX_CHARS_PER_FILE = 4_000
    MAX_TOTAL_CHARS    = 24_000
    parts: list[str] = []
    total = 0

    for filename, code in files.items():
        code_truncated = code[:MAX_CHARS_PER_FILE]
        if len(code) > MAX_CHARS_PER_FILE:
            code_truncated += f"\n... [truncated — {len(code) - MAX_CHARS_PER_FILE} chars omitted]"

        block = f"### {filename}\n```\n{code_truncated}\n```"
        total += len(block)
        if total > MAX_TOTAL_CHARS:
            parts.append(f"### [remaining files omitted — total prompt size limit reached]")
            break
        parts.append(block)

    return "\n\n".join(parts)


async def scan_files(
    files: dict[str, str],
    mapping_name: str = "unknown",
    target_stack: str = "unknown",
    label: str = "generated files",
) -> SecurityScanReport:
    """
    Scan an arbitrary dict of {filename: code} — used to scan test files
    after Step 10 (test generation) without needing a full ConversionOutput.
    """
    from ..models.schemas import TargetStack

    # Wrap in a minimal ConversionOutput-like object
    class _FakeConversion:
        def __init__(self, files, name, stack):
            self.files = files
            self.mapping_name = name
            self.target_stack = stack
            self.parse_ok = True

    fake = _FakeConversion(files, mapping_name, target_stack)

    report = await scan(fake, mapping_name=f"{mapping_name} [{label}]")
    return report


def _extract_json(text: str) -> dict:
    """Extract the first JSON object from a Claude response."""
    # Try direct parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Find ```json ... ``` block
    import re
    m = re.search(r"```(?:json)?\s*(\{[\s\S]+?\})\s*```", text)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass

    # Find first { ... } block
    start = text.find("{")
    end   = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass

    log.warning("security_agent: could not parse Claude JSON response")
    return {"findings": [], "summary": "Parse error", "recommendation": "REVIEW_RECOMMENDED"}
