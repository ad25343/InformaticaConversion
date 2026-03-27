# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
security_knowledge.py — Cross-job security learning for the Informatica Conversion Tool.

Two complementary stores feed into every code generation:

  security_rules.yaml   — Hand-curated standing rules (non-negotiables that always apply).
                          Edit this file to lock in hard requirements for your environment.

  security_patterns.json — Auto-learned patterns built from Gate 2 findings across all jobs.
                           Every APPROVED / ACKNOWLEDGED job contributes its findings here.
                           Patterns grow in weight the more often they appear across jobs,
                           so the most common issues get the most emphasis in future prompts.

Both stores are read by conversion_agent.py and injected into every conversion prompt,
ensuring that knowledge gained from one job improves all future generations.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

log = logging.getLogger(__name__)

# ── File locations ────────────────────────────────────────────────────────────
# security_rules.yaml  — lives next to this module (committed to source control)
# security_patterns.json — lives in app/data/ (runtime state, gitignored)
_DATA_DIR     = Path(__file__).parent.parent / "data"
RULES_PATH    = Path(__file__).parent / "security_rules.yaml"
PATTERNS_PATH = _DATA_DIR / "security_patterns.json"

_DATA_DIR.mkdir(parents=True, exist_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# Standing rules (security_rules.yaml)
# ─────────────────────────────────────────────────────────────────────────────

def _load_default_rules_from_yaml() -> dict:
    """
    Load standing rules directly from security_rules.yaml for use as the
    in-code fallback. Called once at module level so _DEFAULT_RULES is always
    in sync with the YAML without maintaining a duplicate hardcoded list.
    """
    try:
        with RULES_PATH.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        if data.get("rules"):
            return data
    except Exception as exc:
        log.debug("Could not load security_rules.yaml (%s: %s) — using sentinel fallback.", type(exc).__name__, exc)
    # Absolute last resort if the file truly doesn't exist yet — single sentinel rule
    return {
        "rules": [{
            "id": "rule_creds_001",
            "severity": "CRITICAL",
            "category": "credentials",
            "description": "Never hardcode passwords, API keys, tokens, or secrets in generated code.",
            "guidance": (
                "Use os.environ.get('SECRET_NAME') or a secrets-manager client. "
                "Never assign literals like password='abc123' or api_key='sk-...'."
            ),
            "enabled": True,
        }]
    }


# _DEFAULT_RULES is now derived from the YAML file itself — always in sync,
# never a stale hardcoded copy.
_DEFAULT_RULES = _load_default_rules_from_yaml()


def _read_rules_yaml() -> list[dict]:
    """Open security_rules.yaml and return the raw rule list; may raise on I/O error."""
    with RULES_PATH.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return data.get("rules", [])


def load_rules() -> list[dict]:
    """Return all enabled standing security rules from security_rules.yaml.

    If the file does not exist it is seeded with sensible defaults on first call.
    """
    if not RULES_PATH.exists():
        _seed_rules()

    try:
        rules = _read_rules_yaml()
        return [r for r in rules if r.get("enabled", True)]
    except Exception as exc:
        log.warning("security_knowledge: failed to load rules: %s", exc)
        return _DEFAULT_RULES["rules"]


def _seed_rules() -> None:
    """Write the default rules file if it doesn't exist yet."""
    try:
        with RULES_PATH.open("w", encoding="utf-8") as fh:
            yaml.dump(_DEFAULT_RULES, fh, default_flow_style=False, allow_unicode=True, sort_keys=False)
        log.info("security_knowledge: seeded %s", RULES_PATH)
    except Exception as exc:
        log.warning("security_knowledge: could not seed rules file: %s", exc)


# ─────────────────────────────────────────────────────────────────────────────
# Auto-learned patterns (security_patterns.json)
# ─────────────────────────────────────────────────────────────────────────────

def _load_patterns_raw() -> dict:
    if not PATTERNS_PATH.exists():
        return {"patterns": []}
    try:
        with PATTERNS_PATH.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        log.warning("security_knowledge: could not read patterns: %s", exc)
        return {"patterns": []}


def _save_patterns_raw(data: dict) -> None:
    try:
        with PATTERNS_PATH.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
    except Exception as exc:
        log.warning("security_knowledge: could not save patterns: %s", exc)


def load_top_patterns(limit: int = 20) -> list[dict]:
    """Return the top `limit` patterns sorted by occurrence count (most common first)."""
    data = _load_patterns_raw()
    patterns = sorted(data.get("patterns", []), key=lambda p: p.get("occurrences", 0), reverse=True)
    return patterns[:limit]


def _update_existing_pattern(p: dict, finding: dict, job_id: str, now: str) -> None:
    """Increment occurrence counters and refresh optional fields on an existing pattern."""
    p["occurrences"] = p.get("occurrences", 1) + 1
    p["last_seen"]   = now
    if job_id not in p.get("job_ids", []):
        p.setdefault("job_ids", []).append(job_id)
    if finding.get("text") and len(finding["text"]) > len(p.get("description", "")):
        p["description"] = finding["text"]
    if finding.get("remediation"):
        p["remediation"] = finding["remediation"]


def _create_new_pattern(
    finding: dict,
    test_id: str,
    test_name: str,
    severity: str,
    job_id: str,
    now: str,
) -> dict:
    """Build and return a fresh pattern dict from a finding."""
    return {
        "id":          str(uuid.uuid4()),
        "test_id":     test_id,
        "test_name":   test_name,
        "severity":    severity,
        "source":      finding.get("source", "unknown"),
        "description": finding.get("text") or finding.get("description", ""),
        "remediation": finding.get("remediation", ""),
        "filename":    finding.get("filename", ""),
        "occurrences": 1,
        "first_seen":  now,
        "last_seen":   now,
        "job_ids":     [job_id],
    }


def _build_patterns_index(patterns: list[dict]) -> dict[tuple, dict]:
    """Return a lookup dict keyed by (normalised_id, severity) for deduplication."""
    return {
        (_normalise_key(p), p.get("severity", "").upper()): p
        for p in patterns
    }


def _extract_finding_key(finding: dict) -> tuple[str, str, str, tuple]:
    """Extract (test_id, test_name, severity, index_key) from a finding dict."""
    test_id   = (finding.get("test_id") or "").strip()
    test_name = next(
        (v.strip() for v in (finding.get("test_name"), finding.get("finding_type")) if v),
        "",
    )
    severity = (finding.get("severity") or "LOW").upper()
    key      = (_normalise_key({"test_id": test_id, "test_name": test_name}), severity)
    return test_id, test_name, severity, key


def _merge_finding_into_index(
    finding: dict,
    index: dict[tuple, dict],
    patterns: list[dict],
    job_id: str,
    now: str,
) -> None:
    """Merge one finding into the patterns index (update or create)."""
    test_id, test_name, severity, key = _extract_finding_key(finding)
    if key in index:
        _update_existing_pattern(index[key], finding, job_id, now)
    else:
        new_pattern = _create_new_pattern(finding, test_id, test_name, severity, job_id, now)
        patterns.append(new_pattern)
        index[key] = new_pattern


def _try_auto_promote(job_id: str) -> None:
    """Attempt to auto-promote recurring patterns; log but do not raise."""
    try:
        promoted = promote_patterns_to_rules(threshold=3)
        if promoted:
            log.info(
                "security_knowledge: auto-promoted %d pattern(s) to standing rules "
                "after recording findings from job %s",
                promoted, job_id,
            )
    except Exception as exc:
        log.warning("security_knowledge: auto-promotion failed (non-blocking): %s", exc)


def record_findings(job_id: str, findings: list[dict]) -> int:
    """
    Merge findings from a completed job into the patterns store.

    Each finding is matched by (test_id or test_name, severity).  If a matching
    pattern exists its occurrence count is incremented and job_id appended.
    Otherwise a new pattern entry is created.

    Returns the number of patterns created or updated.
    """
    if not findings:
        return 0

    data     = _load_patterns_raw()
    patterns = data.get("patterns", [])
    now      = datetime.now(timezone.utc).isoformat()
    index    = _build_patterns_index(patterns)

    for finding in findings:
        _merge_finding_into_index(finding, index, patterns, job_id, now)

    data["patterns"] = patterns
    _save_patterns_raw(data)
    log.info("security_knowledge: recorded %d findings from job %s (%d total patterns)",
             len(findings), job_id, len(patterns))

    _try_auto_promote(job_id)
    return len(findings)


def _normalise_key(p: dict) -> str:
    """Stable key for deduplication — prefer test_id, fall back to lowercased test_name."""
    tid = (p.get("test_id") or "").strip()
    if tid:
        return tid.upper()
    return (p.get("test_name") or "").strip().lower().replace(" ", "_")


# ─────────────────────────────────────────────────────────────────────────────
# Prompt builder — called by conversion_agent.py
# ─────────────────────────────────────────────────────────────────────────────

def _append_standing_rules_section(lines: list[str], rules: list[dict]) -> None:
    """Append formatted standing-rules lines to *lines* (mutates in place)."""
    lines.append("── Standing Rules (always apply) ──────────────────────")
    for i, r in enumerate(rules, 1):
        sev  = r.get("severity", "")
        desc = r.get("description", "")
        guid = r.get("guidance", "")
        lines.append(f"{i}. [{sev}] {desc}")
        if guid:
            lines.append(f"   → {guid}")
    lines.append("")


def _format_pattern_lines(i: int, p: dict) -> list[str]:
    """Return formatted lines for one recurring pattern entry."""
    name  = p.get("test_name") or p.get("test_id") or "unknown"
    sev   = p.get("severity", "")
    count = p.get("occurrences", 1)
    desc  = p.get("description", "")
    rem   = p.get("remediation", "")
    out   = [f"{i}. [{sev}] {name}  (seen {count}× across past jobs)"]
    if desc:
        out.append(f"   Issue: {desc}")
    if rem:
        out.append(f"   Fix:   {rem}")
    return out


def _append_patterns_section(lines: list[str], patterns: list[dict]) -> None:
    """Append formatted recurring-patterns lines to *lines* (mutates in place)."""
    lines.append("── Recurring Issues Seen in Past Conversions (fix proactively) ──")
    lines.append("These issues have appeared in previously converted code.")
    lines.append("Actively avoid them — do not wait for a security scan to catch them.")
    lines.append("")
    for i, p in enumerate(patterns, 1):
        lines.extend(_format_pattern_lines(i, p))
    lines.append("")


def build_security_context_block(top_n_patterns: int = 15) -> str:
    """
    Build the "Security Requirements" block injected into every conversion prompt.

    Combines:
      • All enabled standing rules (security_rules.yaml)
      • Top N most-recurring patterns learned from past jobs

    Returns an empty string if both stores are empty (safe to inject unconditionally).
    """
    rules    = load_rules()
    patterns = load_top_patterns(limit=top_n_patterns)

    if not rules and not patterns:
        return ""

    lines: list[str] = [
        "═══════════════════════════════════════════════════════",
        "MANDATORY SECURITY REQUIREMENTS",
        "You MUST follow every rule below in ALL generated code.",
        "These are non-negotiable — do not omit, soften, or work around them.",
        "═══════════════════════════════════════════════════════",
        "",
    ]

    if rules:
        _append_standing_rules_section(lines, rules)
    if patterns:
        _append_patterns_section(lines, patterns)

    lines.append("═══════════════════════════════════════════════════════")
    lines.append("")

    return "\n".join(lines)


def _load_rules_data_for_promotion() -> dict:
    """Load rules YAML for duplicate-checking; return empty structure on any error."""
    try:
        with RULES_PATH.open("r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {"rules": []}
    except Exception as exc:
        log.debug(
            "Could not read rules file for dedup check (%s: %s) — treating as empty.",
            type(exc).__name__, exc,
        )
        return {"rules": []}


def _build_existing_rule_sets(existing_rules: list[dict]) -> tuple[set, set]:
    """Return (existing_ids, existing_names) sets for deduplication."""
    existing_ids = {r.get("id", "") for r in existing_rules}
    existing_names = {
        (r.get("test_name") or r.get("description", ""))[:60].lower().replace(" ", "_")
        for r in existing_rules
    }
    return existing_ids, existing_names


def _clamp_severity(severity: str) -> str:
    """Return severity clamped to the recognised set."""
    if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return "MEDIUM"
    return severity


def _build_promoted_rule(pattern: dict, rule_id: str, raw_key: str) -> dict:
    """Construct the rule dict for a newly promoted pattern."""
    severity    = _clamp_severity(pattern.get("severity", "MEDIUM"))
    description = pattern.get("description") or pattern.get("test_name") or raw_key
    guidance    = (
        pattern.get("remediation")
        or "Review all occurrences of this pattern in generated code and apply the fix described above."
    )
    return {
        "id":          rule_id,
        "severity":    severity,
        "category":    pattern.get("source", "scan-finding"),
        "description": f"[Auto-promoted from {pattern.get('occurrences', 3)}× scan finding] {description}",
        "guidance":    guidance,
        "enabled":     True,
    }


def _try_promote_pattern(
    pattern: dict,
    threshold: int,
    existing_ids: set,
    existing_names: set,
    existing_rules: list[dict],
) -> bool:
    """
    Attempt to promote one pattern.  Mutates existing_ids/existing_names/existing_rules
    and the pattern dict.  Returns True if promoted, False otherwise.
    """
    if pattern.get("promoted") or pattern.get("occurrences", 0) < threshold:
        return False

    raw_key    = _normalise_key(pattern)
    rule_id    = f"rule_auto_{raw_key[:40]}"
    short_name = raw_key[:60].lower()

    if rule_id in existing_ids or short_name in existing_names:
        pattern["promoted"] = True
        return False

    new_rule = _build_promoted_rule(pattern, rule_id, raw_key)
    existing_rules.append(new_rule)
    existing_ids.add(rule_id)
    existing_names.add(short_name)
    pattern["promoted"]    = True
    pattern["promoted_to"] = rule_id
    log.info(
        "security_knowledge: promoted pattern '%s' (%dx) to standing rule %s",
        raw_key, pattern["occurrences"], rule_id,
    )
    return True


def _save_promoted_rules(rules_data: dict, data: dict, patterns: list[dict]) -> bool:
    """Persist the updated rules YAML and patterns JSON. Returns False on write error."""
    try:
        with RULES_PATH.open("w", encoding="utf-8") as fh:
            yaml.dump(rules_data, fh, default_flow_style=False,
                      allow_unicode=True, sort_keys=False)
    except Exception as exc:
        log.warning("security_knowledge: could not write promoted rules: %s", exc)
        return False
    data["patterns"] = patterns
    _save_patterns_raw(data)
    return True


def promote_patterns_to_rules(threshold: int = 3) -> int:
    """
    Auto-promote recurring patterns into standing rules in security_rules.yaml.

    Any pattern in security_patterns.json whose occurrence count >= `threshold`
    and that does not already have a matching standing rule is promoted:
      - A new rule entry is written to security_rules.yaml with severity, description,
        and remediation from the pattern.
      - The pattern is marked `promoted: true` in security_patterns.json so it is
        not promoted again.

    This closes the feedback loop: every scan approval makes the tool smarter,
    and patterns that appear repeatedly become non-negotiable standing rules
    rather than just "recurring issue" hints.

    Returns the number of rules newly promoted.
    """
    data           = _load_patterns_raw()
    patterns       = data.get("patterns", [])
    rules_data     = _load_rules_data_for_promotion()
    existing_rules = rules_data.get("rules", [])
    existing_ids, existing_names = _build_existing_rule_sets(existing_rules)

    promoted = sum(
        _try_promote_pattern(p, threshold, existing_ids, existing_names, existing_rules)
        for p in patterns
    )

    if promoted:
        rules_data["rules"] = existing_rules
        if not _save_promoted_rules(rules_data, data, patterns):
            return 0
        log.info("security_knowledge: promoted %d pattern(s) to standing rules", promoted)

    return promoted


def knowledge_base_stats() -> dict:
    """Return a summary dict for API/UI consumption."""
    rules    = load_rules()
    patterns = load_top_patterns(limit=200)
    auto_rules    = [r for r in rules if r.get("id", "").startswith("rule_auto_")]
    promoted_pats = [p for p in patterns if p.get("promoted")]
    return {
        "rules_count":         len(rules),
        "auto_promoted_count": len(auto_rules),
        "patterns_count":      len(patterns),
        "top_patterns":        patterns[:10],
    }
