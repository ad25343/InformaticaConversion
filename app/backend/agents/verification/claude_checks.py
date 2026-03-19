# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Claude-powered qualitative verification checks.

Builds a compact graph summary and asks Claude to identify conversion risks:
hardcoded values, high-risk logic, dead logic, ambiguous expressions, and
incomplete conditionals.
"""
from __future__ import annotations

import json

from ...models.schemas import ComplexityTier, VerificationFlag
from ...config import settings as _cfg
from .._client import make_client
from .constants import _QC_MAX_TOKENS, _get_effective_flag_meta

MODEL = _cfg.claude_model


def _build_graph_summary(graph: dict) -> str:
    """Build a compact, risk-focused summary of the graph for Claude quality review.

    Extracts expressions, SQL overrides, filter conditions, join conditions, and
    connector topology — everything Claude needs to spot conversion risks without
    the verbosity of the full JSON (which can exceed 80k chars).
    """
    lines: list[str] = []

    sources = graph.get("sources", [])
    targets = graph.get("targets", [])
    lines.append(f"Sources ({len(sources)}): {', '.join(s['name'] for s in sources)}")
    lines.append(f"Targets ({len(targets)}): {', '.join(t['name'] for t in targets)}")

    for m in graph.get("mappings", []):
        lines.append(f"\nMapping: {m.get('name', 'unknown')}")
        for t in m.get("transformations", []):
            lines.append(f"\n  [{t['type']}] {t['name']}")

            # Expressions
            for expr in t.get("expressions", []):
                e = expr.get("expression", "")
                if e and e != expr.get("port", ""):  # skip trivial pass-throughs
                    lines.append(f"    expr  {expr['port']} = {e[:300]}")

            # SQL / filter / join / lookup conditions.
            # The parser stores these in table_attribs using the Informatica XML attribute
            # names (e.g. "Filter Condition", "Source Filter", "Sql Query").  We normalise
            # them here so Claude always sees a consistent key name in the summary.
            _ATTRIB_MAP = {
                "Filter Condition":   "filter_condition",   # Filter transformation
                "Source Filter":      "source_filter",      # Source Qualifier
                "Sql Query":          "sql_override",       # Source Qualifier custom SQL
                "User Defined Join":  "join_condition",     # Source Qualifier join
                "Lookup condition":   "lookup_condition",   # Lookup
                "Pre SQL":            "pre_sql",
                "Post SQL":           "post_sql",
            }
            table_attribs = t.get("table_attribs", {})
            for attrib_name, summary_key in _ATTRIB_MAP.items():
                val = table_attribs.get(attrib_name, "").strip()
                if val:
                    lines.append(f"    {summary_key}: {val[:300]}")
            # Legacy fallback — some older parser versions stored these as top-level keys
            for attr_key in ("sql_override", "filter_condition", "join_condition",
                             "lookup_condition", "pre_sql", "post_sql"):
                if t.get(attr_key):
                    lines.append(f"    {attr_key}: {str(t[attr_key])[:300]}")

            # Rank transformation config — emit dedup-critical attributes so Claude
            # knows whether RANKINDEX=1 means latest/earliest and what the group key is.
            if t["type"] == "Rank":
                attribs = t.get("table_attribs", {})
                n_ranks = attribs.get("Number Of Ranks", "")
                rank_dir = attribs.get("Rank", "")          # TOP or BOTTOM
                rank_by  = attribs.get("Rank By", "")       # sort-by port (optional)
                rank_info = []
                if n_ranks:
                    rank_info.append(f"Number Of Ranks={n_ranks}")
                if rank_dir:
                    rank_info.append(f"Rank={rank_dir}")
                if rank_by:
                    rank_info.append(f"Rank By={rank_by}")
                # Also collect ports that are sort keys (porttype may contain "INPUT/OUTPUT" +
                # the port being ranked is identified by being an I/O port passed through).
                # Group-by keys in Rank transformations are the INPUT/OUTPUT ports that are
                # NOT the ranked field — they are the partition key.
                if rank_info:
                    lines.append(f"    rank_config: {', '.join(rank_info)}")

            # Sorter transformation config — emit sort key(s) with direction so Claude
            # can reason about the order data arrives at downstream Rank/Filter transforms.
            # sort_key_position and sort_direction are captured by the parser from the
            # SORTKEYPOSITION and SORTDIRECTION attributes on Sorter TRANSFORMFIELD elements.
            if t["type"] == "Sorter":
                sort_keys = []
                for p in t.get("ports", []):
                    pos  = p.get("sort_key_position", "")
                    dirn = p.get("sort_direction", "")
                    if pos and dirn:
                        sort_keys.append((int(pos), p["name"], dirn))
                if sort_keys:
                    sort_keys.sort()
                    parts = [f"{name} {dirn}" for _, name, dirn in sort_keys]
                    lines.append(f"    sort_keys: {', '.join(parts)}")

            # Port list (names + types only, for connectivity context)
            port_names = [
                f"{p['name']}({'I' if 'INPUT' in p.get('porttype','') else ''}"
                f"{'O' if 'OUTPUT' in p.get('porttype','') else ''})"
                for p in t.get("ports", [])
            ]
            if port_names:
                lines.append(f"    ports: {', '.join(port_names[:20])}"
                             + (" ..." if len(port_names) > 20 else ""))

        # Connector summary (from → to)
        connectors = m.get("connectors", [])
        if connectors:
            lines.append(f"\n  Connectors ({len(connectors)}):")
            for c in connectors[:60]:  # cap at 60 to keep size manageable
                lines.append(f"    {c.get('from_instance')}.{c.get('from_field')} "
                             f"→ {c.get('to_instance')}.{c.get('to_field')}")
            if len(connectors) > 60:
                lines.append(f"    ... and {len(connectors) - 60} more connectors")

    summary = "\n".join(lines)
    # Hard cap — if still very large, truncate gracefully
    if len(summary) > 20_000:
        summary = summary[:20_000] + "\n... [graph summary truncated for length]"
    return summary


async def _run_claude_quality_checks(
    graph: dict,
    mapping_name: str,
    expr_input_ports: set[str] | None = None,
    rank_index_ports: set[str] | None = None,
    tier: ComplexityTier = ComplexityTier.MEDIUM,
) -> list[VerificationFlag]:
    """Ask Claude to identify qualitative risks in the mapping graph.

    We review the graph — not the documentation.  The documentation is human-facing
    and is reviewed visually by the reviewer at Gate 1.  This call is about finding
    conversion risks: hardcoded values, high-risk logic, ambiguous expressions, dead
    logic, and incomplete conditionals — all detectable from the raw graph data.
    """
    client = make_client()

    expr_input_note = ""
    if expr_input_ports:
        port_list = ", ".join(sorted(expr_input_ports))
        expr_input_note = f"""
IMPORTANT — the following ports are INPUT/OUTPUT passthroughs that feed expressions within the
same transformation but are NOT wired to a downstream connector. They are NOT dead logic —
they are expression inputs whose derived counterparts carry the value forward. Do NOT flag
these as DEAD_LOGIC:
{port_list}
"""

    rank_index_note = ""
    if rank_index_ports:
        ri_list = ", ".join(sorted(rank_index_ports))
        rank_index_note = f"""
IMPORTANT — the following are RANKINDEX output ports on Rank transformations: {ri_list}
RANKINDEX is Informatica's internal rank counter. When a Rank transformation is configured
with "Number Of Ranks = N", it outputs ONLY the top-N rows per group — no downstream Filter
on RANKINDEX=1 is needed or expected. Do NOT flag RANKINDEX as DEAD_LOGIC or ORPHANED_PORT.
If you see rank_config in the graph summary for these transformations, that shows the
deduplication is correctly configured in the Rank itself.
"""

    # Build a compact graph summary for Claude — focus on expressions, SQL, and connectors.
    # Full graph JSON can be very large; we extract only what's needed for risk analysis.
    graph_summary = _build_graph_summary(graph)

    prompt = f"""You are a senior data engineer reviewing an Informatica PowerCenter mapping called '{mapping_name}' before automated conversion to dbt/PySpark.

Review the mapping graph below and identify ONLY real conversion risks — do not invent problems.
{expr_input_note}{rank_index_note}
Look for:
1. REVIEW_REQUIRED — logic that is unclear, ambiguous, or open to multiple interpretations
2. DEAD_LOGIC — transformation or port that has no effect on output data (exclude expression-input ports listed above)
3. ENVIRONMENT_SPECIFIC_VALUE — hardcoded connection strings, server names, schema names, file paths, or IP addresses in expressions or SQL overrides
4. HIGH_RISK — logic that is financially sensitive, performs updates/deletes, or processes PII
5. INCOMPLETE_LOGIC — IIF/DECODE/conditional expression that appears to be missing an ELSE branch or default case
6. LINEAGE_GAP — a target field whose source cannot be determined from the graph connectors and expressions

For each issue found, respond with a JSON array. Each item:
{{
  "flag_type": "one of the types above",
  "location": "transformation name and port/field if applicable",
  "description": "specific description of the issue found in the graph",
  "blocking": false,
  "severity": "HIGH or MEDIUM or LOW",
  "recommendation": "one sentence describing the specific action the reviewer should take",
  "auto_fix_suggestion": "A concrete instruction for the code generation prompt (e.g. 'Move the hardcoded value \\"PROD_DB\\" in SQ_ORDERS into a config variable DB_CONNECTION_STRING.'). Set to null if human judgement is needed."
}}

If no issues found, return: []

Mapping graph to review:
---
{graph_summary}
---

Respond with ONLY the JSON array. No other text."""

    try:
        import asyncio as _asyncio
        from ..retry import claude_with_retry
        qc_max_tokens = _QC_MAX_TOKENS.get(tier, 4_096)
        # Hard timeout wraps the full retry sequence so a persistent outage
        # cannot leave the job stuck in 'verifying' state indefinitely.
        _VERIFY_TIMEOUT_SECS = _cfg.verify_timeout_secs
        message = await _asyncio.wait_for(
            claude_with_retry(
                lambda: client.messages.create(
                    model=MODEL,
                    max_tokens=qc_max_tokens,
                    messages=[{"role": "user", "content": prompt}],
                ),
                label="verification quality check",
            ),
            timeout=_VERIFY_TIMEOUT_SECS,
        )
        text = message.content[0].text.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]

        # Try clean parse first; fall back to partial-recovery if Claude was truncated
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = _recover_truncated_json_array(text)

        flags = []
        for item in data:
            # Fill in meta defaults if Claude didn't supply them
            effective_meta = _get_effective_flag_meta()
            if "severity" not in item or not item["severity"]:
                item["severity"] = effective_meta.get(item.get("flag_type",""), {}).get("severity", "MEDIUM")
            if "recommendation" not in item or not item["recommendation"]:
                item["recommendation"] = effective_meta.get(item.get("flag_type",""), {}).get(
                    "recommendation", "Review this flag with your team before proceeding."
                )
            # Normalise auto_fix_suggestion — strip empty strings to None
            fix = item.get("auto_fix_suggestion") or None
            if fix and len(fix.strip()) < 10:  # too short to be a real suggestion
                fix = None
            item["auto_fix_suggestion"] = fix
            flags.append(VerificationFlag(**item))
        return flags
    except Exception as e:
        return [VerificationFlag(
            flag_type="REVIEW_REQUIRED",
            location="Verification Agent",
            description=f"Claude quality check could not complete: {str(e)}",
            blocking=False,
            severity="MEDIUM",
            recommendation="Re-run the verification step or check your ANTHROPIC_API_KEY and model settings.",
        )]


def _recover_truncated_json_array(text: str) -> list:
    """
    Extract all *complete* JSON objects from a potentially truncated JSON array.

    When Claude hits the token limit mid-response the output may look like:
        [{"flag_type": "HIGH_RISK", ...}, {"flag_type": "REVIEW_REQUIRED", "description": "Some long str
    — i.e. the last object's string is unterminated.  This function walks the text
    character-by-character and collects every successfully parsed ``{...}`` block,
    discarding only the incomplete tail.  This recovers all flags that were fully
    written before the cutoff.
    """
    objects: list = []
    depth = 0
    in_string = False
    escape_next = False
    start: int | None = None

    for i, ch in enumerate(text):
        if escape_next:
            escape_next = False
            continue
        if ch == "\\" and in_string:
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue

        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    obj = json.loads(text[start : i + 1])
                    objects.append(obj)
                except json.JSONDecodeError:
                    pass
                start = None

    return objects
