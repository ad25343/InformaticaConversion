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

# Attribute names stored by the parser in table_attribs → normalised summary key
_ATTRIB_MAP = {
    "Filter Condition":  "filter_condition",   # Filter transformation
    "Source Filter":     "source_filter",      # Source Qualifier
    "Sql Query":         "sql_override",       # Source Qualifier custom SQL
    "User Defined Join": "join_condition",     # Source Qualifier join
    "Lookup condition":  "lookup_condition",   # Lookup
    "Pre SQL":           "pre_sql",
    "Post SQL":          "post_sql",
}

# Legacy top-level keys some older parser versions stored directly on the transformation
_LEGACY_ATTR_KEYS = (
    "sql_override", "filter_condition", "join_condition",
    "lookup_condition", "pre_sql", "post_sql",
)


# ─────────────────────────────────────────
# Graph-summary helper extractors
# ─────────────────────────────────────────

def _append_expressions(t: dict, lines: list) -> None:
    """Append non-trivial expression lines for a transformation."""
    for expr in t.get("expressions", []):
        e = expr.get("expression", "")
        if e and e != expr.get("port", ""):
            lines.append(f"    expr  {expr['port']} = {e[:300]}")


def _append_table_attribs(t: dict, lines: list) -> None:
    """Append normalised table_attribs and legacy top-level attribute lines."""
    table_attribs = t.get("table_attribs", {})
    for attrib_name, summary_key in _ATTRIB_MAP.items():
        val = table_attribs.get(attrib_name, "").strip()
        if val:
            lines.append(f"    {summary_key}: {val[:300]}")
    for attr_key in _LEGACY_ATTR_KEYS:
        if t.get(attr_key):
            lines.append(f"    {attr_key}: {str(t[attr_key])[:300]}")


def _append_rank_config(t: dict, lines: list) -> None:
    """Append rank_config line for a Rank transformation."""
    attribs  = t.get("table_attribs", {})
    n_ranks  = attribs.get("Number Of Ranks", "")
    rank_dir = attribs.get("Rank", "")
    rank_by  = attribs.get("Rank By", "")
    rank_info = []
    if n_ranks:
        rank_info.append(f"Number Of Ranks={n_ranks}")
    if rank_dir:
        rank_info.append(f"Rank={rank_dir}")
    if rank_by:
        rank_info.append(f"Rank By={rank_by}")
    if rank_info:
        lines.append(f"    rank_config: {', '.join(rank_info)}")


def _sort_key_from_port(p: dict) -> tuple | None:
    """Return (position, name, direction) sort tuple for port, or None if not sortable."""
    pos  = p.get("sort_key_position", "")
    dirn = p.get("sort_direction", "")
    if pos and dirn:
        return (int(pos), p["name"], dirn)
    return None


def _append_sorter_config(t: dict, lines: list) -> None:
    """Append sort_keys line for a Sorter transformation."""
    sort_keys = sorted(filter(None, (_sort_key_from_port(p) for p in t.get("ports", []))))
    if sort_keys:
        parts = [f"{name} {dirn}" for _, name, dirn in sort_keys]
        lines.append(f"    sort_keys: {', '.join(parts)}")


def _port_io_label(p: dict) -> str:
    """Return 'I', 'O', 'IO', or '' for a port based on its porttype."""
    porttype = p.get("porttype", "")
    return ("I" if "INPUT" in porttype else "") + ("O" if "OUTPUT" in porttype else "")


def _append_port_summary(t: dict, lines: list) -> None:
    """Append a condensed port list line for a transformation."""
    port_names = [f"{p['name']}({_port_io_label(p)})" for p in t.get("ports", [])]
    if not port_names:
        return
    suffix = " ..." if len(port_names) > 20 else ""
    lines.append(f"    ports: {', '.join(port_names[:20])}{suffix}")


def _append_transformation(t: dict, lines: list) -> None:
    """Append all summary lines for a single transformation."""
    lines.append(f"\n  [{t['type']}] {t['name']}")
    _append_expressions(t, lines)
    _append_table_attribs(t, lines)
    if t["type"] == "Rank":
        _append_rank_config(t, lines)
    if t["type"] == "Sorter":
        _append_sorter_config(t, lines)
    _append_port_summary(t, lines)


def _append_connector_summary(connectors: list, lines: list) -> None:
    """Append a capped connector list for a mapping."""
    if not connectors:
        return
    lines.append(f"\n  Connectors ({len(connectors)}):")
    for c in connectors[:60]:
        lines.append(
            f"    {c.get('from_instance')}.{c.get('from_field')} "
            f"→ {c.get('to_instance')}.{c.get('to_field')}"
        )
    if len(connectors) > 60:
        lines.append(f"    ... and {len(connectors) - 60} more connectors")


def _append_mapping(m: dict, lines: list) -> None:
    """Append all summary lines for a single mapping."""
    lines.append(f"\nMapping: {m.get('name', 'unknown')}")
    for t in m.get("transformations", []):
        _append_transformation(t, lines)
    _append_connector_summary(m.get("connectors", []), lines)


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
        _append_mapping(m, lines)

    summary = "\n".join(lines)
    if len(summary) > 20_000:
        summary = summary[:20_000] + "\n... [graph summary truncated for length]"
    return summary


# ─────────────────────────────────────────
# Claude quality-check flag normalisation
# ─────────────────────────────────────────

def _validated_fix(raw_fix) -> str | None:
    """Return the auto_fix_suggestion string or None if absent/too short."""
    fix = raw_fix or None
    if fix is None:
        return None
    return fix if len(fix.strip()) >= 10 else None


def _normalise_flag_item(item: dict) -> dict:
    """Fill in missing severity/recommendation/auto_fix_suggestion from defaults."""
    effective_meta = _get_effective_flag_meta()
    meta = effective_meta.get(item.get("flag_type", ""), {})

    if not item.get("severity"):
        item["severity"] = meta.get("severity", "MEDIUM")
    if not item.get("recommendation"):
        item["recommendation"] = meta.get(
            "recommendation", "Review this flag with your team before proceeding."
        )
    item["auto_fix_suggestion"] = _validated_fix(item.get("auto_fix_suggestion"))
    return item


def _build_prompt_notes(
    expr_input_ports: set[str] | None,
    rank_index_ports: set[str] | None,
) -> tuple[str, str]:
    """Return (expr_input_note, rank_index_note) strings for the Claude prompt."""
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
    return expr_input_note, rank_index_note


def _parse_claude_response(text: str) -> list:
    """Strip markdown fences and parse the JSON array from Claude's response."""
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return _recover_truncated_json_array(text)


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
    expr_input_note, rank_index_note = _build_prompt_notes(expr_input_ports, rank_index_ports)
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
        data = _parse_claude_response(message.content[0].text.strip())
        return [VerificationFlag(**_normalise_flag_item(item)) for item in data]
    except Exception as e:
        return [VerificationFlag(
            flag_type="REVIEW_REQUIRED",
            location="Verification Agent",
            description=f"Claude quality check could not complete: {str(e)}",
            blocking=False,
            severity="MEDIUM",
            recommendation="Re-run the verification step or check your ANTHROPIC_API_KEY and model settings.",
        )]


class _JsonBraceScanner:
    """Stateful scanner that tracks brace depth while skipping quoted strings."""

    __slots__ = ("depth", "in_string", "escape_next", "start")

    def __init__(self) -> None:
        self.depth       = 0
        self.in_string   = False
        self.escape_next = False
        self.start: int | None = None

    def _handle_escape(self, ch: str) -> bool:
        """Process escape state; return True if the character was consumed."""
        if self.escape_next:
            self.escape_next = False
            return True
        if ch == "\\" and self.in_string:
            self.escape_next = True
            return True
        return False

    def _handle_string_boundary(self, ch: str) -> bool:
        """Toggle in_string on quote; return True if character was consumed."""
        if ch == '"':
            self.in_string = not self.in_string
            return True
        return False

    def feed(self, i: int, ch: str) -> int | None:
        """
        Feed one character; return the completed-object start index when a
        top-level ``}`` closes a complete object, else None.
        """
        if self._handle_escape(ch) or self._handle_string_boundary(ch):
            return None
        if self.in_string:
            return None
        return self._handle_brace(i, ch)

    def _handle_brace(self, i: int, ch: str) -> int | None:
        """Process a non-string ``{`` or ``}``; return closed-object start or None."""
        if ch == "{":
            if self.depth == 0:
                self.start = i
            self.depth += 1
            return None
        if ch == "}":
            return self._close_brace()
        return None

    def _close_brace(self) -> int | None:
        """Handle a ``}``; return saved start if an object just closed."""
        self.depth -= 1
        if self.depth == 0 and self.start is not None:
            closed_start = self.start
            self.start   = None
            return closed_start
        return None


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
    scanner = _JsonBraceScanner()
    for i, ch in enumerate(text):
        closed_start = scanner.feed(i, ch)
        if closed_start is not None:
            _try_append_object(text, closed_start, i, objects)
    return objects


def _try_append_object(text: str, start: int, end: int, objects: list) -> None:
    """Parse text[start:end+1] as JSON and append to objects if valid."""
    try:
        objects.append(json.loads(text[start : end + 1]))
    except json.JSONDecodeError:
        pass
