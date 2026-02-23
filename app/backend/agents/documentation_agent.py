"""
STEP 3 — Documentation Agent
Claude-powered. Produces the full Markdown documentation file per mapping.
Works strictly from the parsed graph — never from general Informatica knowledge.
"""
from __future__ import annotations
import json
import os
import anthropic

from ..models.schemas import ComplexityReport, ComplexityTier, ParseReport

MODEL = os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-5-20250929")

# ─────────────────────────────────────────────────────────────────────────────
# Token budgets: tier floors + dynamic estimate.
#
# We can't know in advance exactly how many tokens Claude will output, but we
# can estimate from the number of transformations (the primary driver of doc
# length).  Empirically, each transformation generates ~1 500 output tokens of
# full technical documentation, plus a ~4 000-token fixed overhead.
#
# Formula:  estimated = num_trans × 1 500 + 4 000
#           → rounded up to the next 4 096 multiple, capped at 32 768
#
# The tier-based dict below is used as a FLOOR so that even very simple
# mappings get a reasonable minimum.  The final budget is:
#   max(tier_floor, estimated)
# ─────────────────────────────────────────────────────────────────────────────
_DOC_MAX_TOKENS: dict[ComplexityTier, int] = {
    ComplexityTier.LOW:        8_192,
    ComplexityTier.MEDIUM:    12_288,
    ComplexityTier.HIGH:      16_384,
    ComplexityTier.VERY_HIGH: 32_768,
}

_TOKENS_PER_TRANSFORMATION = 1_500   # empirical: chars-per-trans / avg token size
_DOC_FIXED_OVERHEAD        = 4_000   # header, summary, lineage section
_DOC_TOKEN_CAP             = 32_768  # hard ceiling (model context safety)


def _estimate_doc_tokens(graph: dict) -> int:
    """Return a dynamic output-token estimate based on transformation count.

    Rounds up to the nearest 4 096 multiple so we never land on an
    awkward mid-bucket boundary.
    """
    num_trans = sum(
        len(m.get("transformations", []))
        for m in graph.get("mappings", [])
    )
    raw       = num_trans * _TOKENS_PER_TRANSFORMATION + _DOC_FIXED_OVERHEAD
    bucketed  = ((raw + 4_095) // 4_096) * 4_096   # round UP to next 4 096
    return min(bucketed, _DOC_TOKEN_CAP)

# Sentinel appended to the markdown when Claude hit the token limit.
# The verification agent looks for this string and surfaces a clear
# DOCUMENTATION_TRUNCATED flag instead of confusing "not found in docs" failures.
DOC_TRUNCATION_SENTINEL = "\n\n<!-- DOC_TRUNCATED -->"

SYSTEM_PROMPT = """You are a senior data engineer deeply familiar with Informatica PowerCenter.

You are producing technical documentation for a mapping that will be converted to modern code.
Your ONLY source of truth is the structured data provided. Never invent or assume logic.

Rules:
- Document every transformation — never skip one because it seems trivial
- Preserve every expression verbatim AND explain it in plain English
- Never paraphrase in a way that changes meaning
- Flag AMBIGUITY explicitly — do not guess
- If UNSUPPORTED TRANSFORMATION is present, document all visible ports/metadata and clearly flag it
- Output ONLY the Markdown document — no preamble, no commentary outside the doc
"""

DOCUMENTATION_PROMPT = """Produce full technical documentation for the Informatica mapping below.

## Parse Summary
{parse_summary}

## Complexity Classification
{complexity_summary}

## Full Mapping Graph (JSON)
```json
{graph_json}
```

## Required Documentation Structure

Produce a Markdown document with these sections:

# Mapping: [name]

## Overview
- Inferred purpose (plain English)
- Source systems and tables
- Target systems and tables
- Complexity tier and rationale
- High-level data flow narrative

## Transformations (in execution order)
For EACH transformation:
### [Transformation Name] — [Type]
- **Purpose**: What business logic does this perform?
- **Input Ports**: table with name, datatype, source
- **Output Ports**: table with name, datatype, destination
- **Logic Detail**: every expression verbatim + plain English explanation
- **Table Attributes**: join conditions, lookup conditions, filter conditions, SQL overrides — all verbatim
- **Hardcoded Values**: list any constants
- If UNSUPPORTED: state UNSUPPORTED TRANSFORMATION clearly, document all visible metadata

## Field-Level Lineage
For every target field, trace: source field → each transformation step → target
State what happened at each step (passthrough / renamed / retyped / derived / aggregated / lookup / generated)
Flag as LINEAGE GAP if trace cannot be completed

## Parameters and Variables
Table: name | datatype | default value | purpose | resolved?

## Workflow Context
(If workflow data is available)
- Execution order
- Dependencies
- Scheduling

## Ambiguities and Flags
List every point of uncertainty, with location and description
"""


async def document(
    parse_report: ParseReport,
    complexity: ComplexityReport,
    graph: dict,
) -> str:
    """Returns the full documentation as a Markdown string.

    If Claude hits the output token limit the returned string will end with
    DOC_TRUNCATION_SENTINEL so downstream consumers (verification_agent) can
    detect the truncation and surface a clear warning to the human reviewer
    instead of confusing 'not found in documentation' failures.
    """

    client = anthropic.AsyncAnthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

    parse_summary = (
        f"Parse Status: {parse_report.parse_status}\n"
        f"Objects Found: {json.dumps(parse_report.objects_found)}\n"
        f"Mappings: {', '.join(parse_report.mapping_names)}\n"
        f"Unresolved Parameters: {parse_report.unresolved_parameters}\n"
        f"Flags: {len(parse_report.flags)}"
    )

    complexity_summary = (
        f"Tier: {complexity.tier.value}\n"
        f"Criteria: {'; '.join(complexity.criteria_matched)}\n"
        f"Special Flags: {complexity.special_flags}"
    )

    # Keep the graph JSON compact but complete
    graph_json = json.dumps(graph, indent=2)
    # Truncate if massive — Claude context limit safety
    if len(graph_json) > 80_000:
        graph_json = graph_json[:80_000] + "\n... [truncated for length]"

    prompt = DOCUMENTATION_PROMPT.format(
        parse_summary=parse_summary,
        complexity_summary=complexity_summary,
        graph_json=graph_json,
    )

    # ── Token budget selection ────────────────────────────────────────────────
    # Priority order:
    #   1. DOC_MAX_TOKENS_OVERRIDE env var  (testing / manual override)
    #   2. Dynamic estimate from transformation count  (primary production path)
    #   3. Tier floor as a guaranteed minimum
    #
    # The dynamic estimate grows with num_transformations so a 14-transformation
    # mapping automatically gets a larger budget than a 5-transformation one,
    # without needing to be classified at a higher tier.
    _override = os.environ.get("DOC_MAX_TOKENS_OVERRIDE")
    if _override:
        max_tokens = int(_override)
    else:
        tier_floor = _DOC_MAX_TOKENS.get(complexity.tier, 16_384)
        estimated  = _estimate_doc_tokens(graph)
        max_tokens = max(tier_floor, estimated)

    message = await client.messages.create(
        model=MODEL,
        max_tokens=max_tokens,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )

    doc_text = message.content[0].text

    # Detect token-limit cutoff and stamp the sentinel so the verifier can
    # surface a human-readable warning rather than opaque "not found" failures.
    if message.stop_reason == "max_tokens":
        doc_text += DOC_TRUNCATION_SENTINEL

    return doc_text
