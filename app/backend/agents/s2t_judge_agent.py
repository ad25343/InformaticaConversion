# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
S2T Judge — LLM quality-assurance pass over the deterministic S2T output.

The deterministic tracer is fast and exact but can miss fields when:
  - Connector naming conventions deviate from known patterns
  - Expressions are non-standard or malformed
  - The XML is incomplete or has structural anomalies

The judge reviews the full S2T result and:
  1. Rates each mapped record's confidence (HIGH / MEDIUM / LOW)
  2. Assesses every unmapped target field — is it genuinely unmapped, or
     did the tracer likely miss something?
  3. Flags suspicious mapped records (wrong source, truncated chain, etc.)
  4. Provides an overall completeness verdict with a plain-English summary

The deterministic trace is always authoritative — the judge annotates,
never replaces. If the judge call fails, the S2T result is returned unchanged.
"""
from __future__ import annotations

import json
import logging
from typing import Optional

from ..models.schemas import ParseReport
from ._client import make_client
from ..config import settings as _cfg
from .retry import claude_with_retry

log = logging.getLogger("conversion.s2t_judge")

MODEL = _cfg.claude_model
_MAX_TOKENS = 4_000
_CONFIDENCE_VALUES = ("HIGH", "MEDIUM", "LOW")
_SEVERITY_VALUES   = ("HIGH", "MEDIUM", "LOW")


# ── System prompt ─────────────────────────────────────────────────────────────

_SYSTEM = """You are a senior data integration architect auditing an automated
Source-to-Target (S2T) lineage trace for an Informatica PowerCenter mapping.

The trace was produced by a deterministic graph-traversal algorithm that follows
connector chains backward from each target field to its source. It is generally
accurate but can miss fields due to:
- Non-standard transformation naming conventions
- Expressions that dead-end at an intermediate transformation
- Missing or malformed connectors in the XML
- Lookup or Sequence transformations that have no backward connector

Your job:
1. Review every MAPPED record and assign a confidence rating.
2. Review every UNMAPPED target field and assess whether it is genuinely unmapped
   or whether the tracer likely missed something.
3. Flag any mapped records that look suspicious.
4. Provide an overall completeness verdict.

Be factual and specific. Do not invent sources — only flag gaps when the evidence
supports it. Return ONLY valid JSON — no markdown fences, no commentary."""


# ── User prompt template ──────────────────────────────────────────────────────

_PROMPT = """## Mapping: {mapping_name}

## Mapped S2T Records ({n_mapped} fields)

{mapped_section}

## Unmapped Target Fields ({n_unmapped} fields)

{unmapped_section}

## Unmapped Source Fields ({n_src_unmapped} fields, for context)

{src_unmapped_section}

## Transformation Summary (for context)

{transform_summary}

─────────────────────────────────────────────────────────────────────────────

## Your Task

Return a JSON object with EXACTLY this structure — no extra keys:

{{
  "record_annotations": [
    {{
      "target_table": "<string>",
      "target_field": "<string>",
      "confidence":   "HIGH" | "MEDIUM" | "LOW",
      "note":         "<string or null>"
    }}
  ],
  "gap_findings": [
    {{
      "target_table":           "<string>",
      "target_field":           "<string>",
      "finding":                "<one sentence — what is missing or suspicious>",
      "severity":               "HIGH" | "MEDIUM" | "LOW",
      "suggested_source_table": "<string or null>",
      "suggested_source_field": "<string or null>"
    }}
  ],
  "overall_completeness": "HIGH" | "MEDIUM" | "LOW",
  "summary": "<2-3 sentences — overall quality assessment and key gaps>"
}}

Confidence rating guide:
- HIGH:   Clean trace, source and field name make obvious sense, chain is short and logical
- MEDIUM: Trace looks plausible but chain is long, source is unexpected, or field name is ambiguous
- LOW:    Trace dead-ended at an expression/aggregator, source seems wrong, or chain is suspicious

Gap finding guide:
- Only raise a gap for UNMAPPED fields where you believe the tracer missed something
- For genuinely unconnected fields (audit columns, SCD2 mgmt columns), note that but do NOT
  raise a gap finding — they belong in the unmapped section
- Severity HIGH = blocks conversion (analyst cannot determine source)
- Severity MEDIUM = should investigate before UAT
- Severity LOW = advisory"""


# ── Compact builders ──────────────────────────────────────────────────────────

_MAX_MAPPED_ROWS   = 300   # hard cap — beyond this the judge gets a summary note
_MAX_TRANSFORM_ROWS = 80   # transformations shown in the summary section
_MAX_PROMPT_CHARS  = 80_000  # ~20K tokens — well within Claude's 200K context window


def _build_mapped_section(records: list[dict]) -> str:
    if not records:
        return "(none)"
    shown = records[:_MAX_MAPPED_ROWS]
    lines = ["| # | Target Table | Target Field | Source Table | Source Field | Status | Chain |",
             "|---|-------------|-------------|-------------|-------------|--------|-------|"]
    for i, r in enumerate(shown, 1):
        chain = r.get("transformation_chain_str") or "—"
        if len(chain) > 60:
            chain = chain[:57] + "…"
        lines.append(
            f"| {i} | {r['target_table']} | {r['target_field']} "
            f"| {r.get('source_table') or '—'} | {r.get('source_field') or '—'} "
            f"| {r.get('status','?')} | {chain} |"
        )
    if len(records) > _MAX_MAPPED_ROWS:
        lines.append(f"\n_(first {_MAX_MAPPED_ROWS} of {len(records)} rows shown — remainder omitted for length)_")
    return "\n".join(lines)


def _build_unmapped_section(unmapped: list[dict]) -> str:
    if not unmapped:
        return "(none — all target fields are mapped)"
    lines = ["| # | Target Table | Target Field | Type | Note |",
             "|---|-------------|-------------|------|------|"]
    for i, u in enumerate(unmapped, 1):
        note = (u.get("note") or "No upstream connector found")[:80]
        lines.append(
            f"| {i} | {u['target_table']} | {u['target_field']} "
            f"| {u.get('target_type','?')} | {note} |"
        )
    return "\n".join(lines)


def _build_src_unmapped_section(unmapped: list[dict]) -> str:
    if not unmapped:
        return "(none)"
    items = [f"- {u['source_table']}.{u['source_field']}" for u in unmapped[:20]]
    if len(unmapped) > 20:
        items.append(f"  … and {len(unmapped) - 20} more")
    return "\n".join(items)


def _build_transform_summary(graph: dict) -> str:
    lines = []
    for mapping in graph.get("mappings", []):
        for t in mapping.get("transformations", []):
            ttype = t.get("type", "?")
            tname = t.get("name", "?")
            ports = [p["name"] for p in t.get("ports", [])[:6]]
            port_str = ", ".join(ports)
            if len(t.get("ports", [])) > 6:
                port_str += f" … (+{len(t['ports']) - 6} more)"
            lines.append(f"- {tname} ({ttype}): {port_str}")
    if not lines:
        return "(none)"
    shown = lines[:_MAX_TRANSFORM_ROWS]
    if len(lines) > _MAX_TRANSFORM_ROWS:
        shown.append(f"  … and {len(lines) - _MAX_TRANSFORM_ROWS} more transformations omitted")
    return "\n".join(shown)


# ── Response parser ───────────────────────────────────────────────────────────

def _parse_judge_response(text: str) -> dict:
    """Parse and validate the JSON response from the judge."""
    # Strip markdown fences if Claude adds them despite instructions
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3]
    text = text.strip()

    data = json.loads(text)

    # Validate and normalise confidence values
    annotations = []
    for ann in data.get("record_annotations", []):
        conf = str(ann.get("confidence", "")).upper()
        annotations.append({
            "target_table": str(ann.get("target_table", "")),
            "target_field": str(ann.get("target_field", "")),
            "confidence":   conf if conf in _CONFIDENCE_VALUES else "MEDIUM",
            "note":         ann.get("note") or None,
        })

    gaps = []
    for g in data.get("gap_findings", []):
        sev = str(g.get("severity", "")).upper()
        gaps.append({
            "target_table":           str(g.get("target_table", "")),
            "target_field":           str(g.get("target_field", "")),
            "finding":                str(g.get("finding", "")),
            "severity":               sev if sev in _SEVERITY_VALUES else "MEDIUM",
            "suggested_source_table": g.get("suggested_source_table") or None,
            "suggested_source_field": g.get("suggested_source_field") or None,
        })

    completeness = str(data.get("overall_completeness", "")).upper()
    return {
        "record_annotations":  annotations,
        "gap_findings":        gaps,
        "overall_completeness": completeness if completeness in _CONFIDENCE_VALUES else "MEDIUM",
        "summary":             str(data.get("summary", "")),
    }


# ── Merge judge results into S2T records ──────────────────────────────────────

def _merge_annotations(records: list[dict], annotations: list[dict]) -> list[dict]:
    """Merge judge confidence + notes into S2T records in-place."""
    ann_index: dict[tuple[str, str], dict] = {
        (a["target_table"].upper(), a["target_field"].upper()): a
        for a in annotations
    }
    for r in records:
        key = (r["target_table"].upper(), r["target_field"].upper())
        ann = ann_index.get(key)
        r["judge_confidence"] = ann["confidence"] if ann else None
        r["judge_note"]       = ann["note"]        if ann else None
    return records


# ── Main entry point ──────────────────────────────────────────────────────────

async def judge_s2t(
    s2t_result: dict,
    graph: dict,
    parse_report: ParseReport,
    timeout: Optional[float] = None,
) -> dict:
    """
    Run the LLM judge over a completed S2T result.

    Mutates s2t_result in-place to add:
      - `judge_confidence` + `judge_note` on each record
      - `judge_gaps` list (gap findings from LLM)
      - `judge_overall_completeness` (HIGH/MEDIUM/LOW)
      - `judge_summary` (plain-English assessment)

    Returns the mutated s2t_result. Never raises — on any error the
    original s2t_result is returned with `judge_error` set.
    """
    import asyncio

    records         = s2t_result.get("records", [])
    unmapped_tgt    = s2t_result.get("unmapped_targets", [])
    unmapped_src    = s2t_result.get("unmapped_sources", [])
    mapping_names   = parse_report.mapping_names or ["(unknown)"]
    mapping_name    = ", ".join(mapping_names)

    transform_summary = _build_transform_summary(graph)
    prompt = _PROMPT.format(
        mapping_name         = mapping_name,
        n_mapped             = len(records),
        n_unmapped           = len(unmapped_tgt),
        n_src_unmapped       = len(unmapped_src),
        mapped_section       = _build_mapped_section(records),
        unmapped_section     = _build_unmapped_section(unmapped_tgt),
        src_unmapped_section = _build_src_unmapped_section(unmapped_src),
        transform_summary    = transform_summary,
    )

    # Safety net: if the assembled prompt still exceeds our char budget,
    # drop the transform summary (least critical section) and rebuild.
    if len(prompt) > _MAX_PROMPT_CHARS:
        log.warning(
            "s2t_judge: prompt too large (%d chars) — dropping transform summary and retrying",
            len(prompt),
        )
        prompt = _PROMPT.format(
            mapping_name         = mapping_name,
            n_mapped             = len(records),
            n_unmapped           = len(unmapped_tgt),
            n_src_unmapped       = len(unmapped_src),
            mapped_section       = _build_mapped_section(records),
            unmapped_section     = _build_unmapped_section(unmapped_tgt),
            src_unmapped_section = _build_src_unmapped_section(unmapped_src),
            transform_summary    = "(omitted — prompt size limit reached)",
        )

    log.info("s2t_judge: reviewing %d mapped + %d unmapped fields for %s (prompt=%d chars)",
             len(records), len(unmapped_tgt), mapping_name, len(prompt))

    timeout_secs = timeout or _cfg.agent_timeout_secs
    try:
        client = make_client()
        message = await asyncio.wait_for(
            claude_with_retry(
                lambda: client.messages.create(
                    model=MODEL,
                    max_tokens=_MAX_TOKENS,
                    system=_SYSTEM,
                    messages=[{"role": "user", "content": prompt}],
                ),
                label="s2t judge",
            ),
            timeout=timeout_secs,
        )
        text = message.content[0].text
        judge = _parse_judge_response(text)

        # Merge annotations into records
        _merge_annotations(records, judge["record_annotations"])

        # Attach judge results to the top-level result dict
        s2t_result["judge_gaps"]                = judge["gap_findings"]
        s2t_result["judge_overall_completeness"] = judge["overall_completeness"]
        s2t_result["judge_summary"]              = judge["summary"]

        log.info(
            "s2t_judge: complete — completeness=%s, gap_findings=%d, annotations=%d",
            judge["overall_completeness"],
            len(judge["gap_findings"]),
            len(judge["record_annotations"]),
        )

    except asyncio.TimeoutError:
        log.warning("s2t_judge: timed out after %ss — skipping", timeout_secs)
        s2t_result["judge_error"] = f"Timed out after {timeout_secs}s"
    except Exception as exc:
        log.warning("s2t_judge: failed (%s) — skipping", exc)
        s2t_result["judge_error"] = str(exc)

    return s2t_result
