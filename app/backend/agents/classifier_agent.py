# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
STEP 2 — Complexity Classifier Agent
Rule-based scoring against objective criteria from the spec.
"""
from __future__ import annotations
from ..models.schemas import ComplexityReport, ComplexityTier, ParseReport
from ..org_config_loader import get_pattern_signals, get_unsupported_types

# v2.24.0 — Pattern confidence label → numeric score
_CONFIDENCE_SCORE: dict[str, float] = {
    "HIGH":   90.0,
    "MEDIUM": 65.0,
    "LOW":    40.0,
    "NONE":   15.0,
}

def _get_unsupported_types() -> set[str]:
    try:
        return get_unsupported_types()
    except Exception:
        return {"Java Transformation", "External Procedure",
                "Advanced External Procedure", "Stored Procedure"}

UNSUPPORTED_TYPES = _get_unsupported_types()


def _elevate(current: ComplexityTier, candidate: ComplexityTier) -> ComplexityTier:
    order = [ComplexityTier.LOW, ComplexityTier.MEDIUM,
             ComplexityTier.HIGH, ComplexityTier.VERY_HIGH]
    return candidate if order.index(candidate) > order.index(current) else current


def _is_complex_expression(expr: str) -> bool:
    if not expr:
        return False
    try:
        indicators = get_pattern_signals()["expression_complexity"]
    except Exception:
        indicators = ["IIF(", "DECODE(", "TO_DATE(", "IN(", "INSTR(", "SUBSTR(",
                      "TRUNC(", "ROUND(", ":LKP.", "$$", "$$$"]
    return any(ind in expr.upper() for ind in indicators)


def _build_rationale(tier: ComplexityTier, criteria: list, flags: list) -> str:
    parts = [f"Classified as **{tier.value}** complexity based on the following:"]
    for c in criteria:
        parts.append(f"- {c}")
    if flags:
        parts.append("\nSpecial flags that elevated classification:")
        for f in flags:
            parts.append(f"- {f}")
    return "\n".join(parts)


# ── classify helpers ───────────────────────────────────────────────────────────

def _check_unsupported(trans: list, special_flags: list) -> ComplexityTier:
    """Return VERY_HIGH if any unsupported transformation found, else LOW."""
    tier = ComplexityTier.LOW
    for t in trans:
        if t["type"] in UNSUPPORTED_TYPES:
            special_flags.append(f"UNSUPPORTED_TRANSFORMATION: {t['name']} ({t['type']})")
            tier = ComplexityTier.VERY_HIGH
    return tier


def _check_trans_count(num_trans: int, criteria: list) -> ComplexityTier:
    """Return tier based on transformation count."""
    if num_trans >= 30:
        criteria.append(f"30+ transformations ({num_trans})")
        return ComplexityTier.VERY_HIGH
    if num_trans >= 15:
        criteria.append(f"15+ transformations ({num_trans})")
        return ComplexityTier.VERY_HIGH
    if num_trans >= 10:
        criteria.append(f"10-14 transformations ({num_trans})")
        return ComplexityTier.HIGH
    if num_trans >= 5:
        criteria.append(f"5-9 transformations ({num_trans})")
        return ComplexityTier.MEDIUM
    return ComplexityTier.LOW


def _either_reaches(num_sources: int, num_targets: int, threshold: int) -> bool:
    return num_sources >= threshold or num_targets >= threshold


def _check_source_target_count(
    num_sources: int, num_targets: int, criteria: list
) -> tuple[ComplexityTier, int]:
    """Return (tier, high_structural_delta) based on source/target counts."""
    if _either_reaches(num_sources, num_targets, 5):
        criteria.append(
            f"5+ sources or targets ({num_sources} sources, {num_targets} targets)"
        )
        return ComplexityTier.VERY_HIGH, 0
    if _either_reaches(num_sources, num_targets, 4):
        criteria.append("4+ sources or targets")
        return ComplexityTier.HIGH, 1
    if _either_reaches(num_sources, num_targets, 2):
        criteria.append(f"Multiple sources/targets ({num_sources}s, {num_targets}t)")
        return ComplexityTier.MEDIUM, 0
    return ComplexityTier.LOW, 0


def _check_joiner(joiner_count: int, criteria: list) -> tuple[ComplexityTier, int]:
    if joiner_count > 1:
        criteria.append(f"Multiple Joiners ({joiner_count})")
        return ComplexityTier.HIGH, 1
    if joiner_count == 1:
        criteria.append("Joiner transformation present")
        return ComplexityTier.MEDIUM, 0
    return ComplexityTier.LOW, 0


def _check_lookup(lookup_count: int, criteria: list) -> tuple[ComplexityTier, int]:
    if lookup_count > 1:
        criteria.append(f"Multiple Lookups ({lookup_count})")
        return ComplexityTier.HIGH, 1
    if lookup_count == 1:
        criteria.append("Lookup transformation present")
        return ComplexityTier.MEDIUM, 0
    return ComplexityTier.LOW, 0


def _has_type(keyword: str, trans_types: list) -> bool:
    return any(keyword in t for t in trans_types)


def _check_high_structural_trans(
    trans_types: list, criteria: list
) -> tuple[ComplexityTier, int]:
    """Check Normalizer and Rank — both push to HIGH and count as structural criteria."""
    tier = ComplexityTier.LOW
    high_delta = 0
    if _has_type("Normalizer", trans_types):
        criteria.append("Normalizer transformation present")
        tier = ComplexityTier.HIGH
        high_delta += 1
    if _has_type("Rank", trans_types):
        criteria.append("Rank transformation present")
        tier = _elevate(tier, ComplexityTier.HIGH)
        high_delta += 1
    return tier, high_delta


def _check_very_high_trans(trans_types: list, criteria: list) -> ComplexityTier:
    """Check Transaction Control and HTTP — both push to VERY_HIGH."""
    tier = ComplexityTier.LOW
    if _has_type("Transaction Control", trans_types):
        criteria.append("Transaction Control transformation present")
        tier = ComplexityTier.VERY_HIGH
    if _has_type("HTTP", trans_types):
        criteria.append("HTTP transformation present")
        tier = ComplexityTier.VERY_HIGH
    return tier


def _check_special_trans_types(
    trans_types: list, criteria: list
) -> tuple[ComplexityTier, int]:
    """Check Normalizer, Rank, Transaction Control, HTTP. Returns (tier, high_struct_delta)."""
    tier, high_delta = _check_high_structural_trans(trans_types, criteria)
    tier = _elevate(tier, _check_very_high_trans(trans_types, criteria))
    return tier, high_delta


def _check_sql_override(trans: list, criteria: list) -> ComplexityTier:
    tier = ComplexityTier.LOW
    for t in trans:
        if "Source Qualifier" not in t["type"]:
            continue
        sql = t.get("table_attribs", {}).get("Sql Query", "")
        if not sql:
            continue
        criteria.append("Custom SQL override in Source Qualifier")
        tier = _elevate(tier, ComplexityTier.MEDIUM)
        if len(sql) > 500:
            criteria.append("Complex/long custom SQL override")
            tier = _elevate(tier, ComplexityTier.HIGH)
    return tier


def _check_expressions(trans: list, criteria: list) -> ComplexityTier:
    all_expressions = []
    for t in trans:
        all_expressions.extend(t.get("expressions", []))
    complex_expr = [e for e in all_expressions if _is_complex_expression(e["expression"])]
    if complex_expr:
        criteria.append(f"Complex expressions detected ({len(complex_expr)} fields)")
        return ComplexityTier.MEDIUM
    return ComplexityTier.LOW


def _check_mapplets(trans_types: list, criteria: list) -> ComplexityTier:
    mapplet_count = sum(1 for t in trans_types if "Mapplet" in t)
    if mapplet_count > 1:
        criteria.append(f"Nested/multiple mapplets ({mapplet_count})")
        return ComplexityTier.VERY_HIGH
    if mapplet_count == 1:
        criteria.append("Mapplet used")
        return ComplexityTier.HIGH
    return ComplexityTier.LOW


def _count_type_in_trans(trans_types: list, keyword: str) -> int:
    """Count transformation types containing the given keyword."""
    return sum(1 for t in trans_types if keyword in t)


def _classify_mapping(mapping: dict, graph: dict, criteria: list, special_flags: list) -> tuple[ComplexityTier, int]:
    """Classify a single mapping. Returns (tier, high_structural_criteria)."""
    trans = mapping.get("transformations", [])
    trans_types = [t["type"] for t in trans]
    num_sources = max(len(graph.get("sources", [])), 1)
    num_targets = max(len(graph.get("targets", [])), 1)
    num_trans = len(trans)

    tier = ComplexityTier.LOW
    high_structural_criteria = 0

    tier = _elevate(tier, _check_unsupported(trans, special_flags))
    tier = _elevate(tier, _check_trans_count(num_trans, criteria))

    st_tier, st_high = _check_source_target_count(num_sources, num_targets, criteria)
    tier = _elevate(tier, st_tier)
    high_structural_criteria += st_high

    joiner_count = _count_type_in_trans(trans_types, "Joiner")
    lookup_count = _count_type_in_trans(trans_types, "Lookup")

    j_tier, j_high = _check_joiner(joiner_count, criteria)
    tier = _elevate(tier, j_tier)
    high_structural_criteria += j_high

    l_tier, l_high = _check_lookup(lookup_count, criteria)
    tier = _elevate(tier, l_tier)
    high_structural_criteria += l_high

    sp_tier, sp_high = _check_special_trans_types(trans_types, criteria)
    tier = _elevate(tier, sp_tier)
    high_structural_criteria += sp_high

    tier = _elevate(tier, _check_sql_override(trans, criteria))
    tier = _elevate(tier, _check_expressions(trans, criteria))
    tier = _elevate(tier, _check_mapplets(trans_types, criteria))

    return tier, high_structural_criteria


def _apply_accumulation_escalation(
    tier: ComplexityTier, high_structural_criteria: int, criteria: list
) -> ComplexityTier:
    """Escalate HIGH → VERY_HIGH when 2+ independent structural HIGH criteria accumulate."""
    if tier == ComplexityTier.HIGH and high_structural_criteria >= 2:
        criteria.append(
            f"Accumulation escalation: {high_structural_criteria} independent "
            f"HIGH structural criteria — escalated to VERY_HIGH for documentation budget"
        )
        return ComplexityTier.VERY_HIGH
    return tier


def _default_criteria_if_empty(criteria: list, special_flags: list) -> None:
    if not criteria and not special_flags:
        criteria.append("Single source/target, <5 transformations, no complex logic")


def classify(parse_report: ParseReport, graph: dict) -> ComplexityReport:
    criteria: list[str] = []
    special_flags: list[str] = []
    tier = ComplexityTier.LOW

    for mapping in graph.get("mappings", []):
        m_tier, high_structural_criteria = _classify_mapping(
            mapping, graph, criteria, special_flags
        )
        tier = _elevate(tier, m_tier)
        tier = _apply_accumulation_escalation(tier, high_structural_criteria, criteria)

    _default_criteria_if_empty(criteria, special_flags)

    # ── Pattern classification (v2.16.0-phase5) ──────────────────────────────
    all_trans_types, all_targets = _collect_all_trans_and_targets(graph)

    suggested_pattern, pattern_confidence, pattern_rationale = _classify_pattern(
        trans_types=all_trans_types,
        target_names=all_targets,
        num_sources=max(len(graph.get("sources", [])), 1),
        num_targets=max(len(graph.get("targets", [])), 1),
        has_unsupported=bool(special_flags),
        tier=tier,
        graph=graph,
    )

    # v2.24.0 — numeric scores
    confidence_score = _CONFIDENCE_SCORE.get((pattern_confidence or "NONE").upper(), 65.0)
    completeness_score: float = getattr(parse_report, "completeness_score", 65.0)
    readiness = round(confidence_score * 0.40 + completeness_score * 0.60, 1)

    return ComplexityReport(
        tier=tier,
        criteria_matched=criteria,
        data_volume_est=None,   # Would need session XML or parameter files
        special_flags=special_flags,
        rationale=_build_rationale(tier, criteria, special_flags),
        suggested_pattern=suggested_pattern,
        pattern_confidence=pattern_confidence,
        pattern_rationale=pattern_rationale,
        pattern_confidence_score=confidence_score,
        conversion_readiness=readiness,
    )


def _is_target_trans(t: dict) -> bool:
    """Return True if a transformation is a target (by name or type)."""
    return "Target" in t.get("name", "").upper() or t["type"] in ("Target Definition",)


def _collect_all_trans_and_targets(graph: dict) -> tuple[list[str], list[str]]:
    """Collect all transformation types and target names across all mappings."""
    all_trans_types: list[str] = []
    all_targets: list[str] = []
    for mapping in graph.get("mappings", []):
        all_trans_types.extend(t["type"] for t in mapping.get("transformations", []))
        all_targets.extend(
            t.get("name", "").upper()
            for t in mapping.get("transformations", [])
            if _is_target_trans(t)
        )
    return all_trans_types, all_targets


# ── Pattern classification ─────────────────────────────────────────────────────

def _pattern_unsupported_result() -> tuple[str | None, str | None, str | None]:
    return None, "NONE", (
        "Mapping contains unsupported transformations "
        "(Java/External Procedure/Stored Procedure). "
        "Pattern library cannot be applied; full LLM conversion required."
    )


def _pattern_no_match_result() -> tuple[str | None, str | None, str | None]:
    return (
        None,
        "NONE",
        "Mapping complexity does not clearly match any of the 10 supported patterns. "
        "Full LLM conversion recommended without a config skeleton.",
    )


def _check_filter_route(tset: set, num_targets: int) -> tuple[str | None, str | None, str | None] | None:
    if not any("router" in t for t in tset):
        return None
    conf = "HIGH" if num_targets >= 2 else "MEDIUM"
    return (
        "filter_and_route",
        conf,
        "Router transformation detected. Each Router group maps to a separate "
        "filter_and_route target with a filter_expr condition.",
    )


def _check_union_consolidate(tset: set, sq_count: int) -> tuple[str | None, str | None, str | None] | None:
    has_union = any("union" in t for t in tset)
    if sq_count < 3 and not has_union:
        return None
    conf = "HIGH" if sq_count >= 3 else "MEDIUM"
    return (
        "union_consolidate",
        conf,
        f"{sq_count} Source Qualifier(s) detected — multiple input streams converge "
        "into a single target. Use union_consolidate with per-source column_map "
        "to normalise schemas before concatenation.",
    )


def _check_aggregation_load(tset: set) -> tuple[str | None, str | None, str | None] | None:
    if not any("aggregator" in t for t in tset):
        return None
    return (
        "aggregation_load",
        "HIGH",
        "Aggregator transformation detected. Map GROUP BY columns and aggregate "
        "metrics (sum/count/avg/…) to the aggregation_load config.",
    )


def _check_scd2(tgt_str: str, scd2_signals: list) -> tuple[str | None, str | None, str | None] | None:
    if not any(sig in tgt_str for sig in scd2_signals):
        return None
    return (
        "scd2",
        "HIGH",
        "Target name contains SCD/HISTORY/ARCHIVE indicator. "
        "Classify as scd2 with business_key, tracked_cols, "
        "effective_from/to, and is_current fields.",
    )


def _is_single_joiner_no_agg(tset: set) -> bool:
    joiner_cnt = sum(1 for t in tset if "joiner" in t)
    has_agg = any("aggregator" in t for t in tset)
    return joiner_cnt == 1 and not has_agg


def _check_upsert(
    tset: set, tgt_str: str, upsert_signals: list
) -> tuple[str | None, str | None, str | None] | None:
    name_match = any(sig in tgt_str for sig in upsert_signals)
    has_single_joiner = _is_single_joiner_no_agg(tset)
    if not name_match and not has_single_joiner:
        return None
    conf = "HIGH" if name_match else "MEDIUM"
    return (
        "upsert",
        conf,
        "Target name suggests a dimension/upsert load or a single Joiner was "
        "detected without aggregation. Use upsert with unique_key set to the "
        "natural/business key of the target.",
    )


def _check_lookup_enrich(tset: set) -> tuple[str | None, str | None, str | None] | None:
    lkp_cnt = sum(1 for t in tset if "lookup" in t)
    if lkp_cnt == 0:
        return None
    conf = "HIGH" if lkp_cnt >= 2 else "MEDIUM"
    return (
        "lookup_enrich",
        conf,
        f"{lkp_cnt} Lookup transformation(s) detected. Use lookup_enrich to join "
        "each reference table onto the main source stream. Configure join_keys, "
        "join_type (left/inner), and optional prefix per lookup.",
    )


def _check_incremental_append(
    tset: set, tgt_str: str, inc_signals: list
) -> tuple[str | None, str | None, str | None] | None:
    has_expr = any("expression" in t for t in tset)
    if not any(sig in tgt_str for sig in inc_signals) or not has_expr:
        return None
    return (
        "incremental_append",
        "MEDIUM",
        "Target name contains an incremental/append indicator and an Expression "
        "transformation is present. Configure incremental_append with a watermark "
        "column (e.g. UPDATED_AT or LOAD_DATE) and write_mode: append.",
    )


def _is_simple_one_to_one(trans_types: list, num_sources: int, num_targets: int) -> bool:
    """True if pipeline is ≤4 transforms, single source, single target."""
    return len(trans_types) <= 4 and num_sources == 1 and num_targets == 1


def _check_expression_transform(
    tset: set, trans_types: list, num_sources: int, num_targets: int
) -> tuple[str | None, str | None, str | None] | None:
    has_expr = any("expression" in t for t in tset)
    if not has_expr or not _is_simple_one_to_one(trans_types, num_sources, num_targets):
        return None
    return (
        "expression_transform",
        "MEDIUM",
        "Expression transformation with simple 1→1 pipeline "
        f"({len(trans_types)} transformation(s) total). "
        "Map each output column to an expression in the column_map config.",
    )


def _check_truncate_load(
    trans_types: list, num_sources: int, num_targets: int
) -> tuple[str | None, str | None, str | None] | None:
    if num_sources != 1 or num_targets != 1 or len(trans_types) > 6:
        return None
    return (
        "truncate_and_load",
        "MEDIUM",
        "Single-source single-target pipeline with no aggregation, join, or "
        "routing transformations. Use truncate_and_load with write_mode: replace "
        "for a full reload on each run.",
    )


def _check_pass_through(
    trans_types: list,
) -> tuple[str | None, str | None, str | None] | None:
    if len(trans_types) > 2:
        return None
    return (
        "pass_through",
        "LOW",
        "Two or fewer transformations with no aggregation, join, lookup, or routing. "
        "pass_through copies the source schema directly to the target.",
    )


def _build_pattern_inputs(
    trans_types: list[str], target_names: list[str]
) -> tuple[set, str, int]:
    """Return (tset, tgt_str, sq_count) derived from trans_types and target_names."""
    tset = {t.lower() for t in trans_types}
    tgt_str = " ".join(target_names).upper()
    sq_count = _count_type_in_trans(trans_types, "Source Qualifier")
    return tset, tgt_str, sq_count


def _first_matching_pattern(checks: list) -> tuple[str | None, str | None, str | None] | None:
    """Return the first non-None result from a list of pattern check results."""
    for result in checks:
        if result is not None:
            return result
    return None


def _classify_pattern(
    trans_types: list[str],
    target_names: list[str],
    num_sources: int,
    num_targets: int,
    has_unsupported: bool,
    tier: "ComplexityTier",
    graph: dict,
) -> tuple[str | None, str | None, str | None]:
    """
    10-pattern decision tree.

    Returns (pattern_name, confidence, rationale) where
    confidence ∈ {"HIGH", "MEDIUM", "LOW", "NONE"}.

    A NONE confidence means the mapping does not clearly map to any supported
    pattern and should be fully converted by the LLM without a config skeleton.

    Decision priority (first match wins):
        1. filter_and_route    — Router transformation present
        2. union_consolidate   — 3+ source qualifiers OR Union transformation
        3. aggregation_load    — Aggregator transformation present
        4. scd2                — target name contains SCD/HISTORY/HIST/ARCHIVE
        5. upsert              — target name contains UPSERT/UPDATE/MERGE/DIM
                                 OR single joiner with no aggregation
        6. lookup_enrich       — 1+ Lookup transformations without Aggregator/Router
        7. incremental_append  — Source Qualifier + Expression + target APPEND/INC/DELTA
        8. expression_transform — Expression transformation; ≤2 trans total; 1→1
        9. truncate_and_load   — Simple 1→1 pipeline with no complex transformations
       10. pass_through         — Bare source → target with nothing between (≤2 trans)
    """
    if has_unsupported:
        return _pattern_unsupported_result()

    tset, tgt_str, sq_count = _build_pattern_inputs(trans_types, target_names)
    _signals = get_pattern_signals()

    checks = [
        _check_filter_route(tset, num_targets),
        _check_union_consolidate(tset, sq_count),
        _check_aggregation_load(tset),
        _check_scd2(tgt_str, _signals["scd2"]),
        _check_upsert(tset, tgt_str, _signals["upsert"]),
        _check_lookup_enrich(tset),
        _check_incremental_append(tset, tgt_str, _signals["incremental_append"]),
        _check_expression_transform(tset, trans_types, num_sources, num_targets),
        _check_truncate_load(trans_types, num_sources, num_targets),
        _check_pass_through(trans_types),
    ]

    matched = _first_matching_pattern(checks)
    return matched if matched is not None else _pattern_no_match_result()


# ── YAML skeleton builders ─────────────────────────────────────────────────────

def _build_yaml_header(pattern: str, slug: str, mapping_name: str) -> list[str]:
    return [
        f"# etl_patterns config — auto-generated skeleton for {mapping_name}",
        f"# Review all TODO fields before running.",
        f"",
        f"pattern:      {pattern}",
        f"mapping_name: {slug}",
        f"",
    ]


def _build_db_source_block(src_name: str) -> list[str]:
    return [
        "source:",
        f"  type:    database",
        f"  connection_string: ${{{{SOURCE_CONN}}}}   # TODO: set env var",
        f"  table:   {src_name}",
    ]


def _resolve_flat_file_path(
    file_dir: str, file_name: str, src_name: str
) -> str:
    if file_dir and file_name:
        return f"{file_dir.rstrip('/')}/{file_name}"
    return f"/data/in/{src_name.lower()}.csv   # TODO: set actual file path"


def _build_flat_file_source_block(src_name: str, ff_meta: dict) -> list[str]:
    file_dir = ff_meta.get("file_dir", "") or "/data/in"
    file_name = ff_meta.get("file_name", "") or f"{src_name.lower()}.csv"
    delimiter = ff_meta.get("delimiter", ",")
    has_header = ff_meta.get("has_header", True)
    skip_rows = ff_meta.get("skip_rows", 0)
    full_path = _resolve_flat_file_path(file_dir, file_name, src_name)
    header_str = "true" if has_header else "false"
    lines = [
        "source:",
        f"  type:       flat_file",
        f"  name:       {src_name}",
        f"  path:       {full_path}",
        f"  delimiter:  \"{delimiter}\"",
        f"  has_header: {header_str}",
    ]
    if skip_rows:
        lines.append(f"  skip_rows:  {skip_rows}")
    lines += [
        "  encoding:   utf-8   # TODO: confirm encoding",
        "  file_lifecycle:",
        "    archive_dir:   /data/archive   # TODO: set archive path",
        "    archive_dated: true",
        "    reject_dir:    /data/rejects   # TODO: set reject path",
    ]
    return lines


def _build_yaml_source_block(src: dict) -> list[str]:
    src_name = src.get("name", "SOURCE_TABLE")
    if src.get("db_type", "") != "Flat File":
        return _build_db_source_block(src_name)
    return _build_flat_file_source_block(src_name, src.get("flat_file", {}))


def _build_yaml_pattern_block(pattern: str) -> list[str]:
    """Return pattern-specific YAML block (inserted after source block)."""
    _PATTERN_BLOCKS: dict[str, list[str]] = {
        "incremental_append": [
            "",
            "  watermark:",
            "    column:    UPDATED_AT   # TODO: confirm watermark column name",
            "    data_type: datetime",
            "    initial:   \"1900-01-01\"",
        ],
        "aggregation_load": [
            "",
            "group_by:   # TODO: list your GROUP BY columns",
            "  - BRANCH_ID   # TODO: replace with actual column(s)",
            "",
            "aggregations:   # TODO: fill in aggregate metrics",
            "  - target_col: TXN_COUNT",
            "    func:        count",
            "    source_col:  TXN_ID   # TODO: replace with actual source column",
        ],
        "filter_and_route": [""],
        "scd2": [
            "",
            "scd2:",
            "  business_key:",
            "    - ID   # TODO: replace with your natural/business key column(s)",
            "  tracked_cols:   # TODO: list columns that trigger a new SCD2 row when changed",
            "    - NAME",
            "    - STATUS",
        ],
        "lookup_enrich": [
            "",
            "lookups:   # TODO: configure each reference table lookup",
            "  - name:    DIM_REFERENCE   # TODO: replace with actual lookup name",
            "    type:    database",
            "    connection_string: ${{{{LOOKUP_CONN}}}}",
            "    table:   REFERENCE_TABLE   # TODO",
            "    join_keys:",
            "      SOURCE_KEY: LOOKUP_KEY   # TODO: source_col: lookup_col",
            "    join_type: left",
            "    cache:    true",
        ],
    }
    return _PATTERN_BLOCKS.get(pattern, [])


def _build_yaml_target_block(pattern: str, tgt_name: str) -> list[str]:
    lines = ["", "target:"]
    if pattern == "filter_and_route":
        lines += [
            "  # TODO: add one entry per output stream",
            "  - name:        STREAM_A",
            "    type:        database",
            "    connection_string: ${{{{TARGET_CONN}}}}",
            "    table:       TARGET_A   # TODO",
            "    write_mode:  append",
            "    filter_expr: \"{COLUMN} == 'VALUE'\"   # TODO: condition for this stream",
            "  - name:        STREAM_B",
            "    type:        database",
            "    connection_string: ${{{{TARGET_CONN}}}}",
            "    table:       TARGET_B   # TODO",
            "    write_mode:  append",
            "    filter_expr: \"true\"   # catch-all",
        ]
    elif pattern == "upsert":
        lines += [
            f"  type:       database",
            f"  connection_string: ${{{{TARGET_CONN}}}}",
            f"  table:      {tgt_name}",
            f"  write_mode: upsert",
            f"  unique_key:",
            f"    - ID   # TODO: replace with your business/natural key column(s)",
        ]
    elif pattern == "union_consolidate":
        lines += [
            f"  type:       database",
            f"  connection_string: ${{{{TARGET_CONN}}}}",
            f"  table:      {tgt_name}",
            f"  write_mode: replace",
        ]
    elif pattern == "scd2":
        lines += [
            f"  type:       database",
            f"  connection_string: ${{{{TARGET_CONN}}}}",
            f"  table:      {tgt_name}",
        ]
    else:
        lines += [
            f"  type:       database",
            f"  connection_string: ${{{{TARGET_CONN}}}}",
            f"  table:      {tgt_name}",
            f"  write_mode: replace   # TODO: adjust (replace | append | upsert)",
        ]
    return lines


def _build_pattern_yaml_skeleton(
    pattern: str,
    mapping_name: str,
    graph: dict,
) -> str:
    """
    Return a starter YAML config skeleton for the suggested pattern.
    The skeleton is pre-filled where possible from the parsed graph; any
    field that requires human review is marked with a TODO comment.
    """
    slug = mapping_name.lower().replace(" ", "_")

    sources = graph.get("sources", [])
    targets = graph.get("targets", [])
    src = sources[0] if sources else {}
    tgt_name = targets[0].get("name", "TARGET_TABLE") if targets else "TARGET_TABLE"

    lines = _build_yaml_header(pattern, slug, mapping_name)
    lines += _build_yaml_source_block(src)
    lines += _build_yaml_pattern_block(pattern)
    lines += _build_yaml_target_block(pattern, tgt_name)

    lines += [
        "",
        "etl_metadata: true",
        "",
        "# Run with:",
        f"# python run.py config/{slug}.yaml",
    ]

    if pattern == "union_consolidate":
        lines.insert(
            lines.index("source:"),
            "# TODO: Replace the single 'source:' block below with a 'sources:' list"
            " (one entry per input stream)"
        )

    return "\n".join(lines) + "\n"
