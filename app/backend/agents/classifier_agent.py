"""
STEP 2 — Complexity Classifier Agent
Rule-based scoring against objective criteria from the spec.
"""
from __future__ import annotations
from ..models.schemas import ComplexityReport, ComplexityTier, ParseReport

UNSUPPORTED_TYPES = {
    "Java Transformation", "External Procedure",
    "Advanced External Procedure", "Stored Procedure"
}


def classify(parse_report: ParseReport, graph: dict) -> ComplexityReport:
    criteria: list[str] = []
    special_flags: list[str] = []
    tier = ComplexityTier.LOW

    for mapping in graph.get("mappings", []):
        trans      = mapping.get("transformations", [])
        trans_types = [t["type"] for t in trans]
        sources    = [t for t in trans if "Source Qualifier" in t["type"]]
        targets    = [t for t in trans if "Target" in t.get("name", "").upper() or
                      t["type"] in ("Target Definition",)]
        num_sources = max(len(graph.get("sources", [])), 1)
        num_targets = max(len(graph.get("targets", [])), 1)
        num_trans  = len(trans)

        # Counts of criteria that independently push to HIGH — used for accumulation escalation
        high_structural_criteria = 0

        # ── Check unsupported (auto Very High) ───
        for t in trans:
            if t["type"] in UNSUPPORTED_TYPES:
                special_flags.append(f"UNSUPPORTED_TRANSFORMATION: {t['name']} ({t['type']})")
                tier = ComplexityTier.VERY_HIGH

        # ── Count-based criteria ──────────────────
        if num_trans >= 30:
            criteria.append(f"30+ transformations ({num_trans})")
            tier = _elevate(tier, ComplexityTier.VERY_HIGH)
        elif num_trans >= 15:
            criteria.append(f"15+ transformations ({num_trans})")
            tier = _elevate(tier, ComplexityTier.VERY_HIGH)  # was HIGH — 15+ reliably exceeds HIGH doc budget
        elif num_trans >= 10:
            criteria.append(f"10-14 transformations ({num_trans})")
            tier = _elevate(tier, ComplexityTier.HIGH)       # new intermediate band
        elif num_trans >= 5:
            criteria.append(f"5-9 transformations ({num_trans})")
            tier = _elevate(tier, ComplexityTier.MEDIUM)

        if num_sources >= 5 or num_targets >= 5:
            criteria.append(f"5+ sources or targets ({num_sources} sources, {num_targets} targets)")
            tier = _elevate(tier, ComplexityTier.VERY_HIGH)
        elif num_sources >= 4 or num_targets >= 4:
            criteria.append(f"4+ sources or targets")
            tier = _elevate(tier, ComplexityTier.HIGH)
            high_structural_criteria += 1
        elif num_sources >= 2 or num_targets >= 2:
            criteria.append(f"Multiple sources/targets ({num_sources}s, {num_targets}t)")
            tier = _elevate(tier, ComplexityTier.MEDIUM)

        # ── Transformation-type criteria ──────────
        joiner_count = sum(1 for t in trans_types if "Joiner" in t)
        lookup_count = sum(1 for t in trans_types if "Lookup" in t)
        router_count = sum(1 for t in trans_types if "Router" in t)

        if joiner_count > 1:
            criteria.append(f"Multiple Joiners ({joiner_count})")
            tier = _elevate(tier, ComplexityTier.HIGH)
            high_structural_criteria += 1
        elif joiner_count == 1:
            criteria.append("Joiner transformation present")
            tier = _elevate(tier, ComplexityTier.MEDIUM)

        if lookup_count > 1:
            criteria.append(f"Multiple Lookups ({lookup_count})")
            tier = _elevate(tier, ComplexityTier.HIGH)
            high_structural_criteria += 1
        elif lookup_count == 1:
            criteria.append("Lookup transformation present")
            tier = _elevate(tier, ComplexityTier.MEDIUM)

        if any("Normalizer" in t for t in trans_types):
            criteria.append("Normalizer transformation present")
            tier = _elevate(tier, ComplexityTier.HIGH)
            high_structural_criteria += 1

        if any("Rank" in t for t in trans_types):
            criteria.append("Rank transformation present")
            tier = _elevate(tier, ComplexityTier.HIGH)
            high_structural_criteria += 1

        if any("Transaction Control" in t for t in trans_types):
            criteria.append("Transaction Control transformation present")
            tier = _elevate(tier, ComplexityTier.VERY_HIGH)

        if any("HTTP" in t for t in trans_types):
            criteria.append("HTTP transformation present")
            tier = _elevate(tier, ComplexityTier.VERY_HIGH)

        # ── SQL override check ────────────────────
        for t in trans:
            if "Source Qualifier" in t["type"]:
                sql = t.get("table_attribs", {}).get("Sql Query", "")
                if sql:
                    criteria.append("Custom SQL override in Source Qualifier")
                    tier = _elevate(tier, ComplexityTier.MEDIUM)
                    if len(sql) > 500:
                        criteria.append("Complex/long custom SQL override")
                        tier = _elevate(tier, ComplexityTier.HIGH)

        # ── Expression complexity ─────────────────
        all_expressions = []
        for t in trans:
            all_expressions.extend(t.get("expressions", []))
        complex_expr = [e for e in all_expressions if _is_complex_expression(e["expression"])]
        if complex_expr:
            criteria.append(f"Complex expressions detected ({len(complex_expr)} fields)")
            tier = _elevate(tier, ComplexityTier.MEDIUM)

        # ── Nested mapplets ───────────────────────
        mapplet_count = sum(1 for t in trans_types if "Mapplet" in t)
        if mapplet_count > 1:
            criteria.append(f"Nested/multiple mapplets ({mapplet_count})")
            tier = _elevate(tier, ComplexityTier.VERY_HIGH)
        elif mapplet_count == 1:
            criteria.append("Mapplet used")
            tier = _elevate(tier, ComplexityTier.HIGH)

        # ── Accumulation escalation ───────────────────────────────────────────
        # A mapping that hits HIGH from 2+ independent structural criteria
        # (e.g. multiple joiners + 4+ sources) will generate substantially more
        # documentation than a simple HIGH mapping — escalate to VERY_HIGH so
        # the dynamic token budget allocates sufficient room.
        if tier == ComplexityTier.HIGH and high_structural_criteria >= 2:
            criteria.append(
                f"Accumulation escalation: {high_structural_criteria} independent "
                f"HIGH structural criteria — escalated to VERY_HIGH for documentation budget"
            )
            tier = ComplexityTier.VERY_HIGH

    if not criteria and not special_flags:
        criteria.append("Single source/target, <5 transformations, no complex logic")

    # ── Pattern classification (v2.16.0-phase5) ──────────────────────────────
    all_trans_types: list[str] = []
    all_targets: list[str] = []
    for mapping in graph.get("mappings", []):
        all_trans_types.extend(t["type"] for t in mapping.get("transformations", []))
        all_targets.extend(
            t.get("name", "").upper()
            for t in mapping.get("transformations", [])
            if "Target" in t.get("name", "").upper() or
               t["type"] in ("Target Definition",)
        )

    suggested_pattern, pattern_confidence, pattern_rationale = _classify_pattern(
        trans_types=all_trans_types,
        target_names=all_targets,
        num_sources=max(len(graph.get("sources", [])), 1),
        num_targets=max(len(graph.get("targets", [])), 1),
        has_unsupported=bool(special_flags),
        tier=tier,
        graph=graph,
    )

    return ComplexityReport(
        tier=tier,
        criteria_matched=criteria,
        data_volume_est=None,   # Would need session XML or parameter files
        special_flags=special_flags,
        rationale=_build_rationale(tier, criteria, special_flags),
        suggested_pattern=suggested_pattern,
        pattern_confidence=pattern_confidence,
        pattern_rationale=pattern_rationale,
    )


def _elevate(current: ComplexityTier, candidate: ComplexityTier) -> ComplexityTier:
    order = [ComplexityTier.LOW, ComplexityTier.MEDIUM,
             ComplexityTier.HIGH, ComplexityTier.VERY_HIGH]
    return candidate if order.index(candidate) > order.index(current) else current


def _is_complex_expression(expr: str) -> bool:
    if not expr:
        return False
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


# ── Pattern classification ─────────────────────────────────────────────────────

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
    # Unsupported transformations → no pattern can handle these
    if has_unsupported:
        return None, "NONE", (
            "Mapping contains unsupported transformations "
            "(Java/External Procedure/Stored Procedure). "
            "Pattern library cannot be applied; full LLM conversion required."
        )

    tset = {t.lower() for t in trans_types}

    def _has(keyword: str) -> bool:
        return any(keyword in t for t in tset)

    def _count(keyword: str) -> int:
        return sum(1 for t in tset if keyword in t)

    tgt_str = " ".join(target_names).upper()
    sq_count = sum(1 for t in trans_types if "Source Qualifier" in t)

    # 1. filter_and_route — Router → N targets
    if _has("router"):
        return (
            "filter_and_route",
            "HIGH" if num_targets >= 2 else "MEDIUM",
            "Router transformation detected. Each Router group maps to a separate "
            "filter_and_route target with a filter_expr condition.",
        )

    # 2. union_consolidate — multiple source streams merged into one target
    if sq_count >= 3 or _has("union"):
        return (
            "union_consolidate",
            "HIGH" if sq_count >= 3 else "MEDIUM",
            f"{sq_count} Source Qualifier(s) detected — multiple input streams converge "
            "into a single target. Use union_consolidate with per-source column_map "
            "to normalise schemas before concatenation.",
        )

    # 3. aggregation_load — Aggregator drives a GROUP BY
    if _has("aggregator"):
        return (
            "aggregation_load",
            "HIGH",
            "Aggregator transformation detected. Map GROUP BY columns and aggregate "
            "metrics (sum/count/avg/…) to the aggregation_load config.",
        )

    # 4. scd2 — history / slowly changing dimension type 2
    _SCD2_SIGNALS = ("SCD", "HISTORY", "HIST", "ARCHIVE", "SCD2", "DIM_HIST")
    if any(sig in tgt_str for sig in _SCD2_SIGNALS):
        return (
            "scd2",
            "HIGH",
            "Target name contains SCD/HISTORY/ARCHIVE indicator. "
            "Classify as scd2 with business_key, tracked_cols, "
            "effective_from/to, and is_current fields.",
        )

    # 5. upsert — overwrite-on-key pattern (Type 1 SCD / dimension load)
    _UPSERT_SIGNALS = ("UPSERT", "UPDATE", "MERGE", "DIM_", "_DIM", "DIMENSION")
    has_single_joiner = _count("joiner") == 1 and not _has("aggregator")
    if any(sig in tgt_str for sig in _UPSERT_SIGNALS) or has_single_joiner:
        conf = "HIGH" if any(sig in tgt_str for sig in _UPSERT_SIGNALS) else "MEDIUM"
        return (
            "upsert",
            conf,
            "Target name suggests a dimension/upsert load or a single Joiner was "
            "detected without aggregation. Use upsert with unique_key set to the "
            "natural/business key of the target.",
        )

    # 6. lookup_enrich — reference-table joins onto a transaction stream
    if _has("lookup"):
        lkp_cnt = _count("lookup")
        return (
            "lookup_enrich",
            "HIGH" if lkp_cnt >= 2 else "MEDIUM",
            f"{lkp_cnt} Lookup transformation(s) detected. Use lookup_enrich to join "
            "each reference table onto the main source stream. Configure join_keys, "
            "join_type (left/inner), and optional prefix per lookup.",
        )

    # 7. incremental_append — watermark-filtered append
    # Use specific signals that reliably indicate delta/incremental loads.
    # Avoid generic terms like STAGING that are commonly used for full-reload tables.
    _INC_SIGNALS = ("APPEND", "_INC", "INC_", "DELTA", "INCREMENTAL", "RECENT")
    if any(sig in tgt_str for sig in _INC_SIGNALS) and _has("expression"):
        return (
            "incremental_append",
            "MEDIUM",
            "Target name contains an incremental/append indicator and an Expression "
            "transformation is present. Configure incremental_append with a watermark "
            "column (e.g. UPDATED_AT or LOAD_DATE) and write_mode: append.",
        )

    # 8. expression_transform — pure column-level transform, 1-to-1
    if _has("expression") and len(trans_types) <= 4 and num_sources == 1 and num_targets == 1:
        return (
            "expression_transform",
            "MEDIUM",
            "Expression transformation with simple 1→1 pipeline "
            f"({len(trans_types)} transformation(s) total). "
            "Map each output column to an expression in the column_map config.",
        )

    # 9. truncate_and_load — full-reload into a single target
    if num_sources == 1 and num_targets == 1 and len(trans_types) <= 6:
        return (
            "truncate_and_load",
            "MEDIUM",
            "Single-source single-target pipeline with no aggregation, join, or "
            "routing transformations. Use truncate_and_load with write_mode: replace "
            "for a full reload on each run.",
        )

    # 10. pass_through — minimal pipeline, no meaningful transforms
    if len(trans_types) <= 2:
        return (
            "pass_through",
            "LOW",
            "Two or fewer transformations with no aggregation, join, lookup, or routing. "
            "pass_through copies the source schema directly to the target.",
        )

    # No clear match
    return (
        None,
        "NONE",
        "Mapping complexity does not clearly match any of the 10 supported patterns. "
        "Full LLM conversion recommended without a config skeleton.",
    )


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

    # Gather source and target info from the graph
    sources = graph.get("sources", [])
    targets = graph.get("targets", [])
    src      = sources[0] if sources else {}
    src_name = src.get("name", "SOURCE_TABLE")
    tgt_name = targets[0].get("name", "TARGET_TABLE") if targets else "TARGET_TABLE"
    is_flat_file = src.get("db_type", "") == "Flat File"
    ff_meta      = src.get("flat_file", {}) if is_flat_file else {}

    # Collect all field expressions from Aggregator/Expression transformations
    all_exprs: list[dict] = []
    for mapping in graph.get("mappings", []):
        for t in mapping.get("transformations", []):
            all_exprs.extend(t.get("expressions", []))

    lines = [
        f"# etl_patterns config — auto-generated skeleton for {mapping_name}",
        f"# Review all TODO fields before running.",
        f"",
        f"pattern:      {pattern}",
        f"mapping_name: {slug}",
        f"",
    ]

    # ── source block ──────────────────────────────────────────────────────────
    if is_flat_file:
        # Derive path from parsed flat_file metadata; fall back to TODO placeholders
        file_dir  = ff_meta.get("file_dir", "")   or "/data/in"
        file_name = ff_meta.get("file_name", "") or f"{src_name.lower()}.csv"
        delimiter = ff_meta.get("delimiter", ",")
        has_header = ff_meta.get("has_header", True)
        skip_rows  = ff_meta.get("skip_rows", 0)
        full_path  = (
            f"{file_dir.rstrip('/')}/{file_name}"
            if file_dir and file_name
            else f"/data/in/{src_name.lower()}.csv   # TODO: set actual file path"
        )
        lines += [
            "source:",
            f"  type:       flat_file",
            f"  name:       {src_name}",
            f"  path:       {full_path}",
            f"  delimiter:  \"{delimiter}\"",
            f"  has_header: {'true' if has_header else 'false'}",
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
    else:
        lines += [
            "source:",
            f"  type:    database",
            f"  connection_string: ${{{{SOURCE_CONN}}}}   # TODO: set env var",
            f"  table:   {src_name}",
        ]

    # ── pattern-specific blocks ───────────────────────────────────────────────
    if pattern == "incremental_append":
        lines += [
            "",
            "  watermark:",
            "    column:    UPDATED_AT   # TODO: confirm watermark column name",
            "    data_type: datetime",
            "    initial:   \"1900-01-01\"",
        ]

    elif pattern == "aggregation_load":
        # Try to infer group-by columns and aggregates from expressions
        lines += [
            "",
            "group_by:   # TODO: list your GROUP BY columns",
            "  - BRANCH_ID   # TODO: replace with actual column(s)",
            "",
            "aggregations:   # TODO: fill in aggregate metrics",
            "  - target_col: TXN_COUNT",
            "    func:        count",
            "    source_col:  TXN_ID   # TODO: replace with actual source column",
        ]

    elif pattern == "filter_and_route":
        lines += [""]  # target block handled below

    elif pattern in ("scd2",):
        lines += [
            "",
            "scd2:",
            "  business_key:",
            "    - ID   # TODO: replace with your natural/business key column(s)",
            "  tracked_cols:   # TODO: list columns that trigger a new SCD2 row when changed",
            "    - NAME",
            "    - STATUS",
        ]

    elif pattern == "upsert":
        pass  # unique_key goes in target block

    elif pattern == "lookup_enrich":
        lines += [
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
        ]

    # ── target block ──────────────────────────────────────────────────────────
    lines += ["", "target:"]

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
        # Replace source block with multi-source block
        # (Insert placeholder guidance only — actual source configs need manual input)
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

    lines += [
        "",
        "etl_metadata: true",
        "",
        "# Run with:",
        f"# python run.py config/{slug}.yaml",
    ]

    # union_consolidate needs a multi-source block — add a note
    if pattern == "union_consolidate":
        lines.insert(
            lines.index("source:"),
            "# TODO: Replace the single 'source:' block below with a 'sources:' list"
            " (one entry per input stream)"
        )

    return "\n".join(lines) + "\n"
