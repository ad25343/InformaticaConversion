# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Analyst View Validator — validates 3a (Systems Requirements) and 3b (Gaps & Review
Findings) documents for structural consistency, table schema correctness, and
cross-reference integrity.

Runs immediately after generation, BEFORE the documents are stored in job state.
Returns a ValidationReport that the orchestrator uses to:
  - Log warnings for non-critical issues
  - Auto-repair minor issues (e.g., missing --- separators)
  - Flag critical issues that may warrant a retry

This validator is the quality gate that ensures downstream consumers (code gen,
STTM builder, test case gen) receive a predictably structured input.
"""
from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("conversion.analyst_view_validator")


# ─────────────────────────────────────────────
# Validation Result Types
# ─────────────────────────────────────────────

@dataclass
class Issue:
    section: str           # e.g., "3a/4.3 Lookups"
    severity: str          # "critical", "warning", "info"
    code: str              # machine-readable code, e.g., "MISSING_SECTION"
    message: str           # human-readable description
    auto_fixable: bool = False


@dataclass
class ValidationReport:
    doc_type: str          # "3a" or "3b"
    issues: list[Issue] = field(default_factory=list)
    section_count: int = 0
    table_count: int = 0
    mermaid_count: int = 0
    code_block_count: int = 0

    @property
    def is_valid(self) -> bool:
        return not any(i.severity == "critical" for i in self.issues)

    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "critical")

    @property
    def warning_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "warning")

    def summary(self) -> str:
        if not self.issues:
            return f"{self.doc_type}: PASS ({self.section_count} sections, {self.table_count} tables)"
        crits = self.critical_count
        warns = self.warning_count
        parts = []
        if crits:
            parts.append(f"{crits} critical")
        if warns:
            parts.append(f"{warns} warnings")
        status = "FAIL" if crits else "PASS"
        return f"{self.doc_type}: {status} — {', '.join(parts)} ({self.section_count} sections, {self.table_count} tables)"


# ─────────────────────────────────────────────
# Expected Structures
# ─────────────────────────────────────────────

# 3a required sections (## level)
_3A_REQUIRED_SECTIONS = [
    (r"##\s+1\.\s+Purpose", "1. Purpose & Business Context"),
    (r"##\s+2\.\s+Source",  "2. Source Systems"),
    (r"##\s+3\.\s+Target",  "3. Target Systems"),
    (r"##\s+4\.\s+Data\s+Flow", "4. Data Flow & Transformation Rules"),
    (r"##\s+5\.\s+Key\s+Business", "5. Key Business Rules"),
    (r"##\s+6\.\s+Parameters", "6. Parameters & Runtime Dependencies"),
    (r"##\s+7\.\s+Testing", "7. Testing Considerations"),
    (r"##\s+8\.\s+Structural", "8. Structural Observations"),
]

# 3a required subsections (### level)
_3A_REQUIRED_SUBSECTIONS = [
    (r"###\s+4\.1\s+Pipeline",     "4.1 Pipeline Overview"),
    (r"###\s+4\.2\s+Joins",        "4.2 Joins"),
    (r"###\s+4\.3\s+Lookups",      "4.3 Lookups"),
    (r"###\s+4\.4\s+Filters",      "4.4 Filters"),
    (r"###\s+4\.5\s+Derivations",  "4.5 Derivations"),
    (r"###\s+4\.6\s+Aggregations", "4.6 Aggregations"),
    (r"###\s+4\.7\s+Routing",      "4.7 Routing"),
    (r"###\s+4\.8\s+Complete\s+Field", "4.8 Complete Field Mapping"),
    (r"###\s+7\.1\s+Reconciliation", "7.1 Reconciliation Points"),
    (r"###\s+7\.2\s+Test\s+Data",  "7.2 Test Data"),
    (r"###\s+7\.3\s+Edge\s+Cases", "7.3 Edge Cases"),
]

# 3b required sections
_3B_REQUIRED_SECTIONS = [
    (r"##\s+1\.\s+Summary",            "1. Summary"),
]

# 3b optional sections (should exist if there are findings)
_3B_OPTIONAL_SECTIONS = [
    (r"##\s+2\.\s+Documentation\s+Gaps", "2. Documentation Gaps"),
    (r"##\s+3\.\s+Ambiguities",          "3. Ambiguities"),
    (r"##\s+4\.\s+Data\s+Quality",       "4. Data Quality Concerns"),
    (r"##\s+5\.\s+Structural\s+Issues",  "5. Structural Issues"),
    (r"##\s+6\.\s+Pre-Conversion",       "6. Pre-Conversion Checklist"),
]

# Expected table headers for key tables (column names, lowercase for matching)
_EXPECTED_TABLE_SCHEMAS = {
    "4.2 Joins": {"#", "transform", "join type", "master", "detail", "condition", "business meaning"},
    "4.3 Lookups": {"#", "transform", "lookup table", "lookup condition", "return fields", "cache"},
    "4.4 Filters": {"#", "transform", "filter condition", "purpose"},
    "4.7 Routing": {"group", "condition", "target", "records", "reachable?"},
    "4.8 Complete Field Mapping": {"#", "source table", "source field", "transform chain",
                                   "target table", "target field", "type", "expression", "status"},
    "7.1 Reconciliation Points": {"#", "check", "validation"},
    "8 Structural Observations": {"#", "observation", "detail", "severity"},
    # 3b tables
    "3b/1 Summary": {"category", "count", "highest severity"},
    "3b/2 Documentation Gaps": {"#", "field / transform", "gap", "impact", "severity"},
    "3b/3 Ambiguities": {"#", "area", "assumption made", "risk if wrong", "severity"},
    "3b/4 Data Quality": {"#", "issue", "detail", "recommendation", "severity"},
    "3b/5 Structural Issues": {"#", "issue", "detail", "severity"},
    "3b/6 Pre-Conversion": {"#", "action", "owner", "priority"},
}


# ─────────────────────────────────────────────
# Core Validation Logic
# ─────────────────────────────────────────────

def _extract_tables(md: str) -> list[dict]:
    """Extract all tables as list of {header_row, columns, row_count, line_num}."""
    tables = []
    lines = md.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith("|") and "|" in line[1:]:
            header_line = line
            cols = [c.strip().lower() for c in header_line.strip("|").split("|")]
            # Check if next line is separator
            if i + 1 < len(lines) and re.match(r'\|[\s\-:|]+\|', lines[i + 1].strip()):
                row_count = 0
                j = i + 2
                while j < len(lines) and lines[j].strip().startswith("|"):
                    row_count += 1
                    j += 1
                tables.append({
                    "columns": set(cols),
                    "column_list": cols,
                    "row_count": row_count,
                    "line_num": i + 1,
                    "header_raw": header_line,
                })
                i = j
                continue
        i += 1
    return tables


def _extract_mermaid_blocks(md: str) -> list[dict]:
    """Extract mermaid code blocks and check node labeling."""
    blocks = []
    for m in re.finditer(r'```mermaid\n(.*?)```', md, re.DOTALL):
        content = m.group(1)
        # Find nodes without labels (bare IDs like "A -->" without "[label]")
        bare_nodes = set()
        labeled_nodes = set()

        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("graph ") or line.startswith("%%"):
                continue
            # Strip edge labels like |SIU group| and arrow syntax before scanning for nodes
            clean_line = re.sub(r'\|[^|]*\|', ' ', line)          # remove edge labels
            clean_line = re.sub(r'[-=.]+>',   ' ', clean_line)    # remove arrows
            clean_line = re.sub(r'[-=.]+',    ' ', clean_line)    # remove dashes/dots
            # Extract all node references
            for node_m in re.finditer(r'(\w+)(\[[^\]]+\])?', clean_line):
                node_id = node_m.group(1)
                has_label = bool(node_m.group(2))
                if has_label:
                    labeled_nodes.add(node_id)
                elif node_id not in ("graph", "LR", "TD", "RL", "BT", "subgraph", "end", "style", "class", "classDef"):
                    bare_nodes.add(node_id)

        # Bare nodes that were never labeled anywhere
        unlabeled = bare_nodes - labeled_nodes

        blocks.append({
            "content": content,
            "node_count": len(labeled_nodes | bare_nodes),
            "unlabeled_nodes": unlabeled,
        })
    return blocks


def _find_section_for_table(md: str, table_line_num: int) -> str:
    """Find the closest preceding section heading for a table."""
    lines = md.split("\n")
    for i in range(table_line_num - 1, -1, -1):
        line = lines[i].strip()
        if line.startswith("###"):
            return line.lstrip("#").strip()
        elif line.startswith("##"):
            return line.lstrip("#").strip()
    return "(unknown section)"


def _validate_table_schema(md: str, tables: list[dict], schema_map: dict,
                           doc_label: str, issues: list[Issue]):
    """Validate table headers against expected schemas."""
    for section_label, expected_cols in schema_map.items():
        # Find tables near the section heading
        section_pattern = section_label.split("/")[-1].split(" ", 1)[-1] if "/" in section_label else section_label
        for table in tables:
            table_section = _find_section_for_table(md, table["line_num"])
            # Fuzzy match section name to expected
            if not any(word.lower() in table_section.lower()
                       for word in section_pattern.split()[:2]):
                continue

            actual_cols = table["columns"]
            missing_cols = expected_cols - actual_cols
            extra_cols = actual_cols - expected_cols

            if missing_cols:
                issues.append(Issue(
                    section=f"{doc_label}/{section_label}",
                    severity="warning",
                    code="TABLE_MISSING_COLUMNS",
                    message=f"Table at line {table['line_num']} missing columns: {', '.join(sorted(missing_cols))}",
                ))
            if extra_cols:
                issues.append(Issue(
                    section=f"{doc_label}/{section_label}",
                    severity="info",
                    code="TABLE_EXTRA_COLUMNS",
                    message=f"Table at line {table['line_num']} has extra columns: {', '.join(sorted(extra_cols))}",
                ))


def validate_3a(md: str) -> ValidationReport:
    """Validate the Systems Requirements document (Step 3a)."""
    report = ValidationReport(doc_type="3a")
    issues = report.issues

    if not md or len(md) < 200:
        issues.append(Issue("3a", "critical", "EMPTY_DOC", "Document is empty or too short"))
        return report

    # ── 1. Check title ──
    if not re.search(r'^#\s+\S+.*Systems\s+Requirements', md, re.MULTILINE | re.IGNORECASE):
        # Also accept just the mapping name as title
        if not re.search(r'^#\s+\S+', md, re.MULTILINE):
            issues.append(Issue("3a", "warning", "MISSING_TITLE", "No top-level title heading found"))

    # ── 2. Check required sections ──
    found_sections = 0
    for pattern, label in _3A_REQUIRED_SECTIONS:
        if re.search(pattern, md, re.IGNORECASE):
            found_sections += 1
        else:
            issues.append(Issue(
                section=f"3a/{label}",
                severity="critical",
                code="MISSING_SECTION",
                message=f"Required section missing: {label}",
            ))
    report.section_count = found_sections

    # ── 3. Check required subsections ──
    for pattern, label in _3A_REQUIRED_SUBSECTIONS:
        if not re.search(pattern, md, re.IGNORECASE):
            issues.append(Issue(
                section=f"3a/{label}",
                severity="warning",
                code="MISSING_SUBSECTION",
                message=f"Expected subsection missing: {label}",
            ))

    # ── 4. Check mermaid diagram ──
    mermaid_blocks = _extract_mermaid_blocks(md)
    report.mermaid_count = len(mermaid_blocks)
    if not mermaid_blocks:
        issues.append(Issue(
            section="3a/4.1 Pipeline Overview",
            severity="warning",
            code="NO_MERMAID",
            message="No mermaid flowchart found in Pipeline Overview",
        ))
    for block in mermaid_blocks:
        if block["unlabeled_nodes"]:
            issues.append(Issue(
                section="3a/4.1 Pipeline Overview",
                severity="warning",
                code="MERMAID_UNLABELED",
                message=f"Mermaid nodes without labels: {', '.join(sorted(block['unlabeled_nodes']))}",
                auto_fixable=False,
            ))

    # ── 5. Extract and validate tables ──
    tables = _extract_tables(md)
    report.table_count = len(tables)

    if report.table_count < 3:
        issues.append(Issue("3a", "warning", "FEW_TABLES",
                            f"Only {report.table_count} tables found — expected at least 5"))

    # Validate schemas for key tables
    _validate_table_schema(md, tables, {
        k: v for k, v in _EXPECTED_TABLE_SCHEMAS.items()
        if not k.startswith("3b/")
    }, "3a", issues)

    # ── 6. Check field mapping table (4.8) exists and has rows ──
    fm_section = re.search(r'###\s+4\.8\s+Complete\s+Field\s+Mapping', md, re.IGNORECASE)
    if fm_section:
        fm_start = fm_section.end()
        # Find next ## or ### section
        next_section = re.search(r'\n##\s+', md[fm_start:])
        fm_end = fm_start + next_section.start() if next_section else len(md)
        fm_block = md[fm_start:fm_end]
        fm_tables = _extract_tables(fm_block)
        if not fm_tables:
            issues.append(Issue(
                section="3a/4.8 Complete Field Mapping",
                severity="critical",
                code="NO_FIELD_MAPPING_TABLE",
                message="Section 4.8 exists but contains no table",
            ))
        elif fm_tables[0]["row_count"] == 0:
            issues.append(Issue(
                section="3a/4.8 Complete Field Mapping",
                severity="critical",
                code="EMPTY_FIELD_MAPPING",
                message="Field mapping table has zero rows",
            ))

    # ── 7. Check code blocks ──
    code_blocks = re.findall(r'```(?:sql|text)?\n.*?```', md, re.DOTALL)
    report.code_block_count = len(code_blocks)

    # ── 8. Check expressions are in code blocks, not inline ──
    # Look for common Informatica functions inline (not in code block or table)
    inline_expr_count = 0
    in_code_block = False
    in_table = False
    for line in md.split("\n"):
        stripped = line.strip()
        if stripped.startswith("```"):
            in_code_block = not in_code_block
            continue
        if stripped.startswith("|"):
            in_table = True
            continue
        elif in_table and not stripped.startswith("|"):
            in_table = False

        if not in_code_block and not in_table:
            # Look for IIF, DECODE, TO_DATE, etc. outside code blocks/tables
            if re.search(r'\b(IIF|DECODE|TO_DATE|TO_CHAR|ROUND|NVL|LTRIM|RTRIM|SUBSTR)\s*\(', stripped):
                inline_expr_count += 1

    if inline_expr_count > 2:
        issues.append(Issue(
            section="3a/4.5 Derivations",
            severity="warning",
            code="INLINE_EXPRESSIONS",
            message=f"{inline_expr_count} Informatica expressions found outside code blocks — should be in fenced code blocks",
        ))

    # ── 9. Check section separators ──
    separator_count = len(re.findall(r'^---\s*$', md, re.MULTILINE))
    if separator_count < 4:
        issues.append(Issue(
            section="3a",
            severity="info",
            code="FEW_SEPARATORS",
            message=f"Only {separator_count} horizontal rules — expected between each major section",
            auto_fixable=True,
        ))

    return report


def validate_3b(md: str) -> ValidationReport:
    """Validate the Gaps & Review Findings document (Step 3b)."""
    report = ValidationReport(doc_type="3b")
    issues = report.issues

    if not md or len(md) < 50:
        # 3b can legitimately be short if there are no issues
        issues.append(Issue("3b", "info", "SHORT_DOC", "Gaps document is very short — may be valid if no issues found"))
        return report

    # ── 1. Check title ──
    if not re.search(r'^#\s+\S+.*Gaps', md, re.MULTILINE | re.IGNORECASE):
        issues.append(Issue("3b", "warning", "MISSING_TITLE", "No top-level title with 'Gaps' found"))

    # ── 2. Check required sections ──
    found_sections = 0
    for pattern, label in _3B_REQUIRED_SECTIONS:
        if re.search(pattern, md, re.IGNORECASE):
            found_sections += 1
        else:
            issues.append(Issue(
                section=f"3b/{label}",
                severity="critical",
                code="MISSING_SECTION",
                message=f"Required section missing: {label}",
            ))

    # Check optional sections exist
    for pattern, label in _3B_OPTIONAL_SECTIONS:
        if re.search(pattern, md, re.IGNORECASE):
            found_sections += 1
    report.section_count = found_sections

    # ── 3. Check summary table ──
    tables = _extract_tables(md)
    report.table_count = len(tables)

    if report.table_count == 0:
        issues.append(Issue("3b", "warning", "NO_TABLES", "No tables found — expected at least a summary table"))

    # Validate table schemas
    _validate_table_schema(md, tables, {
        k: v for k, v in _EXPECTED_TABLE_SCHEMAS.items()
        if k.startswith("3b/")
    }, "3b", issues)

    # ── 4. Check summary counts match actual findings ──
    summary_match = re.search(r'##\s+1\.\s+Summary', md, re.IGNORECASE)
    if summary_match:
        # Try to extract counts from summary table
        summary_end = re.search(r'\n##\s+2\.', md[summary_match.end():])
        if summary_end:
            summary_block = md[summary_match.end():summary_match.end() + summary_end.start()]
            summary_tables = _extract_tables(summary_block)
            # We could cross-reference counts here in a future iteration

    # ── 5. Check pre-conversion checklist has priorities ──
    checklist = re.search(r'##\s+6\.\s+Pre-Conversion', md, re.IGNORECASE)
    if checklist:
        checklist_start = checklist.end()
        checklist_block = md[checklist_start:]
        if "P1" not in checklist_block and "P2" not in checklist_block:
            issues.append(Issue(
                section="3b/6. Pre-Conversion Checklist",
                severity="info",
                code="NO_PRIORITIES",
                message="Pre-conversion checklist items don't use P1/P2/P3 priority notation",
            ))

    return report


# ─────────────────────────────────────────────
# Auto-Repair (minor formatting fixes)
# ─────────────────────────────────────────────

def auto_repair_3a(md: str, report: ValidationReport) -> str:
    """Apply auto-fixable repairs to 3a document."""
    repaired = md

    # Ensure --- separators between major sections if missing
    for issue in report.issues:
        if issue.code == "FEW_SEPARATORS" and issue.auto_fixable:
            # Insert --- before each ## heading that doesn't already have one
            lines = repaired.split("\n")
            new_lines = []
            for i, line in enumerate(lines):
                if line.startswith("## ") and i > 0:
                    # Check if previous non-empty line is ---
                    prev_idx = i - 1
                    while prev_idx >= 0 and not lines[prev_idx].strip():
                        prev_idx -= 1
                    if prev_idx >= 0 and lines[prev_idx].strip() != "---":
                        new_lines.append("")
                        new_lines.append("---")
                        new_lines.append("")
                new_lines.append(line)
            repaired = "\n".join(new_lines)
            break

    return repaired


# ─────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────

def validate_and_repair(
    analyst_view_md: str,
    analyst_gaps_md: str,
) -> tuple[str, str, ValidationReport, ValidationReport]:
    """
    Validate both documents and apply auto-repairs where possible.

    Returns:
        (repaired_3a, repaired_3b, report_3a, report_3b)
    """
    report_3a = validate_3a(analyst_view_md)
    report_3b = validate_3b(analyst_gaps_md)

    # Apply auto-repairs
    repaired_3a = auto_repair_3a(analyst_view_md, report_3a) if analyst_view_md else ""
    repaired_3b = analyst_gaps_md  # No auto-repairs for 3b yet

    # Log results
    log.info("analyst_view_validator: %s", report_3a.summary())
    log.info("analyst_view_validator: %s", report_3b.summary())

    for issue in report_3a.issues:
        lvl = logging.WARNING if issue.severity == "critical" else logging.INFO
        log.log(lvl, "  [%s] %s — %s: %s", issue.severity.upper(), issue.code, issue.section, issue.message)

    for issue in report_3b.issues:
        lvl = logging.WARNING if issue.severity == "critical" else logging.INFO
        log.log(lvl, "  [%s] %s — %s: %s", issue.severity.upper(), issue.code, issue.section, issue.message)

    return repaired_3a, repaired_3b, report_3a, report_3b
