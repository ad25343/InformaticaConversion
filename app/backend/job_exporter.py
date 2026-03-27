# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
job_exporter.py — Write completed job artifacts to disk after Gate 3 approval.

UI-submitted jobs are written under OUTPUT_DIR/<job_id>/:

    input/
        mapping.xml                 ← source Informatica XML
        workflow.xml                ← workflow XML (if uploaded)
        params.xml                  ← parameter file (if uploaded)

    output/
        <conversion files>          ← generated code preserving folder structure
        tests/<test files>          ← generated test files (if present)

    docs/
        documentation.md            ← documentation agent output
        s2t_mapping.xlsx            ← source-to-target workbook
        manifest.xlsx               ← pre-conversion manifest
        verification_report.md      ← Stage A verification findings
        security_scan.md            ← Gate 2 security scan findings

    logs/
        <job_id>.log                ← full pipeline log

Watcher-submitted jobs are written under:
    OUTPUT_DIR/<label>_<YYYYMMDD_HHMMSS_ffffff>/<mapping_stem>/
        input/  output/  docs/  logs/   (same structure as above)

The batch folder also contains a batch_index.json that maps each mapping stem
to its job_id for DB cross-reference without querying SQLite:
    OUTPUT_DIR/<label>_<timestamp>/
        batch_index.json            ← {"m_customer_load": "abc123-...", ...}
        m_customer_load/
        m_appraisal_rank/

If OUTPUT_DIR is set to "disabled" or is unavailable, the export is skipped
with a warning. All failures are non-fatal — a failed export never blocks
the pipeline from reaching COMPLETE.
"""
from __future__ import annotations

import io
import json
import logging
import os
import shutil
import zipfile
from pathlib import Path
from typing import Optional

from .config import settings

log = logging.getLogger("conversion.job_exporter")

# ── Resolve output root ───────────────────────────────────────────────────────
def _resolve_output_root() -> Optional[Path]:
    """Return the configured output root directory, or None if disabled."""
    raw = (settings.output_dir or "").strip()
    if raw.lower() == "disabled":
        return None
    if raw:
        return Path(raw)
    # Default: <repo_root>/jobs   (app/ is one level below repo root)
    here = Path(__file__).resolve().parent          # app/backend/
    return here.parent.parent / "jobs"              # repo_root/jobs/


def _safe_path_component(value: str) -> bool:
    """Return True if value contains no path separators (safe for path joining)."""
    return Path(str(value)).name == str(value)


def _watcher_output_path(root: Path, job_id: str,
                         batch_dir: str, mapping_dir: str) -> Optional[Path]:
    """
    Return the watcher-batch output path after validating components, or None
    if either component contains path separators (falls back to job_id path).
    """
    if _safe_path_component(batch_dir) and _safe_path_component(mapping_dir):
        return root / batch_dir / mapping_dir
    log.warning(
        "job_output_dir: watcher path hints contain separators — "
        "falling back to job_id path (job_id=%s batch_dir=%r mapping_dir=%r)",
        job_id, batch_dir, mapping_dir,
    )
    return None


def _resolve_watcher_path(root: Path, job_id: str,
                          state: Optional[dict]) -> Optional[Path]:
    """
    Return the watcher-batch output path when the state carries both hints, or None.

    Returns None for UI-submitted jobs (no hints) or when path validation fails.
    """
    if not state:
        return None
    batch_dir   = state.get("watcher_output_dir")
    mapping_dir = state.get("watcher_mapping_stem")
    if not (batch_dir and mapping_dir):
        return None
    # Defense-in-depth: validate that neither value contains path separators.
    # These are set by watcher.py at job creation (never by the user directly),
    # but we validate here in case of unexpected DB state.
    return _watcher_output_path(root, job_id, batch_dir, mapping_dir)


def _ui_job_folder_name(job_id: str, state: Optional[dict]) -> str:
    """
    Build a human-readable folder name for UI-submitted jobs.

    Format: YYYYMMDD_HHMMSS_<mapping_stem>_<job_id_short>
    Example: 20260317_193000_m_etl_audit_framework_ff845207

    Falls back to bare job_id if filename is unavailable.
    """
    import re
    from datetime import datetime as _dt

    short_id = job_id.replace("-", "")[:8]

    # Try to get filename from state or a cached hint on the state dict
    filename = (state or {}).get("filename") or (state or {}).get("original_filename", "")
    if not filename:
        return job_id  # fallback — no filename available yet

    stem = Path(filename).stem                          # e.g. "m_etl_audit_framework"
    stem = re.sub(r"[^a-zA-Z0-9_\-]", "_", stem)[:60]  # sanitise

    # Use current UTC time — close enough for folder naming purposes
    ts = _dt.utcnow().strftime("%Y%m%d_%H%M%S")
    return f"{ts}_{stem}_{short_id}"


def _ui_folder_cache_path(root: Path, job_id: str) -> Path:
    """Return path to a tiny sidecar file that records the chosen folder name."""
    return root / ".job_folders" / f"{job_id}.txt"


def _resolve_ui_job_path(root: Path, job_id: str, state: Optional[dict]) -> Path:
    """
    Return (and cache) the human-readable output path for a UI job.

    On the first call the folder name is computed and written to a sidecar so
    that all subsequent calls (progressive AUDIT_REPORT updates, final export,
    audit-report download) resolve to the same directory even if the timestamp
    would differ between calls.
    """
    cache = _ui_folder_cache_path(root, job_id)
    if cache.exists():
        folder_name = cache.read_text(encoding="utf-8").strip()
        return root / folder_name

    folder_name = _ui_job_folder_name(job_id, state)
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(folder_name, encoding="utf-8")
    return root / folder_name


def job_output_dir(job_id: str, state: Optional[dict] = None) -> Optional[Path]:
    """
    Return the output directory for a specific job, or None if disabled.

    For watcher-submitted jobs the state dict carries two hints set by watcher.py:
      - watcher_output_dir   : "<label>_<YYYYMMDD_HHMMSS_ffffff>"
      - watcher_mapping_stem : "<mapping filename stem>"

    When both hints are present the path is:
        OUTPUT_DIR/<watcher_output_dir>/<watcher_mapping_stem>/

    For UI-submitted jobs the path is a human-readable folder:
        OUTPUT_DIR/<YYYYMMDD_HHMMSS>_<mapping_stem>_<job_id_short>/
    e.g. OUTPUT_DIR/20260317_193000_m_etl_audit_framework_ff845207/

    The chosen folder name is cached in OUTPUT_DIR/.job_folders/<job_id>.txt
    so all pipeline stages resolve to the same directory.
    """
    root = _resolve_output_root()
    if root is None:
        return None
    watcher_path = _resolve_watcher_path(root, job_id, state)
    if watcher_path is not None:
        return watcher_path
    return _resolve_ui_job_path(root, job_id, state)


# ── Markdown renderers ────────────────────────────────────────────────────────

def _render_verification_md(verification: dict) -> str:
    lines = ["# Verification Report\n"]
    lines.append(f"**Overall status:** {verification.get('overall_status', 'unknown')}\n")
    lines.append(f"**Mapping name:** {verification.get('mapping_name', 'unknown')}\n")
    flags = verification.get("flags", [])
    if flags:
        lines.append(f"\n## Flags ({len(flags)})\n")
        for f in flags:
            sev   = f.get("severity", "")
            ftype = f.get("flag_type", "")
            msg   = f.get("message", "")
            lines.append(f"- **[{sev}]** `{ftype}` — {msg}")
    else:
        lines.append("\n✅ No flags raised.\n")
    notes = verification.get("notes", [])
    if notes:
        lines.append("\n## Notes\n")
        for n in notes:
            lines.append(f"- {n}")
    return "\n".join(lines) + "\n"


def _finding_location(f: dict) -> str:
    """Build a 'file:line' location string from a finding dict, or '' if unavailable."""
    file = f.get("file", "")
    line = f.get("line")
    if file and line:
        return f"{file}:{line}"
    return file or ""


def _finding_lines(f: dict) -> list[str]:
    """Return the markdown lines for one security finding."""
    sev  = f.get("severity", "")
    rule = f.get("rule_id", "")
    msg  = f.get("message", "")
    loc  = _finding_location(f)
    result = [f"### [{sev}] {rule}"]
    if loc:
        result.append(f"*{loc}*")
    result.append(f"{msg}\n")
    return result


def _render_security_scan_md(security_scan: dict) -> str:
    lines = ["# Security Scan Report\n"]
    lines.append(f"**Verdict:** {security_scan.get('verdict', 'unknown')}\n")
    findings = security_scan.get("findings", [])
    if findings:
        lines.append(f"\n## Findings ({len(findings)})\n")
        for f in findings:
            lines.extend(_finding_lines(f))
    else:
        lines.append("\n✅ No security findings.\n")
    if security_scan.get("auto_approved", False):
        lines.append("\n> Auto-approved: no actionable findings.\n")
    return "\n".join(lines) + "\n"


def _copy_s2t_excel(out_dir: Path, job_id: str, state: dict) -> None:
    """Copy S2T Excel workbook to docs/; falls back to s2t_agent path lookup."""
    s2t_rel = state.get("s2t", {}).get("excel_path")
    if not s2t_rel:
        return
    here = Path(__file__).resolve().parent       # app/backend/
    s2t_src = here.parent / s2t_rel              # app/<rel>
    if s2t_src.exists():
        shutil.copy2(s2t_src, out_dir / "docs" / "s2t_mapping.xlsx")
        return
    _copy_s2t_excel_fallback(out_dir, job_id)


def _copy_s2t_excel_fallback(out_dir: Path, job_id: str) -> None:
    """Try the s2t_agent helper as a fallback path lookup."""
    try:
        from .agents.s2t_agent import s2t_excel_path
        p = s2t_excel_path(job_id)
        if p and p.exists():
            shutil.copy2(p, out_dir / "docs" / "s2t_mapping.xlsx")
    except Exception as s2t_exc:
        log.debug("S2T fallback path lookup failed (non-fatal): job_id=%s error=%s",
                  job_id, s2t_exc)


# ── Main export function ──────────────────────────────────────────────────────

async def export_job(job_id: str, job: dict, state: dict) -> Optional[Path]:
    """
    Write all job artifacts to OUTPUT_DIR/<job_id>/.

    Parameters
    ----------
    job_id : str
    job    : dict   — raw job record from db.get_job()
    state  : dict   — decoded state dict (job["state"])

    Returns the job output directory on success, None if export is disabled or
    fails.  All exceptions are caught so a failed export never blocks COMPLETE.
    """
    out_dir = job_output_dir(job_id, state)
    if out_dir is None:
        log.info("Job export disabled (OUTPUT_DIR=disabled): job_id=%s", job_id)
        return None

    try:
        _write_all(out_dir, job_id, job, state)
        log.info("Job exported to disk: job_id=%s path=%s", job_id, out_dir)
        # For watcher batches, update the batch-level index file so every mapping
        # in the batch can be traced back to its job_id without querying the DB.
        _update_batch_index(out_dir, job_id, state)
        return out_dir
    except Exception as exc:
        log.error("Job export failed (non-fatal): job_id=%s error=%s", job_id, exc, exc_info=True)
        return None


def _write_input_files(out_dir: Path, job: dict, state: dict) -> None:
    """Write source input files to out_dir/input/."""
    xml = job.get("xml_content") or state.get("xml_content")
    if xml:
        _write_text(out_dir / "input" / "mapping.xml", xml)
    workflow_xml = job.get("workflow_xml_content")
    if workflow_xml:
        _write_text(out_dir / "input" / "workflow.xml", workflow_xml)
    params = job.get("parameter_file_content")
    if params:
        _write_text(out_dir / "input" / "params.xml", params)


def _write_output_files(out_dir: Path, state: dict) -> None:
    """Write generated code and test files to out_dir/output/."""
    conv_files: dict = state.get("conversion", {}).get("files", {})
    for rel_path, content in conv_files.items():
        dest = out_dir / "output" / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        _write_text(dest, content)
    test_files: dict = state.get("test_report", {}).get("test_files", {})
    for rel_path, content in test_files.items():
        dest = out_dir / "output" / "tests" / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        _write_text(dest, content)


def _write_manifest_xlsx(out_dir: Path, manifest_raw: dict) -> None:
    """Regenerate and write manifest.xlsx from state; log on failure."""
    try:
        from .agents.manifest_agent import ManifestReport, write_xlsx_bytes
        xlsx_bytes = write_xlsx_bytes(ManifestReport(**manifest_raw))
        (out_dir / "docs" / "manifest.xlsx").write_bytes(xlsx_bytes)
    except Exception as exc:
        log.warning("Could not write manifest.xlsx: %s", exc)


def _pending(label: str) -> str:
    """Return a standard pending-section placeholder."""
    return f"⏳ **Pending** — will be populated when {label} completes.\n"


def _render_audit_report_md(job: dict, state: dict, *, current_step: int = 99) -> str:
    """
    Generate a Conversion Audit Report in Markdown format.

    ``current_step`` controls which sections show real data vs ⏳ Pending:
      - step  4 → sections 1–7 (metadata → verification)
      - step  9 → + section 8 (security) + section 9 (pattern library, partial)
      - step 11 → + sections 10 (code review), 11 (reuse), 12 (tests)
      - step 99 → + sections 4, 13 (conversion output, sign-off chain)

    13 sections total:
      1 Job Metadata         2 Source Files          3 Transformation Coverage
      4 Conversion Output    5 Inferred Logic        6 Unresolved Parameters
      7 Verification         8 Security Findings     9 Pattern Library Usage
     10 Code Review         11 Reuse Candidates     12 Test Coverage
     13 Sign-off Chain
    """
    from datetime import datetime as _dt

    lines: list[str] = []

    _STEP_LABELS = {
        4:  "Step 4 — Verification",
        9:  "Step 9 — Security Review",
        11: "Step 11 — Code Review + Test Generation",
        99: "Gate 3 — Final Sign-off",
    }
    _stage = _STEP_LABELS.get(current_step, f"Step {current_step}")

    # ── Header ────────────────────────────────────────────────────────────────
    lines += [
        "# Conversion Audit Report",
        "",
        f"**Last updated:** {_dt.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC  ",
        f"**Pipeline stage:** {_stage}",
        "",
        "> This document is updated automatically after each key pipeline stage.",
        "> Sections marked ⏳ will be populated as the job progresses.",
        "",
        "---",
        "",
    ]

    # ── Job Metadata ──────────────────────────────────────────────────────────
    lines += ["## 1. Job Metadata", ""]
    # v2.24.0 — Conversion Readiness scores
    _parse_state  = state.get("parse_report", {})
    _cplx_state   = state.get("complexity", {})
    _completeness = _parse_state.get("completeness_score") if isinstance(_parse_state, dict) else None
    _readiness    = _cplx_state.get("conversion_readiness") if isinstance(_cplx_state, dict) else None
    _conf_score   = _cplx_state.get("pattern_confidence_score") if isinstance(_cplx_state, dict) else None
    def _readiness_label(score: float | None) -> str:
        if score is None: return "—"
        if score >= 85: return f"{score}/100 HIGH ✅"
        if score >= 65: return f"{score}/100 MEDIUM ⚠️"
        if score >= 40: return f"{score}/100 LOW 🔴"
        return f"{score}/100 CRITICAL ❌"
    lines += [
        f"| Field | Value |",
        f"|---|---|",
        f"| Job ID | `{job.get('job_id', '—')}` |",
        f"| Filename | `{job.get('filename', '—')}` |",
        f"| Submitted by | {job.get('submitter_name') or '—'} |",
        f"| Team | {job.get('submitter_team') or '—'} |",
        f"| Submitted at | {job.get('created_at', '—')} |",
        f"| Completed at | {job.get('updated_at', '—')} |",
        f"| Target stack | {job.get('target_stack') or state.get('stack_assignment', {}).get('target_stack') or '—'} |",
        f"| Complexity tier | {job.get('complexity_tier') or '—'} |",
        f"| Score 1 — Pattern Confidence | {_readiness_label(_conf_score)} |",
        f"| Score 2 — Source Completeness | {_readiness_label(_completeness)} |",
        f"| Combined Conversion Readiness | {_readiness_label(_readiness)} |",
        "",
    ]

    # ── Source Files ──────────────────────────────────────────────────────────
    lines += ["## 2. Source Files", ""]
    xml = job.get("xml_content") or state.get("xml_content")
    wf  = job.get("workflow_xml_content")
    par = job.get("parameter_file_content")
    lines += [
        f"| File | Provided | Size |",
        f"|---|---|---|",
        f"| Mapping XML | {'✓' if xml else '✗'} | {len(xml):,} chars |" if xml else "| Mapping XML | ✗ | — |",
        f"| Workflow XML | {'✓' if wf else '—'} | {len(wf):,} chars |" if wf else "| Workflow XML | — | — |",
        f"| Parameter file | {'✓' if par else '—'} | {len(par):,} chars |" if par else "| Parameter file | — | — |",
        "",
    ]

    # ── Transformation Coverage ───────────────────────────────────────────────
    lines += ["## 3. Transformation Coverage", ""]
    parse = state.get("parse_report", {})
    transformations = parse.get("transformations", []) if isinstance(parse, dict) else []
    if transformations:
        lines.append(f"**{len(transformations)} transformation(s) found in source:**\n")
        lines.append("| Name | Type |")
        lines.append("|---|---|")
        for t in transformations:
            lines.append(f"| `{t.get('name','?')}` | {t.get('type','?')} |")
        lines.append("")
    else:
        lines += ["_No transformation list available._", ""]

    # ── Conversion Output ─────────────────────────────────────────────────────
    lines += ["## 4. Conversion Output (Step 7)", ""]
    conv = state.get("conversion", {})
    if current_step < 99 and not conv:
        lines += [_pending("Step 7 — Conversion"), ""]
    elif conv:
        files = conv.get("files", {})
        total_loc = sum(
            len(c.splitlines()) for c in (files.values() if isinstance(files, dict) else [])
        )
        lines += [
            f"| Metric | Value |",
            f"|---|---|",
            f"| Output files | {len(files)} |",
            f"| Total lines of code | {total_loc:,} |",
            f"| Pattern used | {conv.get('pattern') or '—'} |",
            f"| Pattern confidence | {conv.get('confidence') or '—'} |",
            "",
        ]
        if isinstance(files, dict):
            lines.append("**Generated files:**\n")
            for fname in sorted(files.keys()):
                loc = len(files[fname].splitlines())
                lines.append(f"- `{fname}` ({loc:,} lines)")
            lines.append("")
        notes = conv.get("notes", [])
        if notes:
            lines.append(f"**Conversion notes ({len(notes)}):**\n")
            for n in notes:
                tag = n.split(":")[0] if ":" in n else "NOTE"
                lines.append(f"- `{tag}` — {n}")
            lines.append("")
    else:
        lines += ["_No conversion data available._", ""]

    # ── Inferred Logic ────────────────────────────────────────────────────────
    inferred = [n for n in (conv.get("notes", []) if conv else [])
                if any(k in n.upper() for k in ("INFERRED", "AUTO-FLAG", "LINEAGE_GAP", "REVIEW_REQUIRED", "TODO"))]
    lines += ["## 5. Inferred / Ambiguous Logic", ""]
    if inferred:
        lines.append(f"⚠️ **{len(inferred)} item(s) require mapping owner confirmation:**\n")
        for n in inferred:
            lines.append(f"- {n}")
        lines.append("")
    else:
        lines += ["✅ No inferred logic flagged.", ""]

    # ── Unresolved Parameters ─────────────────────────────────────────────────
    lines += ["## 6. Unresolved Parameters", ""]
    unresolved = parse.get("unresolved_parameters", []) if isinstance(parse, dict) else []
    if unresolved:
        lines.append(f"⚠️ **{len(unresolved)} unresolved `$$PARAMETER`(s):**\n")
        for p in unresolved:
            lines.append(f"- `{p}`")
        lines.append("")
    else:
        lines += ["✅ All parameters resolved.", ""]

    # ── Verification Summary ──────────────────────────────────────────────────
    lines += ["## 7. Verification Summary (Gate 1)", ""]
    verif = state.get("verification", {})
    if verif:
        flags = verif.get("flags", [])
        passed = verif.get("total_passed", 0)
        failed = verif.get("total_failed", 0)
        lines += [
            f"| Result | Count |",
            f"|---|---|",
            f"| ✅ Passed | {passed} |",
            f"| ✗ Failed | {failed} |",
            f"| Overall | {verif.get('overall_status', '—')} |",
            "",
        ]
        blocking = [f for f in flags if f.get("blocking")]
        if blocking:
            lines.append("**Blocking flags:**\n")
            for f in blocking:
                lines.append(f"- **[{f.get('severity','?')}]** {f.get('message','')}")
            lines.append("")
    else:
        lines += ["_No verification data._", ""]

    # ── Security Findings ─────────────────────────────────────────────────────
    lines += ["## 8. Security Findings (Step 8 + Gate 2)", ""]
    sec = state.get("security_scan", {})
    if current_step < 9 and not sec:
        lines += [_pending("Step 8 — Security Scan"), ""]
    elif sec:
        findings = sec.get("findings", [])
        by_sev: dict[str, int] = {}
        for f in findings:
            s = f.get("severity", "INFO")
            by_sev[s] = by_sev.get(s, 0) + 1
        lines += [
            f"| Severity | Count |",
            f"|---|---|",
        ]
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if by_sev.get(sev):
                lines.append(f"| {sev} | {by_sev[sev]} |")
        lines += [f"| **Total** | **{len(findings)}** |", ""]
        if not findings:
            lines += ["✅ No security findings.", ""]
    else:
        lines += ["_No security scan data._", ""]

    # ── Pattern Library Usage ─────────────────────────────────────────────────
    lines += ["## 9. Pattern Library Usage (etl_patterns)", ""]
    cplx = state.get("complexity", {})
    suggested_pattern    = cplx.get("suggested_pattern")    if isinstance(cplx, dict) else None
    pattern_confidence   = cplx.get("pattern_confidence")   if isinstance(cplx, dict) else None
    pattern_rationale    = cplx.get("pattern_rationale")    if isinstance(cplx, dict) else None
    conv_p = state.get("conversion", {})
    conv_files = conv_p.get("files", {}) if isinstance(conv_p, dict) else {}
    # Detect whether generated code imports etl_patterns utilities
    all_code = "\n".join(conv_files.values()) if isinstance(conv_files, dict) else ""
    _uses_etl = "from etl_patterns" in all_code or "import etl_patterns" in all_code
    _lib_utils = [u for u in ("null_safe", "string_clean", "type_cast",
                               "watermark_manager", "etl_metadata", "file_lifecycle")
                  if u in all_code]
    if suggested_pattern:
        conf_emoji = {"HIGH": "✅", "MEDIUM": "⚠️", "LOW": "⚠️", "NONE": "❌"}.get(
            (pattern_confidence or "NONE").upper(), "ℹ️"
        )
        _pconf_score = cplx.get("pattern_confidence_score") if isinstance(cplx, dict) else None
        _pconf_str = (
            f"{conf_emoji} {pattern_confidence or '—'}"
            + (f" ({_pconf_score}/100)" if _pconf_score is not None else "")
        )
        lines += [
            f"| Field | Value |",
            f"|---|---|",
            f"| Detected pattern | `{suggested_pattern}` |",
            f"| Confidence | {_pconf_str} |",
            f"| etl_patterns config emitted | {'✅ Yes' if conv_files and any('config/' in k for k in conv_files) else '—'} |",
            f"| etl_patterns imported in code | {'✅ Yes' if _uses_etl else '❌ No — check Stage D findings'} |",
            f"| Utilities used | {', '.join(f'`{u}`' for u in _lib_utils) or '— none detected'} |",
            "",
        ]
        if pattern_rationale:
            lines += [f"> {pattern_rationale}", ""]
    else:
        lines += ["_Pattern classification not yet complete._", ""]

    # ── Code Review & Logic Equivalence ──────────────────────────────────────
    lines += ["## 10. Code Review & Logic Equivalence (Step 10)", ""]
    cr = state.get("code_review", {})
    if current_step < 11 and not cr:
        lines += [_pending("Step 10 — Code Review"), ""]
    elif cr:
        # Stage B — overall recommendation + pass/fail
        rec = cr.get("recommendation", "—")
        rec_emoji = {"APPROVED": "✅", "REVIEW_RECOMMENDED": "⚠️", "REQUIRES_FIXES": "❌"}.get(rec, "ℹ️")
        lines += [
            f"**Overall recommendation:** {rec_emoji} {rec}",
            "",
            f"| Stage | Result |",
            f"|---|---|",
            f"| Stage B — Code Quality | {cr.get('total_passed', 0)} passed / {cr.get('total_failed', 0)} failed |",
        ]
        # Stage A — equivalence
        eq = cr.get("equivalence_report") or {}
        if eq:
            v   = eq.get("total_verified", 0)
            nr  = eq.get("total_needs_review", 0)
            mm  = eq.get("total_mismatches", 0)
            cov = eq.get("coverage_pct", 0.0)
            eq_emoji = "✅" if mm == 0 else "❌"
            lines.append(
                f"| Stage A — Logic Equivalence | {eq_emoji} {v} verified, {nr} need review, {mm} mismatches ({cov:.0f}% covered) |"
            )
        # Stage C — performance
        perf = cr.get("perf_review") or {}
        if perf:
            p_clean = perf.get("clean", True)
            p_count = len(perf.get("checks", []))
            lines.append(
                f"| Stage C — Performance | {'✅ Clean' if p_clean else f'⚠️ {p_count} anti-pattern(s)'} |"
            )
        lines.append("")

        # Stage B failed checks
        failed_checks = [c for c in cr.get("checks", []) if not c.get("passed")]
        if failed_checks:
            lines.append(f"**Failed checks ({len(failed_checks)}):**\n")
            for c in failed_checks:
                sev = c.get("severity", "MEDIUM")
                lines.append(f"- `[{sev}]` **{c.get('name', '?')}** — {c.get('note', '')}")
            lines.append("")

        # Stage A mismatches
        eq_checks = (eq.get("checks") or []) if eq else []
        mismatches = [c for c in eq_checks if c.get("verdict") == "MISMATCH"]
        if mismatches:
            lines.append(f"**Logic mismatches — require immediate attention ({len(mismatches)}):**\n")
            lines.append("| Rule | XML Rule | Generated Impl | Note |")
            lines.append("|---|---|---|---|")
            for c in mismatches:
                lines.append(
                    f"| `{c.get('rule_id','?')}` ({c.get('rule_type','?')}) "
                    f"| {c.get('xml_rule','')[:80]} "
                    f"| {c.get('generated_impl','')[:80]} "
                    f"| {c.get('note','')[:120]} |"
                )
            lines.append("")
        needs_review = [c for c in eq_checks if c.get("verdict") == "NEEDS_REVIEW"]
        if needs_review:
            lines.append(f"**Rules requiring human confirmation ({len(needs_review)}):**\n")
            for c in needs_review:
                lines.append(f"- `{c.get('rule_id','?')}` — {c.get('note','')}")
            lines.append("")

        # Stage C perf findings
        if perf and not perf.get("clean"):
            lines.append(f"**Performance findings:**\n")
            for p in perf.get("checks", []):
                lines.append(f"- `[{p.get('severity','?')}]` **{p.get('anti_pattern','?')}** @ {p.get('location','?')}: {p.get('suggestion','')}")
            lines.append("")

        # Summary
        summary_txt = cr.get("summary") or (eq.get("summary") if eq else "")
        if summary_txt:
            lines += [f"> {summary_txt}", ""]
    else:
        lines += ["_No code review data available._", ""]

    # ── Framework Reuse Candidates ────────────────────────────────────────────
    lines += ["## 11. Framework & Code Reuse Candidates (Stage D)", ""]
    cr_reuse = (cr.get("reuse_analysis") or {}) if cr else {}
    if current_step < 11 and not cr_reuse:
        lines += [_pending("Step 10 — Code Review / Stage D"), ""]
    elif cr_reuse:
        total    = cr_reuse.get("total_found", 0)
        high_val = cr_reuse.get("high_value", 0)
        gaps     = cr_reuse.get("adoption_gaps", 0)
        net_new  = cr_reuse.get("net_new", 0)
        r_sum    = cr_reuse.get("summary", "")
        if total == 0:
            lines += ["✅ No reuse candidates identified — etl_patterns adopted correctly.", ""]
        else:
            gap_emoji = "❌" if gaps > 0 else "✅"
            lines += [
                f"| Metric | Count |",
                f"|---|---|",
                f"| {gap_emoji} Adoption gaps (should use etl_patterns) | {gaps} |",
                f"| ➕ Net-new candidates (add to library) | {net_new} |",
                f"| ⚡ High-value (LOW effort) | {high_val} |",
                f"| Total | {total} |",
                "",
                f"> {r_sum}" if r_sum else "",
                "",
            ]
            all_candidates = cr_reuse.get("candidates", [])
            gap_items = [c for c in all_candidates if c.get("gap_or_new") == "ADOPTION_GAP"]
            new_items = [c for c in all_candidates if c.get("gap_or_new") != "ADOPTION_GAP"]
            if gap_items:
                lines += ["**⚠️ Adoption gaps — use etl_patterns instead:**\n",
                          "| ID | Pattern | Location | Use Instead | Effort |",
                          "|---|---|---|---|---|"]
                for c in gap_items:
                    lines.append(
                        f"| {c.get('candidate_id','?')} "
                        f"| `{c.get('pattern_type','?')}` "
                        f"| {c.get('location','?')} "
                        f"| `{c.get('suggested_name','?')}` "
                        f"| {c.get('effort','?')} |"
                    )
                lines.append("")
            if new_items:
                lines += ["**➕ Net-new reuse candidates:**\n",
                          "| ID | Pattern | Location | Suggested Name | Effort | Stacks |",
                          "|---|---|---|---|---|---|"]
                for c in new_items:
                    stacks = ", ".join(c.get("applicable_stacks") or []) or "—"
                    lines.append(
                        f"| {c.get('candidate_id','?')} "
                        f"| `{c.get('pattern_type','?')}` "
                        f"| {c.get('location','?')} "
                        f"| `{c.get('suggested_name','?')}` "
                        f"| {c.get('effort','?')} "
                        f"| {stacks} |"
                    )
                lines.append("")
            # Details for high-value items
            high_items = [c for c in all_candidates if c.get("effort") == "LOW"]
            if high_items:
                lines.append("**High-value details:**\n")
                for c in high_items:
                    lines += [
                        f"### `{c.get('suggested_name','?')}`",
                        f"**Type:** {c.get('pattern_type','?')}  **Location:** {c.get('location','?')}",
                        "",
                        f"{c.get('description','')}",
                        "",
                        f"*Rationale:* {c.get('reuse_rationale','')}",
                        "",
                    ]
    else:
        lines += ["_No reuse analysis data available._", ""]

    # ── Test Coverage ─────────────────────────────────────────────────────────
    lines += ["## 12. Test Coverage (Step 11)", ""]
    test = state.get("test_report", {})
    if current_step < 11 and not test:
        lines += [_pending("Step 11 — Test Generation"), ""]
    elif test:
        lines += [
            f"| Metric | Value |",
            f"|---|---|",
            f"| Coverage | {test.get('coverage_pct', 0):.1f}% |",
            f"| Fields covered | {test.get('fields_covered', 0)} |",
            f"| Test files | {len(test.get('test_files', {}))} |",
            "",
        ]
    else:
        lines += ["_No test report data._", ""]

    # ── Reviewer Sign-off Chain ───────────────────────────────────────────────
    lines += ["## 13. Reviewer Sign-off Chain", ""]
    audit_entries = job.get("audit_entries") or state.get("audit_entries") or []
    if current_step < 99 and not audit_entries:
        lines += [_pending("Gate 3 — Final Sign-off"), ""]
    elif audit_entries:
        lines += [
            "| Gate | Reviewer | Decision | Timestamp | Notes |",
            "|---|---|---|---|---|",
        ]
        for entry in audit_entries:
            lines.append(
                f"| {entry.get('gate','—')} "
                f"| {entry.get('reviewer_name','—')} "
                f"| {entry.get('decision','—')} "
                f"| {entry.get('created_at','—')} "
                f"| {(entry.get('notes') or '').replace('|', '/')} |"
            )
        lines.append("")
    else:
        lines += ["_No audit entries recorded._", ""]

    # ── Footer ─────────────────────────────────────────────────────────────────
    lines += [
        "---",
        "",
        "_This report was automatically generated by the Informatica PowerCenter Converter pipeline._",
        "_It should be reviewed by the migration lead before production deployment._",
    ]

    return "\n".join(lines) + "\n"


def _audit_staging_path(job_id: str, state: Optional[dict] = None) -> Optional[Path]:
    """Return the progressive AUDIT_REPORT.md path under the job output dir, or None if disabled."""
    out_dir = job_output_dir(job_id, state)
    if out_dir is None:
        return None
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / "AUDIT_REPORT.md"


def write_audit_report_progressive(
    job_id: str,
    job: dict,
    state: dict,
    *,
    step: int,
) -> None:
    """
    Write (or overwrite) AUDIT_REPORT.md with whatever pipeline data is
    available so far.  Sections whose data hasn't been produced yet are shown
    as ⏳ Pending placeholders so the document is always readable.

    Called after steps 4, 9, 11, and Gate 3 approval.
    """
    path = _audit_staging_path(job_id, state)
    if path is None:
        return
    try:
        md = _render_audit_report_md(job, state, current_step=step)
        path.write_text(md, encoding="utf-8")
        log.debug("AUDIT_REPORT.md updated at step %d: %s", step, path)
    except Exception as exc:
        log.warning("write_audit_report_progressive failed (non-fatal): %s", exc)


def _write_doc_files(out_dir: Path, job_id: str, job: dict, state: dict) -> None:
    """Write all docs/ artefacts (markdown, xlsx, logs) to out_dir."""
    doc_md = state.get("documentation_md")
    if doc_md:
        _write_text(out_dir / "docs" / "documentation.md", doc_md)
    _copy_s2t_excel(out_dir, job_id, state)
    manifest_raw = state.get("manifest_report")
    if manifest_raw:
        _write_manifest_xlsx(out_dir, manifest_raw)
    # AUDIT_REPORT.md — final complete version with sign-off chain
    _write_text(out_dir / "docs" / "AUDIT_REPORT.md",
                _render_audit_report_md(job, state, current_step=99))


def _copy_job_log(out_dir: Path, job_id: str) -> None:
    """Copy the pipeline log file to out_dir/logs/ if it exists."""
    from .logger import job_log_path
    log_src = job_log_path(job_id)
    if log_src and log_src.exists():
        shutil.copy2(log_src, out_dir / "logs" / f"{job_id}.log")


def _write_all(out_dir: Path, job_id: str, job: dict, state: dict) -> None:
    """Core writer — called by export_job; raises on any error."""
    for subdir in ("input", "output", "docs", "logs"):
        (out_dir / subdir).mkdir(parents=True, exist_ok=True)

    _write_input_files(out_dir, job, state)
    _write_output_files(out_dir, state)
    _write_doc_files(out_dir, job_id, job, state)
    _copy_job_log(out_dir, job_id)


# ── Batch index (watcher jobs only) ──────────────────────────────────────────

def _read_batch_index(index_path: Path) -> dict:
    """Read an existing batch_index.json, returning {} on any error."""
    if not index_path.exists():
        return {}
    try:
        data = json.loads(index_path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _write_batch_index(index_path: Path, mapping_stem: str, job_id: str) -> None:
    """Read-modify-write batch_index.json, adding mapping_stem → job_id."""
    index_path.parent.mkdir(parents=True, exist_ok=True)
    existing = _read_batch_index(index_path)
    existing[str(mapping_stem)] = job_id
    index_path.write_text(
        json.dumps(existing, indent=4, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    log.debug("batch_index.json updated: path=%s mapping=%s job_id=%s",
              index_path, mapping_stem, job_id)


def _resolve_batch_index_path(state: dict) -> Optional[Path]:
    """
    Return the batch_index.json path for a watcher job, or None if not applicable.

    Returns None when the job is not a watcher job, when batch_dir contains path
    separators (security validation), or when the output root is disabled.
    """
    batch_dir    = state.get("watcher_output_dir")
    mapping_stem = state.get("watcher_mapping_stem")
    if not (batch_dir and mapping_stem):
        return None   # not a watcher job
    if not _safe_path_component(str(batch_dir)):
        log.warning("_update_batch_index: batch_dir contains path separators — skipping "
                    "(mapping_stem=%r batch_dir=%r)", mapping_stem, batch_dir)
        return None
    root = _resolve_output_root()
    if root is None:
        return None
    return root / batch_dir / "batch_index.json"


def _update_batch_index(out_dir: Path, job_id: str, state: dict) -> None:
    """
    Write / update OUTPUT_DIR/<batch_dir>/batch_index.json for watcher batches.

    The index maps mapping_stem → job_id so teams can trace output folders back
    to the database without querying SQLite.  Each mapping in a batch completes
    at a different time (Gate 3 may be approved per-job), so we read-modify-write
    the file on each call — later entries accumulate rather than overwrite.

    Only written when the job carries watcher_output_dir and watcher_mapping_stem
    hints in its state.  UI-submitted jobs produce no batch_index.json.

    Example output:
        {
            "m_customer_load":  "abc123-def456-...",
            "m_appraisal_rank": "bcd234-efg567-...",
            "m_commission_calc": "cde345-fgh678-..."
        }
    """
    mapping_stem = state.get("watcher_mapping_stem")
    index_path   = _resolve_batch_index_path(state)
    if index_path is None:
        return
    try:
        _write_batch_index(index_path, mapping_stem, job_id)
    except Exception as exc:
        log.warning("Could not update batch_index.json (non-fatal): path=%s error=%s",
                    index_path, exc)


# ── ZIP builder (used by the download endpoint; does NOT require disk write) ──

def build_output_zip(state: dict) -> bytes:
    """
    Build a ZIP archive of the conversion output files from state.
    Preserves folder structure.  Does not require a prior disk export.

    Returns raw ZIP bytes.
    """
    conversion = state.get("conversion", {})
    conv_files: dict = conversion.get("files", {})

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel_path, content in conv_files.items():
            zf.writestr(rel_path, content)
    buf.seek(0)
    return buf.read()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
