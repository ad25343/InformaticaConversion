# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Orchestrator — State machine that drives a ConversionJob through all 8 steps.
Enforces gates: will not advance if a step produces blocking issues.
Each step updates the DB, emits progress, and writes structured log entries
to logs/jobs/<job_id>.log (one JSON line per event).
"""
from __future__ import annotations
import asyncio
from dataclasses import dataclass, field
from datetime import datetime as _datetime
import logging as _logging
import traceback
from typing import AsyncGenerator, Callable, Optional, Any

_orch_log = _logging.getLogger("conversion.orchestrator")

from .db.database import get_xml, get_session_files, update_job
from .db import database as _db
from .models.schemas import JobStatus
from .job_exporter import export_job, write_audit_report_progressive
from .agents import parser_agent, classifier_agent, documentation_agent, \
    verification_agent, conversion_agent, s2t_agent, review_agent, test_agent, \
    session_parser_agent, security_agent, manifest_agent
from .org_config_loader import should_skip_step, should_auto_approve_gate
from .agents.documentation_agent import DOC_TRUNCATION_SENTINEL, DOC_COMPLETE_SENTINEL
from .agents.reconciliation_agent import generate_reconciliation_report
from .smoke_execute import smoke_execute_files, format_smoke_results
from .logger import JobLogger
from .security import scan_xml_for_secrets
from .webhook import fire_webhook
from .notify  import fire_email
from .git_pr import create_pull_request


class EmitError(BaseException):
    """
    Raised by the emit() closure when all DB-write retries are exhausted.

    Inherits BaseException (not Exception) so that existing ``except Exception``
    blocks in the step handlers do NOT accidentally catch and swallow it — it
    must propagate all the way up to the SSE event generator in routes.py,
    which yields the failure event and closes the stream cleanly.
    """
    def __init__(self, event: dict) -> None:
        self.event = event
        super().__init__(event.get("message", "DB write failure"))


def _make_emit(job_id: str, log: Any) -> Callable:
    """Return a retry-enabled emit() coroutine bound to job_id and log."""
    async def emit(step: int, status: JobStatus, message: str, data: dict = None) -> dict:
        patch = data or {}
        patch["pipeline_log"] = log.get_buffer()
        _failure_event = {
            "step": step,
            "status": JobStatus.FAILED.value,
            "message": f"Database write failure — pipeline stopped at step {step}.",
        }
        for _attempt in range(3):
            try:
                await update_job(job_id, status.value, step, patch)
                break
            except Exception as _db_exc:
                if _attempt == 2:
                    _orch_log.error(
                        "emit() DB write failed after 3 attempts "
                        "(job=%s step=%d status=%s): %s — terminating pipeline.",
                        job_id, step, status.value, _db_exc,
                    )
                    raise EmitError(_failure_event) from _db_exc
                _orch_log.warning(
                    "emit() DB write attempt %d failed (job=%s step=%d): %s — retrying.",
                    _attempt + 1, job_id, step, _db_exc,
                )
                await asyncio.sleep(0.5)
        return {"step": step, "status": status.value, "message": message}
    return emit


@dataclass
class _PipelineCtx:
    """
    Shared pipeline state passed between step functions.

    Accumulated during run_pipeline(); restored from DB state in resume_* functions.
    The emit callable and log are injected by the orchestrator generator.
    """
    job_id: str
    filename: str
    emit: Callable        # the retry-enabled emit() closure from the enclosing generator
    log: Any              # JobLogger instance
    pipeline_mode: str = "full"
    # Step outputs (filled in as each step runs):
    xml_content: str = ""
    session_parse_report: Any = None
    parse_report: Any = None
    complexity: Any = None
    graph: dict = field(default_factory=dict)
    documentation_md: str = ""
    analyst_view_md: str = ""
    analyst_gaps_md: str = ""
    verification: Any = None
    manifest_report: Any = None
    manifest_xlsx_bytes: Optional[bytes] = None
    s2t_result: Any = None
    s2t_state: dict = field(default_factory=dict)
    xml_cred_findings: list = field(default_factory=list)
    stack_assignment: Any = None
    conversion_output: Any = None
    security_scan: Any = None
    code_review: Any = None
    test_report: Any = None


def _err(e: Exception) -> dict:
    """Return a state patch that stores the full error for UI display."""
    return {
        "error": str(e),
        "error_detail": traceback.format_exc(),
    }


# ── SMALL HELPERS ─────────────────────────────────────────────────────────────

def _deser(cls, data):
    """Instantiate schema object from raw dict, or return None."""
    return cls(**data) if data else None


async def _get_xml_or_empty(job_id: str) -> str:
    return await get_xml(job_id) or ""


def _missing_keys(state: dict, required) -> list:
    return [k for k in required if not state.get(k)]


def _s2t_field_names(fields: list):
    for f in fields:
        if isinstance(f, dict):
            yield f.get("target_field") or f.get("name") or ""


def _findings_to_fix(prev_scan) -> list:
    return [f.model_dump() for f in prev_scan.findings] if prev_scan else []


def _sum_newlines(files: dict) -> int:
    return sum(c.count("\n") for c in files.values())


def _format_elapsed(elapsed: int) -> str:
    mins, secs = divmod(elapsed, 60)
    return f"{mins}m {secs}s" if mins else f"{secs}s"


def _pass_hint_msg(elapsed: int) -> str:
    return "Pass 2 (lineage)…" if elapsed > 120 else "Pass 1 (transformations)…"


def _ctx_tier(ctx: "_PipelineCtx") -> Optional[str]:
    return ctx.complexity.tier.value if ctx.complexity else None


def _doc_complete_msg(doc_truncated: bool) -> str:
    return "Documentation complete" + (" (truncated — reviewer notified)" if doc_truncated else "")


def _verification_dict(ctx: "_PipelineCtx") -> dict:
    if ctx.verification and hasattr(ctx.verification, "model_dump"):
        return ctx.verification.model_dump()
    return {}


def _reconciliation_dump(r) -> Optional[dict]:
    return r.model_dump() if r else None


def _get_smoke_failures(results: list) -> list:
    return [r for r in results if not r.passed]


def _build_smoke_flags(failures: list) -> list:
    return [
        {
            "flag_type": "SMOKE_CHECK_FAILED",
            "severity": "HIGH",
            "description": f"{r.filename}: {r.tool} check failed — {r.detail}",
            "recommendation": "Review the generated file for syntax errors before running.",
            "auto_fix_suggestion": None,
        }
        for r in failures
    ]


def _log_verify_complete(ctx: "_PipelineCtx") -> None:
    """Log detailed verification summary and warn if conversion is blocked."""
    ctx.log.info(
        f"Verification complete — status={ctx.verification.overall_status}, "
        f"checks={ctx.verification.total_checks}, passed={ctx.verification.total_passed}, "
        f"failed={ctx.verification.total_failed}, flags={ctx.verification.total_flags}, "
        f"blocked={ctx.verification.conversion_blocked}",
        step=4,
        data={
            "overall_status":    ctx.verification.overall_status,
            "total_checks":      ctx.verification.total_checks,
            "total_passed":      ctx.verification.total_passed,
            "total_failed":      ctx.verification.total_failed,
            "total_flags":       ctx.verification.total_flags,
            "conversion_blocked": ctx.verification.conversion_blocked,
            "blocking_reasons":  ctx.verification.blocked_reasons,
            "flags": [
                {"type": f.flag_type, "severity": f.severity,
                 "blocking": f.blocking, "location": f.location}
                for f in ctx.verification.flags
            ],
        },
    )
    if ctx.verification.conversion_blocked:
        ctx.log.warning(
            f"Conversion BLOCKED — {len(ctx.verification.blocked_reasons)} blocking issue(s): "
            + "; ".join(ctx.verification.blocked_reasons),
            step=4,
        )


def _parse_status_str(session_parse_report) -> str:
    return session_parse_report.parse_status if session_parse_report else "SKIPPED"


def _uploaded_files_dump(session_parse_report) -> list:
    return [f.model_dump() for f in session_parse_report.uploaded_files]


def _step_7_convert_kwargs(accepted_fixes, v_flags_raw, manifest_overrides, ctx) -> dict:
    return {
        "accepted_fixes":       accepted_fixes or None,
        "session_parse_report": ctx.session_parse_report,
        "verification_flags":   v_flags_raw or None,
        "manifest_overrides":   manifest_overrides,
        "complexity_report":    ctx.complexity,
    }


def _build_regen_convert_args(
    accepted_fixes, security_findings_to_fix, v_flags_fix,
    session_parse_report, manifest_overrides, complexity,
) -> dict:
    return {
        "accepted_fixes":       accepted_fixes or None,
        "security_findings":    security_findings_to_fix or None,
        "verification_flags":   v_flags_fix or None,
        "session_parse_report": session_parse_report,
        "manifest_overrides":   manifest_overrides,
        "complexity_report":    complexity,
    }


def _unpack_security_fix_or_raise(state: dict, required: tuple):
    """Check required keys, then unpack security-fix state. Raises ValueError on missing keys."""
    missing = [k for k in required if not state.get(k)]
    if missing:
        raise ValueError(
            f"State reconstruction failed — missing keys: {missing}. Re-upload and re-run."
        )
    return _unpack_security_fix_state(state)


async def _step_7_emit_result(ctx: "_PipelineCtx") -> AsyncGenerator[dict, None]:
    """Yield the conversion result event; set ctx.conversion_output=None on parse failure."""
    if ctx.conversion_output.parse_ok:
        file_list = list(ctx.conversion_output.files.keys())
        total_lines = _sum_newlines(ctx.conversion_output.files)
        ctx.log.step_complete(7, "Conversion", f"{len(file_list)} file(s), ~{total_lines:,} lines")
        yield await ctx.emit(7, JobStatus.CONVERTING, "Conversion complete",
                             {"conversion": ctx.conversion_output.model_dump()})
    else:
        file_list = list(ctx.conversion_output.files.keys())
        fail_msg = (
            f"Conversion output degraded — JSON parse failed; "
            f"{len(file_list)} file(s) recovered via fallback but may be incomplete. "
            "Please re-run the job. If this persists the mapping may be too large "
            "for a single generation pass."
        )
        ctx.log.step_failed(7, "Conversion", fail_msg)
        ctx.log.finalize("failed", steps_completed=7)
        ctx.log.close()
        yield await ctx.emit(7, JobStatus.FAILED, f"⚠️ {fail_msg}",
                             {"conversion": ctx.conversion_output.model_dump()})
        ctx.conversion_output = None  # sentinel: pipeline should stop


async def _fix_round_success_emit(
    conversion_output, remediation_round: int, log, emit,
) -> AsyncGenerator[dict, None]:
    """Yield the success SSE event for a security-fix conversion round."""
    file_list = list(conversion_output.files.keys())
    total_lines = _sum_newlines(conversion_output.files)
    log.step_complete(7, f"Conversion (round {remediation_round})",
                      f"{len(file_list)} file(s), ~{total_lines:,} lines")
    yield await emit(7, JobStatus.CONVERTING, f"Regeneration round {remediation_round} complete",
                     {"conversion": conversion_output.model_dump()})


async def _step_0_do_parse(
    session_files: dict, ctx: "_PipelineCtx",
) -> AsyncGenerator[dict, None]:
    """
    Run session-parser; set ctx.session_parse_report on success.
    Sets ctx._step0_aborted=True and yields the failure event on early exit.
    """
    try:
        ctx.session_parse_report = session_parser_agent.parse(
            mapping_xml=session_files.get("xml_content"),
            workflow_xml=session_files.get("workflow_xml_content"),
            parameter_file=session_files.get("parameter_file_content"),
        )
        ctx.log.info(
            f"Step 0 complete — parse_status={ctx.session_parse_report.parse_status}, "
            f"files={len(ctx.session_parse_report.uploaded_files)}, "
            f"cross_ref={ctx.session_parse_report.cross_ref.status}, "
            f"parameters={len(ctx.session_parse_report.parameters)}, "
            f"unresolved={len(ctx.session_parse_report.unresolved_variables)}",
            step=0,
            data={
                "parse_status":     ctx.session_parse_report.parse_status,
                "cross_ref_status": ctx.session_parse_report.cross_ref.status,
                "files":            _uploaded_files_dump(ctx.session_parse_report),
                "unresolved_variables": ctx.session_parse_report.unresolved_variables,
                "notes":            ctx.session_parse_report.notes,
            },
        )
        if ctx.session_parse_report.parse_status == "FAILED":
            ctx.log.step_failed(0, "Session & Parameter Parse",
                                "; ".join(ctx.session_parse_report.cross_ref.issues
                                          + ctx.session_parse_report.notes))
            ctx.log.finalize("blocked", steps_completed=0)
            ctx.log.close()
            ctx._step0_aborted = True
            yield await ctx.emit(0, JobStatus.BLOCKED,
                                 "Step 0 failed — cross-reference validation did not pass. "
                                 "Check that the Workflow XML references the uploaded Mapping.",
                                 {"session_parse_report": ctx.session_parse_report.model_dump(),
                                  "error": "; ".join(ctx.session_parse_report.cross_ref.issues)})
            return
    except Exception as e:
        has_workflow = bool(session_files.get("workflow_xml_content"))
        ctx.log.warning(f"Step 0 error: {e}", step=0)
        if has_workflow:
            ctx.log.step_failed(0, "Session & Parameter Parse", str(e), exc_info=True)
            ctx.log.finalize("failed", steps_completed=0)
            ctx.log.close()
            ctx._step0_aborted = True
            yield await ctx.emit(0, JobStatus.FAILED, f"Step 0 error: {e}", _err(e))
            return
        # Mapping-only: fall through without aborting


async def _yield_all(*gens: AsyncGenerator) -> AsyncGenerator[dict, None]:
    """Yield all events from each async generator in sequence."""
    for gen in gens:
        async for event in gen:
            yield event


async def _run_pipeline_steps_tail(ctx: "_PipelineCtx") -> AsyncGenerator[dict, None]:
    """Steps 1b–5 (runs after Step 1 confirms parse_report is populated)."""
    async for e in _yield_all(
        _step_1b_manifest(ctx), _step_2_classify(ctx), _step_2b_s2t(ctx),
        _step_3_document(ctx), _step_4_verify(ctx), _step_5_gate1(ctx),
    ):
        yield e


# ── STEP FUNCTIONS FOR run_pipeline() ────────────────────────────────────────

async def _step_0_session_parse(ctx: _PipelineCtx) -> AsyncGenerator[dict, None]:
    """Step 0 — Session & Parameter Parse (v1.1)"""
    ctx.log.step_start(0, "Session & Parameter Parse")
    yield await ctx.emit(0, JobStatus.PARSING, "Detecting file types and extracting session config…")

    session_files = await get_session_files(ctx.job_id)
    ctx._step0_aborted = False

    if session_files:
        async for event in _step_0_do_parse(session_files, ctx):
            yield event
        if ctx._step0_aborted:
            return
        ctx.log.step_complete(0, "Session & Parameter Parse",
                              _parse_status_str(ctx.session_parse_report))
        if ctx.session_parse_report:
            yield await ctx.emit(0, JobStatus.PARSING, "Step 0 complete",
                                 {"session_parse_report": ctx.session_parse_report.model_dump()})


async def _step_0b_cred_scan(ctx: _PipelineCtx) -> AsyncGenerator[dict, None]:
    """Step 0b — Scan uploaded XML for embedded credentials"""
    session_files = await get_session_files(ctx.job_id)
    if session_files and session_files.get("xml_content"):
        try:
            ctx.xml_cred_findings = scan_xml_for_secrets(session_files["xml_content"])
            if ctx.xml_cred_findings:
                ctx.log.warning(
                    f"Input XML credential scan: {len(ctx.xml_cred_findings)} potential "
                    "hardcoded credential(s) found in uploaded mapping/workflow XML. "
                    "These will be surfaced in the security scan report.",
                    step=0,
                    data={"xml_credential_count": len(ctx.xml_cred_findings)},
                )
        except Exception as e:
            ctx.log.warning(f"XML credential scan failed (non-blocking): {e}", step=0)
    # This step is always non-blocking — no yields needed on success/failure paths
    return
    yield  # make this an async generator


async def _step_1_invoke_parser(ctx: _PipelineCtx) -> bool:
    """Run parser_agent and populate ctx.parse_report / ctx.graph. Returns False on error."""
    try:
        ctx.parse_report, ctx.graph = parser_agent.parse_xml(ctx.xml_content)
        mapping_name = ctx.parse_report.mapping_names[0] if ctx.parse_report.mapping_names else None
        if mapping_name:
            ctx.log.set_mapping_name(mapping_name)
        ctx.log.info(
            f"Parse complete — status={ctx.parse_report.parse_status}, "
            f"mappings={len(ctx.parse_report.mapping_names)}, "
            f"objects={sum(ctx.parse_report.objects_found.values())}, "
            f"unresolved_params={len(ctx.parse_report.unresolved_parameters)}",
            step=1,
            data={
                "parse_status": ctx.parse_report.parse_status,
                "mappings": ctx.parse_report.mapping_names,
                "objects_found": ctx.parse_report.objects_found,
                "unresolved_parameters": ctx.parse_report.unresolved_parameters,
            }
        )
        return True
    except Exception as e:
        ctx.log.step_failed(1, "Parse XML", str(e), exc_info=True)
        ctx.log.finalize("failed", steps_completed=1)
        ctx.log.close()
        ctx._step1_error = e
        return False


async def _step_1_check_parse_status(ctx: _PipelineCtx) -> bool:
    """Validate parse_status == FAILED or no mapping_names. Returns False to stop pipeline."""
    if ctx.parse_report.parse_status == "FAILED":
        first_flag = ctx.parse_report.flags[0] if ctx.parse_report.flags else None
        user_msg = (
            first_flag.detail if first_flag
            else "XML parse failed. Check the parse report for details."
        )
        ctx.log.step_failed(1, "Parse XML", f"parse_status=FAILED — {user_msg}")
        ctx.log.finalize("blocked", steps_completed=1)
        ctx.log.close()
        await fire_webhook("job_failed", ctx.job_id, ctx.filename, 1, "blocked",
                           f"Parse FAILED — {user_msg}")
        await fire_email("job_failed", ctx.job_id, ctx.filename, 1, "blocked",
                         f"Parse FAILED — {user_msg}")
        ctx._step1_blocked_msg = user_msg
        ctx._step1_blocked_type = "failed"
        return False
    if not ctx.parse_report.mapping_names:
        msg = (
            "No Mapping definitions found in the uploaded XML. "
            "If you uploaded a Workflow file as the primary mapping, please re-upload "
            "with the Mapping XML in the required field and the Workflow XML in the optional field."
        )
        ctx.log.step_failed(1, "Parse XML", msg)
        ctx.log.finalize("blocked", steps_completed=1)
        ctx.log.close()
        ctx._step1_blocked_msg = msg
        ctx._step1_blocked_type = "no_mappings"
        return False
    return True


async def _step_1_parse_xml(ctx: _PipelineCtx) -> AsyncGenerator[dict, None]:
    """Step 1 — Parse Informatica XML"""
    ctx.log.step_start(1, "Parse XML")
    ctx.log.state_change("pending", "parsing", step=1)
    yield await ctx.emit(1, JobStatus.PARSING, "Parsing Informatica XML…")

    ctx.xml_content = await get_xml(ctx.job_id)
    if not ctx.xml_content:
        ctx.log.step_failed(1, "Parse XML", "XML content not found in database")
        ctx.log.finalize("failed", steps_completed=0)
        ctx.log.close()
        yield await ctx.emit(1, JobStatus.FAILED, "XML content not found",
                         {"error": "XML content not found in database"})
        return

    ok = await _step_1_invoke_parser(ctx)
    if not ok:
        yield await ctx.emit(1, JobStatus.FAILED, f"Parse error: {ctx._step1_error}", _err(ctx._step1_error))
        return

    ok = await _step_1_check_parse_status(ctx)
    if not ok:
        if getattr(ctx, "_step1_blocked_type", None) == "no_mappings":
            yield await ctx.emit(1, JobStatus.BLOCKED, "No mappings found",
                             {"parse_report": ctx.parse_report.model_dump(), "error": ctx._step1_blocked_msg})
        else:
            yield await ctx.emit(1, JobStatus.BLOCKED, "Parse FAILED — see parse report",
                             {"parse_report": ctx.parse_report.model_dump(), "error": ctx._step1_blocked_msg})
        ctx.parse_report = None  # sentinel: pipeline should stop
        return

    ctx.log.step_complete(1, "Parse XML",
                      f"{sum(ctx.parse_report.objects_found.values())} objects, "
                      f"{len(ctx.parse_report.mapping_names)} mapping(s)")


async def _step_1b_manifest(ctx: _PipelineCtx) -> AsyncGenerator[dict, None]:
    """Step 1b — Manifest generation (non-blocking)"""
    # Generate a pre-conversion manifest immediately after parsing.
    # The manifest surfaces every source→target connection with a confidence
    # score and flags any ambiguous or unmapped items for human review.
    # This step never blocks the pipeline — it emits the manifest report and
    # xlsx bytes for the UI to surface, then continues.
    try:
        ctx.manifest_report = manifest_agent.build_manifest(ctx.graph)
        ctx.manifest_xlsx_bytes = manifest_agent.write_xlsx_bytes(ctx.manifest_report)
        ctx.log.info(
            f"Manifest built — {ctx.manifest_report.source_count} sources, "
            f"review_required={ctx.manifest_report.review_required}, "
            f"low/unmapped={ctx.manifest_report.unmapped_count + ctx.manifest_report.low_confidence}",
            step=1,
        )
    except Exception as e:
        ctx.log.warning(f"Manifest generation failed (non-blocking): {e}", step=1)

    # manifest_xlsx_b64 is NOT stored in state — it can be large (150KB+ base64)
    # and is regenerated on demand via GET /jobs/{job_id}/manifest.xlsx
    yield await ctx.emit(1, JobStatus.PARSING, "Parse complete", {
        "parse_report":    ctx.parse_report.model_dump(),
        "graph":           ctx.graph,
        "manifest_report": ctx.manifest_report.model_dump() if ctx.manifest_report else None,
        "has_manifest":    ctx.manifest_report is not None,
    })


async def _step_2_classify(ctx: _PipelineCtx) -> AsyncGenerator[dict, None]:
    """Step 2 — Classify mapping complexity"""
    ctx.log.step_start(2, "Classify Complexity")
    ctx.log.state_change("parsing", "classifying", step=2)
    yield await ctx.emit(2, JobStatus.CLASSIFYING, "Classifying mapping complexity…")
    try:
        ctx.complexity = classifier_agent.classify(ctx.parse_report, ctx.graph)
        ctx.log.info(
            f"Classified as {ctx.complexity.tier.value} — criteria: {', '.join(ctx.complexity.criteria_matched)}",
            step=2,
            data={
                "tier": ctx.complexity.tier.value,
                "criteria_matched": ctx.complexity.criteria_matched,
                "special_flags": ctx.complexity.special_flags,
            }
        )
    except Exception as e:
        ctx.log.step_failed(2, "Classify Complexity", str(e), exc_info=True)
        ctx.log.finalize("failed", steps_completed=2)
        ctx.log.close()
        yield await ctx.emit(2, JobStatus.FAILED, f"Classification error: {e}", _err(e))
        return

    ctx.log.step_complete(2, "Classify Complexity", ctx.complexity.tier.value)
    yield await ctx.emit(2, JobStatus.CLASSIFYING, f"Classified as {ctx.complexity.tier.value}",
                     {"complexity": ctx.complexity.model_dump()})


async def _step_2b_s2t(ctx: _PipelineCtx) -> AsyncGenerator[dict, None]:
    """Step 2b — Source-to-target mapping (non-blocking)"""
    ctx.log.step_start("S2T", "Source-to-Target Mapping")
    s2t_result: dict = {}
    try:
        s2t_result = s2t_agent.build_s2t(ctx.parse_report, ctx.graph, ctx.job_id)
        n_mapped   = s2t_result["summary"]["mapped_fields"]
        n_unmapped = s2t_result["summary"]["unmapped_target_fields"]
        n_src_ump  = s2t_result["summary"]["unmapped_source_fields"]
        ctx.log.info(
            f"S2T mapping built — {n_mapped} mapped, {n_unmapped} unmapped target(s), "
            f"{n_src_ump} unmapped source(s), Excel: {s2t_result['excel_filename']}",
            step="S2T",
            data=s2t_result["summary"],
        )
        ctx.log.step_complete("S2T", "Source-to-Target Mapping",
                          f"{n_mapped} mapped fields, {n_unmapped} unmapped")
    except Exception as e:
        ctx.log.warning(f"S2T mapping generation failed (non-blocking): {e}", step="S2T")
        ctx.log.step_complete("S2T", "Source-to-Target Mapping", f"FAILED (non-blocking): {e}")

    # Store summary + records in job state (skip heavy excel_path binary)
    ctx.s2t_result = s2t_result
    ctx.s2t_state = {
        k: v for k, v in s2t_result.items() if k != "excel_path"
    } if s2t_result else {}
    yield await ctx.emit(2, JobStatus.CLASSIFYING, "S2T mapping generated",
                     {"s2t": ctx.s2t_state})


async def _doc_heartbeat_loop(doc_task: asyncio.Task, ctx: _PipelineCtx) -> AsyncGenerator[dict, None]:
    """Emit heartbeat SSE events while the documentation task runs."""
    _HEARTBEAT = 30  # seconds between progress SSE events
    _elapsed   = 0
    while not doc_task.done():
        try:
            await asyncio.wait_for(asyncio.shield(doc_task), timeout=_HEARTBEAT)
        except asyncio.TimeoutError:
            _elapsed += _HEARTBEAT
            yield await ctx.emit(
                3, JobStatus.DOCUMENTING,
                f"Generating documentation — {_pass_hint_msg(_elapsed)} ({_format_elapsed(_elapsed)} elapsed)",
            )
            continue
        except Exception:
            # Non-timeout exception from the shielded task (e.g. API error).
            # Break out so doc_task.result() re-raises it through the handler below.
            break
        break  # task completed normally


def _validate_doc_sentinels(documentation_md: str, log: Any) -> tuple[str, bool, bool]:
    """
    Check doc completeness sentinels; strip them from the output.
    Returns (cleaned_md, doc_truncated, doc_missing_sentinel).
    """
    doc_truncated = DOC_TRUNCATION_SENTINEL in documentation_md
    doc_missing_sentinel = DOC_COMPLETE_SENTINEL not in documentation_md and not doc_truncated

    if doc_truncated:
        log.warning(
            "Documentation was truncated (hit token limit on one pass). "
            "A HIGH warning flag will be surfaced to the reviewer at Gate 1.",
            step=3,
        )
    elif doc_missing_sentinel:
        log.warning(
            "Documentation completion marker missing — output may be incomplete. "
            "A HIGH warning flag will be surfaced to the reviewer at Gate 1.",
            step=3,
        )

    cleaned = (
        documentation_md
        .replace(DOC_COMPLETE_SENTINEL, "")
        .replace(DOC_TRUNCATION_SENTINEL, "")
        .strip()
    )
    return cleaned, doc_truncated, doc_missing_sentinel


async def _step_3_run_doc_agent(ctx: _PipelineCtx) -> AsyncGenerator[dict, None]:
    """Launch doc agent, stream heartbeats, collect result into ctx. Yields heartbeat events."""
    _doc_task = asyncio.create_task(
        documentation_agent.document(
            ctx.parse_report, ctx.complexity, ctx.graph, session_parse_report=ctx.session_parse_report
        )
    )
    async for event in _doc_heartbeat_loop(_doc_task, ctx):
        yield event

    try:
        documentation_md = _doc_task.result()
    except Exception as e:
        ctx.log.step_failed(3, "Generate Documentation", str(e), exc_info=True)
        ctx.log.finalize("failed", steps_completed=3)
        ctx.log.close()
        ctx._step3_error = e
        return

    documentation_md, doc_truncated, doc_missing_sentinel = _validate_doc_sentinels(
        documentation_md, ctx.log
    )
    doc_len = len(documentation_md)
    ctx.log.info(f"Documentation generated — {doc_len} chars (truncated={doc_truncated})",
             step=3, data={"doc_chars": doc_len, "doc_truncated": doc_truncated})
    ctx.log.step_complete(3, "Generate Documentation", f"{doc_len:,} chars")
    ctx.documentation_md = documentation_md
    ctx._doc_truncated = doc_truncated
    ctx._doc_missing_sentinel = doc_missing_sentinel

    # Generate analyst view + gaps (single Claude call, split by delimiter)
    try:
        from .agents.analyst_view import generate_analyst_view
        s2t_records = []
        if hasattr(ctx, 's2t_state') and isinstance(ctx.s2t_state, dict):
            s2t_records = ctx.s2t_state.get("records", [])
        ctx.analyst_view_md, ctx.analyst_gaps_md = await generate_analyst_view(
            ctx.graph, ctx.parse_report, ctx.documentation_md,
            session_parse_report=ctx.session_parse_report,
            s2t_records=s2t_records,
        )
    except Exception as e:
        ctx.log.warning(f"Analyst view generation failed (non-blocking): {e}", step=3)
        ctx.analyst_view_md = ""
        ctx.analyst_gaps_md = ""


async def _step_3_document(ctx: _PipelineCtx) -> AsyncGenerator[dict, None]:
    """Step 3 — Generate documentation"""
    ctx.log.step_start(3, "Generate Documentation")
    ctx.log.state_change("classifying", "documenting", step=3)
    ctx.log.claude_call(3, "documentation generation")

    # G6: Check if this step should be skipped per org_config pipeline_options
    if should_skip_step(3, pattern=None, tier=_ctx_tier(ctx)):
        _orch_log.info("Step 3 (documentation) skipped per pipeline_options config")
        ctx.log.info("Step 3 skipped per org_config pipeline_options", step=3)
        ctx.documentation_md = "(skipped per org config)"
        ctx._doc_truncated = False
        ctx._doc_missing_sentinel = False
        yield await ctx.emit(3, JobStatus.DOCUMENTING, "Documentation skipped per org config",
                             {"documentation_md": ctx.documentation_md, "analyst_view_md": "", "analyst_gaps_md": "", "doc_truncated": False})
        return

    yield await ctx.emit(3, JobStatus.DOCUMENTING, "Generating documentation — Pass 1 (transformations)…")

    # Run documentation as a background task so we can emit heartbeat SSE events
    # every 30 s while both passes run — prevents the client from seeing a frozen
    # spinner and keeps the SSE connection alive during long Claude calls.
    async for event in _step_3_run_doc_agent(ctx):
        yield event

    if getattr(ctx, "_step3_error", None) is not None:
        yield await ctx.emit(3, JobStatus.FAILED, f"Documentation error: {ctx._step3_error}", _err(ctx._step3_error))
        return

    doc_truncated = getattr(ctx, "_doc_truncated", False)
    yield await ctx.emit(3, JobStatus.DOCUMENTING, _doc_complete_msg(doc_truncated),
                         {"documentation_md": ctx.documentation_md, "analyst_view_md": ctx.analyst_view_md, "analyst_gaps_md": ctx.analyst_gaps_md, "doc_truncated": doc_truncated})


def _inject_doc_truncation_flag(ctx: _PipelineCtx, doc_truncated: bool, doc_missing_sentinel: bool) -> None:
    """Inject a HIGH severity DOCUMENTATION_TRUNCATED flag into the verification report."""
    from .models.schemas import VerificationFlag
    trunc_reason = (
        "Documentation hit the token limit during generation — one or more sections "
        "(field-level lineage, session context, or ambiguities) may be incomplete or missing. "
        "Review the documentation tab carefully before approving. "
        "If critical sections are missing, reject and re-upload to regenerate."
        if doc_truncated else
        "Documentation did not finish normally — the completion marker was not found. "
        "Output may be cut off. Review the documentation tab before approving."
    )
    truncation_flag = VerificationFlag(
        flag_type="DOCUMENTATION_TRUNCATED",
        location="Step 3 — Documentation Generation",
        description=trunc_reason,
        blocking=False,
        severity="HIGH",
        recommendation=(
            "Read through the full documentation and confirm all transformations, "
            "field lineage, and business rules are present before approving. "
            "If sections are missing, click Reject and re-upload the mapping to regenerate."
        ),
        auto_fix_suggestion=None,
    )
    ctx.verification.flags.insert(0, truncation_flag)
    ctx.verification.total_flags += 1
    ctx.log.warning("Truncation flag injected into verification report", step=4)


async def _step_4_verify(ctx: _PipelineCtx) -> AsyncGenerator[dict, None]:
    """Step 4 — Verification checks"""
    ctx.log.step_start(4, "Verification")
    ctx.log.state_change("documenting", "verifying", step=4)
    ctx.log.claude_call(4, "qualitative quality checks")
    yield await ctx.emit(4, JobStatus.VERIFYING, "Running verification checks…")

    # Retrieve doc_truncated/doc_missing_sentinel set by _step_3_document
    doc_truncated = getattr(ctx, "_doc_truncated", False)
    doc_missing_sentinel = getattr(ctx, "_doc_missing_sentinel", False)

    try:
        ctx.verification = await verification_agent.verify(
            ctx.parse_report, ctx.complexity, ctx.documentation_md, ctx.graph,
            session_parse_report=ctx.session_parse_report,
        )
        if doc_truncated or doc_missing_sentinel:
            _inject_doc_truncation_flag(ctx, doc_truncated, doc_missing_sentinel)
        _log_verify_complete(ctx)
    except Exception as e:
        ctx.log.step_failed(4, "Verification", str(e), exc_info=True)
        ctx.log.finalize("failed", steps_completed=4)
        ctx.log.close()
        yield await ctx.emit(4, JobStatus.FAILED, f"Verification error: {e}", _err(e))
        return

    ctx.log.step_complete(4, "Verification", ctx.verification.overall_status)
    yield await ctx.emit(4, JobStatus.VERIFYING,
                     f"Verification complete — {ctx.verification.overall_status}",
                     {"verification": ctx.verification.model_dump()})

    # Progressive AUDIT_REPORT — first write after verification
    _job_snap = await _db.get_job(ctx.job_id) or {}
    write_audit_report_progressive(
        ctx.job_id, dict(_job_snap),
        {"filename":     ctx.filename,
         "parse_report": ctx.parse_report.model_dump() if ctx.parse_report else {},
         "complexity":   ctx.complexity.model_dump() if ctx.complexity else {},
         "verification": ctx.verification.model_dump()},
        step=4,
    )


async def _export_docs_only(ctx: _PipelineCtx) -> None:
    """Export artefacts to disk for docs-only mode (non-fatal on failure)."""
    try:
        from .job_exporter import export_job as _export
        _final_state = (await _db.get_job(ctx.job_id) or {}).get("state") or {}
        await _export(ctx.job_id, {"job_id": ctx.job_id, "filename": ctx.filename,
                               "status": JobStatus.COMPLETE.value,
                               "current_step": 4}, _final_state)
    except Exception as _exp_exc:
        ctx.log.warning(f"Docs-only export warning (non-fatal): {_exp_exc}")


async def _step_5_gate1(ctx: _PipelineCtx) -> AsyncGenerator[dict, None]:
    """Step 5 — Gate 1 (docs-only mode exit or Gate 1 pause for human review)"""
    # ── DOCS-ONLY MODE EXIT ────────────────────────────────────
    if ctx.pipeline_mode == "docs_only":
        ctx.log.state_change("verifying", "complete", step=4)
        ctx.log.finalize("complete", steps_completed=4)
        ctx.log.close()
        await _export_docs_only(ctx)
        yield await ctx.emit(4, JobStatus.COMPLETE,
                         "Documentation complete. Stopped after Step 4 (docs-only mode).")
        return

    # ── STEP 5 — AWAIT HUMAN REVIEW ───────────────────────────
    ctx.log.state_change("verifying", "awaiting_review", step=5)
    ctx.log.info("Pipeline paused — awaiting human review and sign-off", step=5)
    v_flags = len(ctx.verification.flags) if ctx.verification else 0
    ctx.log.finalize("awaiting_review", steps_completed=5, flags_count=v_flags)
    await fire_webhook(
        "gate_waiting", ctx.job_id, ctx.filename, 5, "awaiting_review",
        f"Gate 1 is waiting for sign-off on '{ctx.filename}' — "
        f"{v_flags} verification flag(s). Please review and approve or reject.",
        gate="Gate 1 — Human Sign-off",
    )
    await fire_email(
        "gate_waiting", ctx.job_id, ctx.filename, 5, "awaiting_review",
        f"Gate 1 is waiting for sign-off — {v_flags} verification flag(s). "
        f"Please review and approve or reject.",
        gate="gate1",
    )
    yield await ctx.emit(5, JobStatus.AWAITING_REVIEW,
                     "Awaiting human review and sign-off. Pipeline paused.")
    ctx.log.close()


# ── STEP FUNCTIONS FOR resume_after_signoff() ────────────────────────────────

async def _step_6_assign_stack(ctx: _PipelineCtx) -> AsyncGenerator[dict, None]:
    """Step 6 — Stack assignment"""
    ctx.log.step_start(6, "Stack Assignment")
    ctx.log.state_change("awaiting_review", "assigning_stack", step=6)
    ctx.log.claude_call(6, "stack assignment rationale")
    yield await ctx.emit(6, JobStatus.ASSIGNING_STACK, "Assigning target stack…")
    try:
        ctx.stack_assignment = await conversion_agent.assign_stack(ctx.complexity, ctx.graph, ctx.parse_report)
        ctx.log.info(
            f"Stack assigned: {ctx.stack_assignment.assigned_stack.value}",
            step=6,
            data={
                "stack": ctx.stack_assignment.assigned_stack.value,
                "tier": ctx.stack_assignment.complexity_tier.value,
                "special_concerns": ctx.stack_assignment.special_concerns,
            }
        )
    except Exception as e:
        ctx.log.step_failed(6, "Stack Assignment", str(e), exc_info=True)
        ctx.log.finalize("failed", steps_completed=6)
        ctx.log.close()
        yield await ctx.emit(6, JobStatus.FAILED, f"Stack assignment error: {e}", _err(e))
        return

    ctx.log.step_complete(6, "Stack Assignment", ctx.stack_assignment.assigned_stack.value)
    yield await ctx.emit(6, JobStatus.ASSIGNING_STACK,
                     f"Assigned stack: {ctx.stack_assignment.assigned_stack.value}",
                     {"stack_assignment": ctx.stack_assignment.model_dump()})


def _log_convert_inputs(ctx: _PipelineCtx, accepted_fixes: list, v_flags_raw: list,
                        manifest_overrides: list | None) -> None:
    """Log the inputs being injected into the conversion prompt."""
    if accepted_fixes:
        ctx.log.info(
            f"Injecting {len(accepted_fixes)} reviewer-approved fix(es) into conversion prompt",
            step=7, data={"accepted_fixes": accepted_fixes},
        )
    if v_flags_raw:
        ctx.log.info(
            f"Injecting {len(v_flags_raw)} verification flag(s) into conversion prompt "
            "for auto-handling", step=7,
            data={"flag_types": [f["flag_type"] for f in v_flags_raw]},
        )
    if manifest_overrides:
        ctx.log.info(f"Applying {len(manifest_overrides)} manifest override(s) from reviewer", step=7)


def _log_conversion_result(ctx: _PipelineCtx) -> None:
    """Log conversion output details; warn on degraded output or notes."""
    file_list = list(ctx.conversion_output.files.keys())
    total_lines = sum(c.count("\n") for c in ctx.conversion_output.files.values())
    ctx.log.info(
        f"Conversion complete — {len(file_list)} file(s), ~{total_lines:,} lines",
        step=7,
        data={"files": file_list, "total_lines": total_lines, "notes": ctx.conversion_output.notes}
    )
    for note in (ctx.conversion_output.notes or []):
        ctx.log.warning(f"Conversion note: {note}", step=7)
    if not ctx.conversion_output.parse_ok:
        ctx.log.warning(
            f"Conversion output was DEGRADED — JSON parse failed; "
            f"{len(file_list)} file(s) recovered via fallback. "
            "Files may be partial or raw. Review before use.",
            step=7,
        )


async def _step_7_convert(ctx: _PipelineCtx, state: dict) -> AsyncGenerator[dict, None]:
    """Step 7 — Code generation"""
    accepted_fixes = _collect_accepted_fixes(state)
    v_flags_raw = _collect_v_flags_from_ctx(ctx)
    manifest_overrides = state.get("manifest_overrides")

    _log_convert_inputs(ctx, accepted_fixes, v_flags_raw, manifest_overrides)

    ctx.log.step_start(7, f"Convert to {ctx.stack_assignment.assigned_stack.value}")
    ctx.log.state_change("assigning_stack", "converting", step=7)
    ctx.log.claude_call(7, f"code generation ({ctx.stack_assignment.assigned_stack.value})")
    yield await ctx.emit(7, JobStatus.CONVERTING,
                         f"Converting to {ctx.stack_assignment.assigned_stack.value} (Claude)…")

    try:
        ctx.conversion_output = await conversion_agent.convert(
            ctx.stack_assignment, ctx.documentation_md, ctx.graph,
            **_step_7_convert_kwargs(accepted_fixes, v_flags_raw, manifest_overrides, ctx),
        )
        _log_conversion_result(ctx)
    except Exception as e:
        ctx.log.step_failed(7, "Conversion", str(e), exc_info=True)
        ctx.log.finalize("failed", steps_completed=7)
        ctx.log.close()
        await fire_webhook("job_failed", ctx.job_id, ctx.filename, 7, "failed",
                           f"Conversion failed for '{ctx.filename}': {e}")
        await fire_email("job_failed", ctx.job_id, ctx.filename, 7, "failed",
                         f"Conversion failed: {e}")
        yield await ctx.emit(7, JobStatus.FAILED, f"Conversion error: {e}", _err(e))
        return

    async for e in _step_7_emit_result(ctx):
        yield e


async def _step_7b_smoke(ctx: _PipelineCtx) -> AsyncGenerator[dict, None]:
    """Step 7b — Smoke execution check (non-blocking)"""
    # Validates generated files without a live database:
    #   Python/PySpark → py_compile  |  dbt SQL → Jinja balance + SELECT check
    #   YAML → yaml.safe_load
    # Non-blocking: failures surface as HIGH flags appended to the verification
    # report so Gate 3 reviewers see them without stopping the pipeline.
    try:
        smoke_results = smoke_execute_files(
            ctx.conversion_output.files,
            ctx.conversion_output.target_stack,
        )
        smoke_failures = _get_smoke_failures(smoke_results)
        if smoke_failures:
            summary = format_smoke_results(smoke_results)
            ctx.log.warning(
                f"Smoke execution: {len(smoke_failures)}/{len(smoke_results)} file(s) failed "
                f"compilation/structural checks. Details:\n{summary}",
                step=7,
            )
            # Inject as HIGH verification flags so reviewers see them at Gate 3
            smoke_flags = _build_smoke_flags(smoke_failures)
            # Merge into existing conversion state for UI display
            existing_conv = ctx.conversion_output.model_dump()
            existing_conv.setdefault("smoke_flags", [])
            existing_conv["smoke_flags"].extend(smoke_flags)
            await update_job(ctx.job_id, {"conversion": existing_conv})
        else:
            ctx.log.info(
                f"Smoke execution: all {len(smoke_results)} file(s) passed "
                "compilation/structural checks.",
                step=7,
            )
    except Exception as e:
        ctx.log.warning(f"Smoke execution check failed (non-blocking): {e}", step=7)
    # This step is always non-blocking
    return
    yield  # make this an async generator


async def _pause_at_security_gate(ctx: _PipelineCtx) -> AsyncGenerator[dict, None]:
    """Emit Gate 2 pause events and webhooks when security findings are present."""
    ctx.log.state_change("security_scanning", "awaiting_security_review", step=9)
    ctx.log.info(
        f"Security scan found issues (recommendation={ctx.security_scan.recommendation}) — "
        f"pausing for human review at Step 9.",
        step=9,
    )
    ctx.log.finalize("awaiting_security_review", steps_completed=9)
    ctx.log.close()
    finding_count = len(ctx.security_scan.findings) if ctx.security_scan.findings else 0
    rec = ctx.security_scan.recommendation
    await fire_webhook(
        "gate_waiting", ctx.job_id, ctx.filename, 9, "awaiting_security_review",
        f"Gate 2 is waiting for security review on '{ctx.filename}' — "
        f"{finding_count} finding(s), recommendation: {rec}. "
        f"Please review and approve, acknowledge, or fail.",
        gate="Gate 2 — Security Review",
    )
    await fire_email(
        "gate_waiting", ctx.job_id, ctx.filename, 9, "awaiting_security_review",
        f"Gate 2 is waiting for security review — {finding_count} finding(s), "
        f"recommendation: {rec}. Please approve, acknowledge, or fail.",
        gate="gate2",
    )
    yield await ctx.emit(9, JobStatus.AWAITING_SEC_REVIEW,
                     "⚠️ Security findings require review. Pipeline paused at Step 9 — "
                     "please review and decide to proceed, acknowledge, or fail the job.",
                     {"security_scan": ctx.security_scan.model_dump()})


async def _step_8_sec_scan(ctx: _PipelineCtx) -> AsyncGenerator[dict, None]:
    """Step 8 — Security scan of generated code"""
    ctx.log.step_start(8, "Security Scan (bandit + YAML + Claude)")
    ctx.log.state_change("converting", "security_scanning", step=8)
    yield await ctx.emit(8, JobStatus.CONVERTING,
                     "Running security scan on generated code…")

    ctx.security_scan = None
    try:
        ctx.security_scan = await security_agent.scan(
            conversion=ctx.conversion_output,
            mapping_name=ctx.conversion_output.mapping_name,
        )
        _sec_rec = ctx.security_scan.recommendation
        ctx.log.info(
            f"Security scan complete — recommendation={_sec_rec}, "
            f"critical={ctx.security_scan.critical_count}, high={ctx.security_scan.high_count}, "
            f"medium={ctx.security_scan.medium_count}, low={ctx.security_scan.low_count}",
            step=8,
            data={
                "recommendation": _sec_rec,
                "critical":   ctx.security_scan.critical_count,
                "high":       ctx.security_scan.high_count,
                "medium":     ctx.security_scan.medium_count,
                "low":        ctx.security_scan.low_count,
                "ran_bandit": ctx.security_scan.ran_bandit,
            },
        )
        ctx.log.step_complete(8, "Security Scan", _sec_rec)
    except Exception as e:
        ctx.log.warning(f"Security scan failed (non-blocking): {e}", step=8)
        from .models.schemas import SecurityScanReport
        ctx.security_scan = SecurityScanReport(
            mapping_name=ctx.conversion_output.mapping_name,
            target_stack=str(ctx.conversion_output.target_stack),
            recommendation="REVIEW_RECOMMENDED",
            claude_summary=f"Security scan could not complete: {e}. Manual review recommended.",
        )
        ctx.log.step_complete(8, "Security Scan", "SKIPPED (error)")

    # Progressive AUDIT_REPORT — updated after security scan
    _job_snap9 = await _db.get_job(ctx.job_id) or {}
    write_audit_report_progressive(
        ctx.job_id, dict(_job_snap9),
        {"filename":     ctx.filename,
         "parse_report": ctx.parse_report.model_dump() if ctx.parse_report else {},
         "complexity":   ctx.complexity.model_dump() if ctx.complexity else {},
         "verification": ctx.verification.model_dump() if ctx.verification else {},
         "conversion":   ctx.conversion_output.model_dump() if ctx.conversion_output else {},
         "security_scan": ctx.security_scan.model_dump() if ctx.security_scan else {}},
        step=9,
    )

    # ── STEP 9 — HUMAN SECURITY REVIEW GATE ─────────────────────────────────
    if ctx.security_scan and ctx.security_scan.recommendation != "APPROVED":
        async for event in _pause_at_security_gate(ctx):
            yield event
    else:
        ctx.log.info("Security scan clean (APPROVED) — auto-proceeding to Step 10.", step=9)


# ── STEP FUNCTIONS FOR resume_after_security_review() ────────────────────────

def _log_code_review_result(ctx: _PipelineCtx) -> None:
    """Log code review outcome including optional equivalence report."""
    rec = ctx.code_review.recommendation
    eq  = ctx.code_review.equivalence_report
    eq_suffix = (
        f"; equivalence: {eq.total_verified}V/{eq.total_needs_review}NR/{eq.total_mismatches}M"
        if eq else ""
    )
    ctx.log.info(
        f"Code review complete — {ctx.code_review.total_passed}/{len(ctx.code_review.checks)} checks passed, "
        f"recommendation: {rec}" + eq_suffix,
        step=10,
        data={
            "recommendation": rec,
            "total_passed": ctx.code_review.total_passed,
            "total_failed": ctx.code_review.total_failed,
            "equivalence_verified": eq.total_verified if eq else None,
            "equivalence_needs_review": eq.total_needs_review if eq else None,
            "equivalence_mismatches": eq.total_mismatches if eq else None,
        },
    )
    ctx.log.step_complete(10, "Code Quality Review", rec)


def _make_fallback_code_review(ctx: _PipelineCtx, error: Exception) -> Any:
    """Create a minimal CodeReviewReport fallback when the review agent fails."""
    from .models.schemas import CodeReviewReport
    return CodeReviewReport(
        mapping_name=ctx.conversion_output.mapping_name,
        target_stack=ctx.conversion_output.target_stack.value,
        checks=[],
        total_passed=0,
        total_failed=0,
        recommendation="REVIEW_RECOMMENDED",
        summary=f"Automated review could not complete: {error}. Please review the converted code manually.",
        parse_degraded=not ctx.conversion_output.parse_ok,
    )


async def _step_10_review(ctx: _PipelineCtx) -> AsyncGenerator[dict, None]:
    """Step 10 — Code quality review"""
    ctx.log.step_start(10, "Code Quality Review")
    ctx.log.state_change("awaiting_security_review", "reviewing", step=10)
    ctx.log.claude_call(10, "static code review")
    yield await ctx.emit(10, JobStatus.REVIEWING,
                     "Running code quality review (Claude)…",
                     {"security_scan": ctx.security_scan.model_dump() if ctx.security_scan else None})

    verification_dict = (ctx.verification.model_dump()
                         if ctx.verification and hasattr(ctx.verification, "model_dump")
                         else {})
    s2t_dict = ctx.s2t_state  # already stripped of excel_path

    try:
        ctx.code_review = await review_agent.review(
            conversion_output=ctx.conversion_output,
            documentation_md=ctx.documentation_md,
            verification=verification_dict,
            s2t=s2t_dict,
            parse_report=ctx.parse_report,
            xml_content=ctx.xml_content,   # v1.3 — logic equivalence check against original XML
        )
        _log_code_review_result(ctx)
    except Exception as e:
        ctx.log.warning(f"Code review failed (non-blocking): {e}", step=10)
        ctx.code_review = _make_fallback_code_review(ctx, e)
        ctx.log.step_complete(10, "Code Quality Review", "SKIPPED (error)")


def _extract_s2t_field_list(s2t_state: dict) -> list[str]:
    """Extract non-empty target field names from s2t state dict."""
    if not (s2t_state and isinstance(s2t_state.get("fields"), list)):
        return []
    return [name for name in _s2t_field_names(s2t_state["fields"]) if name]


async def _step_10b_reconcile(ctx: _PipelineCtx) -> AsyncGenerator[dict, None]:
    """Step 10b — Structural reconciliation (non-blocking)"""
    reconciliation_report = None
    try:
        s2t_field_list = _extract_s2t_field_list(ctx.s2t_state)
        reconciliation_report = generate_reconciliation_report(
            parse_report=ctx.parse_report,
            conversion_output=ctx.conversion_output,
            s2t_field_list=s2t_field_list,
        )
        ctx.log.info(
            f"Reconciliation complete — status={reconciliation_report.final_status}, "
            f"match_rate={reconciliation_report.match_rate:.1f}%, "
            f"mismatched_fields={len(reconciliation_report.mismatched_fields)}",
            step=10,
            data={
                "final_status": reconciliation_report.final_status,
                "match_rate":   reconciliation_report.match_rate,
                "mismatched":   len(reconciliation_report.mismatched_fields),
            },
        )
    except Exception as e:
        ctx.log.warning(f"Structural reconciliation failed (non-blocking): {e}", step=10)
    # Store on ctx so _step_11_tests can access it
    ctx._reconciliation_report = reconciliation_report
    # This step is always non-blocking
    return
    yield  # make this an async generator


def _make_fallback_test_report(ctx: _PipelineCtx, error: Exception) -> Any:
    """Return a minimal TestReport when test generation fails (non-blocking)."""
    from .models.schemas import TestReport as TR
    return TR(
        mapping_name=ctx.conversion_output.mapping_name,
        target_stack=ctx.conversion_output.target_stack.value,
        test_files={},
        field_coverage=[],
        filter_coverage=[],
        fields_covered=0,
        fields_missing=0,
        coverage_pct=0.0,
        missing_fields=[],
        filters_covered=0,
        filters_missing=0,
        notes=[f"Test generation failed (non-blocking): {error}"],
    )


def _run_test_agent(ctx: _PipelineCtx, verification_dict: dict) -> None:
    """Invoke test_agent; populate ctx.test_report and log results (non-blocking)."""
    ctx.test_report = test_agent.generate_tests(
        conversion_output=ctx.conversion_output,
        s2t=ctx.s2t_state,
        verification=verification_dict,
        graph=ctx.graph,
    )
    ctx.log.info(
        f"Test generation complete — coverage {ctx.test_report.coverage_pct}%, "
        f"{ctx.test_report.fields_covered}/{ctx.test_report.fields_covered + ctx.test_report.fields_missing} fields covered, "
        f"{len(ctx.test_report.test_files)} test file(s) generated",
        step=11,
        data={
            "coverage_pct":   ctx.test_report.coverage_pct,
            "fields_covered": ctx.test_report.fields_covered,
            "fields_missing": ctx.test_report.fields_missing,
            "missing_fields": ctx.test_report.missing_fields,
            "test_files":     list(ctx.test_report.test_files.keys()),
        }
    )
    for note in (ctx.test_report.notes or []):
        ctx.log.info(f"Test note: {note}", step=11)
    ctx.log.step_complete(11, "Test Generation",
                      f"{ctx.test_report.coverage_pct}% coverage, {len(ctx.test_report.test_files)} file(s)")


async def _step_11_tests(ctx: _PipelineCtx, state: dict) -> AsyncGenerator[dict, None]:
    """Step 11 — Test generation & coverage check"""
    ctx.log.step_start(11, "Test Generation & Coverage Check")
    ctx.log.state_change("reviewing", "testing", step=11)

    reconciliation_report = getattr(ctx, "_reconciliation_report", None)
    verification_dict = _verification_dict(ctx)

    # G6: Check if this step should be skipped per org_config pipeline_options
    _pattern = state.get("pattern_classification", {}).get("pattern")
    _tier = state.get("complexity", {}).get("tier")
    if should_skip_step(11, pattern=_pattern, tier=_tier):
        _orch_log.info("Step 11 (test generation) skipped per pipeline_options config")
        ctx.log.info("Step 11 skipped per org_config pipeline_options", step=11)
        ctx.test_report = None
        return

    yield await ctx.emit(11, JobStatus.TESTING, "Generating tests and checking field coverage…",
                         {
                             "code_review": ctx.code_review.model_dump(),
                             "reconciliation": _reconciliation_dump(reconciliation_report),
                         })

    try:
        _run_test_agent(ctx, verification_dict)
    except Exception as e:
        ctx.log.warning(f"Test generation failed (non-blocking): {e}", step=11)
        ctx.test_report = _make_fallback_test_report(ctx, e)
        ctx.log.step_complete(11, "Test Generation", "SKIPPED (error)")

    # Progressive AUDIT_REPORT — updated after test generation
    _job_snap11 = await _db.get_job(ctx.job_id) or {}
    write_audit_report_progressive(
        ctx.job_id, dict(_job_snap11),
        {"filename":     ctx.filename,
         "parse_report": ctx.parse_report.model_dump() if ctx.parse_report else {},
         "complexity":   ctx.complexity.model_dump() if ctx.complexity else {},
         "verification": ctx.verification.model_dump() if ctx.verification else {},
         "conversion":   ctx.conversion_output.model_dump() if ctx.conversion_output else {},
         "security_scan": ctx.security_scan.model_dump() if ctx.security_scan else {},
         "code_review":  ctx.code_review.model_dump() if ctx.code_review else {},
         "test_report":  ctx.test_report.model_dump() if ctx.test_report else {}},
        step=11,
    )


def _merge_test_security_findings(ctx: _PipelineCtx, test_sec: Any) -> None:
    """Merge test-file security findings into the main security_scan report."""
    if not test_sec.findings:
        return
    ctx.security_scan.findings.extend(test_sec.findings)
    ctx.security_scan.high_count   += test_sec.high_count
    ctx.security_scan.medium_count += test_sec.medium_count
    ctx.security_scan.low_count    += test_sec.low_count
    if test_sec.high_count > 0 and ctx.security_scan.recommendation == "APPROVED":
        ctx.security_scan.recommendation = "REVIEW_RECOMMENDED"
    ctx.log.info(
        f"Test file security scan: {len(test_sec.findings)} additional finding(s)",
        step=11,
    )


async def _step_11b_sec_test(ctx: _PipelineCtx) -> AsyncGenerator[dict, None]:
    """Step 11b — Security scan of generated test files (non-blocking)"""
    if ctx.test_report and ctx.test_report.test_files:
        try:
            test_sec = await security_agent.scan_files(
                files=ctx.test_report.test_files,
                mapping_name=ctx.conversion_output.mapping_name,
                target_stack=str(ctx.conversion_output.target_stack),
                label="test files",
            )
            _merge_test_security_findings(ctx, test_sec)
        except Exception as e:
            ctx.log.warning(f"Test file security scan failed (non-blocking): {e}", step=11)
    # This step is always non-blocking
    return
    yield  # make this an async generator


async def _step_12_gate3(ctx: _PipelineCtx) -> AsyncGenerator[dict, None]:
    """Step 12 — Gate 3 (yield AWAITING_CODE_REVIEW)"""
    ctx.log.state_change("testing", "awaiting_code_review", step=12)
    ctx.log.info("Pipeline paused — awaiting code review sign-off", step=12)
    ctx.log.finalize("awaiting_code_review", steps_completed=12)
    ctx.log.close()
    await fire_webhook(
        "gate_waiting", ctx.job_id, ctx.filename, 12, "awaiting_code_review",
        f"Gate 3 is waiting for code sign-off on '{ctx.filename}' — "
        f"coverage {ctx.test_report.coverage_pct}%, "
        f"{ctx.test_report.fields_covered} field(s) covered. Please approve or reject.",
        gate="Gate 3 — Code Sign-off",
    )
    await fire_email(
        "gate_waiting", ctx.job_id, ctx.filename, 12, "awaiting_code_review",
        f"Gate 3 is waiting for code sign-off — "
        f"coverage {ctx.test_report.coverage_pct}%, {ctx.test_report.fields_covered} field(s) covered. "
        f"Please approve or reject.",
        gate="gate3",
    )
    yield await ctx.emit(12, JobStatus.AWAITING_CODE_REVIEW,
                     "Awaiting code review sign-off. Pipeline paused.",
                     {
                         "test_report":   ctx.test_report.model_dump(),
                         "security_scan": ctx.security_scan.model_dump() if ctx.security_scan else None,
                     })


# ── STEP FUNCTIONS FOR resume_after_code_signoff() ───────────────────────────

async def _export_job_artifacts(ctx: _PipelineCtx, state: dict) -> None:
    """Export all job artifacts to disk (non-fatal on failure)."""
    try:
        job_record = await _db.get_job(ctx.job_id)
        if job_record:
            export_path = await export_job(ctx.job_id, job_record, state)
            if export_path:
                ctx.log.info("Artifacts written to disk: %s", export_path, step=12)
    except Exception as _export_exc:
        ctx.log.warning("Disk export failed (non-fatal): %s", _export_exc, step=12)


async def _open_github_pr(ctx: _PipelineCtx, state: dict) -> str | None:
    """Open a GitHub PR for generated code; return the PR URL or None (non-fatal)."""
    try:
        pr_url = await create_pull_request(ctx.job_id, state, ctx.filename)
        if pr_url:
            ctx.log.info("GitHub PR opened: %s", pr_url, step=12)
            await update_job(ctx.job_id, JobStatus.COMPLETE.value, 12, {"pr_url": pr_url})
        return pr_url
    except Exception as _pr_exc:
        ctx.log.warning("GitHub PR creation failed (non-fatal): %s", _pr_exc, step=12)
        return None


async def _step_12_final_export(ctx: _PipelineCtx, state: dict) -> AsyncGenerator[dict, None]:
    """Step 12 — Export artifacts + mark complete.

    IMPORTANT: the COMPLETE DB write (via ctx.emit) is the authoritative status
    transition.  Any failure in the optional export helpers (artifact zip,
    GitHub PR, webhook, email) must NOT prevent that write — otherwise a
    server restart between the approved sign-off and this point would leave
    the job permanently stuck at awaiting_code_review.
    """
    ctx.log.info("✅ Code review approved — pipeline complete", step=12)
    ctx.log.finalize("complete", steps_completed=12)
    ctx.log.close()

    pr_url: str | None = None
    export_note = ""

    try:
        await _export_job_artifacts(ctx, state)
    except Exception as _exp_exc:
        _orch_log.error(
            "Step 12 artifact export failed (job=%s) — marking COMPLETE anyway: %s",
            ctx.job_id, _exp_exc,
        )
        export_note = " (artifact export failed — see logs)"

    try:
        pr_url = await _open_github_pr(ctx, state)
    except Exception as _pr_exc:
        _orch_log.error(
            "Step 12 GitHub PR open failed (job=%s) — marking COMPLETE anyway: %s",
            ctx.job_id, _pr_exc,
        )

    pr_suffix = f" PR: {pr_url}" if pr_url else ""
    try:
        await fire_webhook(
            "job_complete", ctx.job_id, ctx.filename, 12, "complete",
            f"'{ctx.filename}' conversion complete — code approved and ready for export/deployment.{pr_suffix}",
        )
    except Exception:
        pass  # non-blocking

    try:
        await fire_email(
            "job_complete", ctx.job_id, ctx.filename, 12, "complete",
            f"Conversion complete — code approved and ready for export/deployment.{pr_suffix}",
        )
    except Exception:
        pass  # non-blocking

    yield await ctx.emit(12, JobStatus.COMPLETE,
                     "✅ Pipeline complete — code approved and ready for deployment."
                     + (f" PR opened: {pr_url}" if pr_url else "")
                     + export_note,
                     {"pr_url": pr_url} if pr_url else {})


# ── ORCHESTRATOR GENERATORS ───────────────────────────────────────────────────

async def _run_pipeline_steps(ctx: _PipelineCtx) -> AsyncGenerator[dict, None]:
    """Execute Steps 0–5 for run_pipeline."""
    async for e in _yield_all(
        _step_0_session_parse(ctx), _step_0b_cred_scan(ctx), _step_1_parse_xml(ctx),
    ):
        yield e
    if ctx.parse_report is None:
        return
    async for e in _run_pipeline_steps_tail(ctx):
        yield e


async def run_pipeline(job_id: str, filename: str = "unknown") -> AsyncGenerator[dict, None]:
    """
    Run Step 0 (v1.1 session/parameter parse) then Steps 1–4 automatically,
    then pause at Step 5 (human review) — or stop at Step 4 in docs_only mode.
    Yields progress dicts for SSE streaming to the UI.
    All steps are logged to logs/jobs/<job_id>.log.
    """
    log = JobLogger(job_id, filename)

    # Read pipeline_mode once from DB state (set at job creation by routes.py).
    # Default to "full" so existing jobs without the hint still work normally.
    _job_rec = await _db.get_job(job_id)
    _pipeline_mode: str = ((_job_rec or {}).get("state") or {}).get("pipeline_mode", "full")

    emit = _make_emit(job_id, log)
    ctx = _PipelineCtx(
        job_id=job_id, filename=filename, emit=emit, log=log,
        pipeline_mode=_pipeline_mode,
    )

    try:
        async for event in _run_pipeline_steps(ctx): yield event
    except EmitError as e:
        yield e.event


def _reconstruct_signoff_state(state: dict) -> dict:
    """Deserialise state for resume_after_signoff. Returns dict of schema objects."""
    from .models.schemas import ComplexityReport, ParseReport, VerificationReport, SessionParseReport
    parse_report     = ParseReport(**state["parse_report"])
    complexity       = ComplexityReport(**state["complexity"])
    _v               = state.get("verification")
    verification     = VerificationReport(**_v) if _v else None
    _spr             = state.get("session_parse_report")
    session_parse_report = SessionParseReport(**_spr) if _spr else None
    return {
        "parse_report":        parse_report,
        "complexity":          complexity,
        "documentation_md":    state.get("documentation_md", ""),
        "analyst_view_md":     state.get("analyst_view_md", ""),
        "analyst_gaps_md":     state.get("analyst_gaps_md", ""),
        "graph":               state["graph"],
        "verification":        verification,
        "s2t_state":           state.get("s2t", {}),
        "session_parse_report": session_parse_report,
    }


async def _resume_signoff_steps(ctx: _PipelineCtx, state: dict) -> AsyncGenerator[dict, None]:
    """Run Steps 6–9 after Gate 1 sign-off."""
    async for event in _step_6_assign_stack(ctx): yield event
    if ctx.stack_assignment is None: return
    async for event in _ckpt_chain_7(ctx, state): yield event


async def resume_after_signoff(job_id: str, state: dict, filename: str = "unknown") -> AsyncGenerator[dict, None]:
    """Called after human sign-off. Runs Steps 6–9."""
    import copy
    log  = JobLogger(job_id, filename)
    emit = _make_emit(job_id, log)
    state = copy.deepcopy(state)

    sign_off = state.get("sign_off", {})
    log.info(
        f"Resuming after sign-off — decision={sign_off.get('decision')}, "
        f"reviewer={sign_off.get('reviewer_name')}",
        step=5
    )

    # documentation_md is optional — jobs that pre-date its persistence default to ""
    _missing = _missing_keys(state, ("parse_report", "complexity", "graph"))
    if _missing:
        msg = f"State reconstruction failed — missing keys: {_missing}. Re-upload and re-run."
        log.step_failed(6, "State reconstruction", msg)
        log.finalize("failed", steps_completed=5)
        log.close()
        yield await emit(6, JobStatus.FAILED, msg, {"error": msg})
        return

    try:
        s = _reconstruct_signoff_state(state)
    except Exception as e:
        log.step_failed(6, "State reconstruction", str(e), exc_info=True)
        log.close()
        yield await emit(6, JobStatus.FAILED, f"State reconstruction failed: {e}", _err(e))
        return

    ctx = _PipelineCtx(
        job_id=job_id, filename=filename, emit=emit, log=log,
        parse_report=s["parse_report"],
        complexity=s["complexity"],
        documentation_md=s["documentation_md"],
        analyst_view_md=s.get("analyst_view_md", ""),
        analyst_gaps_md=s.get("analyst_gaps_md", ""),
        graph=s["graph"],
        verification=s["verification"],
        s2t_state=s["s2t_state"],
        session_parse_report=s["session_parse_report"],
    )

    try:
        async for event in _resume_signoff_steps(ctx, state): yield event
    except EmitError as e:
        yield e.event


def _unpack_security_fix_state(state: dict) -> tuple:
    """
    Unpack state keys needed for a security fix round.
    Returns (documentation_md, graph, stack_assignment, session_parse_report, prev_security_scan).
    Raises ValueError / KeyError / ValidationError on bad state.
    """
    from .models.schemas import StackAssignment, SessionParseReport, SecurityScanReport
    documentation_md = state.get("documentation_md", "")
    graph            = state["graph"]
    stack_assignment = StackAssignment(**state["stack_assignment"])
    _spr = state.get("session_parse_report")
    session_parse_report = SessionParseReport(**_spr) if _spr else None
    _sec = state.get("security_scan")
    prev_security_scan = SecurityScanReport(**_sec) if _sec else None
    return documentation_md, graph, stack_assignment, session_parse_report, prev_security_scan


async def _run_security_rescan(conversion_output, remediation_round: int, log) -> "SecurityScanReport":
    """Run security re-scan; return a fallback report on error (non-blocking)."""
    try:
        result = await security_agent.scan(
            conversion=conversion_output,
            mapping_name=conversion_output.mapping_name,
        )
        log.step_complete(
            8, f"Security Re-scan (round {remediation_round})",
            f"recommendation={result.recommendation}",
        )
        return result
    except Exception as e:
        log.warning(f"Security re-scan failed (non-blocking): {e}", step=8)
        from .models.schemas import SecurityScanReport
        return SecurityScanReport(
            mapping_name=conversion_output.mapping_name,
            target_stack=str(conversion_output.target_stack),
            recommendation="REVIEW_RECOMMENDED",
            claude_summary=f"Security re-scan could not complete: {e}. Manual review recommended.",
        )


async def _regenerate_conversion(
    state: dict, stack_assignment: Any, documentation_md: str, graph: dict,
    session_parse_report: Any, security_findings_to_fix: list,
    remediation_round: int, log: Any,
) -> Any:
    """
    Call conversion_agent.convert() with security findings injected as fix context.
    Returns the ConversionOutput or raises on error.
    """
    from .models.schemas import ComplexityReport as _CR
    complexity      = _deser(_CR, state.get("complexity"))
    accepted_fixes  = _collect_accepted_fixes(state)
    v_flags_fix     = _collect_v_flags_from_state(state)
    manifest_overrides = state.get("manifest_overrides")
    if manifest_overrides:
        log.info(f"Applying {len(manifest_overrides)} manifest override(s) from reviewer", step=7)
    conversion_output = await conversion_agent.convert(
        stack_assignment, documentation_md, graph,
        **_build_regen_convert_args(
            accepted_fixes, security_findings_to_fix, v_flags_fix,
            session_parse_report, manifest_overrides, complexity,
        ),
    )
    file_list   = list(conversion_output.files.keys())
    total_lines = _sum_newlines(conversion_output.files)
    log.info(
        f"Regeneration complete — {len(file_list)} file(s), ~{total_lines:,} lines",
        step=7, data={"files": file_list, "total_lines": total_lines},
    )
    return conversion_output


async def _represent_gate2(
    job_id: str, filename: str, state: dict,
    security_scan: Any, prev_security_scan: Any,
    remediation_round: int, max_rounds: int,
    log: Any, emit: Callable,
) -> AsyncGenerator[dict, None]:
    """Pause at Gate 2 with updated findings, or auto-proceed if scan is clean."""
    can_fix_again = remediation_round < max_rounds
    prev_rounds   = list(state.get("security_scan_rounds", []))
    if prev_security_scan:
        prev_rounds.append(prev_security_scan.model_dump())

    if security_scan.recommendation != "APPROVED":
        log.state_change("security_scanning", "awaiting_security_review", step=9)
        log.finalize("awaiting_security_review", steps_completed=9)
        log.close()
        fix_hint = "One more fix attempt available." if can_fix_again else "No further fix rounds — choose Approve, Acknowledge, or Fail."
        yield await emit(
            9, JobStatus.AWAITING_SEC_REVIEW,
            f"⚠️ Security findings remain after fix round {remediation_round}. {fix_hint} Pipeline paused at Step 9.",
            {
                "security_scan":        security_scan.model_dump(),
                "security_scan_rounds": prev_rounds,
                "remediation_round":    remediation_round,
                "can_request_fix":      can_fix_again,
            },
        )
    else:
        log.info(
            f"Security re-scan clean after fix round {remediation_round} — auto-proceeding to Step 10.",
            step=9,
        )
        from .models.schemas import SecuritySignOffRecord, SecurityReviewDecision
        auto_signoff = SecuritySignOffRecord(
            reviewer_name="system",
            reviewer_role="auto",
            review_date=_datetime.utcnow().isoformat() + "Z",
            decision=SecurityReviewDecision.APPROVED,
            notes=f"Auto-approved after clean re-scan (fix round {remediation_round})",
            remediation_round=remediation_round,
        )
        state["security_sign_off"] = auto_signoff.model_dump()
        state["security_scan"]     = security_scan.model_dump()
        async for event in resume_after_security_review(job_id, state, filename):
            yield event


async def resume_after_security_fix_request(
    job_id: str,
    state: dict,
    filename: str = "unknown",
    remediation_round: int = 1,
) -> AsyncGenerator[dict, None]:
    """
    Called after a REQUEST_FIX decision at Gate 2 (Step 9).
    Re-runs Steps 7 (conversion) and 8 (security scan) with the security findings
    injected as mandatory fix requirements, then re-pauses at Gate 2.
    Capped at MAX_REMEDIATION_ROUNDS to prevent infinite loops.
    """
    MAX_REMEDIATION_ROUNDS = 2
    import copy

    log  = JobLogger(job_id, filename)
    emit = _make_emit(job_id, log)
    state = copy.deepcopy(state)

    try:
        documentation_md, graph, stack_assignment, session_parse_report, prev_security_scan = (
            _unpack_security_fix_or_raise(state, ("documentation_md", "graph", "stack_assignment"))
        )
        security_findings_to_fix = _findings_to_fix(prev_security_scan)
        log.info(
            f"Security fix round {remediation_round}/{MAX_REMEDIATION_ROUNDS} — "
            f"re-running conversion with {len(security_findings_to_fix)} finding(s) as fix context",
            step=7,
        )
        log.step_start(7, f"Convert (Remediation Round {remediation_round})")
        log.state_change("awaiting_security_review", "converting", step=7)
        log.claude_call(7, f"code regeneration — security fix round {remediation_round}")
        yield await emit(
            7, JobStatus.CONVERTING,
            f"Regenerating code to address security findings (round {remediation_round} of {MAX_REMEDIATION_ROUNDS})…",
        )
        conversion_output = await _regenerate_conversion(
            state, stack_assignment, documentation_md, graph,
            session_parse_report, security_findings_to_fix, remediation_round, log,
        )
    except Exception as e:
        log.step_failed(7, "Fix round", str(e), exc_info=True)
        log.finalize("failed", steps_completed=7)
        log.close()
        yield await emit(7, JobStatus.FAILED, f"Error in security fix round: {e}", _err(e))
        return

    if not conversion_output.parse_ok:
        fail_msg = (
            f"Conversion output degraded during fix round {remediation_round} — "
            "JSON parse failed. Re-upload and retry."
        )
        log.step_failed(7, "Conversion (fix round)", fail_msg)
        log.finalize("failed", steps_completed=7)
        log.close()
        yield await emit(7, JobStatus.FAILED, f"⚠️ {fail_msg}",
                         {"conversion": conversion_output.model_dump()})
        return

    async for e in _fix_round_success_emit(conversion_output, remediation_round, log, emit):
        yield e

    # ── RE-RUN STEP 8 — SECURITY SCAN ────────────────────────────────────────
    log.step_start(8, f"Security Re-scan (round {remediation_round})")
    log.state_change("converting", "security_scanning", step=8)
    yield await emit(8, JobStatus.CONVERTING, "Re-scanning regenerated code for security issues…")

    security_scan = await _run_security_rescan(conversion_output, remediation_round, log)
    state["conversion"] = conversion_output.model_dump()

    # ── RE-PRESENT GATE 2 ─────────────────────────────────────────────────────
    async for event in _represent_gate2(
        job_id, filename, state, security_scan, prev_security_scan,
        remediation_round, MAX_REMEDIATION_ROUNDS, log, emit,
    ):
        yield event


def _reconstruct_security_review_state(state: dict) -> dict:
    """Deserialise state for resume_after_security_review. Returns dict of schema objects."""
    from .models.schemas import (
        ComplexityReport, ParseReport, VerificationReport, SessionParseReport,
        ConversionOutput, SecurityScanReport, StackAssignment,
    )
    _v   = state.get("verification")
    _spr = state.get("session_parse_report")
    _sec = state.get("security_scan")
    return {
        "parse_report":        ParseReport(**state["parse_report"]),
        "complexity":          ComplexityReport(**state["complexity"]),
        "documentation_md":    state.get("documentation_md", ""),
        "analyst_view_md":     state.get("analyst_view_md", ""),
        "analyst_gaps_md":     state.get("analyst_gaps_md", ""),
        "graph":               state["graph"],
        "verification":        VerificationReport(**_v) if _v else None,
        "s2t_state":           state.get("s2t", {}),
        "session_parse_report": SessionParseReport(**_spr) if _spr else None,
        "conversion_output":   ConversionOutput(**state["conversion"]),
        "stack_assignment":    StackAssignment(**state["stack_assignment"]),
        "security_scan":       SecurityScanReport(**_sec) if _sec else None,
    }


async def _resume_security_review_steps(ctx: _PipelineCtx, state: dict) -> AsyncGenerator[dict, None]:
    """Run Steps 10-12 after security review sign-off."""
    async for e in _yield_all(
        _step_10_review(ctx), _step_10b_reconcile(ctx), _step_11_tests(ctx, state),
        _step_11b_sec_test(ctx), _step_12_gate3(ctx),
    ):
        yield e


async def resume_after_security_review(job_id: str, state: dict, filename: str = "unknown") -> AsyncGenerator[dict, None]:
    """
    Called after human security review (Gate 2 — Step 9).
    Continues with Step 10 (Code Quality Review) through Step 12 (Code Sign-Off gate).
    """
    import copy
    log  = JobLogger(job_id, filename)
    emit = _make_emit(job_id, log)
    state = copy.deepcopy(state)

    # documentation_md is optional — defaults to "" for jobs pre-dating its persistence
    _missing = _missing_keys(state, ("graph", "stack_assignment", "conversion"))
    if _missing:
        msg = f"State reconstruction failed — missing keys: {_missing}. Re-upload and re-run."
        log.step_failed(10, "State reconstruction", msg)
        log.finalize("failed", steps_completed=9)
        log.close()
        yield await emit(10, JobStatus.FAILED, msg, {"error": msg})
        return

    sec_signoff  = state.get("security_sign_off", {})
    decision_str = sec_signoff.get("decision", "APPROVED")
    reviewer     = sec_signoff.get("reviewer_name", "unknown")
    log.info(
        f"Security review decision received — decision={decision_str}, reviewer={reviewer}",
        step=9,
    )

    try:
        s = _reconstruct_security_review_state(state)
    except Exception as e:
        log.step_failed(10, "State reconstruction", str(e), exc_info=True)
        log.close()
        yield await emit(10, JobStatus.FAILED, f"State reconstruction failed: {e}", _err(e))
        return

    xml_content_for_review = await _get_xml_or_empty(job_id)

    ctx = _PipelineCtx(
        job_id=job_id, filename=filename, emit=emit, log=log,
        parse_report=s["parse_report"],
        complexity=s["complexity"],
        documentation_md=s["documentation_md"],
        analyst_view_md=s.get("analyst_view_md", ""),
        analyst_gaps_md=s.get("analyst_gaps_md", ""),
        graph=s["graph"],
        verification=s["verification"],
        s2t_state=s["s2t_state"],
        session_parse_report=s["session_parse_report"],
        conversion_output=s["conversion_output"],
        stack_assignment=s["stack_assignment"],
        security_scan=s["security_scan"],
        xml_content=xml_content_for_review,
    )

    try:
        async for event in _resume_security_review_steps(ctx, state): yield event
    except EmitError as e:
        yield e.event


def _deserialize_checkpoint_schemas(s: dict) -> dict:
    """Instantiate schema objects from raw checkpoint state dict fields."""
    from .models.schemas import (
        ComplexityReport, ParseReport, VerificationReport,
        SessionParseReport, StackAssignment, ConversionOutput, SecurityScanReport,
    )
    return {
        "parse_report":         _deser(ParseReport,         s.get("parse_report")),
        "complexity":           _deser(ComplexityReport,    s.get("complexity")),
        "verification":         _deser(VerificationReport,  s.get("verification")),
        "session_parse_report": _deser(SessionParseReport,  s.get("session_parse_report")),
        "stack_assignment":     _deser(StackAssignment,     s.get("stack_assignment")),
        "conversion_output":    _deser(ConversionOutput,    s.get("conversion") or s.get("conversion_output")),
        "security_scan":        _deser(SecurityScanReport,  s.get("security_scan")),
    }


def _reconstruct_checkpoint_state(state: dict) -> dict:
    """Deserialise persisted state dicts back into schema objects for checkpoint resume."""
    import copy
    s = copy.deepcopy(state)
    schemas = _deserialize_checkpoint_schemas(s)
    return {
        **schemas,
        "documentation_md": s.get("documentation_md", ""),
        "analyst_view_md":  s.get("analyst_view_md", ""),
        "analyst_gaps_md":  s.get("analyst_gaps_md", ""),
        "graph":            s.get("graph", {}),
        "s2t_state":        s.get("s2t", {}),
        "pipeline_mode":    s.get("pipeline_mode", "full"),
    }


_ACTIONABLE_FLAG_TYPES = {
    "INCOMPLETE_LOGIC", "ENVIRONMENT_SPECIFIC_VALUE", "HIGH_RISK",
    "LINEAGE_GAP", "DEAD_LOGIC", "REVIEW_REQUIRED", "ORPHANED_PORT",
    "UNRESOLVED_PARAMETER", "UNRESOLVED_VARIABLE", "UNSUPPORTED_TRANSFORMATION",
}


def _collect_accepted_fixes(state: dict) -> list[str]:
    """Extract reviewer-approved fix strings from Gate 1 sign-off data."""
    sign_off_data = state.get("sign_off", {})
    fixes: list[str] = []
    for res in (sign_off_data.get("flags_accepted", []) + sign_off_data.get("flags_resolved", [])):
        if res.get("apply_fix") and res.get("fix_suggestion"):
            fix_text = res["fix_suggestion"].strip()
            if fix_text:
                fixes.append(fix_text)
    return fixes


def _collect_v_flags_from_ctx(ctx: "_PipelineCtx") -> list[dict]:
    """Extract actionable verification flags from pipeline context."""
    if not ctx.verification or not ctx.verification.flags:
        return []
    return [f.model_dump() for f in ctx.verification.flags if f.flag_type in _ACTIONABLE_FLAG_TYPES]


def _collect_v_flags_from_state(state: dict) -> list[dict]:
    """Extract actionable verification flags from raw state dict."""
    from .models.schemas import VerificationReport
    _v = state.get("verification")
    if not _v:
        return []
    try:
        vr = VerificationReport(**_v)
        return [f.model_dump() for f in vr.flags if f.flag_type in _ACTIONABLE_FLAG_TYPES]
    except Exception:
        return []


async def _dispatch_checkpoint_steps(
    step_number: int,
    ctx: "_PipelineCtx",
    state: dict,
) -> AsyncGenerator[dict, None]:
    """Run the correct sequence of pipeline steps for the given checkpoint."""
    _chains = {
        1:  _ckpt_chain_1,
        2:  _ckpt_chain_2,
        3:  _ckpt_chain_3,
        6:  _ckpt_chain_6,
        7:  _ckpt_chain_7,
        10: _ckpt_chain_10,
    }
    chain_fn = _chains.get(step_number)
    if chain_fn:
        async for e in chain_fn(ctx, state): yield e


async def _ckpt_chain_1b_onwards(ctx: "_PipelineCtx", state: dict) -> AsyncGenerator[dict, None]:
    """Run Steps 1b–5 (after parse succeeded)."""
    async for e in _step_1b_manifest(ctx): yield e
    async for e in _ckpt_chain_2(ctx, state): yield e


async def _ckpt_chain_1(ctx: "_PipelineCtx", state: dict) -> AsyncGenerator[dict, None]:
    async for e in _step_1_parse_xml(ctx): yield e
    if ctx.parse_report is None: return
    async for e in _ckpt_chain_1b_onwards(ctx, state): yield e


async def _ckpt_chain_2(ctx: "_PipelineCtx", state: dict) -> AsyncGenerator[dict, None]:
    async for e in _yield_all(
        _step_2_classify(ctx), _step_2b_s2t(ctx), _step_3_document(ctx),
        _step_4_verify(ctx), _step_5_gate1(ctx),
    ):
        yield e


async def _ckpt_chain_3(ctx: "_PipelineCtx", state: dict) -> AsyncGenerator[dict, None]:
    async for e in _step_3_document(ctx): yield e
    async for e in _step_4_verify(ctx): yield e
    async for e in _step_5_gate1(ctx): yield e


async def _ckpt_chain_6(ctx: "_PipelineCtx", state: dict) -> AsyncGenerator[dict, None]:
    async for e in _step_6_assign_stack(ctx): yield e
    if ctx.stack_assignment is None: return
    async for e in _ckpt_chain_7(ctx, state): yield e


async def _ckpt_chain_7(ctx: "_PipelineCtx", state: dict) -> AsyncGenerator[dict, None]:
    async for e in _step_7_convert(ctx, state): yield e
    if ctx.conversion_output is None: return
    async for e in _step_7b_smoke(ctx): yield e
    async for e in _step_8_sec_scan(ctx): yield e


async def _ckpt_chain_10(ctx: "_PipelineCtx", state: dict) -> AsyncGenerator[dict, None]:
    async for e in _resume_security_review_steps(ctx, state):
        yield e


async def resume_from_step(
    job_id: str,
    filename: str,
    step_number: int,
    state: dict,
) -> AsyncGenerator[dict, None]:
    """
    Checkpoint-based resume: restart the pipeline from a specific step without
    re-uploading the mapping XML.  Called after a Gate 1 or Gate 3 REJECTED
    decision that includes a ``restart_from_step`` value.

    Supported restart points:
      Gate 1 (REJECTED):
        1 — re-run Steps 1 → 1b → 2 → 2b → 3 → 4 → 5
        2 — re-run Steps 2 → 2b → 3 → 4 → 5
        3 — re-run Steps 3 → 4 → 5
      Gate 3 (REJECTED):
        6  — re-run Steps 6 → 7 → 7b → 8  (includes Gate 2 pause if findings)
        7  — re-run Steps 7 → 7b → 8
        10 — re-run Steps 10 → 10b → 11 → 11b → 12
    """
    log  = JobLogger(job_id, filename)
    emit = _make_emit(job_id, log)

    _valid_steps = {1, 2, 3, 6, 7, 10}
    if step_number not in _valid_steps:
        msg = f"Invalid restart step {step_number}. Valid restart steps are: {sorted(_valid_steps)}."
        log.step_failed(step_number, "Checkpoint resume", msg)
        log.close()
        yield await emit(step_number, JobStatus.FAILED, msg, {"error": msg})
        return

    log.info(f"Checkpoint resume requested — step_number={step_number}", step=step_number)

    try:
        s = _reconstruct_checkpoint_state(state)
    except Exception as e:
        log.step_failed(step_number, "State reconstruction", str(e), exc_info=True)
        log.close()
        yield await emit(step_number, JobStatus.FAILED, f"State reconstruction failed: {e}", _err(e))
        return

    xml_content_for_review = await _get_xml_or_empty(job_id)

    ctx = _PipelineCtx(
        job_id=job_id, filename=filename, emit=emit, log=log,
        pipeline_mode=s["pipeline_mode"],
        parse_report=s["parse_report"],
        complexity=s["complexity"],
        documentation_md=s["documentation_md"],
        graph=s["graph"],
        verification=s["verification"],
        s2t_state=s["s2t_state"],
        session_parse_report=s["session_parse_report"],
        stack_assignment=s["stack_assignment"],
        conversion_output=s["conversion_output"],
        security_scan=s["security_scan"],
        xml_content=xml_content_for_review,
    )

    try:
        async for event in _dispatch_checkpoint_steps(step_number, ctx, state):
            yield event
    except EmitError as e:
        yield e.event


async def resume_after_code_signoff(job_id: str, state: dict, filename: str = "unknown") -> AsyncGenerator[dict, None]:
    """
    Called after APPROVED code review sign-off.
    REGENERATE is handled entirely in routes.py (re-runs from Step 6).
    REJECTED  is handled entirely in routes.py (sets BLOCKED immediately).
    This function is only called for APPROVED decisions.
    """
    log = JobLogger(job_id, filename)

    async def emit(step: int, status: JobStatus, message: str, data: dict = None):
        patch = data or {}
        patch["pipeline_log"] = log.get_buffer()
        try:
            await update_job(job_id, status.value, step, patch)
        except Exception as _db_exc:
            # DB write failed — log it but still return the SSE event so the
            # client receives the status update even if persistence failed.
            _orch_log.error(
                "emit() DB write failed (job=%s step=%d status=%s): %s",
                job_id, step, status.value, _db_exc,
            )
        return {"step": step, "status": status.value, "message": message}

    code_signoff = state.get("code_sign_off", {})
    reviewer = code_signoff.get("reviewer_name", "unknown")

    ctx = _PipelineCtx(
        job_id=job_id,
        filename=filename,
        emit=emit,
        log=log,
    )

    async for event in _step_12_final_export(ctx, state): yield event
