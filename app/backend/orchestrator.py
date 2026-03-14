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
from .job_exporter import export_job
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


# ── STEP FUNCTIONS FOR run_pipeline() ────────────────────────────────────────

async def _step_0_session_parse(ctx: _PipelineCtx) -> AsyncGenerator[dict, None]:
    """Step 0 — Session & Parameter Parse (v1.1)"""
    ctx.log.step_start(0, "Session & Parameter Parse")
    yield await ctx.emit(0, JobStatus.PARSING, "Detecting file types and extracting session config…")

    session_files = await get_session_files(ctx.job_id)

    if session_files:
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
                    "parse_status":    ctx.session_parse_report.parse_status,
                    "cross_ref_status": ctx.session_parse_report.cross_ref.status,
                    "files": [f.model_dump() for f in ctx.session_parse_report.uploaded_files],
                    "unresolved_variables": ctx.session_parse_report.unresolved_variables,
                    "notes": ctx.session_parse_report.notes,
                },
            )
            if ctx.session_parse_report.parse_status == "FAILED":
                ctx.log.step_failed(0, "Session & Parameter Parse",
                                "; ".join(ctx.session_parse_report.cross_ref.issues
                                          + ctx.session_parse_report.notes))
                ctx.log.finalize("blocked", steps_completed=0)
                ctx.log.close()
                yield await ctx.emit(0, JobStatus.BLOCKED,
                                 "Step 0 failed — cross-reference validation did not pass. "
                                 "Check that the Workflow XML references the uploaded Mapping.",
                                 {"session_parse_report": ctx.session_parse_report.model_dump(),
                                  "error": "; ".join(ctx.session_parse_report.cross_ref.issues)})
                return
        except Exception as e:
            # Step 0 failure is non-blocking only when we have no workflow XML
            # (mapping-only mode).  If a workflow was explicitly uploaded we want
            # to halt so the user gets useful feedback rather than silent skipping.
            has_workflow = bool(session_files.get("workflow_xml_content"))
            ctx.log.warning(f"Step 0 error: {e}", step=0)
            if has_workflow:
                ctx.log.step_failed(0, "Session & Parameter Parse", str(e), exc_info=True)
                ctx.log.finalize("failed", steps_completed=0)
                ctx.log.close()
                yield await ctx.emit(0, JobStatus.FAILED, f"Step 0 error: {e}", _err(e))
                return
            # Mapping-only: fall through to Step 1 without session context

        ctx.log.step_complete(0, "Session & Parameter Parse",
                          ctx.session_parse_report.parse_status if ctx.session_parse_report else "SKIPPED")
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
    except Exception as e:
        ctx.log.step_failed(1, "Parse XML", str(e), exc_info=True)
        ctx.log.finalize("failed", steps_completed=1)
        ctx.log.close()
        yield await ctx.emit(1, JobStatus.FAILED, f"Parse error: {e}", _err(e))
        return

    if ctx.parse_report.parse_status == "FAILED":
        # Surface the first flag's detail as the human-readable error so the UI
        # shows something actionable rather than just "Blocked".
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
        yield await ctx.emit(1, JobStatus.BLOCKED, "Parse FAILED — see parse report",
                         {"parse_report": ctx.parse_report.model_dump(),
                          "error": user_msg})
        ctx.parse_report = None  # sentinel: pipeline should stop
        return

    # Guard: a "COMPLETE" parse with no mappings means the wrong file was uploaded
    # (e.g. a Workflow XML in the primary mapping slot). Fail fast with a clear message.
    if not ctx.parse_report.mapping_names:
        msg = (
            "No Mapping definitions found in the uploaded XML. "
            "If you uploaded a Workflow file as the primary mapping, please re-upload "
            "with the Mapping XML in the required field and the Workflow XML in the optional field."
        )
        ctx.log.step_failed(1, "Parse XML", msg)
        ctx.log.finalize("blocked", steps_completed=1)
        ctx.log.close()
        yield await ctx.emit(1, JobStatus.BLOCKED, "No mappings found",
                         {"parse_report": ctx.parse_report.model_dump(), "error": msg})
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


async def _step_3_document(ctx: _PipelineCtx) -> AsyncGenerator[dict, None]:
    """Step 3 — Generate documentation"""
    ctx.log.step_start(3, "Generate Documentation")
    ctx.log.state_change("classifying", "documenting", step=3)
    ctx.log.claude_call(3, "documentation generation")

    # G6: Check if this step should be skipped per org_config pipeline_options
    # NOTE: pattern_classification is determined later (gate review); use None here.
    #       complexity is already available as a local variable from step 2.
    _pattern = None
    _tier = ctx.complexity.tier.value if ctx.complexity else None
    if should_skip_step(3, pattern=_pattern, tier=_tier):
        _orch_log.info("Step 3 (documentation) skipped per pipeline_options config")
        ctx.log.info("Step 3 skipped per org_config pipeline_options", step=3)
        ctx.documentation_md = "(skipped per org config)"
        doc_truncated = False
        yield await ctx.emit(3, JobStatus.DOCUMENTING, "Documentation skipped per org config",
                         {"documentation_md": ctx.documentation_md, "doc_truncated": doc_truncated})
    else:
        yield await ctx.emit(3, JobStatus.DOCUMENTING, "Generating documentation — Pass 1 (transformations)…")

        # Run documentation as a background task so we can emit heartbeat SSE events
        # every 30 s while both passes run — prevents the client from seeing a frozen
        # spinner and keeps the SSE connection alive during long Claude calls.
        _doc_task = asyncio.create_task(
            documentation_agent.document(
                ctx.parse_report, ctx.complexity, ctx.graph, session_parse_report=ctx.session_parse_report
            )
        )
        _HEARTBEAT = 30  # seconds between progress SSE events
        _elapsed   = 0
        while not _doc_task.done():
            try:
                await asyncio.wait_for(asyncio.shield(_doc_task), timeout=_HEARTBEAT)
            except asyncio.TimeoutError:
                _elapsed += _HEARTBEAT
                _mins, _secs = divmod(_elapsed, 60)
                _elapsed_str = f"{_mins}m {_secs}s" if _mins else f"{_secs}s"
                _pass_hint = "Pass 2 (lineage)…" if _elapsed > 120 else "Pass 1 (transformations)…"
                yield await ctx.emit(
                    3, JobStatus.DOCUMENTING,
                    f"Generating documentation — {_pass_hint} ({_elapsed_str} elapsed)",
                )
                continue
            except Exception:
                # Non-timeout exception from the shielded task (e.g. API error).
                # Break out so _doc_task.result() re-raises it through the handler below.
                break
            break  # task completed normally

        try:
            documentation_md = _doc_task.result()
        except Exception as e:
            ctx.log.step_failed(3, "Generate Documentation", str(e), exc_info=True)
            ctx.log.finalize("failed", steps_completed=3)
            ctx.log.close()
            yield await ctx.emit(3, JobStatus.FAILED, f"Documentation error: {e}", _err(e))
            return

        # ── STEP 3 VALIDATION — check doc completeness ────────────────────────────
        # Truncation is a WARNING, not a hard failure.  The reviewer sees a prominent
        # flag at Gate 1 and decides whether the partial documentation is sufficient
        # to proceed.  Hard-failing here wastes all prior Claude calls and forces a
        # full re-upload — not worth it when the doc is usually 90%+ complete.
        doc_truncated = DOC_TRUNCATION_SENTINEL in documentation_md
        doc_missing_sentinel = DOC_COMPLETE_SENTINEL not in documentation_md and not doc_truncated

        if doc_truncated:
            ctx.log.warning(
                "Documentation was truncated (hit token limit on one pass). "
                "A HIGH warning flag will be surfaced to the reviewer at Gate 1.",
                step=3,
            )
        elif doc_missing_sentinel:
            ctx.log.warning(
                "Documentation completion marker missing — output may be incomplete. "
                "A HIGH warning flag will be surfaced to the reviewer at Gate 1.",
                step=3,
            )

        # Strip sentinels so they never appear in UI, reports, or agent prompts.
        documentation_md = (
            documentation_md
            .replace(DOC_COMPLETE_SENTINEL, "")
            .replace(DOC_TRUNCATION_SENTINEL, "")
            .strip()
        )

        doc_len = len(documentation_md)
        ctx.log.info(f"Documentation generated — {doc_len} chars (truncated={doc_truncated})",
                 step=3, data={"doc_chars": doc_len, "doc_truncated": doc_truncated})
        ctx.log.step_complete(3, "Generate Documentation", f"{doc_len:,} chars")
        ctx.documentation_md = documentation_md
        # Expose doc_truncated and doc_missing_sentinel to next step via ctx
        ctx._doc_truncated = doc_truncated
        ctx._doc_missing_sentinel = doc_missing_sentinel
        yield await ctx.emit(3, JobStatus.DOCUMENTING,
                         "Documentation complete" + (" (truncated — reviewer notified)" if doc_truncated else ""),
                         {"documentation_md": ctx.documentation_md, "doc_truncated": doc_truncated})


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

        # If documentation was truncated, inject a prominent flag so the reviewer
        # sees it at Gate 1 and can decide whether to proceed or re-upload.
        if doc_truncated or doc_missing_sentinel:
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

        ctx.log.info(
            f"Verification complete — status={ctx.verification.overall_status}, "
            f"checks={ctx.verification.total_checks}, passed={ctx.verification.total_passed}, "
            f"failed={ctx.verification.total_failed}, flags={ctx.verification.total_flags}, "
            f"blocked={ctx.verification.conversion_blocked}",
            step=4,
            data={
                "overall_status": ctx.verification.overall_status,
                "total_checks": ctx.verification.total_checks,
                "total_passed": ctx.verification.total_passed,
                "total_failed": ctx.verification.total_failed,
                "total_flags": ctx.verification.total_flags,
                "conversion_blocked": ctx.verification.conversion_blocked,
                "blocking_reasons": ctx.verification.blocked_reasons,
                "flags": [
                    {"type": f.flag_type, "severity": f.severity,
                     "blocking": f.blocking, "location": f.location}
                    for f in ctx.verification.flags
                ],
            }
        )
        if ctx.verification.conversion_blocked:
            ctx.log.warning(
                f"Conversion BLOCKED — {len(ctx.verification.blocked_reasons)} blocking issue(s): "
                + "; ".join(ctx.verification.blocked_reasons),
                step=4
            )
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


async def _step_5_gate1(ctx: _PipelineCtx) -> AsyncGenerator[dict, None]:
    """Step 5 — Gate 1 (docs-only mode exit or Gate 1 pause for human review)"""
    # ── DOCS-ONLY MODE EXIT ────────────────────────────────────
    # When pipeline_mode == "docs_only" we stop here and mark the job COMPLETE.
    # The documentation, verification report, and all artefacts produced by
    # steps 1-4 are exported to the output folder; no code conversion is run.
    if ctx.pipeline_mode == "docs_only":
        ctx.log.state_change("verifying", "complete", step=4)
        ctx.log.finalize("complete", steps_completed=4)
        ctx.log.close()
        # Export artefacts (docs, verification report, etc.) to output folder
        try:
            from .job_exporter import export_job as _export
            _final_state = (await _db.get_job(ctx.job_id) or {}).get("state") or {}
            await _export(ctx.job_id, {"job_id": ctx.job_id, "filename": ctx.filename,
                                   "status": JobStatus.COMPLETE.value,
                                   "current_step": 4}, _final_state)
        except Exception as _exp_exc:
            ctx.log.warning(f"Docs-only export warning (non-fatal): {_exp_exc}")
        yield await ctx.emit(4, JobStatus.COMPLETE,
                         "Documentation complete. Stopped after Step 4 (docs-only mode).")
        return

    # ── STEP 5 — AWAIT HUMAN REVIEW ───────────────────────────
    ctx.log.state_change("verifying", "awaiting_review", step=5)
    ctx.log.info("Pipeline paused — awaiting human review and sign-off", step=5)
    # Note flags count for registry
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


async def _step_7_convert(ctx: _PipelineCtx, state: dict) -> AsyncGenerator[dict, None]:
    """Step 7 — Code generation"""
    # Collect reviewer-approved fixes from Step 5 sign-off
    accepted_fixes: list[str] = []
    sign_off_data = state.get("sign_off", {})
    all_resolutions = (
        sign_off_data.get("flags_accepted", []) +
        sign_off_data.get("flags_resolved", [])
    )
    for res in all_resolutions:
        if res.get("apply_fix") and res.get("fix_suggestion"):
            fix_text = res["fix_suggestion"].strip()
            if fix_text:
                accepted_fixes.append(fix_text)

    if accepted_fixes:
        ctx.log.info(
            f"Injecting {len(accepted_fixes)} reviewer-approved fix(es) into conversion prompt",
            step=7,
            data={"accepted_fixes": accepted_fixes},
        )

    ctx.log.step_start(7, f"Convert to {ctx.stack_assignment.assigned_stack.value}")
    ctx.log.state_change("assigning_stack", "converting", step=7)
    ctx.log.claude_call(7, f"code generation ({ctx.stack_assignment.assigned_stack.value})")
    yield await ctx.emit(7, JobStatus.CONVERTING,
                     f"Converting to {ctx.stack_assignment.assigned_stack.value} (Claude)…")
    # Gather verification flags so the conversion agent can auto-handle them in code
    v_flags_raw = []
    if ctx.verification and ctx.verification.flags:
        v_flags_raw = [f.model_dump() for f in ctx.verification.flags]
        actionable_flag_types = {
            "INCOMPLETE_LOGIC", "ENVIRONMENT_SPECIFIC_VALUE", "HIGH_RISK",
            "LINEAGE_GAP", "DEAD_LOGIC", "REVIEW_REQUIRED", "ORPHANED_PORT",
            "UNRESOLVED_PARAMETER", "UNRESOLVED_VARIABLE", "UNSUPPORTED_TRANSFORMATION",
        }
        v_flags_raw = [f for f in v_flags_raw if f.get("flag_type") in actionable_flag_types]
        if v_flags_raw:
            ctx.log.info(
                f"Injecting {len(v_flags_raw)} verification flag(s) into conversion prompt "
                "for auto-handling",
                step=7,
                data={"flag_types": [f["flag_type"] for f in v_flags_raw]},
            )

    # Load manifest overrides if the reviewer submitted an annotated manifest xlsx
    manifest_overrides: list[dict] | None = None
    _manifest_overrides_raw = state.get("manifest_overrides")
    if _manifest_overrides_raw:
        manifest_overrides = _manifest_overrides_raw
        ctx.log.info(
            f"Applying {len(manifest_overrides)} manifest override(s) from reviewer",
            step=7,
        )

    try:
        ctx.conversion_output = await conversion_agent.convert(
            ctx.stack_assignment, ctx.documentation_md, ctx.graph,
            accepted_fixes=accepted_fixes or None,
            session_parse_report=ctx.session_parse_report,
            verification_flags=v_flags_raw or None,
            manifest_overrides=manifest_overrides,
            complexity_report=ctx.complexity,
        )
        file_list = list(ctx.conversion_output.files.keys())
        total_lines = sum(c.count("\n") for c in ctx.conversion_output.files.values())
        ctx.log.info(
            f"Conversion complete — {len(file_list)} file(s), ~{total_lines:,} lines",
            step=7,
            data={
                "files": file_list,
                "total_lines": total_lines,
                "notes": ctx.conversion_output.notes,
            }
        )
        if ctx.conversion_output.notes:
            for note in ctx.conversion_output.notes:
                ctx.log.warning(f"Conversion note: {note}", step=7)

        if not ctx.conversion_output.parse_ok:
            ctx.log.warning(
                f"Conversion output was DEGRADED — JSON parse failed; "
                f"{len(file_list)} file(s) recovered via fallback. "
                "Files may be partial or raw. Review before use.",
                step=7,
            )
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

    if ctx.conversion_output.parse_ok:
        file_list = list(ctx.conversion_output.files.keys())
        total_lines = sum(c.count("\n") for c in ctx.conversion_output.files.values())
        ctx.log.step_complete(7, "Conversion",
                          f"{len(file_list)} file(s), ~{total_lines:,} lines")
        yield await ctx.emit(7, JobStatus.CONVERTING, "Conversion complete",
                         {"conversion": ctx.conversion_output.model_dump()})
    else:
        # JSON parse failed — recovered files may be partial/truncated.
        # Step 8 review on degraded output would be meaningless, so halt here.
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
        return


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
        smoke_failures = [r for r in smoke_results if not r.passed]
        if smoke_failures:
            summary = format_smoke_results(smoke_results)
            ctx.log.warning(
                f"Smoke execution: {len(smoke_failures)}/{len(smoke_results)} file(s) failed "
                f"compilation/structural checks. Details:\n{summary}",
                step=7,
            )
            # Inject as HIGH verification flags so reviewers see them at Gate 3
            smoke_flags = [
                {
                    "flag_type": "SMOKE_CHECK_FAILED",
                    "severity": "HIGH",
                    "description": f"{r.filename}: {r.tool} check failed — {r.detail}",
                    "recommendation": "Review the generated file for syntax errors before running.",
                    "auto_fix_suggestion": None,
                }
                for r in smoke_failures
            ]
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

    # ── STEP 9 — HUMAN SECURITY REVIEW GATE ─────────────────────────────────
    # Pause for human review whenever findings exist (REVIEW_RECOMMENDED or REQUIRES_FIXES).
    # Only auto-proceed when the scan is fully clean (APPROVED).
    if ctx.security_scan and ctx.security_scan.recommendation != "APPROVED":
        ctx.log.state_change("security_scanning", "awaiting_security_review", step=9)
        ctx.log.info(
            f"Security scan found issues (recommendation={ctx.security_scan.recommendation}) — "
            f"pausing for human review at Step 9.",
            step=9,
        )
        ctx.log.finalize("awaiting_security_review", steps_completed=9)
        ctx.log.close()
        finding_count = len(ctx.security_scan.findings) if ctx.security_scan and ctx.security_scan.findings else 0
        await fire_webhook(
            "gate_waiting", ctx.job_id, ctx.filename, 9, "awaiting_security_review",
            f"Gate 2 is waiting for security review on '{ctx.filename}' — "
            f"{finding_count} finding(s), recommendation: {ctx.security_scan.recommendation if ctx.security_scan else 'unknown'}. "
            f"Please review and approve, acknowledge, or fail.",
            gate="Gate 2 — Security Review",
        )
        await fire_email(
            "gate_waiting", ctx.job_id, ctx.filename, 9, "awaiting_security_review",
            f"Gate 2 is waiting for security review — {finding_count} finding(s), "
            f"recommendation: {ctx.security_scan.recommendation if ctx.security_scan else 'unknown'}. "
            f"Please approve, acknowledge, or fail.",
            gate="gate2",
        )
        yield await ctx.emit(9, JobStatus.AWAITING_SEC_REVIEW,
                         "⚠️ Security findings require review. Pipeline paused at Step 9 — "
                         "please review and decide to proceed, acknowledge, or fail the job.",
                         {"security_scan": ctx.security_scan.model_dump()})
    else:
        # Clean scan — skip the human gate, continue automatically
        ctx.log.info("Security scan clean (APPROVED) — auto-proceeding to Step 10.", step=9)


# ── STEP FUNCTIONS FOR resume_after_security_review() ────────────────────────

async def _step_10_review(ctx: _PipelineCtx) -> AsyncGenerator[dict, None]:
    """Step 10 — Code quality review"""
    ctx.log.step_start(10, "Code Quality Review")
    ctx.log.state_change("awaiting_security_review", "reviewing", step=10)
    ctx.log.claude_call(10, "static code review")
    yield await ctx.emit(10, JobStatus.REVIEWING,
                     "Running code quality review (Claude)…",
                     {"security_scan": ctx.security_scan.model_dump() if ctx.security_scan else None})

    # All needed variables are in scope from earlier steps (or restored from state).
    # verification may be a VerificationReport object or None.
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
        rec = ctx.code_review.recommendation
        eq  = ctx.code_review.equivalence_report
        ctx.log.info(
            f"Code review complete — {ctx.code_review.total_passed}/{len(ctx.code_review.checks)} checks passed, "
            f"recommendation: {rec}"
            + (f"; equivalence: {eq.total_verified}V/{eq.total_needs_review}NR/{eq.total_mismatches}M" if eq else ""),
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
    except Exception as e:
        ctx.log.warning(f"Code review failed (non-blocking): {e}", step=10)
        from .models.schemas import CodeReviewReport
        ctx.code_review = CodeReviewReport(
            mapping_name=ctx.conversion_output.mapping_name,
            target_stack=ctx.conversion_output.target_stack.value,
            checks=[],
            total_passed=0,
            total_failed=0,
            recommendation="REVIEW_RECOMMENDED",
            summary=f"Automated review could not complete: {e}. Please review the converted code manually.",
            parse_degraded=not ctx.conversion_output.parse_ok,
        )
        ctx.log.step_complete(10, "Code Quality Review", "SKIPPED (error)")


async def _step_10b_reconcile(ctx: _PipelineCtx) -> AsyncGenerator[dict, None]:
    """Step 10b — Structural reconciliation (non-blocking)"""
    # Validates that every target field from the S2T mapping appears in the
    # generated code.  No live database required — pure text analysis.
    # Non-blocking: the reconciliation_report is stored in job state and shown
    # at Gate 3 alongside the code review result.
    reconciliation_report = None
    try:
        s2t_field_list = None
        if ctx.s2t_state and isinstance(ctx.s2t_state.get("fields"), list):
            s2t_field_list = [
                f.get("target_field") or f.get("name") or ""
                for f in ctx.s2t_state["fields"]
                if isinstance(f, dict)
            ]
            s2t_field_list = [f for f in s2t_field_list if f]
        reconciliation_report = generate_reconciliation_report(
            parse_report=ctx.parse_report,
            conversion_output=ctx.conversion_output,
            s2t_field_list=s2t_field_list or [],
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


async def _step_11_tests(ctx: _PipelineCtx, state: dict) -> AsyncGenerator[dict, None]:
    """Step 11 — Test generation & coverage check"""
    ctx.log.step_start(11, "Test Generation & Coverage Check")
    ctx.log.state_change("reviewing", "testing", step=11)

    reconciliation_report = getattr(ctx, "_reconciliation_report", None)
    verification_dict = (ctx.verification.model_dump()
                         if ctx.verification and hasattr(ctx.verification, "model_dump")
                         else {})

    # G6: Check if this step should be skipped per org_config pipeline_options
    _pattern = state.get("pattern_classification", {}).get("pattern")
    _tier = state.get("complexity", {}).get("tier")
    if should_skip_step(11, pattern=_pattern, tier=_tier):
        _orch_log.info("Step 11 (test generation) skipped per pipeline_options config")
        ctx.log.info("Step 11 skipped per org_config pipeline_options", step=11)
        ctx.test_report = None
    else:
        yield await ctx.emit(11, JobStatus.TESTING, "Generating tests and checking field coverage…",
                         {
                             "code_review": ctx.code_review.model_dump(),
                             "reconciliation": reconciliation_report.model_dump() if reconciliation_report else None,
                         })

        try:
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
            if ctx.test_report.notes:
                for note in ctx.test_report.notes:
                    ctx.log.info(f"Test note: {note}", step=11)
            ctx.log.step_complete(11, "Test Generation",
                              f"{ctx.test_report.coverage_pct}% coverage, {len(ctx.test_report.test_files)} file(s)")
        except Exception as e:
            ctx.log.warning(f"Test generation failed (non-blocking): {e}", step=11)
            from .models.schemas import TestReport as TR
            ctx.test_report = TR(
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
                notes=[f"Test generation failed (non-blocking): {e}"],
            )
            ctx.log.step_complete(11, "Test Generation", "SKIPPED (error)")


async def _step_11b_sec_test(ctx: _PipelineCtx) -> AsyncGenerator[dict, None]:
    """Step 11b — Security scan of generated test files (non-blocking)"""
    # Test code can contain hardcoded credentials and real-looking connection strings.
    if ctx.test_report and ctx.test_report.test_files:
        try:
            test_sec = await security_agent.scan_files(
                files=ctx.test_report.test_files,
                mapping_name=ctx.conversion_output.mapping_name,
                target_stack=str(ctx.conversion_output.target_stack),
                label="test files",
            )
            if test_sec.findings:
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

async def _step_12_final_export(ctx: _PipelineCtx, state: dict) -> AsyncGenerator[dict, None]:
    """Step 12 — Export artifacts + mark complete"""
    ctx.log.info("✅ Code review approved — pipeline complete", step=12)
    ctx.log.finalize("complete", steps_completed=12)
    ctx.log.close()

    # ── Export all job artifacts to disk (non-fatal if it fails) ─────────
    try:
        job_record = await _db.get_job(ctx.job_id)
        if job_record:
            export_path = await export_job(ctx.job_id, job_record, state)
            if export_path:
                ctx.log.info("Artifacts written to disk: %s", export_path, step=12)
    except Exception as _export_exc:
        ctx.log.warning("Disk export failed (non-fatal): %s", _export_exc, step=12)

    # ── Open GitHub PR with generated code (non-fatal if it fails) ────────
    pr_url: str | None = None
    try:
        pr_url = await create_pull_request(ctx.job_id, state, ctx.filename)
        if pr_url:
            ctx.log.info("GitHub PR opened: %s", pr_url, step=12)
            await update_job(ctx.job_id, JobStatus.COMPLETE.value, 12, {"pr_url": pr_url})
    except Exception as _pr_exc:
        ctx.log.warning("GitHub PR creation failed (non-fatal): %s", _pr_exc, step=12)

    await fire_webhook(
        "job_complete", ctx.job_id, ctx.filename, 12, "complete",
        f"'{ctx.filename}' conversion complete — code approved and ready for export/deployment."
        + (f" PR: {pr_url}" if pr_url else ""),
    )
    await fire_email(
        "job_complete", ctx.job_id, ctx.filename, 12, "complete",
        f"Conversion complete — code approved and ready for export/deployment."
        + (f" PR: {pr_url}" if pr_url else ""),
    )
    yield await ctx.emit(12, JobStatus.COMPLETE,
                     "✅ Pipeline complete — code approved and ready for deployment."
                     + (f" PR opened: {pr_url}" if pr_url else ""),
                     {"pr_url": pr_url} if pr_url else {})


# ── ORCHESTRATOR GENERATORS ───────────────────────────────────────────────────

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

    async def emit(step: int, status: JobStatus, message: str, data: dict = None):
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
                break   # success — exit retry loop
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

    ctx = _PipelineCtx(
        job_id=job_id, filename=filename, emit=emit, log=log,
        pipeline_mode=_pipeline_mode,
    )

    try:
        async for event in _step_0_session_parse(ctx): yield event
        async for event in _step_0b_cred_scan(ctx): yield event
        async for event in _step_1_parse_xml(ctx): yield event
        if ctx.parse_report is None: return  # step stopped pipeline
        async for event in _step_1b_manifest(ctx): yield event
        async for event in _step_2_classify(ctx): yield event
        async for event in _step_2b_s2t(ctx): yield event
        async for event in _step_3_document(ctx): yield event
        async for event in _step_4_verify(ctx): yield event
        async for event in _step_5_gate1(ctx): yield event
    except EmitError as e:
        yield e.event


async def resume_after_signoff(job_id: str, state: dict, filename: str = "unknown") -> AsyncGenerator[dict, None]:
    """Called after human sign-off. Runs Steps 6–9."""
    log = JobLogger(job_id, filename)

    async def emit(step: int, status: JobStatus, message: str, data: dict = None):
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

    import copy
    from .models.schemas import ComplexityReport, ParseReport

    # GAP #2 — deep copy state so mutations during this resume don't corrupt
    # the DB-persisted dict if the task is interrupted mid-run.
    state = copy.deepcopy(state)

    sign_off = state.get("sign_off", {})
    log.info(
        f"Resuming after sign-off — decision={sign_off.get('decision')}, "
        f"reviewer={sign_off.get('reviewer_name')}",
        step=5
    )

    # GAP #6 — validate required state keys before touching anything
    _required = ("parse_report", "complexity", "documentation_md", "graph")
    _missing  = [k for k in _required if not state.get(k)]
    if _missing:
        msg = f"State reconstruction failed — missing keys: {_missing}. Re-upload and re-run."
        log.step_failed(6, "State reconstruction", msg)
        log.finalize("failed", steps_completed=5)
        log.close()
        yield await emit(6, JobStatus.FAILED, msg, {"error": msg})
        return

    try:
        parse_report     = ParseReport(**state["parse_report"])
        complexity       = ComplexityReport(**state["complexity"])
        documentation_md = state["documentation_md"]
        graph            = state["graph"]
        # Needed for Step 8 review
        from .models.schemas import VerificationReport, SessionParseReport
        _v = state.get("verification")
        verification     = VerificationReport(**_v) if _v else None
        s2t_state        = state.get("s2t", {})
        _spr = state.get("session_parse_report")
        session_parse_report = SessionParseReport(**_spr) if _spr else None
    except Exception as e:
        log.step_failed(6, "State reconstruction", str(e), exc_info=True)
        log.close()
        yield await emit(6, JobStatus.FAILED, f"State reconstruction failed: {e}", _err(e))
        return

    ctx = _PipelineCtx(
        job_id=job_id,
        filename=filename,
        emit=emit,
        log=log,
        parse_report=parse_report,
        complexity=complexity,
        documentation_md=documentation_md,
        graph=graph,
        verification=verification,
        s2t_state=s2t_state,
        session_parse_report=session_parse_report,
    )

    try:
        async for event in _step_6_assign_stack(ctx): yield event
        if ctx.stack_assignment is None: return  # step stopped pipeline

        async for event in _step_7_convert(ctx, state): yield event
        if ctx.conversion_output is None: return  # step stopped pipeline

        async for event in _step_7b_smoke(ctx): yield event
        async for event in _step_8_sec_scan(ctx): yield event

        # If security scan paused the pipeline, step 8 already yielded the gate event
        # and the generator ends naturally here (no further steps to run).
    except EmitError as e:
        yield e.event


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

    log = JobLogger(job_id, filename)

    async def emit(step: int, status: JobStatus, message: str, data: dict = None):
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

    import copy
    from .models.schemas import (
        ComplexityReport, ParseReport, SessionParseReport,
        StackAssignment, ConversionOutput, SecurityScanReport,
    )

    # GAP #2 — deep copy, GAP #6 — validate
    state = copy.deepcopy(state)
    _required = ("documentation_md", "graph", "stack_assignment")
    _missing  = [k for k in _required if not state.get(k)]
    if _missing:
        msg = f"State reconstruction failed — missing keys: {_missing}. Re-upload and re-run."
        log.step_failed(7, "State reconstruction", msg)
        log.finalize("failed", steps_completed=7)
        log.close()
        yield await emit(7, JobStatus.FAILED, msg, {"error": msg})
        return

    try:
        documentation_md  = state["documentation_md"]
        graph             = state["graph"]
        stack_assignment  = StackAssignment(**state["stack_assignment"])
        _spr = state.get("session_parse_report")
        session_parse_report = SessionParseReport(**_spr) if _spr else None
        _sec = state.get("security_scan")
        prev_security_scan = SecurityScanReport(**_sec) if _sec else None
    except Exception as e:
        log.step_failed(7, "State reconstruction (fix round)", str(e), exc_info=True)
        log.close()
        yield await emit(7, JobStatus.FAILED, f"State reconstruction failed: {e}", _err(e))
        return

    # Collect the findings that the reviewer asked to fix
    security_findings_to_fix = []
    if prev_security_scan:
        security_findings_to_fix = [
            f.model_dump() for f in prev_security_scan.findings
        ]

    log.info(
        f"Security fix round {remediation_round}/{MAX_REMEDIATION_ROUNDS} — "
        f"re-running conversion with {len(security_findings_to_fix)} finding(s) as fix context",
        step=7,
    )

    # ── RE-RUN STEP 7 — CONVERT (with security findings as fix context) ──────
    log.step_start(7, f"Convert (Remediation Round {remediation_round})")
    log.state_change("awaiting_security_review", "converting", step=7)
    log.claude_call(7, f"code regeneration — security fix round {remediation_round}")
    yield await emit(
        7, JobStatus.CONVERTING,
        f"Regenerating code to address security findings (round {remediation_round} of {MAX_REMEDIATION_ROUNDS})…",
    )

    # Carry forward any Gate 1 accepted fixes
    accepted_fixes: list[str] = []
    sign_off_data = state.get("sign_off", {})
    for res in (sign_off_data.get("flags_accepted", []) + sign_off_data.get("flags_resolved", [])):
        if res.get("apply_fix") and res.get("fix_suggestion"):
            fix_text = res["fix_suggestion"].strip()
            if fix_text:
                accepted_fixes.append(fix_text)

    # Carry verification flags forward into the fix round as well
    from .models.schemas import VerificationReport
    _v = state.get("verification")
    _verification_fix = VerificationReport(**_v) if _v else None
    v_flags_fix: list[dict] = []
    if _verification_fix and _verification_fix.flags:
        actionable_flag_types = {
            "INCOMPLETE_LOGIC", "ENVIRONMENT_SPECIFIC_VALUE", "HIGH_RISK",
            "LINEAGE_GAP", "DEAD_LOGIC", "REVIEW_REQUIRED", "ORPHANED_PORT",
            "UNRESOLVED_PARAMETER", "UNRESOLVED_VARIABLE", "UNSUPPORTED_TRANSFORMATION",
        }
        v_flags_fix = [
            f.model_dump() for f in _verification_fix.flags
            if f.flag_type in actionable_flag_types
        ]

    # Extract manifest overrides from state if present (from reviewer feedback)
    manifest_overrides: list[dict] | None = None
    _manifest_overrides_raw = state.get("manifest_overrides")
    if _manifest_overrides_raw:
        manifest_overrides = _manifest_overrides_raw
        log.info(
            f"Applying {len(manifest_overrides)} manifest override(s) from reviewer",
            step=7,
        )

    # complexity is needed for convert() — restore from state
    from .models.schemas import ComplexityReport as _CR
    _c = state.get("complexity")
    complexity = _CR(**_c) if _c else None

    try:
        conversion_output = await conversion_agent.convert(
            stack_assignment,
            documentation_md,
            graph,
            accepted_fixes=accepted_fixes or None,
            security_findings=security_findings_to_fix or None,
            session_parse_report=session_parse_report,
            verification_flags=v_flags_fix or None,
            manifest_overrides=manifest_overrides,
            complexity_report=complexity,
        )
        file_list   = list(conversion_output.files.keys())
        total_lines = sum(c.count("\n") for c in conversion_output.files.values())
        log.info(
            f"Regeneration complete — {len(file_list)} file(s), ~{total_lines:,} lines",
            step=7,
            data={"files": file_list, "total_lines": total_lines},
        )
    except Exception as e:
        log.step_failed(7, "Conversion (fix round)", str(e), exc_info=True)
        log.finalize("failed", steps_completed=7)
        log.close()
        yield await emit(7, JobStatus.FAILED, f"Conversion error during fix round: {e}", _err(e))
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

    log.step_complete(7, f"Conversion (round {remediation_round})",
                      f"{len(file_list)} file(s), ~{total_lines:,} lines")
    yield await emit(7, JobStatus.CONVERTING, f"Regeneration round {remediation_round} complete",
                     {"conversion": conversion_output.model_dump()})

    # ── RE-RUN STEP 8 — SECURITY SCAN ────────────────────────────────────────
    log.step_start(8, f"Security Re-scan (round {remediation_round})")
    log.state_change("converting", "security_scanning", step=8)
    yield await emit(8, JobStatus.CONVERTING, "Re-scanning regenerated code for security issues…")

    try:
        security_scan = await security_agent.scan(
            conversion=conversion_output,
            mapping_name=conversion_output.mapping_name,
        )
        log.step_complete(
            8, f"Security Re-scan (round {remediation_round})",
            f"recommendation={security_scan.recommendation}",
        )
    except Exception as e:
        log.warning(f"Security re-scan failed (non-blocking): {e}", step=8)
        from .models.schemas import SecurityScanReport
        security_scan = SecurityScanReport(
            mapping_name=conversion_output.mapping_name,
            target_stack=str(conversion_output.target_stack),
            recommendation="REVIEW_RECOMMENDED",
            claude_summary=f"Security re-scan could not complete: {e}. Manual review recommended.",
        )

    # ── RE-PRESENT GATE 2 ─────────────────────────────────────────────────────
    can_request_fix_again = remediation_round < MAX_REMEDIATION_ROUNDS

    # Archive the previous scan before overwriting so the UI can show what changed
    prev_rounds = list(state.get("security_scan_rounds", []))
    if prev_security_scan:
        prev_rounds.append(prev_security_scan.model_dump())

    if security_scan.recommendation != "APPROVED":
        log.state_change("security_scanning", "awaiting_security_review", step=9)
        log.finalize("awaiting_security_review", steps_completed=9)
        log.close()
        yield await emit(
            9, JobStatus.AWAITING_SEC_REVIEW,
            f"⚠️ Security findings remain after fix round {remediation_round}. "
            f"{'One more fix attempt available.' if can_request_fix_again else 'No further fix rounds — choose Approve, Acknowledge, or Fail.'} "
            "Pipeline paused at Step 9.",
            {
                "security_scan":        security_scan.model_dump(),
                "security_scan_rounds": prev_rounds,
                "remediation_round":    remediation_round,
                "can_request_fix":      can_request_fix_again,
            },
        )
    else:
        # Re-scan is clean — auto-proceed
        log.info(
            f"Security re-scan clean after fix round {remediation_round} — auto-proceeding to Step 10.",
            step=9,
        )
        # Fall through to Step 10 in resume_after_security_review by yielding a
        # synthetic APPROVED sign-off then running the rest of the pipeline.
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
        state["conversion"]        = conversion_output.model_dump()
        async for event in resume_after_security_review(job_id, state, filename):
            yield event


async def resume_after_security_review(job_id: str, state: dict, filename: str = "unknown") -> AsyncGenerator[dict, None]:
    """
    Called after human security review (Gate 2 — Step 9).
    Continues with Step 10 (Code Quality Review) through Step 12 (Code Sign-Off gate).
    Decision options:
      APPROVED     — no issues / clean scan
      ACKNOWLEDGED — issues noted, accepted risk — continue with notes
      REQUEST_FIX  — re-run Steps 7-8 with findings as fix context, re-present Gate 2
      FAILED       — block pipeline permanently
    """
    log = JobLogger(job_id, filename)

    async def emit(step: int, status: JobStatus, message: str, data: dict = None):
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

    import copy
    from .models.schemas import (
        SecurityReviewDecision, ComplexityReport, ParseReport,
        VerificationReport, SessionParseReport,
    )

    # GAP #2 + GAP #6
    state = copy.deepcopy(state)
    _required = ("documentation_md", "graph", "stack_assignment", "conversion")
    _missing  = [k for k in _required if not state.get(k)]
    if _missing:
        msg = f"State reconstruction failed — missing keys: {_missing}. Re-upload and re-run."
        log.step_failed(10, "State reconstruction", msg)
        log.finalize("failed", steps_completed=9)
        log.close()
        yield await emit(10, JobStatus.FAILED, msg, {"error": msg})
        return

    sec_signoff = state.get("security_sign_off", {})
    decision_str = sec_signoff.get("decision", "APPROVED")
    reviewer = sec_signoff.get("reviewer_name", "unknown")

    log.info(
        f"Security review decision received — decision={decision_str}, reviewer={reviewer}",
        step=9,
    )

    # Reconstruct state objects needed by Steps 10-12
    try:
        parse_report     = ParseReport(**state["parse_report"])
        complexity       = ComplexityReport(**state["complexity"])
        documentation_md = state["documentation_md"]
        graph            = state["graph"]
        _v = state.get("verification")
        verification     = VerificationReport(**_v) if _v else None
        s2t_state        = state.get("s2t", {})
        _spr = state.get("session_parse_report")
        session_parse_report = SessionParseReport(**_spr) if _spr else None
        from .models.schemas import ConversionOutput, SecurityScanReport, StackAssignment
        conversion_output = ConversionOutput(**state["conversion"])
        stack_assignment  = StackAssignment(**state["stack_assignment"])
        _sec = state.get("security_scan")
        security_scan = SecurityScanReport(**_sec) if _sec else None
    except Exception as e:
        log.step_failed(10, "State reconstruction", str(e), exc_info=True)
        log.close()
        yield await emit(10, JobStatus.FAILED, f"State reconstruction failed: {e}", _err(e))
        return

    # Load original XML for logic equivalence check (v1.3)
    xml_content_for_review = await get_xml(job_id) or ""

    ctx = _PipelineCtx(
        job_id=job_id,
        filename=filename,
        emit=emit,
        log=log,
        parse_report=parse_report,
        complexity=complexity,
        documentation_md=documentation_md,
        graph=graph,
        verification=verification,
        s2t_state=s2t_state,
        session_parse_report=session_parse_report,
        conversion_output=conversion_output,
        stack_assignment=stack_assignment,
        security_scan=security_scan,
        xml_content=xml_content_for_review,
    )

    try:
        async for event in _step_10_review(ctx): yield event
        async for event in _step_10b_reconcile(ctx): yield event
        async for event in _step_11_tests(ctx, state): yield event
        async for event in _step_11b_sec_test(ctx): yield event
        async for event in _step_12_gate3(ctx): yield event
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
