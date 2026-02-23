"""
Orchestrator — State machine that drives a ConversionJob through all 8 steps.
Enforces gates: will not advance if a step produces blocking issues.
Each step updates the DB, emits progress, and writes structured log entries
to logs/jobs/<job_id>.log (one JSON line per event).
"""
from __future__ import annotations
import asyncio
import traceback
from typing import AsyncGenerator

from .db.database import get_xml, update_job
from .models.schemas import JobStatus
from .agents import parser_agent, classifier_agent, documentation_agent, \
    verification_agent, conversion_agent, s2t_agent, review_agent, test_agent
from .logger import JobLogger


def _err(e: Exception) -> dict:
    """Return a state patch that stores the full error for UI display."""
    return {
        "error": str(e),
        "error_detail": traceback.format_exc(),
    }


async def run_pipeline(job_id: str, filename: str = "unknown") -> AsyncGenerator[dict, None]:
    """
    Run Steps 1–4 automatically, then pause at Step 5 (human review).
    Yields progress dicts for SSE streaming to the UI.
    All steps are logged to logs/jobs/<job_id>.log.
    """
    log = JobLogger(job_id, filename)

    async def emit(step: int, status: JobStatus, message: str, data: dict = None):
        patch = data or {}
        patch["pipeline_log"] = log.get_buffer()
        await update_job(job_id, status.value, step, patch)
        return {"step": step, "status": status.value, "message": message}

    # ── STEP 1 — PARSE ────────────────────────────────────────
    log.step_start(1, "Parse XML")
    log.state_change("pending", "parsing", step=1)
    yield await emit(1, JobStatus.PARSING, "Parsing Informatica XML…")

    xml_content = await get_xml(job_id)
    if not xml_content:
        log.step_failed(1, "Parse XML", "XML content not found in database")
        log.finalize("failed", steps_completed=0)
        log.close()
        yield await emit(1, JobStatus.FAILED, "XML content not found",
                         {"error": "XML content not found in database"})
        return

    try:
        parse_report, graph = parser_agent.parse_xml(xml_content)
        mapping_name = parse_report.mapping_names[0] if parse_report.mapping_names else None
        if mapping_name:
            log.set_mapping_name(mapping_name)
        log.info(
            f"Parse complete — status={parse_report.parse_status}, "
            f"mappings={len(parse_report.mapping_names)}, "
            f"objects={sum(parse_report.objects_found.values())}, "
            f"unresolved_params={len(parse_report.unresolved_parameters)}",
            step=1,
            data={
                "parse_status": parse_report.parse_status,
                "mappings": parse_report.mapping_names,
                "objects_found": parse_report.objects_found,
                "unresolved_parameters": parse_report.unresolved_parameters,
            }
        )
    except Exception as e:
        log.step_failed(1, "Parse XML", str(e), exc_info=True)
        log.finalize("failed", steps_completed=1)
        log.close()
        yield await emit(1, JobStatus.FAILED, f"Parse error: {e}", _err(e))
        return

    if parse_report.parse_status == "FAILED":
        log.step_failed(1, "Parse XML", "parse_status=FAILED")
        log.finalize("blocked", steps_completed=1)
        log.close()
        yield await emit(1, JobStatus.BLOCKED, "Parse FAILED — see parse report",
                         {"parse_report": parse_report.model_dump(),
                          "error": "XML parse failed. Check the parse report for details."})
        return

    log.step_complete(1, "Parse XML",
                      f"{sum(parse_report.objects_found.values())} objects, "
                      f"{len(parse_report.mapping_names)} mapping(s)")
    yield await emit(1, JobStatus.PARSING, "Parse complete",
                     {"parse_report": parse_report.model_dump(), "graph": graph})

    # ── STEP 2 — CLASSIFY ─────────────────────────────────────
    log.step_start(2, "Classify Complexity")
    log.state_change("parsing", "classifying", step=2)
    yield await emit(2, JobStatus.CLASSIFYING, "Classifying mapping complexity…")
    try:
        complexity = classifier_agent.classify(parse_report, graph)
        log.info(
            f"Classified as {complexity.tier.value} — criteria: {', '.join(complexity.criteria_matched)}",
            step=2,
            data={
                "tier": complexity.tier.value,
                "criteria_matched": complexity.criteria_matched,
                "special_flags": complexity.special_flags,
            }
        )
    except Exception as e:
        log.step_failed(2, "Classify Complexity", str(e), exc_info=True)
        log.finalize("failed", steps_completed=2)
        log.close()
        yield await emit(2, JobStatus.FAILED, f"Classification error: {e}", _err(e))
        return

    log.step_complete(2, "Classify Complexity", complexity.tier.value)
    yield await emit(2, JobStatus.CLASSIFYING, f"Classified as {complexity.tier.value}",
                     {"complexity": complexity.model_dump()})

    # ── STEP 2b — SOURCE-TO-TARGET MAPPING ───────────────────
    log.step_start(0, "Source-to-Target Mapping")
    s2t_result: dict = {}
    try:
        s2t_result = s2t_agent.build_s2t(parse_report, graph, job_id)
        n_mapped   = s2t_result["summary"]["mapped_fields"]
        n_unmapped = s2t_result["summary"]["unmapped_target_fields"]
        n_src_ump  = s2t_result["summary"]["unmapped_source_fields"]
        log.info(
            f"S2T mapping built — {n_mapped} mapped, {n_unmapped} unmapped target(s), "
            f"{n_src_ump} unmapped source(s), Excel: {s2t_result['excel_filename']}",
            step=2,
            data=s2t_result["summary"],
        )
        log.step_complete(0, "Source-to-Target Mapping",
                          f"{n_mapped} mapped fields, {n_unmapped} unmapped")
    except Exception as e:
        log.warning(f"S2T mapping generation failed (non-blocking): {e}", step=2)
        log.step_complete(0, "Source-to-Target Mapping", f"FAILED (non-blocking): {e}")

    # Store summary + records in job state (skip heavy excel_path binary)
    s2t_state = {
        k: v for k, v in s2t_result.items() if k != "excel_path"
    } if s2t_result else {}
    yield await emit(2, JobStatus.CLASSIFYING, "S2T mapping generated",
                     {"s2t": s2t_state})

    # ── STEP 3 — DOCUMENT ─────────────────────────────────────
    log.step_start(3, "Generate Documentation")
    log.state_change("classifying", "documenting", step=3)
    log.claude_call(3, "documentation generation")
    yield await emit(3, JobStatus.DOCUMENTING, "Generating documentation (Claude)…")
    try:
        documentation_md = await documentation_agent.document(parse_report, complexity, graph)
        doc_len = len(documentation_md)
        log.info(f"Documentation generated — {doc_len} chars", step=3,
                 data={"doc_chars": doc_len})
    except Exception as e:
        log.step_failed(3, "Generate Documentation", str(e), exc_info=True)
        log.finalize("failed", steps_completed=3)
        log.close()
        yield await emit(3, JobStatus.FAILED, f"Documentation error: {e}", _err(e))
        return

    log.step_complete(3, "Generate Documentation", f"{len(documentation_md):,} chars")
    yield await emit(3, JobStatus.DOCUMENTING, "Documentation complete",
                     {"documentation_md": documentation_md})

    # ── STEP 4 — VERIFY ───────────────────────────────────────
    log.step_start(4, "Verification")
    log.state_change("documenting", "verifying", step=4)
    log.claude_call(4, "qualitative quality checks")
    yield await emit(4, JobStatus.VERIFYING, "Running verification checks…")
    try:
        verification = await verification_agent.verify(
            parse_report, complexity, documentation_md, graph
        )
        log.info(
            f"Verification complete — status={verification.overall_status}, "
            f"checks={verification.total_checks}, passed={verification.total_passed}, "
            f"failed={verification.total_failed}, flags={verification.total_flags}, "
            f"blocked={verification.conversion_blocked}",
            step=4,
            data={
                "overall_status": verification.overall_status,
                "total_checks": verification.total_checks,
                "total_passed": verification.total_passed,
                "total_failed": verification.total_failed,
                "total_flags": verification.total_flags,
                "conversion_blocked": verification.conversion_blocked,
                "blocking_reasons": verification.blocked_reasons,
                "flags": [
                    {"type": f.flag_type, "severity": f.severity,
                     "blocking": f.blocking, "location": f.location}
                    for f in verification.flags
                ],
            }
        )
        if verification.conversion_blocked:
            log.warning(
                f"Conversion BLOCKED — {len(verification.blocked_reasons)} blocking issue(s): "
                + "; ".join(verification.blocked_reasons),
                step=4
            )
    except Exception as e:
        log.step_failed(4, "Verification", str(e), exc_info=True)
        log.finalize("failed", steps_completed=4)
        log.close()
        yield await emit(4, JobStatus.FAILED, f"Verification error: {e}", _err(e))
        return

    log.step_complete(4, "Verification", verification.overall_status)
    yield await emit(4, JobStatus.VERIFYING,
                     f"Verification complete — {verification.overall_status}",
                     {"verification": verification.model_dump()})

    # ── STEP 5 — AWAIT HUMAN REVIEW ───────────────────────────
    log.state_change("verifying", "awaiting_review", step=5)
    log.info("Pipeline paused — awaiting human review and sign-off", step=5)
    # Note flags count for registry
    v_flags = len(verification.flags) if verification else 0
    log.finalize("awaiting_review", steps_completed=5, flags_count=v_flags)
    yield await emit(5, JobStatus.AWAITING_REVIEW,
                     "Awaiting human review and sign-off. Pipeline paused.")
    log.close()


async def resume_after_signoff(job_id: str, state: dict, filename: str = "unknown") -> AsyncGenerator[dict, None]:
    """Called after human sign-off. Runs Steps 6–7."""
    log = JobLogger(job_id, filename)

    async def emit(step: int, status: JobStatus, message: str, data: dict = None):
        patch = data or {}
        patch["pipeline_log"] = log.get_buffer()
        await update_job(job_id, status.value, step, patch)
        return {"step": step, "status": status.value, "message": message}

    from .models.schemas import ComplexityReport, ParseReport

    sign_off = state.get("sign_off", {})
    log.info(
        f"Resuming after sign-off — decision={sign_off.get('decision')}, "
        f"reviewer={sign_off.get('reviewer_name')}",
        step=5
    )

    try:
        parse_report     = ParseReport(**state["parse_report"])
        complexity       = ComplexityReport(**state["complexity"])
        documentation_md = state["documentation_md"]
        graph            = state["graph"]
        # Needed for Step 8 review
        from .models.schemas import VerificationReport
        _v = state.get("verification")
        verification     = VerificationReport(**_v) if _v else None
        s2t_state        = state.get("s2t", {})
    except Exception as e:
        log.step_failed(6, "State reconstruction", str(e), exc_info=True)
        log.close()
        yield await emit(6, JobStatus.FAILED, f"State reconstruction failed: {e}", _err(e))
        return

    # ── STEP 6 — STACK ASSIGNMENT ─────────────────────────────
    log.step_start(6, "Stack Assignment")
    log.state_change("awaiting_review", "assigning_stack", step=6)
    log.claude_call(6, "stack assignment rationale")
    yield await emit(6, JobStatus.ASSIGNING_STACK, "Assigning target stack…")
    try:
        stack_assignment = await conversion_agent.assign_stack(complexity, graph, parse_report)
        log.info(
            f"Stack assigned: {stack_assignment.assigned_stack.value}",
            step=6,
            data={
                "stack": stack_assignment.assigned_stack.value,
                "tier": stack_assignment.complexity_tier.value,
                "special_concerns": stack_assignment.special_concerns,
            }
        )
    except Exception as e:
        log.step_failed(6, "Stack Assignment", str(e), exc_info=True)
        log.finalize("failed", steps_completed=6)
        log.close()
        yield await emit(6, JobStatus.FAILED, f"Stack assignment error: {e}", _err(e))
        return

    log.step_complete(6, "Stack Assignment", stack_assignment.assigned_stack.value)
    yield await emit(6, JobStatus.ASSIGNING_STACK,
                     f"Assigned stack: {stack_assignment.assigned_stack.value}",
                     {"stack_assignment": stack_assignment.model_dump()})

    # ── STEP 7 — CONVERT ──────────────────────────────────────
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
        log.info(
            f"Injecting {len(accepted_fixes)} reviewer-approved fix(es) into conversion prompt",
            step=7,
            data={"accepted_fixes": accepted_fixes},
        )

    log.step_start(7, f"Convert to {stack_assignment.assigned_stack.value}")
    log.state_change("assigning_stack", "converting", step=7)
    log.claude_call(7, f"code generation ({stack_assignment.assigned_stack.value})")
    yield await emit(7, JobStatus.CONVERTING,
                     f"Converting to {stack_assignment.assigned_stack.value} (Claude)…")
    try:
        conversion_output = await conversion_agent.convert(
            stack_assignment, documentation_md, graph,
            accepted_fixes=accepted_fixes or None,
        )
        file_list = list(conversion_output.files.keys())
        total_lines = sum(c.count("\n") for c in conversion_output.files.values())
        log.info(
            f"Conversion complete — {len(file_list)} file(s), ~{total_lines:,} lines",
            step=7,
            data={
                "files": file_list,
                "total_lines": total_lines,
                "notes": conversion_output.notes,
            }
        )
        if conversion_output.notes:
            for note in conversion_output.notes:
                log.warning(f"Conversion note: {note}", step=7)

        if not conversion_output.parse_ok:
            log.warning(
                f"Conversion output was DEGRADED — JSON parse failed; "
                f"{len(file_list)} file(s) recovered via fallback. "
                "Files may be partial or raw. Review before use.",
                step=7,
            )
    except Exception as e:
        log.step_failed(7, "Conversion", str(e), exc_info=True)
        log.finalize("failed", steps_completed=7)
        log.close()
        yield await emit(7, JobStatus.FAILED, f"Conversion error: {e}", _err(e))
        return

    if conversion_output.parse_ok:
        log.step_complete(7, "Conversion",
                          f"{len(file_list)} file(s), ~{total_lines:,} lines")
        yield await emit(7, JobStatus.CONVERTING, "Conversion complete",
                         {"conversion": conversion_output.model_dump()})
    else:
        # JSON parse failed — recovered files may be partial/truncated.
        # Step 8 review on degraded output would be meaningless, so halt here.
        fail_msg = (
            f"Conversion output degraded — JSON parse failed; "
            f"{len(file_list)} file(s) recovered via fallback but may be incomplete. "
            "Please re-run the job. If this persists the mapping may be too large "
            "for a single generation pass."
        )
        log.step_failed(7, "Conversion", fail_msg)
        log.finalize("failed", steps_completed=7)
        log.close()
        yield await emit(7, JobStatus.FAILED, f"⚠️ {fail_msg}",
                         {"conversion": conversion_output.model_dump()})
        return

    # ── STEP 8 — CODE QUALITY REVIEW ──────────────────────────
    log.step_start(8, "Code Quality Review")
    log.state_change("converting", "reviewing", step=8)
    log.claude_call(8, "static code review")
    yield await emit(8, JobStatus.CONVERTING,
                     "Running code quality review (Claude)…")

    # All needed variables are in scope from earlier steps (or restored from state).
    # verification may be a VerificationReport object or None.
    verification_dict = (verification.model_dump()
                         if verification and hasattr(verification, "model_dump")
                         else {})
    s2t_dict = s2t_state  # already stripped of excel_path

    try:
        code_review = await review_agent.review(
            conversion_output=conversion_output,
            documentation_md=documentation_md,
            verification=verification_dict,
            s2t=s2t_dict,
            parse_report=parse_report,
        )
        rec = code_review.recommendation
        log.info(
            f"Code review complete — {code_review.total_passed}/{len(code_review.checks)} checks passed, "
            f"recommendation: {rec}",
            step=8,
            data={
                "recommendation": rec,
                "total_passed": code_review.total_passed,
                "total_failed": code_review.total_failed,
            },
        )
        log.step_complete(8, "Code Quality Review", rec)
    except Exception as e:
        log.warning(f"Code review failed (non-blocking): {e}", step=8)
        from .models.schemas import CodeReviewReport
        code_review = CodeReviewReport(
            mapping_name=conversion_output.mapping_name,
            target_stack=conversion_output.target_stack.value,
            checks=[],
            total_passed=0,
            total_failed=0,
            recommendation="REVIEW_RECOMMENDED",
            summary=f"Automated review could not complete: {e}. Please review the converted code manually.",
            parse_degraded=not conversion_output.parse_ok,
        )
        log.step_complete(8, "Code Quality Review", "SKIPPED (error)")

    # ── STEP 9 — TEST GENERATION & COVERAGE CHECK ─────────────
    log.step_start(9, "Test Generation & Coverage Check")
    log.state_change("reviewing", "testing", step=9)
    yield await emit(9, JobStatus.TESTING, "Generating tests and checking field coverage…",
                     {"code_review": code_review.model_dump()})

    try:
        test_report = test_agent.generate_tests(
            conversion_output=conversion_output,
            s2t=s2t_state,
            verification=verification_dict,
            graph=graph,
        )
        log.info(
            f"Test generation complete — coverage {test_report.coverage_pct}%, "
            f"{test_report.fields_covered}/{test_report.fields_covered + test_report.fields_missing} fields covered, "
            f"{len(test_report.test_files)} test file(s) generated",
            step=9,
            data={
                "coverage_pct": test_report.coverage_pct,
                "fields_covered": test_report.fields_covered,
                "fields_missing": test_report.fields_missing,
                "missing_fields": test_report.missing_fields,
                "test_files": list(test_report.test_files.keys()),
            }
        )
        if test_report.notes:
            for note in test_report.notes:
                log.info(f"Test note: {note}", step=9)
        log.step_complete(9, "Test Generation",
                          f"{test_report.coverage_pct}% coverage, {len(test_report.test_files)} file(s)")
    except Exception as e:
        log.warning(f"Test generation failed (non-blocking): {e}", step=9)
        from .models.schemas import TestReport as TR
        test_report = TR(
            mapping_name=conversion_output.mapping_name,
            target_stack=conversion_output.target_stack.value,
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
        log.step_complete(9, "Test Generation", "SKIPPED (error)")

    # ── STEP 10 — AWAIT CODE REVIEW SIGN-OFF ──────────────────
    log.state_change("testing", "awaiting_code_review", step=10)
    log.info("Pipeline paused — awaiting code review sign-off", step=10)
    log.finalize("awaiting_code_review", steps_completed=10)
    log.close()
    yield await emit(10, JobStatus.AWAITING_CODE_REVIEW,
                     "Awaiting code review sign-off. Pipeline paused.",
                     {"test_report": test_report.model_dump()})


async def resume_after_code_signoff(job_id: str, state: dict, filename: str = "unknown") -> AsyncGenerator[dict, None]:
    """Called after code review sign-off decision. Finalises job (COMPLETE or re-queues)."""
    log = JobLogger(job_id, filename)

    async def emit(step: int, status: JobStatus, message: str, data: dict = None):
        patch = data or {}
        patch["pipeline_log"] = log.get_buffer()
        await update_job(job_id, status.value, step, patch)
        return {"step": step, "status": status.value, "message": message}

    code_signoff = state.get("code_sign_off", {})
    decision = code_signoff.get("decision", "APPROVED")
    reviewer = code_signoff.get("reviewer_name", "unknown")

    log.info(
        f"Code sign-off received — decision={decision}, reviewer={reviewer}",
        step=10,
    )

    if decision == "REGENERATE":
        # Soft reject — mark failed so reviewer can re-run conversion from Step 6
        log.step_failed(10, "Code Sign-Off", "Reviewer requested regeneration")
        log.finalize("failed", steps_completed=10)
        log.close()
        yield await emit(10, JobStatus.FAILED,
                         "Code review — regeneration requested. Please re-run the job.")
        return

    if decision == "REJECTED":
        # Hard reject — job is permanently blocked; route handler already set BLOCKED status
        log.step_failed(10, "Code Sign-Off",
                        f"Code hard-rejected by reviewer '{reviewer}'. Job blocked.")
        log.finalize("blocked", steps_completed=10)
        log.close()
        yield await emit(10, JobStatus.BLOCKED,
                         "❌ Code review rejected. Job is blocked — upload the mapping again "
                         "to start a fresh conversion.")
        return

    # APPROVED — mark complete
    log.info("✅ Code review approved — pipeline complete", step=10)
    log.finalize("complete", steps_completed=10)
    log.close()
    yield await emit(10, JobStatus.COMPLETE,
                     "✅ Pipeline complete — code approved and ready for deployment.")
