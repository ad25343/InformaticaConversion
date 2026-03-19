# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Verification constants — FLAG_META, severity/recommendation defaults, and
flag-construction helpers shared by all verification sub-modules.
"""
from __future__ import annotations

from ...models.schemas import ComplexityTier, VerificationFlag
from ...org_config_loader import get_verification_policy, get_unsupported_types


def _get_unsupported_types() -> set[str]:
    try:
        return get_unsupported_types()
    except Exception:
        return {"Java Transformation", "External Procedure",
                "Advanced External Procedure", "Stored Procedure"}


UNSUPPORTED_TYPES = _get_unsupported_types()

BLOCKING_FLAG_TYPES = {
    "UNSUPPORTED_TRANSFORMATION", "UNRESOLVED_PARAMETER_BLOCKING",
    "SQL_REVIEW_REQUIRED", "PARSE_FAILED"
}

# ─────────────────────────────────────────────────────────────────────────────
# FLAG METADATA — severity + actionable recommendation per flag type
# ─────────────────────────────────────────────────────────────────────────────
FLAG_META: dict[str, dict] = {
    "UNSUPPORTED_TRANSFORMATION": {
        "severity": "CRITICAL",
        "recommendation": (
            "This transformation type cannot be automatically converted. Manual re-implementation "
            "is required before conversion can proceed. Consider splitting this mapping into a "
            "separate manual migration task and converting the rest automatically."
        ),
    },
    "PARSE_FAILED": {
        "severity": "CRITICAL",
        "recommendation": (
            "The XML could not be parsed. Verify this is a valid Informatica PowerCenter export "
            "(.xml). Re-export from Informatica Designer, ensure the file is not truncated, and "
            "check for XML encoding issues."
        ),
    },
    "SQL_REVIEW_REQUIRED": {
        "severity": "CRITICAL",
        "recommendation": (
            "This SQL override cannot be automatically converted. Manually translate the custom "
            "SQL into the target stack's equivalent (e.g., Spark SQL / dbt SQL). Review for "
            "database-specific syntax that won't port directly."
        ),
    },
    "UNRESOLVED_PARAMETER_BLOCKING": {
        "severity": "CRITICAL",
        "recommendation": (
            "This parameter is used in a critical position (filter, join condition, or SQL). "
            "Resolve the actual runtime value before conversion proceeds. Document the value "
            "in the converted code's config section."
        ),
    },
    "UNRESOLVED_PARAMETER": {
        "severity": "HIGH",
        "recommendation": (
            "Replace the parameter with its runtime value, or externalize it to a config "
            "file (.env or config.yaml). If it is a session-level parameter (e.g. $PMRootDir), "
            "document it as a required input in the converted code's README."
        ),
    },
    "ENVIRONMENT_SPECIFIC_VALUE": {
        "severity": "HIGH",
        "recommendation": (
            "Move this hardcoded value to an environment config file. Never embed connection "
            "strings, file paths, server names, or schema names directly in converted code — "
            "they will break across environments (dev/staging/prod)."
        ),
    },
    "HIGH_RISK": {
        "severity": "HIGH",
        "recommendation": (
            "Flag for additional peer review and UAT testing before promoting to production. "
            "Add reconciliation row counts and data quality assertions around this logic in "
            "the converted code. Ensure an audit trail is maintained."
        ),
    },
    "LINEAGE_GAP": {
        "severity": "HIGH",
        "recommendation": (
            "Trace this target field manually in the Informatica mapping. If truly unresolvable, "
            "document it as a known gap in the conversion notes and add a TODO comment in the "
            "generated code so downstream engineers are aware."
        ),
    },
    "ACCURACY_CONCERN": {
        "severity": "HIGH",
        "recommendation": (
            "Review the generated documentation against the original XML to verify no business "
            "logic was altered during the documentation step. If inaccurate, delete this job, "
            "correct the XML or the documentation prompt, and re-run."
        ),
    },
    "INCOMPLETE_LOGIC": {
        "severity": "HIGH",
        "recommendation": (
            "Review all branches of the conditional logic. Ensure every ELSE / default case is "
            "handled explicitly. Missing branches cause silent data loss, incorrect routing, or "
            "wrong aggregation results in production."
        ),
    },
    "REVIEW_REQUIRED": {
        "severity": "MEDIUM",
        "recommendation": (
            "Assign a subject matter expert to clarify the ambiguous logic before finalising "
            "the conversion. Document the interpretation chosen in the sign-off notes so the "
            "decision is auditable."
        ),
    },
    "CLASSIFICATION_MISMATCH": {
        "severity": "MEDIUM",
        "recommendation": (
            "Review the complexity tier manually. Misclassification may result in the wrong "
            "target stack being assigned (e.g., Python/Pandas selected for a mapping that "
            "processes millions of rows and should use PySpark)."
        ),
    },
    "DEAD_LOGIC": {
        "severity": "LOW",
        "recommendation": (
            "Confirm with the business owner whether this transformation is intentional. "
            "If confirmed unused, remove it to reduce code complexity and improve readability "
            "in the converted output. It adds no value to the data flow."
        ),
    },
    "ORPHANED_PORT": {
        "severity": "LOW",
        "recommendation": (
            "Confirm whether this port is intentionally disconnected (e.g. a placeholder or "
            "legacy field). If it serves no purpose, remove it from the mapping to reduce "
            "dead code and simplify the converted output."
        ),
    },
    "DOCUMENTATION_TRUNCATED": {
        "severity": "HIGH",
        "recommendation": (
            "The documentation was cut off by the AI token limit before all transformations "
            "were written. Any 'not found in documentation' failures below are caused by this "
            "truncation — they do NOT indicate missing logic in your Informatica mapping. "
            "Re-run Step 3 to regenerate the documentation. If truncation persists, contact "
            "your admin to increase the token budget for this complexity tier."
        ),
    },
    "MAPPLET_DETECTED": {
        "severity": "HIGH",
        "recommendation": (
            "The mapplet definition was not found in this export — inline expansion was skipped. "
            "Re-export from Informatica Repository Manager with 'Include Dependencies' enabled "
            "to allow full inline expansion on the next run. Until then, manually verify any "
            "references to the affected mapplet(s) in the generated code."
        ),
    },
    "MAPPLET_EXPANDED": {
        "severity": "MEDIUM",
        "recommendation": (
            "Mapplet logic has been inlined into the graph. Review the generated code section "
            "corresponding to each expanded mapplet and confirm that: (1) all inner "
            "transformations and expressions are correctly represented, (2) input/output port "
            "wiring matches the original mapplet interface, and (3) data types are preserved "
            "across the Input/Output interface nodes."
        ),
    },
}

# Tier-aware token budget for the Claude quality-check call.
# More transformations → more flags → more tokens needed in the response.
_QC_MAX_TOKENS: dict[ComplexityTier, int] = {
    ComplexityTier.LOW:       2_048,
    ComplexityTier.MEDIUM:    4_096,
    ComplexityTier.HIGH:      6_144,
    ComplexityTier.VERY_HIGH: 8_192,
}


def _get_effective_flag_meta() -> dict:
    """G4: Merge FLAG_META with org-level verification_policy overrides."""
    policy = get_verification_policy()
    if not policy:
        return FLAG_META
    merged = {k: dict(v) for k, v in FLAG_META.items()}
    for flag_type, overrides in policy.items():
        if flag_type not in merged:
            merged[flag_type] = {}
        merged[flag_type].update(overrides)
    return merged


def _make_flag(
    flag_type: str,
    location: str,
    description: str,
    blocking: bool,
    severity: str = None,
    recommendation: str = None,
    auto_fix_suggestion: str = None,
) -> VerificationFlag:
    """Create a VerificationFlag, auto-populating severity/recommendation from FLAG_META."""
    meta = _get_effective_flag_meta().get(flag_type, {})
    return VerificationFlag(
        flag_type=flag_type,
        location=location,
        description=description,
        blocking=blocking,
        severity=severity or meta.get("severity", "MEDIUM"),
        recommendation=recommendation or meta.get("recommendation", "Review this flag with your team before proceeding."),
        auto_fix_suggestion=auto_fix_suggestion,
    )
