"""
Pydantic schemas and SQLAlchemy models for the Informatica Conversion Tool.
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
from pydantic import BaseModel


# ─────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────

class JobStatus(str, Enum):
    PENDING          = "pending"
    PARSING          = "parsing"
    CLASSIFYING      = "classifying"
    DOCUMENTING      = "documenting"
    VERIFYING        = "verifying"
    AWAITING_REVIEW  = "awaiting_review"
    ASSIGNING_STACK  = "assigning_stack"
    CONVERTING       = "converting"
    VALIDATING       = "validating"
    TESTING          = "testing"           # Step 9 — test generation
    AWAITING_CODE_REVIEW = "awaiting_code_review"  # Step 10 — code sign-off gate
    COMPLETE         = "complete"
    FAILED           = "failed"
    BLOCKED          = "blocked"

class ComplexityTier(str, Enum):
    LOW       = "Low"
    MEDIUM    = "Medium"
    HIGH      = "High"
    VERY_HIGH = "Very High"

class TargetStack(str, Enum):
    PYSPARK = "PySpark"
    DBT     = "dbt"
    PYTHON  = "Python"
    HYBRID  = "Hybrid"

class ReviewDecision(str, Enum):
    """Gate 1 (Step 5) decisions — documentation / verification sign-off."""
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"

class CodeReviewDecision(str, Enum):
    """Gate 2 (Step 10) decisions — generated code review sign-off."""
    APPROVED   = "APPROVED"    # Accept the code — pipeline complete
    REGENERATE = "REGENERATE"  # Reject this attempt — re-run conversion (Steps 6–9)
    REJECTED   = "REJECTED"    # Hard stop — code is fundamentally unacceptable

class FileType(str, Enum):
    """v1.1 — auto-detected type for each uploaded file."""
    MAPPING   = "MAPPING"    # Contains <MAPPING> element
    WORKFLOW  = "WORKFLOW"   # Contains <WORKFLOW> element with <SESSION> tasks
    PARAMETER = "PARAMETER"  # Key=value parameter file ($$VARIABLES)
    UNKNOWN   = "UNKNOWN"    # Could not be determined


# ─────────────────────────────────────────────
# v1.1 — Session & Parameter schemas
# ─────────────────────────────────────────────

class UploadedFile(BaseModel):
    """Metadata for one file uploaded as part of a job."""
    filename:      str
    file_type:     FileType
    detected_at:   str                     # ISO datetime

class CrossRefValidation(BaseModel):
    """Result of cross-referencing the uploaded files before Step 0 runs."""
    status:        str                     # VALID | INVALID | WARNINGS
    mapping_name:  Optional[str] = None    # Mapping name found in Mapping XML
    session_name:  Optional[str] = None    # Session name found in Workflow XML
    referenced_mapping: Optional[str] = None  # Mapping name the Session references
    issues:        List[str] = []          # Error/warning messages

class SessionConnection(BaseModel):
    """A source or target connection extracted from a Session."""
    transformation_name: str
    role:                str          # SOURCE | TARGET
    connection_name:     Optional[str] = None
    connection_type:     Optional[str] = None   # RELATIONAL | FILE | FTP etc.
    file_name:           Optional[str] = None
    file_dir:            Optional[str] = None

class SessionConfig(BaseModel):
    """Runtime config extracted from the Session task in the Workflow XML."""
    session_name:        str
    mapping_name:        str
    workflow_name:       str
    connections:         List[SessionConnection] = []
    pre_session_sql:     Optional[str] = None
    post_session_sql:    Optional[str] = None
    commit_interval:     Optional[int] = None
    error_threshold:     Optional[int] = None
    reject_filename:     Optional[str] = None
    reject_filedir:      Optional[str] = None
    raw_attributes:      Dict[str, str] = {}   # All other session attributes

class ParameterEntry(BaseModel):
    """One resolved parameter from a parameter file."""
    name:    str          # e.g. $$BATCH_DATE
    value:   str          # Resolved value
    scope:   str          # GLOBAL | WORKFLOW | SESSION

class SessionParseReport(BaseModel):
    """Output of Step 0 — Session & Parameter Parser."""
    uploaded_files:       List[UploadedFile]
    cross_ref:            CrossRefValidation
    session_config:       Optional[SessionConfig]  = None
    parameters:           List[ParameterEntry]     = []
    unresolved_variables: List[str]                = []   # $$VARs with no value
    parse_status:         str                             # COMPLETE | PARTIAL | FAILED | MAPPING_ONLY
    notes:                List[str]                = []


# ─────────────────────────────────────────────
# Parse Report
# ─────────────────────────────────────────────

class ParseFlag(BaseModel):
    flag_type: str          # UNRESOLVED_PARAMETER | PARSE_ERROR | UNKNOWN_ELEMENT
    element:   str
    detail:    str

class ParseReport(BaseModel):
    objects_found:         Dict[str, int]       # e.g. {"Mapping": 1, "Transformation": 8}
    reusable_components:   List[str]
    unresolved_parameters: List[str]
    malformed_xml:         List[str]
    unrecognized_elements: List[str]
    flags:                 List[ParseFlag]
    parse_status:          str                  # COMPLETE | PARTIAL | FAILED
    mapping_names:         List[str]


# ─────────────────────────────────────────────
# Complexity Classification
# ─────────────────────────────────────────────

class ComplexityReport(BaseModel):
    tier:            ComplexityTier
    criteria_matched: List[str]
    data_volume_est: Optional[str]
    special_flags:   List[str]
    rationale:       str


# ─────────────────────────────────────────────
# Verification Report
# ─────────────────────────────────────────────

class VerificationFlag(BaseModel):
    flag_type:            str    # UNSUPPORTED_TRANSFORMATION | LINEAGE_GAP | HIGH_RISK | etc.
    location:             str
    description:          str
    blocking:             bool
    severity:             str = "MEDIUM"   # CRITICAL | HIGH | MEDIUM | LOW | INFO
    recommendation:       str = ""         # Actionable fix guidance for the reviewer
    auto_fix_suggestion:  Optional[str] = None  # Specific code-level fix Claude can apply if reviewer approves

class CheckResult(BaseModel):
    name:   str
    passed: bool
    detail: Optional[str] = None

class VerificationReport(BaseModel):
    mapping_name:         str
    complexity_tier:      ComplexityTier
    overall_status:       str               # APPROVED_FOR_CONVERSION | REQUIRES_REMEDIATION
    completeness_checks:  List[CheckResult]
    accuracy_checks:      List[CheckResult]
    self_checks:          List[CheckResult]
    flags:                List[VerificationFlag]
    total_checks:         int
    total_passed:         int
    total_failed:         int
    total_flags:          int
    conversion_blocked:   bool
    blocked_reasons:      List[str]
    recommendation:       str


# ─────────────────────────────────────────────
# Human Sign-off
# ─────────────────────────────────────────────

class FlagResolution(BaseModel):
    flag_type:      str
    location:       str
    action:         str            # "accepted" | "resolved"
    rationale:      str
    apply_fix:      bool = False   # True if reviewer wants the suggested fix applied in Step 7
    fix_suggestion: Optional[str] = None  # The auto_fix_suggestion text (carried from flag)

class SignOffRecord(BaseModel):
    reviewer_name:     str
    reviewer_role:     str
    review_date:       str
    blocking_resolved: List[str]
    flags_accepted:    List[FlagResolution]
    flags_resolved:    List[FlagResolution]
    decision:          ReviewDecision
    notes:             Optional[str] = None


# ─────────────────────────────────────────────
# Stack Assignment
# ─────────────────────────────────────────────

class StackAssignment(BaseModel):
    mapping_name:      str
    complexity_tier:   ComplexityTier
    assigned_stack:    TargetStack
    rationale:         str
    data_volume_est:   Optional[str]
    special_concerns:  List[str]


# ─────────────────────────────────────────────
# Conversion Output
# ─────────────────────────────────────────────

class ConversionOutput(BaseModel):
    mapping_name:  str
    target_stack:  TargetStack
    files:         Dict[str, str]   # filename -> code content
    notes:         List[str]
    parse_ok:      bool = True      # False = JSON parse failed; files may be partial/raw


# ─────────────────────────────────────────────
# Reconciliation Report (Step 8)
# ─────────────────────────────────────────────

class ReconciliationReport(BaseModel):
    mapping_name:      str
    input_description: str
    informatica_rows:  Optional[int]
    converted_rows:    Optional[int]
    match_rate:        Optional[float]
    mismatched_fields: List[Dict[str, Any]]
    root_cause:        Optional[str]
    resolution:        Optional[str]
    final_status:      str   # RECONCILED | FAILED | PENDING_EXECUTION


# ─────────────────────────────────────────────
# Code Review Report (Step 8)
# ─────────────────────────────────────────────

class CodeReviewCheck(BaseModel):
    name:     str
    passed:   bool
    severity: str = "MEDIUM"   # CRITICAL | HIGH | MEDIUM | LOW
    note:     str = ""

class CodeReviewReport(BaseModel):
    mapping_name:    str
    target_stack:    str
    checks:          List[CodeReviewCheck]
    total_passed:    int
    total_failed:    int
    recommendation:  str   # APPROVED | REVIEW_RECOMMENDED | REQUIRES_FIXES
    summary:         str
    parse_degraded:  bool = False   # True if Step 7 output was degraded


# ─────────────────────────────────────────────
# Test Generation Report (Step 9)
# ─────────────────────────────────────────────

class FieldCoverageCheck(BaseModel):
    target_field:   str
    target_table:   str
    covered:        bool
    found_in_files: List[str]   # which generated files contain this field name
    note:           str = ""

class FilterCoverageCheck(BaseModel):
    filter_description: str     # e.g. "STATUS != 'CANCELLED'"
    source:             str     # where it came from (SQ filter, FIL transformation, etc.)
    covered:            bool
    found_in_files:     List[str]
    note:               str = ""

class TestReport(BaseModel):
    mapping_name:       str
    target_stack:       str
    test_files:         Dict[str, str]          # filename -> test file content
    field_coverage:     List[FieldCoverageCheck]
    filter_coverage:    List[FilterCoverageCheck]
    fields_covered:     int
    fields_missing:     int
    coverage_pct:       float
    missing_fields:     List[str]
    filters_covered:    int
    filters_missing:    int
    notes:              List[str]


# ─────────────────────────────────────────────
# Code Sign-off Record (Step 10)
# ─────────────────────────────────────────────

class CodeSignOffRecord(BaseModel):
    reviewer_name:  str
    reviewer_role:  str
    review_date:    str
    decision:       CodeReviewDecision   # APPROVED | REGENERATE | REJECTED
    notes:          Optional[str] = None


# ─────────────────────────────────────────────
# Top-level Job
# ─────────────────────────────────────────────

class ConversionJob(BaseModel):
    job_id:               str
    filename:             str
    created_at:           str
    updated_at:           str
    status:               JobStatus
    current_step:         int                               # 0-10
    # v1.1 — session & parameter parse (Step 0)
    session_parse_report: Optional[SessionParseReport]  = None
    # Core pipeline (Steps 1-10)
    parse_report:         Optional[ParseReport]         = None
    complexity:           Optional[ComplexityReport]    = None
    documentation_md:     Optional[str]                 = None
    verification:         Optional[VerificationReport]  = None
    sign_off:             Optional[SignOffRecord]        = None
    stack_assignment:     Optional[StackAssignment]     = None
    conversion:           Optional[ConversionOutput]    = None
    reconciliation:       Optional[ReconciliationReport]= None
    error:                Optional[str]                 = None


# ─────────────────────────────────────────────
# API Request/Response helpers
# ─────────────────────────────────────────────

class SignOffRequest(BaseModel):
    reviewer_name:     str
    reviewer_role:     str
    decision:          ReviewDecision
    flag_resolutions:  List[FlagResolution] = []
    notes:             Optional[str] = None

class CodeSignOffRequest(BaseModel):
    reviewer_name: str
    reviewer_role: str
    decision:      CodeReviewDecision   # APPROVED | REGENERATE | REJECTED
    notes:         Optional[str] = None

class JobSummary(BaseModel):
    job_id:       str
    filename:     str
    status:       JobStatus
    current_step: int
    created_at:   str
    updated_at:   str
    complexity:   Optional[str] = None
