# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
STEP 0 — Session & Parameter Parser  (v1.1)

Responsibilities
----------------
1. Auto-detect the type of each uploaded file (MAPPING / WORKFLOW / PARAMETER / UNKNOWN)
   from its XML structure or content.
2. Cross-reference validation: the Session task inside a Workflow XML must reference
   the same mapping name found in the Mapping XML before the pipeline is allowed to run.
3. Session config extraction: pull connections, reject-file config, pre/post SQL,
   commit intervals, error thresholds, and any other SESSTRANSFORMINSTATTR rows from
   the Workflow XML.
4. Parameter file resolution: parse $$VARIABLE=value lines and resolve any $$VARS
   referenced in session attributes or SQL overrides.

Returns a SessionParseReport which is stored on the job and threaded through to
documentation_agent (for context injection) and conversion_agent (YAML artifacts).
"""
from __future__ import annotations

import re
from typing import Optional

from lxml import etree

from ..security import safe_parse_xml
from ..models.schemas import (
    CrossRefValidation,
    FileType,
    ParameterEntry,
    SessionConfig,
    SessionConnection,
    SessionParseReport,
    UploadedFile,
)
from datetime import datetime, timezone
from .base import BaseAgent


# ─────────────────────────────────────────────────────────────────────────────
# Agent class + public entry point
# ─────────────────────────────────────────────────────────────────────────────

class SessionParserAgent(BaseAgent):

    def parse(
        self,
        mapping_xml:    Optional[str],
        workflow_xml:   Optional[str] = None,
        parameter_file: Optional[str] = None,
    ) -> SessionParseReport:
        return _parse_impl(mapping_xml, workflow_xml, parameter_file)


def _make_uploaded_file(filename: str, file_type: FileType, now: str) -> UploadedFile:
    return UploadedFile(filename=filename, file_type=file_type, detected_at=now)


def _detect_workflow_type(workflow_xml: Optional[str], now: str) -> tuple[Optional[str], list[UploadedFile]]:
    """Detect workflow file type and build its UploadedFile entry."""
    if workflow_xml is None:
        return None, []
    wf_type = _detect_type(workflow_xml)
    return wf_type, [_make_uploaded_file("workflow.xml", wf_type, now)]


def _determine_parse_status(
    cross_ref: CrossRefValidation,
    workflow_xml: Optional[str],
    session_config: Optional[SessionConfig],
) -> str:
    """Determine the parse_status string from cross-ref and session config results."""
    if cross_ref.status == "INVALID":
        return "FAILED"
    if cross_ref.status == "WARNINGS":
        return "PARTIAL"
    if workflow_xml is None:
        return "MAPPING_ONLY"
    if session_config is None:
        return "PARTIAL"
    return "COMPLETE"


def _wf_type_label(wf_type) -> str:
    """Return a human-readable label for the workflow file type."""
    if wf_type is None:
        return "UNKNOWN"
    return wf_type.value


def _extract_session_or_notes(
    workflow_xml: Optional[str],
    wf_type,
    param_lookup: dict[str, str],
) -> tuple[Optional[SessionConfig], list[str], list[str]]:
    """
    Run session config extraction if conditions are met.
    Returns (session_config, unresolved_variables, notes).
    """
    notes: list[str] = []
    if workflow_xml and wf_type == FileType.WORKFLOW:
        session_config, unresolved = _extract_session_config(workflow_xml, param_lookup)
        if session_config is None:
            notes.append("Workflow XML present but no SESSION task could be extracted.")
        return session_config, unresolved, notes
    if workflow_xml:
        notes.append(
            f"workflow.xml was detected as {_wf_type_label(wf_type)} "
            "rather than WORKFLOW — session config skipped."
        )
    return None, [], notes


def _resolve_params_and_session(
    workflow_xml: Optional[str],
    wf_type,
    parameter_file: Optional[str],
) -> tuple:
    """
    Parse parameters and extract session config.
    Returns (raw_params, param_lookup, session_config, unresolved_variables, notes).
    """
    raw_params = _parse_parameter_file(parameter_file) if parameter_file else []
    param_lookup: dict[str, str] = {p.name.upper(): p.value for p in raw_params}
    session_config, unresolved_variables, notes = _extract_session_or_notes(
        workflow_xml, wf_type, param_lookup
    )
    return raw_params, param_lookup, session_config, unresolved_variables, notes


def _finalize_status_and_notes(
    cross_ref: CrossRefValidation,
    workflow_xml: Optional[str],
    session_config: Optional[SessionConfig],
    notes: list[str],
) -> tuple[str, list[str]]:
    """Append cross-ref failure note if needed and return (parse_status, notes)."""
    if cross_ref.status == "INVALID":
        notes.append("Cross-reference validation failed — see cross_ref.issues for details.")
    return _determine_parse_status(cross_ref, workflow_xml, session_config), notes


def _validate_mapping_type(
    mapping_xml: Optional[str],
    mapping_type: FileType,
    uploaded_files: list[UploadedFile],
    cross_ref: CrossRefValidation,
) -> Optional[SessionParseReport]:
    """
    Return a FAILED SessionParseReport if the mapping XML is missing or wrong type,
    or None if validation passes.
    """
    if mapping_xml is None or mapping_type == FileType.UNKNOWN:
        return SessionParseReport(
            uploaded_files=uploaded_files,
            cross_ref=cross_ref,
            parse_status="FAILED",
            notes=["Mapping XML is missing or could not be identified."],
        )
    if mapping_type != FileType.MAPPING:
        return SessionParseReport(
            uploaded_files=uploaded_files,
            cross_ref=cross_ref,
            parse_status="FAILED",
            notes=[f"Uploaded mapping file was detected as {mapping_type.value}, not MAPPING."],
        )
    return None


def _parse_impl(
    mapping_xml:    Optional[str],
    workflow_xml:   Optional[str] = None,
    parameter_file: Optional[str] = None,
) -> SessionParseReport:
    """
    Run Step 0.

    Parameters
    ----------
    mapping_xml     Required — the Informatica Mapping XML export.
    workflow_xml    Optional — the Workflow XML that contains a Session referencing
                    the mapping.
    parameter_file  Optional — plain-text parameter file ($$VAR=value lines).

    Returns
    -------
    SessionParseReport
    """
    now = datetime.now(timezone.utc).isoformat()

    # ── 1. Detect file types ────────────────────────────────────────────────
    mapping_type = _detect_type(mapping_xml) if mapping_xml else FileType.UNKNOWN
    wf_type, wf_files = _detect_workflow_type(workflow_xml, now)

    uploaded_files: list[UploadedFile] = [
        _make_uploaded_file("mapping.xml", mapping_type, now),
        *wf_files,
    ]
    if parameter_file is not None:
        uploaded_files.append(_make_uploaded_file("parameter_file.txt", FileType.PARAMETER, now))

    # ── 2. Cross-reference validation ───────────────────────────────────────
    wf_xml_for_xref = workflow_xml if wf_type == FileType.WORKFLOW else None
    cross_ref = _cross_reference(mapping_xml=mapping_xml, workflow_xml=wf_xml_for_xref)

    # Stop early if mapping XML is completely missing / wrong type
    early = _validate_mapping_type(mapping_xml, mapping_type, uploaded_files, cross_ref)
    if early is not None:
        return early

    # ── 3 & 4. Parameter resolution + session config extraction ─────────────
    raw_params, param_lookup, session_config, unresolved_variables, notes = (
        _resolve_params_and_session(workflow_xml, wf_type, parameter_file)
    )

    # ── 5. Determine parse status ────────────────────────────────────────────
    parse_status, notes = _finalize_status_and_notes(
        cross_ref, workflow_xml, session_config, notes
    )

    return SessionParseReport(
        uploaded_files=uploaded_files,
        cross_ref=cross_ref,
        session_config=session_config,
        parameters=raw_params,
        unresolved_variables=unresolved_variables,
        parse_status=parse_status,
        notes=notes,
    )


# Backward-compat shim — keeps orchestrator.py call sites unchanged
def parse(
    mapping_xml:    Optional[str],
    workflow_xml:   Optional[str] = None,
    parameter_file: Optional[str] = None,
) -> SessionParseReport:
    return SessionParserAgent().parse(mapping_xml, workflow_xml, parameter_file)


# ─────────────────────────────────────────────────────────────────────────────
# File-type auto-detection
# ─────────────────────────────────────────────────────────────────────────────

def _is_parameter_content(stripped: str) -> bool:
    """Check if content looks like a parameter file.
    Handles both flat ($$VAR=value) and XML (<PARAMFILE> / <PARAM NAME="$$...">).
    """
    if not stripped.startswith("<"):
        return "$$" in stripped
    # XML param file: must contain a <PARAM or <PARAMFILE element with $$ names
    return "<PARAM" in stripped and "$$" in stripped


def _try_parse_xml(stripped: str):
    """Parse XML content; return root element or None on failure."""
    try:
        return safe_parse_xml(stripped)
    except Exception:
        return None


def _classify_xml_root(root) -> FileType:
    """Classify a parsed XML root as MAPPING, WORKFLOW, or UNKNOWN."""
    ns = "http://powermart.informatica.com/DTD/PowerMart"
    if root.find(f".//{{{ns}}}MAPPING") is not None or root.find(".//MAPPING") is not None:
        return FileType.MAPPING
    if _is_workflow_root(root, ns):
        return FileType.WORKFLOW
    return FileType.UNKNOWN


def _is_workflow_root(root, ns: str) -> bool:
    """Return True if the XML root contains a workflow with session tasks."""
    has_wf = (
        root.find(f".//{{{ns}}}WORKFLOW") is not None
        or root.find(".//WORKFLOW") is not None
    )
    if not has_wf:
        return False
    return (
        root.find(".//TASKINSTANCE[@TASKTYPE='Session']") is not None
        or root.find(".//SESSION") is not None
        or root.find(".//TASK[@TYPE='Session']") is not None
    )


def _detect_type(content: Optional[str]) -> FileType:
    """Infer whether content is a Mapping XML, Workflow XML, or Parameter file."""
    if not content:
        return FileType.UNKNOWN

    stripped = content.strip()

    if _is_parameter_content(stripped):
        return FileType.PARAMETER

    root = _try_parse_xml(stripped)
    if root is None:
        return FileType.PARAMETER if re.search(r"\$\$\w+\s*=", stripped) else FileType.UNKNOWN

    return _classify_xml_root(root)


# ─────────────────────────────────────────────────────────────────────────────
# Cross-reference validation
# ─────────────────────────────────────────────────────────────────────────────

def _extract_mapping_name(mapping_xml: str) -> Optional[str]:
    """Pull the first MAPPING/@NAME from the mapping XML."""
    try:
        root = safe_parse_xml(mapping_xml)
    except Exception:
        return None
    el = root.find(".//MAPPING")
    if el is None:
        el = root.find(".//{http://powermart.informatica.com/DTD/PowerMart}MAPPING")
    return el.get("NAME") if el is not None else None


def _find_session_element(root):
    """Find SESSION or TASK[@TYPE='Session'] element in the XML tree."""
    el = root.find(".//SESSION")
    if el is None:
        el = root.find(".//TASK[@TYPE='Session']")
    return el


_MAPPING_NAME_KEYS = frozenset(("mapping name", "mappingname"))


def _attr_name_is_mapping(attr, name_key: str, value_key: str) -> Optional[str]:
    """Return the attribute value if its name-key matches a mapping name key, else None."""
    if (attr.get(name_key) or "").lower() in _MAPPING_NAME_KEYS:
        return attr.get(value_key)
    return None


def _find_mapping_ref_from_sess_attrs(root) -> Optional[str]:
    """Look in SESSTRANSFORMINSTATTR elements for the mapping name reference."""
    for attr in root.iter("SESSTRANSFORMINSTATTR"):
        val = _attr_name_is_mapping(attr, "ATTRIBUTENAME", "ATTRIBUTEVALUE")
        if val:
            return val
    return None


def _find_mapping_ref_from_config_attrs(root) -> Optional[str]:
    """Look in ATTRIBUTE/CONFIG elements for the mapping name reference."""
    for attr in root.iter("ATTRIBUTE"):
        val = _attr_name_is_mapping(attr, "NAME", "VALUE")
        if val is None:
            val = _attr_name_is_mapping(attr, "NAME", "ATTRIBUTEVALUE")
        if val:
            return val
    return None


def _find_mapping_ref_from_instances(root) -> Optional[str]:
    """Fall back to searching INSTANCE elements for a mapping reference."""
    for inst in root.iter("INSTANCE"):
        if inst.get("TYPE") == "Mapping":
            return inst.get("REUSABLE_INSTANCE_NAME") or inst.get("NAME")
        reusable = inst.get("REUSABLE_INSTANCE_NAME")
        if reusable:
            return reusable
    return None


def _find_mapping_ref_in_attrs(root, session_el) -> Optional[str]:
    """Search session element attributes and child elements for the mapping reference."""
    ref = session_el.get("MAPPINGNAME")
    if ref:
        return ref
    return (
        _find_mapping_ref_from_sess_attrs(root)
        or _find_mapping_ref_from_config_attrs(root)
        or _find_mapping_ref_from_instances(root)
    )


def _extract_session_mapping_ref(workflow_xml: str) -> tuple[Optional[str], Optional[str]]:
    """
    Pull (session_name, referenced_mapping_name) from the workflow XML.

    Informatica stores the mapping link in different places depending on
    PowerCenter version:
      - SESSTRANSFORMINSTATTR row with ATTRIBUTENAME='Mapping name'
      - SESSION/@MAPPINGNAME (older exports)
      - INSTANCE/@REUSABLE_INSTANCE_NAME pointing to a MAPPING
    """
    try:
        root = safe_parse_xml(workflow_xml)
    except Exception:
        return None, None

    session_el = _find_session_element(root)
    if session_el is None:
        return None, None

    session_name = session_el.get("NAME") or session_el.get("TASKNAME")
    ref_mapping = _find_mapping_ref_in_attrs(root, session_el)
    return session_name, ref_mapping


def _issue_is_hard(issue: str) -> bool:
    """Return True if an issue text represents a hard validation failure."""
    low = issue.lower()
    return "mismatch" in low or "could not" in low


def _names_match(mapping_name: Optional[str], ref_mapping: Optional[str]) -> bool:
    """Return True if both names are non-None and equal."""
    return bool(mapping_name and ref_mapping and mapping_name == ref_mapping)


def _both_names_present(mapping_name: Optional[str], ref_mapping: Optional[str]) -> bool:
    """Return True if both mapping_name and ref_mapping are non-empty."""
    return bool(mapping_name) and bool(ref_mapping)


def _any_hard(issues: list[str]) -> bool:
    """Return True if any issue in issues is considered a hard (blocking) issue."""
    return any(_issue_is_hard(i) for i in issues)


def _build_cross_ref_status(
    issues: list[str],
    mapping_name: Optional[str],
    ref_mapping: Optional[str],
) -> str:
    """Determine the CrossRefValidation status string from issues list."""
    if not issues:
        return "VALID"
    if _names_match(mapping_name, ref_mapping):
        return "WARNINGS"
    if _any_hard(issues) and _both_names_present(mapping_name, ref_mapping):
        return "INVALID"
    return "WARNINGS"


def _names_mismatch(mapping_name: Optional[str], ref_mapping: Optional[str]) -> bool:
    """Return True if both names are present but differ."""
    return bool(mapping_name) and bool(ref_mapping) and mapping_name != ref_mapping


def _collect_cross_ref_issues(
    mapping_name: Optional[str],
    session_name: Optional[str],
    ref_mapping: Optional[str],
) -> list[str]:
    """Build the list of cross-reference validation issues."""
    issues: list[str] = []
    if not session_name:
        issues.append("Could not find a SESSION task inside the Workflow XML.")
    if not ref_mapping:
        issues.append(
            "Could not determine which mapping the Session references "
            "(MAPPINGNAME attribute or SESSTRANSFORMINSTATTR not found)."
        )
    if _names_mismatch(mapping_name, ref_mapping):
        issues.append(
            f"Mapping name mismatch: Mapping XML contains '{mapping_name}' "
            f"but Session references '{ref_mapping}'."
        )
    return issues


def _cross_reference(
    mapping_xml: Optional[str],
    workflow_xml: Optional[str],
) -> CrossRefValidation:
    """Build the CrossRefValidation result."""
    mapping_name = _extract_mapping_name(mapping_xml) if mapping_xml else None

    pre_issues: list[str] = []
    if not mapping_name:
        pre_issues.append("Could not extract MAPPING/@NAME from the Mapping XML.")

    if workflow_xml is None:
        return CrossRefValidation(status="VALID", mapping_name=mapping_name)

    session_name, ref_mapping = _extract_session_mapping_ref(workflow_xml)
    issues = pre_issues + _collect_cross_ref_issues(mapping_name, session_name, ref_mapping)
    status = _build_cross_ref_status(issues, mapping_name, ref_mapping)

    return CrossRefValidation(
        status=status,
        mapping_name=mapping_name,
        session_name=session_name,
        referenced_mapping=ref_mapping,
        issues=issues,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Parameter file parsing
# ─────────────────────────────────────────────────────────────────────────────

_SCOPE_FROM_PARTS = {1: "GLOBAL", 2: "WORKFLOW"}


def _scope_from_header(header: str) -> str:
    """Determine parameter scope from a scope-header string."""
    parts = header.split(".")
    if len(parts) >= 3:
        return "SESSION"
    return _SCOPE_FROM_PARTS.get(len(parts), "GLOBAL")


def _parse_parameter_line(line: str, current_scope: str) -> Optional[ParameterEntry]:
    """Parse a single parameter assignment line; returns None if not an assignment."""
    if "=" not in line:
        return None
    name, _, value = line.partition("=")
    return ParameterEntry(name=name.strip(), value=value.strip(), scope=current_scope)


def _is_scope_header(line: str) -> bool:
    """Return True if line is a parameter-file scope header like [folder.workflow]."""
    return line.startswith("[") and line.endswith("]")


def _process_param_line(
    line: str,
    current_scope: str,
    params: list[ParameterEntry],
) -> str:
    """
    Process one non-empty, non-comment parameter file line.
    Updates params in-place and returns the (possibly updated) current_scope.
    """
    if _is_scope_header(line):
        return _scope_from_header(line[1:-1])
    entry = _parse_parameter_line(line, current_scope)
    if entry is not None:
        params.append(entry)
    return current_scope


def _parse_parameter_file_xml(content: str) -> list[ParameterEntry]:
    """Parse Informatica XML-format parameter file (<PARAM NAME="$$KEY" VALUE="val"/>)."""
    import xml.etree.ElementTree as ET
    params: list[ParameterEntry] = []
    try:
        root = ET.fromstring(content)
        for elem in root.iter("PARAM"):
            name  = elem.get("NAME", "").strip()
            value = elem.get("VALUE", "").strip()
            if name.startswith("$$"):
                params.append(ParameterEntry(name=name, value=value, scope="GLOBAL"))
    except ET.ParseError:
        pass
    return params


def _parse_parameter_file(content: str) -> list[ParameterEntry]:
    """
    Parse an Informatica parameter file — handles both formats:
      • XML:  <PARAM NAME="$$VAR" VALUE="val"/>  (Informatica repo export)
      • Flat: [scope]\\n$$VARIABLE=value          (classic .txt param file)
    """
    stripped = content.lstrip()
    if stripped.startswith("<"):
        return _parse_parameter_file_xml(content)

    params: list[ParameterEntry] = []
    current_scope = "GLOBAL"

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        current_scope = _process_param_line(line, current_scope, params)

    return params


# ─────────────────────────────────────────────────────────────────────────────
# Session config extraction
# ─────────────────────────────────────────────────────────────────────────────

_PARAM_RE = re.compile(r"\$\$[A-Z0-9_]+", re.IGNORECASE)


def _resolve(value: str, lookup: dict[str, str]) -> tuple[str, list[str]]:
    """
    Replace $$VARIABLES in a string using the lookup dict.
    Returns (resolved_value, list_of_unresolved_names).
    """
    unresolved: list[str] = []

    def replacer(match: re.Match) -> str:
        var = match.group(0).upper()
        if var in lookup:
            return lookup[var]
        unresolved.append(match.group(0))
        return match.group(0)  # leave as-is

    resolved = _PARAM_RE.sub(replacer, value)
    return resolved, unresolved


def _get_attr_name(attr) -> str:
    """Get the name of an XML attribute element."""
    return attr.get("ATTRIBUTENAME") or attr.get("NAME") or ""


def _get_attr_value(attr) -> str:
    """Get the value of an XML attribute element."""
    return attr.get("ATTRIBUTEVALUE") or attr.get("VALUE") or ""


def _collect_child_attrs(
    session_el,
    param_lookup: dict[str, str],
    raw_attributes: dict[str, str],
    all_unresolved: list[str],
) -> None:
    """Collect SESSTRANSFORMINSTATTR/SESSIONEXTENSION/ATTRIBUTE child rows into raw_attributes."""
    for attr in session_el.iter("SESSTRANSFORMINSTATTR", "SESSIONEXTENSION", "ATTRIBUTE"):
        attr_name  = _get_attr_name(attr)
        attr_value = _get_attr_value(attr)
        if attr_name:
            resolved, unresolved = _resolve(attr_value, param_lookup)
            raw_attributes[attr_name] = resolved
            all_unresolved.extend(unresolved)


def _collect_direct_attrs(
    session_el,
    param_lookup: dict[str, str],
    raw_attributes: dict[str, str],
    all_unresolved: list[str],
) -> None:
    """Collect direct attributes on the SESSION element into raw_attributes."""
    for k, v in session_el.attrib.items():
        if k not in raw_attributes:
            resolved, unresolved = _resolve(v, param_lookup)
            raw_attributes[k] = resolved
            all_unresolved.extend(unresolved)


def _collect_raw_attributes(
    session_el,
    param_lookup: dict[str, str],
) -> tuple[dict[str, str], list[str]]:
    """
    Collect all session attribute rows, resolving $$VARIABLES.
    Returns (raw_attributes dict, list of unresolved variable names).
    """
    raw_attributes: dict[str, str] = {}
    all_unresolved: list[str] = []
    _collect_child_attrs(session_el, param_lookup, raw_attributes, all_unresolved)
    _collect_direct_attrs(session_el, param_lookup, raw_attributes, all_unresolved)
    return raw_attributes, all_unresolved


def _lookup_attr(raw_attributes: dict[str, str], *keys: str) -> Optional[str]:
    """Return the first non-empty value found in raw_attributes for any of the given keys."""
    for k in keys:
        v = raw_attributes.get(k)
        if v:
            return v
    return None


def _safe_int(raw: Optional[str]) -> Optional[int]:
    """Convert a raw string to int, or return None on failure."""
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _get_well_known_attrs(raw_attributes: dict[str, str]):
    """Extract well-known session attributes from the raw attribute dict."""
    pre_sql      = _lookup_attr(raw_attributes, "Pre SQL", "Pre-session SQL", "PRE_SQL", "PreSQL")
    post_sql     = _lookup_attr(raw_attributes, "Post SQL", "Post-session SQL", "POST_SQL", "PostSQL")
    reject_fname = _lookup_attr(raw_attributes, "Reject Filename", "RejectFilename", "REJECTFILE")
    reject_fdir  = _lookup_attr(raw_attributes, "Reject File Directory", "RejectFiledir", "REJECTFILEDIR")
    commit_raw   = _lookup_attr(raw_attributes, "Commit Interval", "CommitInterval", "COMMIT_INTERVAL")
    error_raw    = _lookup_attr(raw_attributes, "Stop On Errors", "ErrorThreshold", "STOPONERRORS")
    return pre_sql, post_sql, reject_fname, reject_fdir, _safe_int(commit_raw), _safe_int(error_raw)


_SOURCE_PREFIXES = ("SQ_", "SRC", "SOURCE")


def _infer_role(trans_name: str) -> str:
    """Infer SOURCE or TARGET role from transformation name heuristic."""
    upper = trans_name.upper()
    for prefix in _SOURCE_PREFIXES:
        if prefix in upper:
            return "SOURCE"
    return "TARGET"


def _get_conn_trans_name(conn_el) -> str:
    """Extract the transformation instance name from a CONNECTIONREFERENCE element."""
    return (
        conn_el.get("TRANSFORMATIONINSTANCENAME")
        or conn_el.get("TRANSFORMATIONNAME")
        or conn_el.get("INSTANCENAME")
        or "UNKNOWN"
    )


def _get_conn_role(conn_el) -> str:
    """Extract and normalize the role from a CONNECTIONREFERENCE element."""
    raw_role = (conn_el.get("ROLE") or "").upper()
    return "SOURCE" if raw_role == "SOURCE" else "TARGET"


def _collect_connections_from_refs(root) -> list[SessionConnection]:
    """Build SessionConnection list from CONNECTIONREFERENCE elements."""
    connections: list[SessionConnection] = []
    for conn_el in root.iter("CONNECTIONREFERENCE"):
        connections.append(SessionConnection(
            transformation_name=_get_conn_trans_name(conn_el),
            role=_get_conn_role(conn_el),
            connection_name=conn_el.get("CONNECTIONNAME") or conn_el.get("DBDNAME"),
            connection_type=conn_el.get("CONNECTIONSUBTYPE") or conn_el.get("CONNECTIONTYPE"),
        ))
    return connections


def _is_connection_attr(attr_name: str) -> bool:
    return "connection" in attr_name


def _get_sess_attr_parts(attr) -> tuple[str, str, str]:
    """Extract (attr_name_lower, trans_name, attr_value) from SESSTRANSFORMINSTATTR."""
    attr_name  = (attr.get("ATTRIBUTENAME") or "").lower()
    trans_name = attr.get("TRANSFORMATIONINSTANCENAME") or attr.get("INSTANCENAME") or ""
    attr_value = attr.get("ATTRIBUTEVALUE") or ""
    return attr_name, trans_name, attr_value


def _collect_connections_from_sess_attrs(session_el) -> list[SessionConnection]:
    """Fallback: extract connections from SESSTRANSFORMINSTATTR elements."""
    connections: list[SessionConnection] = []
    for attr in session_el.iter("SESSTRANSFORMINSTATTR"):
        attr_name, trans_name, attr_value = _get_sess_attr_parts(attr)
        if _is_connection_attr(attr_name) and attr_value and trans_name:
            connections.append(SessionConnection(
                transformation_name=trans_name,
                role=_infer_role(trans_name),
                connection_name=attr_value,
            ))
    return connections


def _is_file_name_attr(attr_name: str) -> bool:
    return "file name" in attr_name or "filename" in attr_name


def _is_file_dir_attr(attr_name: str) -> bool:
    return "file dir" in attr_name or "filedir" in attr_name


def _find_connection_by_trans(connections: list[SessionConnection], trans_name: str):
    """Return the first connection matching trans_name, or None."""
    return next((c for c in connections if c.transformation_name == trans_name), None)


def _apply_file_name_attr(
    trans_name: str,
    attr_value: str,
    connections: list[SessionConnection],
) -> None:
    """Set file_name on existing connection or add a new FILE connection."""
    existing = _find_connection_by_trans(connections, trans_name)
    if existing:
        existing.file_name = attr_value
    else:
        connections.append(SessionConnection(
            transformation_name=trans_name,
            role=_infer_role(trans_name),
            file_name=attr_value,
            connection_type="FILE",
        ))


def _apply_file_attrs_to_connections(
    session_el,
    connections: list[SessionConnection],
) -> None:
    """Mutate connections list to add file_name / file_dir from session attributes."""
    for attr in session_el.iter("SESSTRANSFORMINSTATTR"):
        attr_name, trans_name, attr_value = _get_sess_attr_parts(attr)
        if _is_file_name_attr(attr_name):
            _apply_file_name_attr(trans_name, attr_value, connections)
        elif _is_file_dir_attr(attr_name):
            existing = _find_connection_by_trans(connections, trans_name)
            if existing:
                existing.file_dir = attr_value


def _build_connections(root, session_el) -> list[SessionConnection]:
    """Build the full connection list using CONNECTIONREFERENCE first, then fallback."""
    connections = _collect_connections_from_refs(root)
    if not connections:
        connections = _collect_connections_from_sess_attrs(session_el)
    _apply_file_attrs_to_connections(session_el, connections)
    return connections


def _find_workflow_name(root) -> str:
    """Extract workflow name from the XML root."""
    workflow_el = root.find(".//WORKFLOW") or root.find(".//WORKFLOW[@NAME]")
    return (workflow_el.get("NAME") if workflow_el is not None else None) or "UNKNOWN_WORKFLOW"


def _get_session_name(session_el) -> str:
    """Extract session name from element, defaulting to UNKNOWN_SESSION."""
    return session_el.get("NAME") or session_el.get("TASKNAME") or "UNKNOWN_SESSION"


def _extract_session_config(
    workflow_xml: str,
    param_lookup: dict[str, str],
) -> tuple[Optional[SessionConfig], list[str]]:
    """
    Extract a SessionConfig from the Workflow XML.

    Returns (SessionConfig or None, list_of_unresolved_variable_names).
    """
    try:
        root = safe_parse_xml(workflow_xml)
    except Exception:
        return None, []

    session_el = _find_session_element(root)
    if session_el is None:
        return None, []

    session_name  = _get_session_name(session_el)
    mapping_name  = session_el.get("MAPPINGNAME") or "UNKNOWN_MAPPING"
    workflow_name = _find_workflow_name(root)

    raw_attributes, all_unresolved = _collect_raw_attributes(session_el, param_lookup)

    (pre_sql, post_sql, reject_fname, reject_fdir,
     commit_interval, error_threshold) = _get_well_known_attrs(raw_attributes)

    connections = _build_connections(root, session_el)

    return SessionConfig(
        session_name=session_name,
        mapping_name=mapping_name,
        workflow_name=workflow_name,
        connections=connections,
        pre_session_sql=pre_sql,
        post_session_sql=post_sql,
        commit_interval=commit_interval,
        error_threshold=error_threshold,
        reject_filename=reject_fname,
        reject_filedir=reject_fdir,
        raw_attributes=raw_attributes,
    ), list(set(all_unresolved))
