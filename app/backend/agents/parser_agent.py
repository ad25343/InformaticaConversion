# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
STEP 1 — XML Parser Agent
Deterministic lxml-based parser. Extracts all Informatica PowerCenter objects
and builds a structured representation of the mapping graph.

v2.12: Mapplet inline expansion — <MAPPLET> definitions are expanded into each
mapping that references them, replacing the black-box instance with its full
set of transformations and connectors so downstream agents see resolved logic.
"""
from __future__ import annotations
import re
from typing import Any
from lxml import etree

from ..models.schemas import ParseReport, ParseFlag
from ..security import safe_parse_xml
from ..org_config_loader import get_unsupported_types as _get_cfg_unsupported_types


# ─────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────

def _make_empty_graph() -> dict[str, Any]:
    return {
        "mappings":    [],
        "workflows":   [],
        "sources":     [],
        "targets":     [],
        "parameters":  [],
        "connections": [],
        "mapplets":    [],
    }


def _parse_failed_report(error: Exception) -> ParseReport:
    msg = str(error)
    return ParseReport(
        objects_found={},
        reusable_components=[],
        unresolved_parameters=[],
        malformed_xml=[msg],
        unrecognized_elements=[],
        flags=[ParseFlag(flag_type="PARSE_ERROR", element="root", detail=msg)],
        parse_status="FAILED",
        mapping_names=[],
    )


def _scan_sources(root: etree._Element, graph: dict, counts: dict) -> None:
    for src in root.iter("SOURCE"):
        counts["Source"] = counts.get("Source", 0) + 1
        graph["sources"].append(_extract_source(src))
    _merge_flatfile_sq_attribs(root, graph["sources"])


def _scan_targets(root: etree._Element, graph: dict, counts: dict) -> None:
    for tgt in root.iter("TARGET"):
        counts["Target"] = counts.get("Target", 0) + 1
        graph["targets"].append(_extract_target(tgt))


def _scan_mapplets(
    root: etree._Element,
    graph: dict,
    counts: dict,
    flags: list,
) -> tuple[dict[str, dict], list[str]]:
    mapplet_defs: dict[str, dict] = {}
    mapplets_detected: list[str] = []
    for mlt in root.iter("MAPPLET"):
        mlt_name = mlt.get("NAME", "")
        if not mlt_name:
            continue
        counts["Mapplet"] = counts.get("Mapplet", 0) + 1
        defn = _extract_mapplet_def(mlt, flags)
        mapplet_defs[mlt_name] = defn
        graph["mapplets"].append({"name": mlt_name, "source": "definition"})
        if mlt_name not in mapplets_detected:
            mapplets_detected.append(mlt_name)
    return mapplet_defs, mapplets_detected


def _scan_mappings(
    root: etree._Element,
    graph: dict,
    counts: dict,
    flags: list,
    reusable: list,
    unresolved_params: list,
    mapplet_defs: dict,
) -> None:
    for mapping in root.iter("MAPPING"):
        counts["Mapping"] = counts.get("Mapping", 0) + 1
        # In Informatica XML, TRANSFORMATIONs are siblings of MAPPING under FOLDER,
        # not children of MAPPING. Pass the parent FOLDER element so _extract_mapping
        # can find transformations defined at the folder level.
        folder_el = _find_parent_folder(root, mapping)
        m = _extract_mapping(mapping, flags, reusable, unresolved_params, mapplet_defs, folder_el)
        graph["mappings"].append(m)


def _find_parent_folder(root: etree._Element, target: etree._Element) -> etree._Element | None:
    """Walk the tree to find the FOLDER parent of a given element."""
    for folder in root.iter("FOLDER"):
        for child in folder:
            if child is target:
                return folder
            # Also check if MAPPING is nested deeper
            if child.tag == "MAPPING" or target in child.iter("MAPPING"):
                pass
        # Direct iteration over folder's children
        if target in list(folder):
            return folder
    return None


def _scan_workflows(root: etree._Element, graph: dict, counts: dict) -> None:
    for wf in root.iter("WORKFLOW"):
        counts["Workflow"] = counts.get("Workflow", 0) + 1
        graph["workflows"].append(_extract_workflow(wf))


def _scan_reusable_transformations(
    root: etree._Element, reusable: list, counts: dict
) -> None:
    for rt in root.iter("TRANSFORMATIONS"):
        for child in rt:
            if child.get("REUSABLE", "NO") == "YES":
                name = child.get("NAME", "unknown")
                reusable.append(f"{child.tag}:{name}")
                counts["ReusableTransformation"] = counts.get("ReusableTransformation", 0) + 1


def _scan_parameters(
    root: etree._Element, graph: dict, counts: dict, flags: list, unresolved_params: list
) -> None:
    for param in root.iter("PARAMETER"):
        name = param.get("NAME", "")
        value = param.get("VALUE", "")
        graph["parameters"].append({"name": name, "value": value})
        counts["Parameter"] = counts.get("Parameter", 0) + 1
        if not value and name:
            unresolved_params.append(name)
            flags.append(ParseFlag(
                flag_type="UNRESOLVED_PARAMETER",
                element=name,
                detail="Parameter has no default value in the XML"
            ))


def _collect_expanded_mapplets(graph: dict) -> list[str]:
    mapplets_expanded: list[str] = []
    for m in graph["mappings"]:
        for exp_name in m.get("mapplet_expansions", []):
            if exp_name not in mapplets_expanded:
                mapplets_expanded.append(exp_name)
    return mapplets_expanded


def _add_mapplet_detected_flags(flags: list, mapplets_detected: list) -> None:
    for f in flags:
        if f.flag_type == "MAPPLET_DETECTED" and f.element not in mapplets_detected:
            mapplets_detected.append(f.element)


def _emit_mapplet_expanded_flags(flags: list, mapplets_expanded: list) -> None:
    for mlt_name in mapplets_expanded:
        flags.append(ParseFlag(
            flag_type="MAPPLET_EXPANDED",
            element=mlt_name,
            detail=(
                f"Mapplet '{mlt_name}' was inline-expanded: its internal transformations "
                "and connectors have been added to the mapping graph and its external "
                "connectors rewired through the Input/Output interface nodes. "
                "Review the generated code to verify completeness of the expanded logic."
            )
        ))


def _no_mappings(graph: dict) -> bool:
    return not graph["mappings"]


def _status_from_flags(flags: list) -> str:
    has_blocking = any(f.flag_type == "PARSE_ERROR" for f in flags)
    if has_blocking:
        return "FAILED"
    if flags:
        return "PARTIAL"
    return "COMPLETE"


def _determine_parse_status(graph: dict, flags: list) -> str:
    if _no_mappings(graph) and graph["workflows"]:
        return "FAILED"
    if _no_mappings(graph) and not graph["workflows"]:
        return "PARTIAL"
    return _status_from_flags(flags)


def _insert_wrong_file_type_flag(graph: dict, flags: list) -> None:
    wf_names = ", ".join(w.get("name", "?") for w in graph["workflows"][:5])
    flags.insert(0, ParseFlag(
        flag_type="WRONG_FILE_TYPE",
        element="root",
        detail=(
            f"This file contains {len(graph['workflows'])} Workflow definition(s) "
            f"({wf_names}) but no Mapping definitions. "
            "It looks like you uploaded a Workflow XML as the primary mapping file. "
            "Please re-upload: put the Mapping XML (.xml from Informatica Designer) "
            "in the required 'Mapping XML' field, and optionally put this file in "
            "the 'Workflow XML' field."
        )
    ))


def _insert_unknown_element_flag(flags: list) -> None:
    flags.append(ParseFlag(
        flag_type="UNKNOWN_ELEMENT",
        element="root",
        detail="No MAPPING or WORKFLOW elements found — file may be a partial export"
    ))


def _emit_empty_result_flags(graph: dict, flags: list) -> None:
    """Insert appropriate flags when no mappings were found."""
    if not graph["mappings"] and graph["workflows"]:
        _insert_wrong_file_type_flag(graph, flags)
    elif not graph["mappings"] and not graph["workflows"]:
        _insert_unknown_element_flag(flags)


def parse_xml(xml_content: str) -> tuple[ParseReport, dict]:
    """
    Parse Informatica PowerCenter XML.
    Returns (ParseReport, graph_dict) where graph_dict is the full
    internal representation passed to downstream agents.
    """
    flags: list[ParseFlag] = []
    graph = _make_empty_graph()

    try:
        root = safe_parse_xml(xml_content)
    except etree.XMLSyntaxError as e:
        return _parse_failed_report(e), graph

    counts: dict[str, int] = {}
    reusable: list[str] = []
    unresolved_params: list[str] = []

    _scan_sources(root, graph, counts)
    _scan_targets(root, graph, counts)
    mapplet_defs, mapplets_detected = _scan_mapplets(root, graph, counts, flags)
    _scan_mappings(root, graph, counts, flags, reusable, unresolved_params, mapplet_defs)
    _scan_workflows(root, graph, counts)
    _scan_reusable_transformations(root, reusable, counts)
    _scan_parameters(root, graph, counts, flags, unresolved_params)

    mapplets_expanded = _collect_expanded_mapplets(graph)
    _add_mapplet_detected_flags(flags, mapplets_detected)
    _emit_mapplet_expanded_flags(flags, mapplets_expanded)

    parse_status = _determine_parse_status(graph, flags)
    _emit_empty_result_flags(graph, flags)

    mapping_names = [m["name"] for m in graph["mappings"]]

    completeness_score, completeness_signals = _compute_completeness_score(
        graph, unresolved_params
    )

    return ParseReport(
        objects_found=counts,
        reusable_components=reusable,
        unresolved_parameters=unresolved_params,
        malformed_xml=[],
        unrecognized_elements=[],
        flags=flags,
        parse_status=parse_status,
        mapping_names=mapping_names,
        mapplets_detected=mapplets_detected,
        mapplets_expanded=mapplets_expanded,
        completeness_score=completeness_score,
        completeness_signals=completeness_signals,
    ), graph


# ─────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────

def _extract_mapplet_def(mlt_el: etree._Element, flags: list) -> dict:
    """
    Extract a mapplet definition for inline expansion.
    Returns a dict containing all internal transformations, connectors,
    and the names of the Input / Output interface transformations.
    """
    transformations: list[dict] = []
    connectors: list[dict] = []
    input_trans_name: str = "Input"
    output_trans_name: str = "Output"

    for trans in mlt_el.iter("TRANSFORMATION"):
        t = _extract_transformation(trans, flags)
        transformations.append(t)
        ttype = trans.get("TYPE", "")
        if ttype == "Input Transformation":
            input_trans_name = trans.get("NAME", "Input")
        elif ttype == "Output Transformation":
            output_trans_name = trans.get("NAME", "Output")

    for conn in mlt_el.iter("CONNECTOR"):
        connectors.append({
            "from_instance": conn.get("FROMINSTANCE", ""),
            "from_field":    conn.get("FROMFIELD", ""),
            "to_instance":   conn.get("TOINSTANCE", ""),
            "to_field":      conn.get("TOFIELD", ""),
        })

    return {
        "name":               mlt_el.get("NAME", ""),
        "transformations":    transformations,
        "connectors":         connectors,
        "input_trans_name":   input_trans_name,
        "output_trans_name":  output_trans_name,
    }


def _prefix_mapplet_transformations(
    defn: dict, prefix: str
) -> list[dict]:
    result = []
    for t in defn["transformations"]:
        prefixed: dict = dict(t)
        prefixed["name"] = f"{prefix}__{t['name']}"
        prefixed["_mapplet_source"] = defn["name"]
        result.append(prefixed)
    return result


def _prefix_mapplet_connectors(defn: dict, prefix: str) -> list[dict]:
    return [
        {
            "from_instance": f"{prefix}__{c['from_instance']}",
            "from_field":    c["from_field"],
            "to_instance":   f"{prefix}__{c['to_instance']}",
            "to_field":      c["to_field"],
        }
        for c in defn["connectors"]
    ]


def _rewire_external_connectors(
    connectors: list, mapplet_inst_to_def: dict, mapplet_defs: dict
) -> list[dict]:
    rewired: list[dict] = []
    for c in connectors:
        new_c = dict(c)
        to_inst = c["to_instance"]
        from_inst = c["from_instance"]
        if to_inst in mapplet_inst_to_def:
            defn = mapplet_defs[mapplet_inst_to_def[to_inst]]
            new_c["to_instance"] = f"{to_inst}__{defn['input_trans_name']}"
        if from_inst in mapplet_inst_to_def:
            defn = mapplet_defs[mapplet_inst_to_def[from_inst]]
            new_c["from_instance"] = f"{from_inst}__{defn['output_trans_name']}"
        rewired.append(new_c)
    return rewired


def _build_mapplet_inst_to_def(
    instance_map: dict[str, str], mapplet_defs: dict[str, dict]
) -> dict[str, str]:
    """Return a filtered dict mapping instance names to mapplet definition names."""
    return {
        inst_name: trans_name
        for inst_name, trans_name in instance_map.items()
        if trans_name in mapplet_defs
    }


def _expand_single_mapplet(
    inst_name: str,
    mlt_def_name: str,
    mapplet_defs: dict[str, dict],
    extra_transformations: list,
    extra_connectors: list,
    expanded_def_names: list,
) -> None:
    """Expand one mapplet instance: accumulate prefixed transforms, connectors, and def names."""
    defn = mapplet_defs[mlt_def_name]
    extra_transformations.extend(_prefix_mapplet_transformations(defn, inst_name))
    extra_connectors.extend(_prefix_mapplet_connectors(defn, inst_name))
    if mlt_def_name not in expanded_def_names:
        expanded_def_names.append(mlt_def_name)


def _inline_expand_mapplets(
    mapping_name: str,
    transformations: list,
    connectors: list,
    instance_map: dict[str, str],   # instance_name → transformation_name
    mapplet_defs: dict[str, dict],
    flags: list,
) -> tuple[list, list, list[str]]:
    """
    Replace each mapplet INSTANCE in the mapping with the inline transformations
    and connectors from its definition.

    Prefix convention: ``{instance_name}__{internal_node_name}``
    Using the instance name (not the definition name) ensures two instances of the
    same mapplet in one mapping get distinct node names.

    Returns:
        (expanded_transformations, expanded_connectors, expanded_mapplet_def_names)
    """
    mapplet_inst_to_def = _build_mapplet_inst_to_def(instance_map, mapplet_defs)

    if not mapplet_inst_to_def:
        return transformations, connectors, []

    extra_transformations: list[dict] = []
    extra_connectors: list[dict] = []
    expanded_def_names: list[str] = []

    for inst_name, mlt_def_name in mapplet_inst_to_def.items():
        _expand_single_mapplet(
            inst_name, mlt_def_name, mapplet_defs,
            extra_transformations, extra_connectors, expanded_def_names,
        )

    rewired = _rewire_external_connectors(connectors, mapplet_inst_to_def, mapplet_defs)

    return (
        transformations + extra_transformations,
        rewired + extra_connectors,
        expanded_def_names,
    )


def _flag_missing_mapplet(
    flags: list, inst_name: str, trans_name: str, mapping_name: str
) -> None:
    already = any(
        f.flag_type == "MAPPLET_DETECTED" and f.element == trans_name
        for f in flags
    )
    if already:
        return
    flags.append(ParseFlag(
        flag_type="MAPPLET_DETECTED",
        element=trans_name,
        detail=(
            f"Mapplet '{trans_name}' is referenced in mapping '{mapping_name}' "
            "but its definition block was not found in this export. "
            "Re-export the mapping with 'Include Dependencies' enabled in "
            "Informatica Repository Manager to allow full inline expansion. "
            "Until then, verify any references to "
            f"'{trans_name}' in the generated code manually."
        )
    ))


def _scan_mapping_instances(
    mapping_el: etree._Element,
    mapping_name: str,
    mapplet_defs: dict,
    flags: list,
) -> dict[str, str]:
    """Scan INSTANCE elements; flag missing mapplets. Returns instance_map."""
    instance_map: dict[str, str] = {}
    for inst in mapping_el.iter("INSTANCE"):
        inst_name = inst.get("NAME", "")
        trans_name = inst.get("TRANSFORMATION_NAME", inst_name)
        trans_type = inst.get("TYPE", "")
        instance_map[inst_name] = trans_name
        if trans_type == "Mapplet" and trans_name and trans_name not in mapplet_defs:
            _flag_missing_mapplet(flags, inst_name, trans_name, mapping_name)
    return instance_map


def _scan_mapping_connectors(mapping_el: etree._Element) -> list[dict]:
    return [
        {
            "from_instance": conn.get("FROMINSTANCE", ""),
            "from_field":    conn.get("FROMFIELD", ""),
            "to_instance":   conn.get("TOINSTANCE", ""),
            "to_field":      conn.get("TOFIELD", ""),
        }
        for conn in mapping_el.iter("CONNECTOR")
    ]


def _scan_mapping_variables(
    mapping_el: etree._Element, unresolved_params: list
) -> list[dict]:
    mapping_params: list[dict] = []
    for param in mapping_el.iter("MAPPINGVARIABLE"):
        pname = param.get("NAME", "")
        dtype = param.get("DATATYPE", "")
        default = param.get("DEFAULTVALUE", "")
        mapping_params.append({"name": pname, "datatype": dtype, "default": default})
        if not default:
            unresolved_params.append(pname)
    return mapping_params


def _extract_mapping(
    mapping_el: etree._Element,
    flags: list,
    reusable: list,
    unresolved_params: list,
    mapplet_defs: dict[str, dict] | None = None,
    folder_el: etree._Element | None = None,
) -> dict:
    if mapplet_defs is None:
        mapplet_defs = {}

    name = mapping_el.get("NAME", "unknown")

    instance_map = _scan_mapping_instances(mapping_el, name, mapplet_defs, flags)

    # In Informatica XML, TRANSFORMATION elements can be either:
    # 1. Children of MAPPING (inline transforms) — common in some exports
    # 2. Children of FOLDER (siblings of MAPPING) — standard PowerCenter export format
    # Search both locations to handle all XML variants.
    transformations = [
        _extract_transformation(trans, flags)
        for trans in mapping_el.iter("TRANSFORMATION")
    ]
    if not transformations and folder_el is not None:
        # Transformations are at FOLDER level — extract those referenced by this mapping's INSTANCEs
        instance_names = set(instance_map.values()) | set(instance_map.keys())
        for trans in folder_el.findall("TRANSFORMATION"):
            tname = trans.get("NAME", "")
            if tname in instance_names or not instance_names:
                transformations.append(_extract_transformation(trans, flags))

    connectors = _scan_mapping_connectors(mapping_el)

    expanded_mlt_names: list[str] = []
    if mapplet_defs:
        transformations, connectors, expanded_mlt_names = _inline_expand_mapplets(
            name, transformations, connectors, instance_map, mapplet_defs, flags
        )

    mapping_params = _scan_mapping_variables(mapping_el, unresolved_params)

    return {
        "name":               name,
        "description":        mapping_el.get("DESCRIPTION", ""),
        "transformations":    transformations,
        "connectors":         connectors,
        "parameters":         mapping_params,
        "instance_map":       instance_map,
        "mapplet_expansions": expanded_mlt_names,
    }


def _extract_sorter_port_extras(field: etree._Element, ttype: str) -> dict:
    """Return sort_key_position / sort_direction extras for Sorter transformations."""
    extras: dict = {}
    if ttype != "Sorter":
        return extras
    sort_pos = field.get("SORTKEYPOSITION", "")
    sort_dir = field.get("SORTDIRECTION", "")
    if sort_pos:
        extras["sort_key_position"] = sort_pos
    if sort_dir:
        extras["sort_direction"] = sort_dir
    return extras


def _extract_transformation(trans_el: etree._Element, flags: list) -> dict:
    name = trans_el.get("NAME", "unknown")
    ttype = trans_el.get("TYPE", "unknown")
    reusable = trans_el.get("REUSABLE", "NO")
    ports: list[dict] = []
    expressions: list[dict] = []

    for field in trans_el.iter("TRANSFORMFIELD"):
        port = {
            "name":       field.get("NAME", ""),
            "datatype":   field.get("DATATYPE", ""),
            "porttype":   field.get("PORTTYPE", ""),
            "expression": field.get("EXPRESSION", ""),
            "default":    field.get("DEFAULTVALUE", ""),
        }
        port.update(_extract_sorter_port_extras(field, ttype))
        ports.append(port)
        if port["expression"]:
            expressions.append({
                "port":       port["name"],
                "expression": port["expression"],
            })

    table_attribs: dict[str, str] = {
        ta.get("NAME", ""): ta.get("VALUE", "")
        for ta in trans_el.iter("TABLEATTRIBUTE")
    }

    _flag_unsupported_transformation(ttype, name, flags)

    return {
        "name":          name,
        "type":          ttype,
        "reusable":      reusable == "YES",
        "ports":         ports,
        "expressions":   expressions,
        "table_attribs": table_attribs,
    }


def _flag_unsupported_transformation(ttype: str, name: str, flags: list) -> None:
    unsupported_types = {
        "Java Transformation", "External Procedure", "Advanced External Procedure",
        "Stored Procedure"
    }
    if ttype in unsupported_types:
        flags.append(ParseFlag(
            flag_type="UNSUPPORTED_TRANSFORMATION",
            element=name,
            detail=f"Transformation type '{ttype}' is not supported for automated conversion"
        ))


def _match_flat_source_for_sq(
    sq_name: str, table_name: str, flat_sources: dict
) -> dict | None:
    """Return the matching flat source dict or None."""
    for src_name, src in flat_sources.items():
        if sq_name == f"SQ_{src_name}" or table_name == src_name:
            return src
    return None


_DELIMITER_MAP = {
    "COMMA": ",", "TAB": "\t", "PIPE": "|",
    "SEMICOLON": ";", "SPACE": " ",
}


def _apply_sq_file_path_attribs(ff: dict, attribs: dict) -> None:
    """Apply file name, directory, and delimiter from SQ attribs."""
    if attribs.get("Source File Name"):
        ff["file_name"] = attribs["Source File Name"]
    if attribs.get("Source File Directory"):
        ff["file_dir"] = attribs["Source File Directory"]
    if attribs.get("Delimiter"):
        raw = attribs["Delimiter"]
        ff["delimiter"] = _DELIMITER_MAP.get(raw.upper(), raw)


def _apply_sq_row_attribs(ff: dict, attribs: dict) -> None:
    """Apply header and row delimiter from SQ attribs."""
    if "Skip Header" in attribs:
        ff["has_header"] = attribs["Skip Header"] != "NO"
    if "Row Delimiter" in attribs:
        ff["row_delimiter"] = attribs["Row Delimiter"]


def _apply_sq_attribs_to_source(matched_src: dict, attribs: dict) -> None:
    """Merge SQ TABLEATTRIBUTE values into the flat file source metadata."""
    ff = matched_src.setdefault("flat_file", {})
    _apply_sq_file_path_attribs(ff, attribs)
    _apply_sq_row_attribs(ff, attribs)


def _index_flat_sources(sources: list[dict]) -> dict[str, dict]:
    """Return a name→source dict for flat file sources only."""
    return {s["name"]: s for s in sources if s.get("db_type") == "Flat File"}


def _process_sq_element(
    trans_el: etree._Element, flat_sources: dict
) -> None:
    """Match a Source Qualifier element to a flat source and merge its attribs."""
    attribs: dict[str, str] = {
        ta.get("NAME", ""): ta.get("VALUE", "")
        for ta in trans_el.iter("TABLEATTRIBUTE")
    }
    sq_name = trans_el.get("NAME", "")
    table_name = attribs.get("Source Table Name", "")
    matched_src = _match_flat_source_for_sq(sq_name, table_name, flat_sources)
    if matched_src is not None:
        _apply_sq_attribs_to_source(matched_src, attribs)


def _merge_flatfile_sq_attribs(root: etree._Element, sources: list[dict]) -> None:
    """
    For every flat file source in *sources*, locate the paired Source Qualifier
    and pull "Source File Name", "Source File Directory", and "Delimiter" from
    its TABLEATTRIBUTE nodes.  These values take precedence over anything
    extracted from the SOURCE element itself (they are more reliable).

    Informatica stores the SQ paired to a flat file source with the naming
    convention SQ_<SOURCE_NAME>.  We try that first, then fall back to any
    Source Qualifier whose TABLEATTRIBUTE "Source Table Name" matches.
    """
    flat_sources = _index_flat_sources(sources)
    if not flat_sources:
        return

    for trans_el in root.iter("TRANSFORMATION"):
        if trans_el.get("TYPE") != "Source Qualifier":
            continue
        _process_sq_element(trans_el, flat_sources)


def _extract_source(src_el: etree._Element) -> dict:
    fields = []
    for f in src_el.iter("SOURCEFIELD"):
        fields.append({
            "name":     f.get("NAME", ""),
            "datatype": f.get("DATATYPE", ""),
            "length":   f.get("LENGTH", ""),
        })
    result = {
        "name":        src_el.get("NAME", ""),
        "db_type":     src_el.get("DATABASETYPE", ""),
        "owner":       src_el.get("OWNERNAME", ""),
        "db_name":     src_el.get("DBDNAME", ""),
        "description": src_el.get("DESCRIPTION", ""),
        "fields":      fields,
    }

    # For flat file sources Informatica stores file metadata on the SOURCE
    # element itself (FILE_NAME, DELIMITER, SKIP_ROWS) and on the paired
    # Source Qualifier's TABLEATTRIBUTE nodes.  Capture what we can from the
    # SOURCE element here; the SQ TABLEATTRIBUTE values are merged in
    # _merge_flatfile_sq_attribs() during the mapping extraction pass.
    if result["db_type"] == "Flat File":
        result["flat_file"] = {
            "file_name":  src_el.get("FILE_NAME", ""),
            "file_dir":   src_el.get("FILE_DIR", ""),
            "delimiter":  src_el.get("DELIMITER", ","),
            "has_header": src_el.get("HASHEADER", "YES") != "NO",
            "skip_rows":  int(src_el.get("SKIPROWS", "0") or "0"),
        }
    return result


def _extract_target(tgt_el: etree._Element) -> dict:
    fields = []
    for f in tgt_el.iter("TARGETFIELD"):
        fields.append({
            "name":     f.get("NAME", ""),
            "datatype": f.get("DATATYPE", ""),
            "length":   f.get("LENGTH", ""),
        })
    return {
        "name":        tgt_el.get("NAME", ""),
        "db_type":     tgt_el.get("DATABASETYPE", ""),
        "owner":       tgt_el.get("OWNERNAME", ""),
        "db_name":     tgt_el.get("DBDNAME", ""),
        "description": tgt_el.get("DESCRIPTION", ""),
        "fields":      fields,
    }


# ─────────────────────────────────────────────
# v2.24.0 — Source Completeness Scoring
# ─────────────────────────────────────────────

def _score_expression_coverage(all_trans: list[dict]) -> dict:
    """
    Score 35 pts: fraction of Expression-transformation ports that carry
    a non-trivial expression (contains a function call or operator).
    If no Expression transformations exist → full 35 (no gap to penalise).
    """
    MAX = 35
    exp_trans = [t for t in all_trans if "expression" in t.get("type", "").lower()]
    if not exp_trans:
        return {"score": MAX, "max": MAX, "detail": "no Expression transformations (full score)"}

    total_ports = 0
    complex_ports = 0
    for t in exp_trans:
        for p in t.get("ports", []):
            expr = p.get("expression", "")
            if not expr:
                continue
            total_ports += 1
            # Non-trivial = contains a function call token, IIF/DECODE/date/string funcs,
            # arithmetic operator, or a literal (not just a bare field passthrough).
            bare_field = re.match(r"^\s*[\w$.]+\s*$", expr) is None
            if bare_field:
                complex_ports += 1

    if total_ports == 0:
        return {"score": MAX, "max": MAX, "detail": "Expression ports have no expressions (full score)"}

    frac = complex_ports / total_ports
    score = round(MAX * frac, 1)
    return {
        "score": score,
        "max": MAX,
        "detail": f"{complex_ports}/{total_ports} expression ports have explicit logic",
    }


def _score_joiner_conditions(all_trans: list[dict]) -> dict:
    """
    Score 20 pts: fraction of Joiner transformations that have a
    'Join Condition' TABLEATTRIBUTE defined.
    """
    MAX = 20
    joiners = [t for t in all_trans if "joiner" in t.get("type", "").lower()]
    if not joiners:
        return {"score": MAX, "max": MAX, "detail": "no Joiner transformations (full score)"}

    with_condition = sum(
        1 for j in joiners
        if j.get("table_attribs", {}).get("Join Condition", "").strip()
    )
    frac = with_condition / len(joiners)
    score = round(MAX * frac, 1)
    return {
        "score": score,
        "max": MAX,
        "detail": f"{with_condition}/{len(joiners)} Joiners have a Join Condition defined",
    }


def _score_router_conditions(all_trans: list[dict]) -> dict:
    """
    Score 15 pts: Router transformations should have at least one non-default
    Group Filter Condition in their TABLEATTRIBUTE map.
    A Router with no condition is a pass-through — not wrong, but worth noting.
    """
    MAX = 15
    routers = [t for t in all_trans if "router" in t.get("type", "").lower()]
    if not routers:
        return {"score": MAX, "max": MAX, "detail": "no Router transformations (full score)"}

    # Inspect TABLEATTRIBUTE for "Group Filter Condition" or similar.
    # Informatica Router groups use TABLEATTRIBUTE NAME="Group Filter Condition i"
    with_condition = 0
    for r in routers:
        attribs = r.get("table_attribs", {})
        has_any = any(
            "group filter" in k.lower() and v.strip()
            for k, v in attribs.items()
        )
        if has_any:
            with_condition += 1
    frac = with_condition / len(routers)
    score = round(MAX * frac, 1)
    return {
        "score": score,
        "max": MAX,
        "detail": f"{with_condition}/{len(routers)} Routers have Group Filter Conditions defined",
    }


def _score_lookup_conditions(all_trans: list[dict]) -> dict:
    """
    Score 15 pts: fraction of Lookup transformations that have a
    'Lookup Condition' TABLEATTRIBUTE defined.
    """
    MAX = 15
    lookups = [t for t in all_trans if "lookup" in t.get("type", "").lower()]
    if not lookups:
        return {"score": MAX, "max": MAX, "detail": "no Lookup transformations (full score)"}

    with_condition = sum(
        1 for lkp in lookups
        if lkp.get("table_attribs", {}).get("Lookup Condition", "").strip()
    )
    frac = with_condition / len(lookups)
    score = round(MAX * frac, 1)
    return {
        "score": score,
        "max": MAX,
        "detail": f"{with_condition}/{len(lookups)} Lookups have a Lookup Condition defined",
    }


def _score_unresolved_params(unresolved_params: list[str]) -> dict:
    """
    Score 10 pts: deduct 1 pt per unresolved $$PARAMETER, capped at 10 deductions.
    0 unresolved → full 10; ≥10 unresolved → 0.
    """
    MAX = 10
    n = min(len(unresolved_params), MAX)
    score = round(MAX - n, 1)
    return {
        "score": score,
        "max": MAX,
        "detail": f"{len(unresolved_params)} unresolved $$PARAMETER(s) ({n} pts deducted)",
    }


def _score_sql_complexity(all_trans: list[dict]) -> dict:
    """
    Score 5 pts: custom SQL overrides in Source Qualifier TABLEATTRIBUTE.
    No SQL → full 5. Short custom SQL (≤500 chars) → 3. Long complex SQL → 0.
    """
    MAX = 5
    sq_trans = [t for t in all_trans if "source qualifier" in t.get("type", "").lower()]
    complex_sqls = []
    for t in sq_trans:
        sql = t.get("table_attribs", {}).get("Sql Query", "").strip()
        if sql:
            complex_sqls.append(len(sql))

    if not complex_sqls:
        return {"score": MAX, "max": MAX, "detail": "no custom SQL overrides (full score)"}

    longest = max(complex_sqls)
    if longest > 500:
        score = 0.0
        detail = f"complex SQL override ({longest} chars) — manual review required"
    else:
        score = 3.0
        detail = f"short custom SQL override ({longest} chars)"
    return {"score": score, "max": MAX, "detail": detail}


def _compute_completeness_score(
    graph: dict, unresolved_params: list[str]
) -> tuple[float, dict]:
    """
    Compute the Source Completeness Score (0–100).

    Components (all 5 add up to max 100):
      - expression_coverage   35 pts
      - joiner_conditions     20 pts
      - router_conditions     15 pts
      - lookup_conditions     15 pts
      - unresolved_params     10 pts
      - sql_complexity         5 pts
                             ─────────
                             100 pts

    Returns (rounded_score, signals_dict).
    """
    all_trans: list[dict] = []
    for mapping in graph.get("mappings", []):
        all_trans.extend(mapping.get("transformations", []))

    signals = {
        "expression_coverage":  _score_expression_coverage(all_trans),
        "joiner_conditions":     _score_joiner_conditions(all_trans),
        "router_conditions":     _score_router_conditions(all_trans),
        "lookup_conditions":     _score_lookup_conditions(all_trans),
        "unresolved_params":     _score_unresolved_params(unresolved_params),
        "sql_complexity":        _score_sql_complexity(all_trans),
    }

    total = sum(v["score"] for v in signals.values())
    score = round(min(100.0, max(0.0, total)), 1)
    return score, signals


def _extract_workflow(wf_el: etree._Element) -> dict:
    tasks = []
    for task in wf_el.iter("TASK"):
        tasks.append({
            "name": task.get("NAME", ""),
            "type": task.get("TYPE", ""),
        })
    return {
        "name":  wf_el.get("NAME", ""),
        "tasks": tasks,
    }
