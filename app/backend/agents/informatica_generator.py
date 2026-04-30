# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Informatica PowerCenter XML Generator — spec-based reverse generation.

Reads the 3b Technical Specification (analyst_view_md) and produces
PowerCenter-importable XML that a developer can import into Designer,
validate, and deploy — without building from scratch.

Two entry points:
  generate_from_spec(spec_md, mapping_name)
      Flow 1 — reconstruct/regenerate from an existing 3b spec

  generate_from_new_spec(spec_md, mapping_name)
      Flow 2 — generate from an analyst-authored spec for a net-new mapping
      (same function — different caller; kept separate for future divergence)
"""
from __future__ import annotations

import logging
import xml.etree.ElementTree as ET

from ..config import settings as _cfg

log = logging.getLogger("conversion.informatica_generator")

MODEL       = _cfg.claude_model
_MAX_TOKENS = 16_000   # XML output can be large for complex mappings; 16K handles most

# ── System prompt ─────────────────────────────────────────────────────────────

_SYSTEM = """You are a senior Informatica PowerCenter 10.x developer.
Your task is to generate valid, importable PowerCenter XML from a Technical Specification document.

The specification is structured with these sections — read each one to build the XML:
  Section 2  (Source Systems)        → <SOURCE> blocks + <SOURCEFIELD> children
  Section 3  (Target Systems)        → <TARGET> blocks + <TARGETFIELD> children
  Section 4.1 (Pipeline Overview)    → determines transformation names and order
  Section 4.2 (Joins)               → <TRANSFORMATION TYPE="Joiner">
  Section 4.3 (Lookups)             → <TRANSFORMATION TYPE="Lookup Procedure">
  Section 4.4 (Filters)             → <TRANSFORMATION TYPE="Filter">
  Section 4.5 (Derivations)         → <TRANSFORMATION TYPE="Expression"> with verbatim expressions
  Section 4.6 (Aggregations)        → <TRANSFORMATION TYPE="Aggregator">
  Section 4.7 (Routing)             → <TRANSFORMATION TYPE="Router"> with group conditions
  Section 4.8 (Complete Field Map)  → <CONNECTOR> elements tracing field lineage
  Section 6   (Parameters)          → <PARAMETER> elements if any

======================================================
REQUIRED XML STRUCTURE (follow this exactly)
======================================================

<?xml version="1.0" encoding="Windows-1252"?>
<!DOCTYPE POWERMART SYSTEM "powrmart.dtd">
<POWERMART CREATION_DATE="01/01/2026 00:00:00" REPOSITORY_VERSION="187.94">
<REPOSITORY CODEPAGE="MS1252" DATABASETYPE="Oracle" NAME="DEV_REP" VERSION="187">
<FOLDER DESCRIPTION="" GROUP="" NAME="CONVERSION" OWNER="Administrator"
        PERMISSIONS="rwx---r--" SHARED="NOTSHARED" UUID="">

  <!-- ── SOURCES ── -->
  <SOURCE BUSINESSNAME="" DATABASETYPE="Oracle" DBDNAME="" DESCRIPTION=""
          NAME="TABLE_NAME" OBJECTVERSION="1" OWNERNAME="SCHEMA" VERSIONNUMBER="1">
    <SOURCEFIELD BUSINESSNAME="" DATATYPE="number" DESCRIPTION="" FIELDNUMBER="0"
                 FIELDPROPERTY="0" FIELDTYPE="DEST" HIDDEN="NO" KEYTYPE="NOT A KEY"
                 LENGTH="0" LEVEL="0" NAME="FIELD_NAME" NULLABLE="NULLABLE"
                 OCCURS="0" OFFSET="0" PHYSICALLENGTH="0" PHYSICALOFFSET="0"
                 PICTURETEXT="" PRECISION="10" SCALE="0" USAGE_FLAGS=""/>
  </SOURCE>

  <!-- ── TARGETS ── -->
  <TARGET BUSINESSNAME="" CONSTRAINT="" DATABASETYPE="Oracle" DESCRIPTION=""
          NAME="TARGET_TABLE" OBJECTVERSION="1" TABLEOPTIONS="" VERSIONNUMBER="1">
    <TARGETFIELD BUSINESSNAME="" DATATYPE="number" DESCRIPTION="" FIELDNUMBER="0"
                 KEYTYPE="NOT A KEY" NAME="FIELD_NAME" NULLABLE="NULL"
                 PICTURETEXT="" PRECISION="10" SCALE="0"/>
  </TARGET>

  <!-- ── TRANSFORMATIONS ── -->

  <!-- Source Qualifier (one per source table; output ports match source fields) -->
  <TRANSFORMATION DESCRIPTION="" NAME="SQ_TABLE_NAME" OBJECTVERSION="1"
                  REUSABLE="NO" TYPE="Source Qualifier" VERSIONNUMBER="1">
    <TRANSFORMFIELD DATATYPE="number" DEFAULTVALUE="" DESCRIPTION="" EXPRESSION=""
                    EXPRESSIONTYPE="GENERAL" NAME="FIELD_NAME" PICTURETEXT=""
                    PORTTYPE="OUTPUT" PRECISION="10" SCALE="0"/>
    <TABLEATTRIBUTE NAME="Sql Query" VALUE=""/>
    <TABLEATTRIBUTE NAME="Source Filter" VALUE=""/>
    <TABLEATTRIBUTE NAME="Number Of Distinct Ports" VALUE="0"/>
  </TRANSFORMATION>

  <!-- Expression (INPUT/OUTPUT for pass-through fields; OUTPUT for new derived fields) -->
  <TRANSFORMATION DESCRIPTION="" NAME="EXP_NAME" OBJECTVERSION="1"
                  REUSABLE="NO" TYPE="Expression" VERSIONNUMBER="1">
    <TRANSFORMFIELD DATATYPE="number" DEFAULTVALUE="" DESCRIPTION=""
                    EXPRESSION="FIELD_NAME" EXPRESSIONTYPE="GENERAL"
                    NAME="FIELD_NAME" PICTURETEXT="" PORTTYPE="INPUT/OUTPUT"
                    PRECISION="10" SCALE="0"/>
    <TRANSFORMFIELD DATATYPE="varchar" DEFAULTVALUE="" DESCRIPTION=""
                    EXPRESSION="IIF(ISNULL(STATUS), 'UNKNOWN', STATUS)"
                    EXPRESSIONTYPE="GENERAL" NAME="DERIVED_FIELD" PICTURETEXT=""
                    PORTTYPE="OUTPUT" PRECISION="20" SCALE="0"/>
  </TRANSFORMATION>

  <!-- Joiner -->
  <TRANSFORMATION DESCRIPTION="" NAME="JNR_NAME" OBJECTVERSION="1"
                  REUSABLE="NO" TYPE="Joiner" VERSIONNUMBER="1">
    <TRANSFORMFIELD DATATYPE="number" DEFAULTVALUE="" DESCRIPTION="" EXPRESSION=""
                    EXPRESSIONTYPE="GENERAL" NAME="FIELD_NAME" PICTURETEXT=""
                    PORTTYPE="MASTERINPUT" PRECISION="10" SCALE="0"/>
    <TRANSFORMFIELD DATATYPE="number" DEFAULTVALUE="" DESCRIPTION="" EXPRESSION=""
                    EXPRESSIONTYPE="GENERAL" NAME="FIELD_NAME_D" PICTURETEXT=""
                    PORTTYPE="DETAILINPUT" PRECISION="10" SCALE="0"/>
    <TRANSFORMFIELD DATATYPE="number" DEFAULTVALUE="" DESCRIPTION="" EXPRESSION=""
                    EXPRESSIONTYPE="GENERAL" NAME="OUT_FIELD" PICTURETEXT=""
                    PORTTYPE="OUTPUT" PRECISION="10" SCALE="0"/>
    <TABLEATTRIBUTE NAME="Join Condition" VALUE="MASTER.KEY = DETAIL.KEY"/>
    <TABLEATTRIBUTE NAME="Join Type" VALUE="Normal Join"/>
    <TABLEATTRIBUTE NAME="Case Sensitive String Comparison" VALUE="NO"/>
    <TABLEATTRIBUTE NAME="Null ordering in master" VALUE="Null Is Highest Value"/>
    <TABLEATTRIBUTE NAME="Null ordering in detail" VALUE="Null Is Highest Value"/>
  </TRANSFORMATION>

  <!-- Filter -->
  <TRANSFORMATION DESCRIPTION="" NAME="FIL_NAME" OBJECTVERSION="1"
                  REUSABLE="NO" TYPE="Filter" VERSIONNUMBER="1">
    <TRANSFORMFIELD DATATYPE="number" DEFAULTVALUE="" DESCRIPTION=""
                    EXPRESSION="FIELD_NAME" EXPRESSIONTYPE="GENERAL"
                    NAME="FIELD_NAME" PICTURETEXT="" PORTTYPE="INPUT/OUTPUT"
                    PRECISION="10" SCALE="0"/>
    <TABLEATTRIBUTE NAME="Filter Condition" VALUE="FIELD_NAME IS NOT NULL"/>
  </TRANSFORMATION>

  <!-- Router (one output group per route; DEFAULT group needs no condition) -->
  <TRANSFORMATION DESCRIPTION="" NAME="RTR_NAME" OBJECTVERSION="1"
                  REUSABLE="NO" TYPE="Router" VERSIONNUMBER="1">
    <TRANSFORMFIELD DATATYPE="number" DEFAULTVALUE="" DESCRIPTION="" EXPRESSION=""
                    EXPRESSIONTYPE="GENERAL" NAME="FIELD_NAME" PICTURETEXT=""
                    PORTTYPE="INPUT" PRECISION="10" SCALE="0"/>
    <TABLEATTRIBUTE NAME="Number of Output Groups" VALUE="2"/>
    <TABLEATTRIBUTE NAME="Group1 Name" VALUE="GROUP_A"/>
    <TABLEATTRIBUTE NAME="Group1 Filter Condition" VALUE="FIELD = 'VALUE'"/>
    <TABLEATTRIBUTE NAME="Group2 Name" VALUE="DEFAULT"/>
    <TABLEATTRIBUTE NAME="Group2 Filter Condition" VALUE=""/>
  </TRANSFORMATION>

  <!-- Lookup -->
  <TRANSFORMATION DESCRIPTION="" NAME="LKP_NAME" OBJECTVERSION="1"
                  REUSABLE="NO" TYPE="Lookup Procedure" VERSIONNUMBER="1">
    <TRANSFORMFIELD DATATYPE="number" DEFAULTVALUE="" DESCRIPTION="" EXPRESSION=""
                    EXPRESSIONTYPE="GENERAL" NAME="INPUT_KEY" PICTURETEXT=""
                    PORTTYPE="INPUT" PRECISION="10" SCALE="0"/>
    <TRANSFORMFIELD DATATYPE="varchar" DEFAULTVALUE="ERROR" DESCRIPTION="" EXPRESSION=""
                    EXPRESSIONTYPE="GENERAL" NAME="RETURN_FIELD" PICTURETEXT=""
                    PORTTYPE="RETURN" PRECISION="50" SCALE="0"/>
    <TABLEATTRIBUTE NAME="Lookup table name" VALUE="SCHEMA.TABLE"/>
    <TABLEATTRIBUTE NAME="Lookup Condition" VALUE="TABLE.KEY = INPUT_KEY"/>
    <TABLEATTRIBUTE NAME="Connection Information" VALUE="$$DB_CONNECTION"/>
    <TABLEATTRIBUTE NAME="Lookup Cache Persistent" VALUE="NO"/>
  </TRANSFORMATION>

  <!-- Aggregator -->
  <TRANSFORMATION DESCRIPTION="" NAME="AGG_NAME" OBJECTVERSION="1"
                  REUSABLE="NO" TYPE="Aggregator" VERSIONNUMBER="1">
    <TRANSFORMFIELD DATATYPE="number" DEFAULTVALUE="" DESCRIPTION=""
                    EXPRESSION="GROUP_BY_FIELD" EXPRESSIONTYPE="GENERAL"
                    NAME="GROUP_BY_FIELD" PICTURETEXT="" PORTTYPE="INPUT/OUTPUT"
                    PRECISION="10" SCALE="0"/>
    <TRANSFORMFIELD DATATYPE="number" DEFAULTVALUE="0" DESCRIPTION=""
                    EXPRESSION="SUM(AMOUNT)" EXPRESSIONTYPE="GENERAL"
                    NAME="TOTAL_AMOUNT" PICTURETEXT="" PORTTYPE="OUTPUT"
                    PRECISION="18" SCALE="2"/>
    <TABLEATTRIBUTE NAME="Sorted Input" VALUE="NO"/>
  </TRANSFORMATION>

  <!-- ── MAPPING ── -->
  <MAPPING DESCRIPTION="" ISVALID="YES" NAME="m_MAPPING_NAME"
           OBJECTVERSION="1" VERSIONNUMBER="1">

    <!-- INSTANCE for each source (TYPE="SOURCE") -->
    <INSTANCE DESCRIPTION="" NAME="SOURCE_TABLE"
              TRANSFORMATION_NAME="SOURCE_TABLE"
              TRANSFORMATION_TYPE="Source Definition" TYPE="SOURCE"/>

    <!-- INSTANCE for each transformation (TYPE="TRANSFORMATION") -->
    <INSTANCE DESCRIPTION="" NAME="SQ_TABLE_NAME"
              TRANSFORMATION_NAME="SQ_TABLE_NAME"
              TRANSFORMATION_TYPE="Source Qualifier" TYPE="TRANSFORMATION"/>

    <!-- INSTANCE for each target (TYPE="TARGET") -->
    <INSTANCE DESCRIPTION="" NAME="TARGET_TABLE"
              TRANSFORMATION_NAME="TARGET_TABLE"
              TRANSFORMATION_TYPE="Target Definition" TYPE="TARGET"/>

    <!-- CONNECTOR for every field link in the pipeline -->
    <CONNECTOR FROMFIELD="FIELD_NAME" FROMINSTANCE="SQ_TABLE_NAME"
               FROMINSTANCETYPE="Source Qualifier"
               TOFIELD="FIELD_NAME" TOINSTANCE="EXP_NAME"
               TOINSTANCETYPE="Expression"/>
    <CONNECTOR FROMFIELD="FIELD_NAME" FROMINSTANCE="EXP_NAME"
               FROMINSTANCETYPE="Expression"
               TOFIELD="FIELD_NAME" TOINSTANCE="TARGET_TABLE"
               TOINSTANCETYPE="Target Definition"/>

  </MAPPING>

</FOLDER>
</REPOSITORY>
</POWERMART>

======================================================
PORTTYPE RULES (strict)
======================================================
Source Qualifier ports          → PORTTYPE="OUTPUT"
Expression pass-through ports   → PORTTYPE="INPUT/OUTPUT"   (same field in and out)
Expression new derived ports    → PORTTYPE="OUTPUT"          (output only, no INPUT twin)
Joiner master-side ports        → PORTTYPE="MASTERINPUT"
Joiner detail-side ports        → PORTTYPE="DETAILINPUT"
Joiner output ports             → PORTTYPE="OUTPUT"
Filter ports                    → PORTTYPE="INPUT/OUTPUT"
Router input ports              → PORTTYPE="INPUT"
Lookup input key ports          → PORTTYPE="INPUT"
Lookup return value ports       → PORTTYPE="RETURN"
Aggregator group-by ports       → PORTTYPE="INPUT/OUTPUT"
Aggregator aggregate ports      → PORTTYPE="OUTPUT"

======================================================
CONNECTOR INSTANCE TYPES (use these exact strings)
======================================================
Source table       → "Source Definition"
Source Qualifier   → "Source Qualifier"
Expression         → "Expression"
Filter             → "Filter"
Joiner             → "Joiner"
Lookup             → "Lookup Procedure"
Router             → "Router"
Aggregator         → "Aggregator"
Target table       → "Target Definition"

======================================================
DATATYPE MAPPING
======================================================
number(p)          → DATATYPE="number" PRECISION="p" SCALE="0"
number(p,s)        → DATATYPE="number" PRECISION="p" SCALE="s"
varchar(n)         → DATATYPE="varchar" PRECISION="n" SCALE="0"
date / timestamp   → DATATYPE="date/time" PRECISION="19" SCALE="0"
char(n)            → DATATYPE="char" PRECISION="n" SCALE="0"
integer            → DATATYPE="integer" PRECISION="10" SCALE="0"

======================================================
OUTPUT RULES
======================================================
- Output ONLY the XML — no markdown fences, no explanation text.
- Start with: <?xml version="1.0" encoding="Windows-1252"?>
- Every transformation referenced in a CONNECTOR must have an INSTANCE element.
- Every field in section 4.8 must have a CONNECTOR chain tracing it from source to target.
- Verbatim IIF expressions from section 4.5 go in EXPRESSION="" on the derived TRANSFORMFIELD.
- If a field has status "Direct" in section 4.8, it flows through with PORTTYPE="INPUT/OUTPUT" in Expression.
- If a field has status "⚠ Gap", include the CONNECTOR but set EXPRESSION="/* GAP — no expression found */"
- For parameters (section 6), use $$PARAM_NAME notation in expressions as shown in the spec.
"""

# ── Section extractor ────────────────────────────────────────────────────────

def _extract_sections(spec_md: str, section_numbers: list[str]) -> str:
    """
    Extract specific numbered sections from the spec markdown.
    Returns just the matched sections concatenated — reduces prompt size.
    """
    import re
    lines = spec_md.split("\n")
    result: list[str] = []
    capturing = False
    current_level = 0

    for line in lines:
        # Detect a section heading
        m = re.match(r'^(#{1,4})\s+(\d[\d.]*)\s+', line)
        if m:
            level = len(m.group(1))
            num   = m.group(2).rstrip(".")
            # Start capturing if this section is one we want
            if any(num == s or num.startswith(s + ".") for s in section_numbers):
                capturing = True
                current_level = level
                result.append(line)
                continue
            # Stop capturing if we've moved to a sibling/parent section
            elif capturing and level <= current_level:
                capturing = False

        if capturing:
            result.append(line)

    return "\n".join(result)


# ── Pass 1 prompt — structure only (SOURCE, TARGET, TRANSFORMATION) ───────────

_PROMPT_STRUCTURE = """## Technical Specification (key sections)

{spec_sections}

---
## Task — Pass 1: Structure Only

Generate the SOURCE, TARGET, and TRANSFORMATION XML blocks for mapping **{mapping_name}**.

IMPORTANT: Do NOT generate the MAPPING element, CONNECTOR elements, or INSTANCE elements yet.
Output ONLY this fragment (no XML declaration, no POWERMART wrapper):

  <SOURCE ...> ... </SOURCE>          (one per source table)
  <TARGET ...> ... </TARGET>          (one per target table)
  <TRANSFORMATION ...> ... </TRANSFORMATION>  (one per transform in the pipeline)

Use the source schemas from Section 2, target schemas from Section 3,
derivation expressions from Section 4.5, join conditions from Section 4.2,
filter conditions from Section 4.4, router groups from Section 4.7,
lookup conditions from Section 4.3, and aggregations from Section 4.6.

Output ONLY the XML fragment — no prose, no markdown, no POWERMART wrapper.
Start with the first <SOURCE and end with the last </TRANSFORMATION>.
"""

# ── Pass 2 prompt — MAPPING block (CONNECTOR + INSTANCE) ─────────────────────

_PROMPT_MAPPING = """## Field Mapping Table (Section 4.8)

{section_48}

## Pipeline Overview (Section 4.1)

{section_41}

## Transformations generated in Pass 1

{transform_list}

---
## Task — Pass 2: MAPPING Block

Generate ONLY the <MAPPING> element for mapping **{mapping_name}**.

Rules:
1. Include one <INSTANCE> for every SOURCE, TRANSFORMATION, and TARGET used.
2. Include one <CONNECTOR> for every field link in the field mapping table above.
   - Trace each row: Source Table → SQ → (transforms) → Target Table
   - Use the Transform Chain column to determine intermediate hops.
   - Direct fields (status=Direct) go: SQ → Expression → Target
   - Derived fields go through whichever transform derives them
   - Gap fields: still include connector but add comment in EXPRESSION attribute
3. INSTANCE TYPE values: SOURCE instances → TYPE="SOURCE", TARGET → TYPE="TARGET", transformations → TYPE="TRANSFORMATION"
4. FROMINSTANCETYPE / TOINSTANCETYPE must match the transformation TYPE string exactly
   (e.g., "Source Qualifier", "Expression", "Joiner", "Router", "Target Definition", "Source Definition")

Output ONLY the <MAPPING ...>...</MAPPING> element — nothing else.
"""

# ── Pass 1 system — tightly scoped ───────────────────────────────────────────

_SYSTEM_STRUCTURE = """You are an Informatica PowerCenter XML generator.
Generate ONLY the SOURCE, TARGET, and TRANSFORMATION XML blocks — no MAPPING, no CONNECTOR, no INSTANCE.
Follow the PowerCenter XML format exactly as shown in your training.
Output raw XML only — no markdown, no explanation.

PORTTYPE rules:
  Source Qualifier output ports     → PORTTYPE="OUTPUT"
  Expression pass-through ports     → PORTTYPE="INPUT/OUTPUT"
  Expression new derived ports      → PORTTYPE="OUTPUT"
  Joiner master ports               → PORTTYPE="MASTERINPUT"
  Joiner detail ports               → PORTTYPE="DETAILINPUT"
  Joiner output ports               → PORTTYPE="OUTPUT"
  Filter ports                      → PORTTYPE="INPUT/OUTPUT"
  Router input ports                → PORTTYPE="INPUT"
  Lookup input ports                → PORTTYPE="INPUT"
  Lookup return ports               → PORTTYPE="RETURN"
  Aggregator group-by ports         → PORTTYPE="INPUT/OUTPUT"
  Aggregator aggregate ports        → PORTTYPE="OUTPUT"

Datatype mapping:
  number(p) / number(p,s) → DATATYPE="number" PRECISION="p" SCALE="s"
  varchar(n)              → DATATYPE="varchar" PRECISION="n" SCALE="0"
  date / timestamp        → DATATYPE="date/time" PRECISION="19" SCALE="0"
  integer                 → DATATYPE="integer" PRECISION="10" SCALE="0"
"""

# ── Pass 2 system — mapping only ──────────────────────────────────────────────

_SYSTEM_MAPPING = """You are an Informatica PowerCenter XML generator.
Generate ONLY the <MAPPING> element containing INSTANCE and CONNECTOR child elements.
Output raw XML only — no markdown, no explanation, no wrapper.

CONNECTOR format:
  <CONNECTOR FROMFIELD="FIELD" FROMINSTANCE="SRC_NAME" FROMINSTANCETYPE="Source Qualifier"
             TOFIELD="FIELD" TOINSTANCE="EXP_NAME" TOINSTANCETYPE="Expression"/>

INSTANCE format:
  <INSTANCE NAME="SQ_ORDERS" TRANSFORMATION_NAME="SQ_ORDERS"
            TRANSFORMATION_TYPE="Source Qualifier" TYPE="TRANSFORMATION"/>
  <INSTANCE NAME="ORDERS" TRANSFORMATION_NAME="ORDERS"
            TRANSFORMATION_TYPE="Source Definition" TYPE="SOURCE"/>
  <INSTANCE NAME="TGT_ORDERS" TRANSFORMATION_NAME="TGT_ORDERS"
            TRANSFORMATION_TYPE="Target Definition" TYPE="TARGET"/>

Generate one CONNECTOR per field hop in the pipeline (not just source-to-target).
For a field going SQ -> EXP -> RTR -> TARGET, generate 3 connectors.
"""


# ── XML helpers ───────────────────────────────────────────────────────────────

def _clean_structure(xml: str) -> str:
    """
    Remove any trailing incomplete XML element from the structure fragment.

    Pass 1 can hit the token limit mid-tag, leaving an unclosed opening element
    at the end (e.g. '<TRANSFORMATION ... REUS'). Find the last complete closing
    tag and truncate there so the assembled document stays well-formed.
    """
    # Tags that can appear at the top level of the structure fragment
    close_tags = ["</TRANSFORMATION>", "</TARGET>", "</SOURCE>"]
    last_pos = -1
    for tag in close_tags:
        pos = xml.rfind(tag)
        if pos != -1:
            candidate = pos + len(tag)
            if candidate > last_pos:
                last_pos = candidate
    if last_pos > 0:
        cleaned = xml[:last_pos]
        removed = xml[last_pos:].strip()
        if removed:
            log.warning(
                "informatica_generator: trimmed %d chars of truncated structure output",
                len(removed),
            )
        return cleaned
    return xml


def _strip_fences(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("```"):
        lines = raw.split("\n")
        raw = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
    return raw.strip()


def _extract_transform_names(structure_xml: str) -> str:
    """Pull transformation names+types from the structure XML for pass 2."""
    import re
    names = re.findall(
        r'<TRANSFORMATION[^>]+NAME="([^"]+)"[^>]+TYPE="([^"]+)"', structure_xml
    )
    return "\n".join(f"  {name} (TYPE: {ttype})" for name, ttype in names)


def _assemble_xml(structure_fragment: str, mapping_fragment: str, mapping_name: str) -> str:
    """Wrap the two fragments in a complete PowerCenter XML document."""
    return (
        '<?xml version="1.0" encoding="Windows-1252"?>\n'
        '<!DOCTYPE POWERMART SYSTEM "powrmart.dtd">\n'
        '<POWERMART CREATION_DATE="01/01/2026 00:00:00" REPOSITORY_VERSION="187.94">\n'
        '<REPOSITORY CODEPAGE="MS1252" DATABASETYPE="Oracle" NAME="DEV_REP" VERSION="187">\n'
        f'<FOLDER DESCRIPTION="" GROUP="" NAME="CONVERSION" OWNER="Administrator" '
        f'PERMISSIONS="rwx---r--" SHARED="NOTSHARED" UUID="">\n\n'
        f'{structure_fragment.strip()}\n\n'
        f'{mapping_fragment.strip()}\n\n'
        '</FOLDER>\n</REPOSITORY>\n</POWERMART>'
    )


# ── Core generation function — two-pass ───────────────────────────────────────

async def generate_from_spec(spec_md: str, mapping_name: str) -> str:
    """
    Generate PowerCenter XML from an existing 3b Technical Specification.

    Uses a two-pass approach:
      Pass 1 — SOURCE + TARGET + TRANSFORMATION blocks (from sections 2, 3, 4.x)
      Pass 2 — MAPPING block with all CONNECTOR + INSTANCE elements (from section 4.8)

    Both passes run sequentially; pass 2 uses the transformation names from pass 1.

    Returns:
        Valid PowerCenter XML string ready for Designer import.
    """
    import asyncio
    from ._client import make_client, call_claude_with_retry

    log.info("informatica_generator: two-pass XML generation for '%s' (%d spec chars)",
             mapping_name, len(spec_md))

    client = make_client()

    # ── Pass 1: Structure (SOURCE / TARGET / TRANSFORMATION) ──────────────────
    # Feed only the schema + transformation sections to keep the prompt focused
    structure_sections = _extract_sections(
        spec_md,
        ["2", "3", "4.1", "4.2", "4.3", "4.4", "4.5", "4.6", "4.7"]
    )
    if len(structure_sections) > 30_000:
        structure_sections = structure_sections[:30_000] + "\n... [truncated]"

    prompt_p1 = _PROMPT_STRUCTURE.format(
        spec_sections=structure_sections,
        mapping_name=mapping_name,
    )

    log.info("informatica_generator: pass 1 — structure (%d chars input)", len(prompt_p1))
    msg1 = await call_claude_with_retry(
        client,
        model=MODEL,
        max_tokens=_MAX_TOKENS,
        system=_SYSTEM_STRUCTURE,
        messages=[{"role": "user", "content": prompt_p1}],
        label=f"informatica_xml_structure:{mapping_name}",
    )
    structure_xml = _clean_structure(_strip_fences(msg1.content[0].text))
    transform_list = _extract_transform_names(structure_xml)
    log.info("informatica_generator: pass 1 complete — %d chars, %d transforms",
             len(structure_xml), transform_list.count("\n") + 1)

    # ── Pass 2: MAPPING block (CONNECTOR + INSTANCE) ──────────────────────────
    section_48 = _extract_sections(spec_md, ["4.8"])
    section_41 = _extract_sections(spec_md, ["4.1"])
    if len(section_48) > 20_000:
        section_48 = section_48[:20_000] + "\n... [truncated]"

    prompt_p2 = _PROMPT_MAPPING.format(
        section_48=section_48,
        section_41=section_41,
        transform_list=transform_list or "  (see structure above)",
        mapping_name=mapping_name,
    )

    log.info("informatica_generator: pass 2 — mapping block (%d chars input)", len(prompt_p2))
    msg2 = await call_claude_with_retry(
        client,
        model=MODEL,
        max_tokens=_MAX_TOKENS,
        system=_SYSTEM_MAPPING,
        messages=[{"role": "user", "content": prompt_p2}],
        label=f"informatica_xml_mapping:{mapping_name}",
    )
    mapping_xml = _strip_fences(msg2.content[0].text)
    log.info("informatica_generator: pass 2 complete — %d chars, %d connectors",
             len(mapping_xml), mapping_xml.count("<CONNECTOR "))

    # ── Assemble + validate ───────────────────────────────────────────────────
    full_xml = _assemble_xml(structure_xml, mapping_xml, mapping_name)

    try:
        ET.fromstring(full_xml.encode("utf-8", errors="replace"))
        log.info("informatica_generator: XML valid — %d chars total", len(full_xml))
    except ET.ParseError as e:
        log.warning("informatica_generator: XML parse warning for '%s': %s", mapping_name, e)
        full_xml = f"<!-- ⚠ XML PARSE WARNING: {e} — import and validate in Designer -->\n" + full_xml

    return full_xml


# Flow 2 entry point (same logic — separate name for future divergence)
generate_from_new_spec = generate_from_spec
