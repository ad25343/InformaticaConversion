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
_MAX_TOKENS = 12_000   # XML output can be large for complex mappings

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

══════════════════════════════════════════════════════
REQUIRED XML STRUCTURE (follow this exactly)
══════════════════════════════════════════════════════

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

══════════════════════════════════════════════════════
PORTTYPE RULES (strict)
══════════════════════════════════════════════════════
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

══════════════════════════════════════════════════════
CONNECTOR INSTANCE TYPES (use these exact strings)
══════════════════════════════════════════════════════
Source table       → "Source Definition"
Source Qualifier   → "Source Qualifier"
Expression         → "Expression"
Filter             → "Filter"
Joiner             → "Joiner"
Lookup             → "Lookup Procedure"
Router             → "Router"
Aggregator         → "Aggregator"
Target table       → "Target Definition"

══════════════════════════════════════════════════════
DATATYPE MAPPING
══════════════════════════════════════════════════════
number(p)          → DATATYPE="number" PRECISION="p" SCALE="0"
number(p,s)        → DATATYPE="number" PRECISION="p" SCALE="s"
varchar(n)         → DATATYPE="varchar" PRECISION="n" SCALE="0"
date / timestamp   → DATATYPE="date/time" PRECISION="19" SCALE="0"
char(n)            → DATATYPE="char" PRECISION="n" SCALE="0"
integer            → DATATYPE="integer" PRECISION="10" SCALE="0"

══════════════════════════════════════════════════════
OUTPUT RULES
══════════════════════════════════════════════════════
- Output ONLY the XML — no markdown fences, no explanation text.
- Start with: <?xml version="1.0" encoding="Windows-1252"?>
- Every transformation referenced in a CONNECTOR must have an INSTANCE element.
- Every field in section 4.8 must have a CONNECTOR chain tracing it from source to target.
- Verbatim IIF expressions from section 4.5 go in EXPRESSION="" on the derived TRANSFORMFIELD.
- If a field has status "Direct" in section 4.8, it flows through with PORTTYPE="INPUT/OUTPUT" in Expression.
- If a field has status "⚠ Gap", include the CONNECTOR but set EXPRESSION="/* GAP — no expression found */"
- For parameters (section 6), use $$PARAM_NAME notation in expressions as shown in the spec.
"""

# ── User prompt ───────────────────────────────────────────────────────────────

_PROMPT = """## Technical Specification

{spec_md}

─────────────────────────────────────────────
## Task

Generate the complete PowerCenter XML for mapping: **{mapping_name}**

Read every section of the specification above and produce a single valid
PowerCenter XML document. Start with the XML declaration and end with </POWERMART>.
Do NOT include any text before or after the XML.
"""


# ── Core generation function ──────────────────────────────────────────────────

async def generate_from_spec(spec_md: str, mapping_name: str) -> str:
    """
    Generate PowerCenter XML from an existing 3b Technical Specification.

    Args:
        spec_md:      The analyst_view_md content (3b Technical Specification markdown)
        mapping_name: The mapping name to use in the XML (e.g. "m_LOAN_HISTORY")

    Returns:
        Valid PowerCenter XML string ready for Designer import.

    Raises:
        ValueError: If the generated XML is not parseable (Claude produced invalid XML)
        RuntimeError: If the Claude call fails
    """
    from ._client import make_client, call_claude_with_retry

    # Cap spec length to keep prompt inside context budget
    spec_for_prompt = spec_md
    if len(spec_for_prompt) > 35_000:
        spec_for_prompt = spec_for_prompt[:35_000] + "\n\n... [spec truncated for length]"

    prompt = _PROMPT.format(spec_md=spec_for_prompt, mapping_name=mapping_name)

    log.info("informatica_generator: generating XML for '%s' (%d spec chars)",
             mapping_name, len(spec_md))

    client = make_client()
    message = await call_claude_with_retry(
        client,
        model=MODEL,
        max_tokens=_MAX_TOKENS,
        system=_SYSTEM,
        messages=[{"role": "user", "content": prompt}],
        label=f"informatica_xml_gen:{mapping_name}",
    )
    raw = message.content[0].text.strip()

    # Strip accidental markdown fences
    if raw.startswith("```"):
        lines = raw.split("\n")
        raw = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

    # Find XML start
    if not raw.startswith("<?xml") and not raw.startswith("<POWERMART"):
        for marker in ("<?xml", "<POWERMART"):
            idx = raw.find(marker)
            if idx != -1:
                raw = raw[idx:]
                break

    # Validate XML is parseable — raises ET.ParseError on bad XML
    try:
        ET.fromstring(raw.encode("utf-8", errors="replace"))
    except ET.ParseError as e:
        log.warning("informatica_generator: XML parse error for '%s': %s", mapping_name, e)
        # Return with a warning comment prepended rather than crashing
        raw = f"<!-- ⚠ XML PARSE WARNING: {e} — import and validate in Designer -->\n" + raw

    log.info("informatica_generator: generated %d chars of XML for '%s'", len(raw), mapping_name)
    return raw


# Flow 2 entry point (same logic — separate name for future divergence)
generate_from_new_spec = generate_from_spec
