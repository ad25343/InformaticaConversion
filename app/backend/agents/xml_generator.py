# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
XML Generator Agent — Phase 3 bidirectional migration.
Generates Informatica PowerCenter XML from an ETL pattern config.
"""
import time
import textwrap
import xml.etree.ElementTree as ET
from typing import Optional, List

from pydantic import BaseModel
import yaml

from .base import BaseAgent
from ..config import settings as _cfg


class XmlGenerationResult(BaseModel):
    pattern_name: str
    mapping_name: str
    xml_content: str
    notes: List[str] = []
    duration_ms: int


# Few-shot examples embedded in the prompt so Claude knows the XML structure
_INFORMATICA_XML_EXAMPLES = """
Example 1 — simple truncate_and_load mapping:
<POWERMART CREATION_DATE="03/14/2026 00:00:00" REPOSITORY_VERSION="187.97" ...>
<REPOSITORY NAME="REP_PROD" ...>
<FOLDER NAME="ETL_MAPPINGS" ...>
<SOURCE NAME="SRC_ORDERS" DATABASETYPE="Oracle" DBDNAME="PROD_DB" ...>
  <SOURCEFIELD DATATYPE="number" FIELDNUMBER="1" FIELDWIDTH="10" NAME="ORDER_ID" .../>
  <SOURCEFIELD DATATYPE="varchar" FIELDNUMBER="2" FIELDWIDTH="100" NAME="CUSTOMER_NAME" .../>
</SOURCE>
<TARGET NAME="TGT_ORDERS_DW" DATABASETYPE="Oracle" DBDNAME="DW_DB" ...>
  <TARGETFIELD DATATYPE="number" FIELDNUMBER="1" FIELDWIDTH="10" NAME="ORDER_ID" .../>
  <TARGETFIELD DATATYPE="varchar" FIELDNUMBER="2" FIELDWIDTH="100" NAME="CUSTOMER_NAME" .../>
</TARGET>
<MAPPING NAME="m_orders_load" ISVALID="YES" OBJECTVERSION="1" ...>
  <TRANSFORMATION NAME="SQ_ORDERS" TYPE="Source Qualifier" ...>
    <TRANSFORMFIELD DATATYPE="number" NAME="ORDER_ID" .../>
    <TRANSFORMFIELD DATATYPE="varchar" NAME="CUSTOMER_NAME" .../>
  </TRANSFORMATION>
  <CONNECTOR FROMFIELD="ORDER_ID" FROMINSTANCE="SQ_ORDERS" FROMINSTANCETYPE="Source Qualifier" TOFIELD="ORDER_ID" TOINSTANCE="TGT_ORDERS_DW" TOINSTANCETYPE="Target Definition"/>
  <CONNECTOR FROMFIELD="CUSTOMER_NAME" FROMINSTANCE="SQ_ORDERS" FROMINSTANCETYPE="Source Qualifier" TOFIELD="CUSTOMER_NAME" TOINSTANCE="TGT_ORDERS_DW" TOINSTANCETYPE="Target Definition"/>
  <INSTANCE NAME="SQ_ORDERS" TRANSFORMATION_NAME="SQ_ORDERS" TRANSFORMATION_TYPE="Source Qualifier" TYPE="TRANSFORMATION"/>
  <INSTANCE NAME="TGT_ORDERS_DW" TRANSFORMATION_NAME="TGT_ORDERS_DW" TRANSFORMATION_TYPE="Target Definition" TYPE="TARGET"/>
</MAPPING>
</FOLDER>
</REPOSITORY>
</POWERMART>
"""


class XmlGeneratorAgent(BaseAgent):
    """Generate Informatica PowerCenter XML from a pattern config."""

    async def generate_xml(
        self,
        pattern_name: str,
        pattern_config: dict,
        mapping_name: str,
        metadata: Optional[dict] = None,
    ) -> XmlGenerationResult:
        t0 = time.monotonic()

        config_yaml_str = yaml.dump(pattern_config, default_flow_style=False)
        meta_str = yaml.dump(metadata, default_flow_style=False) if metadata else "none"

        system = textwrap.dedent(f"""
            You are an expert Informatica PowerCenter XML generator.
            You produce syntactically valid Informatica PowerCenter 9.x/10.x XML from ETL pattern configs.

            Rules:
            1. Always produce a complete <POWERMART> root element.
            2. Include <REPOSITORY>, <FOLDER>, <MAPPING>, <SOURCE>, <TARGET>, and appropriate <TRANSFORMATION> elements.
            3. Include all <CONNECTOR> elements to wire the mapping together.
            4. Include <INSTANCE> elements for each transformation and target.
            5. Use ISVALID="YES" and OBJECTVERSION="1" on the MAPPING element.
            6. The mapping NAME attribute must equal: {mapping_name}
            7. Field datatypes: use Informatica native types (number, varchar, date).
            8. Generate realistic but minimal field definitions based on the config.
            9. Output ONLY the XML — no explanation text, no markdown fences.
        """).strip()

        user_prompt = textwrap.dedent(f"""
            Pattern: {pattern_name}
            Mapping name: {mapping_name}
            Metadata: {meta_str}

            Pattern config (YAML):
            {config_yaml_str}

            Reference XML structure:
            {_INFORMATICA_XML_EXAMPLES}

            Generate the complete Informatica PowerCenter XML for this pattern config.
            Output ONLY the XML starting with <POWERMART and ending with </POWERMART>.
        """).strip()

        response = await self._call_claude(
            system=system,
            user_prompt=user_prompt,
            max_tokens=4096,
        )
        raw = response.content[0].text.strip()

        # Extract XML block (strip any accidental markdown fences)
        if raw.startswith("```"):
            lines = raw.split("\n")
            raw = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        if not raw.startswith("<POWERMART"):
            start = raw.find("<POWERMART")
            if start != -1:
                raw = raw[start:]

        # Validate XML is parseable
        ET.fromstring(raw)  # raises ParseError if invalid

        elapsed_ms = int((time.monotonic() - t0) * 1000)
        return XmlGenerationResult(
            pattern_name=pattern_name,
            mapping_name=mapping_name,
            xml_content=raw,
            notes=[f"Generated by {_cfg.claude_model}"],
            duration_ms=elapsed_ms,
        )
