#!/usr/bin/env python3
"""
Sample Data Validator
Leader Agent + 10 Sub-Agents

Goal: Ensure sample_data test fixtures are complete, clean, and cover all
scenarios needed to test the Informatica PowerCenter code conversion pipeline.

Usage:
    python3 sample_data_validator.py [--fix] [--verbose]
"""

import os
import re
import sys
import json
import shutil
import argparse
import textwrap
import xml.etree.ElementTree as ET
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Set
from collections import defaultdict
import datetime

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).parent
SAMPLE_DATA_DIR = BASE_DIR / "sample_data"
PROJECTS = ["apex_insurance", "firstbank", "meridian_am", "nexus_scm"]
TIERS = ["simple", "medium", "complex"]

SUPPORTED_TRANSFORM_TYPES = {
    "Source Qualifier", "Expression", "Lookup Procedure",
    "Joiner", "Router", "Aggregator", "Normalizer",
    "Rank", "Sorter", "Filter", "Update Strategy",
    "Sequence Generator", "Stored Procedure"
}

# Transformation types required per tier
TIER_REQUIRED_TYPES = {
    "simple": {"Source Qualifier", "Expression"},
    "medium": {"Source Qualifier", "Lookup Procedure", "Aggregator"},
    "complex": {"Source Qualifier", "Joiner", "Router"},
}

# Scenario coverage: what the pipeline stages need to see in test data
REQUIRED_SCENARIOS = {
    "scd2_pattern": {
        "description": "SCD2 change detection (Lookup Procedure + Router or Update Strategy)",
        "detect": lambda root: (
            any(t.get("TYPE") == "Lookup Procedure"
                for t in root.iter("TRANSFORMATION")) and
            any(t.get("TYPE") in ("Router", "Update Strategy")
                for t in root.iter("TRANSFORMATION"))
        )
    },
    "multi_target": {
        "description": "Multi-target routing (Router → multiple targets)",
        "detect": lambda root: (
            len(list(root.iter("TARGET"))) >= 2 and
            any(t.get("TYPE") == "Router" for t in root.iter("TRANSFORMATION"))
        )
    },
    "multi_source_join": {
        "description": "Multi-source joiner pattern",
        "detect": lambda root: (
            len(list(root.iter("SOURCE"))) >= 2 and
            any(t.get("TYPE") == "Joiner" for t in root.iter("TRANSFORMATION"))
        )
    },
    "aggregation_rollup": {
        "description": "Aggregation rollup (Aggregator transform)",
        "detect": lambda root: any(
            t.get("TYPE") == "Aggregator" for t in root.iter("TRANSFORMATION")
        )
    },
    "sql_override": {
        "description": "SQL override in Source Qualifier (verification_agent trigger)",
        "detect": lambda root: any(
            a.get("NAME") == "Sql Query" and a.get("VALUE", "").strip()
            for t in root.iter("TRANSFORMATION")
            if t.get("TYPE") == "Source Qualifier"
            for a in t.iter("TABLEATTRIBUTE")
        )
    },
    "filter_condition": {
        "description": "Source filter condition on Source Qualifier",
        "detect": lambda root: any(
            a.get("NAME") in ("Source Filter", "Filter Condition") and a.get("VALUE", "").strip()
            for t in root.iter("TRANSFORMATION")
            for a in t.iter("TABLEATTRIBUTE")
        )
    },
    "parameter_usage": {
        "description": "$$PARAM variable usage in mapping",
        "detect": lambda root: bool(
            re.search(r'\$\$\w+', ET.tostring(root, encoding="unicode"))
        )
    },
    "lookup_connected": {
        "description": "Connected lookup transformation",
        "detect": lambda root: any(
            t.get("TYPE") == "Lookup Procedure" for t in root.iter("TRANSFORMATION")
        )
    },
    "sequence_generator": {
        "description": "Sequence Generator transformation (surrogate key generation)",
        "detect": lambda root: any(
            t.get("TYPE") == "Sequence Generator" for t in root.iter("TRANSFORMATION")
        )
    },
    "update_strategy": {
        "description": "Update Strategy transformation (CDC insert/update/delete pattern)",
        "detect": lambda root: any(
            t.get("TYPE") == "Update Strategy" for t in root.iter("TRANSFORMATION")
        )
    },
    "reusable_transform": {
        "description": "Reusable transformation (REUSABLE=YES — shared across mappings)",
        "detect": lambda root: any(
            t.get("REUSABLE") == "YES" for t in root.iter("TRANSFORMATION")
        )
    },
    "unconnected_lookup": {
        "description": "Unconnected lookup (:LKP. invocation syntax in expression)",
        "detect": lambda root: bool(
            re.search(r':LKP\.', ET.tostring(root, encoding="unicode"))
        )
    },
    "sorter": {
        "description": "Sorter transformation (explicit sort before Rank or Aggregator)",
        "detect": lambda root: any(
            t.get("TYPE") == "Sorter" for t in root.iter("TRANSFORMATION")
        )
    },
    "rank": {
        "description": "Rank transformation (top-N or bottom-N filter)",
        "detect": lambda root: any(
            t.get("TYPE") == "Rank" for t in root.iter("TRANSFORMATION")
        )
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# Data Structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    agent: str
    project: str
    file: str
    severity: str       # CRITICAL | HIGH | MEDIUM | LOW | INFO
    category: str
    message: str
    fixed: bool = False
    fix_description: str = ""


@dataclass
class AgentReport:
    agent_name: str
    findings: List[Finding] = field(default_factory=list)
    files_checked: int = 0
    passed: int = 0

    def add_finding(self, f: Finding):
        self.findings.append(f)

    def add_pass(self):
        self.passed += 1

    @property
    def failed(self):
        return len(self.findings)

    @property
    def fixed(self):
        return sum(1 for f in self.findings if f.fixed)

    def summary(self):
        criticals = sum(1 for f in self.findings if f.severity == "CRITICAL" and not f.fixed)
        highs = sum(1 for f in self.findings if f.severity == "HIGH" and not f.fixed)
        return f"checked={self.files_checked} pass={self.passed} findings={self.failed} fixed={self.fixed} CRIT={criticals} HIGH={highs}"


# ─────────────────────────────────────────────────────────────────────────────
# Base Agent
# ─────────────────────────────────────────────────────────────────────────────

class BaseAgent:
    name = "BaseAgent"

    def run(self, fix: bool = False, verbose: bool = False) -> AgentReport:
        raise NotImplementedError

    def parse_xml(self, path: Path) -> Optional[ET.Element]:
        try:
            tree = ET.parse(path)
            return tree.getroot()
        except ET.ParseError:
            return None

    def get_folder(self, root: ET.Element) -> Optional[ET.Element]:
        repo = root.find("REPOSITORY")
        if repo is None:
            return None
        return repo.find("FOLDER")

    def all_mapping_files(self) -> List[Tuple[str, str, Path]]:
        """Yields (project, tier, path) for all mapping XML files."""
        results = []
        for project in PROJECTS:
            for tier in TIERS:
                d = SAMPLE_DATA_DIR / project / "mappings" / tier
                if d.exists():
                    for f in sorted(d.glob("*.xml")):
                        results.append((project, tier, f))
        return results

    def all_workflow_files(self) -> List[Tuple[str, str, Path]]:
        results = []
        for project in PROJECTS:
            for tier in TIERS:
                d = SAMPLE_DATA_DIR / project / "workflows" / tier
                if d.exists():
                    for f in sorted(d.glob("*.xml")):
                        results.append((project, tier, f))
        return results


# ─────────────────────────────────────────────────────────────────────────────
# Agent 1: XML Schema Validator
# ─────────────────────────────────────────────────────────────────────────────

class Agent01_XMLSchema(BaseAgent):
    name = "01_XMLSchemaValidator"

    def run(self, fix=False, verbose=False) -> AgentReport:
        report = AgentReport(self.name)

        for project, tier, path in self.all_mapping_files():
            report.files_checked += 1
            root = self.parse_xml(path)
            if root is None:
                report.add_finding(Finding(self.name, project, path.name,
                    "CRITICAL", "XML Parse Error", "File cannot be parsed as valid XML"))
                continue

            ok = True
            if root.tag != "POWERMART":
                report.add_finding(Finding(self.name, project, path.name,
                    "CRITICAL", "Wrong Root", f"Expected <POWERMART>, got <{root.tag}>"))
                ok = False

            repo = root.find("REPOSITORY")
            if repo is None:
                report.add_finding(Finding(self.name, project, path.name,
                    "CRITICAL", "Missing REPOSITORY", "No <REPOSITORY> element"))
                ok = False
            else:
                folder = repo.find("FOLDER")
                if folder is None:
                    report.add_finding(Finding(self.name, project, path.name,
                        "CRITICAL", "Missing FOLDER", "No <FOLDER> inside REPOSITORY"))
                    ok = False
                else:
                    for req in ("SOURCE", "TARGET", "TRANSFORMATION", "MAPPING"):
                        if folder.find(req) is None:
                            report.add_finding(Finding(self.name, project, path.name,
                                "HIGH", f"Missing {req}", f"No <{req}> element in FOLDER"))
                            ok = False
            if ok:
                report.add_pass()

        for project, tier, path in self.all_workflow_files():
            report.files_checked += 1
            root = self.parse_xml(path)
            if root is None:
                report.add_finding(Finding(self.name, project, path.name,
                    "CRITICAL", "XML Parse Error", "Workflow file cannot be parsed"))
                continue
            ok = True
            if root.find(".//TASK") is None:
                report.add_finding(Finding(self.name, project, path.name,
                    "HIGH", "Missing TASK", "No <TASK> element in workflow"))
                ok = False
            if root.find(".//WORKFLOW") is None:
                report.add_finding(Finding(self.name, project, path.name,
                    "HIGH", "Missing WORKFLOW", "No <WORKFLOW> element"))
                ok = False
            if ok:
                report.add_pass()

        return report


# ─────────────────────────────────────────────────────────────────────────────
# Agent 2: INSTANCE / CONNECTOR Completeness
# ─────────────────────────────────────────────────────────────────────────────

class Agent02_InstanceConnector(BaseAgent):
    name = "02_InstanceConnector"

    def run(self, fix=False, verbose=False) -> AgentReport:
        report = AgentReport(self.name)

        for project, tier, path in self.all_mapping_files():
            report.files_checked += 1
            root = self.parse_xml(path)
            if root is None:
                continue
            folder = self.get_folder(root)
            if folder is None:
                continue

            mapping = folder.find("MAPPING")
            if mapping is None:
                report.add_finding(Finding(self.name, project, path.name,
                    "HIGH", "Missing MAPPING", "No <MAPPING> element"))
                continue

            # Collect declared instance names
            instances = {inst.get("NAME") for inst in mapping.findall("INSTANCE") if inst.get("NAME")}

            # Collect source/target/transformation names (should all be instances)
            sources = {s.get("NAME") for s in folder.findall("SOURCE") if s.get("NAME")}
            targets = {t.get("NAME") for t in folder.findall("TARGET") if t.get("NAME")}
            transforms = {t.get("NAME") for t in folder.findall("TRANSFORMATION") if t.get("NAME")}
            all_expected = sources | targets | transforms

            ok = True

            # Check every connector references valid instances
            connector_refs = set()
            for conn in mapping.findall("CONNECTOR"):
                from_inst = conn.get("FROMINSTANCE")
                to_inst = conn.get("TOINSTANCE")
                if from_inst:
                    connector_refs.add(from_inst)
                if to_inst:
                    connector_refs.add(to_inst)

            # Missing instances referenced in connectors
            missing_in_instances = connector_refs - instances
            if missing_in_instances:
                for m in sorted(missing_in_instances):
                    report.add_finding(Finding(self.name, project, path.name,
                        "CRITICAL", "Missing INSTANCE",
                        f"CONNECTOR references '{m}' but no INSTANCE with that name exists",
                        fixed=fix and m in all_expected,
                        fix_description=f"Would add <INSTANCE NAME='{m}'/>" if fix and m in all_expected else ""))
                ok = False

            # Expected objects not declared as instances
            missing_from_expected = all_expected - instances
            if missing_from_expected:
                for m in sorted(missing_from_expected):
                    was_fixed = False
                    if fix:
                        # Add INSTANCE element for each missing one
                        itype = "SOURCE" if m in sources else ("TARGET" if m in targets else "TRANSFORMATION")
                        elem = ET.SubElement(mapping, "INSTANCE")
                        elem.set("DESCRIPTION", "")
                        elem.set("NAME", m)
                        if itype == "SOURCE":
                            src = folder.find(f"SOURCE[@NAME='{m}']")
                            if src:
                                elem.set("SOURCENAME", m)
                                elem.set("TRANSFORMATION_NAME", m)
                                elem.set("TRANSFORMATION_TYPE", "Source Definition")
                                elem.set("TYPE", "SOURCE")
                        elif itype == "TARGET":
                            elem.set("TARGETNAME", m)
                            elem.set("TRANSFORMATION_NAME", m)
                            elem.set("TRANSFORMATION_TYPE", "Target Definition")
                            elem.set("TYPE", "TARGET")
                        else:
                            tf = folder.find(f"TRANSFORMATION[@NAME='{m}']")
                            tf_type = tf.get("TYPE", "") if tf is not None else ""
                            elem.set("TRANSFORMATION_NAME", m)
                            elem.set("TRANSFORMATION_TYPE", tf_type)
                            elem.set("TYPE", "TRANSFORMATION")
                        was_fixed = True
                    report.add_finding(Finding(self.name, project, path.name,
                        "HIGH", "Missing INSTANCE",
                        f"'{m}' defined as SOURCE/TARGET/TRANSFORMATION but not declared as INSTANCE",
                        fixed=was_fixed,
                        fix_description=f"Added INSTANCE element for '{m}'" if was_fixed else ""))
                ok = False

            # Orphan instances (declared but not referenced in any connector)
            orphan_instances = instances - connector_refs - {"StartTask", "s_m_", "sq_"}
            for o in sorted(orphan_instances):
                if not any(o.startswith(p) for p in ("StartTask",)):
                    report.add_finding(Finding(self.name, project, path.name,
                        "LOW", "Orphan INSTANCE",
                        f"INSTANCE '{o}' declared but not referenced in any CONNECTOR"))
                    ok = False

            if fix and (missing_from_expected or missing_in_instances):
                # Re-indent and write back
                _indent_xml(root)
                ET.register_namespace("", "")
                tree = ET.ElementTree(root)
                with open(path, "wb") as fh:
                    fh.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
                    fh.write(b'<!DOCTYPE POWERMART SYSTEM "powrmart.dtd">\n')
                    tree.write(fh, encoding="utf-8", xml_declaration=False)

            if ok:
                report.add_pass()

        return report


# ─────────────────────────────────────────────────────────────────────────────
# Agent 3: Mapping-Workflow Pairing
# ─────────────────────────────────────────────────────────────────────────────

class Agent03_MappingWorkflowPairing(BaseAgent):
    name = "03_MappingWorkflowPairing"

    def run(self, fix=False, verbose=False) -> AgentReport:
        report = AgentReport(self.name)

        for project in PROJECTS:
            for tier in TIERS:
                m_dir = SAMPLE_DATA_DIR / project / "mappings" / tier
                w_dir = SAMPLE_DATA_DIR / project / "workflows" / tier

                if not m_dir.exists():
                    continue

                mapping_names = {f.stem for f in m_dir.glob("*.xml")}
                workflow_names = {f.stem.removeprefix("wf_") for f in w_dir.glob("*.xml")} if w_dir.exists() else set()

                report.files_checked += len(mapping_names)

                # Mappings without workflows
                for missing in sorted(mapping_names - workflow_names):
                    was_fixed = False
                    if fix:
                        _generate_workflow(project, tier, missing, w_dir)
                        was_fixed = True
                    report.add_finding(Finding(self.name, project, f"{missing}.xml",
                        "HIGH", "Missing Workflow",
                        f"No workflow found for mapping '{missing}'",
                        fixed=was_fixed,
                        fix_description=f"Generated wf_{missing}.xml" if was_fixed else ""))

                # Workflows without mappings (orphan workflows)
                for orphan in sorted(workflow_names - mapping_names):
                    report.add_finding(Finding(self.name, project, f"wf_{orphan}.xml",
                        "MEDIUM", "Orphan Workflow",
                        f"Workflow 'wf_{orphan}.xml' has no corresponding mapping"))

                report.passed += len(mapping_names & workflow_names)

        return report


# ─────────────────────────────────────────────────────────────────────────────
# Agent 4: Parameter Reference Coverage
# ─────────────────────────────────────────────────────────────────────────────

class Agent04_ParameterCoverage(BaseAgent):
    name = "04_ParameterCoverage"

    def run(self, fix=False, verbose=False) -> AgentReport:
        report = AgentReport(self.name)

        for project in PROJECTS:
            # Collect all $$PARAM references across all mapping XMLs
            all_params: Set[str] = set()
            for tier in TIERS:
                m_dir = SAMPLE_DATA_DIR / project / "mappings" / tier
                if not m_dir.exists():
                    continue
                for xml_file in m_dir.glob("*.xml"):
                    try:
                        text = xml_file.read_text(encoding="utf-8")
                        found = re.findall(r'\$\$([A-Z_][A-Z0-9_]*)', text)
                        all_params.update(found)
                    except Exception:
                        pass

            report.files_checked += 3  # dev/uat/prod

            param_dir = SAMPLE_DATA_DIR / project / "parameter_files"
            for env in ("dev", "uat", "prod"):
                param_file = param_dir / f"params_{project}_{env}.xml"
                if not param_file.exists():
                    report.add_finding(Finding(self.name, project, f"params_{project}_{env}.xml",
                        "HIGH", "Missing Param File",
                        f"Parameter file for {env} environment not found"))
                    continue

                root = self.parse_xml(param_file)
                if root is None:
                    report.add_finding(Finding(self.name, project, param_file.name,
                        "HIGH", "Parse Error", "Cannot parse parameter file"))
                    continue

                declared = {p.get("NAME", "").lstrip("$") for p in root.findall("PARAM")}
                missing = all_params - declared

                if missing:
                    for m in sorted(missing):
                        was_fixed = False
                        if fix:
                            elem = ET.SubElement(root, "PARAM")
                            elem.set("NAME", f"$${m}")
                            elem.set("VALUE", _default_param_value(m, env))
                            was_fixed = True
                            # Write back
                            _indent_xml(root)
                            tree = ET.ElementTree(root)
                            with open(param_file, "wb") as fh:
                                fh.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
                                tree.write(fh, encoding="utf-8", xml_declaration=False)
                        report.add_finding(Finding(self.name, project, param_file.name,
                            "MEDIUM", "Missing Param Declaration",
                            f"'$${m}' used in mappings but not declared in {env} param file",
                            fixed=was_fixed,
                            fix_description=f"Added $${m} with default value" if was_fixed else ""))
                else:
                    report.add_pass()

        return report


# ─────────────────────────────────────────────────────────────────────────────
# Agent 5: Tier Coverage Validator
# ─────────────────────────────────────────────────────────────────────────────

class Agent05_TierCoverage(BaseAgent):
    name = "05_TierCoverageValidator"

    def run(self, fix=False, verbose=False) -> AgentReport:
        report = AgentReport(self.name)

        for project in PROJECTS:
            for tier in TIERS:
                m_dir = SAMPLE_DATA_DIR / project / "mappings" / tier
                if not m_dir.exists():
                    continue

                # Collect all transformation types present in this tier
                types_found: Set[str] = set()
                file_count = 0
                for xml_file in m_dir.glob("*.xml"):
                    report.files_checked += 1
                    file_count += 1
                    root = self.parse_xml(xml_file)
                    if root is None:
                        continue
                    for t in root.iter("TRANSFORMATION"):
                        tf_type = t.get("TYPE")
                        if tf_type:
                            types_found.add(tf_type)

                required = TIER_REQUIRED_TYPES.get(tier, set())
                missing_types = required - types_found

                if missing_types:
                    for mt in sorted(missing_types):
                        report.add_finding(Finding(self.name, project,
                            f"{tier}/",
                            "HIGH", "Missing Transform Type",
                            f"Tier '{tier}' has no mapping with '{mt}' transformation (required for pipeline coverage)"))
                else:
                    report.add_pass()

                # Check minimum file counts
                expected_min = {"simple": 15, "medium": 20, "complex": 15}
                if file_count < expected_min.get(tier, 0):
                    report.add_finding(Finding(self.name, project, f"{tier}/",
                        "MEDIUM", "Low File Count",
                        f"Tier '{tier}' has {file_count} files, expected >= {expected_min[tier]}"))

        return report


# ─────────────────────────────────────────────────────────────────────────────
# Agent 6: Session / Workflow Structure
# ─────────────────────────────────────────────────────────────────────────────

class Agent06_SessionWorkflow(BaseAgent):
    name = "06_SessionWorkflowStructure"

    def run(self, fix=False, verbose=False) -> AgentReport:
        report = AgentReport(self.name)

        for project, tier, path in self.all_workflow_files():
            report.files_checked += 1
            root = self.parse_xml(path)
            if root is None:
                continue
            ok = True

            task = root.find(".//TASK")
            if task is None:
                report.add_finding(Finding(self.name, project, path.name,
                    "HIGH", "Missing TASK", "No SESSION task found in workflow"))
                ok = False
                continue

            task_type = task.get("TYPE", "")
            if task_type != "Session":
                report.add_finding(Finding(self.name, project, path.name,
                    "MEDIUM", "Wrong TASK TYPE",
                    f"TASK TYPE is '{task_type}', expected 'Session'"))
                ok = False

            # Check session has Mapping Name attribute
            task_attrs = {a.get("NAME"): a.get("VALUE") for a in task.findall("ATTRIBUTE")}
            if "Mapping Name" not in task_attrs:
                report.add_finding(Finding(self.name, project, path.name,
                    "HIGH", "Missing Mapping Name",
                    "SESSION task has no 'Mapping Name' attribute linking to a mapping"))
                ok = False

            # Check TASKINSTANCE exists
            wf = root.find(".//WORKFLOW")
            if wf is not None:
                if wf.find("TASKINSTANCE") is None:
                    report.add_finding(Finding(self.name, project, path.name,
                        "MEDIUM", "Missing TASKINSTANCE",
                        "WORKFLOW element has no TASKINSTANCE child"))
                    ok = False

            if ok:
                report.add_pass()

        return report


# ─────────────────────────────────────────────────────────────────────────────
# Agent 7: Cross-Reference Integrity
# ─────────────────────────────────────────────────────────────────────────────

class Agent07_CrossReference(BaseAgent):
    name = "07_CrossReferenceIntegrity"

    def run(self, fix=False, verbose=False) -> AgentReport:
        report = AgentReport(self.name)

        for project, tier, path in self.all_mapping_files():
            report.files_checked += 1
            root = self.parse_xml(path)
            if root is None:
                continue
            folder = self.get_folder(root)
            if folder is None:
                continue
            mapping = folder.find("MAPPING")
            if mapping is None:
                continue

            # Build name registries
            source_names = {s.get("NAME") for s in folder.findall("SOURCE") if s.get("NAME")}
            target_names = {t.get("NAME") for t in folder.findall("TARGET") if t.get("NAME")}
            tf_names = {t.get("NAME") for t in folder.findall("TRANSFORMATION") if t.get("NAME")}
            instance_names = {i.get("NAME") for i in mapping.findall("INSTANCE") if i.get("NAME")}
            all_valid = source_names | target_names | tf_names | instance_names

            ok = True
            for conn in mapping.findall("CONNECTOR"):
                from_inst = conn.get("FROMINSTANCE", "")
                to_inst = conn.get("TOINSTANCE", "")

                if from_inst and from_inst not in all_valid:
                    report.add_finding(Finding(self.name, project, path.name,
                        "CRITICAL", "Dangling FROMINSTANCE",
                        f"CONNECTOR FROMINSTANCE='{from_inst}' not defined anywhere in the mapping"))
                    ok = False

                if to_inst and to_inst not in all_valid:
                    report.add_finding(Finding(self.name, project, path.name,
                        "CRITICAL", "Dangling TOINSTANCE",
                        f"CONNECTOR TOINSTANCE='{to_inst}' not defined anywhere in the mapping"))
                    ok = False

            # Check INSTANCE TRANSFORMATION_NAME exists
            for inst in mapping.findall("INSTANCE"):
                tf_name = inst.get("TRANSFORMATION_NAME", "")
                inst_type = inst.get("TYPE", "")
                if inst_type == "TRANSFORMATION" and tf_name and tf_name not in tf_names:
                    report.add_finding(Finding(self.name, project, path.name,
                        "HIGH", "Broken INSTANCE ref",
                        f"INSTANCE references TRANSFORMATION_NAME='{tf_name}' which doesn't exist"))
                    ok = False
                elif inst_type == "SOURCE" and tf_name and tf_name not in source_names:
                    report.add_finding(Finding(self.name, project, path.name,
                        "HIGH", "Broken INSTANCE ref",
                        f"SOURCE INSTANCE references '{tf_name}' which isn't a declared SOURCE"))
                    ok = False
                elif inst_type == "TARGET" and tf_name and tf_name not in target_names:
                    report.add_finding(Finding(self.name, project, path.name,
                        "HIGH", "Broken INSTANCE ref",
                        f"TARGET INSTANCE references '{tf_name}' which isn't a declared TARGET"))
                    ok = False

            if ok:
                report.add_pass()

        return report


# ─────────────────────────────────────────────────────────────────────────────
# Agent 8: Scenario Coverage Auditor
# ─────────────────────────────────────────────────────────────────────────────

class Agent08_ScenarioCoverage(BaseAgent):
    name = "08_ScenarioCoverageAuditor"

    def run(self, fix=False, verbose=False) -> AgentReport:
        report = AgentReport(self.name)

        # Track which scenarios are covered across all projects
        scenario_hits: Dict[str, List[str]] = defaultdict(list)

        for project, tier, path in self.all_mapping_files():
            report.files_checked += 1
            root = self.parse_xml(path)
            if root is None:
                continue
            for scenario_key, scenario_def in REQUIRED_SCENARIOS.items():
                try:
                    if scenario_def["detect"](root):
                        scenario_hits[scenario_key].append(f"{project}/{tier}/{path.name}")
                        report.add_pass()
                except Exception:
                    pass

        # Report missing scenarios
        for scenario_key, scenario_def in REQUIRED_SCENARIOS.items():
            hits = scenario_hits.get(scenario_key, [])
            if not hits:
                report.add_finding(Finding(self.name, "ALL", "—",
                    "HIGH", "Missing Pipeline Scenario",
                    f"No mapping covers scenario '{scenario_key}': {scenario_def['description']}. "
                    f"This means pipeline agents may not be tested for this case."))
            elif len(hits) == 1:
                report.add_finding(Finding(self.name, "ALL", hits[0],
                    "LOW", "Single Coverage",
                    f"Scenario '{scenario_key}' covered by only 1 file — consider adding a second test case"))
            else:
                if verbose:
                    print(f"  ✓ {scenario_key}: {len(hits)} files cover this scenario")

        return report


# ─────────────────────────────────────────────────────────────────────────────
# Agent 9: Symmetry Enforcer
# ─────────────────────────────────────────────────────────────────────────────

class Agent09_SymmetryEnforcer(BaseAgent):
    name = "09_SymmetryEnforcer"

    def run(self, fix=False, verbose=False) -> AgentReport:
        report = AgentReport(self.name)

        counts: Dict[str, Dict[str, int]] = {}
        for project in PROJECTS:
            report.files_checked += 1
            tier_counts = {}
            for tier in TIERS:
                m_dir = SAMPLE_DATA_DIR / project / "mappings" / tier
                w_dir = SAMPLE_DATA_DIR / project / "workflows" / tier
                tier_counts[f"m_{tier}"] = len(list(m_dir.glob("*.xml"))) if m_dir.exists() else 0
                tier_counts[f"w_{tier}"] = len(list(w_dir.glob("*.xml"))) if w_dir.exists() else 0

            # Check all_mappings sync
            all_m = SAMPLE_DATA_DIR / project / "all_mappings"
            tier_counts["all_mappings"] = len(list(all_m.glob("*.xml"))) if all_m.exists() else 0
            tier_counts["total_m"] = sum(tier_counts[f"m_{t}"] for t in TIERS)
            counts[project] = tier_counts

        # Compare across projects
        ref_project = PROJECTS[0]
        ref_counts = counts[ref_project]

        for project in PROJECTS[1:]:
            for key, ref_val in ref_counts.items():
                actual = counts[project].get(key, 0)
                if actual != ref_val:
                    severity = "MEDIUM" if abs(actual - ref_val) <= 2 else "HIGH"
                    report.add_finding(Finding(self.name, project, f"{key}/",
                        severity, "Asymmetric Count",
                        f"'{key}' count={actual} vs {ref_project} count={ref_val} (diff={actual-ref_val:+d})"))
                else:
                    report.add_pass()

        # Check mapping count == workflow count per project
        for project in PROJECTS:
            for tier in TIERS:
                mc = counts[project].get(f"m_{tier}", 0)
                wc = counts[project].get(f"w_{tier}", 0)
                if mc != wc:
                    report.add_finding(Finding(self.name, project, f"{tier}/",
                        "HIGH", "Mapping/Workflow Mismatch",
                        f"Tier '{tier}': {mc} mappings but {wc} workflows"))

        # Check all_mappings count == total mappings
        for project in PROJECTS:
            total = counts[project]["total_m"]
            all_count = counts[project]["all_mappings"]
            if all_count != total:
                was_fixed = False
                if fix:
                    _sync_all_mappings(project)
                    was_fixed = True
                report.add_finding(Finding(self.name, project, "all_mappings/",
                    "MEDIUM", "all_mappings Out of Sync",
                    f"all_mappings/ has {all_count} files but total from tiers is {total}",
                    fixed=was_fixed,
                    fix_description="Synced all_mappings/ from tier directories" if was_fixed else ""))
            else:
                report.add_pass()

        return report


# ─────────────────────────────────────────────────────────────────────────────
# Agent 10: Manifest / Index Sync
# ─────────────────────────────────────────────────────────────────────────────

class Agent10_ManifestSync(BaseAgent):
    name = "10_ManifestIndexSync"

    def run(self, fix=False, verbose=False) -> AgentReport:
        report = AgentReport(self.name)

        for project in PROJECTS:
            report.files_checked += 2  # manifest + index

            # Collect actual mapping filenames (from all_mappings or tiers)
            actual_files: Set[str] = set()
            for tier in TIERS:
                m_dir = SAMPLE_DATA_DIR / project / "mappings" / tier
                if m_dir.exists():
                    actual_files.update(f.name for f in m_dir.glob("*.xml"))

            # Check manifest JSON
            manifest_path = SAMPLE_DATA_DIR / project / f"{project}_full.manifest.json"
            if not manifest_path.exists():
                report.add_finding(Finding(self.name, project, manifest_path.name,
                    "HIGH", "Missing Manifest", "Manifest JSON file not found"))
            else:
                try:
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    manifest_files = set(manifest.get("mappings", []))
                    declared_total = manifest.get("total_mappings", -1)

                    missing_from_manifest = actual_files - manifest_files
                    extra_in_manifest = manifest_files - actual_files

                    if missing_from_manifest or extra_in_manifest or declared_total != len(actual_files):
                        was_fixed = False
                        if fix:
                            manifest["mappings"] = sorted(actual_files)
                            manifest["total_mappings"] = len(actual_files)
                            dist = {}
                            for tier in TIERS:
                                m_dir = SAMPLE_DATA_DIR / project / "mappings" / tier
                                dist[tier] = len(list(m_dir.glob("*.xml"))) if m_dir.exists() else 0
                            manifest["mapping_distribution"] = dist
                            manifest_path.write_text(
                                json.dumps(manifest, indent=2), encoding="utf-8")
                            was_fixed = True

                        details = []
                        if missing_from_manifest:
                            details.append(f"{len(missing_from_manifest)} files on disk not in manifest")
                        if extra_in_manifest:
                            details.append(f"{len(extra_in_manifest)} entries in manifest not on disk")
                        if declared_total != len(actual_files):
                            details.append(f"total_mappings={declared_total} but actual={len(actual_files)}")

                        report.add_finding(Finding(self.name, project, manifest_path.name,
                            "MEDIUM", "Manifest Out of Sync",
                            "; ".join(details),
                            fixed=was_fixed,
                            fix_description="Regenerated manifest from disk" if was_fixed else ""))
                    else:
                        report.add_pass()

                except (json.JSONDecodeError, KeyError) as e:
                    report.add_finding(Finding(self.name, project, manifest_path.name,
                        "HIGH", "Manifest Parse Error", str(e)))

            # Check INDEX.txt
            index_path = SAMPLE_DATA_DIR / project / "INDEX.txt"
            if not index_path.exists():
                report.add_finding(Finding(self.name, project, "INDEX.txt",
                    "LOW", "Missing INDEX", "INDEX.txt not found"))
            else:
                index_text = index_path.read_text(encoding="utf-8")
                missing_from_index = [f for f in sorted(actual_files)
                                       if f.replace(".xml", "") not in index_text and f not in index_text]
                if missing_from_index:
                    report.add_finding(Finding(self.name, project, "INDEX.txt",
                        "LOW", "INDEX Out of Sync",
                        f"{len(missing_from_index)} mapping files not referenced in INDEX.txt"))
                else:
                    report.add_pass()

        return report


# ─────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────────────────────────────────────

def _indent_xml(elem: ET.Element, level: int = 0):
    """Add pretty-print indentation to an XML tree in-place."""
    indent = "\n" + "  " * level
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = indent + "  "
        if not elem.tail or not elem.tail.strip():
            elem.tail = indent
        for child in elem:
            _indent_xml(child, level + 1)
        if not child.tail or not child.tail.strip():
            child.tail = indent
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = indent


def _default_param_value(param_name: str, env: str) -> str:
    """Return a sensible default value for a missing parameter."""
    name_lower = param_name.lower()
    schema_map = {"dev": "DEV", "uat": "UAT", "prod": "PROD"}
    suffix = schema_map.get(env, "DEV")
    if "src_schema" in name_lower or "source_schema" in name_lower:
        return f"OLTP_{suffix}"
    if "tgt_schema" in name_lower or "target_schema" in name_lower:
        return f"DWH_{suffix}"
    if "load_date" in name_lower or "date" in name_lower:
        return "TRUNC(SYSDATE)"
    if "environment" in name_lower or "env" in name_lower:
        return env.upper()
    if "batch" in name_lower:
        return "1"
    if "conn" in name_lower or "connection" in name_lower:
        return f"$$SRC_CONN_{suffix}"
    return f"DEFAULT_{suffix}"


def _generate_workflow(project: str, tier: str, mapping_stem: str, w_dir: Path):
    """Generate a minimal workflow XML for a mapping that has no workflow."""
    w_dir.mkdir(parents=True, exist_ok=True)
    session_name = f"s_{mapping_stem}"
    wf_name = f"wf_{mapping_stem}"
    xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE POWERMART SYSTEM "powrmart.dtd">
<POWERMART CREATION_DATE="{datetime.date.today().strftime('%m/%d/%Y')}" REPOSITORY_VERSION="112">
<REPOSITORY CODEPAGE="UTF-8" DATABASETYPE="Oracle" NAME="{project.upper()}_DWH" VERSION="112">
<FOLDER DESCRIPTION="{project} folder" GROUP="" NAME="{project}" OWNER="Administrator" PERMISSIONS="rwx---r--" SHARED="NOTSHARED">
<CONFIG DESCRIPTION="" ISDEFAULT="YES" NAME="default" VERSIONNUMBER="1">
<ATTRIBUTE NAME="Enable Test Load" VALUE="NO"/>
<ATTRIBUTE NAME="Commit Interval" VALUE="10000"/>
<ATTRIBUTE NAME="Commit Type" VALUE="Source"/>
<ATTRIBUTE NAME="Rollback Segment" VALUE=""/>
<ATTRIBUTE NAME="Recovery Strategy" VALUE="Restart from beginning"/>
</CONFIG>
<TASK DESCRIPTION="Session for {mapping_stem}" ISVALID="YES" NAME="{session_name}" REUSABLE="NO" TYPE="Session" VERSIONNUMBER="1">
<ATTRIBUTE NAME="Mapping Name" VALUE="{mapping_stem}"/>
<ATTRIBUTE NAME="Session Log File" VALUE="{session_name}.log"/>
<ATTRIBUTE NAME="Enable Test Load" VALUE="NO"/>
<ATTRIBUTE NAME="Error Threshold" VALUE="0"/>
<ATTRIBUTE NAME="Treat Source Rows As" VALUE="Data Driven"/>
</TASK>
<WORKFLOW DESCRIPTION="Workflow for {mapping_stem}" ISENABLED="YES" ISRUNNABLEINDEPENDENTLY="YES" ISSERVICE="NO" ISSESSIONBASEDREPO="YES" ISVALID="YES" NAME="{wf_name}" REUSABLE="NO" SCHEDULERTYPE="0" VERSIONNUMBER="1">
<TASKINSTANCE DESCRIPTION="" ISOVERRIDABLE="NO" NAME="{session_name}" TASKTYPENAME="Session" TASKNAME="{session_name}"/>
</WORKFLOW>
</FOLDER>
</REPOSITORY>
</POWERMART>
"""
    out_path = w_dir / f"wf_{mapping_stem}.xml"
    out_path.write_text(xml_content, encoding="utf-8")


def _sync_all_mappings(project: str):
    """Sync all_mappings/ directory from the tier directories."""
    all_dir = SAMPLE_DATA_DIR / project / "all_mappings"
    all_dir.mkdir(exist_ok=True)
    # Remove stale files
    for f in all_dir.glob("*.xml"):
        f.unlink()
    # Copy from tiers
    for tier in TIERS:
        m_dir = SAMPLE_DATA_DIR / project / "mappings" / tier
        if m_dir.exists():
            for f in m_dir.glob("*.xml"):
                shutil.copy2(f, all_dir / f.name)


# ─────────────────────────────────────────────────────────────────────────────
# Leader Agent
# ─────────────────────────────────────────────────────────────────────────────

class LeaderAgent:
    """
    Orchestrates all sub-agents, collects reports, applies fixes,
    evaluates completeness, and issues a final pass/fail verdict.
    """

    AGENTS = [
        Agent01_XMLSchema,
        Agent02_InstanceConnector,
        Agent03_MappingWorkflowPairing,
        Agent04_ParameterCoverage,
        Agent05_TierCoverage,
        Agent06_SessionWorkflow,
        Agent07_CrossReference,
        Agent08_ScenarioCoverage,
        Agent09_SymmetryEnforcer,
        Agent10_ManifestSync,
    ]

    def __init__(self, fix: bool = False, verbose: bool = False):
        self.fix = fix
        self.verbose = verbose
        self.reports: List[AgentReport] = []

    def run(self):
        print("=" * 70)
        print("  LEADER AGENT — Sample Data Validator")
        print(f"  Mode: {'FIX' if self.fix else 'AUDIT ONLY'} | Verbose: {self.verbose}")
        print(f"  Projects: {', '.join(PROJECTS)}")
        print(f"  Sample Data Dir: {SAMPLE_DATA_DIR}")
        print("=" * 70)
        print()

        if not SAMPLE_DATA_DIR.exists():
            print(f"[FATAL] sample_data directory not found at: {SAMPLE_DATA_DIR}")
            sys.exit(1)

        for AgentClass in self.AGENTS:
            agent = AgentClass()
            print(f"▶  Running {agent.name} ...", end=" ", flush=True)
            report = agent.run(fix=self.fix, verbose=self.verbose)
            self.reports.append(report)
            status = "✓ PASS" if not report.findings else f"⚠ {report.failed} finding(s)"
            if self.fix and report.fixed:
                status += f" [{report.fixed} fixed]"
            print(status)
            print(f"   {report.summary()}")

            if self.verbose and report.findings:
                for f in report.findings:
                    prefix = "  [FIXED]" if f.fixed else "  [OPEN] "
                    print(f"   {prefix} [{f.severity}] {f.project}/{f.file}: {f.message}")
            print()

        self._final_evaluation()

    def _final_evaluation(self):
        print("=" * 70)
        print("  LEADER AGENT — FINAL EVALUATION")
        print("=" * 70)
        print()

        all_findings = [f for r in self.reports for f in r.findings]
        open_findings = [f for f in all_findings if not f.fixed]
        fixed_findings = [f for f in all_findings if f.fixed]

        # Count by severity
        sev_counts: Dict[str, int] = defaultdict(int)
        for f in open_findings:
            sev_counts[f.severity] += 1

        # Print finding summary
        print("  Finding Summary (open):")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            n = sev_counts.get(sev, 0)
            if n > 0:
                bar = "█" * min(n, 40)
                print(f"    {sev:8s} {n:4d}  {bar}")
        print()
        if fixed_findings:
            print(f"  Auto-fixed this run: {len(fixed_findings)}")
            print()

        # Per-agent pass rate
        print("  Agent Results:")
        print(f"  {'Agent':<35} {'Checked':>7} {'Pass':>6} {'Open':>6} {'Fixed':>6}")
        print("  " + "-" * 62)
        for r in self.reports:
            open_count = r.failed - r.fixed
            print(f"  {r.agent_name:<35} {r.files_checked:>7} {r.passed:>6} {open_count:>6} {r.fixed:>6}")
        print()

        # Open findings detail
        if open_findings:
            print("  Open Findings:")
            print()
            by_severity = defaultdict(list)
            for f in open_findings:
                by_severity[f.severity].append(f)

            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                findings_for_sev = by_severity.get(sev, [])
                if not findings_for_sev:
                    continue
                print(f"  [{sev}] ({len(findings_for_sev)} finding(s))")
                for f in findings_for_sev[:20]:  # cap at 20 per severity
                    loc = f"{f.project}/{f.file}"
                    msg = textwrap.shorten(f.message, width=65)
                    print(f"    • [{f.agent}] {loc}")
                    print(f"      {msg}")
                if len(findings_for_sev) > 20:
                    print(f"    ... and {len(findings_for_sev) - 20} more")
                print()

        # Verdict
        criticals = sev_counts.get("CRITICAL", 0)
        highs = sev_counts.get("HIGH", 0)
        mediums = sev_counts.get("MEDIUM", 0)

        print("  " + "─" * 60)
        if criticals > 0:
            verdict = "FAIL — CRITICAL issues must be resolved before testing"
            verdict_icon = "✗"
        elif highs > 0:
            verdict = "CONDITIONAL PASS — HIGH issues should be fixed"
            verdict_icon = "⚠"
        elif mediums > 0:
            verdict = "PASS WITH WARNINGS — MEDIUM issues are advisory"
            verdict_icon = "✓"
        else:
            verdict = "FULL PASS — Sample data is clean and test-ready"
            verdict_icon = "✓"

        print(f"\n  {verdict_icon}  VERDICT: {verdict}")
        print()

        total_checked = sum(r.files_checked for r in self.reports)
        total_pass = sum(r.passed for r in self.reports)
        completeness_pct = (total_pass / total_checked * 100) if total_checked else 0
        print(f"  Completeness Score: {completeness_pct:.1f}%  "
              f"({total_pass}/{total_checked} checks passed)")
        print()

        if self.fix and fixed_findings:
            print("  ✓ Auto-fix applied. Re-run without --fix to confirm clean state.")
        elif not self.fix and open_findings:
            print("  Tip: Re-run with --fix to auto-repair eligible issues.")

        print("=" * 70)

        # Exit code
        return 0 if criticals == 0 else 1


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Sample Data Validator — Leader Agent for Informatica PowerCenter test fixtures")
    parser.add_argument("--fix", action="store_true",
        help="Auto-repair eligible issues (missing params, orphan workflows, manifest sync, all_mappings sync)")
    parser.add_argument("--verbose", "-v", action="store_true",
        help="Print all findings inline as agents run")
    args = parser.parse_args()

    leader = LeaderAgent(fix=args.fix, verbose=args.verbose)
    leader.run()


if __name__ == "__main__":
    main()
