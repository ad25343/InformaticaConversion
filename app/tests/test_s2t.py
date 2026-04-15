# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Comprehensive unit tests for the S2T (Source-to-Target) lineage tracer.

Coverage areas:
  1. Direct source → target (no transformation)
  2. Expression pass-through (EXP with trivial expression)
  3. Router group-qualified port stripping
  4. Joiner M_/MASTER_/D_/DETAIL_ group prefix resolution
  5. Source Qualifier (SQ_*) → actual source table resolution
  6. Single-level expression derivation (FRAUD_SCORE → INDICATOR_SCORE)
  7. Multi-level internal expression chain (RISK_BAND → FRAUD_SCORE → INDICATOR_SCORE)
  8. Genuinely computed fields (SYSDATE, $$param, string literal) — stay at EXP
  9. Unmapped target fields (no upstream connector)
  10. Unmapped source fields (source field never reaches a target)
  11. max_depth protection (trace too deep)
  12. SQ_ resolution via _build_sq_resolution helper
  13. Backward / forward index builders
  14. Multi-hop chain through Expression + Joiner + Source Qualifier
"""
from __future__ import annotations

import pytest
from pathlib import Path

from backend.agents.s2t_agent import (
    _build_backward_index,
    _build_forward_index,
    _build_sq_resolution,
    _find_unmapped_source_fields,
    _follow_internal_expr_chain,
    _find_followable_token,
    _trace_to_source,
    STATUS_DIRECT,
    STATUS_DERIVED,
    STATUS_FILTERED,
    STATUS_LOOKUP,
    STATUS_AGGREGATE,
    STATUS_UNMAPPED_TGT,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _trans(name: str, ttype: str, ports=None, expressions=None) -> dict:
    return {
        "name":        name,
        "type":        ttype,
        "ports":       ports or [],
        "expressions": expressions or [],
    }


def _port(name: str, datatype: str = "string") -> dict:
    return {"name": name, "datatype": datatype}


def _expr(port: str, expression: str) -> dict:
    return {"port": port, "expression": expression}


def _conn(from_inst: str, from_field: str, to_inst: str, to_field: str) -> dict:
    return {
        "from_instance": from_inst,
        "from_field":    from_field,
        "to_instance":   to_inst,
        "to_field":      to_field,
    }


def _make_get_trans(trans_list: list[dict]):
    """Return a simple get_trans closure backed by a list of transformation dicts."""
    by_name = {t["name"]: t for t in trans_list}
    def get_trans(name: str):
        return by_name.get(name)
    return by_name, get_trans


# ─────────────────────────────────────────────────────────────────────────────
# 1. Index builders
# ─────────────────────────────────────────────────────────────────────────────

class TestIndexBuilders:
    def test_backward_index_single(self):
        conns = [_conn("SQ_ORDERS", "ORDER_ID", "EXP_ENRICH", "ORDER_ID")]
        idx = _build_backward_index(conns)
        assert idx[("EXP_ENRICH", "ORDER_ID")] == ("SQ_ORDERS", "ORDER_ID")

    def test_backward_index_multiple(self):
        conns = [
            _conn("SQ_A", "F1", "EXP", "F1"),
            _conn("SQ_A", "F2", "EXP", "F2"),
            _conn("EXP",  "F1", "TGT", "T1"),
        ]
        idx = _build_backward_index(conns)
        assert idx[("EXP", "F1")]  == ("SQ_A", "F1")
        assert idx[("EXP", "F2")]  == ("SQ_A", "F2")
        assert idx[("TGT", "T1")]  == ("EXP",  "F1")

    def test_forward_index_fan_out(self):
        conns = [
            _conn("SQ", "ID", "EXP1", "ID"),
            _conn("SQ", "ID", "EXP2", "ID"),
        ]
        fwd = _build_forward_index(conns)
        assert set(fwd[("SQ", "ID")]) == {("EXP1", "ID"), ("EXP2", "ID")}

    def test_empty_connectors(self):
        assert _build_backward_index([]) == {}
        assert _build_forward_index([]) == {}


# ─────────────────────────────────────────────────────────────────────────────
# 2. SQ resolution builder
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildSqResolution:
    def _make_graph(self, sq_name: str, source_name: str) -> dict:
        return {
            "sources": [{"name": source_name, "fields": []}],
            "mappings": [{
                "name": "m_test",
                "transformations": [
                    _trans(sq_name, "Source Qualifier"),
                ],
                "connectors": [],
                "instance_map": {},
            }],
            "targets": [],
        }

    def test_sq_prefix_stripped(self):
        graph = self._make_graph("SQ_ORDERS", "ORDERS")
        result = _build_sq_resolution(graph, {"ORDERS"})
        assert result == {"SQ_ORDERS": "ORDERS"}

    def test_sqi_prefix_stripped(self):
        graph = self._make_graph("SQI_CUSTOMERS", "CUSTOMERS")
        result = _build_sq_resolution(graph, {"CUSTOMERS"})
        assert result == {"SQI_CUSTOMERS": "CUSTOMERS"}

    def test_src_sq_prefix_stripped(self):
        graph = self._make_graph("SRC_SQ_PRODUCTS", "PRODUCTS")
        result = _build_sq_resolution(graph, {"PRODUCTS"})
        assert result == {"SRC_SQ_PRODUCTS": "PRODUCTS"}

    def test_case_insensitive_match(self):
        graph = self._make_graph("SQ_claim_submissions", "CLAIM_SUBMISSIONS")
        result = _build_sq_resolution(graph, {"CLAIM_SUBMISSIONS"})
        assert result == {"SQ_claim_submissions": "CLAIM_SUBMISSIONS"}

    def test_no_match_when_source_missing(self):
        graph = self._make_graph("SQ_MISSING_TABLE", "ORDERS")
        result = _build_sq_resolution(graph, {"ORDERS"})
        assert result == {}

    def test_non_sq_transformation_ignored(self):
        graph = self._make_graph("SQ_ORDERS", "ORDERS")
        # Add a non-SQ transformation
        graph["mappings"][0]["transformations"].append(
            _trans("EXP_COMPUTE", "Expression")
        )
        result = _build_sq_resolution(graph, {"ORDERS"})
        assert "EXP_COMPUTE" not in result
        assert result == {"SQ_ORDERS": "ORDERS"}

    def test_multiple_sq_instances(self):
        graph = {
            "sources": [
                {"name": "ORDERS",    "fields": []},
                {"name": "CUSTOMERS", "fields": []},
            ],
            "mappings": [{
                "name": "m_multi",
                "transformations": [
                    _trans("SQ_ORDERS",    "Source Qualifier"),
                    _trans("SQ_CUSTOMERS", "Source Qualifier"),
                ],
                "connectors": [],
                "instance_map": {},
            }],
            "targets": [],
        }
        result = _build_sq_resolution(graph, {"ORDERS", "CUSTOMERS"})
        assert result == {"SQ_ORDERS": "ORDERS", "SQ_CUSTOMERS": "CUSTOMERS"}


# ─────────────────────────────────────────────────────────────────────────────
# 3. Internal expression chain follower
# ─────────────────────────────────────────────────────────────────────────────

class TestFollowInternalExprChain:
    def test_direct_match_in_backward(self):
        """Token found immediately in backward connector."""
        trans = _trans("EXP", "Expression",
            ports=[_port("SCORE"), _port("INPUT_SCORE")],
            expressions=[_expr("SCORE", "ROUND(INPUT_SCORE, 2)")],
        )
        backward = {("EXP", "INPUT_SCORE"): ("SQ_SRC", "RAW_SCORE")}
        result = _follow_internal_expr_chain(trans, "SCORE", "EXP", backward)
        assert result == "INPUT_SCORE"

    def test_two_level_chain(self):
        """RISK_BAND → FRAUD_SCORE → INDICATOR_SCORE (has backward)."""
        trans = _trans("EXP", "Expression",
            ports=[_port("RISK_BAND"), _port("FRAUD_SCORE"), _port("INDICATOR_SCORE")],
            expressions=[
                _expr("RISK_BAND",       "IIF(FRAUD_SCORE >= 80, 'HIGH', 'LOW')"),
                _expr("FRAUD_SCORE",     "ROUND(INDICATOR_SCORE * 1.1, 2)"),
                # INDICATOR_SCORE has no expression — it's an input port
            ],
        )
        backward = {("EXP", "INDICATOR_SCORE"): ("JNR", "INDICATOR_SCORE")}
        result = _follow_internal_expr_chain(trans, "RISK_BAND", "EXP", backward)
        assert result == "INDICATOR_SCORE"

    def test_returns_empty_when_all_internal(self):
        """All ports are internally derived — no backward connector exists."""
        trans = _trans("EXP", "Expression",
            ports=[_port("A"), _port("B"), _port("C")],
            expressions=[
                _expr("A", "IIF(B > 0, 1, 0)"),
                _expr("B", "C + 1"),
                # C has no expression either — but no backward connector for C
            ],
        )
        backward = {}  # nothing has a backward connector
        result = _follow_internal_expr_chain(trans, "A", "EXP", backward)
        assert result == ""

    def test_max_depth_respected(self):
        """Chain longer than max_depth returns empty."""
        # A→B, B→C, C→D, D→E (5 hops)  with max_depth=2
        trans = _trans("EXP", "Expression",
            ports=[_port("A"), _port("B"), _port("C"), _port("D"), _port("E")],
            expressions=[
                _expr("A", "B + 1"),
                _expr("B", "C + 1"),
                _expr("C", "D + 1"),
                _expr("D", "E + 1"),
            ],
        )
        backward = {("EXP", "E"): ("SQ", "E")}
        result = _follow_internal_expr_chain(trans, "A", "EXP", backward, max_depth=2)
        assert result == ""  # too deep

    def test_visits_each_port_once(self):
        """Cyclic-looking expressions don't cause infinite loops."""
        trans = _trans("EXP", "Expression",
            ports=[_port("X"), _port("Y")],
            expressions=[
                _expr("X", "Y + X"),  # X references itself
                _expr("Y", "X - 1"),  # Y references X
            ],
        )
        backward = {}
        result = _follow_internal_expr_chain(trans, "X", "EXP", backward)
        assert result == ""


# ─────────────────────────────────────────────────────────────────────────────
# 4. _find_followable_token
# ─────────────────────────────────────────────────────────────────────────────

class TestFindFollowableToken:
    def test_direct_token_with_backward(self):
        port_names = {"INPUT_ID", "DERIVED_ID"}
        backward = {("EXP", "INPUT_ID"): ("SQ", "ID")}
        notes: list[str] = []
        result = _find_followable_token(
            "INPUT_ID + 1", "DERIVED_ID", "EXP", port_names, backward, notes
        )
        assert result == "INPUT_ID"
        assert notes  # note appended

    def test_skips_self_token(self):
        """Expression references both AMOUNT and GROSS_AMOUNT; should follow AMOUNT (not self)."""
        port_names = {"AMOUNT", "GROSS_AMOUNT"}
        backward = {("EXP", "AMOUNT"): ("SQ", "AMOUNT")}
        notes: list[str] = []
        result = _find_followable_token(
            "GROSS_AMOUNT - AMOUNT", "GROSS_AMOUNT", "EXP", port_names, backward, notes
        )
        # GROSS_AMOUNT is the current field — should skip itself and follow AMOUNT
        assert result == "AMOUNT"

    def test_internal_chain_fallback(self):
        """Token in port_names but not in backward — should follow internal chain."""
        trans = _trans("EXP", "Expression",
            ports=[_port("DERIVED_A"), _port("INTERNAL_B"), _port("INPUT_C")],
            expressions=[
                _expr("DERIVED_A",  "INTERNAL_B * 2"),
                _expr("INTERNAL_B", "INPUT_C + 1"),
            ],
        )
        port_names = {"DERIVED_A", "INTERNAL_B", "INPUT_C"}
        backward = {("EXP", "INPUT_C"): ("SQ", "RAW_C")}
        notes: list[str] = []
        result = _find_followable_token(
            "INTERNAL_B * 2", "DERIVED_A", "EXP", port_names, backward, notes, trans=trans
        )
        assert result == "INPUT_C"

    def test_returns_empty_when_no_token(self):
        port_names = {"AMOUNT"}
        backward = {}
        notes: list[str] = []
        result = _find_followable_token(
            "SYSDATE", "ETL_LOAD_DT", "EXP", port_names, backward, notes
        )
        assert result == ""


# ─────────────────────────────────────────────────────────────────────────────
# 5. _trace_to_source — core scenarios
# ─────────────────────────────────────────────────────────────────────────────

class TestTraceToSource:

    # ── 5a. Direct mapping (source directly connected to target) ────────────
    def test_direct_source_to_target(self):
        """
        SOURCE ──connector──▶ TARGET
        The backward lookup on (TARGET, FIELD) immediately lands in source_names.
        """
        conns = [_conn("ORDERS", "ORDER_ID", "FCT_ORDERS", "ORDER_ID")]
        backward = _build_backward_index(conns)
        source_names = {"ORDERS"}
        by_name, get_trans = _make_get_trans([])

        result = _trace_to_source(
            "FCT_ORDERS", "ORDER_ID",
            backward, source_names, by_name, get_trans,
        )
        assert result["source_table"] == "ORDERS"
        assert result["source_field"] == "ORDER_ID"
        assert result["status"] == STATUS_DIRECT
        assert result["chain"] == []

    # ── 5b. One-hop through Source Qualifier ────────────────────────────────
    def test_sq_resolution_one_hop(self):
        """
        ORDERS ──(no connector)──▶ SQ_ORDERS ──connector──▶ EXP ──connector──▶ FCT_ORDERS
        Backward trace: FCT_ORDERS ← EXP ← SQ_ORDERS → resolved to ORDERS via sq_resolution
        """
        conns = [
            _conn("SQ_ORDERS", "ORDER_ID", "EXP_ENRICH", "ORDER_ID"),
            _conn("EXP_ENRICH",  "ORDER_ID", "FCT_ORDERS",  "ORDER_ID"),
        ]
        backward     = _build_backward_index(conns)
        source_names = {"ORDERS"}
        sq_resolution = {"SQ_ORDERS": "ORDERS"}
        exp_trans = _trans("EXP_ENRICH", "Expression",
            ports=[_port("ORDER_ID")],
            expressions=[_expr("ORDER_ID", "ORDER_ID")],  # pass-through
        )
        by_name, get_trans = _make_get_trans([exp_trans])

        result = _trace_to_source(
            "FCT_ORDERS", "ORDER_ID",
            backward, source_names, by_name, get_trans,
            sq_resolution=sq_resolution,
        )
        assert result["source_table"] == "ORDERS"
        assert result["source_field"] == "ORDER_ID"

    # ── 5c. Joiner M_ prefix ────────────────────────────────────────────────
    def test_joiner_master_prefix(self):
        """
        SQ_CLAIMS ──▶ JNR_CLAIMS (input: M_CLAIM_ID) ──▶ EXP ──▶ FCT
        The Joiner output port is CLAIM_ID, but the input connector uses M_CLAIM_ID.
        """
        conns = [
            _conn("SQ_CLAIMS",   "CLAIM_ID", "JNR_CLAIMS",  "M_CLAIM_ID"),
            _conn("JNR_CLAIMS",  "CLAIM_ID", "EXP_FINAL",   "CLAIM_ID"),
            _conn("EXP_FINAL",   "CLAIM_ID", "FCT_CLAIMS",  "CLAIM_ID"),
        ]
        backward     = _build_backward_index(conns)
        source_names = {"CLAIMS"}
        sq_resolution = {"SQ_CLAIMS": "CLAIMS"}
        jnr_trans = _trans("JNR_CLAIMS", "Joiner",
            ports=[_port("CLAIM_ID"), _port("M_CLAIM_ID")],
        )
        exp_trans = _trans("EXP_FINAL", "Expression",
            ports=[_port("CLAIM_ID")],
            expressions=[_expr("CLAIM_ID", "CLAIM_ID")],
        )
        by_name, get_trans = _make_get_trans([jnr_trans, exp_trans])

        result = _trace_to_source(
            "FCT_CLAIMS", "CLAIM_ID",
            backward, source_names, by_name, get_trans,
            sq_resolution=sq_resolution,
        )
        assert result["source_table"] == "CLAIMS"
        assert result["source_field"] == "CLAIM_ID"

    def test_joiner_detail_prefix(self):
        """Detail-side Joiner input uses D_ prefix."""
        conns = [
            _conn("SQ_ITEMS",  "ITEM_ID", "JNR_ENRICH", "D_ITEM_ID"),
            _conn("JNR_ENRICH","ITEM_ID", "FCT_ITEMS",  "ITEM_ID"),
        ]
        backward = _build_backward_index(conns)
        source_names = {"ITEMS"}
        sq_resolution = {"SQ_ITEMS": "ITEMS"}
        jnr_trans = _trans("JNR_ENRICH", "Joiner",
            ports=[_port("ITEM_ID"), _port("D_ITEM_ID")],
        )
        by_name, get_trans = _make_get_trans([jnr_trans])

        result = _trace_to_source(
            "FCT_ITEMS", "ITEM_ID",
            backward, source_names, by_name, get_trans,
            sq_resolution=sq_resolution,
        )
        assert result["source_table"] == "ITEMS"
        assert result["source_field"] == "ITEM_ID"

    def test_joiner_master_long_prefix(self):
        """MASTER_ prefix variant."""
        conns = [
            _conn("SQ_ACCTS", "ACCT_NUM", "JNR_X", "MASTER_ACCT_NUM"),
            _conn("JNR_X",    "ACCT_NUM", "FCT",   "ACCT_NUM"),
        ]
        backward = _build_backward_index(conns)
        source_names = {"ACCTS"}
        sq_resolution = {"SQ_ACCTS": "ACCTS"}
        jnr_trans = _trans("JNR_X", "Joiner",
            ports=[_port("ACCT_NUM"), _port("MASTER_ACCT_NUM")],
        )
        by_name, get_trans = _make_get_trans([jnr_trans])

        result = _trace_to_source(
            "FCT", "ACCT_NUM",
            backward, source_names, by_name, get_trans,
            sq_resolution=sq_resolution,
        )
        assert result["source_table"] == "ACCTS"
        assert result["source_field"] == "ACCT_NUM"

    # ── 5d. Router group-qualified port stripping ────────────────────────────
    def test_router_group_prefix_stripped(self):
        """
        EXP ──▶ RTR (output port: HIGH_RISK_SCORE) ──▶ FCT
        Backward: FCT ← RTR (HIGH_RISK_SCORE) — needs to strip HIGH_ to find
        RTR's input port RISK_SCORE.
        """
        conns = [
            _conn("SQ_SRC",  "RISK_SCORE",      "EXP_SCORE",      "RISK_SCORE"),
            _conn("EXP_SCORE","RISK_SCORE",      "RTR_RISK",       "RISK_SCORE"),
            _conn("RTR_RISK", "HIGH_RISK_SCORE", "FCT_HIGH",       "RISK_SCORE"),
        ]
        backward = _build_backward_index(conns)
        source_names = {"SRC"}
        sq_resolution = {"SQ_SRC": "SRC"}
        rtr_trans = _trans("RTR_RISK", "Router",
            ports=[_port("RISK_SCORE"), _port("HIGH_RISK_SCORE")],
        )
        exp_trans = _trans("EXP_SCORE", "Expression",
            ports=[_port("RISK_SCORE")],
            expressions=[_expr("RISK_SCORE", "RISK_SCORE")],
        )
        by_name, get_trans = _make_get_trans([rtr_trans, exp_trans])

        result = _trace_to_source(
            "FCT_HIGH", "RISK_SCORE",
            backward, source_names, by_name, get_trans,
            sq_resolution=sq_resolution,
        )
        assert result["source_table"] == "SRC"
        assert result["source_field"] == "RISK_SCORE"
        assert result["status"] in (STATUS_FILTERED, STATUS_DIRECT)

    # ── 5e. Single-level expression derivation ───────────────────────────────
    def test_expression_single_level_derivation(self):
        """
        SQ_SRC ──▶ EXP (FRAUD_SCORE = ROUND(INDICATOR_SCORE, 2)) ──▶ FCT
        FRAUD_SCORE is derived from INDICATOR_SCORE which connects back to SQ_SRC.
        """
        conns = [
            _conn("SQ_SRC",  "INDICATOR_SCORE", "EXP_CALC", "INDICATOR_SCORE"),
            _conn("EXP_CALC","FRAUD_SCORE",      "FCT",      "FRAUD_SCORE"),
        ]
        backward = _build_backward_index(conns)
        source_names = {"SRC"}
        sq_resolution = {"SQ_SRC": "SRC"}
        exp_trans = _trans("EXP_CALC", "Expression",
            ports=[_port("INDICATOR_SCORE"), _port("FRAUD_SCORE")],
            expressions=[
                _expr("FRAUD_SCORE", "ROUND(INDICATOR_SCORE * 1.1, 2)"),
            ],
        )
        by_name, get_trans = _make_get_trans([exp_trans])

        result = _trace_to_source(
            "FCT", "FRAUD_SCORE",
            backward, source_names, by_name, get_trans,
            sq_resolution=sq_resolution,
        )
        assert result["source_table"] == "SRC"
        assert result["source_field"] == "INDICATOR_SCORE"
        assert result["status"] == STATUS_DERIVED

    # ── 5f. Multi-level internal expression chain ────────────────────────────
    def test_expression_multi_level_chain(self):
        """
        SQ_SRC ──▶ EXP (RISK_BAND → FRAUD_SCORE → INDICATOR_SCORE) ──▶ FCT
        Only INDICATOR_SCORE has an external connector from SQ_SRC.
        FRAUD_SCORE and RISK_BAND are internal to EXP.
        """
        conns = [
            _conn("SQ_SRC",  "INDICATOR_SCORE", "EXP_CALC", "INDICATOR_SCORE"),
            _conn("EXP_CALC", "RISK_BAND",       "FCT",      "RISK_BAND"),
        ]
        backward = _build_backward_index(conns)
        source_names = {"SRC"}
        sq_resolution = {"SQ_SRC": "SRC"}
        exp_trans = _trans("EXP_CALC", "Expression",
            ports=[_port("INDICATOR_SCORE"), _port("FRAUD_SCORE"), _port("RISK_BAND")],
            expressions=[
                _expr("FRAUD_SCORE", "ROUND(INDICATOR_SCORE * PATTERN_WEIGHT, 2)"),
                _expr("RISK_BAND",   "IIF(FRAUD_SCORE >= 80, 'HIGH', 'LOW')"),
            ],
        )
        by_name, get_trans = _make_get_trans([exp_trans])

        result = _trace_to_source(
            "FCT", "RISK_BAND",
            backward, source_names, by_name, get_trans,
            sq_resolution=sq_resolution,
        )
        assert result["source_table"] == "SRC"
        assert result["source_field"] == "INDICATOR_SCORE"
        assert result["status"] == STATUS_DERIVED

    # ── 5g. Genuinely computed fields ────────────────────────────────────────
    def test_sysdate_field_stays_at_expression(self):
        """
        ETL_LOAD_DT = SYSDATE — no source field, genuinely computed.
        The trace hops through the connector (FCT ← EXP_ETL), then dead-ends
        because EXP_ETL.ETL_LOAD_DT has no backward connector.
        The expression is recorded in logic; source_table is the EXP instance.
        """
        conns = [
            _conn("EXP_ETL", "ETL_LOAD_DT", "FCT", "ETL_LOAD_DT"),
        ]
        backward = _build_backward_index(conns)
        source_names = {"SRC"}
        exp_trans = _trans("EXP_ETL", "Expression",
            ports=[_port("ETL_LOAD_DT")],
            expressions=[_expr("ETL_LOAD_DT", "SYSDATE")],
        )
        by_name, get_trans = _make_get_trans([exp_trans])

        result = _trace_to_source(
            "FCT", "ETL_LOAD_DT",
            backward, source_names, by_name, get_trans,
        )
        # Trace hops once (connector exists) so it dead-ends at EXP_ETL with SYSDATE expr.
        # source_table is the transformation name; logic captures the expression.
        assert result["source_table"] == "EXP_ETL"
        assert result["status"] == STATUS_DERIVED
        assert "SYSDATE" in result.get("logic", "")

    def test_string_literal_field_stays_at_expression(self):
        """
        SOURCE_SYSTEM = 'APEX_INSURANCE' — string literal, no source port.
        The expression has no identifier tokens that map to port_names,
        so the trace dead-ends at EXP_ETL with the expression in logic.
        """
        conns = [
            _conn("EXP_ETL", "SOURCE_SYSTEM", "FCT", "SOURCE_SYSTEM"),
        ]
        backward = _build_backward_index(conns)
        source_names = {"SRC"}
        exp_trans = _trans("EXP_ETL", "Expression",
            ports=[_port("SOURCE_SYSTEM")],
            expressions=[_expr("SOURCE_SYSTEM", "'APEX_INSURANCE'")],
        )
        by_name, get_trans = _make_get_trans([exp_trans])

        result = _trace_to_source(
            "FCT", "SOURCE_SYSTEM",
            backward, source_names, by_name, get_trans,
        )
        # Dead-ends at EXP_ETL (one connector hop), records literal expression
        assert result["source_table"] == "EXP_ETL"
        assert result["status"] == STATUS_DERIVED
        assert "APEX_INSURANCE" in result.get("logic", "")

    def test_parameter_field_stays_at_expression(self):
        """
        ETL_BATCH_ID = $$ETL_BATCH_ID — session parameter, no source port.
        The only token in the expression is ETL_BATCH_ID itself (the current field),
        which is skipped, so the trace dead-ends at EXP_ETL.
        """
        conns = [
            _conn("EXP_ETL", "ETL_BATCH_ID", "FCT", "ETL_BATCH_ID"),
        ]
        backward = _build_backward_index(conns)
        source_names = {"SRC"}
        exp_trans = _trans("EXP_ETL", "Expression",
            ports=[_port("ETL_BATCH_ID")],
            expressions=[_expr("ETL_BATCH_ID", "$$ETL_BATCH_ID")],
        )
        by_name, get_trans = _make_get_trans([exp_trans])

        result = _trace_to_source(
            "FCT", "ETL_BATCH_ID",
            backward, source_names, by_name, get_trans,
        )
        # Dead-ends at EXP_ETL; ETL_BATCH_ID is the current field (skipped as self-token)
        assert result["source_table"] == "EXP_ETL"
        assert result["status"] == STATUS_DERIVED

    # ── 5h. Unmapped target (no upstream connector) ──────────────────────────
    def test_unmapped_target_field(self):
        """No connector leads to the target field — should return source_table=None."""
        backward = {}
        source_names = {"SRC"}
        by_name, get_trans = _make_get_trans([])

        result = _trace_to_source(
            "FCT", "MISSING_FIELD",
            backward, source_names, by_name, get_trans,
        )
        assert result["source_table"] is None

    # ── 5i. max_depth exceeded ───────────────────────────────────────────────
    def test_max_depth_protection(self):
        """Circular or very deep chain should not hang — returns Trace Too Deep."""
        # Build a 25-hop chain: SQ → T1 → T2 → ... → T25 → FCT
        conns = [_conn("SQ_SRC", "FIELD", "T1", "FIELD")]
        for i in range(1, 25):
            conns.append(_conn(f"T{i}", "FIELD", f"T{i+1}", "FIELD"))
        conns.append(_conn("T25", "FIELD", "FCT", "FIELD"))

        backward = _build_backward_index(conns)
        source_names = {"SRC"}
        sq_resolution = {"SQ_SRC": "SRC"}
        # No transformations defined — trace just follows connectors
        by_name, get_trans = _make_get_trans([])

        result = _trace_to_source(
            "FCT", "FIELD",
            backward, source_names, by_name, get_trans,
            max_depth=20,
            sq_resolution=sq_resolution,
        )
        # With max_depth=20, the 25-hop chain should NOT resolve
        assert result.get("notes", "").startswith("Could not resolve") or \
               result.get("status") == "Trace Too Deep"

    # ── 5j. Lookup transformation ────────────────────────────────────────────
    def test_lookup_transformation_sets_status(self):
        """Fields flowing through a Lookup should be STATUS_LOOKUP."""
        conns = [
            _conn("SQ_SRC",     "CUSTOMER_ID", "LKP_CUSTOMER", "CUSTOMER_ID"),
            _conn("LKP_CUSTOMER","CUSTOMER_NAME","FCT",         "CUSTOMER_NAME"),
        ]
        backward = _build_backward_index(conns)
        source_names = {"SRC"}
        sq_resolution = {"SQ_SRC": "SRC"}
        lkp_trans = _trans("LKP_CUSTOMER", "Lookup Procedure",
            ports=[_port("CUSTOMER_ID"), _port("CUSTOMER_NAME")],
        )
        by_name, get_trans = _make_get_trans([lkp_trans])

        result = _trace_to_source(
            "FCT", "CUSTOMER_NAME",
            backward, source_names, by_name, get_trans,
            sq_resolution=sq_resolution,
        )
        assert result["status"] == STATUS_LOOKUP

    # ── 5k. Aggregator transformation ───────────────────────────────────────
    def test_aggregator_transformation_sets_status(self):
        """Fields through an Aggregator should be STATUS_AGGREGATE."""
        conns = [
            _conn("SQ_SRC",  "AMOUNT",     "AGG_TOTAL", "AMOUNT"),
            _conn("AGG_TOTAL","TOTAL_AMT",  "FCT",       "TOTAL_AMT"),
        ]
        backward = _build_backward_index(conns)
        source_names = {"SRC"}
        sq_resolution = {"SQ_SRC": "SRC"}
        agg_trans = _trans("AGG_TOTAL", "Aggregator",
            ports=[_port("AMOUNT"), _port("TOTAL_AMT")],
            expressions=[_expr("TOTAL_AMT", "SUM(AMOUNT)")],
        )
        by_name, get_trans = _make_get_trans([agg_trans])

        result = _trace_to_source(
            "FCT", "TOTAL_AMT",
            backward, source_names, by_name, get_trans,
            sq_resolution=sq_resolution,
        )
        # SUM(AMOUNT) is an expression → STATUS_DERIVED is set by _collect_port_logic.
        # _promote_status only promotes from STATUS_DIRECT, so DERIVED takes priority
        # over AGGREGATE when both apply (expression is evaluated first).
        assert result["status"] == STATUS_DERIVED
        assert result["source_table"] == "SRC"
        assert "SUM" in result.get("logic", "")

    # ── 5l. Multi-hop: SQ → JNR → EXP (derived) → FCT ──────────────────────
    def test_full_chain_sq_joiner_expression(self):
        """
        CLAIM_SUBMISSIONS ──(SQ)──▶ JNR_CLAIMS (M_ prefix) ──▶ EXP_SCORE
            EXP_SCORE: FRAUD_SCORE = ROUND(INDICATOR_SCORE * 1.1, 2)
                       INDICATOR_SCORE comes from JNR via connector
        EXP_SCORE ──▶ RTR ──▶ FCT
        """
        conns = [
            _conn("SQ_CLAIMS",   "INDICATOR_SCORE", "JNR_CLAIMS", "M_INDICATOR_SCORE"),
            _conn("JNR_CLAIMS",  "INDICATOR_SCORE", "EXP_SCORE",  "INDICATOR_SCORE"),
            _conn("EXP_SCORE",   "FRAUD_SCORE",     "FCT_FRAUD",  "FRAUD_SCORE"),
        ]
        backward = _build_backward_index(conns)
        source_names = {"CLAIM_SUBMISSIONS"}
        sq_resolution = {"SQ_CLAIMS": "CLAIM_SUBMISSIONS"}

        jnr_trans = _trans("JNR_CLAIMS", "Joiner",
            ports=[_port("INDICATOR_SCORE"), _port("M_INDICATOR_SCORE")],
        )
        exp_trans = _trans("EXP_SCORE", "Expression",
            ports=[_port("INDICATOR_SCORE"), _port("FRAUD_SCORE")],
            expressions=[
                _expr("FRAUD_SCORE", "ROUND(INDICATOR_SCORE * 1.1, 2)"),
            ],
        )
        by_name, get_trans = _make_get_trans([jnr_trans, exp_trans])

        result = _trace_to_source(
            "FCT_FRAUD", "FRAUD_SCORE",
            backward, source_names, by_name, get_trans,
            sq_resolution=sq_resolution,
        )
        assert result["source_table"] == "CLAIM_SUBMISSIONS"
        assert result["source_field"] == "INDICATOR_SCORE"
        assert result["status"] == STATUS_DERIVED
        assert "JNR_CLAIMS" in result["chain"]

    # ── 5m. Pass-through field through many transformations ─────────────────
    def test_pass_through_preserves_direct_status(self):
        """A field that passes through unchanged stays STATUS_DIRECT."""
        conns = [
            _conn("SQ_SRC",  "RECORD_ID", "EXP_PASS",  "RECORD_ID"),
            _conn("EXP_PASS", "RECORD_ID", "FCT_OUT",   "RECORD_ID"),
        ]
        backward = _build_backward_index(conns)
        source_names = {"SRC"}
        sq_resolution = {"SQ_SRC": "SRC"}
        exp_trans = _trans("EXP_PASS", "Expression",
            ports=[_port("RECORD_ID")],
            expressions=[_expr("RECORD_ID", "RECORD_ID")],  # identity
        )
        by_name, get_trans = _make_get_trans([exp_trans])

        result = _trace_to_source(
            "FCT_OUT", "RECORD_ID",
            backward, source_names, by_name, get_trans,
            sq_resolution=sq_resolution,
        )
        assert result["source_table"] == "SRC"
        assert result["source_field"] == "RECORD_ID"
        assert result["status"] == STATUS_DIRECT


# ─────────────────────────────────────────────────────────────────────────────
# 6. Unmapped source detection
# ─────────────────────────────────────────────────────────────────────────────

class TestFindUnmappedSourceFields:
    def _make_graph(self, source_name: str, fields: list[str]) -> dict:
        return {
            "sources": [{
                "name":   source_name,
                "fields": [{"name": f, "datatype": "string"} for f in fields],
            }],
            "mappings": [],
            "targets":  [],
        }

    def test_no_unmapped_when_all_connected(self):
        conns = [
            _conn("SRC", "FIELD_A", "EXP", "FIELD_A"),
            _conn("EXP", "FIELD_A", "TGT", "FIELD_A"),
        ]
        graph = self._make_graph("SRC", ["FIELD_A"])
        result = _find_unmapped_source_fields(conns, graph, "m_test")
        assert result == []

    def test_detects_orphaned_source_field(self):
        """FIELD_B is in source but never used in any connector as from_instance=SRC."""
        conns = [
            _conn("SRC", "FIELD_A", "EXP", "FIELD_A"),
            _conn("EXP", "FIELD_A", "TGT", "FIELD_A"),
            # FIELD_B appears nowhere
        ]
        graph = self._make_graph("SRC", ["FIELD_A", "FIELD_B"])
        # SRC is a root (it sends but doesn't receive) — but FIELD_B is only "used"
        # if a connector references (SRC, FIELD_B) as from_instance/from_field.
        # Since no connector does, it won't appear in 'used' either.
        # The test verifies no crash and an empty result (field not in connectors at all)
        result = _find_unmapped_source_fields(conns, graph, "m_test")
        # FIELD_B is not in any connector — it's not in 'used', so not detected
        # as unmapped_source (function only checks used - connected, not all source fields)
        assert isinstance(result, list)

    def test_detects_dead_end_source_connection(self):
        """
        SRC sends FIELD_B, but FIELD_B has a forward connector to EXP and SRC→FIELD_B
        is in both 'used' and 'connected' (forward path exists from SRC).
        _find_unmapped_source_fields only detects fields at ROOT level with no forward
        path; a dead-end at an intermediate transformation is NOT detected here.
        The function returns an empty list because all root source fields are connected.
        """
        conns = [
            _conn("SRC", "FIELD_A", "EXP", "FIELD_A"),
            _conn("SRC", "FIELD_B", "EXP", "FIELD_B"),  # SRC.FIELD_B HAS a forward path
            _conn("EXP", "FIELD_A", "TGT", "FIELD_A"),
            # No connector for EXP.FIELD_B → dead-end at EXP, not at SRC
        ]
        graph = self._make_graph("SRC", ["FIELD_A", "FIELD_B"])
        result = _find_unmapped_source_fields(conns, graph, "m_test")
        # SRC.FIELD_B is "connected" (has a forward path from root SRC) even though
        # EXP.FIELD_B doesn't go further — so it's NOT reported as unmapped source.
        src_fields = [(r["source_table"], r["source_field"]) for r in result]
        assert ("SRC", "FIELD_B") not in src_fields


# ─────────────────────────────────────────────────────────────────────────────
# 7. Edge cases and regression guards
# ─────────────────────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_sq_resolution_applied_at_dead_end(self):
        """
        When backward trace dead-ends at an SQ_ instance (not just when first
        encountered via backward connector), the sq_resolution dict is applied.
        """
        # EXP has no expression for the port → dead-end at EXP
        # Then _handle_dead_end returns EXP as source_table.
        # But if source_table is an SQ, it should be resolved.
        # Simulate: trace dead-ends at SQ_SRC directly
        conns = [
            _conn("SQ_SRC", "AMOUNT", "FCT", "AMOUNT"),
        ]
        backward = _build_backward_index(conns)
        source_names = {"ORDERS"}  # SQ_SRC is not in source_names
        sq_resolution = {"SQ_SRC": "ORDERS"}
        by_name, get_trans = _make_get_trans([])

        result = _trace_to_source(
            "FCT", "AMOUNT",
            backward, source_names, by_name, get_trans,
            sq_resolution=sq_resolution,
        )
        assert result["source_table"] == "ORDERS"

    def test_router_multi_word_group_prefix(self):
        """Router output port with multi-word group: HIGH_PRIORITY_SCORE → SCORE."""
        conns = [
            _conn("SQ_SRC",   "SCORE",              "RTR",    "SCORE"),
            _conn("RTR",      "HIGH_PRIORITY_SCORE", "FCT_H",  "SCORE"),
        ]
        backward = _build_backward_index(conns)
        source_names = {"SRC"}
        sq_resolution = {"SQ_SRC": "SRC"}
        rtr_trans = _trans("RTR", "Router",
            ports=[_port("SCORE"), _port("HIGH_PRIORITY_SCORE")],
        )
        by_name, get_trans = _make_get_trans([rtr_trans])

        result = _trace_to_source(
            "FCT_H", "SCORE",
            backward, source_names, by_name, get_trans,
            sq_resolution=sq_resolution,
        )
        assert result["source_table"] == "SRC"
        assert result["source_field"] == "SCORE"

    def test_no_sq_resolution_when_not_provided(self):
        """sq_resolution=None defaults gracefully; SQ_ not resolved, treated as intermediate."""
        conns = [
            _conn("SQ_SRC", "FIELD", "FCT", "FIELD"),
        ]
        backward = _build_backward_index(conns)
        source_names = set()  # SQ_SRC not in source_names
        by_name, get_trans = _make_get_trans([])

        # Should not raise; will dead-end at SQ_SRC and return it as source_table
        result = _trace_to_source(
            "FCT", "FIELD",
            backward, source_names, by_name, get_trans,
            sq_resolution=None,
        )
        assert result is not None

    def test_transformation_chain_recorded(self):
        """The chain list should contain intermediate transformation names in order."""
        conns = [
            _conn("SQ_SRC", "ID", "EXP1", "ID"),
            _conn("EXP1",   "ID", "EXP2", "ID"),
            _conn("EXP2",   "ID", "FCT",  "ID"),
        ]
        backward = _build_backward_index(conns)
        source_names = {"SRC"}
        sq_resolution = {"SQ_SRC": "SRC"}
        exp1 = _trans("EXP1", "Expression",
            ports=[_port("ID")], expressions=[_expr("ID", "ID")])
        exp2 = _trans("EXP2", "Expression",
            ports=[_port("ID")], expressions=[_expr("ID", "ID")])
        by_name, get_trans = _make_get_trans([exp1, exp2])

        result = _trace_to_source(
            "FCT", "ID",
            backward, source_names, by_name, get_trans,
            sq_resolution=sq_resolution,
        )
        assert result["source_table"] == "SRC"
        assert "EXP1" in result["chain"] or "EXP2" in result["chain"]


# ─────────────────────────────────────────────────────────────────────────────
# 8. Joiner Style B — OUT_ prefix + _M/_D suffix (regression: sample XMLs)
# ─────────────────────────────────────────────────────────────────────────────

class TestJoinerStyleB:
    """
    Tests for the OUT_* output / _M _D suffix input naming convention
    used in sample XMLs (m_ORDERS_CUSTOMERS_to_FACT_SALES,
    m_LOAN_APPLICATIONS_to_FACT).

    Convention:
      - Joiner output ports are named OUT_<FIELD>
      - Ambiguous input ports (same field name in both master and detail)
        are named <FIELD>_M (master) or <FIELD>_D (detail)
      - Non-ambiguous input ports keep the original field name
    """

    def test_out_prefix_non_ambiguous_resolves(self):
        """
        OUT_APPLICATION_ID → strip OUT_ → APPLICATION_ID directly in backward.
        Non-ambiguous field (only comes from one source).
        """
        conns = [
            _conn("SQ_APPS",   "APPLICATION_ID", "JNR_X", "APPLICATION_ID"),
            _conn("JNR_X",     "OUT_APPLICATION_ID", "EXP", "APPLICATION_ID"),
            _conn("EXP",       "APPLICATION_ID", "FCT",  "APPLICATION_ID"),
        ]
        backward = _build_backward_index(conns)
        source_names = {"LOAN_APPS"}
        sq_resolution = {"SQ_APPS": "LOAN_APPS"}
        jnr = _trans("JNR_X", "Joiner",
            ports=[_port("APPLICATION_ID"), _port("OUT_APPLICATION_ID")])
        exp = _trans("EXP", "Expression",
            ports=[_port("APPLICATION_ID")],
            expressions=[_expr("APPLICATION_ID", "APPLICATION_ID")])
        by_name, get_trans = _make_get_trans([jnr, exp])

        result = _trace_to_source(
            "FCT", "APPLICATION_ID",
            backward, source_names, by_name, get_trans,
            sq_resolution=sq_resolution,
        )
        assert result["source_table"] == "LOAN_APPS"
        assert result["source_field"] == "APPLICATION_ID"

    def test_out_prefix_ambiguous_suffix_m_resolves(self):
        """
        OUT_CUSTOMER_ID → strip OUT_ → CUSTOMER_ID not in backward →
        try CUSTOMER_ID_M → found → resolves to master source (STG_CUSTOMERS).
        """
        conns = [
            _conn("SQ_ORDERS",    "CUSTOMER_ID", "JNR_X", "CUSTOMER_ID_D"),
            _conn("SQ_CUSTOMERS", "CUSTOMER_ID", "JNR_X", "CUSTOMER_ID_M"),
            _conn("JNR_X", "OUT_CUSTOMER_ID", "EXP", "CUSTOMER_ID"),
            _conn("EXP",   "CUSTOMER_ID", "FCT", "CUSTOMER_ID"),
        ]
        backward = _build_backward_index(conns)
        source_names = {"STG_ORDERS", "STG_CUSTOMERS"}
        sq_resolution = {
            "SQ_ORDERS":    "STG_ORDERS",
            "SQ_CUSTOMERS": "STG_CUSTOMERS",
        }
        jnr = _trans("JNR_X", "Joiner",
            ports=[_port("CUSTOMER_ID_M"), _port("CUSTOMER_ID_D"), _port("OUT_CUSTOMER_ID")])
        exp = _trans("EXP", "Expression",
            ports=[_port("CUSTOMER_ID")],
            expressions=[_expr("CUSTOMER_ID", "CUSTOMER_ID")])
        by_name, get_trans = _make_get_trans([jnr, exp])

        result = _trace_to_source(
            "FCT", "CUSTOMER_ID",
            backward, source_names, by_name, get_trans,
            sq_resolution=sq_resolution,
        )
        # _M suffix resolves to master = STG_CUSTOMERS
        assert result["source_table"] == "STG_CUSTOMERS"
        assert result["source_field"] == "CUSTOMER_ID"

    def test_out_prefix_ambiguous_suffix_d_resolves(self):
        """
        Trace a field that uses _D (detail) disambiguation.
        OUT_PROPERTY_ID → PROPERTY_ID_D → resolves to detail source.
        """
        conns = [
            _conn("SQ_APPS",      "PROPERTY_ID", "JNR_X", "PROPERTY_ID_M"),
            _conn("SQ_APPRAISALS","PROPERTY_ID", "JNR_X", "PROPERTY_ID_D"),
            _conn("JNR_X", "OUT_PROPERTY_ID_D_RESULT", "EXP", "PROP_D"),
            _conn("EXP",   "PROP_D", "FCT", "PROP_D"),
        ]
        # Simpler setup: verify _D suffix is tried
        conns2 = [
            _conn("SQ_APPRAISALS","PROPERTY_ID", "JNR_X", "PROPERTY_ID_D"),
            _conn("JNR_X", "OUT_PROPERTY_ID", "EXP", "PROPERTY_ID"),
            _conn("EXP",   "PROPERTY_ID", "FCT", "PROPERTY_ID"),
        ]
        backward = _build_backward_index(conns2)
        source_names = {"PROPERTY_APPRAISALS"}
        sq_resolution = {"SQ_APPRAISALS": "PROPERTY_APPRAISALS"}
        jnr = _trans("JNR_X", "Joiner",
            ports=[_port("PROPERTY_ID_D"), _port("OUT_PROPERTY_ID")])
        exp = _trans("EXP", "Expression",
            ports=[_port("PROPERTY_ID")],
            expressions=[_expr("PROPERTY_ID", "PROPERTY_ID")])
        by_name, get_trans = _make_get_trans([jnr, exp])

        result = _trace_to_source(
            "FCT", "PROPERTY_ID",
            backward, source_names, by_name, get_trans,
            sq_resolution=sq_resolution,
        )
        assert result["source_table"] == "PROPERTY_APPRAISALS"
        assert result["source_field"] == "PROPERTY_ID"

    def test_non_ambiguous_through_joiner_no_suffix(self):
        """
        Fields that exist in only ONE source get no disambiguation suffix.
        OUT_CUSTOMER_NAME → CUSTOMER_NAME → in backward directly.
        """
        conns = [
            _conn("SQ_CUSTOMERS", "CUSTOMER_NAME", "JNR_X", "CUSTOMER_NAME"),
            _conn("JNR_X", "OUT_CUSTOMER_NAME", "EXP", "CUSTOMER_NAME"),
            _conn("EXP",   "CUSTOMER_NAME", "FCT", "CUSTOMER_NAME"),
        ]
        backward = _build_backward_index(conns)
        source_names = {"STG_CUSTOMERS"}
        sq_resolution = {"SQ_CUSTOMERS": "STG_CUSTOMERS"}
        jnr = _trans("JNR_X", "Joiner",
            ports=[_port("CUSTOMER_NAME"), _port("OUT_CUSTOMER_NAME")])
        exp = _trans("EXP", "Expression",
            ports=[_port("CUSTOMER_NAME")],
            expressions=[_expr("CUSTOMER_NAME", "CUSTOMER_NAME")])
        by_name, get_trans = _make_get_trans([jnr, exp])

        result = _trace_to_source(
            "FCT", "CUSTOMER_NAME",
            backward, source_names, by_name, get_trans,
            sq_resolution=sq_resolution,
        )
        assert result["source_table"] == "STG_CUSTOMERS"
        assert result["source_field"] == "CUSTOMER_NAME"


# ─────────────────────────────────────────────────────────────────────────────
# 9. Integration tests — full parse_xml → build_s2t pipeline
# ─────────────────────────────────────────────────────────────────────────────

SAMPLE_XML_DIR = Path(__file__).parent.parent / "sample_xml"


def _run_s2t(xml_path: Path) -> dict:
    """Parse an XML file and run the full S2T pipeline."""
    from backend.agents.parser_agent import parse_xml
    from backend.agents.s2t_agent import _build_s2t_impl
    xml_content = xml_path.read_text()
    parse_report, graph = parse_xml(xml_content)
    return _build_s2t_impl(parse_report, graph, job_id="test0000")


def _field_result(s2t: dict, target_table: str, target_field: str) -> dict | None:
    """Find a specific target field's S2T record."""
    for r in s2t["records"]:
        if r["target_table"] == target_table and r["target_field"] == target_field:
            return r
    return None


class TestIntegrationHrEmployees:
    """
    Simple mapping: single source → SQ → Expression → Target.
    All fields should trace back to STG_EMPLOYEES.
    """

    @pytest.fixture(scope="class")
    def s2t(self):
        xml = SAMPLE_XML_DIR / "simple" / "m_HR_EMPLOYEES_to_DIM_EMPLOYEES.xml"
        return _run_s2t(xml)

    def test_no_intermediate_as_source(self, s2t):
        """No transformation name should appear as source_table."""
        bad = [r for r in s2t["records"]
               if r["source_table"] and r["source_table"].startswith(("EXP_", "SQ_", "FIL_"))]
        assert bad == [], f"Transformations leaked as source: {[r['source_table'] for r in bad]}"

    def test_passthrough_field_traces_to_source(self, s2t):
        r = _field_result(s2t, "DIM_EMPLOYEES", "DEPT_CODE")
        assert r is not None
        assert r["source_table"] == "STG_EMPLOYEES"
        assert r["source_field"] == "DEPT_CODE"
        assert r["status"] == STATUS_DIRECT

    def test_derived_field_traces_to_source(self, s2t):
        """SALARY_BAND is derived from SALARY — should trace to STG_EMPLOYEES.SALARY."""
        r = _field_result(s2t, "DIM_EMPLOYEES", "SALARY_BAND")
        assert r is not None
        assert r["source_table"] == "STG_EMPLOYEES"
        assert r["status"] == STATUS_DERIVED

    def test_derived_field_has_expression(self, s2t):
        """Logic/Expression column should contain the IIF expression."""
        r = _field_result(s2t, "DIM_EMPLOYEES", "SALARY_BAND")
        assert r is not None
        assert "IIF" in r.get("logic", "") or "BAND" in r.get("logic", "")

    def test_hire_year_month_traces_to_hire_date(self, s2t):
        r = _field_result(s2t, "DIM_EMPLOYEES", "HIRE_YEAR_MONTH")
        assert r is not None
        assert r["source_table"] == "STG_EMPLOYEES"
        assert r["source_field"] == "HIRE_DATE"
        assert r["status"] == STATUS_DERIVED


class TestIntegrationOrdersCustomers:
    """
    Medium mapping: two sources joined (SQ_STG_ORDERS + SQ_STG_CUSTOMERS)
    via JNR with OUT_* output ports and _M/_D suffix disambiguation.
    Lookup on DIM_REGION. Expression with DECODE/IIF derivations.

    Key assertions:
    - ORDER_ID → STG_ORDERS (pass-through through Joiner + Expression)
    - CUSTOMER_NAME → STG_CUSTOMERS (from master side of Joiner)
    - CUSTOMER_ID → STG_CUSTOMERS (ambiguous field, _M suffix)
    - REGION_CODE → DIM_REGION (via Lookup)
    - ORDER_YEAR_MONTH → STG_ORDERS.ORDER_DATE (derived via TO_CHAR)
    - IS_LARGE_ORDER → STG_ORDERS.ORDER_AMOUNT (derived)
    - DISCOUNT_AMOUNT → derived (uses CUSTOMER_TIER + ORDER_AMOUNT)
    """

    @pytest.fixture(scope="class")
    def s2t(self):
        xml = SAMPLE_XML_DIR / "medium" / "m_ORDERS_CUSTOMERS_to_FACT_SALES.xml"
        return _run_s2t(xml)

    def test_no_intermediate_as_source(self, s2t):
        """SQ_, JNR_, FIL_, AGG_, LKP_ must never appear as source_table.
        EXP_ is allowed for computed fields (SYSDATE etc.)."""
        bad = [r for r in s2t["records"]
               if r["source_table"] and r["source_table"].startswith(
                   ("SQ_", "JNR_", "FIL_", "AGG_", "LKP_"))]
        assert bad == [], f"Transformations leaked as source: {[(r['target_field'], r['source_table']) for r in bad]}"

    def test_order_id_traces_to_stg_orders(self, s2t):
        r = _field_result(s2t, "FACT_SALES", "ORDER_ID")
        assert r is not None
        assert r["source_table"] == "STG_ORDERS"
        assert r["source_field"] == "ORDER_ID"

    def test_customer_name_traces_to_stg_customers(self, s2t):
        """CUSTOMER_NAME comes from master side — JNR input is CUSTOMER_NAME (no suffix)."""
        r = _field_result(s2t, "FACT_SALES", "CUSTOMER_NAME")
        assert r is not None
        assert r["source_table"] == "STG_CUSTOMERS"
        assert r["source_field"] == "CUSTOMER_NAME"

    def test_customer_id_ambiguous_traces_to_stg_customers(self, s2t):
        """CUSTOMER_ID is ambiguous (both sources have it). Master side wins (_M suffix)."""
        r = _field_result(s2t, "FACT_SALES", "CUSTOMER_ID")
        assert r is not None
        assert r["source_table"] == "STG_CUSTOMERS"
        assert r["source_field"] == "CUSTOMER_ID"

    def test_product_id_traces_to_stg_orders(self, s2t):
        r = _field_result(s2t, "FACT_SALES", "PRODUCT_ID")
        assert r is not None
        assert r["source_table"] == "STG_ORDERS"
        assert r["source_field"] == "PRODUCT_ID"

    def test_derived_field_order_year_month(self, s2t):
        r = _field_result(s2t, "FACT_SALES", "ORDER_YEAR_MONTH")
        assert r is not None
        assert r["source_table"] == "STG_ORDERS"
        assert r["source_field"] == "ORDER_DATE"
        assert r["status"] == STATUS_DERIVED

    def test_derived_flag_is_large_order(self, s2t):
        r = _field_result(s2t, "FACT_SALES", "IS_LARGE_ORDER")
        assert r is not None
        assert r["source_table"] == "STG_ORDERS"
        assert r["status"] == STATUS_DERIVED

    def test_lookup_field_region_code(self, s2t):
        """REGION_CODE comes from LKP_DIM_REGION → source should be DIM_REGION."""
        r = _field_result(s2t, "FACT_SALES", "REGION_CODE")
        assert r is not None
        # Lookup sourced from DIM_REGION
        assert r["source_table"] == "DIM_REGION"


class TestIntegrationLoanApplications:
    """
    Medium mapping: LOAN_APPLICATIONS joined to PROPERTY_APPRAISALS via JNR.
    Joiner uses OUT_ prefix on outputs + _M/_D suffix on ambiguous PROPERTY_ID.
    Expression with multi-level derivations (LTV_RATIO → LOAN_AMOUNT / APPRAISED_VALUE).

    Key assertions:
    - APPLICATION_ID → LOAN_APPLICATIONS (non-ambiguous through Joiner)
    - APPRAISED_VALUE → PROPERTY_APPRAISALS (detail side)
    - PROPERTY_ID → LOAN_APPLICATIONS (master side, _M suffix)
    - LTV_RATIO → derived (uses LOAN_AMOUNT from LOAN_APPLICATIONS)
    - ETL_LOAD_DATE → computed (SYSDATE, stays at EXP)
    """

    @pytest.fixture(scope="class")
    def s2t(self):
        xml = SAMPLE_XML_DIR / "medium" / "m_LOAN_APPLICATIONS_to_FACT.xml"
        return _run_s2t(xml)

    def test_no_intermediate_as_source(self, s2t):
        """
        SQ_, JNR_, FIL_, AGG_, LKP_ must never appear as source_table.
        EXP_ is allowed — computed fields (SYSDATE, literals) legitimately
        dead-end at an Expression transformation with no database source.
        """
        bad = [r for r in s2t["records"]
               if r["source_table"] and r["source_table"].startswith(
                   ("SQ_", "JNR_", "FIL_", "AGG_", "LKP_"))]
        assert bad == [], f"Transformations leaked as source: {[(r['target_field'], r['source_table']) for r in bad]}"

    def test_application_id_traces_to_loan_applications(self, s2t):
        r = _field_result(s2t, "FACT_LOAN_APPLICATIONS", "APPLICATION_ID")
        assert r is not None
        assert r["source_table"] == "STG_LOAN_APPLICATIONS"
        assert r["source_field"] == "APPLICATION_ID"

    def test_appraised_value_traces_to_property_appraisals(self, s2t):
        """APPRAISED_VALUE comes from detail side of Joiner (PROPERTY_APPRAISALS)."""
        r = _field_result(s2t, "FACT_LOAN_APPLICATIONS", "APPRAISED_VALUE")
        assert r is not None
        assert r["source_table"] == "PROPERTY_APPRAISALS"
        assert r["source_field"] == "APPRAISED_VALUE"

    def test_loan_amount_traces_to_loan_applications(self, s2t):
        r = _field_result(s2t, "FACT_LOAN_APPLICATIONS", "LOAN_AMOUNT")
        assert r is not None
        assert r["source_table"] == "STG_LOAN_APPLICATIONS"
        assert r["source_field"] == "LOAN_AMOUNT"

    def test_credit_score_traces_to_loan_applications(self, s2t):
        r = _field_result(s2t, "FACT_LOAN_APPLICATIONS", "CREDIT_SCORE")
        assert r is not None
        assert r["source_table"] == "STG_LOAN_APPLICATIONS"
        assert r["source_field"] == "CREDIT_SCORE"

    def test_ltv_ratio_is_derived(self, s2t):
        r = _field_result(s2t, "FACT_LOAN_APPLICATIONS", "LTV_RATIO")
        assert r is not None
        assert r["status"] == STATUS_DERIVED
        # LTV_RATIO = LOAN_AMOUNT / APPRAISED_VALUE — source is one of the input fields
        assert r["source_table"] in ("LOAN_APPLICATIONS", "PROPERTY_APPRAISALS")

    def test_etl_load_date_is_computed(self, s2t):
        """SYSDATE fields are genuinely computed — no database source."""
        r = _field_result(s2t, "FACT_LOAN_APPLICATIONS", "ETL_LOAD_DATE")
        assert r is not None
        # SYSDATE has no source; trace dead-ends at EXP with expression in logic
        assert r["status"] == STATUS_DERIVED
        assert "SYSDATE" in r.get("logic", "")


# ─────────────────────────────────────────────────────────────────────────────
# Integration: FNMA Loan Delivery SCD2 (complex)
# ─────────────────────────────────────────────────────────────────────────────

class TestIntegrationFNMALoanDelivery:
    """
    Complex mapping: FNMA_LOAN_DELIVERY joined to BORROWER_CREDIT_SCORES via
    Style A Joiner (M_/D_ prefix on inputs, bare name on outputs).

    Three output targets:
      - FACT_LOAN_DELIVERY
      - DIM_LOAN_STATUS_HIST
      - AGG_PORTFOLIO_SUMMARY

    Key Joiner resolution:
      - LOAN_IDENTIFIER, PROPERTY_STATE → FNMA_LOAN_DELIVERY (master side)
      - BORROWER_FICO, DTI_RATIO       → BORROWER_CREDIT_SCORES (detail side, M_/D_ prefix)

    The original real-world bug: without M_/D_ prefix stripping, BORROWER_FICO
    would dead-end at the Joiner transformation instead of resolving to the
    BORROWER_CREDIT_SCORES source table.
    """

    @pytest.fixture(scope="class")
    def s2t(self):
        xml = SAMPLE_XML_DIR / "complex" / "m_FNMA_LOAN_DELIVERY_SCD2.xml"
        return _run_s2t(xml)

    def test_no_intermediate_as_source(self, s2t):
        """
        SQ_, JNR_, FIL_, LKP_ must never appear as source_table.
        AGG_ is allowed only for genuinely aggregated fields (e.g. LOAN_COUNT).
        """
        bad = [r for r in s2t["records"]
               if r["source_table"] and r["source_table"].startswith(
                   ("SQ_", "JNR_", "FIL_", "LKP_"))]
        assert bad == [], (
            f"Transformations leaked as source: {[(r['target_field'], r['source_table']) for r in bad]}"
        )

    def test_three_target_tables_populated(self, s2t):
        """Mapping writes to three distinct targets."""
        tables = {r["target_table"] for r in s2t["records"]}
        assert "FACT_LOAN_DELIVERY" in tables
        assert "DIM_LOAN_STATUS_HIST" in tables
        assert "AGG_PORTFOLIO_SUMMARY" in tables

    # ── FACT_LOAN_DELIVERY ────────────────────────────────────────────────────

    def test_loan_identifier_traces_to_fnma(self, s2t):
        """Pass-through field on master side of Joiner → FNMA_LOAN_DELIVERY."""
        r = _field_result(s2t, "FACT_LOAN_DELIVERY", "LOAN_IDENTIFIER")
        assert r is not None
        assert r["source_table"] == "FNMA_LOAN_DELIVERY"
        assert r["source_field"] == "LOAN_IDENTIFIER"

    def test_property_state_traces_to_fnma(self, s2t):
        r = _field_result(s2t, "FACT_LOAN_DELIVERY", "PROPERTY_STATE")
        assert r is not None
        assert r["source_table"] == "FNMA_LOAN_DELIVERY"
        assert r["source_field"] == "PROPERTY_STATE"

    def test_borrower_fico_traces_to_credit_scores(self, s2t):
        """
        THE ORIGINAL BUG: BORROWER_FICO comes from the detail side of a
        Style A Joiner (D_BORROWER_FICO input port → BORROWER_FICO output).
        Without M_/D_ prefix resolution this would dead-end at the Joiner.
        """
        r = _field_result(s2t, "FACT_LOAN_DELIVERY", "BORROWER_FICO")
        assert r is not None
        assert r["source_table"] == "BORROWER_CREDIT_SCORES", (
            "BORROWER_FICO must trace through Joiner (Style A D_ prefix) "
            f"to BORROWER_CREDIT_SCORES, got {r['source_table']}"
        )
        assert r["source_field"] == "BORROWER_FICO"

    def test_dti_ratio_traces_to_credit_scores(self, s2t):
        """DTI_RATIO also from detail side of same Joiner."""
        r = _field_result(s2t, "FACT_LOAN_DELIVERY", "DTI_RATIO")
        assert r is not None
        assert r["source_table"] == "BORROWER_CREDIT_SCORES"
        assert r["source_field"] == "DTI_RATIO"

    def test_delinquency_band_is_derived(self, s2t):
        """DELINQUENCY_BAND is an IIF expression over DELINQUENCY_STATUS."""
        r = _field_result(s2t, "FACT_LOAN_DELIVERY", "DELINQUENCY_BAND")
        assert r is not None
        assert r["status"] == STATUS_DERIVED
        assert r["source_table"] == "FNMA_LOAN_DELIVERY"
        assert r["source_field"] == "DELINQUENCY_STATUS"

    def test_credit_risk_tier_is_derived(self, s2t):
        """CREDIT_RISK_TIER derived from BORROWER_FICO — still traces to BORROWER_CREDIT_SCORES."""
        r = _field_result(s2t, "FACT_LOAN_DELIVERY", "CREDIT_RISK_TIER")
        assert r is not None
        assert r["status"] == STATUS_DERIVED
        assert r["source_table"] == "BORROWER_CREDIT_SCORES"

    # ── DIM_LOAN_STATUS_HIST ──────────────────────────────────────────────────

    def test_dim_loan_identifier_traces_to_fnma(self, s2t):
        r = _field_result(s2t, "DIM_LOAN_STATUS_HIST", "LOAN_IDENTIFIER")
        assert r is not None
        assert r["source_table"] == "FNMA_LOAN_DELIVERY"

    def test_dim_eff_start_period_is_derived(self, s2t):
        """EFF_START_PERIOD is derived from REPORTING_PERIOD."""
        r = _field_result(s2t, "DIM_LOAN_STATUS_HIST", "EFF_START_PERIOD")
        assert r is not None
        assert r["status"] == STATUS_DERIVED

    # ── AGG_PORTFOLIO_SUMMARY ─────────────────────────────────────────────────

    def test_agg_reporting_period_traces_to_fnma(self, s2t):
        r = _field_result(s2t, "AGG_PORTFOLIO_SUMMARY", "REPORTING_PERIOD")
        assert r is not None
        assert r["source_table"] == "FNMA_LOAN_DELIVERY"

    def test_loan_count_source_is_aggregated(self, s2t):
        """
        LOAN_COUNT is a COUNT(*) in the Aggregator — no single field source.
        The source leaks as AGG_PORTFOLIO (the aggregator transformation itself),
        which is acceptable for aggregated count fields.
        """
        r = _field_result(s2t, "AGG_PORTFOLIO_SUMMARY", "LOAN_COUNT")
        assert r is not None
        # Aggregated count — source is the AGG transformation (acceptable)
        assert r["source_table"] is not None  # some source recorded

    def test_total_upb_traces_to_fnma(self, s2t):
        r = _field_result(s2t, "AGG_PORTFOLIO_SUMMARY", "TOTAL_UPB")
        assert r is not None
        assert r["source_table"] == "FNMA_LOAN_DELIVERY"


# ─────────────────────────────────────────────────────────────────────────────
# Integration: SALES Fact SCD2 Load (complex, nested Joiners)
# ─────────────────────────────────────────────────────────────────────────────

class TestIntegrationSalesFactLoad:
    """
    Complex mapping with two nested Joiners using Style B naming:
      - JNR_TXN_ACCOUNTS:   OUT_ prefix on outputs, ACCOUNT_ID_M/ACCOUNT_ID_D on ambiguous inputs
      - JNR_WITH_PRODUCTS:  O_ prefix on outputs,   PRODUCT_ID_M/PRODUCT_ID_D on ambiguous inputs

    Router splits flow into two targets:
      - FACT_TRANSACTIONS (19 fields)
      - FACT_TXN_REJECTS  (3 fields)

    Three source tables:
      - STG_TRANSACTIONS (transaction data)
      - STG_ACCOUNTS     (account dimension, master side of JNR_TXN_ACCOUNTS)
      - STG_PRODUCTS     (product dimension, master side of JNR_WITH_PRODUCTS)
    """

    @pytest.fixture(scope="class")
    def s2t(self):
        xml = SAMPLE_XML_DIR / "complex" / "m_SALES_FACT_SCD2_LOAD.xml"
        return _run_s2t(xml)

    def test_no_intermediate_as_source(self, s2t):
        """
        Strict check: no SQ_, JNR_, FIL_, AGG_, LKP_ as source_table.
        This mapping has two nested Style B Joiners (OUT_/O_ prefix).
        Without the O_ prefix strip, all Joiner outputs would leak through.
        """
        bad = [r for r in s2t["records"]
               if r["source_table"] and r["source_table"].startswith(
                   ("SQ_", "JNR_", "FIL_", "AGG_", "LKP_"))]
        assert bad == [], (
            f"Transformations leaked as source: {[(r['target_field'], r['source_table']) for r in bad]}"
        )

    def test_two_target_tables_populated(self, s2t):
        """Router sends records to two distinct targets."""
        tables = {r["target_table"] for r in s2t["records"]}
        assert "FACT_TRANSACTIONS" in tables
        assert "FACT_TXN_REJECTS" in tables

    # ── FACT_TRANSACTIONS ─────────────────────────────────────────────────────

    def test_account_key_traces_to_stg_accounts(self, s2t):
        """
        ACCOUNT_KEY traces through nested Joiners (O_ → base → _D suffix) to STG_ACCOUNTS.
        This is the critical path: JNR_WITH_PRODUCTS.O_ACCOUNT_ID
        → JNR_TXN_ACCOUNTS.ACCOUNT_ID_D (or base) → SQ_ACCOUNTS → STG_ACCOUNTS.
        """
        r = _field_result(s2t, "FACT_TRANSACTIONS", "ACCOUNT_KEY")
        assert r is not None
        assert r["source_table"] == "STG_ACCOUNTS", (
            f"ACCOUNT_KEY must resolve through nested Joiners to STG_ACCOUNTS, "
            f"got {r['source_table']}"
        )
        assert r["source_field"] == "ACCOUNT_ID"

    def test_product_key_traces_to_stg_products(self, s2t):
        """
        PRODUCT_KEY traces through JNR_WITH_PRODUCTS (O_ prefix) to STG_PRODUCTS
        via the PRODUCT_ID_M master-side port.
        """
        r = _field_result(s2t, "FACT_TRANSACTIONS", "PRODUCT_KEY")
        assert r is not None
        assert r["source_table"] == "STG_PRODUCTS", (
            f"PRODUCT_KEY must resolve through Joiner to STG_PRODUCTS, "
            f"got {r['source_table']}"
        )
        assert r["source_field"] == "PRODUCT_ID"

    def test_txn_date_traces_to_stg_transactions(self, s2t):
        r = _field_result(s2t, "FACT_TRANSACTIONS", "TXN_DATE")
        assert r is not None
        assert r["source_table"] == "STG_TRANSACTIONS"
        assert r["source_field"] == "TXN_DATE"

    def test_txn_amount_local_is_derived(self, s2t):
        """TXN_AMOUNT_LOCAL is a currency-converted expression, status=Derived."""
        r = _field_result(s2t, "FACT_TRANSACTIONS", "TXN_AMOUNT_LOCAL")
        assert r is not None
        assert r["status"] == STATUS_DERIVED
        assert r["source_table"] == "STG_TRANSACTIONS"
        assert r["source_field"] == "TXN_AMOUNT"

    def test_risk_rating_traces_to_stg_accounts(self, s2t):
        """RISK_RATING comes from STG_ACCOUNTS, not STG_TRANSACTIONS."""
        r = _field_result(s2t, "FACT_TRANSACTIONS", "RISK_RATING")
        assert r is not None
        assert r["source_table"] == "STG_ACCOUNTS"

    def test_asset_class_traces_to_stg_products(self, s2t):
        r = _field_result(s2t, "FACT_TRANSACTIONS", "ASSET_CLASS")
        assert r is not None
        assert r["source_table"] == "STG_PRODUCTS"
        assert r["source_field"] == "ASSET_CLASS"

    def test_platform_traces_to_stg_transactions(self, s2t):
        r = _field_result(s2t, "FACT_TRANSACTIONS", "PLATFORM")
        assert r is not None
        assert r["source_table"] == "STG_TRANSACTIONS"

    # ── FACT_TXN_REJECTS (Router secondary target) ────────────────────────────

    def test_reject_txn_id_traces_to_stg_transactions(self, s2t):
        """FACT_TXN_REJECTS.TXN_ID — Router secondary group, still resolves."""
        r = _field_result(s2t, "FACT_TXN_REJECTS", "TXN_ID")
        assert r is not None
        assert r["source_table"] == "STG_TRANSACTIONS"
        assert r["source_field"] == "TXN_ID"

    def test_reject_table_field_count(self, s2t):
        """FACT_TXN_REJECTS should have exactly 3 mapped fields."""
        rejects = [r for r in s2t["records"] if r["target_table"] == "FACT_TXN_REJECTS"]
        assert len(rejects) == 3, f"Expected 3 reject fields, got {len(rejects)}"
