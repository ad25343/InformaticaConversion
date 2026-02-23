"""
Smoke test — runs Steps 1-4 directly against the sample XML.
No server needed. Just: python3 test_pipeline.py
Requires ANTHROPIC_API_KEY in .env
"""
import asyncio
import json
import sys
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

from backend.agents import parser_agent, classifier_agent, documentation_agent, verification_agent

SAMPLE_XML = Path(__file__).parent / "sample_xml" / "sample_mapping.xml"
OUTPUT_DIR = Path(__file__).parent / "test_output"
OUTPUT_DIR.mkdir(exist_ok=True)

SEP = "─" * 60


def heading(text): print(f"\n{SEP}\n {text}\n{SEP}")
def ok(text):       print(f"  ✅ {text}")
def warn(text):     print(f"  ⚠️  {text}")
def fail(text):     print(f"  ❌ {text}")


async def run():
    xml = SAMPLE_XML.read_text()
    errors = []

    # ── STEP 1 — PARSE ───────────────────────────────────────
    heading("STEP 1 — PARSE")
    report, graph = parser_agent.parse_xml(xml)
    print(f"  Status        : {report.parse_status}")
    print(f"  Mappings      : {report.mapping_names}")
    print(f"  Objects       : {json.dumps(report.objects_found)}")
    print(f"  Flags         : {len(report.flags)}")

    if report.parse_status == "FAILED":
        fail("Parse failed — stopping")
        return
    ok("Parse complete")

    # ── STEP 2 — CLASSIFY ────────────────────────────────────
    heading("STEP 2 — CLASSIFY")
    complexity = classifier_agent.classify(report, graph)
    print(f"  Tier          : {complexity.tier.value}")
    print(f"  Criteria      : {'; '.join(complexity.criteria_matched)}")
    if complexity.special_flags:
        warn(f"Special flags: {complexity.special_flags}")
    ok("Classification complete")

    # ── STEP 3 — DOCUMENT ────────────────────────────────────
    heading("STEP 3 — DOCUMENT  (calling Claude...)")
    try:
        docs = await documentation_agent.document(report, complexity, graph)
        doc_path = OUTPUT_DIR / "documentation.md"
        doc_path.write_text(docs)
        print(f"  Length        : {len(docs):,} chars")
        print(f"  Saved to      : {doc_path}")

        # Quick sanity checks on doc content
        mapping_name = report.mapping_names[0]
        checks = [
            (mapping_name in docs,              f"Mapping name '{mapping_name}' present"),
            ("EXP_BUSINESS_RULES" in docs,      "Expression transformation documented"),
            ("FIL_VALID_ORDERS" in docs,        "Filter transformation documented"),
            ("SQ_STG_ORDERS" in docs,           "Source Qualifier documented"),
            ("Field-Level Lineage" in docs or
             "lineage" in docs.lower(),         "Lineage section present"),
            ("ORDER_AMOUNT * 0.085" in docs or
             "0.085" in docs,                   "Tax expression captured"),
        ]
        for passed, label in checks:
            ok(label) if passed else warn(f"Missing: {label}")

    except Exception as e:
        fail(f"Documentation failed: {e}")
        errors.append(str(e))
        docs = "Documentation failed"

    # ── STEP 4 — VERIFY ──────────────────────────────────────
    heading("STEP 4 — VERIFY  (calling Claude...)")
    try:
        verification = await verification_agent.verify(report, complexity, docs, graph)
        ver_path = OUTPUT_DIR / "verification_report.json"
        ver_path.write_text(json.dumps(verification.model_dump(), indent=2))

        print(f"  Overall       : {verification.overall_status}")
        print(f"  Checks        : {verification.total_passed}/{verification.total_checks} passed")
        print(f"  Flags         : {verification.total_flags}")
        print(f"  Blocked       : {verification.conversion_blocked}")
        print(f"  Saved to      : {ver_path}")

        if verification.flags:
            print("\n  Flags raised:")
            for f in verification.flags:
                marker = "🚫" if f.blocking else "⚠️ "
                print(f"    {marker} [{f.flag_type}] {f.location}")
                print(f"       {f.description[:100]}...")

        if not verification.conversion_blocked:
            ok("Verification passed — APPROVED FOR CONVERSION")
        else:
            warn(f"Conversion blocked: {verification.blocked_reasons}")

    except Exception as e:
        fail(f"Verification failed: {e}")
        errors.append(str(e))

    # ── SUMMARY ──────────────────────────────────────────────
    heading("SUMMARY")
    print(f"  Test outputs  : {OUTPUT_DIR}/")
    if errors:
        fail(f"{len(errors)} error(s) — check output above")
        sys.exit(1)
    else:
        ok("All steps completed — pipeline is working")
        print("\n  Next: start the server and try the full UI flow")
        print("  $ bash start.sh\n")


if __name__ == "__main__":
    asyncio.run(run())
