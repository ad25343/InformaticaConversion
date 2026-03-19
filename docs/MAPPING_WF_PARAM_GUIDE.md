# Mappings, Workflows & Parameter Files — Conversion Planning Guide

> **Version:** 2.25.0
> **Audience:** Migration leads, data engineers planning Informatica PowerCenter conversions
> **Last updated:** 2026-03-18

---

## 1. The three file types — what they are and why they exist

Informatica PowerCenter separates ETL concerns across three distinct artefacts. Understanding what each one holds is the foundation for conversion planning.

### Mapping XML (`mappings/`)

The **mapping** is the unit of ETL logic. It defines:

- **What** data to read (source tables, source qualifiers, SQL overrides)
- **What** transformations to apply (Expressions, Joiners, Routers, Lookups, Aggregators, Rank, Sorter, Mapplets)
- **What** to write and where (target definitions)

A mapping knows nothing about connections, scheduling, or runtime values. It uses `$$PARAMETER` placeholders wherever runtime values are needed.

**Exported as:** one XML file per mapping, or a batch export containing multiple `<MAPPING>` elements inside a `<POWERMART>` root.

---

### Workflow XML (`workflows/`)

The **workflow** is the execution container. It does not contain transformation logic — instead it orchestrates one or more **Sessions**, each of which runs a mapping against real connections.

A workflow holds:

| Element | What it captures |
|---------|-----------------|
| `<WORKFLOW>` | Name, scheduling config, event triggers |
| `<TASK type="Session">` | Links a mapping name to actual source/target connections |
| `<SESSION>` attributes | Pre/post-session SQL, commit interval, error threshold, reject file config, partition settings |
| `<TASKINSTANCE>` links | Execution order — which sessions run in parallel, which are sequential |
| `<DECISION>` tasks | Conditional branching based on row counts or return codes |
| `<COMMAND>` tasks | Shell commands run before/after sessions |
| `<EMAIL>` tasks | Notification steps |

> **Key insight:** the workflow is where you discover the **runtime connections** for each mapping (e.g. `OLTP_PROD` → `DWH_PROD`), the **execution dependencies** between mappings, and any **pre/post SQL** (like truncate statements) that surround the mapping run.

**Exported as:** one XML file per workflow, or a batch export containing `<WORKFLOW>` elements.

---

### Parameter File (`.txt` / `.par`)

The **parameter file** provides runtime values for `$$PARAMETER` placeholders used in mappings and sessions. Parameters are scoped:

| Scope | Syntax | Example |
|-------|--------|---------|
| **Global** | `[Global]` section | Applies to every session in every workflow |
| **Workflow** | `[WorkflowName]` section | Applies to all sessions within that workflow |
| **Session** | `[WorkflowName.SessionName]` section | Applies to a single session only |

Common uses:

```
[Global]
$$ENV=PROD
$$BATCH_DATE=2026-03-18

[wf_dim_load]
$$SOURCE_DB=OLTP_PROD
$$TARGET_DB=DWH_PROD

[wf_dim_load.s_m_dim_policyholder_load]
$$REJECT_FILE=/data/rejects/policyholder.bad
```

Without a parameter file, any `$$PARAM` in a mapping expression becomes an **UNRESOLVED_PARAMETER** flag — the converter will still generate code but will emit a `TODO: resolve $$PARAM` comment wherever that value is needed.

---

## 2. How the converter uses each file

### Step 0 — Session & Parameter Parse (automatic)

When you upload files, Step 0 runs before the main pipeline and extracts:

**From the Workflow XML:**
- Cross-reference validation — does the session in the workflow reference the same mapping name as the uploaded mapping XML?
- Session config: source/target connection names and types (`RELATIONAL`, `FILE`, `FTP`)
- Pre-session SQL (e.g. `TRUNCATE TABLE DWH.DIM_POLICYHOLDER`)
- Post-session SQL, commit interval, error threshold, reject file paths
- All raw session attributes (partition config, treat source rows as, etc.)

**From the Parameter File:**
- Resolves all `$$PARAM` references found in the mapping
- Identifies unresolved variables (present in the mapping but missing from the file)
- Scopes each parameter (GLOBAL / WORKFLOW / SESSION)

**Output:** a `SessionParseReport` that flows into every downstream step. The converter uses it to:
- Generate `connections.yaml` and `runtime_config.yaml` with real connection names
- Inject resolved parameter values into expression logic
- Flag any remaining `$$PARAM` references as `UNRESOLVED_VARIABLE` verification findings

---

### Step 1 — XML Parse

Reads the Mapping XML to build the transformation graph:
- All transformation instances and their types
- Port definitions (input/output, datatype, precision)
- Connector chains (which port feeds which)
- Expression logic per port
- Source/target table names and column definitions
- Any inline parameters (`<MAPPINGVARIABLE>` elements)

The session config from Step 0 enriches this — connection names supplement the source/target names found in the mapping.

---

### Step 7 — Code Generation

The converter uses all three inputs together:

| Input | How it shapes the generated code |
|-------|----------------------------------|
| Mapping XML | Core transformation logic, field names, expressions |
| Workflow XML | Connection names → DB config in `connections.yaml`; pre/post SQL → injected as setup/teardown steps in the pipeline; execution order → documented in README |
| Parameter File | Resolved `$$PARAM` values → hardened into config; unresolved ones → `TODO` comments with the parameter name |

---

## 3. What do you actually need?

### Minimum viable conversion

| File | Required? | Impact if missing |
|------|-----------|-------------------|
| **Mapping XML** | ✅ Always | Cannot convert without it |
| **Workflow XML** | ⚠️ Recommended | No connection names → `connections.yaml` uses placeholder names; no pre/post SQL → truncate/cleanup steps missed; no execution order context |
| **Parameter File** | ⚠️ Recommended | Every `$$PARAM` → UNRESOLVED_PARAMETER flag; generated code has `TODO` stubs instead of real values |

### Decision guide

```
Is this a simple pass-through with no $$PARAMS?
  → Mapping XML only is fine.

Does the mapping use $$PARAMS in filter logic, source SQL, or expressions?
  → Add the parameter file. Without it you get TODO stubs in critical logic.

Do you need correct connection names in connections.yaml?
  → Add the workflow XML. Otherwise connection names are inferred from source/target table names.

Does the workflow include TRUNCATE TABLE pre-session SQL or post-load cleanup?
  → Add the workflow XML. That SQL is not in the mapping — it lives in the session config.

Are you converting for a specific environment (DEV vs PROD)?
  → Use the environment-specific parameter file. Parameters change between environments.
```

---

## 4. Batch conversion — what you need and how to organise it

When converting many mappings, the relationship between workflows and parameter files determines how you group your upload batches.

### How Informatica estates are typically structured

```
repository/
  mappings/
    m_dim_policyholder_load.xml
    m_dim_product_load.xml
    m_fct_regulatory_return.xml
    m_fct_claims_daily.xml
    ...
  workflows/
    wf_dim_loads.xml          ← orchestrates 5 dimension mapping sessions
    wf_fact_loads.xml         ← orchestrates 3 fact mapping sessions
    wf_regulatory.xml         ← standalone, one session
  parameter_files/
    params_dev.txt            ← DEV environment values
    params_prod.txt           ← PROD environment values
```

A single workflow XML often references **multiple mappings** (one session per mapping). A single parameter file typically covers **all mappings within a workflow**, scoped by `[WorkflowName.SessionName]` sections.

### Batch grouping strategy

**Option A — Workflow-aligned batches (recommended)**

Group your uploads to match the workflow they belong to. Upload the workflow XML once alongside each mapping that belongs to it.

```
Batch 1: wf_dim_loads.xml + params_prod.txt
  → m_dim_policyholder_load.xml
  → m_dim_product_load.xml
  → m_dim_agent_load.xml

Batch 2: wf_fact_loads.xml + params_prod.txt
  → m_fct_regulatory_return.xml
  → m_fct_claims_daily.xml
```

Benefits:
- Every mapping in the batch gets correct connection names from the shared workflow
- Pre/post SQL captured for each session
- Parameter file scoped sections resolve correctly for each mapping
- Execution order documented in generated READMEs

**Option B — Mapping-only batches (fast, shallow)**

Upload mapping XMLs only, without a workflow or parameter file. Use this for:
- Initial estate survey (Documentation Only mode — Steps 1–4 only)
- Simple pass-through mappings with no $$PARAMS or pre/post SQL
- Mappings you know have no workflow (standalone session jobs)

You will get `UNRESOLVED_PARAMETER` flags for any `$$PARAMS` and placeholder connection names in `connections.yaml`. These can be resolved later via manifest override or by re-submitting with the parameter file.

---

### Do you need all three files for every mapping in a batch?

No. The tool handles each mapping independently:

| What you upload | What you get |
|-----------------|-------------|
| Mapping only | Converts correctly; connection names inferred; $$PARAMS flagged |
| Mapping + Param file | $$PARAMS resolved; connection names inferred |
| Mapping + Workflow | Connection names correct; pre/post SQL captured; $$PARAMS still flagged |
| Mapping + Workflow + Param | Full fidelity — recommended for production conversion |

The parameter file is especially important for mappings that use `$$PARAM` in:
- Source SQL `WHERE` clauses (e.g. `WHERE BATCH_DATE = $$BATCH_DATE`)
- Filter transformation conditions
- Expression port logic
- Target table names (dynamic routing)

Missing those will produce code that compiles but runs incorrectly at runtime.

---

## 5. Practical conversion planning checklist

### Before starting a wave

- [ ] Export all mapping XMLs from the PowerCenter repository (Designer → Export)
- [ ] Export all workflow XMLs for the mappings in scope
- [ ] Identify which environment parameter file to use (DEV for initial conversion, PROD for final handover)
- [ ] Group mappings by workflow — mappings in the same workflow share a session context
- [ ] Flag any mappings with no workflow (standalone jobs) — these need extra documentation of their execution context

### During upload

- [ ] Upload Mapping XML + Workflow XML + Parameter File as a group
- [ ] If the workflow covers multiple mappings, upload each mapping separately but include the same workflow XML and parameter file each time — the tool cross-references by name
- [ ] For Documentation Only runs (estate survey), mapping XML alone is sufficient

### At Gate 1 — Review checklist

- [ ] Check for `UNRESOLVED_PARAMETER` flags — these mean the parameter file was missing or didn't cover the mapping
- [ ] Check for `UNRESOLVED_VARIABLE` flags — these mean the workflow XML referenced `$$VARs` that weren't in the parameter file
- [ ] Check Conversion Readiness scores — LOW Score 2 (Source Completeness) often means the mapping has expression ports with no logic, or joiners/routers without conditions defined → verify in the Informatica repository before approving
- [ ] Review the generated `connections.yaml` — confirm connection names match your target environment config

### After Gate 3

- [ ] Verify `connections.yaml` connection names against your target platform's connection registry
- [ ] Resolve any `TODO: $$PARAM` stubs in the generated code with environment-specific values
- [ ] Run `compare_golden.py` against a captured Informatica output to validate field-level equivalence

---

## 6. Common problems and fixes

| Problem | Root cause | Fix |
|---------|-----------|-----|
| `UNRESOLVED_PARAMETER` flags on every job | No parameter file uploaded | Add the `.txt` / `.par` parameter file to the upload |
| `UNRESOLVED_VARIABLE` flags | Workflow XML has `$$VARs` not covered by the parameter file | Add the correct environment parameter file; check the `[WorkflowName]` section covers the variable |
| `connections.yaml` has placeholder names | No workflow XML uploaded | Re-submit with the workflow XML, or fill in the manifest override at Gate 1 |
| Pre-session TRUNCATE not in generated code | No workflow XML uploaded | The TRUNCATE lives in the session's pre-session SQL, not the mapping — upload the workflow XML |
| Cross-reference validation fails (INVALID) | Workflow session references a different mapping name than the uploaded mapping XML | Check the session's `MAPPINGNAME` attribute — export the correct mapping, or upload the workflow that matches |
| Score 2 (Source Completeness) is LOW | Expression ports have no documented logic, or Joiner/Router conditions are missing | Inspect the mapping in Informatica Designer — conditions may be defined in a mapplet or inherited from a reusable transformation not included in the export |

---

## 7. Best practices for conversion

### Estate assessment — before you convert anything

**Run Documentation Only mode first.**

Upload every mapping XML (without workflow or parameter files) in Documentation Only mode (Steps 1–4). This gives you:
- Pattern classification and Conversion Readiness scores for the whole estate
- A ranked inventory of every mapping by complexity tier
- An early warning of mappings with Score 2 = LOW (incomplete source logic in the repository)

Do this before writing a single line of target code. It costs nothing to run and prevents surprises mid-wave.

**Resolve Score 2 = LOW before scheduling a mapping for conversion.**

A LOW Source Completeness score means the Informatica repository itself has gaps — missing expression logic, unpopulated Joiner conditions, or logic hidden inside a reusable Mapplet that wasn't included in the export. Fix or document these in Informatica Designer before the conversion wave reaches that mapping. Discovering them mid-wave is expensive.

---

### Wave planning — work complexity tiers in order

Sequence waves by Conversion Readiness score, lowest risk first:

| Wave | Score range | What to expect |
|------|-------------|----------------|
| Wave 1 | HIGH (80–100) | Reliable output; minimal review time; use these to validate your pipeline config and connection setup |
| Wave 2 | MEDIUM (65–79) | Most of the estate; expect some `UNRESOLVED_PARAMETER` flags and manual connection review |
| Wave 3 | LOW (< 65) | Complex mappings — Mapplets, dynamic SQL, many `$$PARAMS`, unusual transformation chains; allocate extra review time |

Never mix LOW-score mappings into early waves. A single blocked or failed mapping creates noise that slows the whole wave review.

**Group by workflow, not by team ownership.**

Mappings that share a workflow are runtime-coupled — they share connections, parameter file sections, and sometimes pre/post SQL that coordinates across sessions. Convert them together in the same batch so the generated output reflects their actual execution relationship.

---

### File organisation and naming

Follow a consistent directory structure from day one:

```
conversion_project/
  wave_1/
    dim_loads/
      m_dim_policyholder_load.xml
      m_dim_product_load.xml
      wf_dim_loads.xml
      params_prod.txt
  wave_2/
    fact_loads/
      m_fct_claims_daily.xml
      wf_fact_loads.xml
      params_prod.txt
  wave_3/
    complex/
      ...
  parameter_files/
    params_dev.txt       ← keep one canonical copy per environment
    params_prod.txt
  golden_data/
    m_dim_policyholder_load_expected.csv
    m_fct_claims_daily_expected.csv
```

Rules:
- Keep one canonical copy of each parameter file in `parameter_files/` — never duplicate and edit separately per mapping, or versions will diverge
- Name mapping XMLs to match the Informatica mapping name exactly — cross-reference validation in Step 0 is case-sensitive
- Store golden CSVs alongside conversion artefacts from the start, even if you don't run comparison scripts until later

---

### Parameter file management

**Use environment-specific parameter files from the start.**

Never use a `params_dev.txt` to convert mappings destined for production. Connection names, schema names, file paths, and batch dates all differ between environments. Converting with the wrong parameter file produces generated code with the wrong hardened values.

**Keep a DEV file for initial conversion, PROD file for final handover.**

| Stage | Parameter file to use |
|-------|----------------------|
| Initial conversion & testing | `params_dev.txt` |
| Gate 3 final review | `params_prod.txt` |
| Post-handover validation | `params_prod.txt` |

**Audit every `$$PARAM` before Gate 3.**

At Gate 3, check the generated `connections.yaml` and any `TODO: $$PARAM` stubs in the code. Every stub is a runtime defect waiting to happen. Do not approve Gate 3 with unresolved stubs unless you have a documented plan to inject values at deployment time (e.g., via environment variables or a secrets manager).

---

### Gate review standards

Establish a consistent review checklist that every reviewer applies at each gate. Avoid approving "because it looks right" — always verify against the checklist.

**Gate 1 — Minimum review checklist:**

- [ ] Conversion Readiness score ≥ 65 (tool enforces; check the reason if it's borderline)
- [ ] Pattern classification matches your expectation for this mapping (e.g. SCD2 not misclassified as Truncate and Load)
- [ ] Source and target table names in the S2T Manifest match the Informatica mapping
- [ ] No `UNRESOLVED_PARAMETER` flags, OR each one is documented and has an owner
- [ ] Score 2 (Source Completeness) is not LOW — if LOW, reject and fix in Informatica first

**Gate 2 — Minimum review checklist:**

- [ ] Generated SQL/Python logic matches the documented transformation intent
- [ ] All joins have correct keys and join types (INNER / LEFT OUTER — check against Joiner transformation settings)
- [ ] Filter conditions are correctly translated (especially `IIF` / `DECODE` into `CASE WHEN`)
- [ ] Target field list and datatypes match the target table DDL
- [ ] Pre/post SQL (TRUNCATE, index rebuild) is present if the workflow had it

**Gate 3 — Minimum review checklist:**

- [ ] All `TODO: $$PARAM` stubs are resolved or tracked in your issue log
- [ ] `connections.yaml` connection names match your target platform connection registry
- [ ] Boundary test file (`test_expressions_*.py`) passes `pytest` with no errors
- [ ] Golden comparison script run against a captured Informatica output (if golden data is available)
- [ ] Row count and field-level match rates are above your project threshold (typically ≥ 99.5%)

---

### Testing strategy

**Boundary tests are a minimum bar, not a finish line.**

The generated `test_expressions_*.py` file covers boundary values for expression logic — null handling, edge dates, IIF/DECODE branches. These should pass before Gate 3. But they are unit tests of individual expressions; they do not prove the full pipeline is correct end-to-end.

**Always run a golden comparison if you can capture Informatica output.**

Before decommissioning an Informatica job:
1. Run the Informatica mapping against a representative data slice and capture the output CSV
2. Run the converted pipeline against the same input
3. Use `compare_golden.py` to compare — review the mismatch sample for any systematic differences
4. A field-level match rate below 99.5% is a blocking defect; 99.5–99.9% warrants investigation

**Prioritise golden comparison for:**
- Any mapping with complex expression logic (IIF nesting > 2 levels, DECODE with many branches)
- Any mapping that feeds a regulatory report or financial reconciliation
- Any mapping that uses `$$BATCH_DATE` or other runtime-varying parameters (run comparison with the same date in both systems)

---

### Post-conversion validation

After the converted pipeline is deployed to the target platform, before sign-off:

- [ ] Run the pipeline end-to-end in a non-production environment with production-representative data
- [ ] Compare row counts to the last known Informatica run for the same period
- [ ] Verify reject file handling — confirm rejects are captured and routed correctly
- [ ] Check commit/error thresholds — confirm the pipeline fails cleanly on bad data (doesn't silently continue)
- [ ] Review execution time — if the converted pipeline is significantly slower, investigate parallelism and partition settings from the original workflow
- [ ] Confirm monitoring and alerting is configured before decommissioning Informatica for that mapping

**Run Informatica and the converted pipeline in parallel for at least one full batch cycle** before switching over. This gives you a live comparison rather than relying on historical golden data alone.
