# Design: Config-Driven Pattern Library for Informatica Conversion

**Status:** Design / Pre-implementation
**Version target:** v2.16.0
**Last updated:** 2026-03-10
**Authors:** Engineering

---

## 1. Motivation

The current conversion pipeline operates on a strict **one-to-one** model: one
Informatica mapping XML in, one bespoke set of generated code files out. Each
conversion is self-contained and isolated — it does not know what other mappings
exist, cannot share logic with them, and produces no reusable artefacts.

This is correct for correctness but inefficient at scale. In any real Informatica
estate the same logical patterns repeat constantly:

- Every dimension table is loaded the same way (truncate and reload, or SCD2)
- Every fact table joins to the same set of dimension lookups
- Every staging extract is a filtered pass-through with ETL metadata columns appended
- Every aggregation groups by a key set and applies SUM/COUNT/AVG

Generating bespoke code for each instance of the same pattern produces:

- **Large code footprint** — N implementations of the same logic instead of one
- **Inconsistency** — subtle variation between instances of the same pattern
- **Maintenance burden** — fixing a bug in the SCD2 logic means fixing N files
- **No reuse** — the target platform (dbt, PySpark, Python) rewards shared
  libraries and macros; the current output ignores that completely

The pattern library approach inverts this. Pre-built, tested, stack-specific
library components handle the execution logic for each recognised pattern. The
conversion agent's job becomes: **identify the pattern, extract the config
parameters, emit a config file**. The library does the rest.

---

## 2. Core Concept

```
TODAY
─────────────────────────────────────────────────────────────
Mapping XML  →  Conversion Agent  →  200 lines of bespoke code
                (generates everything)

WITH PATTERN LIBRARY
─────────────────────────────────────────────────────────────
Mapping XML  →  Pattern Classifier  →  Pattern: scd2 (HIGH)
                                    ↓
              Config Generator    →  20-line config YAML
                                    ↓
              Library (pre-built)  →  Executes at runtime
```

The library is written once, tested once, maintained in one place. Each mapping
becomes a config file that parameterises the appropriate library component.
Bespoke code is generated only for the minority of mappings that do not fit any
recognised pattern — and even then, only for the non-standard portions.

---

## 3. The Ten Patterns

### 3.1 Truncate and Load (Full Refresh)

**What it is:** Drop all data in the target, reload from source. No delta logic,
no keys, no history. The simplest and most common pattern.

**Trigger conditions (ALL must be true):**
- Single source table or query
- No Aggregator transformation
- No Lookup transformation (or only enrichment lookups — see 3.5)
- No Update Strategy transformation
- No Router transformation
- Load type is full / unconditional (no watermark filter)

**Common in:** Reference tables (`REF_`), static dimension loads, configuration
tables, any table where a full reload is cheaper than delta tracking.

**dbt:** `materialized='table'` — the model is rebuilt from scratch on every run.

**PySpark / Python:** `df.write.mode("overwrite")` to the target.

**Config example:**
```yaml
pattern: truncate_and_load
source:
  type: database
  connection: FIRSTBANK_OLTP
  query: "SELECT * FROM INTEREST_RATE_TABLE WHERE IS_ACTIVE = 'Y'"
target:
  type: database
  connection: FIRSTBANK_DWH
  table: REF_INTEREST_RATES
column_map:
  - source: RATE_ID
    target: RATE_ID
  - source: BASE_RATE
    target: BASE_RATE
  - source: SPREAD
    target: SPREAD
  - source: FINAL_RATE
    target: FINAL_RATE
    expression: "BASE_RATE + SPREAD"
etl_metadata: true
```

---

### 3.2 Incremental Append

**What it is:** Read only new records since the last successful run (using a
watermark — a date column, a sequence ID, a timestamp), append to the target.
No updates to existing records.

**Trigger conditions:**
- Filter transformation on a date or sequence field (the watermark column)
- No Update Strategy transformation
- Append-only target (no business key deduplication)

**Common in:** Transaction fact tables, event logs, audit trails, high-volume
append-only tables.

**dbt:** `materialized='incremental'` with `{% if is_incremental() %}` filter.

**PySpark / Python:** Read watermark from a control table, filter source, append.

**Config example:**
```yaml
pattern: incremental_append
source:
  type: database
  connection: FIRSTBANK_OLTP
  query: "SELECT * FROM TRANSACTIONS_RAW WHERE TXN_DATE >= :watermark"
watermark:
  column: TXN_DATE
  control_table: ETL_WATERMARKS
  control_key: fct_daily_transactions
target:
  type: database
  connection: FIRSTBANK_DWH
  table: FCT_DAILY_TRANSACTIONS
column_map:
  - source: TXN_ID
    target: TXN_ID
etl_metadata: true
```

---

### 3.3 Upsert / SCD Type 1

**What it is:** Insert new records, update existing ones based on a business key.
No history is kept — only the current state of each record. Sometimes called a
"merge" or "Type 1 slowly changing dimension."

**Trigger conditions:**
- Update Strategy transformation present
- Lookup transformation checking existence (not a self-lookup — see 3.4)
- Business key fields identifiable from the lookup join condition

**Common in:** Dimension tables where history is not required, customer master
data, account status tables.

**dbt:** `materialized='incremental'` with `unique_key` and merge strategy.

**PySpark:** `DeltaTable.forPath().merge()` or equivalent upsert pattern.

**Config example:**
```yaml
pattern: upsert
source:
  type: database
  connection: FIRSTBANK_OLTP
  query: "SELECT * FROM BRANCH"
target:
  type: database
  connection: FIRSTBANK_DWH
  table: DIM_BRANCH
business_key: [BRANCH_ID]
update_columns: [BRANCH_NAME, ADDRESS, CITY, STATE, STATUS, MANAGER_EMPLOYEE_ID]
column_map:
  - source: BRANCH_ID
    target: BRANCH_ID
etl_metadata: true
```

---

### 3.4 SCD Type 2 (History-Preserving Dimension)

**What it is:** Detect changed records, expire the current row (set end date,
clear current flag), insert a new version. Full history of every change is
retained. The most formulaic of the complex patterns.

**Trigger conditions (strong signal — any one is sufficient):**
- Lookup transformation that points at the **same table as the target** (the
  self-lookup pattern — the mapping checks if the record already exists in its
  own output)
- Router transformation with groups named or structured as new / changed /
  unchanged (or equivalent)
- Update Strategy present alongside a Lookup against the target table

**Common in:** Customer dimensions, account dimensions, product dimensions,
any slowly-changing attribute that needs full audit history.

**dbt:** `dbt snapshot` with `strategy: check` (tracked columns) or
`strategy: timestamp` (updated-at column).

**PySpark:** Window function pattern — `partitionBy(business_key).orderBy(desc(eff_date))`,
`row_number() == 1` identifies the current record.

**Config example:**
```yaml
pattern: scd2
source:
  type: database
  connection: FIRSTBANK_OLTP
  query: "SELECT * FROM CUSTOMER"
target:
  type: database
  connection: FIRSTBANK_DWH
  table: DIM_CUSTOMER
business_key: [CUSTOMER_ID]
tracked_columns:
  - FIRST_NAME
  - LAST_NAME
  - EMAIL
  - STATUS
  - CUSTOMER_TYPE
  - ADDRESS_LINE1
effective_date_column: EFF_START_DATE
expiry_date_column: EFF_END_DATE
current_flag_column: IS_CURRENT
surrogate_key_column: CUSTOMER_SK
column_map:
  - source: FIRST_NAME
    target: FIRST_NAME
    expression: "UPPER(TRIM({value}))"
  - source: EMAIL
    target: EMAIL
    expression: "null_safe({value}, 'UNKNOWN')"
etl_metadata: true
```

---

### 3.5 Lookup Enrichment

**What it is:** A main data stream joined to one or more reference/dimension
tables to add descriptive attributes. The Informatica Lookup transformation
pattern applied to external tables (not self-referential). Extremely common in
fact table loads.

**Trigger conditions:**
- One or more Lookup transformations pointing at tables **other than** the target
- Each lookup adds columns to the main flow (not just a check for existence)
- The lookups are logically enrichments — adding foreign keys or descriptive
  columns from dimension tables

**Common in:** Fact table loads (join to DIM_DATE, DIM_CUSTOMER, DIM_ACCOUNT),
transaction enrichment, any mapping that resolves natural keys to surrogate keys.

**dbt:** `ref()` joins to dimension models in a CTE chain.

**PySpark / Python:** `df.join(broadcast(lookup_df), on=key, how='left')` per lookup.

**Config example:**
```yaml
pattern: lookup_enrich
source:
  type: database
  connection: FIRSTBANK_OLTP
  query: "SELECT * FROM TRANSACTIONS_RAW WHERE TXN_DATE = :run_date"
lookups:
  - name: customer_dim
    table: DIM_CUSTOMER
    connection: FIRSTBANK_DWH
    join_key: CUSTOMER_ID
    columns: [CUSTOMER_SK, CUSTOMER_TYPE, SEGMENT]
    strategy: left
  - name: date_dim
    table: DIM_DATE
    connection: FIRSTBANK_DWH
    join_key: TXN_DATE
    join_key_target: FULL_DATE
    columns: [DATE_KEY, FISCAL_PERIOD, FISCAL_YEAR]
    strategy: left
target:
  type: database
  connection: FIRSTBANK_DWH
  table: FCT_DAILY_TRANSACTIONS
column_map:
  - source: TXN_ID
    target: TXN_ID
  - lookup: customer_dim
    source: CUSTOMER_SK
    target: CUSTOMER_SK
etl_metadata: true
```

---

### 3.6 Aggregation Load

**What it is:** Read a dataset, group by a set of key columns, apply aggregate
functions (SUM, COUNT, AVG, MAX, MIN), write to a summary table. The Informatica
Aggregator transformation.

**Trigger conditions:**
- Aggregator transformation present (unambiguous — no other pattern uses it)

**Common in:** Monthly/weekly summaries (`AGG_`), reporting tables, KPI tables,
branch/product performance rollups.

**dbt:** `GROUP BY` in a SQL model.

**PySpark / Python:** `.groupBy().agg()`.

**Config example:**
```yaml
pattern: aggregation_load
source:
  type: database
  connection: FIRSTBANK_DWH
  query: "SELECT * FROM FCT_DAILY_TRANSACTIONS WHERE MONTH_KEY = :run_month"
group_by: [CUSTOMER_ID, MONTH_KEY]
aggregates:
  - output: TOTAL_TXN_AMOUNT
    function: SUM
    input: TXN_AMOUNT
  - output: TXN_COUNT
    function: COUNT
    input: TXN_ID
  - output: AVG_TXN_AMOUNT
    function: AVG
    input: TXN_AMOUNT
  - output: MAX_TXN_AMOUNT
    function: MAX
    input: TXN_AMOUNT
target:
  type: database
  connection: FIRSTBANK_DWH
  table: AGG_MONTHLY_CUSTOMER_SUMMARY
etl_metadata: true
```

---

### 3.7 Filter and Route

**What it is:** Read a single dataset, split into multiple output streams based
on conditional logic, write each stream to a different target. The Informatica
Router transformation.

**Trigger conditions:**
- Router transformation present
- Multiple TARGETLOADORDER entries in the mapping (multiple targets)

**Common in:** Risk categorisation (HIGH/MEDIUM/LOW buckets), fraud triage,
regulatory classification, any mapping that splits records by business rule.

**dbt:** Multiple models — each filters the shared staging model with a `WHERE`
clause referencing the route condition.

**PySpark / Python:** Multiple filtered writes from one read.

**Config example:**
```yaml
pattern: filter_and_route
source:
  type: database
  connection: FIRSTBANK_OLTP
  query: "SELECT *, FRAUD_SCORE FROM TXN_STREAM"
routes:
  - name: high_risk
    condition: "FRAUD_SCORE >= 80"
    target:
      type: database
      connection: FIRSTBANK_DWH
      table: FCT_HIGH_RISK_FRAUD_EVENTS
  - name: medium_risk
    condition: "FRAUD_SCORE >= 40 AND FRAUD_SCORE < 80"
    target:
      type: database
      connection: FIRSTBANK_DWH
      table: FCT_MEDIUM_RISK_EVENTS
  - name: normal
    condition: "FRAUD_SCORE < 40"
    target:
      type: database
      connection: FIRSTBANK_DWH
      table: FCT_CLEAN_TRANSACTIONS
etl_metadata: true
```

---

### 3.8 Union Consolidation

**What it is:** Read from multiple sources with compatible schemas, union them
into a single dataset, optionally deduplicate, write to one target. The
Informatica Union transformation.

**Trigger conditions:**
- Union transformation present
- Multiple SOURCE elements with the same or compatible field structure

**Common in:** Cross-system consolidation (multiple regional databases feeding
one central table), multi-file aggregation, combining current and historical
data from different systems.

**Config example:**
```yaml
pattern: union_consolidate
sources:
  - name: lending_exposure
    type: database
    connection: LENDING_DB
    query: "SELECT COUNTERPARTY_ID, EXPOSURE_TYPE, AMOUNT FROM LENDING_EXPOSURES"
  - name: trading_book
    type: database
    connection: TRADING_DB
    query: "SELECT COUNTERPARTY_ID, 'TRADING' AS EXPOSURE_TYPE, MTE AS AMOUNT FROM TRADING_BOOK"
  - name: derivatives_book
    type: database
    connection: DERIV_DB
    query: "SELECT COUNTERPARTY_ID, INSTRUMENT_TYPE AS EXPOSURE_TYPE, MTM_VALUE AS AMOUNT FROM DERIVATIVES_BOOK"
deduplication:
  enabled: false
target:
  type: database
  connection: FIRSTBANK_DWH
  table: FCT_COUNTERPARTY_EXPOSURE
etl_metadata: true
```

---

### 3.9 Expression Transform

**What it is:** A single source, a set of column-level transformations (type
casts, string functions, NULL handling, date conversions, simple conditionals),
one target. No joins, no aggregations, no routing. The Informatica Expression
transformation applied to a single stream.

**Trigger conditions:**
- Single source
- Expression transformation present with business-logic output ports
- No Aggregator, Joiner, Router, or Union
- No self-referential Lookup

**Common in:** Data cleansing, staging enrichment with derived columns, type
normalisation, ETL metadata column injection.

**Config example:**
```yaml
pattern: expression_transform
source:
  type: database
  connection: FIRSTBANK_OLTP
  query: "SELECT * FROM CUSTOMER"
target:
  type: database
  connection: FIRSTBANK_DWH
  table: STG_CUSTOMER
column_map:
  - source: CUSTOMER_ID
    target: CUSTOMER_ID
  - source: FIRST_NAME
    target: FIRST_NAME
    expression: "UPPER(TRIM({value}))"
  - source: EMAIL
    target: EMAIL
    expression: "null_safe({value}, 'UNKNOWN')"
  - source: DATE_OF_BIRTH
    target: DATE_OF_BIRTH
    expression: "type_cast({value}, 'date', format='MM/DD/YYYY')"
  - derived: true
    target: CUSTOMER_AGE
    expression: "date_diff(today(), DATE_OF_BIRTH, 'years')"
etl_metadata: true
```

---

### 3.10 Pass-Through

**What it is:** Read from source, apply no meaningful transformation (only
implicit type casts or column renames if any), write to target. The purest
extract-and-load. Often used for staging raw data before any transformation
layer touches it.

**Trigger conditions:**
- Single source
- No Expression transformation with derived logic (or trivial EXP — only
  pass-through ports, no output-only ports with expressions)
- No Aggregator, Joiner, Router, Lookup, or Union

**Common in:** Raw staging extracts, archive loads, feed handoffs between
systems where the consuming system does all the transformation.

**Config example:**
```yaml
pattern: pass_through
source:
  type: flat_file
  path: /inbound/atm_transactions_*.csv
  format: delimited
  delimiter: ","
  has_header: true
  encoding: UTF-8
  null_value: ""
  date_format: "YYYY-MM-DD"
target:
  type: database
  connection: FIRSTBANK_DWH
  table: STG_ATM_TRANSACTIONS_RAW
column_map:
  - source: TXN_ID
    target: TXN_ID
  - source: TXN_DATE
    target: TXN_DATE
  - source: AMOUNT
    target: AMOUNT
etl_metadata: true
post_hooks:
  - archive_source_file: /inbound/processed/
```

---

## 4. IO Abstraction Layer

The source and target blocks are IO-agnostic. The same pattern works regardless
of where data comes from or goes to. The `type` field determines which reader
or writer the library uses.

### 4.1 Source Types

```yaml
# Relational database
source:
  type: database
  connection: <connection_name>   # resolved at runtime from connections.yaml
  query: "SELECT ..."             # full SQL or table name

# Delimited flat file (CSV, pipe, tab, etc.)
source:
  type: flat_file
  path: /path/to/file.csv         # supports glob wildcards for multi-file loads
  format: delimited
  delimiter: ","                  # or "|" or "\t"
  has_header: true
  encoding: UTF-8
  null_value: ""                  # how NULL is represented in the file
  date_format: "YYYY-MM-DD"
  quote_char: '"'                 # optional

# Fixed-width flat file
source:
  type: flat_file
  format: fixed_width
  path: /path/to/file.dat
  encoding: UTF-8
  columns:
    - name: ACCOUNT_ID
      start: 1
      length: 10
      type: string
    - name: BALANCE
      start: 11
      length: 15
      type: decimal
      scale: 2

# XML file
source:
  type: xml_file
  path: /path/to/data.xml
  record_xpath: "/root/record"
  field_map:
    CUSTOMER_ID: "id/@value"
    FIRST_NAME:  "name/first/text()"

# JSON file
source:
  type: json_file
  path: /path/to/data.json
  record_path: "$.records[*]"
  field_map:
    CUSTOMER_ID: "$.id"
    FIRST_NAME:  "$.name.first"

# Excel
source:
  type: excel_file
  path: /path/to/data.xlsx
  sheet: "Sheet1"
  header_row: 1
  data_start_row: 2

# Multi-file (wildcard — all files matching the pattern are read and unioned)
source:
  type: flat_file
  path: /inbound/txns_*.csv
  format: delimited
  delimiter: "|"
  has_header: true
```

### 4.2 Target Types

Mirrors the source types. All targets additionally support:
- `mode: overwrite | append | merge` — default depends on the pattern
- `pre_hooks` / `post_hooks` — SQL or shell commands run before/after the write

```yaml
# Database target
target:
  type: database
  connection: FIRSTBANK_DWH
  table: DIM_CUSTOMER
  mode: overwrite                 # set by pattern; not normally hand-specified

# Flat file target
target:
  type: flat_file
  path: /outbound/customer_extract_{{run_date}}.csv
  format: delimited
  delimiter: ","
  include_header: true
  encoding: UTF-8
  null_value: ""

# Reject / error file (automatically generated by patterns that support it)
reject_target:
  type: flat_file
  path: /outbound/rejects/customer_extract_{{run_date}}_rejects.csv
  format: delimited
  include_header: true
```

---

## 5. Shared Utilities

Every pattern uses these. They are built once and available across all stacks.

### 5.1 `etl_metadata`

Appends standard audit columns to every target row. Eliminates the most repeated
pattern in any Informatica estate — the four or five EXP ports that every single
mapping adds for ETL tracking.

| Column | Value |
|---|---|
| `ETL_LOAD_DATE` | Run timestamp (SYSDATE / current_timestamp) |
| `ETL_BATCH_ID` | Unique batch identifier for the run |
| `ETL_SOURCE_SYSTEM` | Source system name from config |
| `ETL_SOURCE_FILE` | File path (for file-based loads; NULL for DB loads) |
| `ETL_RUN_ID` | Run ID from the control framework (if enabled) |

**Config:**
```yaml
etl_metadata: true               # adds all standard columns
# OR fine-grained:
etl_metadata:
  load_date: true
  batch_id: true
  source_system: "FIRSTBANK_OLTP"
  source_file: true              # only populated for file-based sources
  run_id: false
```

### 5.2 `null_safe`

Replaces the `IIF(ISNULL(x), default, x)` pattern that appears in every estate.

```yaml
expression: "null_safe({value}, 'UNKNOWN')"
expression: "null_safe({value}, 0)"
expression: "null_safe({value}, '1900-01-01', type='date')"
```

### 5.3 `type_cast`

Consistent type conversion with format strings. Replaces `TO_DATE`, `TO_NUMBER`,
`TO_CHAR` patterns.

```yaml
expression: "type_cast({value}, 'date', format='MM/DD/YYYY')"
expression: "type_cast({value}, 'decimal', precision=15, scale=2)"
expression: "type_cast({value}, 'integer')"
```

### 5.4 `string_clean`

Replaces the `UPPER(TRIM(x))` and `LTRIM(RTRIM(x))` patterns.

```yaml
expression: "string_clean({value}, upper=true, trim=true)"
expression: "string_clean({value}, trim=true)"
```

### 5.5 `watermark_manager`

Reads the last successful run watermark from a control table, passes it to the
source query as `:watermark`, updates it on successful completion.

```yaml
watermark:
  column: TXN_DATE
  control_table: ETL_WATERMARKS
  control_key: fct_daily_transactions
  type: date                     # or: timestamp, integer, string
```

### 5.6 `config_loader`

The runtime entry point. Reads a pattern config YAML, validates it, dispatches
to the correct pattern class, and executes. Every generated run script calls
this with the path to the config file — the run script itself is static and
never changes.

```python
# run.py — static, never generated, same for every mapping
from etl_patterns import config_loader
config_loader.run("config/m_dim_customer_load.yaml")
```

### 5.7 `file_lifecycle`

Handles file-based source lifecycle operations automatically based on config.

- `archive_source_file` — move processed files to archive folder with timestamp prefix
- `reject_writer` — write rejected records to a sidecar error file
- `file_validator` — check row count, required column presence, key field
  non-null before processing begins

---

## 6. Confidence Classification

The pattern classifier emits a confidence level alongside the pattern name.
Confidence feeds into the existing gate review so humans see it at the right
moment — not as a new gate, but as additional signal at the existing gates.

| Level | Meaning | What happens |
|---|---|---|
| **HIGH** | Structural signature is unambiguous | Config generated automatically; no special flag at gate |
| **MEDIUM** | Fits pattern but has unusual elements | Config generated; flagged elements highlighted at Gate 1 for human confirmation |
| **LOW** | Partially fits; significant deviation | Pattern suggested as starting point; human confirms at Gate 1 before conversion runs |
| **NONE** | Does not fit any known pattern | Falls back to current full bespoke code generation; flagged prominently |

For MEDIUM and LOW confidence, the specific elements that caused the reduced
confidence are surfaced in the Gate 1 review so the human knows exactly what to
look at.

For NONE confidence, the `bespoke_overrides` field in the config envelope
contains the generated code, so the output structure is identical — a human
reading the output always sees a config file, whether the pattern was recognised
or not.

---

## 7. The Decision Tree

The pattern is determined by reading the transformation chain. This is
**deterministic** — the XML structure tells you the pattern; it is not
inferred by AI heuristics.

```
1. Multiple distinct SOURCE elements feeding a Joiner?
      YES → Lookup Enrichment (if Lookups against external tables)
            OR Union Consolidation (if Union transformation present)
      NO  → continue

2. Aggregator transformation present?
      YES → Aggregation Load  (STOP — unambiguous)
      NO  → continue

3. Router transformation present?
      YES → Filter and Route  (STOP — check for multiple TARGETLOADORDER)
      NO  → continue

4. Lookup transformation that points at the TARGET table itself?
      YES → SCD Type 2  (STOP — self-lookup is the definitive signature)
      NO  → continue

5. Update Strategy transformation present?
      YES → Upsert / SCD Type 1  (STOP)
      NO  → continue

6. Lookup transformations pointing at OTHER tables?
      YES → Lookup Enrichment
      NO  → continue

7. Filter transformation on a date/sequence column?
      YES → Incremental Append
      NO  → continue

8. Expression transformation with derived output ports?
      YES → Expression Transform
      NO  → Pass-Through
```

**Secondary refinements** (applied after pattern assignment):

- `DATABASETYPE="Flat File"` on SOURCE or TARGET → use file IO reader/writer
- Custom SQL in Source Qualifier (`Sql Query` TABLEATTRIBUTE non-empty and
  > 100 chars) → reduce confidence to MEDIUM; surface the SQL for human review
- External Procedure transformation present → reduce confidence to LOW; flag
  the external call
- 3+ Joiner transformations in one mapping → reduce confidence to LOW regardless
  of pattern; high structural complexity warrants human confirmation

---

## 8. Config Envelope (Full Schema)

Every pattern config follows this structure. Stack-specific fields are nested
under a `stack_hints` key and are optional — the library defaults apply if absent.

```yaml
# ── Required ─────────────────────────────────────────────────────────────────
pattern: <pattern_name>           # one of the ten patterns
confidence: HIGH | MEDIUM | LOW | NONE

# ── Source(s) ────────────────────────────────────────────────────────────────
source:                           # single source (most patterns)
  type: database | flat_file | xml_file | json_file | excel_file
  # ... type-specific fields (see Section 4)

sources:                          # multiple sources (union_consolidate only)
  - name: <source_alias>
    type: ...

# ── Target ───────────────────────────────────────────────────────────────────
target:
  type: database | flat_file | ...
  # ... type-specific fields

reject_target:                    # optional — where rejected rows go
  type: flat_file
  path: ...

# ── Column mapping ───────────────────────────────────────────────────────────
column_map:
  - source: <source_column_name>
    target: <target_column_name>
    expression: "<expression>"    # optional; uses shared utility functions
  - derived: true                 # column not from source — purely computed
    target: <target_column_name>
    expression: "<expression>"

# ── Pattern-specific fields ──────────────────────────────────────────────────
# SCD2 only:
business_key: [<col>, ...]
tracked_columns: [<col>, ...]
effective_date_column: <col>
expiry_date_column: <col>
current_flag_column: <col>
surrogate_key_column: <col>

# Incremental append only:
watermark:
  column: <col>
  control_table: ETL_WATERMARKS
  control_key: <unique_key>

# Upsert only:
business_key: [<col>, ...]
update_columns: [<col>, ...]

# Aggregation only:
group_by: [<col>, ...]
aggregates:
  - output: <col>
    function: SUM | COUNT | AVG | MAX | MIN
    input: <source_col>

# Filter and Route only:
routes:
  - name: <route_name>
    condition: "<expression>"
    target: { ... }

# Lookups (lookup_enrich only):
lookups:
  - name: <alias>
    table: <table_name>
    connection: <connection>
    join_key: <source_col>
    join_key_target: <lookup_col>  # if different name in lookup table
    columns: [<col>, ...]
    strategy: left | inner

# ── Shared utilities ─────────────────────────────────────────────────────────
etl_metadata: true | false | { ... fine-grained config }

# ── Lifecycle hooks ──────────────────────────────────────────────────────────
pre_hooks: []                     # SQL or shell commands before processing
post_hooks:
  - archive_source_file: /inbound/processed/
  - validate_row_count: true
  - notify_webhook: true

# ── Bespoke overrides (NONE confidence only) ─────────────────────────────────
bespoke_overrides:
  - column: <target_col>
    reason: "Complex nested IIF beyond expression library scope"
    code: |
      # Hand-generated code for this column only
      ...

# ── Stack hints (optional — override library defaults) ───────────────────────
stack_hints:
  dbt:
    materialized: table | incremental | view | ephemeral
    unique_key: [<col>, ...]       # for incremental models
    on_schema_change: fail | append_new_columns | sync_all_columns
  pyspark:
    broadcast_lookups: true        # use broadcast join for small lookup tables
    partition_by: [<col>, ...]     # partition the output dataset
    cache_intermediate: false
  python:
    chunk_size: 50000              # rows per chunk for large file processing
    parallel_files: 4              # parallel readers for multi-file sources
```

---

## 9. Stack-Specific Implementation Notes

### 9.1 dbt

- Each pattern config generates a single `.sql` model file plus an entry in
  `sources.yml` (if the source is an OLTP table)
- SCD2 generates a `snapshots/` file, not a `models/` file
- The `etl_metadata` utility is a dbt macro (`macros/etl_metadata.sql`)
- `null_safe`, `type_cast`, `string_clean` are dbt macros
- `lookup_enrich` generates a CTE chain: one CTE per lookup, final SELECT
  joining all CTEs
- Pattern library macros live in the project's `macros/` directory, generated
  once for the whole project (not per mapping)

### 9.2 PySpark

- Each pattern config drives a Python script that imports from `etl_patterns`
  package
- `etl_patterns` is a pip-installable package committed alongside the generated
  project
- File IO uses PySpark's native readers/writers (CSV, JSON, XML, Parquet)
- SCD2 uses `DeltaTable` merge if Delta Lake is available; falls back to
  window-function pattern otherwise
- Broadcast joins applied automatically for lookup tables below a configurable
  size threshold

### 9.3 Python / Pandas

- Each pattern config drives a Pandas script importing from `etl_patterns`
- Chunked IO used automatically for large sources (`chunk_size` from config)
- File IO uses `pandas.read_csv`, `pandas.read_excel`, custom fixed-width reader
- SCD2 uses merge + concat pattern (no Delta Lake dependency)
- Suitable for low-to-medium volume; high-volume should use PySpark

---

## 10. What the Conversion Agent Produces

Under this model the conversion agent outputs **three things**, not one:

1. **`config/<mapping_name>.yaml`** — the pattern config (always present)
2. **`run.py`** — a static launcher script (identical for every mapping using
   the same stack; not generated fresh each time)
3. **`bespoke/<mapping_name>.py`** — only present for NONE confidence mappings
   or when `bespoke_overrides` is non-empty

The bespoke code generation path (current behaviour) is preserved as the
fallback. A mapping that fits no pattern produces the same output as today.
The library is additive — it does not replace the existing path, it provides
a better path for the majority of mappings.

---

## 11. Build Sequence

### Phase 1 — Shared utilities (no pattern logic, needed by everything)

- `etl_metadata` (dbt macro + PySpark function + Pandas function)
- `null_safe`, `type_cast`, `string_clean`
- `config_loader` (reads YAML, validates, dispatches)
- `watermark_manager`
- `file_lifecycle` (archive, reject writer, validator)
- IO readers/writers for: database, delimited flat file, fixed-width flat file

### Phase 2 — High-frequency patterns (covers ~70% of a typical estate)

- `truncate_and_load`
- `incremental_append`
- `pass_through`
- `expression_transform`

### Phase 3 — Medium-complexity patterns

- `scd2`
- `upsert`
- `lookup_enrich`

### Phase 4 — Remaining patterns

- `aggregation_load`
- `filter_and_route`
- `union_consolidate`

### Phase 5 — Classifier extension

- Extend `classifier_agent.py` to emit pattern name + confidence level +
  config parameter extraction
- Extend Gate 1 review to surface confidence and flagged elements
- Extend conversion agent to call config generator (HIGH/MEDIUM confidence)
  or existing bespoke generator (LOW/NONE confidence)

---

## 12. Future Roadmap (Out of Scope for v2.16.0)

The following IO source/target types are noted for future versions:

- **Message queues** — Kafka, AWS SQS, Azure Service Bus; event-driven
  incremental patterns
- **REST API sources** — paginated API reads, OAuth-managed connections
- **Cloud storage** — S3, ADLS, GCS with native format support
- **FTP/SFTP** — file arrival triggers and secure transfer
- **Email attachments** — SMTP-based file ingestion
- **Streaming targets** — write to Kafka topics from batch sources
- **NoSQL targets** — MongoDB, DynamoDB document writes

---

## 13. Open Questions (Resolved in Design)

| Question | Decision |
|---|---|
| Do we need a new human gate for pattern confidence? | No — LOW/NONE confidence surfaces at the existing Gate 1. No new gates added. |
| What if a mapping fits two patterns? | The decision tree is ordered; the first match wins. Ambiguous cases are flagged as MEDIUM confidence. |
| Do we assume naming conventions (DIM_, FCT_ etc.)? | No. Pattern is determined entirely from transformation topology and XML structure. Names are one optional hint, not the primary signal. |
| What about non-DB, non-file sources (APIs, queues)? | Future roadmap. Current scope: database and file-based IO only. |
| Does the library handle mixed IO (file→DB, DB→file)? | Yes. Source and target types are independent. Any combination is valid. |
| Is the library stack-specific or shared? | Each stack has its own implementation of each pattern. The config schema is shared across stacks. |
