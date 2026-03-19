# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
dbt-specific system prompt and runtime artifact generation for the conversion agent.

Exports:
  DBT_SYSTEM                  — Claude system message for dbt conversions
  build_dbt_runtime_artifacts — generates profiles.yml + requirements.txt
"""
from __future__ import annotations

from typing import Optional

from ._common import _DW_AUDIT_RULES, _load_prompt_template
from ...models.schemas import StackAssignment, SessionParseReport
from ...org_config_loader import get_warehouse_registry, get_warehouse_cred_overrides

# ─────────────────────────────────────────────────────────────────────────────
# dbt system prompt
# ─────────────────────────────────────────────────────────────────────────────

_DBT_SYSTEM_DEFAULT = """You are a senior analytics engineer converting Informatica PowerCenter mappings to dbt.

Rules:
- Work ONLY from the documentation provided — never invent logic not documented there
- Match the number of models to the actual mapping complexity:
    * Simple mapping (1 source → 1 target, basic expressions/filters): ONE model + sources.yml + dbt_project.yml
    * Medium mapping (multiple sources, lookups, or aggregations): staging model + final model + sources.yml + dbt_project.yml
    * Complex mapping (multiple joins, SCD, complex routing): staging + intermediate + mart + sources.yml + dbt_project.yml
- Do NOT create intermediate layers that add no transformation value
- Define sources in sources.yml (required)
- Add tests only for primary keys and not-null on critical fields — keep schema YMLs lean
- Combine all model schema docs into a single schema.yml per folder rather than one YML per model

Informatica-to-dbt pattern guide (apply where relevant):
- Large target tables that load incrementally → use incremental materialisation:
    {{ config(materialized='incremental', unique_key='<pk_column>') }}
    {% if is_incremental() %} WHERE updated_at > (SELECT MAX(updated_at) FROM {{ this }}) {% endif %}
- Surrogate key generation (replaces Informatica sequence generators):
    {{ dbt_utils.generate_surrogate_key(['col1', 'col2']) }} AS surrogate_key
- SCD Type 2 → use dbt snapshots (dbt_project/snapshots/) with strategy: timestamp or check
- LOOKUP transformation → use a ref() join to the lookup model; never hardcode lookup values inline
- ROUTER transformation → use separate CTEs or models with explicit WHERE filters
- Reusable expression logic → extract to a dbt macro in macros/

- Output complete, runnable SQL model files

## Performance Rules — apply to ALL dbt conversions
- Materialisation selection:
  * Staging / intermediate models that feed further transforms: materialized='view'
  * Final mart / fact / dimension models with > ~100k estimated rows: materialized='incremental'
  * Small lookup / reference models: materialized='table'
  * Never default all models to 'view' — unmaterialised chains force full re-scan on every run.
- Incremental strategy: use unique_key on the primary key column(s). Choose the correct
  strategy for the warehouse:
    BigQuery → strategy='insert_overwrite', partition_by the date/event column
    Snowflake / Redshift → strategy='merge', unique_key=[pk]
    Spark/Databricks → strategy='insert_overwrite', partition_by the date/event column
- Partition / cluster keys: for warehouse-native partitioning (BigQuery partition_by,
  Snowflake cluster_by, Redshift sortkey/distkey), add the config block when the target
  table has a clear date or high-cardinality join column.
- Avoid SELECT *: always list columns explicitly in the final SELECT to avoid schema drift
  and unnecessary column scans.
- Filter early: push WHERE / QUALIFY predicates as close to the source CTE as possible,
  before joins, to minimise the rows that flow through the pipeline.

## Execution-Ready Requirements — REQUIRED for all dbt conversions

dbt only handles the transformation layer (T).  To make the output fully execution-ready
you MUST also generate the following two Python files:

### extract/extract_{mapping_name}.py  — Python EL (Extract-Load) script
A self-contained Python script that:
- Reads from every SOURCE connection documented in the mapping
    * Relational / JDBC sources → SQLAlchemy: pd.read_sql(query, engine, chunksize=50_000)
    * Flat-file sources → pd.read_csv(path, chunksize=50_000) with dtype=str fallback
- Applies any pre_session_sql documented in the session config BEFORE the main extract
  (execute via connection.execute(text(pre_sql)) before pd.read_sql)
- Writes extracted data into the warehouse STAGING schema as table stg_{source_table}
  (use pandas DataFrame.to_sql with if_exists="replace" and method="multi")
- Uses a CONFIG dict at the top for ALL connection strings, schema names, paths, passwords
  (read values from os.environ — never hardcode credentials)
- Structured JSON logging: extract start, row count after read, row count after load, duration
- Error handling: on failure log the error with traceback and call sys.exit(1)
- Uses context managers for all DB connections: with engine.connect() as conn:
- Replace {mapping_name} with the actual mapping name (lowercase, underscores)

### run_pipeline.py  — Orchestration wrapper
A Python script that sequences EL → dbt run → dbt test:
- Step 1 — EL: subprocess.run([sys.executable, "extract/extract_{mapping_name}.py"], check=False)
    On non-zero exit: log "EL step failed" and sys.exit(1) — do NOT continue to dbt
- Step 2 — dbt run: subprocess.run(["dbt", "run", "--select", "{dbt_model_name}", "--profiles-dir", "."], check=False)
    On non-zero exit: log "dbt run failed" and sys.exit(1)
- Step 3 — dbt test: subprocess.run(["dbt", "test", "--select", "{dbt_model_name}", "--profiles-dir", "."], check=False)
    On non-zero exit: log "dbt test failed" and sys.exit(1)
- Structured logging with timestamps at each step start and completion
- Single entry point: if __name__ == "__main__": run_pipeline()
- Replace {mapping_name} and {dbt_model_name} with the actual names

Both files use the same <<<BEGIN_FILE: ...>>> / <<<END_FILE>>> delimiter format as all other output files.
""" + _DW_AUDIT_RULES

DBT_SYSTEM: str = _load_prompt_template("dbt", _DBT_SYSTEM_DEFAULT)

# ─────────────────────────────────────────────────────────────────────────────
# dbt warehouse-specific profiles.yml templates
# All credentials are sourced from environment variables — no hardcoded values.
# ─────────────────────────────────────────────────────────────────────────────

_PROFILES_TEMPLATES: dict[str, str] = {
    "postgres": """\
# profiles.yml — generated by Informatica Conversion Tool
# Set the environment variables below before running dbt.
# Run:  dbt run --profiles-dir .
{mapping_name}:
  target: dev
  outputs:
    dev:
      type: postgres
      host: "{{{{ env_var('DBT_HOST') }}}}"
      port: 5432
      user: "{{{{ env_var('DBT_USER') }}}}"
      password: "{{{{ env_var('DBT_PASSWORD') }}}}"
      dbname: "{{{{ env_var('DBT_DATABASE') }}}}"
      schema: "{{{{ env_var('DBT_SCHEMA', 'public') }}}}"
      threads: 4
    prod:
      type: postgres
      host: "{{{{ env_var('DBT_HOST_PROD') }}}}"
      port: 5432
      user: "{{{{ env_var('DBT_USER_PROD') }}}}"
      password: "{{{{ env_var('DBT_PASSWORD_PROD') }}}}"
      dbname: "{{{{ env_var('DBT_DATABASE_PROD') }}}}"
      schema: "{{{{ env_var('DBT_SCHEMA_PROD', 'public') }}}}"
      threads: 8
""",
    "snowflake": """\
# profiles.yml — generated by Informatica Conversion Tool
# Set the environment variables below before running dbt.
{mapping_name}:
  target: dev
  outputs:
    dev:
      type: snowflake
      account: "{{{{ env_var('SNOWFLAKE_ACCOUNT') }}}}"
      user: "{{{{ env_var('SNOWFLAKE_USER') }}}}"
      password: "{{{{ env_var('SNOWFLAKE_PASSWORD') }}}}"
      role: "{{{{ env_var('SNOWFLAKE_ROLE', 'TRANSFORMER') }}}}"
      database: "{{{{ env_var('SNOWFLAKE_DATABASE') }}}}"
      warehouse: "{{{{ env_var('SNOWFLAKE_WAREHOUSE') }}}}"
      schema: "{{{{ env_var('SNOWFLAKE_SCHEMA', 'DEV') }}}}"
      threads: 8
    prod:
      type: snowflake
      account: "{{{{ env_var('SNOWFLAKE_ACCOUNT') }}}}"
      user: "{{{{ env_var('SNOWFLAKE_USER_PROD') }}}}"
      password: "{{{{ env_var('SNOWFLAKE_PASSWORD_PROD') }}}}"
      role: "{{{{ env_var('SNOWFLAKE_ROLE_PROD', 'TRANSFORMER') }}}}"
      database: "{{{{ env_var('SNOWFLAKE_DATABASE_PROD') }}}}"
      warehouse: "{{{{ env_var('SNOWFLAKE_WAREHOUSE_PROD') }}}}"
      schema: "{{{{ env_var('SNOWFLAKE_SCHEMA_PROD', 'PROD') }}}}"
      threads: 16
""",
    "redshift": """\
# profiles.yml — generated by Informatica Conversion Tool
{mapping_name}:
  target: dev
  outputs:
    dev:
      type: redshift
      host: "{{{{ env_var('REDSHIFT_HOST') }}}}"
      port: 5439
      user: "{{{{ env_var('REDSHIFT_USER') }}}}"
      password: "{{{{ env_var('REDSHIFT_PASSWORD') }}}}"
      dbname: "{{{{ env_var('REDSHIFT_DATABASE') }}}}"
      schema: "{{{{ env_var('REDSHIFT_SCHEMA', 'public') }}}}"
      threads: 4
      ra3_node: true
    prod:
      type: redshift
      host: "{{{{ env_var('REDSHIFT_HOST_PROD') }}}}"
      port: 5439
      user: "{{{{ env_var('REDSHIFT_USER_PROD') }}}}"
      password: "{{{{ env_var('REDSHIFT_PASSWORD_PROD') }}}}"
      dbname: "{{{{ env_var('REDSHIFT_DATABASE_PROD') }}}}"
      schema: "{{{{ env_var('REDSHIFT_SCHEMA_PROD', 'public') }}}}"
      threads: 8
      ra3_node: true
""",
    "bigquery": """\
# profiles.yml — generated by Informatica Conversion Tool
# Authentication: set GOOGLE_APPLICATION_CREDENTIALS to your service-account JSON path.
{mapping_name}:
  target: dev
  outputs:
    dev:
      type: bigquery
      method: service-account
      project: "{{{{ env_var('BQ_PROJECT') }}}}"
      dataset: "{{{{ env_var('BQ_DATASET_DEV') }}}}"
      keyfile: "{{{{ env_var('GOOGLE_APPLICATION_CREDENTIALS') }}}}"
      threads: 4
      timeout_seconds: 300
    prod:
      type: bigquery
      method: service-account
      project: "{{{{ env_var('BQ_PROJECT_PROD') }}}}"
      dataset: "{{{{ env_var('BQ_DATASET_PROD') }}}}"
      keyfile: "{{{{ env_var('GOOGLE_APPLICATION_CREDENTIALS_PROD') }}}}"
      threads: 8
      timeout_seconds: 300
""",
    "databricks": """\
# profiles.yml — generated by Informatica Conversion Tool
{mapping_name}:
  target: dev
  outputs:
    dev:
      type: databricks
      host: "{{{{ env_var('DATABRICKS_HOST') }}}}"
      http_path: "{{{{ env_var('DATABRICKS_HTTP_PATH') }}}}"
      token: "{{{{ env_var('DATABRICKS_TOKEN') }}}}"
      schema: "{{{{ env_var('DATABRICKS_SCHEMA', 'dev') }}}}"
      catalog: "{{{{ env_var('DATABRICKS_CATALOG', 'hive_metastore') }}}}"
      threads: 4
    prod:
      type: databricks
      host: "{{{{ env_var('DATABRICKS_HOST_PROD') }}}}"
      http_path: "{{{{ env_var('DATABRICKS_HTTP_PATH_PROD') }}}}"
      token: "{{{{ env_var('DATABRICKS_TOKEN_PROD') }}}}"
      schema: "{{{{ env_var('DATABRICKS_SCHEMA_PROD', 'prod') }}}}"
      catalog: "{{{{ env_var('DATABRICKS_CATALOG_PROD', 'hive_metastore') }}}}"
      threads: 8
""",
    "sqlserver": """\
# profiles.yml — generated by Informatica Conversion Tool
{mapping_name}:
  target: dev
  outputs:
    dev:
      type: sqlserver
      driver: "ODBC Driver 18 for SQL Server"
      server: "{{{{ env_var('MSSQL_SERVER') }}}}"
      port: 1433
      database: "{{{{ env_var('MSSQL_DATABASE') }}}}"
      schema: "{{{{ env_var('MSSQL_SCHEMA', 'dbo') }}}}"
      username: "{{{{ env_var('MSSQL_USER') }}}}"
      password: "{{{{ env_var('MSSQL_PASSWORD') }}}}"
      authentication: sql
      threads: 4
    prod:
      type: sqlserver
      driver: "ODBC Driver 18 for SQL Server"
      server: "{{{{ env_var('MSSQL_SERVER_PROD') }}}}"
      port: 1433
      database: "{{{{ env_var('MSSQL_DATABASE_PROD') }}}}"
      schema: "{{{{ env_var('MSSQL_SCHEMA_PROD', 'dbo') }}}}"
      username: "{{{{ env_var('MSSQL_USER_PROD') }}}}"
      password: "{{{{ env_var('MSSQL_PASSWORD_PROD') }}}}"
      authentication: sql
      threads: 8
""",
}

_DBT_ADAPTER_PACKAGES: dict[str, str] = {
    "snowflake":  "dbt-snowflake>=1.7,<2.0",
    "redshift":   "dbt-redshift>=1.7,<2.0",
    "bigquery":   "dbt-bigquery>=1.7,<2.0",
    "databricks": "dbt-databricks>=1.7,<2.0",
    "sqlserver":  "dbt-sqlserver>=1.7,<2.0",
    "postgres":   "dbt-postgres>=1.7,<2.0",
}


def _get_profiles_yml_from_registry(mapping_name: str, db_type: str) -> str | None:
    """G5: Generate profiles.yml from warehouse_registry.yaml if the warehouse is registered."""
    try:
        registry = get_warehouse_registry()
        cred_overrides = get_warehouse_cred_overrides()
        key = db_type.lower().replace(" ", "_").replace("-", "_")
        if key not in registry:
            return None
        wh = registry[key]
        cred_vars = dict(wh.get("credential_vars", {}))
        # Apply org credential overrides
        org_overrides = cred_overrides.get(key, {})
        for var_key, new_env_var in org_overrides.items():
            if var_key in cred_vars:
                cred_vars[var_key] = new_env_var
        defaults = wh.get("defaults", {})
        adapter = wh.get("adapter", key)
        # Build profiles.yml YAML string
        lines = [
            "# profiles.yml — generated by Informatica Conversion Tool",
            "# Set the environment variables below before running dbt.",
            f"{mapping_name}:",
            "  target: dev",
            "  outputs:",
            "    dev:",
            f"      type: {adapter}",
        ]
        for var_key, env_var in cred_vars.items():
            default = defaults.get(var_key, "")
            if default:
                lines.append(f"      {var_key}: \"{{{{{{ env_var('{env_var}', '{default}') }}}}}}\"")
            else:
                lines.append(f"      {var_key}: \"{{{{{{ env_var('{env_var}') }}}}}}\"")
        threads = defaults.get("threads", 4)
        lines.append(f"      threads: {threads}")
        lines.append("    prod:")
        lines.append(f"      type: {adapter}")
        for var_key, env_var in cred_vars.items():
            env_var_prod = env_var + "_PROD" if not env_var.endswith("_PROD") else env_var
            default = defaults.get(var_key + "_prod", defaults.get(var_key, ""))
            if default:
                lines.append(f"      {var_key}: \"{{{{{{ env_var('{env_var_prod}', '{default}') }}}}}}\"")
            else:
                lines.append(f"      {var_key}: \"{{{{{{ env_var('{env_var_prod}') }}}}}}\"")
        threads_prod = defaults.get("threads_prod", threads * 2)
        lines.append(f"      threads: {threads_prod}")
        return "\n".join(lines) + "\n"
    except Exception:
        return None


def build_dbt_runtime_artifacts(
    stack_assignment: StackAssignment,
    session_parse_report: Optional[SessionParseReport],
) -> dict[str, str]:
    """
    Programmatically generate profiles.yml and requirements.txt for dbt jobs.

    These are deterministic templates (no Claude call needed).
    The warehouse type is auto-detected from the connection_type in the session
    config; falls back to postgres when no session data is available.
    """
    artifacts: dict[str, str] = {}
    mapping_slug = stack_assignment.mapping_name.lower().replace(" ", "_").replace("-", "_")

    # ── Detect warehouse from connection metadata ──────────────────────────
    warehouse = "postgres"
    sc = session_parse_report.session_config if session_parse_report else None
    if sc:
        for conn in sc.connections:
            ct = (conn.connection_type or "").upper()
            if "SNOWFLAKE"  in ct: warehouse = "snowflake";   break
            if "REDSHIFT"   in ct: warehouse = "redshift";    break
            if "BIGQUERY"   in ct: warehouse = "bigquery";    break
            if "DATABRICKS" in ct: warehouse = "databricks";  break
            if "MSSQL"      in ct or "SQLSERVER" in ct: warehouse = "sqlserver"; break

    # ── profiles.yml ──────────────────────────────────────────────────────
    # G5: Try warehouse_registry.yaml first
    registry_result = _get_profiles_yml_from_registry(mapping_slug, warehouse)
    if registry_result is not None:
        artifacts["profiles.yml"] = registry_result
    else:
        template = _PROFILES_TEMPLATES.get(warehouse, _PROFILES_TEMPLATES["postgres"])
        artifacts["profiles.yml"] = template.replace("{mapping_name}", mapping_slug)

    # ── requirements.txt ──────────────────────────────────────────────────
    adapter_pkg = _DBT_ADAPTER_PACKAGES.get(warehouse, "dbt-postgres>=1.7,<2.0")
    artifacts["requirements.txt"] = "\n".join([
        "# Generated by Informatica Conversion Tool — install before running the pipeline",
        "# pip install -r requirements.txt",
        "",
        "# dbt + warehouse adapter",
        "dbt-core>=1.7,<2.0",
        adapter_pkg,
        "",
        "# EL script dependencies",
        "pandas>=2.0,<3.0",
        "pyarrow>=14.0",
        "sqlalchemy>=2.0,<3.0",
        "python-dotenv>=1.0",
        "",
    ])

    return artifacts
