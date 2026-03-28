# Informatica PowerCenter Sample Data Estate

## Overview
Four enterprise organizations representing distinct industry verticals,
each with a complete set of Informatica PowerCenter ETL mappings, workflows,
parameter files, and shared mapplets.

## Organizations

| Org | Industry | Mappings | Workflows | Key Domains |
|-----|----------|----------|-----------|-------------|
| **firstbank** | Retail Banking | 56 | 56 | Fraud, AML, Basel III, Derivatives, Mortgage, GL Reconciliation |
| **nexus_scm** | Supply Chain | 56 | 56 | MRP, Demand Sensing, ABC/XYZ, Supplier Risk, Landed Cost, CO2 |
| **meridian_am** | Asset Management | 56 | 56 | Brinson Attribution, ESG, Stress Testing, TCA, Tax Lots, VaR |
| **apex_insurance** | P&C Insurance | 55 | 55 | IFRS 17, Solvency II, Cat Modeling, Claims Triage, Actuarial Pricing |

## Complexity Tiers

| Tier | Description | Pattern |
|------|-------------|---------|
| **Simple** (~30%) | Dimension loads, staging extracts, reference tables | Source → SQ → EXP → Target |
| **Medium** (~40%) | SCD2, aggregations, unions, incremental loads, routers | + LKP, AGG, FIL, RTR, UPD, SEQ |
| **Complex** (~30%) | Multi-source regulatory/analytical calculations | + JNR, multiple targets, Stored Procedures |

## Transformation Types Covered
Source Qualifier, Expression, Joiner, Router, Aggregator, Lookup Procedure,
Filter, Update Strategy, Sequence Generator, Stored Procedure, Sorter, Rank,
Union, Normalizer

## Enterprise Patterns
- **SCD Type 2** with MD5 hash change detection
- **Surrogate key generation** via Sequence Generator
- **Unconnected Lookups** (:LKP syntax in expressions)
- **Reusable transformations** (ISREUSABLE="YES")
- **Flat file sources** (CSV, pipe-delimited, fixed-width)
- **SQL Override** on Source Qualifiers (incremental extracts)
- **Multi-session workflows** with conditional branching
- **Error handling** (CMD pre-session, Email on success/failure)
- **Shared Mapplets** (audit stamp, data cleansing, date lookup + domain-specific)
- **Environment-specific parameters** (DEV/UAT/PROD, 33 params each)

## File Structure (per org)
```
{org}/
  mappings/
    simple/      # Dimension loads, staging, reference
    medium/      # SCD2, aggregations, incremental, routing
    complex/     # Multi-source analytics, regulatory
  all_mappings/  # Flat copy of all mappings
  workflows/
    simple/      # Single-session workflows
    medium/      # Single-session with error handling
    complex/     # Multi-session sequential chains
  mapplets/
    shared_mapplets.xml  # Reusable transformation fragments
  parameter_files/
    params_{org}_dev.xml   # 33 params
    params_{org}_uat.xml   # 33 params
    params_{org}_prod.xml  # 33 params
  README.md
  INDEX.txt
  {org}_full.manifest.json
```

## Informatica Functions Used
IIF, ISNULL, ROUND, ABS, DECODE, SUBSTR, LPAD, LTRIM, RTRIM, UPPER,
INITCAP, TO_CHAR, TO_DATE, TO_DECIMAL, TRUNC, MD5, LENGTH, CONCAT,
REG_REPLACE, REPLACECHR, SYSDATE, ADD_TO_DATE, EXP, SQRT, SUM, COUNT,
AVG, STDDEV, MAX, MIN
