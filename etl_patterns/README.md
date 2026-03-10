# etl_patterns

Config-driven ETL pattern library for Informatica PowerCenter conversion outputs.

Each converted mapping produces a YAML config file that references one of ten
pre-built, tested patterns. This library executes those patterns at runtime —
the generated project carries no bespoke ETL logic of its own.

## Installation

```bash
pip install -e .              # development (editable)
pip install etl_patterns      # production (when published)
```

## Usage

```python
from etl_patterns import config_loader
config_loader.run("config/m_dim_customer_load.yaml")
```

## Supported patterns

| Pattern | Description |
|---|---|
| `truncate_and_load` | Full refresh — drop and reload |
| `incremental_append` | Watermark-based append, no updates |
| `upsert` | SCD Type 1 merge on business key |
| `scd2` | SCD Type 2 history-preserving dimension |
| `lookup_enrich` | Main stream enriched by N external lookups |
| `aggregation_load` | GROUP BY + aggregate functions |
| `filter_and_route` | One input split to N targets by condition |
| `union_consolidate` | N sources merged to one target |
| `expression_transform` | Column-level derivations, single source/target |
| `pass_through` | Trivial extract with no meaningful transformation |

## Supported IO types

**Sources / Targets:** database (via SQLAlchemy), delimited flat file, fixed-width
flat file, XML file, JSON file, Excel file.

## Design specification

See `docs/DESIGN_PATTERN_LIBRARY.md` in the parent repository.
