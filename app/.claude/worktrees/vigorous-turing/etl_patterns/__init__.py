"""
etl_patterns — Config-driven ETL pattern library (v0.1.0)
==========================================================
Each converted Informatica mapping produces a YAML config file. This library
executes those configs at runtime using pre-built, tested pattern implementations.

Quick start:
    from etl_patterns import config_loader
    config_loader.run("config/m_dim_customer_load.yaml")
"""

__version__ = "0.1.0"
