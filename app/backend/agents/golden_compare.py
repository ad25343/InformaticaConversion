# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
golden_compare.py — backward-compat shim
=========================================
Delegates to the two focused modules:
  - boundary_tests.py   (Component A: expression boundary test generation)
  - compare_script.py   (Component B: golden CSV comparison script generation)
"""
from .boundary_tests import generate_boundary_tests  # noqa: F401
from .compare_script import generate_comparison_script  # noqa: F401
