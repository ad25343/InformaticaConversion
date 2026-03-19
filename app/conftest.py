"""
conftest.py — pytest session configuration.

Adds the repository root to sys.path so that the top-level `etl_patterns`
package is importable when running tests from within the app/ directory.
"""
import sys
from pathlib import Path

# Repository root is one level above this file (app/)
_REPO_ROOT = str(Path(__file__).parent.parent.resolve())
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
