"""
io/readers — Source reader implementations.

Factory
-------
Use ``get_reader(source_config)`` to get the right reader for any source type:

    from etl_patterns.io.readers import get_reader
    reader = get_reader(cfg["source"])
    df = reader.read()
"""
from __future__ import annotations

from etl_patterns.exceptions import ConfigError
from etl_patterns.io.base import BaseReader
from etl_patterns.io.readers.db_reader import DatabaseReader
from etl_patterns.io.readers.flat_file_reader import FlatFileReader
from etl_patterns.io.readers.fixed_width_reader import FixedWidthReader

_READER_MAP: dict[str, type[BaseReader]] = {
    "database":    DatabaseReader,
    "db":          DatabaseReader,
    "flat_file":   FlatFileReader,
    "delimited":   FlatFileReader,
    "csv":         FlatFileReader,
    "fixed_width": FixedWidthReader,
    "fwf":         FixedWidthReader,
}


def get_reader(source_config: dict) -> BaseReader:
    """
    Return the correct reader instance for the given source config block.

    Parameters
    ----------
    source_config   The ``source:`` section of the pattern YAML (already parsed).

    Raises
    ------
    ConfigError  If ``type`` is missing or unrecognised.
    """
    src_type = source_config.get("type", "").lower().strip()
    if not src_type:
        raise ConfigError("source block is missing 'type'")
    reader_cls = _READER_MAP.get(src_type)
    if reader_cls is None:
        raise ConfigError(
            f"Unknown source type: {src_type!r}. "
            f"Supported: {sorted(_READER_MAP)}"
        )
    return reader_cls(source_config)


__all__ = [
    "get_reader",
    "BaseReader",
    "DatabaseReader",
    "FlatFileReader",
    "FixedWidthReader",
]
