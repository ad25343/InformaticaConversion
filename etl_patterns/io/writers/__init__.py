"""
io/writers — Target writer implementations.

Factory
-------
Use ``get_writer(target_config)`` to get the right writer for any target type:

    from etl_patterns.io.writers import get_writer
    writer = get_writer(cfg["target"])
    rows_written = writer.write(df)
"""
from __future__ import annotations

from etl_patterns.exceptions import ConfigError
from etl_patterns.io.base import BaseWriter
from etl_patterns.io.writers.db_writer import DatabaseWriter
from etl_patterns.io.writers.flat_file_writer import FlatFileWriter

_WRITER_MAP: dict[str, type[BaseWriter]] = {
    "database":  DatabaseWriter,
    "db":        DatabaseWriter,
    "flat_file": FlatFileWriter,
    "delimited": FlatFileWriter,
    "csv":       FlatFileWriter,
}


def get_writer(target_config: dict) -> BaseWriter:
    """
    Return the correct writer instance for the given target config block.

    Parameters
    ----------
    target_config   The ``target:`` section of the pattern YAML (already parsed).

    Raises
    ------
    ConfigError  If ``type`` is missing or unrecognised.
    """
    tgt_type = target_config.get("type", "").lower().strip()
    if not tgt_type:
        raise ConfigError("target block is missing 'type'")
    writer_cls = _WRITER_MAP.get(tgt_type)
    if writer_cls is None:
        raise ConfigError(
            f"Unknown target type: {tgt_type!r}. "
            f"Supported: {sorted(_WRITER_MAP)}"
        )
    return writer_cls(target_config)


__all__ = [
    "get_writer",
    "BaseWriter",
    "DatabaseWriter",
    "FlatFileWriter",
]
