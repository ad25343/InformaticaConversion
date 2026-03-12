# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
io/base.py — Abstract base classes for all IO readers and writers
=================================================================
Every reader returns a pandas DataFrame (or a generator of chunks).
Every writer accepts a pandas DataFrame and persists it to the target.

Both classes parse the standard ``source:`` / ``target:`` YAML config block
and expose a ``from_config()`` class method for construction.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Generator, Iterator

import pandas as pd


class BaseReader(ABC):
    """
    Abstract base for all source readers.

    Subclasses must implement ``read()`` and may optionally override
    ``read_chunks()`` for memory-efficient processing of large files.
    """

    def __init__(self, config: dict) -> None:
        self._cfg = config

    @classmethod
    def from_config(cls, config: dict) -> "BaseReader":
        """Construct from a parsed YAML source block."""
        return cls(config)

    @abstractmethod
    def read(self) -> pd.DataFrame:
        """
        Read the entire source into a single DataFrame.

        Use this for small-to-medium datasets.  For large sources prefer
        ``read_chunks()`` to avoid loading everything into memory.
        """

    def read_chunks(self, chunksize: int = 100_000) -> Iterator[pd.DataFrame]:
        """
        Yield successive chunks of *chunksize* rows.

        Default implementation reads everything and yields a single chunk.
        Subclasses that support native chunked reading should override this.
        """
        yield self.read()

    @property
    def source_name(self) -> str:
        """Human-readable label for log messages."""
        return str(self._cfg.get("name", type(self).__name__))


class BaseWriter(ABC):
    """
    Abstract base for all target writers.

    Subclasses must implement ``write()``.
    """

    def __init__(self, config: dict) -> None:
        self._cfg = config

    @classmethod
    def from_config(cls, config: dict) -> "BaseWriter":
        """Construct from a parsed YAML target block."""
        return cls(config)

    @abstractmethod
    def write(self, df: pd.DataFrame) -> int:
        """
        Write *df* to the target.

        Returns
        -------
        Number of rows written.
        """

    @property
    def target_name(self) -> str:
        """Human-readable label for log messages."""
        return str(self._cfg.get("name", type(self).__name__))
