"""
exceptions.py — etl_patterns exception hierarchy
=================================================
All exceptions raised by the library inherit from ETLPatternError so callers
can catch the entire library with a single except clause if needed.
"""


class ETLPatternError(Exception):
    """Base class for all etl_patterns errors."""


class ConfigError(ETLPatternError):
    """Raised when a pattern config file is invalid or missing required fields."""


class PatternNotFoundError(ETLPatternError):
    """Raised when the pattern name in a config is not registered."""


class ReaderError(ETLPatternError):
    """Raised when a source read operation fails."""


class WriterError(ETLPatternError):
    """Raised when a target write operation fails."""


class ExpressionError(ETLPatternError):
    """Raised when a column-map expression cannot be evaluated."""


class PatternError(ETLPatternError):
    """Raised for pattern-level runtime errors (e.g. misconfigured pattern execution)."""


class WatermarkError(ETLPatternError):
    """Raised when watermark read or write fails."""


class ValidationError(ETLPatternError):
    """Raised when pre/post load validation fails (row count, null checks, etc.)."""
