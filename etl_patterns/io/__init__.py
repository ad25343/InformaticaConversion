"""
io — IO abstraction layer.
"""
from etl_patterns.io.readers import get_reader
from etl_patterns.io.writers import get_writer

__all__ = ["get_reader", "get_writer"]
