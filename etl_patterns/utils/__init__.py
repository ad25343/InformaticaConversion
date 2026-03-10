"""
utils — Shared ETL helpers used by all pattern implementations.
"""
from etl_patterns.utils.etl_metadata import add_etl_metadata, metadata_columns
from etl_patterns.utils.null_safe import coalesce, is_null, null_safe, nvl, nvl2
from etl_patterns.utils.string_clean import (
    clean_whitespace,
    instr,
    lpad,
    ltrim,
    normalize_string,
    replace_chr,
    replace_str,
    rpad,
    rtrim,
    substr,
    to_lower,
    to_upper,
    trim,
)
from etl_patterns.utils.type_cast import type_cast
from etl_patterns.utils.watermark_manager import WatermarkManager, read_watermark, write_watermark
from etl_patterns.utils.file_lifecycle import (
    FileValidator,
    RejectWriter,
    archive_file,
    archive_glob,
    lifecycle_from_config,
    reject_path_for,
)

__all__ = [
    # etl_metadata
    "add_etl_metadata",
    "metadata_columns",
    # null_safe
    "null_safe",
    "coalesce",
    "is_null",
    "nvl",
    "nvl2",
    # type_cast
    "type_cast",
    # string_clean
    "to_upper", "to_lower", "trim", "ltrim", "rtrim",
    "lpad", "rpad", "substr", "instr",
    "replace_chr", "replace_str",
    "clean_whitespace", "normalize_string",
    # watermark_manager
    "WatermarkManager",
    "read_watermark",
    "write_watermark",
    # file_lifecycle
    "FileValidator",
    "RejectWriter",
    "archive_file",
    "archive_glob",
    "lifecycle_from_config",
    "reject_path_for",
]
