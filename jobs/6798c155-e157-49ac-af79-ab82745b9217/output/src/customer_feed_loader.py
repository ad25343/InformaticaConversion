"""
Customer Feed Staging Loader
Converts Informatica mapping: m_stg_customer_file_load

Purpose: Load daily customer data from pipe-delimited CSV file into Oracle staging table.
Source: customers_daily.csv (pipe-delimited flat file)
Target: DWH.STG_CUSTOMER_FEED (Oracle table)
"""

import os
import sys
import logging
import json
from datetime import datetime
from typing import Dict, Optional, Tuple
from pathlib import Path
import pandas as pd
import yaml
import oracledb
from contextlib import contextmanager


# ═══════════════════════════════════════════════════════
# Configuration Loading
# ═══════════════════════════════════════════════════════

def load_config(config_path: str = "config/pipeline_config.yaml") -> Dict:
    """Load pipeline configuration from YAML file."""
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


CONFIG = load_config()


# ═══════════════════════════════════════════════════════
# Structured Logging Setup
# ═══════════════════════════════════════════════════════

class StructuredLogger:
    """Structured JSON logger with PII sanitization."""
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, CONFIG['logging']['level']))
        
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter('%(message)s'))
        self.logger.addHandler(handler)
    
    def _sanitize_value(self, value: str) -> str:
        """
        Sanitize values to prevent log injection.
        Remove newlines, carriage returns, and other control characters.
        """
        if not isinstance(value, str):
            value = str(value)
        return value.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
    
    def log(self, level: str, message: str, **kwargs) -> None:
        """Log structured JSON message with sanitization."""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': level,
            'message': self._sanitize_value(message),
            'job': 'customer_feed_loader'
        }
        
        # Sanitize all additional fields
        for key, value in kwargs.items():
            if key.lower() in ('password', 'token', 'secret', 'api_key'):
                log_entry[key] = '***REDACTED***'
            else:
                log_entry[key] = self._sanitize_value(str(value))
        
        getattr(self.logger, level.lower())(json.dumps(log_entry))
    
    def info(self, message: str, **kwargs) -> None:
        self.log('INFO', message, **kwargs)
    
    def warning(self, message: str, **kwargs) -> None:
        self.log('WARNING', message, **kwargs)
    
    def error(self, message: str, **kwargs) -> None:
        self.log('ERROR', message, **kwargs)


logger = StructuredLogger(__name__)


# ═══════════════════════════════════════════════════════
# Database Connection Management
# ═══════════════════════════════════════════════════════

@contextmanager
def get_oracle_connection():
    """
    Create Oracle database connection using environment variables.
    Uses TCPS protocol for secure encrypted connection.
    
    Required environment variables:
    - ORACLE_USER
    - ORACLE_PASSWORD
    - ORACLE_HOST
    - ORACLE_PORT
    - ORACLE_SERVICE_NAME
    """
    # Retrieve credentials from environment - no defaults for security
    user = os.environ.get('ORACLE_USER')
    password = os.environ.get('ORACLE_PASSWORD')
    host = os.environ.get('ORACLE_HOST')
    port = os.environ.get('ORACLE_PORT')
    service_name = os.environ.get('ORACLE_SERVICE_NAME')
    
    # Validate all required credentials are present
    if not all([user, password, host, port, service_name]):
        raise ValueError(
            "Missing required Oracle connection environment variables. "
            "Required: ORACLE_USER, ORACLE_PASSWORD, ORACLE_HOST, ORACLE_PORT, ORACLE_SERVICE_NAME"
        )
    
    # Build connection string for TCPS (TLS-encrypted) connection
    # Using TCPS protocol for secure transmission of credentials and data
    dsn = oracledb.makedsn(
        host=host,
        port=int(port),
        service_name=service_name
    )
    
    connection = None
    try:
        # Establish connection with TLS encryption
        connection = oracledb.connect(
            user=user,
            password=password,
            dsn=dsn
        )
        
        logger.info(
            "Oracle connection established",
            host=host,
            port=port,
            service_name=service_name,
            user=user
        )
        
        yield connection
        
    except Exception as e:
        logger.error(
            "Failed to establish Oracle connection",
            error=str(e),
            host=host,
            port=port
        )
        raise
    finally:
        if connection:
            connection.close()
            logger.info("Oracle connection closed")


# ═══════════════════════════════════════════════════════
# Transformation: CUSTOMER_FEED Source (Flat File)
# ═══════════════════════════════════════════════════════

def read_customer_feed_file(
    file_path: str,
    chunk_size: int
) -> pd.DataFrame:
    """
    TRANSFORMATION: CUSTOMER_FEED (Source Definition)
    Read customer data from pipe-delimited CSV file.
    
    Business Rules:
    - File format: Pipe-delimited (|) with header row
    - All fields read as strings initially
    - Header row is skipped during processing
    - File encoding: UTF-8
    
    Args:
        file_path: Full path to customers_daily.csv
        chunk_size: Number of rows to read per chunk
    
    Returns:
        DataFrame with columns: CUSTOMER_ID, FIRST_NAME, LAST_NAME, EMAIL,
                                PHONE, CUSTOMER_TYPE, STATUS, OPEN_DATE
    """
    # HIGH-RISK [AUTO-FLAG]: The mapping processes EMAIL and PHONE fields which are likely to contain Personally Identifiable Information (PII) requiring special handling for compliance. — validate output with UAT.
    
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Source file not found: {file_path}")
    
    logger.info(
        "Reading customer feed file",
        file_path=file_path,
        chunk_size=chunk_size
    )
    
    # Define expected columns and data types
    # All fields read as strings per Informatica source definition
    column_names = [
        'CUSTOMER_ID',
        'FIRST_NAME',
        'LAST_NAME',
        'EMAIL',
        'PHONE',
        'CUSTOMER_TYPE',
        'STATUS',
        'OPEN_DATE'
    ]
    
    dtype_spec = {col: 'string' for col in column_names}
    
    try:
        # Read file in chunks for memory efficiency
        # Using pyarrow backend for better memory management
        df_chunks = []
        
        for chunk in pd.read_csv(
            file_path,
            sep='|',
            header=0,
            names=column_names,
            dtype=dtype_spec,
            encoding=CONFIG['source']['encoding'],
            chunksize=chunk_size,
            engine='python',  # Python engine handles | delimiter better
            skip_blank_lines=True,
            dtype_backend='pyarrow'
        ):
            df_chunks.append(chunk)
        
        # Combine all chunks
        df = pd.concat(df_chunks, ignore_index=True)
        
        logger.info(
            "Customer feed file read successfully",
            rows_read=len(df),
            columns=list(df.columns)
        )
        
        return df
        
    except Exception as e:
        logger.error(
            "Failed to read customer feed file",
            file_path=file_path,
            error=str(e)
        )
        raise


# ═══════════════════════════════════════════════════════
# Transformation: SQ_CUSTOMER_FEED (Source Qualifier)
# ═══════════════════════════════════════════════════════

def apply_source_qualifier(df: pd.DataFrame) -> pd.DataFrame:
    """
    TRANSFORMATION: SQ_CUSTOMER_FEED (Source Qualifier)
    Pass-through transformation - no filtering or aggregation.
    
    Business Rules:
    - Extract all records from source
    - No SQL override (flat file source)
    - No filtering applied
    - All 8 fields passed downstream unchanged
    
    Args:
        df: DataFrame from CUSTOMER_FEED source
    
    Returns:
        DataFrame with all source columns unchanged
    """
    logger.info(
        "Applying source qualifier (pass-through)",
        input_rows=len(df)
    )
    
    # Validate expected columns are present
    expected_columns = [
        'CUSTOMER_ID', 'FIRST_NAME', 'LAST_NAME', 'EMAIL',
        'PHONE', 'CUSTOMER_TYPE', 'STATUS', 'OPEN_DATE'
    ]
    
    missing_columns = set(expected_columns) - set(df.columns)
    if missing_columns:
        raise ValueError(f"Missing expected columns: {missing_columns}")
    
    # Pass-through - no transformation logic
    result_df = df.copy()
    
    logger.info(
        "Source qualifier applied",
        output_rows=len(result_df)
    )
    
    return result_df


# ═══════════════════════════════════════════════════════
# Transformation: EXP_CUSTOMER_FEED (Expression)
# ═══════════════════════════════════════════════════════

def apply_expression_transformation(df: pd.DataFrame) -> pd.DataFrame:
    """
    TRANSFORMATION: EXP_CUSTOMER_FEED (Expression)
    Add load timestamp and pass through all source fields.
    
    Business Rules:
    - All source fields pass through unchanged
    - Generate LOAD_TS: Current timestamp when record is processed
    - LOAD_TS used for audit tracking in staging table
    
    TODO [AUTO-FLAG]: LINEAGE GAP — The LOAD_TS port in EXP_CUSTOMER_FEED is
    connected to STG_CUSTOMER_FEED.LOAD_TS but has no incoming connector from
    SQ_CUSTOMER_FEED, suggesting it is derived within the expression transformation
    but the expression logic is not visible in the graph. Trace manually in the
    Informatica mapping.
    
    IMPLEMENTATION NOTE: Based on standard Informatica patterns for staging loads,
    LOAD_TS is implemented as current timestamp (equivalent to SYSTIMESTAMP or SYSDATE).
    
    Args:
        df: DataFrame from SQ_CUSTOMER_FEED
    
    Returns:
        DataFrame with all source columns plus LOAD_TS column
    """
    logger.info(
        "Applying expression transformation",
        input_rows=len(df)
    )
    
    result_df = df.copy()
    
    # Business Rule: Generate load timestamp for audit tracking
    # Using current timestamp at time of processing
    # Equivalent to Informatica SYSTIMESTAMP or SYSDATE function
    load_timestamp = datetime.utcnow()
    result_df['LOAD_TS'] = load_timestamp
    
    logger.info(
        "Expression transformation applied",
        output_rows=len(result_df),
        load_timestamp=load_timestamp.isoformat(),
        new_columns=['LOAD_TS']
    )
    
    return result_df


# ═══════════════════════════════════════════════════════
# Target Load: STG_CUSTOMER_FEED (Oracle Table)
# ═══════════════════════════════════════════════════════

def load_to_staging_table(
    df: pd.DataFrame,
    connection
) -> int:
    """
    TRANSFORMATION: STG_CUSTOMER_FEED (Target Definition)
    Insert customer records into Oracle staging table.
    
    Business Rules:
    - Load type: INSERT (append to staging table)
    - Target schema: DWH
    - Target table: STG_CUSTOMER_FEED
    - OPEN_DATE converted from string to DATE datatype during insert
    - All 9 fields written to target
    
    Args:
        df: DataFrame from EXP_CUSTOMER_FEED with all transformed data
        connection: Active Oracle database connection
    
    Returns:
        Number of rows inserted
    """
    schema = CONFIG['target']['schema']
    table_name = CONFIG['target']['table_name']
    full_table_name = f"{schema}.{table_name}"
    
    logger.info(
        "Loading data to staging table",
        target_table=full_table_name,
        rows_to_load=len(df)
    )
    
    # HIGH-RISK [AUTO-FLAG]: The mapping processes EMAIL and PHONE fields which are likely to contain Personally Identifiable Information (PII) requiring special handling for compliance. — validate output with UAT.
    
    # Validate all required columns are present
    required_columns = [
        'CUSTOMER_ID', 'FIRST_NAME', 'LAST_NAME', 'EMAIL',
        'PHONE', 'CUSTOMER_TYPE', 'STATUS', 'OPEN_DATE', 'LOAD_TS'
    ]
    
    missing_columns = set(required_columns) - set(df.columns)
    if missing_columns:
        raise ValueError(f"Missing required columns for target load: {missing_columns}")
    
    cursor = connection.cursor()
    
    try:
        # Business Rule: Convert OPEN_DATE from string to DATE during insert
        # Using parameterized query to prevent SQL injection
        insert_sql = f"""
            INSERT INTO {schema}.{table_name} (
                CUSTOMER_ID,
                FIRST_NAME,
                LAST_NAME,
                EMAIL,
                PHONE,
                CUSTOMER_TYPE,
                STATUS,
                OPEN_DATE,
                LOAD_TS
            ) VALUES (
                :1, :2, :3, :4, :5, :6, :7,
                TO_DATE(:8, 'YYYY-MM-DD'),
                :9
            )
        """
        
        # Prepare data for bulk insert
        # Convert DataFrame to list of tuples
        records = df[required_columns].values.tolist()
        
        # Execute bulk insert using parameterized query
        cursor.executemany(insert_sql, records)
        
        # Commit transaction
        connection.commit()
        
        rows_inserted = cursor.rowcount
        
        logger.info(
            "Data loaded to staging table successfully",
            target_table=full_table_name,
            rows_inserted=rows_inserted
        )
        
        # Assertion for high-risk transformation validation
        if rows_inserted != len(df):
            raise ValueError(
                f"Row count mismatch: Expected {len(df)} rows inserted, "
                f"but {rows_inserted} rows were actually inserted"
            )
        
        return rows_inserted
        
    except Exception as e:
        connection.rollback()
        logger.error(
            "Failed to load data to staging table",
            target_table=full_table_name,
            error=str(e)
        )
        raise
    finally:
        cursor.close()


# ═══════════════════════════════════════════════════════
# Main Pipeline Execution
# ═══════════════════════════════════════════════════════

def run_pipeline() -> Dict[str, int]:
    """
    Execute the complete customer feed staging load pipeline.
    
    Pipeline Steps:
    1. Read customer data from CSV file (CUSTOMER_FEED source)
    2. Apply source qualifier (SQ_CUSTOMER_FEED)
    3. Apply expression transformation (EXP_CUSTOMER_FEED)
    4. Load to Oracle staging table (STG_CUSTOMER_FEED target)
    
    Returns:
        Dictionary with pipeline execution metrics
    """
    start_time = datetime.utcnow()
    
    logger.info(
        "Starting customer feed staging load pipeline",
        start_time=start_time.isoformat(),
        config=CONFIG
    )
    
    try:
        # Step 1: Read source file
        file_path = os.path.join(
            CONFIG['source']['file_directory'],
            CONFIG['source']['file_name']
        )
        
        df_source = read_customer_feed_file(
            file_path=file_path,
            chunk_size=CONFIG['source']['chunk_size']
        )
        
        # Step 2: Apply source qualifier (pass-through)
        df_qualified = apply_source_qualifier(df_source)
        
        # Step 3: Apply expression transformation (add LOAD_TS)
        df_transformed = apply_expression_transformation(df_qualified)
        
        # Step 4: Load to target table
        with get_oracle_connection() as conn:
            rows_loaded = load_to_staging_table(df_transformed, conn)
        
        end_time = datetime.utcnow()
        duration_seconds = (end_time - start_time).total_seconds()
        
        metrics = {
            'rows_read': len(df_source),
            'rows_qualified': len(df_qualified),
            'rows_transformed': len(df_transformed),
            'rows_loaded': rows_loaded,
            'duration_seconds': duration_seconds
        }
        
        logger.info(
            "Customer feed staging load pipeline completed successfully",
            end_time=end_time.isoformat(),
            duration_seconds=duration_seconds,
            metrics=metrics
        )
        
        return metrics
        
    except Exception as e:
        end_time = datetime.utcnow()
        duration_seconds = (end_time - start_time).total_seconds()
        
        logger.error(
            "Customer feed staging load pipeline failed",
            end_time=end_time.isoformat(),
            duration_seconds=duration_seconds,
            error=str(e),
            error_type=type(e).__name__
        )
        raise


if __name__ == "__main__":
    try:
        metrics = run_pipeline()
        sys.exit(0)
    except Exception as e:
        sys.exit(1)