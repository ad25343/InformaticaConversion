"""
ATM Transactions Fact Load
Converted from Informatica PowerCenter mapping: m_fct_atm_transactions_load

Purpose:
This script loads ATM transaction data from the operational OLTP system into 
a data warehouse fact table. It performs a straightforward extraction and load 
of ATM transaction records.

Source: OLTP.ATM_TRANSACTIONS (Oracle)
Target: DWH.FCT_ATM_TRANSACTIONS (Oracle)

Complexity: Low (single source to target, minimal transformations)
"""

import os
import sys
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path
from contextlib import contextmanager

import pandas as pd
import oracledb
import yaml


# ============================================================================
# CONFIGURATION
# ============================================================================

# Load configuration from YAML
CONFIG_PATH = Path(__file__).parent.parent / 'config' / 'mapping_config.yaml'
with open(CONFIG_PATH, 'r') as f:
    CONFIG = yaml.safe_load(f)

# Import connection configuration
sys.path.append(str(Path(__file__).parent.parent))
from config.db_connections import get_source_connection_config, get_target_connection_config


# ============================================================================
# LOGGING SETUP
# ============================================================================

class StructuredLogger:
    """Structured JSON logger for ETL processes."""
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, CONFIG['logging']['level']))
        
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(message)s'))
        self.logger.addHandler(handler)
    
    def log(self, level: str, message: str, **kwargs) -> None:
        """
        Log structured JSON message.
        Sanitizes all values to prevent log injection.
        """
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': level,
            'message': self._sanitize_for_log(message),
            'mapping': 'm_fct_atm_transactions_load'
        }
        
        # Sanitize all additional fields
        for key, value in kwargs.items():
            log_entry[key] = self._sanitize_for_log(str(value)) if value is not None else None
        
        log_method = getattr(self.logger, level.lower())
        log_method(json.dumps(log_entry))
    
    @staticmethod
    def _sanitize_for_log(value: str) -> str:
        """
        Sanitize string values to prevent log injection.
        Removes newlines and carriage returns.
        """
        if not isinstance(value, str):
            return value
        return value.replace('\n', '\\n').replace('\r', '\\r')


logger = StructuredLogger(__name__)


# ============================================================================
# RUNTIME PARAMETER VALIDATION
# ============================================================================

def validate_runtime_parameters() -> Dict[str, str]:
    """
    Validate required runtime parameters from environment variables.
    These parameters have no defaults and must fail loudly if missing.
    
    Returns:
        Dict containing validated runtime parameters
        
    Raises:
        ValueError: If required parameters are missing or invalid
    """
    etl_batch_id = os.environ.get('ETL_BATCH_ID')
    source_system_name = os.environ.get('SOURCE_SYSTEM_NAME')
    
    if not etl_batch_id:
        raise ValueError("ETL_BATCH_ID environment variable is required but not set")
    
    if not source_system_name:
        raise ValueError("SOURCE_SYSTEM_NAME environment variable is required but not set")
    
    # Validate ETL_BATCH_ID format (alphanumeric, hyphens, underscores only)
    if not all(c.isalnum() or c in '-_' for c in etl_batch_id):
        raise ValueError(
            f"ETL_BATCH_ID contains invalid characters. "
            f"Only alphanumeric, hyphens, and underscores allowed. "
            f"Received length: {len(etl_batch_id)}"
        )
    
    logger.log('info', 'Runtime parameters validated', 
               etl_batch_id=etl_batch_id,
               source_system=source_system_name)
    
    return {
        'etl_batch_id': etl_batch_id,
        'source_system_name': source_system_name
    }


# ============================================================================
# DATABASE CONNECTION MANAGEMENT
# ============================================================================

@contextmanager
def get_oracle_connection(config: Dict[str, Any]):
    """
    Context manager for Oracle database connections.
    Ensures proper connection cleanup.
    
    Args:
        config: Database connection configuration
        
    Yields:
        Oracle connection object
    """
    connection = None
    try:
        connection = oracledb.connect(
            user=config['user'],
            password=config['password'],
            host=config['host'],
            port=config['port'],
            service_name=config['service_name']
        )
        logger.log('info', 'Database connection established',
                   host=config['host'],
                   service=config['service_name'])
        yield connection
    except Exception as e:
        logger.log('error', f'Database connection failed: {str(e)}',
                   host=config['host'])
        raise
    finally:
        if connection:
            connection.close()
            logger.log('info', 'Database connection closed')


# ============================================================================
# DATA EXTRACTION
# ============================================================================

def extract_source_data(connection) -> pd.DataFrame:
    """
    Extract ATM transaction data from source OLTP system.
    Corresponds to: SQ_ATM_TRANSACTIONS (Source Qualifier)
    
    Business Logic:
    - Reads all records from OLTP.ATM_TRANSACTIONS table
    - No filtering or custom SQL applied
    - Fields extracted: TXN_ID, TXN_DATE, ACCOUNT_ID, ATM_ID, TXN_TYPE, 
      AMOUNT, STATUS, FEE_AMOUNT, CARD_LAST4
    
    Args:
        connection: Active Oracle database connection
        
    Returns:
        DataFrame containing source ATM transaction records
    """
    logger.log('info', 'Starting source data extraction',
               schema=CONFIG['source']['schema'],
               table=CONFIG['source']['table'])
    
    # Source Qualifier - standard SELECT with no filters or custom SQL
    query = f"""
        SELECT 
            TXN_ID,
            TXN_DATE,
            ACCOUNT_ID,
            ATM_ID,
            TXN_TYPE,
            AMOUNT,
            STATUS,
            FEE_AMOUNT,
            CARD_LAST4
        FROM {CONFIG['source']['schema']}.{CONFIG['source']['table']}
    """
    
    try:
        # Use chunked reading for memory efficiency
        df_chunks = pd.read_sql(
            query,
            connection,
            chunksize=CONFIG['processing']['chunk_size']
        )
        
        # Combine chunks
        df = pd.concat(df_chunks, ignore_index=True)
        
        row_count = len(df)
        logger.log('info', 'Source data extraction completed',
                   row_count=row_count,
                   schema=CONFIG['source']['schema'],
                   table=CONFIG['source']['table'])
        
        return df
        
    except Exception as e:
        logger.log('error', f'Source data extraction failed: {str(e)}')
        raise


# ============================================================================
# DATA TRANSFORMATION
# ============================================================================

def transform_atm_transactions(df: pd.DataFrame, runtime_params: Dict[str, str]) -> pd.DataFrame:
    """
    Apply transformation logic to ATM transaction data.
    Corresponds to: EXP_ATM_TRANSACTIONS (Expression Transformation)
    
    Business Logic:
    - Pass-through transformation for all source fields
    - Add standard DW audit fields (DW_INSERT_DT, DW_UPDATE_DT, ETL_BATCH_ID, ETL_SOURCE)
    
    Note: Original Informatica Expression transformation metadata did not contain
    detailed transformation expressions. This implements pass-through logic with
    standard audit field population.
    
    Args:
        df: Source DataFrame from extraction
        runtime_params: Runtime parameters (ETL_BATCH_ID, SOURCE_SYSTEM_NAME)
        
    Returns:
        Transformed DataFrame ready for load
    """
    logger.log('info', 'Starting transformation',
               input_row_count=len(df))
    
    # Create output DataFrame with all source fields
    df_transformed = df.copy()
    
    # Standard DW audit fields - populated for all target records
    current_timestamp = pd.Timestamp.now()
    
    # DW_INSERT_DT - timestamp when record was first inserted
    df_transformed['DW_INSERT_DT'] = current_timestamp
    
    # DW_UPDATE_DT - timestamp when record was last updated
    df_transformed['DW_UPDATE_DT'] = current_timestamp
    
    # ETL_BATCH_ID - batch identifier for this ETL run
    df_transformed['ETL_BATCH_ID'] = runtime_params['etl_batch_id']
    
    # ETL_SOURCE - source system identifier
    df_transformed['ETL_SOURCE'] = runtime_params['source_system_name']
    
    logger.log('info', 'Transformation completed',
               output_row_count=len(df_transformed))
    
    return df_transformed


# ============================================================================
# DATA LOADING
# ============================================================================

def load_target_data(df: pd.DataFrame, connection) -> int:
    """
    Load transformed ATM transaction data to target fact table.
    Corresponds to: FCT_ATM_TRANSACTIONS (Target Definition)
    
    Business Logic:
    - Loads data to DWH.FCT_ATM_TRANSACTIONS table
    - Uses INSERT operation (standard fact table load pattern)
    - Target fields: TXN_ID, TXN_DATE, ACCOUNT_ID, ATM_ID, TXN_TYPE,
      AMOUNT, STATUS, FEE_AMOUNT, CARD_LAST4, DW_INSERT_DT, DW_UPDATE_DT,
      ETL_BATCH_ID, ETL_SOURCE
    
    Args:
        df: Transformed DataFrame to load
        connection: Active Oracle database connection
        
    Returns:
        Number of rows loaded
    """
    logger.log('info', 'Starting target data load',
               row_count=len(df),
               schema=CONFIG['target']['schema'],
               table=CONFIG['target']['table'])
    
    if df.empty:
        logger.log('warning', 'No data to load - DataFrame is empty')
        return 0
    
    # Prepare parameterized INSERT statement
    # TODO [AUTO-FLAG]: LINEAGE GAP — Only TXN_ID field has visible lineage from source to target.
    # All other target table fields (if any exist) have no documented source in the mapping graph.
    # This implementation includes all source fields plus standard audit fields based on
    # common DW patterns. Verify target table structure manually in Informatica mapping.
    
    insert_sql = f"""
        INSERT INTO {CONFIG['target']['schema']}.{CONFIG['target']['table']} (
            TXN_ID,
            TXN_DATE,
            ACCOUNT_ID,
            ATM_ID,
            TXN_TYPE,
            AMOUNT,
            STATUS,
            FEE_AMOUNT,
            CARD_LAST4,
            DW_INSERT_DT,
            DW_UPDATE_DT,
            ETL_BATCH_ID,
            ETL_SOURCE
        ) VALUES (
            :1, :2, :3, :4, :5, :6, :7, :8, :9, :10, :11, :12, :13
        )
    """
    
    try:
        cursor = connection.cursor()
        
        # Prepare data for batch insert
        records = df[[
            'TXN_ID', 'TXN_DATE', 'ACCOUNT_ID', 'ATM_ID', 'TXN_TYPE',
            'AMOUNT', 'STATUS', 'FEE_AMOUNT', 'CARD_LAST4',
            'DW_INSERT_DT', 'DW_UPDATE_DT', 'ETL_BATCH_ID', 'ETL_SOURCE'
        ]].values.tolist()
        
        # Execute batch insert using parameterized query
        cursor.executemany(insert_sql, records)
        connection.commit()
        
        rows_loaded = cursor.rowcount
        cursor.close()
        
        logger.log('info', 'Target data load completed',
                   rows_loaded=rows_loaded,
                   schema=CONFIG['target']['schema'],
                   table=CONFIG['target']['table'])
        
        return rows_loaded
        
    except Exception as e:
        connection.rollback()
        logger.log('error', f'Target data load failed: {str(e)}')
        raise


# ============================================================================
# MAIN ORCHESTRATION
# ============================================================================

def main() -> int:
    """
    Main orchestration function for ATM transactions fact load.
    
    Returns:
        0 for success, 1 for failure
    """
    start_time = datetime.utcnow()
    
    logger.log('info', 'Job started',
               mapping='m_fct_atm_transactions_load',
               start_time=start_time.isoformat())
    
    try:
        # Validate runtime parameters
        runtime_params = validate_runtime_parameters()
        
        # Get database connection configurations
        source_config = get_source_connection_config()
        target_config = get_target_connection_config()
        
        # Extract data from source
        with get_oracle_connection(source_config) as source_conn:
            df_source = extract_source_data(source_conn)
        
        # Transform data
        df_transformed = transform_atm_transactions(df_source, runtime_params)
        
        # Load data to target
        with get_oracle_connection(target_config) as target_conn:
            rows_loaded = load_target_data(df_transformed, target_conn)
        
        # Job completion
        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds()
        
        logger.log('info', 'Job completed successfully',
                   mapping='m_fct_atm_transactions_load',
                   start_time=start_time.isoformat(),
                   end_time=end_time.isoformat(),
                   duration_seconds=duration,
                   rows_processed=len(df_source),
                   rows_loaded=rows_loaded)
        
        return 0
        
    except Exception as e:
        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds()
        
        logger.log('error', 'Job failed',
                   mapping='m_fct_atm_transactions_load',
                   error=str(e),
                   start_time=start_time.isoformat(),
                   end_time=end_time.isoformat(),
                   duration_seconds=duration)
        
        return 1


if __name__ == '__main__':
    sys.exit(main())