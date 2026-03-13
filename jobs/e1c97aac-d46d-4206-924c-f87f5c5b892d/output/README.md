# ATM Transactions Fact Load - m_fct_atm_transactions_load

## Overview

This ETL process loads ATM transaction data from the operational OLTP system into the data warehouse fact table `FCT_ATM_TRANSACTIONS`.

**Source:** OLTP.ATM_TRANSACTIONS (Oracle)  
**Target:** DWH.FCT_ATM_TRANSACTIONS (Oracle)  
**Complexity:** Low (single source-to-target with minimal transformation)

## Transformation Flow

1. **SQ_ATM_TRANSACTIONS** - Extract all ATM transaction records from source
2. **EXP_ATM_TRANSACTIONS** - Apply field-level transformations (pass-through)
3. **FCT_ATM_TRANSACTIONS** - Load transformed data to target fact table

## Required Environment Variables

### Source Connection (OLTP_ORACLE)
```bash
export OLTP_ORACLE_USER=<username>
export OLTP_ORACLE_PASSWORD=<password>
export OLTP_ORACLE_HOST=<hostname>
export OLTP_ORACLE_PORT=2484
export OLTP_ORACLE_SERVICE=<service_name>
```

### Target Connection (DWH_ORACLE)
```bash
export DWH_ORACLE_USER=<username>
export DWH_ORACLE_PASSWORD=<password>
export DWH_ORACLE_HOST=<hostname>
export DWH_ORACLE_PORT=2484
export DWH_ORACLE_SERVICE=<service_name>
```

### ETL Parameters
```bash
export ETL_BATCH_ID=<batch_identifier>
```

## Security Notes

- **TCPS Protocol**: All Oracle connections must use TCPS (TLS-encrypted) protocol on port 2484
- **Credential Management**: All credentials sourced from environment variables only - no hardcoded values
- **SSL/TLS Configuration**: Ensure Oracle wallet is configured with proper CA certificates
- **TNS Configuration**: Set `TNS_ADMIN` environment variable to point to wallet location

## Installation

### Prerequisites
- Python 3.8+
- Oracle Instant Client 19c or later
- Oracle Wallet configured for TCPS connections

### Setup
```bash
# Install Python dependencies
pip install -r requirements.txt

# Set TNS_ADMIN for Oracle wallet
export TNS_ADMIN=/path/to/oracle/wallet

# Verify Oracle Instant Client installation
python -c "import cx_Oracle; print(cx_Oracle.version)"
```

## Usage

```bash
# Set all required environment variables first
source set_env_vars.sh

# Run the ETL process
python src/extract_atm_transactions.py
```

## Output

The script outputs structured JSON logs to stdout with execution statistics:

```json
{
  "status": "SUCCESS",
  "rows_extracted": 15000,
  "rows_transformed": 15000,
  "rows_loaded": 15000,
  "duration_seconds": 45.32,
  "etl_batch_id": "20240115_120000",
  "start_time": "2024-01-15T12:00:00.000000",
  "end_time": "2024-01-15T12:00:45.320000"
}
```

## Verification Flags Applied

**[LINEAGE_GAP]**: Only `TXN_ID` field has fully documented lineage from source to target. All other target fields are mapped based on input port documentation. If the target table contains additional unmapped columns, they will receive NULL values. Verify target table structure manually against the Informatica mapping.

## Standard DW Audit Fields

The following audit fields are automatically populated for all target records:

- `DW_INSERT_DT`: Current timestamp at load time
- `DW_UPDATE_DT`: Current timestamp at load time
- `ETL_BATCH_ID`: From `ETL_BATCH_ID` environment variable
- `ETL_SOURCE`: Set to 'OLTP_ATM_SYSTEM' (configured value)

## Error Handling

- Database connection failures: Logged with full error details, job exits with code 1
- Missing environment variables: Validation error raised at job start
- Empty source data: Warning logged, job completes successfully with 0 rows loaded
- Target load failures: Transaction rolled back, error logged, job exits with code 1

## Logging

All log entries are structured JSON with the following fields:
- `timestamp`: ISO-8601 UTC timestamp
- `level`: Log level (INFO, WARNING, ERROR)
- `message`: Human-readable message
- `step`: Current transformation step
- `row_count`: Number of rows processed (where applicable)

## Configuration

Edit `config/mapping_config.yaml` to modify:
- Source/target connection names
- Schema and table names
- Processing parameters (chunk size, dtype backend)
- Logging configuration
- Audit field mappings

## Monitoring

Key metrics to monitor:
- Row counts at each step (should remain consistent for this pass-through mapping)
- Execution duration (baseline ~3-5 seconds per 10,000 rows)
- NULL values in `TXN_ID` (should be 0 - indicates data quality issues)
- Database connection errors (indicates network or credential issues)

## Known Limitations

1. **Expression Logic Ambiguity**: The Informatica metadata does not include detailed expression definitions for `EXP_ATM_TRANSACTIONS`. The current implementation assumes pass-through logic. If business transformations exist in the original mapping, they must be added manually.

2. **Target Table Structure**: Only the documented input ports are mapped. If the target table contains additional columns not present in the source mapping documentation, they will receive NULL values unless explicitly handled.

3. **Incremental Loading**: This mapping implements a simple INSERT pattern. For incremental loads with change detection, additional logic (e.g., CDC, high-water mark) must be implemented separately.

## Troubleshooting

**cx_Oracle.DatabaseError: ORA-12170: TNS:Connect timeout occurred**
- Verify TCPS port 2484 is accessible
- Check firewall rules
- Confirm Oracle wallet is properly configured

**ValueError: Required environment variable not set: ETL_BATCH_ID**
- Ensure all required environment variables are exported
- Use `env | grep ORACLE` and `env | grep ETL` to verify

**ORA-00942: table or view does not exist**
- Verify schema and table names in config/mapping_config.yaml
- Confirm database user has SELECT/INSERT privileges
- Check that you're connecting to the correct Oracle instance

## Maintenance

- **Credential Rotation**: Update environment variables; no code changes required
- **Schema Changes**: Update config/mapping_config.yaml and verify field mappings
- **Performance Tuning**: Adjust `chunk_size` in config for memory vs. speed tradeoff