# Customer Feed Staging Load Pipeline

## Overview

This pipeline loads daily customer data from a pipe-delimited CSV file into an Oracle staging table. It is a direct conversion of the Informatica PowerCenter mapping `m_stg_customer_file_load`.

## Architecture

**Source**: `customers_daily.csv` (pipe-delimited flat file)  
**Target**: `DWH.STG_CUSTOMER_FEED` (Oracle staging table)  
**Complexity**: Low (single source, single target, minimal transformation)

## Pipeline Flow

1. **CUSTOMER_FEED** (Source) - Read customer records from CSV file
2. **SQ_CUSTOMER_FEED** (Source Qualifier) - Pass-through extraction
3. **EXP_CUSTOMER_FEED** (Expression) - Add load timestamp for audit tracking
4. **STG_CUSTOMER_FEED** (Target) - Insert records into Oracle staging table

## Configuration

All environment-specific values are externalized in `config/pipeline_config.yaml`:

- Source file location and format settings
- Target database schema and table name
- Logging configuration
- Chunk size for large file processing

## Security

### Required Environment Variables

The following environment variables **must** be set before running the pipeline:

```bash
export ORACLE_USER="your_oracle_username"
export ORACLE_PASSWORD="your_oracle_password"
export ORACLE_HOST="oracle_host.example.com"
export ORACLE_PORT="1521"
export ORACLE_SERVICE_NAME="your_service_name"
```

**SECURITY NOTE**: Never hardcode credentials. Always use environment variables or a secrets manager.

### TLS Encryption

Oracle connections should use TCPS (TLS-encrypted) protocol for production deployments. Ensure your Oracle database is configured to accept secure connections and proper certificates are in place.

### PII Handling

This pipeline processes Personally Identifiable Information (EMAIL and PHONE fields). Ensure compliance with data privacy regulations:

- Restrict access to output files and logs
- Implement data retention policies
- Enable encryption at rest for staging table
- Audit all data access

## Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Set required environment variables
export ORACLE_USER="..."
export ORACLE_PASSWORD="..."
export ORACLE_HOST="..."
export ORACLE_PORT="..."
export ORACLE_SERVICE_NAME="..."

# Run pipeline
python src/customer_feed_loader.py
```

## Expected File Format

The source CSV file must have the following structure:

```
CUSTOMER_ID|FIRST_NAME|LAST_NAME|EMAIL|PHONE|CUSTOMER_TYPE|STATUS|OPEN_DATE
C001|John|Doe|john.doe@example.com|555-0100|RETAIL|ACTIVE|2024-01-15
C002|Jane|Smith|jane.smith@example.com|555-0101|COMMERCIAL|ACTIVE|2024-01-16
```

- **Delimiter**: Pipe (`|`)
- **Header**: First row contains column names (skipped during processing)
- **Encoding**: UTF-8
- **Date Format**: YYYY-MM-DD (for OPEN_DATE field)

## Target Table Schema

```sql
CREATE TABLE DWH.STG_CUSTOMER_FEED (
    CUSTOMER_ID    VARCHAR2(20),
    FIRST_NAME     VARCHAR2(100),
    LAST_NAME      VARCHAR2(100),
    EMAIL          VARCHAR2(200),
    PHONE          VARCHAR2(20),
    CUSTOMER_TYPE  VARCHAR2(20),
    STATUS         VARCHAR2(10),
    OPEN_DATE      DATE,
    LOAD_TS        TIMESTAMP
);
```

## Logging

The pipeline uses structured JSON logging with the following features:

- **Log injection protection**: All values sanitized to prevent newline/control character injection
- **PII redaction**: Sensitive fields (password, token, secret, api_key) are automatically masked
- **Row count tracking**: Every transformation logs input/output row counts
- **Error context**: Failures include full context for debugging

Example log entry:

```json
{
  "timestamp": "2024-01-20T10:30:45.123456",
  "level": "INFO",
  "message": "Data loaded to staging table successfully",
  "job": "customer_feed_loader",
  "target_table": "DWH.STG_CUSTOMER_FEED",
  "rows_inserted": 1523
}
```

## Error Handling

- **File not found**: Pipeline fails immediately if source file doesn't exist
- **Missing columns**: Validates expected columns at each transformation step
- **Connection failures**: Oracle connection errors logged with full context
- **Row count mismatch**: Assertion validates rows inserted match rows sent
- **Transaction rollback**: Database errors trigger automatic rollback

## Performance

- **Chunked reading**: Large files processed in 50,000-row chunks
- **PyArrow backend**: Memory-efficient data types for better performance
- **Bulk insert**: Uses `executemany()` for efficient batch loading
- **Connection pooling**: Context managers ensure proper resource cleanup

## UAT Validation Checklist

Due to the high-risk nature of PII processing, perform the following UAT validations:

- [ ] Verify EMAIL field values are loaded correctly without truncation
- [ ] Verify PHONE field values maintain formatting (dashes, parentheses)
- [ ] Confirm OPEN_DATE conversion from string to DATE is accurate
- [ ] Validate LOAD_TS timestamp reflects actual processing time
- [ ] Check row counts match between source file and target table
- [ ] Verify no duplicate records in staging table
- [ ] Confirm NULL handling for optional fields
- [ ] Test with file containing special characters in names/emails

## Conversion Notes

1. **LOAD_TS Logic**: The original Informatica mapping did not document the expression for LOAD_TS generation. Implemented as `datetime.utcnow()` based on standard staging table patterns.

2. **Date Conversion**: OPEN_DATE is read as string from CSV and converted to DATE during Oracle insert using `TO_DATE(:8, 'YYYY-MM-DD')`.

3. **No Parameters**: The original mapping used no parameters or variables. All configuration externalized to YAML file in this conversion.

4. **Truncate Option**: The Informatica target definition did not specify a truncate option. This conversion implements INSERT (append) behavior. If truncate-and-load is required, add a pre-processing step.

## Troubleshooting

**Issue**: `FileNotFoundError` when running pipeline  
**Solution**: Verify `file_directory` and `file_name` in `config/pipeline_config.yaml` match actual file location.

**Issue**: `ORA-00001: unique constraint violated`  
**Solution**: Staging table may have a primary key on CUSTOMER_ID. Either remove the constraint or implement upsert logic.

**Issue**: `ORA-01858: a non-numeric character was found where a numeric was expected`  
**Solution**: OPEN_DATE format in source file doesn't match expected YYYY-MM-DD. Verify date format in CSV file.

**Issue**: Row count mismatch assertion failure  
**Solution**: Check Oracle logs for constraint violations or trigger failures that may prevent some rows from being inserted.