# ATM Transactions Fact Load

Converted from Informatica PowerCenter mapping: `m_fct_atm_transactions_load`

## Overview

This ETL job loads ATM transaction data from the operational OLTP system into a data warehouse fact table. It performs a straightforward extraction and load of ATM transaction records including transaction identifiers, dates, account information, ATM locations, transaction types, amounts, status, fees, and masked card numbers.

**Complexity:** Low (single source to target, minimal transformations)

## Source and Target

- **Source:** `OLTP.ATM_TRANSACTIONS` (Oracle)
- **Target:** `DWH.FCT_ATM_TRANSACTIONS` (Oracle)

## Required Environment Variables

### Database Connections

**Source (OLTP):**
- `SOURCE_ORACLE_HOST` - Source Oracle database host
- `SOURCE_ORACLE_PORT` - Source Oracle database port
- `SOURCE_ORACLE_SERVICE` - Source Oracle service name
- `SOURCE_ORACLE_USER` - Source database username
- `SOURCE_ORACLE_PASSWORD` - Source database password (use secrets manager)

**Target (DWH):**
- `TARGET_ORACLE_HOST` - Target Oracle database host
- `TARGET_ORACLE_PORT` - Target Oracle database port
- `TARGET_ORACLE_SERVICE` - Target Oracle service name
- `TARGET_ORACLE_USER` - Target database username
- `TARGET_ORACLE_PASSWORD` - Target database password (use secrets manager)

### Runtime Parameters

- `ETL_BATCH_ID` - Unique identifier for this ETL batch run (required, no default)
- `SOURCE_SYSTEM_NAME` - Source system identifier (required, no default)

## Security

- All database connections use TCPS (TLS-encrypted) protocol with certificate validation
- All credentials sourced from environment variables - never hardcoded
- Parameterized SQL queries prevent SQL injection
- Log sanitization prevents log injection attacks
- No sensitive data logged

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Set required environment variables
export ETL_BATCH_ID="20240115_120000"
export SOURCE_SYSTEM_NAME="OLTP_PROD"
export SOURCE_ORACLE_HOST="source-db.example.com"
export SOURCE_ORACLE_PORT="2484"
export SOURCE_ORACLE_SERVICE="OLTP"
export SOURCE_ORACLE_USER="etl_user"
export SOURCE_ORACLE_PASSWORD="$(aws secretsmanager get-secret-value --secret-id oltp-password --query SecretString --output text)"
export TARGET_ORACLE_HOST="dwh-db.example.com"
export TARGET_ORACLE_PORT="2484"
export TARGET_ORACLE_SERVICE="DWH"
export TARGET_ORACLE_USER="etl_user"
export TARGET_ORACLE_PASSWORD="$(aws secretsmanager get-secret-value --secret-id dwh-password --query SecretString --output text)"

# Run the job
python src/m_fct_atm_transactions_load.py
```

## Data Flow

1. **Extract** - Read ATM transaction records from `OLTP.ATM_TRANSACTIONS`
2. **Transform** - Apply pass-through transformation and add DW audit fields
3. **Load** - Insert records into `DWH.FCT_ATM_TRANSACTIONS`

## Transformations

- **Source Qualifier (SQ_ATM_TRANSACTIONS):** Standard extraction with no filters
- **Expression (EXP_ATM_TRANSACTIONS):** Pass-through with audit field population
  - Adds `DW_INSERT_DT` (current timestamp)
  - Adds `DW_UPDATE_DT` (current timestamp)
  - Adds `ETL_BATCH_ID` (from runtime parameter)
  - Adds `ETL_SOURCE` (from runtime parameter)

## Logging

All log messages are output in structured JSON format with the following fields:
- `timestamp` - UTC timestamp
- `level` - Log level (INFO, WARNING, ERROR)
- `message` - Log message
- `mapping` - Mapping name
- Additional context fields (row counts, durations, etc.)

## Known Issues / Manual Verification Required

- **[LINEAGE GAP]** The Informatica mapping metadata only documents lineage for the `TXN_ID` field. All other target table fields have been included based on common DW patterns and source field availability. Verify the complete target table structure in the original Informatica mapping.

## Error Handling

- Missing environment variables cause immediate failure with descriptive error
- Database connection failures are logged and propagate to job failure
- All database connections use context managers for guaranteed cleanup
- Transaction rollback on load failure