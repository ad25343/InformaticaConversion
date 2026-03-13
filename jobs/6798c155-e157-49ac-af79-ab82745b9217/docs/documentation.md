# Mapping: m_stg_customer_file_load

## Overview

**Inferred Purpose:**  
This mapping loads daily customer data from a pipe-delimited CSV file into a staging table in Oracle. It performs a straightforward extract-and-load operation with minimal transformation, appending a system timestamp to track when each record was loaded.

**Source Systems and Tables:**
- **Flat File**: `customers_daily.csv` located in `/data/in/customers`
  - Format: Pipe-delimited (`|`) with header row
  - Source Table: `CUSTOMER_FEED`

**Target Systems and Tables:**
- **Oracle Database**: Schema `DWH`
  - Target Table: `STG_CUSTOMER_FEED`

**Complexity Tier and Rationale:**  
**Low** — This mapping meets all criteria for low complexity:
- Single source (flat file) and single target (Oracle table)
- Only 3 transformations in the pipeline (Source Qualifier, Expression, Target)
- No complex logic: the Expression transformation appears to perform pass-through for most fields with only a timestamp generation
- No lookups, joins, filters, or conditional logic

**High-Level Data Flow Narrative:**  
Customer records are read from a daily CSV file through the `CUSTOMER_FEED` source definition. The `SQ_CUSTOMER_FEED` source qualifier extracts all 8 fields from the file without filtering or SQL override. The `EXP_CUSTOMER_FEED` expression transformation receives all source fields and generates an additional `LOAD_TS` field (timestamp of load execution). All 9 fields are then written to the `STG_CUSTOMER_FEED` Oracle staging table. This is a full-load pattern with no incremental logic or deduplication.

---

## Transformations (in execution order)

### CUSTOMER_FEED — Source Definition (Flat File)

**Purpose:**  
Defines the structure and location of the daily customer CSV feed file. This source definition specifies the file format, delimiter, and field definitions to enable Informatica to parse the incoming flat file data.

**Input Ports:**  
Not applicable — this is a source definition (no upstream ports).

**Output Ports:**

| Port Name      | Datatype | Length | Destination            |
|----------------|----------|--------|------------------------|
| CUSTOMER_ID    | string   | 20     | SQ_CUSTOMER_FEED       |
| FIRST_NAME     | string   | 100    | SQ_CUSTOMER_FEED       |
| LAST_NAME      | string   | 100    | SQ_CUSTOMER_FEED       |
| EMAIL          | string   | 200    | SQ_CUSTOMER_FEED       |
| PHONE          | string   | 20     | SQ_CUSTOMER_FEED       |
| CUSTOMER_TYPE  | string   | 20     | SQ_CUSTOMER_FEED       |
| STATUS         | string   | 10     | SQ_CUSTOMER_FEED       |
| OPEN_DATE      | string   | 10     | SQ_CUSTOMER_FEED       |

**Logic Detail:**  
No transformation logic — this is a source definition. All fields are read as strings from the file, including `OPEN_DATE` which is stored as a 10-character string (likely format: YYYY-MM-DD).

**Table Attributes:**
- **File Name**: `customers_daily.csv`
- **File Directory**: `/data/in/customers`
- **Delimiter**: `|` (pipe)
- **Has Header**: `true` (first row contains column names and will be skipped)
- **Skip Rows**: `0` (no additional rows skipped beyond the header)
- **Row Delimiter**: `LF` (line feed / newline character)

**Hardcoded Values:**  
None — this is a source definition with file path configuration.

---

### SQ_CUSTOMER_FEED — Source Qualifier

**Purpose:**  
Acts as the extraction layer for the flat file source. This source qualifier reads all records from the `CUSTOMER_FEED` flat file and passes them downstream without filtering, aggregation, or transformation.

**Input Ports:**

| Port Name      | Datatype | Length | Source          |
|----------------|----------|--------|-----------------|
| CUSTOMER_ID    | string   | 20     | CUSTOMER_FEED   |
| FIRST_NAME     | string   | 100    | CUSTOMER_FEED   |
| LAST_NAME      | string   | 100    | CUSTOMER_FEED   |
| EMAIL          | string   | 200    | CUSTOMER_FEED   |
| PHONE          | string   | 20     | CUSTOMER_FEED   |
| CUSTOMER_TYPE  | string   | 20     | CUSTOMER_FEED   |
| STATUS         | string   | 10     | CUSTOMER_FEED   |
| OPEN_DATE      | string   | 10     | CUSTOMER_FEED   |

**Output Ports:**

| Port Name      | Datatype | Length | Destination         |
|----------------|----------|--------|---------------------|
| CUSTOMER_ID    | string   | 20     | EXP_CUSTOMER_FEED   |
| FIRST_NAME     | string   | 100    | EXP_CUSTOMER_FEED   |
| LAST_NAME      | string   | 100    | EXP_CUSTOMER_FEED   |
| EMAIL          | string   | 200    | EXP_CUSTOMER_FEED   |
| PHONE          | string   | 20     | EXP_CUSTOMER_FEED   |
| CUSTOMER_TYPE  | string   | 20     | EXP_CUSTOMER_FEED   |
| STATUS         | string   | 10     | EXP_CUSTOMER_FEED   |
| OPEN_DATE      | string   | 10     | EXP_CUSTOMER_FEED   |

**Logic Detail:**  
No transformation logic is applied. All input fields are passed through as-is to output ports. This is a standard flat file source qualifier with no SQL override (flat files do not support SQL).

**Table Attributes:**
- **SQL Override**: None (not applicable for flat file sources)
- **Filter Condition**: None
- **Join Condition**: None (single source)
- **Sorting**: None specified
- **Distinct**: Not enabled

**Hardcoded Values:**  
None

---

### EXP_CUSTOMER_FEED — Expression

**Purpose:**  
Performs minimal transformation on the incoming customer data. The primary purpose is to generate a load timestamp (`LOAD_TS`) that captures the exact moment the record is processed, enabling audit tracking in the staging table. All other fields pass through unchanged.

**Input Ports:**

| Port Name      | Datatype | Length | Source              |
|----------------|----------|--------|---------------------|
| CUSTOMER_ID    | string   | 20     | SQ_CUSTOMER_FEED    |
| FIRST_NAME     | string   | 100    | SQ_CUSTOMER_FEED    |
| LAST_NAME      | string   | 100    | SQ_CUSTOMER_FEED    |
| EMAIL          | string   | 200    | SQ_CUSTOMER_FEED    |
| PHONE          | string   | 20     | SQ_CUSTOMER_FEED    |
| CUSTOMER_TYPE  | string   | 20     | SQ_CUSTOMER_FEED    |
| STATUS         | string   | 10     | SQ_CUSTOMER_FEED    |
| OPEN_DATE      | string   | 10     | SQ_CUSTOMER_FEED    |

**Output Ports:**

| Port Name      | Datatype | Length | Destination         |
|----------------|----------|--------|---------------------|
| CUSTOMER_ID    | string   | 20     | STG_CUSTOMER_FEED   |
| FIRST_NAME     | string   | 100    | STG_CUSTOMER_FEED   |
| LAST_NAME      | string   | 100    | STG_CUSTOMER_FEED   |
| EMAIL          | string   | 200    | STG_CUSTOMER_FEED   |
| PHONE          | string   | 20     | STG_CUSTOMER_FEED   |
| CUSTOMER_TYPE  | string   | 20     | STG_CUSTOMER_FEED   |
| STATUS         | string   | 10     | STG_CUSTOMER_FEED   |
| OPEN_DATE      | string   | 10     | STG_CUSTOMER_FEED   |
| LOAD_TS        | *(inferred)* | *(inferred)* | STG_CUSTOMER_FEED   |

**Logic Detail:**

⚠️ **AMBIGUITY FLAGGED**: The structured data shows that `EXP_CUSTOMER_FEED` outputs a `LOAD_TS` field (connected to `STG_CUSTOMER_FEED.LOAD_TS`), but the transformation definition does not include the expression logic or port metadata for this field. Based on the field name and common Informatica patterns, the expression is likely one of the following:
- `SYSTIMESTAMP` — Returns current database timestamp
- `SYSDATE` — Returns current database date/time
- `SESSSTARTTIME` — Returns session start time
- `GETDATE()` — Returns current system date/time

**Without the actual expression definition, the exact logic cannot be confirmed.**

For all other fields, the transformation performs pass-through:
- `CUSTOMER_ID` = `CUSTOMER_ID` (passes input directly to output)
- `FIRST_NAME` = `FIRST_NAME` (passes input directly to output)
- `LAST_NAME` = `LAST_NAME` (passes input directly to output)
- `EMAIL` = `EMAIL` (passes input directly to output)
- `PHONE` = `PHONE` (passes input directly to output)
- `CUSTOMER_TYPE` = `CUSTOMER_TYPE` (passes input directly to output)
- `STATUS` = `STATUS` (passes input directly to output)
- `OPEN_DATE` = `OPEN_DATE` (passes input directly to output)

**Table Attributes:**  
Not applicable — Expression transformations do not have join, lookup, or filter conditions.

**Hardcoded Values:**  
Cannot confirm without expression definition. If `LOAD_TS` uses `SYSTIMESTAMP`, `SYSDATE`, or `SESSSTARTTIME`, the value is system-generated rather than hardcoded. No other hardcoded values are evident.

---

### STG_CUSTOMER_FEED — Target Definition (Oracle Table)

**Purpose:**  
Defines the target Oracle staging table where customer feed data is loaded. This table captures all customer attributes from the source file plus a load timestamp for auditing purposes.

**Input Ports:**

| Port Name      | Datatype | Length | Source              |
|----------------|----------|--------|---------------------|
| CUSTOMER_ID    | string   | 20     | EXP_CUSTOMER_FEED   |
| FIRST_NAME     | string   | 100    | EXP_CUSTOMER_FEED   |
| LAST_NAME      | string   | 100    | EXP_CUSTOMER_FEED   |
| EMAIL          | string   | 200    | EXP_CUSTOMER_FEED   |
| PHONE          | string   | 20     | EXP_CUSTOMER_FEED   |
| CUSTOMER_TYPE  | string   | 20     | EXP_CUSTOMER_FEED   |
| STATUS         | string   | 10     | EXP_CUSTOMER_FEED   |
| OPEN_DATE      | string   | 10     | EXP_CUSTOMER_FEED   |
| LOAD_TS        | *(inferred)* | *(inferred)* | EXP_CUSTOMER_FEED   |

**Output Ports:**  
Not applicable — this is a target definition (no downstream ports).

**Target Table Structure:**

| Column Name    | Datatype | Length | Purpose                                    |
|----------------|----------|--------|--------------------------------------------|
| CUSTOMER_ID    | varchar  | *(not specified)* | Unique customer identifier            |
| FIRST_NAME     | varchar  | *(not specified)* | Customer first name                   |
| LAST_NAME      | varchar  | *(not specified)* | Customer last name                    |
| EMAIL          | varchar  | *(not specified)* | Customer email address                |
| PHONE          | varchar  | *(not specified)* | Customer phone number                 |
| CUSTOMER_TYPE  | varchar  | *(not specified)* | Customer classification/type          |
| STATUS         | varchar  | *(not specified)* | Customer account status               |
| OPEN_DATE      | date     | *(not specified)* | Date customer account was opened      |
| LOAD_TS        | date     | *(not specified)* | Timestamp when record was loaded      |

**Logic Detail:**  
No transformation logic — this is a target definition. Data is inserted into the Oracle table as received from the Expression transformation.

⚠️ **AMBIGUITY FLAGGED**: The target field definitions show datatype but no length specifications for varchar columns. This may indicate:
- Lengths are defined at the database level but not captured in the Informatica metadata
- The export/parsing process omitted length metadata
- Informatica is relying on database column definitions for length validation

**Data Type Conversion Note:**  
`OPEN_DATE` is read as a string (length 10) from the flat file and written to a `date` datatype column in Oracle. This implies an implicit or explicit date conversion occurs, likely during the load operation. The date format is not specified in the provided metadata.

**Table Attributes:**
- **Database Type**: Oracle
- **Owner/Schema**: `DWH`
- **Table Name**: `STG_CUSTOMER_FEED`
- **Load Type**: *(not specified in metadata — likely INSERT based on staging table pattern)*
- **Truncate Target**: *(not specified)*
- **Update Strategy**: *(not specified)*

**Hardcoded Values:**  
None — all values are sourced from upstream transformation.

---

## Parameters and Variables

| Name | Datatype | Default Value | Purpose | Resolved? |
|------|----------|---------------|---------|-----------|
| *(None)* | — | — | No parameters or variables are defined in this mapping | N/A |

**Note:** The structured data indicates `"parameters": []` and `"Unresolved Parameters: []"`, confirming that this mapping does not use any mapping parameters, mapping variables, session parameters, or workflow variables. All configuration values (file paths, delimiters, etc.) are hardcoded in the source and target definitions.