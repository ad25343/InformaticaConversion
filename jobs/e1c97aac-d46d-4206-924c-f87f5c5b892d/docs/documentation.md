# Mapping: m_dim_employee_load

## Overview

**Inferred Purpose**: This mapping loads employee dimension data from the operational OLTP system into the data warehouse DIM_EMPLOYEE table. It appears to perform a straightforward extract-and-load operation for employee master data including personal information, organizational attributes, and employment status.

**Source Systems and Tables**:
- Database: Oracle
- Schema: OLTP
- Table: EMPLOYEE

**Target Systems and Tables**:
- Database: Oracle
- Schema: DWH
- Table: DIM_EMPLOYEE

**Complexity Tier**: Low
- Single source and single target
- Contains 3 transformations (Source Qualifier, Expression)
- No complex joins, lookups, or aggregations
- Straightforward field-level passthrough logic

**High-Level Data Flow Narrative**: 
The mapping extracts all employee records from the OLTP.EMPLOYEE source table through a Source Qualifier transformation (SQ_EMPLOYEE). Data flows through an Expression transformation (EXP_EMPLOYEE) which may apply business rules or transformations to the employee fields. Finally, the transformed data is loaded into the DWH.DIM_EMPLOYEE target table. Based on the connector information, at minimum the EMPLOYEE_ID field flows through each transformation stage, maintaining the primary key relationship from source to target.

---

## Transformations (in execution order)

### EMPLOYEE — Source Definition

**Purpose**: Defines the structure and metadata of the source EMPLOYEE table from the OLTP system. This is the entry point for employee data into the mapping.

**Input Ports**: N/A (Source Definition)

**Output Ports**:

| Port Name | Datatype | Precision/Length | Destination |
|-----------|----------|------------------|-------------|
| EMPLOYEE_ID | number | 0 | SQ_EMPLOYEE |
| EMP_NUMBER | varchar | 0 | SQ_EMPLOYEE |
| FIRST_NAME | varchar | 0 | SQ_EMPLOYEE |
| LAST_NAME | varchar | 0 | SQ_EMPLOYEE |
| ROLE | varchar | 0 | SQ_EMPLOYEE |
| DEPARTMENT | varchar | 0 | SQ_EMPLOYEE |
| BRANCH_ID | number | 0 | SQ_EMPLOYEE |
| HIRE_DATE | date | 0 | SQ_EMPLOYEE |
| TERMINATION_DATE | date | 0 | SQ_EMPLOYEE |
| EMAIL | varchar | 0 | SQ_EMPLOYEE |
| IS_ACTIVE | varchar | 0 | SQ_EMPLOYEE |

**Logic Detail**: No transformation logic; this is a source definition that describes the structure of the OLTP.EMPLOYEE table.

**Table Attributes**: 
- Database Type: Oracle
- Owner: OLTP
- No SQL override documented
- No filter conditions documented

**Hardcoded Values**: None

---

### SQ_EMPLOYEE — Source Qualifier

**Purpose**: Extracts employee records from the EMPLOYEE source table and passes them to downstream transformations. The Source Qualifier can optionally apply SQL-level filtering, sorting, or joining, though no such logic is explicitly documented in the provided metadata.

**Input Ports**:

| Port Name | Datatype | Precision/Length | Source |
|-----------|----------|------------------|--------|
| EMPLOYEE_ID | number | 0 | EMPLOYEE |
| EMP_NUMBER | varchar | 0 | EMPLOYEE |
| FIRST_NAME | varchar | 0 | EMPLOYEE |
| LAST_NAME | varchar | 0 | EMPLOYEE |
| ROLE | varchar | 0 | EMPLOYEE |
| DEPARTMENT | varchar | 0 | EMPLOYEE |
| BRANCH_ID | number | 0 | EMPLOYEE |
| HIRE_DATE | date | 0 | EMPLOYEE |
| TERMINATION_DATE | date | 0 | EMPLOYEE |
| EMAIL | varchar | 0 | EMPLOYEE |
| IS_ACTIVE | varchar | 0 | EMPLOYEE |

**Output Ports**:

| Port Name | Datatype | Precision/Length | Destination |
|-----------|----------|------------------|-------------|
| EMPLOYEE_ID | number | 0 | EXP_EMPLOYEE |
| EMP_NUMBER | varchar | 0 | (not documented in connectors) |
| FIRST_NAME | varchar | 0 | (not documented in connectors) |
| LAST_NAME | varchar | 0 | (not documented in connectors) |
| ROLE | varchar | 0 | (not documented in connectors) |
| DEPARTMENT | varchar | 0 | (not documented in connectors) |
| BRANCH_ID | number | 0 | (not documented in connectors) |
| HIRE_DATE | date | 0 | (not documented in connectors) |
| TERMINATION_DATE | date | 0 | (not documented in connectors) |
| EMAIL | varchar | 0 | (not documented in connectors) |
| IS_ACTIVE | varchar | 0 | (not documented in connectors) |

**Logic Detail**: No explicit transformation expressions are documented. The Source Qualifier performs a standard SELECT operation on the EMPLOYEE table. All fields are passed through without modification at this stage.

**Table Attributes**:
- SQL Override: Not documented
- Filter Condition: Not documented
- Sort Order: Not documented
- Join Conditions: Not applicable (single source)

**Hardcoded Values**: None

**AMBIGUITY**: The connector information only documents the EMPLOYEE_ID field flowing from SQ_EMPLOYEE to EXP_EMPLOYEE. It is unclear whether the remaining 10 fields (EMP_NUMBER, FIRST_NAME, LAST_NAME, ROLE, DEPARTMENT, BRANCH_ID, HIRE_DATE, TERMINATION_DATE, EMAIL, IS_ACTIVE) are also connected to the Expression transformation. This may be a metadata extraction limitation or indicate that only EMPLOYEE_ID is explicitly connected while other fields flow implicitly.

---

### EXP_EMPLOYEE — Expression

**Purpose**: Applies business rules, transformations, or data cleansing logic to employee data before loading to the target dimension table. The specific transformation logic is not documented in the provided metadata.

**Input Ports**:

| Port Name | Datatype | Precision/Length | Source |
|-----------|----------|------------------|--------|
| EMPLOYEE_ID | number | 0 | SQ_EMPLOYEE |

**Output Ports**:

| Port Name | Datatype | Precision/Length | Destination |
|-----------|----------|------------------|-------------|
| EMPLOYEE_ID | number | 0 | DIM_EMPLOYEE |

**Logic Detail**: No transformation expressions are documented in the provided metadata. 

**AMBIGUITY**: The expression logic for all fields is not provided. Based on the connector information, only EMPLOYEE_ID is explicitly documented as flowing through this transformation. The following is unknown:
- Whether the remaining 10 fields (EMP_NUMBER, FIRST_NAME, LAST_NAME, ROLE, DEPARTMENT, BRANCH_ID, HIRE_DATE, TERMINATION_DATE, EMAIL, IS_ACTIVE) are processed by this Expression transformation
- What specific transformation expressions, if any, are applied to each field
- Whether any derived fields are created
- Whether any data type conversions, null handling, or business rules are applied

Without the detailed port-level expressions, the actual transformation logic cannot be documented. The Expression transformation may be performing passthrough logic, or it may contain significant business rules that are not captured in the provided structured data.

**Table Attributes**: Not applicable (Expression transformation)

**Hardcoded Values**: Cannot be determined without expression details

---

### DIM_EMPLOYEE — Target Definition

**Purpose**: Defines the structure of the target employee dimension table in the data warehouse where transformed employee data is loaded.

**Input Ports**:

| Port Name | Datatype | Precision/Length | Source |
|-----------|----------|------------------|--------|
| EMPLOYEE_ID | number | (not specified) | EXP_EMPLOYEE |
| EMP_NUMBER | varchar | (not specified) | (not documented in connectors) |
| FIRST_NAME | varchar | (not specified) | (not documented in connectors) |
| LAST_NAME | varchar | (not specified) | (not documented in connectors) |
| ROLE | varchar | (not specified) | (not documented in connectors) |
| DEPARTMENT | varchar | (not specified) | (not documented in connectors) |
| BRANCH_ID | number | (not specified) | (not documented in connectors) |
| HIRE_DATE | date | (not specified) | (not documented in connectors) |
| TERMINATION_DATE | date | (not specified) | (not documented in connectors) |
| EMAIL | varchar | (not specified) | (not documented in connectors) |
| IS_ACTIVE | varchar | (not specified) | (not documented in connectors) |

**Output Ports**: N/A (Target Definition)

**Logic Detail**: No transformation logic; this is a target definition that describes the structure of the DWH.DIM_EMPLOYEE table.

**Table Attributes**:
- Database Type: Oracle
- Owner: DWH
- Target Load Type: Not documented
- Update Strategy: Not documented
- Truncate Target: Not documented

**Hardcoded Values**: None

**AMBIGUITY**: The connector information only documents EMPLOYEE_ID flowing from EXP_EMPLOYEE to DIM_EMPLOYEE. The connection status of the remaining 10 fields is not explicitly documented in the connector metadata.

---

## Parameters and Variables

| Name | Datatype | Default Value | Purpose | Resolved? |
|------|----------|---------------|---------|-----------|
| *(none documented)* | - | - | - | - |

**Note**: No mapping parameters or variables are documented in the provided metadata. The mapping appears to use only hardcoded source and target table references without parameterization.