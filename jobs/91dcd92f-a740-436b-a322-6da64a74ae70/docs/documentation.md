# Mapping: m_fct_atm_transactions_load

## Overview

**Inferred Purpose:**  
This mapping loads ATM transaction data from the operational OLTP system into a data warehouse fact table. It performs a straightforward extraction and load of ATM transaction records including transaction identifiers, dates, account information, ATM locations, transaction types, amounts, status, fees, and masked card numbers.

**Source Systems and Tables:**
- **Database Type:** Oracle
- **Owner/Schema:** OLTP
- **Table:** ATM_TRANSACTIONS

**Target Systems and Tables:**
- **Database Type:** Oracle
- **Owner/Schema:** DWH
- **Table:** FCT_ATM_TRANSACTIONS

**Complexity Tier and Rationale:**  
**Tier: Low**  
This mapping qualifies as low complexity based on the following criteria:
- Single source table to single target table
- Contains only 3 transformation instances (Source Qualifier, Expression, Target)
- No complex joins, lookups, or aggregations
- Straightforward field-level pass-through logic
- No branching or multiple data flows

**High-Level Data Flow Narrative:**  
ATM transaction records are extracted from the OLTP.ATM_TRANSACTIONS source table through a Source Qualifier transformation (SQ_ATM_TRANSACTIONS). The data flows through an Expression transformation (EXP_ATM_TRANSACTIONS) where field-level transformations or mapping logic is applied. Finally, the transformed records are loaded into the target data warehouse fact table DWH.FCT_ATM_TRANSACTIONS. The mapping appears to follow a simple ETL pattern with minimal transformation complexity between source and target.

---

## Transformations (in execution order)

### ATM_TRANSACTIONS — Source Definition

**Purpose:**  
This is the source definition representing the ATM_TRANSACTIONS table in the OLTP Oracle database. It defines the structure and metadata of the source data to be extracted for the ATM transactions fact load process.

**Input Ports:**  
N/A — This is a source definition with no input ports.

**Output Ports:**

| Port Name | Datatype | Precision/Length | Description |
|-----------|----------|------------------|-------------|
| TXN_ID | number | 0 | Transaction identifier |
| TXN_DATE | date | 0 | Transaction date |
| ACCOUNT_ID | number | 0 | Account identifier |
| ATM_ID | varchar | 0 | ATM machine identifier |
| TXN_TYPE | varchar | 0 | Transaction type code |
| AMOUNT | decimal | 0 | Transaction amount |
| STATUS | varchar | 0 | Transaction status |
| FEE_AMOUNT | decimal | 0 | Fee amount charged |
| CARD_LAST4 | varchar | 0 | Last 4 digits of card number |

**Logic Detail:**  
No transformation logic — this is a source definition. All fields are passed as-is from the source table structure.

**Table Attributes:**  
- **Database Type:** Oracle
- **Owner:** OLTP
- **Table Name:** ATM_TRANSACTIONS

**Hardcoded Values:**  
None

---

### SQ_ATM_TRANSACTIONS — Source Qualifier

**Purpose:**  
The Source Qualifier reads data from the ATM_TRANSACTIONS source table and provides the initial extraction point for the mapping. It enables SQL override capabilities, filtering, and sorting of source data before passing records downstream to transformation logic.

**Input Ports:**

| Port Name | Datatype | Precision/Length | Source |
|-----------|----------|------------------|--------|
| TXN_ID | number | 0 | ATM_TRANSACTIONS.TXN_ID |
| TXN_DATE | date | 0 | ATM_TRANSACTIONS.TXN_DATE |
| ACCOUNT_ID | number | 0 | ATM_TRANSACTIONS.ACCOUNT_ID |
| ATM_ID | varchar | 0 | ATM_TRANSACTIONS.ATM_ID |
| TXN_TYPE | varchar | 0 | ATM_TRANSACTIONS.TXN_TYPE |
| AMOUNT | decimal | 0 | ATM_TRANSACTIONS.AMOUNT |
| STATUS | varchar | 0 | ATM_TRANSACTIONS.STATUS |
| FEE_AMOUNT | decimal | 0 | ATM_TRANSACTIONS.FEE_AMOUNT |
| CARD_LAST4 | varchar | 0 | ATM_TRANSACTIONS.CARD_LAST4 |

**Output Ports:**

| Port Name | Datatype | Precision/Length | Destination |
|-----------|----------|------------------|-------------|
| TXN_ID | number | 0 | EXP_ATM_TRANSACTIONS.TXN_ID |
| TXN_DATE | date | 0 | EXP_ATM_TRANSACTIONS.TXN_DATE |
| ACCOUNT_ID | number | 0 | EXP_ATM_TRANSACTIONS.ACCOUNT_ID |
| ATM_ID | varchar | 0 | EXP_ATM_TRANSACTIONS.ATM_ID |
| TXN_TYPE | varchar | 0 | EXP_ATM_TRANSACTIONS.TXN_TYPE |
| AMOUNT | decimal | 0 | EXP_ATM_TRANSACTIONS.AMOUNT |
| STATUS | varchar | 0 | EXP_ATM_TRANSACTIONS.STATUS |
| FEE_AMOUNT | decimal | 0 | EXP_ATM_TRANSACTIONS.FEE_AMOUNT |
| CARD_LAST4 | varchar | 0 | EXP_ATM_TRANSACTIONS.CARD_LAST4 |

**Logic Detail:**  
No explicit transformation expressions documented in the provided metadata. The Source Qualifier performs a standard SELECT of all fields from the ATM_TRANSACTIONS table, passing each field through without modification to the downstream Expression transformation.

**AMBIGUITY:** The provided JSON does not contain detailed transformation objects or SQL override information. If custom SQL, filters, or sorting exists within this Source Qualifier, it is not visible in the current metadata structure.

**Table Attributes:**  
- No SQL override documented
- No filter condition documented
- No sort order documented
- No join condition (single source table)

**Hardcoded Values:**  
None

---

### EXP_ATM_TRANSACTIONS — Expression

**Purpose:**  
This Expression transformation applies business logic, data type conversions, calculations, or field-level transformations to the ATM transaction data before loading it into the target fact table. Based on the connector information, it processes all fields from the Source Qualifier.

**Input Ports:**

| Port Name | Datatype | Precision/Length | Source |
|-----------|----------|------------------|--------|
| TXN_ID | number | 0 | SQ_ATM_TRANSACTIONS.TXN_ID |
| TXN_DATE | date | 0 | SQ_ATM_TRANSACTIONS.TXN_DATE |
| ACCOUNT_ID | number | 0 | SQ_ATM_TRANSACTIONS.ACCOUNT_ID |
| ATM_ID | varchar | 0 | SQ_ATM_TRANSACTIONS.ATM_ID |
| TXN_TYPE | varchar | 0 | SQ_ATM_TRANSACTIONS.TXN_TYPE |
| AMOUNT | decimal | 0 | SQ_ATM_TRANSACTIONS.AMOUNT |
| STATUS | varchar | 0 | SQ_ATM_TRANSACTIONS.STATUS |
| FEE_AMOUNT | decimal | 0 | SQ_ATM_TRANSACTIONS.FEE_AMOUNT |
| CARD_LAST4 | varchar | 0 | SQ_ATM_TRANSACTIONS.CARD_LAST4 |

**Output Ports:**

| Port Name | Datatype | Precision/Length | Destination |
|-----------|----------|------------------|-------------|
| TXN_ID | number | 0 | FCT_ATM_TRANSACTIONS.TXN_ID |
| TXN_DATE | date | 0 | FCT_ATM_TRANSACTIONS.TXN_DATE |
| ACCOUNT_ID | number | 0 | FCT_ATM_TRANSACTIONS.ACCOUNT_ID |
| ATM_ID | varchar | 0 | FCT_ATM_TRANSACTIONS.ATM_ID |
| TXN_TYPE | varchar | 0 | FCT_ATM_TRANSACTIONS.TXN_TYPE |
| AMOUNT | decimal | 0 | FCT_ATM_TRANSACTIONS.AMOUNT |
| STATUS | varchar | 0 | FCT_ATM_TRANSACTIONS.STATUS |
| FEE_AMOUNT | decimal | 0 | FCT_ATM_TRANSACTIONS.FEE_AMOUNT |
| CARD_LAST4 | varchar | 0 | FCT_ATM_TRANSACTIONS.CARD_LAST4 |

**Logic Detail:**  

**AMBIGUITY:** The provided JSON structure does not contain the detailed transformation expressions or port-level logic for the Expression transformation. The connector information shows that TXN_ID flows from input to output, but the complete expression definitions for all ports are not present in the metadata.

Based on the connector data available, at minimum:
- **TXN_ID:** Passed through from input to output (no expression documented)

Without the complete transformation object details including port expressions, it is not possible to document the specific business logic, calculations, or transformations applied to each field. In a typical ATM transaction fact load, this Expression might include:
- Data type conversions
- NULL handling
- Default value assignments
- Data quality transformations
- Audit field population (though none are visible in target)

**Table Attributes:**  
N/A — Expression transformations do not have table-level attributes like joins or filters.

**Hardcoded Values:**  
Cannot be determined from the provided metadata without detailed expression definitions.

---

### FCT_ATM_TRANSACTIONS — Target Definition

**Purpose:**  
This is the target table definition representing the FCT_ATM_TRANSACTIONS fact table in the DWH (Data Warehouse) Oracle database. It receives the transformed ATM transaction records and persists them for analytical and reporting purposes.

**Input Ports:**

| Port Name | Datatype | Precision/Length | Source |
|-----------|----------|------------------|--------|
| TXN_ID | number | (empty) | EXP_ATM_TRANSACTIONS.TXN_ID |
| TXN_DATE | date | (empty) | EXP_ATM_TRANSACTIONS.TXN_DATE |
| ACCOUNT_ID | number | (empty) | EXP_ATM_TRANSACTIONS.ACCOUNT_ID |
| ATM_ID | varchar | (empty) | EXP_ATM_TRANSACTIONS.ATM_ID |
| TXN_TYPE | varchar | (empty) | EXP_ATM_TRANSACTIONS.TXN_TYPE |
| AMOUNT | decimal | (empty) | EXP_ATM_TRANSACTIONS.AMOUNT |
| STATUS | varchar | (empty) | EXP_ATM_TRANSACTIONS.STATUS |
| FEE_AMOUNT | decimal | (empty) | EXP_ATM_TRANSACTIONS.FEE_AMOUNT |
| CARD_LAST4 | varchar | (empty) | EXP_ATM_TRANSACTIONS.CARD_LAST4 |

**Output Ports:**  
N/A — This is a target definition with no output ports.

**Logic Detail:**  
No transformation logic — this is a target definition. All fields are loaded as received from the Expression transformation.

**Table Attributes:**  
- **Database Type:** Oracle
- **Owner:** DWH
- **Table Name:** FCT_ATM_TRANSACTIONS
- **Load Type:** Not specified in metadata (typically INSERT based on fact table pattern)
- **Truncate Target:** Not specified in metadata
- **Update Strategy:** Not specified in metadata

**Hardcoded Values:**  
None

---

## Parameters and Variables

| Name | Datatype | Default Value | Purpose | Resolved? |
|------|----------|---------------|---------|-----------|
| *(No parameters defined)* | — | — | — | — |

**Note:** The provided mapping metadata indicates "Unresolved Parameters: []" and the parameters array is empty. This mapping does not utilize any mapping parameters or variables for dynamic configuration or runtime value substitution.