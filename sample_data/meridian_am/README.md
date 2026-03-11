# Meridian Asset Management — Informatica PowerCenter Test Estate

**Domain:** Investment Management / Asset Management
**Repository:** MERIDIAN_DWH (SQL Server, PowerCenter v112)
**Generated:** 10/03/2026 09:00:00
**Total Mappings:** 50 (15 simple · 20 medium · 15 complex)

## Business Domain Coverage

- Portfolio & Fund Management (dimensions, NAV, AUM)
- Trade lifecycle (execution → settlement → reconciliation)
- Performance & Attribution (Brinson model, GIPS)
- Risk (VaR, factor decomposition, stress testing, counterparty)
- Compliance (investment guidelines, AIFMD, MiFID II)
- Corporate actions, dividends, coupons, fees
- ESG scoring and regulatory reporting

## Mapping Tiers

| Tier    | Count | Patterns |
|---------|-------|----------|
| Simple  | 15    | SQ→EXP, SQ→FIL→EXP |
| Medium  | 20    | SCD2, LKP enrichment, AGG |
| Complex | 15    | 3-source JNR/UNI/RTR |

## Usage

Point the Informatica Conversion Tool watcher at `all_mappings/` or load individual
tiers from `mappings/simple|medium|complex/`. Parameter files in `parameter_files/`
support DEV, UAT, and PROD environments.
