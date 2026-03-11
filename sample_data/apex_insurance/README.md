# Apex P&C Insurance — Informatica PowerCenter Test Estate

**Domain:** Property & Casualty Insurance
**Repository:** APEX_INS_DWH (Oracle, PowerCenter v112)
**Generated:** 10/03/2026 09:00:00
**Total Mappings:** 50 (15 simple · 20 medium · 15 complex)

## Business Domain Coverage

- Policyholder & policy management (dimensions, SCD2)
- Claims lifecycle (triage, reserves, payments, recovery)
- Underwriting (premium, rating, endorsements, renewals)
- Reinsurance (treaty cession, CAT modeling, recovery)
- Actuarial (IBNR, loss development, pricing indication)
- Regulatory (IFRS 17, Solvency II SCR, statutory schedules)
- Agent distribution (commissions, channel performance)

## Mapping Tiers

| Tier | Count | Patterns |
|------|-------|----------|
| Simple | 15 | SQ→EXP, SQ→FIL→EXP |
| Medium | 20 | SCD2, LKP enrichment, AGG |
| Complex | 15 | 3-source JNR/UNI/RTR |
