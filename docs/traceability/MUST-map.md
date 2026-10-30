# MUST → test traceability (excerpt)

| Requirement | Test |
| --- | --- |
| AT-10 / SEC-KM-001 | `TestAT_10_*` in crypto + http |
| AT-11 / SEC-LOG-001 | `TestAT_11_AuditChainDetectsTamper` |
| SEC-CTN-006 | `TestSEC_CTN_006_*` |
| SEC-AZ-004 | `TestAuthorizationMatrixHarness` |
| AT-01 | `TestAT_01_PrivilegedAndClientConfidential` |
| ASM-001 | `TestASM_001_*` |
| AT-07 / QST | questionnaire publish + offline (template tests) |
| AT-08 | `TestAT_08_ArchiveBombRejectedAtValidation` |
| AT-14 / ARC-003 | `TestAT_14_ShredLeavesTombstone` |
| AT-02 | `TestAT_02_RestrictedRecord404Semantics` |
| AT-03 | `TestAT_03_NoApproveToolListed` |
| AT-09 | `TestAT_09_HeaderBodyNameMismatch` |
| AT-05 / AT-06 | `TestAT_05_*` / `TestAT_06_*` |
| AT-13 / GEN-014 | `TestAT_13_*` / `TestGEN_014_*` |
| AT-12 | `TestAT_12_DisabledConnectorBlocked` |
| AT-04 | `TestAT_04_InjectionNotObeyed` + evidence detectors |

CI must fail when a MUST in this table has no matching test (gate expands over milestones).
