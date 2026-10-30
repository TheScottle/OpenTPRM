# MUST → test traceability (excerpt)

| Requirement | Test |
| --- | --- |
| AT-10 / SEC-KM-001 | `TestAT_10_*` in crypto + http |
| AT-11 / SEC-LOG-001 | `TestAT_11_AuditChainDetectsTamper` |
| SEC-CTN-006 | `TestSEC_CTN_006_*` |
| SEC-AZ-004 | `TestAuthorizationMatrixHarness` |
| AT-01 | `TestAT_01_PrivilegedAndClientConfidential`, `TestAT_01_IntakeSubmitHTTPE2E` |
| ASM-001 | `TestASM_001_*` |
| AT-07 / QST | `TestQST_PublishAndSTD006Seeds`, `TestAT_07_LockedCellEditRejected`, `TestOfflineZipRoundTripAndLockedCell` |
| STD-006 | `TestQST_PublishAndSTD006Seeds` / `ValidateProvenanceJSON` |
| QST-010 | `TestImportOSCALCatalog`, `TestImportCSVAndFormulaRefuse`, `TestImportXLSXHappyPath` |
| QST-011 | `TestQST_011_ArchiveBombRejected`, `TestQST_011_XLSXMacroPathRefused`, `TestEVD_UploadRejectsArchiveBomb` |
| AT-08 | `TestAT_08_ArchiveBombRejectedAtValidation`, `TestEVD_UploadRejectsArchiveBomb` |
| EVD chunked upload | `TestEVD_ChunkedUploadCompleteQuarantine`, `TestBlobRoundTrip` |
| SEC-UP sandbox | `TestSandboxValidateJobAllowList`, `TestSandboxForbidNetworkEnv` |
| AT-14 / ARC-003 | `TestAT_14_ShredLeavesTombstone` |
| AT-02 | `TestAT_02_RestrictedRecord404Semantics` |
| AT-03 | `TestAT_03_NoApproveToolListed` |
| AT-09 | `TestAT_09_HeaderBodyNameMismatch` |
| AT-05 / AT-06 | `TestAT_05_*` / `TestAT_06_*` |
| AT-13 / GEN-014 | `TestAT_13_*` / `TestGEN_014_*` |
| AT-12 | `TestAT_12_DisabledConnectorBlocked` |
| AT-04 | `TestAT_04_InjectionNotObeyed` + evidence detectors |
| SEC-AN-004 | `TestSEC_AN_004_SessionHashedIdleAbsolute` |
| SEC-AN-005 | `TestSEC_AN_005_LogoutRevokes` |
| SEC-AN-003 | `TestSEC_AN_003_StepUpWindow`, `TestSEC_AN_006_WebAuthnEnrollLoginStepUp` |
| SEC-AN-006 | `TestSEC_AN_006_ChallengeSingleUseAndThrottle`, `TestSEC_AN_006_WebAuthnEnrollLoginStepUp` |
| SEC-AN-001 | `TestSEC_AN_001_OIDCClaimValidation` |
| SEC-WEB CSRF | `TestSEC_WEB_CSRF_OriginReject` |
| OPS-001 | `TestOPS_001_ProductionRefusesInsecure` |
| OPS-002 | `TestOPS_002_RefuseSecretEnv` |
| OPS-003 | `TestOPS_003_BootstrapTokenSelfDestruct` |
| SOD-8 | `TestSOD_8_BreakGlassRequiresReasonAndStepUp` |
| INV-001 | `TestINV_001_VendorFieldsPersisted` |
| INV-002 | `TestINV_002_DuplicateDetectAndMerge`, `TestINV_002_NormalizeKey` |
| INV-003 / INV-004 / INV-005 | `TestINV_003_004_005_EngagementsContactsFourthParties` |
| INV-006 | `TestINV_006_TagsAndCustomFields` |
| INV-007 | `TestINV_007_UpdateWritesHistory` |
| INV-008 | `TestINV_008_BulkCSVRejectsFormulas` |
| INV-009 | `TestINV_009_NextActionDueEarliest` |
| INV API routes | `TestINV_API_VendorContactEngagementRoutes` |
| SEC-AZ-001 | `TestSEC_AZ_001_ProductionDevHeadersRefused` |

CI must fail when a MUST in this table has no matching test (gate expands over milestones).
