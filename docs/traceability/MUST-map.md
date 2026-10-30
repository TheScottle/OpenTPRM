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
| AT-15 | `TestAT_15_DeltaPrefill`, `TestQST_InstanceResponseReviewAndAT15Delta`, `TestAT_15_DeltaInstanceHTTPE2E` |
| STD-006 | `TestQST_PublishAndSTD006Seeds` / `ValidateProvenanceJSON` |
| QST-010 | `TestImportOSCALCatalog`, `TestImportCSVAndFormulaRefuse`, `TestImportXLSXHappyPath` |
| QST-011 | `TestQST_011_ArchiveBombRejected`, `TestQST_011_XLSXMacroPathRefused`, `TestEVD_UploadRejectsArchiveBomb` |
| AT-08 | `TestAT_08_ArchiveBombRejectedAtValidation`, `TestEVD_UploadRejectsArchiveBomb` |
| EVD chunked upload | `TestEVD_ChunkedUploadCompleteQuarantine`, `TestBlobRoundTrip` |
| EVD-007 safe viewer | `TestSanitizeViewerTextStripsControlsAndTags`, `TestRenderViewerHTMLSafe`, `TestEVD_EvidencePageAndSOCReview`, `TestEVD_EvidencePageHTMLViewer` |
| EVD-020 SOC schema | `TestSOCReviewSchemaEmbedded`, `TestEVD_EvidencePageAndSOCReview` |
| SEC-UP sandbox | `TestSandboxValidateJobAllowList`, `TestSandboxForbidNetworkEnv`, `TestSandboxProbeIsolation`, `TestSandboxApplyChildHooks*`, `TestSandboxExtractTXTAndJSON`, `TestSandboxExpectedChildPolicy` |
| QST-035 answer library | `TestQST_035_AnswerLibrary`, `TestQST_035_AnswerLibraryHTTP` |
| RPT-004 second approver | `TestRPT_004_ExportSecondApproverSOD`, `TestRPT_004_ExportSecondApproverHTTP` |
| POR-002 passkey/TOTP | `TestPOR_002_PasskeyEnrollStub`, `TestPOR_002_TOTPEnrollVerifyStub` |
| OPS-004 | `TestOPS_004_DemoSeedRefusedInProduction`, `TestOPS_004_DemoNotRequested` |
| NFR-001 ready latency smoke | `TestNFR_001_HealthReadyLatencySmoke` |
| OpenAPI mux contract | `TestOpenAPI_RoutesHaveMuxRegistrationSmoke` |
| SEC-UP-002 fuzz | `FuzzValidateUpload` (+ `testdata/fuzz/ValidateUpload`) |
| FND-002 / FND-003 / FND-005 | `TestFND_002_StatusTransitions`, `TestFND_003_DefaultSLA`, `TestFND_RSK_RemediationAndRegister` |
| RSK-001 / RSK-003 | `TestFND_RSK_RemediationAndRegister` |
| CON-002 / CON-003 / CON-004 | `TestCON_002_004_ClausesAndFlowDown`, `TestCON_ObligationsAndFlowDown` |
| MON-005 | `TestMON_005_Dispositions`, `TestMON_OFF_DispositionAndChecklist` |
| OFF-001 | `TestOFF_001_DefaultChecklist`, `TestMON_OFF_DispositionAndChecklist` |
| ARC-001 / ARC-002 / ARC-004 | `TestARC_002_LegalHoldBlocksShred` |
| ARC-010 / ARC-013 | `TestARC_013_RestoreVerifyOnly` |
| AT-14 / ARC-003 | `TestAT_14_ShredLeavesTombstone`, `TestARC_002_LegalHoldBlocksShred` |
| GEN-012 / RPT-002 / RPT-004 | `TestGEN_012_ConfigurableMarkings`, `TestRPT_004_SensitiveClassification`, `TestRPT_ExportMarkingsGEN012`, `TestRPT_EXC_ReportsExportsExceptionsHTTP` |
| EXC-001 / EXC-002 / SOD-2 | `TestEXC_CreateListApprove_SOD2`, `TestRPT_EXC_ReportsExportsExceptionsHTTP`, `TestSignVerifyRoundTrip` |
| AI-023 | `TestAI_023_OpaqueTokenIssueVerifyHashed`, `TestAI_023_DPoPHeaderPresenceStub`, `TestAI_023_PKCEChallengeStoreAndAuthCode`, `TestAI_023_DPoPProofParseVerify`, `TestOAuth_TokenIssueRequiresDPoP`, `TestOAuth_PKCEAuthorizeCodeAndToken` |
| AI-005 | `TestAI_005_TasksExtensionStubs` |
| AI-032 | `TestAI_032_BudgetWiredOnGateway` |
| AI model registry | `TestAI_ModelEndpointHTTPCRUD` |
| AI job suggestions-only | `TestAI_JobStubCreatesSuggestionsOnly` |
| AI-064 citations on accept | `TestAI_AcceptRequiresVerifiedCitations`, `TestAI_AcceptSuggestionCitationPath`, `TestAI_SuggestionAcceptCitationHTTP` |
| AI call logs | `TestAI_CallLogWrites` |
| AI-071 / AT-04 eval harness | `TestAT_04_EvalHarnessInjectionZeroTolerance`, `TestAT_04_InjectionNotObeyed` |
| UI analyst home | `TestUI_AnalystHomeAndVendors` |
| UI intake queue | `TestUI_IntakeAnalystQueue` |
| POR-002 magic-link | `TestPOR_002_MagicLinkIssueConsume` |
| POR vendor questionnaires | `TestPOR_VendorQuestionnaireListScoped` |
| Portal listener | `TestPortalEnabledWiresListener` |
| AT-02 | `TestAT_02_RestrictedRecord404Semantics` |
| AT-03 | `TestAT_03_NoApproveToolListed` |
| AT-09 | `TestAT_09_HeaderBodyNameMismatch` |
| AT-05 / AT-06 | `TestAT_05_ChangeRequestApprovalUI`, `TestAT_06_StaleChangeRequestRefused`, `TestAT_06_StaleChangeRequestHTTP`, `TestAT_06_DecideChangeRequestStaleAndSOD` |
| MCP initialize/discover | `TestMCP_InitializeAndDiscoverConformance`, `TestMCP_ToolsListShape` |
| OAuth refresh reuse | `TestOAuth_RefreshRotateAndReuseDetect` |
| OAuth mTLS client-cred stub | `TestOAuth_MTLSClientCredentialsStub` |
| AT-13 / GEN-014 | `TestAT_13_*` / `TestGEN_014_*` |
| AT-12 | `TestAT_12_DisabledConnectorBlocked` |
| AT-04 | `TestAT_04_InjectionNotObeyed`, `TestAT_04_EvalHarnessInjectionZeroTolerance` + evidence detectors |
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
