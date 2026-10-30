package store_test

import (
	"testing"
	"time"

	"github.com/TheScottle/OpenTPRM/internal/domain/risk"
	"github.com/TheScottle/OpenTPRM/internal/store"
	"github.com/google/uuid"
)

func TestFND_RSK_RemediationAndRegister(t *testing.T) {
	st, ctx := testStore(t)
	vid := uuid.Must(uuid.NewV7()).String()
	eid := uuid.Must(uuid.NewV7()).String()
	if err := st.CreateVendor(ctx, store.Vendor{ID: vid, LegalName: "RiskCo", CreatedBy: "analyst1", UpdatedBy: "analyst1"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateEngagement(ctx, store.Engagement{
		ID: eid, ThirdPartyID: vid, RelationshipOwner: "owner1", CreatedBy: "analyst1", UpdatedBy: "analyst1",
	}); err != nil {
		t.Fatal(err)
	}
	f, err := st.CreateFinding(ctx, store.Finding{EngagementID: eid, Title: "MFA gap", Severity: "high"}, "analyst1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.TransitionFinding(ctx, f.ID, "acknowledged", "analyst1", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := st.TransitionFinding(ctx, f.ID, "plan_agreed", "analyst1", ""); err != nil {
		t.Fatal(err)
	}
	plan, err := st.UpsertRemediationPlan(ctx, store.RemediationPlan{
		FindingID: f.ID, StepsJSON: `[{"step":"enable MFA"}]`, Owner: "vendor", DueDate: time.Now().UTC().AddDate(0, 0, 30).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.GetRemediationPlan(ctx, f.ID)
	if err != nil || got.ID != plan.ID {
		t.Fatal(err)
	}
	if _, err := st.TransitionFinding(ctx, f.ID, "closed", "analyst1", ""); err == nil {
		t.Fatal("closure without evidence must fail")
	}
	rr, err := st.PersistRiskResult(ctx, eid, "", "analyst1", risk.Input{
		QuestionnaireScore: 0.8, Assurance: 0.7, HighFindings: 1, Sensitivity: 3, Criticality: 3, Regulatory: 2,
		Access: 2, PrivilegedAccess: 1, ExternalImpact: 2, AIUse: 1, FourthParty: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rr.FormulaVersion != "v1" || rr.ResidualBand == "" {
		t.Fatalf("risk result incomplete: %+v", rr)
	}
	list, err := st.ListRiskResults(ctx, eid)
	if err != nil || len(list) != 1 {
		t.Fatalf("register: %v len=%d", err, len(list))
	}
}

func TestCON_ObligationsAndFlowDown(t *testing.T) {
	st, ctx := testStore(t)
	vid := uuid.Must(uuid.NewV7()).String()
	eid := uuid.Must(uuid.NewV7()).String()
	_ = st.CreateVendor(ctx, store.Vendor{ID: vid, LegalName: "FlowCo", CreatedBy: "analyst1", UpdatedBy: "analyst1"})
	if err := st.CreateEngagement(ctx, store.Engagement{
		ID: eid, ThirdPartyID: vid, RelationshipOwner: "owner1", CreatedBy: "analyst1", UpdatedBy: "analyst1",
	}); err != nil {
		t.Fatal(err)
	}
	c, err := st.CreateClient(ctx, store.ClientRecord{Name: "BigLaw Client", CreatedBy: "analyst1", UpdatedBy: "analyst1"})
	if err != nil {
		t.Fatal(err)
	}
	req, err := st.CreateClientRequirement(ctx, store.ClientRequirement{
		ClientID: c.ID, Text: "No training on client data", CreatedBy: "analyst1",
	})
	if err != nil {
		t.Fatal(err)
	}
	ob, err := st.FlowDownRequirement(ctx, req.ID, eid, "analyst1")
	if err != nil {
		t.Fatal(err)
	}
	if ob.Source != "client_ocg" || ob.EngagementID != eid {
		t.Fatalf("flow-down: %+v", ob)
	}
	obs, err := st.ListObligations(ctx, eid)
	if err != nil || len(obs) != 1 {
		t.Fatalf("obligations: %v", err)
	}
	contract, err := st.CreateContract(ctx, store.ContractRecord{
		EngagementID: eid, Title: "MSA", CreatedBy: "analyst1", UpdatedBy: "analyst1",
	})
	if err != nil {
		t.Fatal(err)
	}
	filled, err := st.ApplyDefaultContractClauses(ctx, contract.ID)
	if err != nil || filled.ClauseChecklistJSON == "" || filled.ClauseChecklistJSON == "[]" {
		t.Fatalf("clauses: %v %s", err, filled.ClauseChecklistJSON)
	}
}

func TestMON_OFF_DispositionAndChecklist(t *testing.T) {
	st, ctx := testStore(t)
	vid := uuid.Must(uuid.NewV7()).String()
	eid := uuid.Must(uuid.NewV7()).String()
	_ = st.CreateVendor(ctx, store.Vendor{ID: vid, LegalName: "MonCo", CreatedBy: "analyst1", UpdatedBy: "analyst1"})
	if err := st.CreateEngagement(ctx, store.Engagement{
		ID: eid, ThirdPartyID: vid, RelationshipOwner: "owner1", CreatedBy: "analyst1", UpdatedBy: "analyst1",
	}); err != nil {
		t.Fatal(err)
	}
	sig, err := st.CreateMonitoringSignal(ctx, store.MonitoringSignal{
		EngagementID: eid, Source: "internal", UpdatedBy: "analyst1",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.SetMonitoringDisposition(ctx, sig.ID, "triggered_assessment", "analyst1")
	if err != nil || got.Disposition != "triggered_assessment" {
		t.Fatalf("disposition: %v %+v", err, got)
	}
	if _, err := st.SetMonitoringDisposition(ctx, sig.ID, "auto_rate", "analyst1"); err == nil {
		t.Fatal("invalid disposition must fail")
	}
	cl, err := st.CreateOffboardingChecklist(ctx, eid, "analyst1")
	if err != nil || cl.Status != "open" {
		t.Fatal(err)
	}
	updated, err := st.MarkOffboardingItem(ctx, eid, "revoke_accounts", "analyst1", true, "")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status == "complete" {
		t.Fatal("single item should not complete checklist")
	}
}

func TestARC_002_LegalHoldBlocksShred(t *testing.T) {
	st, ctx := testStore(t)
	vid := uuid.Must(uuid.NewV7()).String()
	if err := st.CreateVendor(ctx, store.Vendor{ID: vid, LegalName: "HoldCo", CreatedBy: "analyst1", UpdatedBy: "analyst1"}); err != nil {
		t.Fatal(err)
	}
	hold, err := st.PlaceLegalHold(ctx, "third_party", vid, "litigation", "counsel1")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ShredVendor(ctx, vid, "admin", "retention"); err == nil {
		t.Fatal("shred must fail under legal hold")
	}
	if err := st.ReleaseLegalHold(ctx, hold.ID, "counsel1"); err == nil {
		t.Fatal("same user cannot release hold")
	}
	if err := st.ReleaseLegalHold(ctx, hold.ID, "counsel2"); err != nil {
		t.Fatal(err)
	}
	if err := st.ShredVendor(ctx, vid, "admin", "retention"); err != nil {
		t.Fatal(err)
	}
	p := store.DefaultRetention()
	deadline := store.RetentionDeadline(p, "evidence", time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
	if !deadline.After(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("evidence retention too short: %v", deadline)
	}
	if store.BackupRetentionNotice(p) == "" {
		t.Fatal("backup notice required")
	}
}
