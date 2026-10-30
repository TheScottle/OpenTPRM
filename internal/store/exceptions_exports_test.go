package store_test

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/TheScottle/OpenTPRM/internal/authz"
	"github.com/TheScottle/OpenTPRM/internal/crypto"
	"github.com/TheScottle/OpenTPRM/internal/domain/exception"
	"github.com/TheScottle/OpenTPRM/internal/domain/reporting"
	"github.com/TheScottle/OpenTPRM/internal/store"
	"github.com/google/uuid"
)

func TestEXC_CreateListApprove_SOD2(t *testing.T) {
	st, ctx := testStore(t)
	vid := uuid.Must(uuid.NewV7()).String()
	eid := uuid.Must(uuid.NewV7()).String()
	_ = st.CreateVendor(ctx, store.Vendor{ID: vid, LegalName: "ExcCo", CreatedBy: "analyst1", UpdatedBy: "analyst1"})
	if err := st.CreateEngagement(ctx, store.Engagement{
		ID: eid, ThirdPartyID: vid, RelationshipOwner: "owner1", CreatedBy: "analyst1", UpdatedBy: "analyst1",
	}); err != nil {
		t.Fatal(err)
	}
	exc, err := st.CreateException(ctx, store.ExceptionRecord{
		EngagementID: eid, Scope: "MFA gap residual", Rationale: "compensating monitoring",
		Requester: "analyst1", CreatedBy: "analyst1", UpdatedBy: "analyst1",
	})
	if err != nil {
		t.Fatal(err)
	}
	list, err := st.ListExceptions(ctx, eid)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v len=%d", err, len(list))
	}
	kr := crypto.NewSealed()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 7)
	}
	if err := kr.Unseal(key); err != nil {
		t.Fatal(err)
	}
	payload := exception.Payload{
		AssessmentID: eid, ExceptionID: exc.ID, ResidualRating: "high",
		Conditions: []string{"monitor-quarterly"}, ApproverID: "analyst1",
		DecidedAt: time.Now().UTC(), EvidenceHashes: []string{},
	}
	body, err := payload.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := kr.SignEd25519(body)
	if err != nil {
		t.Fatal(err)
	}
	sigHex := hex.EncodeToString(sig)
	if _, err := st.ApproveException(ctx, exc.ID, "analyst1", payload, sigHex); err != store.ErrSOD2RequesterApprover {
		t.Fatalf("SOD-2: got %v", err)
	}
	approverCtx := authz.WithContext(ctx, authz.Context{
		PrincipalID: "approver1", PrincipalType: authz.PrincipalWorkforce,
		Roles: []string{"approver"}, AAL: 2,
	})
	payload.ApproverID = "approver1"
	body, _ = payload.CanonicalJSON()
	sig, _ = kr.SignEd25519(body)
	approved, err := st.ApproveException(approverCtx, exc.ID, "approver1", payload, hex.EncodeToString(sig))
	if err != nil {
		t.Fatal(err)
	}
	if approved.Status != "approved" || approved.ApprovedBy != "approver1" || approved.DecisionSignature == "" {
		t.Fatalf("approve: %+v", approved)
	}
}

func TestRPT_ExportMarkingsGEN012(t *testing.T) {
	st, ctx := testStore(t)
	markings := map[string]string{
		"Privileged": "Privileged & Confidential — Prepared at the Direction of Counsel",
	}
	exp, err := st.CreateExport(ctx, store.ExportRecord{
		Format: "json", Scope: "exceptions-register", Classification: "Privileged", Requester: "analyst1",
	}, markings)
	if err != nil {
		t.Fatal(err)
	}
	if exp.Marking != markings["Privileged"] {
		t.Fatalf("marking: %q", exp.Marking)
	}
	if !exp.StepUpRequired || !reporting.SensitiveClassification(exp.Classification) {
		t.Fatal("privileged export must require step-up")
	}
	list, err := st.ListExports(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list exports: %v", err)
	}
}
