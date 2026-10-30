package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/ai"
	"github.com/TheScottle/OpenTPRM/internal/authz"
	"github.com/TheScottle/OpenTPRM/internal/store"
)

func TestAI_CallLogWrites(t *testing.T) {
	st, ctx := testStore(t)
	got, err := st.InsertAICallLog(ctx, store.AICallLog{
		EndpointID: "ep1", ModelDigest: "sha256:abc", TemplateHash: "t1",
		InputHash: "in", OutputHash: "out", Tokens: 12, LatencyMs: 5, Principal: "analyst1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID == "" || got.CreatedAt == "" {
		t.Fatalf("%+v", got)
	}
	list, err := st.ListAICallLogs(ctx, 10)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %d", err, len(list))
	}
}

func TestAI_AcceptSuggestionCitationPath(t *testing.T) {
	st, ctx := testStore(t)
	cites, _ := json.Marshal([]ai.Citation{{SourceID: "ev1", Quote: "encrypts data at rest", Page: 1}})
	sug, err := st.CreateSuggestion(ctx, store.Suggestion{
		Kind: "soc_field", PayloadJSON: `{"field":"encryption"}`, CitationsJSON: string(cites),
	})
	if err != nil {
		t.Fatal(err)
	}
	src := "The vendor encrypts data at rest using AES-256."
	got, err := st.AcceptSuggestion(ctx, sug.ID, src, "approver1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "accepted" {
		t.Fatalf("%+v", got)
	}
	_, err = st.AcceptSuggestion(ctx, sug.ID, src, "approver1")
	if !errors.Is(err, ai.ErrSuggestionNotProposed) {
		t.Fatalf("re-accept: %v", err)
	}
}

func TestAT_06_DecideChangeRequestStaleAndSOD(t *testing.T) {
	st, ctx := testStore(t)
	cr, err := st.CreateChangeRequest(ctx, store.ChangeRequest{
		Action: "due_date_set", TargetType: "finding", TargetID: "f1",
		PatchJSON: `{"due":"2026-01-01"}`, PatchSHA256: "abc", TargetETag: "etag-1",
		DelegatorID: "analyst1", Rationale: "extend",
	})
	if err != nil {
		t.Fatal(err)
	}
	approverCtx := authz.WithContext(context.Background(), authz.Context{
		PrincipalID: "approver1", PrincipalType: authz.PrincipalWorkforce,
		Roles: []string{"approver"}, AAL: 2,
	})
	_, err = st.DecideChangeRequest(approverCtx, cr.ID, "approved", "approver1", "etag-stale")
	if !errors.Is(err, store.ErrStaleChangeRequest) {
		t.Fatalf("AT-06 stale: %v", err)
	}
	_, err = st.DecideChangeRequest(ctx, cr.ID, "approved", "analyst1", "etag-1")
	if err == nil {
		t.Fatal("SOD dual-control: requester must not approve")
	}
	got, err := st.DecideChangeRequest(approverCtx, cr.ID, "approved", "approver1", "etag-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "approved" {
		t.Fatalf("%+v", got)
	}
}
