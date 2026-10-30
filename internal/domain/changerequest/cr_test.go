package changerequest_test

import (
	"encoding/json"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/domain/changerequest"
)

func TestAT_06_StaleChangeRequestRefused(t *testing.T) {
	patch := json.RawMessage(`[{"op":"replace","path":"/state","value":"scoping"}]`)
	cr := changerequest.Request{
		Patch: patch, PatchSHA256: changerequest.HashPatch(patch), TargetETag: "etag-1", Status: "pending_approval",
	}
	_, err := changerequest.Approve(cr, "etag-2", patch)
	if err != changerequest.ErrStaleETag {
		t.Fatalf("AT-06: want stale, got %v", err)
	}
}

func TestAT_05_OutboundIsHumanGated(t *testing.T) {
	if !changerequest.OutboundRequiresHumanGate("questionnaire_send") {
		t.Fatal("AT-05: questionnaire_send must require human gate")
	}
}
