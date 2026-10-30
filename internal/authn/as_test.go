package authn

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAI_023_OpaqueTokenIssueVerifyHashed(t *testing.T) {
	as := NewAuthorizationServer(time.Minute, true)
	issued, err := as.IssueOpaqueAccessToken("client-1", "user-1", "https://tprm.example/mcp",
		[]string{"tprm.read"}, "thumb-abc")
	if err != nil {
		t.Fatal(err)
	}
	if len(issued.AccessToken) != 64 {
		t.Fatalf("expected 256-bit hex token, got len=%d", len(issued.AccessToken))
	}
	if _, ok := as.tokens[issued.AccessToken]; ok {
		t.Fatal("plaintext token must not be stored")
	}
	if _, ok := as.tokens[issued.IDHash]; !ok {
		t.Fatal("hash must be stored")
	}
	if issued.IDHash != HashToken(issued.AccessToken) {
		t.Fatal("id hash mismatch")
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "DPoP "+issued.AccessToken)
	req.Header.Set("DPoP", "eyJstub.proof")
	got, err := as.VerifyOpaqueAccessToken(req, "https://tprm.example/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientID != "client-1" || got.UserID != "user-1" {
		t.Fatalf("claims: %+v", got)
	}

	// Bearer refused when sender-constraint required.
	req2 := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req2.Header.Set("Authorization", "Bearer "+issued.AccessToken)
	req2.Header.Set("DPoP", "eyJstub.proof")
	if _, err := as.VerifyOpaqueAccessToken(req2, "https://tprm.example/mcp"); err != ErrBearerNotAllowed {
		t.Fatalf("got %v", err)
	}
}

func TestAI_023_DPoPHeaderPresenceStub(t *testing.T) {
	as := NewAuthorizationServer(time.Minute, true)
	issued, err := as.IssueOpaqueAccessToken("c", "u", "aud", []string{"tprm.read"}, "thumb")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "DPoP "+issued.AccessToken)
	if _, err := as.VerifyOpaqueAccessToken(req, "aud"); err != ErrMissingDPoP {
		t.Fatalf("expected missing DPoP, got %v", err)
	}
	if err := CheckDPoPHeaderPresent(req, true); err != ErrMissingDPoP {
		t.Fatalf("stub: %v", err)
	}
	req.Header.Set("DPoP", "proof")
	if err := CheckDPoPHeaderPresent(req, true); err != nil {
		t.Fatal(err)
	}
}

func TestAI_023_IssueRequiresThumbprintWhenConstrained(t *testing.T) {
	as := NewAuthorizationServer(time.Minute, true)
	if _, err := as.IssueOpaqueAccessToken("c", "u", "aud", nil, ""); err != ErrMissingDPoP {
		t.Fatalf("got %v", err)
	}
}
