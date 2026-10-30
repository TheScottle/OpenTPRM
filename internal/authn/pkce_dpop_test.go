package authn

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAI_023_PKCEChallengeStoreAndAuthCode(t *testing.T) {
	reg := NewClientRegistry()
	if err := reg.Register(RegisteredClient{
		ID: "agent-1", RedirectURIs: []string{"https://agent.example/cb"}, Public: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := reg.ValidateRedirect("agent-1", "https://evil.example/cb"); err != ErrInvalidRedirect {
		t.Fatalf("redirect: %v", err)
	}
	if _, err := reg.Get("missing"); err != ErrUnknownClient {
		t.Fatalf("unknown: %v", err)
	}

	verifierBytes := make([]byte, 32)
	_, _ = rand.Read(verifierBytes)
	verifier := hex.EncodeToString(verifierBytes)
	challenge := S256Challenge(verifier)
	if err := VerifyPKCE(challenge, "S256", verifier); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPKCE(challenge, "S256", "wrong"); err != ErrInvalidPKCE {
		t.Fatalf("got %v", err)
	}

	codes := NewAuthCodeStore(time.Minute)
	code, err := codes.Issue("agent-1", "user-1", "https://agent.example/cb", "https://tprm/mcp",
		[]string{"tprm.read"}, challenge, "S256")
	if err != nil {
		t.Fatal(err)
	}
	ac, err := codes.Consume(code, "agent-1", "https://agent.example/cb", verifier)
	if err != nil {
		t.Fatal(err)
	}
	if ac.UserID != "user-1" || ac.ClientID != "agent-1" {
		t.Fatalf("%+v", ac)
	}
	if _, err := codes.Consume(code, "agent-1", "https://agent.example/cb", verifier); err != ErrAuthCodeUsed {
		t.Fatalf("reuse: %v", err)
	}
	if _, err := codes.Issue("c", "u", "https://x", "aud", nil, "", "S256"); err != ErrMissingPKCE {
		t.Fatalf("missing pkce: %v", err)
	}
}

func TestAI_023_DPoPProofParseVerify(t *testing.T) {
	nonces := NewDPoPNonceStore(time.Minute)
	proof, thumb, err := MintTestDPoPProof(http.MethodPost, "https://tprm.example/oauth/token", "")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://tprm.example/oauth/token", nil)
	req.Host = "tprm.example"
	req.Header.Set("DPoP", proof)
	got, err := ParseAndVerifyDPoP(req, "", nonces)
	if err != nil {
		t.Fatal(err)
	}
	if got.Thumbprint != thumb {
		t.Fatalf("thumb %s vs %s", got.Thumbprint, thumb)
	}
	// Replay jti
	req2 := httptest.NewRequest(http.MethodPost, "https://tprm.example/oauth/token", nil)
	req2.Host = "tprm.example"
	req2.Header.Set("DPoP", proof)
	if _, err := ParseAndVerifyDPoP(req2, "", nonces); err != ErrDPoPReplay {
		t.Fatalf("replay: %v", err)
	}

	as := NewAuthorizationServer(time.Minute, true)
	_ = as.Clients.Register(RegisteredClient{ID: "c1", RedirectURIs: []string{"https://agent.example/cb"}})
	dkey, err := NewTestDPoPKey()
	if err != nil {
		t.Fatal(err)
	}
	issued, err := as.IssueOpaqueAccessToken("c1", "u1", "https://tprm.example/mcp", []string{"tprm.read"}, dkey.Thumbprint)
	if err != nil {
		t.Fatal(err)
	}
	proof3, err := dkey.Proof(http.MethodPost, "https://tprm.example/mcp", issued.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	req3 := httptest.NewRequest(http.MethodPost, "https://tprm.example/mcp", nil)
	req3.Host = "tprm.example"
	req3.Header.Set("Authorization", "DPoP "+issued.AccessToken)
	req3.Header.Set("DPoP", proof3)
	if _, err := as.VerifyOpaqueAccessToken(req3, "https://tprm.example/mcp"); err != nil {
		t.Fatal(err)
	}
}
