package authn

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOAuth_RefreshRotateAndReuseDetect(t *testing.T) {
	store := NewRefreshStore(time.Hour)
	plain, g, err := store.Issue("client-1", "user-1", "https://tprm/mcp", "thumb", []string{"tprm.read"})
	if err != nil {
		t.Fatal(err)
	}
	if g.FamilyID == "" || plain == "" {
		t.Fatalf("%+v", g)
	}
	next, g2, err := store.Rotate(plain)
	if err != nil {
		t.Fatal(err)
	}
	if next == plain || g2.CurrentHash == HashToken(plain) {
		t.Fatal("refresh must rotate")
	}
	// Reuse of the old token must revoke the family.
	if _, _, err := store.Rotate(plain); err != ErrRefreshReuse {
		t.Fatalf("reuse: got %v", err)
	}
	if _, _, err := store.Rotate(next); err != ErrRefreshRevoked {
		t.Fatalf("family after reuse: got %v", err)
	}
}

func TestOAuth_MTLSClientCredentialsStub(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://tprm.example/oauth/token", nil)
	if _, err := RequireClientCertificate(req, true); err != ErrMTLSRequired {
		t.Fatalf("got %v", err)
	}
	if _, err := RequireClientCertificate(req, false); err != nil {
		t.Fatal(err)
	}
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{
			Subject: pkix.Name{CommonName: "agent-bot"},
		}},
	}
	id, err := RequireClientCertificate(req, true)
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject == "" {
		t.Fatal("expected subject")
	}
	thumb, err := BindTokenToCertThumbprint(req)
	if err != nil || len(thumb) != 32 {
		t.Fatalf("thumb %q err %v", thumb, err)
	}
}
