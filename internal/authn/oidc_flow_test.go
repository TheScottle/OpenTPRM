package authn_test

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/TheScottle/OpenTPRM/internal/authn"
)

// TestSEC_AN_001_OIDCAuthCodePKCEAgainstFakeIdP exercises the full authorization-code + PKCE
// client against an in-process fake IdP (Keycloak-shaped paths).
func TestSEC_AN_001_OIDCAuthCodePKCEAgainstFakeIdP(t *testing.T) {
	priv, err := authn.NewTestECDSAKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()

	var pending struct {
		codeChallenge string
		nonce         string
		redirectURI   string
		clientID      string
		code          string
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/realms/firm/protocol/openid-connect/auth", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("response_type") != "code" {
			http.Error(w, "implicit refused", http.StatusBadRequest)
			return
		}
		if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
			http.Error(w, "pkce required", http.StatusBadRequest)
			return
		}
		pending.codeChallenge = q.Get("code_challenge")
		pending.nonce = q.Get("nonce")
		pending.redirectURI = q.Get("redirect_uri")
		pending.clientID = q.Get("client_id")
		pending.code = "authcode-test-1"
		loc := pending.redirectURI + "?code=" + url.QueryEscape(pending.code) + "&state=" + url.QueryEscape(q.Get("state"))
		http.Redirect(w, r, loc, http.StatusFound)
	})
	mux.HandleFunc("/realms/firm/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "authorization_code" {
			http.Error(w, "bad grant", http.StatusBadRequest)
			return
		}
		if r.Form.Get("code") != pending.code {
			http.Error(w, "bad code", http.StatusBadRequest)
			return
		}
		verifier := r.Form.Get("code_verifier")
		sum := sha256.Sum256([]byte(verifier))
		chal := base64.RawURLEncoding.EncodeToString(sum[:])
		if chal != pending.codeChallenge {
			http.Error(w, "pkce fail", http.StatusBadRequest)
			return
		}
		idTok, err := authn.SignTestIDToken(priv, authn.IDTokenClaims{
			Iss: "https://idp.example/realms/firm", Aud: []string{"opentprm"},
			Exp: now.Add(5 * time.Minute), Nonce: pending.nonce, Sub: "user-42",
			ACR: "phr", AMR: []string{"pwd", "otp"}, Email: "analyst@example.com",
		})
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "opaque-at",
			"id_token":     idTok,
			"token_type":   "Bearer",
			"expires_in":   300,
		})
	})
	idp := httptest.NewServer(mux)
	t.Cleanup(idp.Close)

	cfg := authn.OIDCConfig{
		Issuer:      "https://idp.example/realms/firm",
		ClientID:    "opentprm",
		RedirectURI: "https://app.example/api/v1/auth/oidc/callback",
		RequiredACR: []string{"phr"},
		RequiredAMR: []string{"otp", "mfa"},
	}
	client := &authn.OIDCClient{
		Cfg:          cfg,
		States:       authn.NewAuthStateStore(),
		AuthorizeURL: idp.URL + "/realms/firm/protocol/openid-connect/auth",
		TokenURL:     idp.URL + "/realms/firm/protocol/openid-connect/token",
		JWKSKey:      &priv.PublicKey,
		HTTPClient:   idp.Client(),
	}

	start, err := client.StartAuthorization(now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(start.RedirectURL, "code_challenge_method=S256") || !strings.Contains(start.RedirectURL, "response_type=code") {
		t.Fatalf("authorize url: %s", start.RedirectURL)
	}

	// Follow authorize → redirect without auto-follow so we capture Location.
	noRedir := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp2, err := noRedir.Get(start.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(resp2.Body)
		t.Fatalf("authorize: %d %s", resp2.StatusCode, b)
	}
	loc, err := url.Parse(resp2.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := loc.Query().Get("code")
	state := loc.Query().Get("state")
	if code == "" || state != start.StateID {
		t.Fatalf("callback params code=%q state=%q want state=%q", code, state, start.StateID)
	}

	tr, err := client.ExchangeCode(state, code, now)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Claims.Sub != "user-42" || tr.Claims.Email != "analyst@example.com" {
		t.Fatalf("claims: %+v", tr.Claims)
	}
	if tr.AccessToken == "" || tr.IDToken == "" {
		t.Fatal("expected tokens")
	}

	// State is single-use
	if _, err := client.ExchangeCode(state, code, now); err != authn.ErrOIDCState {
		t.Fatalf("replay state: %v", err)
	}
}

func TestSEC_AN_001_OIDCClientRejectsBadPKCEAtIdP(t *testing.T) {
	priv, err := authn.NewTestECDSAKey()
	if err != nil {
		t.Fatal(err)
	}
	_ = priv
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "pkce fail", http.StatusBadRequest)
	})
	idp := httptest.NewServer(mux)
	t.Cleanup(idp.Close)

	c := &authn.OIDCClient{
		Cfg: authn.OIDCConfig{
			Issuer: "https://idp.example/realms/firm", ClientID: "opentprm",
			RedirectURI: "https://app.example/cb",
		},
		States:     authn.NewAuthStateStore(),
		TokenURL:   idp.URL + "/token",
		HTTPClient: idp.Client(),
		JWKSKey:    &ecdsa.PublicKey{},
	}
	now := time.Now().UTC()
	start, err := c.StartAuthorization(now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.ExchangeCode(start.StateID, "x", now)
	if err == nil {
		t.Fatal("expected token error")
	}
}
