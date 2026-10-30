package httpserver_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/TheScottle/OpenTPRM/internal/authn"
)

func TestLogin_OriginAllowlistUnraid(t *testing.T) {
	app, h := testApp(t)
	app.Cfg.Server.PublicBaseURL = "https://192.168.1.50:8443"

	token := "csrf-login-bootstrap-token-0123456789abcdef"
	if err := authn.RegisterBootstrapToken(t.Context(), app.Store.DB(), token, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	// Seed admin via bootstrap API with LAN Origin + internal Host (Docker-style).
	body := `{"token":"` + token + `","security_admin_email":"sec@ex.com","system_admin_email":"sys@ex.com","security_admin_password":"security-admin-pass1","system_admin_password":"system-admin-pass1xx"}`
	req := httptest.NewRequest(http.MethodPost, "https://opentprm:8443/api/v1/auth/bootstrap", strings.NewReader(body))
	req.Host = "opentprm:8443"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://192.168.1.50:8443")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 201 {
		t.Fatalf("bootstrap with LAN origin / internal host: %d %s", w.Code, w.Body.String())
	}

	form := url.Values{}
	form.Set("email", "sec@ex.com")
	form.Set("password", "security-admin-pass1")
	req = httptest.NewRequest(http.MethodPost, "https://opentprm:8443/login", strings.NewReader(form.Encode()))
	req.Host = "opentprm:8443"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://192.168.1.50:8443")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login want redirect, got %d %s", w.Code, w.Body.String())
	}
}

func TestLogin_RejectsTrueCrossSite(t *testing.T) {
	app, h := testApp(t)
	_ = app
	form := url.Values{}
	form.Set("email", "sec@ex.com")
	form.Set("password", "security-admin-pass1")
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Host = "192.168.1.50:8443"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d %s", w.Code, w.Body.String())
	}
}

func TestLogin_LoopbackAllowsMatchingOriginDespiteCrossSiteSFS(t *testing.T) {
	app, h := testApp(t)
	app.Cfg.Server.PublicBaseURL = "https://127.0.0.1:8443"
	token := "csrf-loopback-bootstrap-token-0123456789ab"
	if err := authn.RegisterBootstrapToken(t.Context(), app.Store.DB(), token, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	body := `{"token":"` + token + `","security_admin_email":"sec2@ex.com","system_admin_email":"sys2@ex.com","security_admin_password":"security-admin-pass1","system_admin_password":"system-admin-pass1xx"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/bootstrap", strings.NewReader(body))
	req.Host = "localhost:8443"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://127.0.0.1:8443")
	req.Header.Set("Sec-Fetch-Site", "cross-site") // browsers sometimes mis-label local HTTPS
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 201 {
		t.Fatalf("bootstrap: %d %s", w.Code, w.Body.String())
	}

	form := url.Values{}
	form.Set("email", "sec2@ex.com")
	form.Set("password", "security-admin-pass1")
	req = httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Host = "localhost:8443"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://127.0.0.1:8443")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login want redirect, got %d %s", w.Code, w.Body.String())
	}
}

