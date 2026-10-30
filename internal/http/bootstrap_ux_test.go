package httpserver_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TheScottle/OpenTPRM/internal/authn"
)

func TestBootstrap_SuccessPointsToLogin(t *testing.T) {
	app, h := testApp(t)
	token := "ux-bootstrap-token-hex-0123456789abcdef0123"
	if err := authn.RegisterBootstrapToken(t.Context(), app.Store.DB(), token, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{
		"token": token,
		"security_admin_email": "secux@example.com", "system_admin_email": "sysux@example.com",
		"security_admin_password": "security-admin-pass1", "system_admin_password": "system-admin-pass1xx",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/bootstrap", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 201 {
		t.Fatalf("bootstrap: %d %s", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte(`"login_url":"/login?bootstrap=1"`)) {
		t.Fatalf("missing login_url: %s", w.Body.String())
	}
	if bytes.Contains(w.Body.Bytes(), []byte("enroll passkeys via POST")) {
		t.Fatal("must not instruct API-only passkey enroll as next step")
	}

	wLogin := httptest.NewRecorder()
	h.ServeHTTP(wLogin, httptest.NewRequest(http.MethodGet, "/login?bootstrap=1&email=secux%40example.com", nil))
	if wLogin.Code != 200 {
		t.Fatalf("login: %d", wLogin.Code)
	}
	if !bytes.Contains(wLogin.Body.Bytes(), []byte("Administrators created")) {
		t.Fatalf("missing bootstrap success banner: %s", wLogin.Body.String())
	}
	if !bytes.Contains(wLogin.Body.Bytes(), []byte(`value="secux@example.com"`)) {
		t.Fatalf("email not prefilled: %s", wLogin.Body.String())
	}

	js := httptest.NewRecorder()
	h.ServeHTTP(js, httptest.NewRequest(http.MethodGet, "/static/bootstrap.js", nil))
	if !strings.Contains(js.Body.String(), "/login?bootstrap=1") {
		t.Fatal("bootstrap.js must redirect to /login on success")
	}
}
