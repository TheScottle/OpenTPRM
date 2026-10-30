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

func TestAuthGate_AnonymousDenied(t *testing.T) {
	app, h := testApp(t)
	app.AllowDevHeaders = false

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/vendors", nil))
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "/login") {
		t.Fatalf("UI want redirect login, got %d %s", w.Code, w.Header().Get("Location"))
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/vendors", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("API want 401, got %d %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("openapi want 401, got %d", w.Code)
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/login", nil))
	if w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte("Sign in")) {
		t.Fatalf("login page: %d %s", w.Code, w.Body.String())
	}
}

func TestAuth_PasswordLoginAndUsersCRUD(t *testing.T) {
	app, h := testApp(t)
	token := "pw-login-bootstrap-token-0123456789abcdef01"
	if err := authn.RegisterBootstrapToken(t.Context(), app.Store.DB(), token, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{
		"token":                   token,
		"security_admin_email":    "sec@example.com",
		"system_admin_email":      "sys@example.com",
		"security_admin_password": "security-admin-pass1",
		"system_admin_password":   "system-admin-pass1xx",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/bootstrap", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 201 {
		t.Fatalf("bootstrap: %d %s", w.Code, w.Body.String())
	}

	loginBody, _ := json.Marshal(map[string]string{
		"email": "sec@example.com", "password": "security-admin-pass1",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/login", bytes.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	var loginOut map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &loginOut)
	cookie := ""
	for _, c := range w.Result().Cookies() {
		if c.Name == authn.SessionCookie {
			cookie = c.Value
		}
	}
	if cookie == "" {
		t.Fatal("missing session cookie")
	}
	csrf, _ := loginOut["csrf_token"].(string)

	// Create analyst without admin role — no second admin needed.
	createBody, _ := json.Marshal(map[string]any{
		"email": "analyst@example.com", "display_name": "Analyst",
		"roles": []string{"risk_analyst"}, "password": "analyst-password-1",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader(createBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(authn.CSRFHeader, csrf)
	req.AddCookie(&http.Cookie{Name: authn.SessionCookie, Value: cookie})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 201 {
		t.Fatalf("create user: %d %s", w.Code, w.Body.String())
	}

	// Self role change denied via patch as same user — login as analyst then try.
	loginBody, _ = json.Marshal(map[string]string{
		"email": "analyst@example.com", "password": "analyst-password-1",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/login", bytes.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("analyst login: %d %s", w.Code, w.Body.String())
	}

	// Analyst cannot list users.
	var aLogin map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &aLogin)
	aCookie := ""
	for _, c := range w.Result().Cookies() {
		if c.Name == authn.SessionCookie {
			aCookie = c.Value
		}
	}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req.AddCookie(&http.Cookie{Name: authn.SessionCookie, Value: aCookie})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("analyst users list want 403, got %d %s", w.Code, w.Body.String())
	}

	// Vendor UI create with session + CSRF.
	loginBody, _ = json.Marshal(map[string]string{
		"email": "sec@example.com", "password": "security-admin-pass1",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/login", bytes.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	_ = json.Unmarshal(w.Body.Bytes(), &loginOut)
	csrf, _ = loginOut["csrf_token"].(string)
	cookie = ""
	for _, c := range w.Result().Cookies() {
		if c.Name == authn.SessionCookie {
			cookie = c.Value
		}
	}

	// Security admin lacks vendor:write in Cedar — use analyst session for vendor create API via form after granting... 
	// Analyst has vendor write. Login analyst and create via API with cookie.
	loginBody, _ = json.Marshal(map[string]string{
		"email": "analyst@example.com", "password": "analyst-password-1",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/login", bytes.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	_ = json.Unmarshal(w.Body.Bytes(), &loginOut)
	csrf, _ = loginOut["csrf_token"].(string)
	cookie = ""
	for _, c := range w.Result().Cookies() {
		if c.Name == authn.SessionCookie {
			cookie = c.Value
		}
	}
	form := strings.NewReader("action=create&legal_name=AuthGate+Vendor&csrf_token=" + csrf)
	req = httptest.NewRequest(http.MethodPost, "/vendors", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: authn.SessionCookie, Value: cookie})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("vendor form create: %d %s", w.Code, w.Body.String())
	}
}

func TestAuth_PasswordLockout(t *testing.T) {
	app, h := testApp(t)
	token := "lockout-bootstrap-token-0123456789abcdef012"
	if err := authn.RegisterBootstrapToken(t.Context(), app.Store.DB(), token, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{
		"token": token, "security_admin_email": "sec2@example.com", "system_admin_email": "sys2@example.com",
		"security_admin_password": "security-admin-pass2", "system_admin_password": "system-admin-pass2xx",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/bootstrap", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 201 {
		t.Fatalf("bootstrap: %d", w.Code)
	}
	for i := 0; i < authn.MaxFailedLogins; i++ {
		b, _ := json.Marshal(map[string]string{"email": "sec2@example.com", "password": "wrong-password!!!!!"})
		req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/login", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		w = httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 401 {
			t.Fatalf("fail %d want 401, got %d", i, w.Code)
		}
	}
	b, _ := json.Marshal(map[string]string{"email": "sec2@example.com", "password": "security-admin-pass2"})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/login", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 423 {
		t.Fatalf("locked want 423, got %d %s", w.Code, w.Body.String())
	}
}
