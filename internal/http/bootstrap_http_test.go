package httpserver_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TheScottle/OpenTPRM/internal/authn"
)

func TestOPS_003_BootstrapHTTPConsume(t *testing.T) {
	app, h := testApp(t)
	token := "live-prep-bootstrap-token-hex-0123456789abcdef"
	if err := authn.RegisterBootstrapToken(t.Context(), app.Store.DB(), token, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(map[string]string{
		"token":                token,
		"security_admin_email": "sec@example.com",
		"system_admin_email":   "sys@example.com",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/bootstrap", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("bootstrap: %d %s", w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["security_administrator_id"] == nil || out["system_administrator_id"] == nil {
		t.Fatalf("missing ids: %v", out)
	}

	// Replay must fail (self-destruct).
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/bootstrap", bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w2, req2)
	if w2.Code != http.StatusConflict {
		t.Fatalf("replay want 409, got %d %s", w2.Code, w2.Body.String())
	}

	reqUI := httptest.NewRequest(http.MethodGet, "/bootstrap", nil)
	wUI := httptest.NewRecorder()
	h.ServeHTTP(wUI, reqUI)
	if wUI.Code != http.StatusOK || !bytes.Contains(wUI.Body.Bytes(), []byte("First login")) {
		t.Fatalf("bootstrap UI: %d %s", wUI.Code, wUI.Body.String())
	}
}
