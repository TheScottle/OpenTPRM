package portal_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TheScottle/OpenTPRM/internal/portal"
	"github.com/TheScottle/OpenTPRM/internal/store"
)

func TestPortalDisabledByDefault(t *testing.T) {
	s := portal.NewServer(false)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rr.Code)
	}
}

func TestRouteIsolation_InternalAPINotOnPortal(t *testing.T) {
	s := portal.NewServer(true)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/vendors", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("internal API must not be on portal listener: %d", rr.Code)
	}
}

func TestPOR_002_MagicLinkIssueConsume(t *testing.T) {
	s := portal.NewServer(true)
	rr := httptest.NewRecorder()
	body := strings.NewReader("vendor_id=v1&email=vendor@example.com")
	req := httptest.NewRequest(http.MethodPost, "/portal/login", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("issue: %d %s", rr.Code, rr.Body.String())
	}
	var issued map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &issued)
	tok, _ := issued["token"].(string)
	if tok == "" {
		t.Fatal("expected token")
	}
	rr2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/portal/magic?token="+tok, nil))
	if rr2.Code != 200 {
		t.Fatalf("consume: %d %s", rr2.Code, rr2.Body.String())
	}
	rr3 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr3, httptest.NewRequest(http.MethodGet, "/portal/magic?token="+tok, nil))
	if rr3.Code != http.StatusConflict {
		t.Fatalf("reuse want 409, got %d", rr3.Code)
	}
}

type stubLister struct {
	items []store.QuestionnaireInstance
}

func (s stubLister) ListQuestionnaireInstancesByVendor(ctx context.Context, vendorID string) ([]store.QuestionnaireInstance, error) {
	var out []store.QuestionnaireInstance
	for _, it := range s.items {
		out = append(out, it)
	}
	_ = vendorID
	_ = ctx
	return out, nil
}

func TestPOR_002_PasskeyEnrollStub(t *testing.T) {
	s := portal.NewServer(true)
	body := strings.NewReader("vendor_id=v1&email=vendor@example.com&public_key=ed25519:stub")
	req := httptest.NewRequest(http.MethodPost, "/portal/passkey/enroll", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 201 {
		t.Fatalf("enroll: %d %s", rr.Code, rr.Body.String())
	}
	cred, ok := s.Passkeys.Lookup("v1", "vendor@example.com")
	if !ok || cred.ID == "" {
		t.Fatal("passkey not stored")
	}
}

func TestPOR_002_TOTPEnrollVerifyStub(t *testing.T) {
	s := portal.NewServer(true)
	body := strings.NewReader("vendor_id=v1&email=vendor@example.com")
	req := httptest.NewRequest(http.MethodPost, "/portal/totp/enroll", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 201 {
		t.Fatalf("enroll: %d %s", rr.Code, rr.Body.String())
	}
	var issued map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &issued)
	if issued["secret"] == "" {
		t.Fatal("expected secret")
	}
	now := time.Now().UTC()
	code, err := s.TOTP.CurrentCode("v1", "vendor@example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	okBody := strings.NewReader("vendor_id=v1&email=vendor@example.com&code=" + code)
	reqOK := httptest.NewRequest(http.MethodPost, "/portal/totp/verify", okBody)
	reqOK.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rrOK := httptest.NewRecorder()
	s.Handler().ServeHTTP(rrOK, reqOK)
	if rrOK.Code != 200 {
		t.Fatalf("verify ok: %d %s", rrOK.Code, rrOK.Body.String())
	}
	bad := strings.NewReader("vendor_id=v1&email=vendor@example.com&code=000000")
	req2 := httptest.NewRequest(http.MethodPost, "/portal/totp/verify", bad)
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr2, req2)
	if code == "000000" {
		t.Skip("clock hit 000000; skip negative case")
	}
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("verify bad want 401, got %d", rr2.Code)
	}
}

func TestPOR_VendorQuestionnaireListScoped(t *testing.T) {
	s := portal.NewServer(true)
	s.Store = stubLister{items: []store.QuestionnaireInstance{{ID: "qi1", EngagementID: "e1", Status: "draft"}}}
	req := httptest.NewRequest(http.MethodGet, "/portal/questionnaires", nil)
	req.Header.Set("X-OpenTPRM-Vendor", "vendor-abc")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("list: %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "vendor-abc") || !strings.Contains(rr.Body.String(), "qi1") {
		t.Fatalf("body: %s", rr.Body.String())
	}
	rr2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/portal/questionnaires", nil))
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("unauth: %d", rr2.Code)
	}
}
