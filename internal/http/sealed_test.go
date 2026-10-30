package httpserver_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/crypto"
	httpserver "github.com/TheScottle/OpenTPRM/internal/http"
)

func TestAT_10_DataEndpoints503WhenSealed(t *testing.T) {
	app := &httpserver.App{
		Keyring:    crypto.NewSealed(),
		SealedMode: true,
		Log:        slog.New(slog.NewTextHandler(os.Stderr, nil)),
	}
	srv := app.NewServer()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/vendors", nil)
	rr := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("AT-10: want 503, got %d body=%s", rr.Code, rr.Body.String())
	}
	req2 := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	rr2 := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("health should work sealed, got %d", rr2.Code)
	}
}
