package httpserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/TheScottle/OpenTPRM/internal/audit"
	"github.com/TheScottle/OpenTPRM/internal/authz"
	"github.com/TheScottle/OpenTPRM/internal/config"
	"github.com/TheScottle/OpenTPRM/internal/crypto"
	"github.com/TheScottle/OpenTPRM/internal/gateway"
	"github.com/TheScottle/OpenTPRM/internal/store"
)

// App wires dependencies for Listener A.
type App struct {
	Cfg     config.Config
	Keyring *crypto.Keyring
	Store   *store.Store
	Audit   *audit.Logger
	PDP     *authz.PDP
	GW      *gateway.Gateway
	Log     *slog.Logger

	// SealedMode is true when master key is unavailable (AT-10).
	SealedMode bool
}

// NewServer builds the internal HTTPS server.
func (a *App) NewServer() *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/health/live", a.handleLive)
	mux.HandleFunc("/health/ready", a.handleReady)
	mux.HandleFunc("/mcp", a.middleware(a.handleMCP))
	mux.HandleFunc("/.well-known/oauth-protected-resource", a.middleware(a.handlePRM))
	mux.HandleFunc("/.well-known/oauth-authorization-server", a.middleware(a.handleASMeta))
	mux.HandleFunc("/api/v1/", a.middleware(a.handleAPI))
	mux.HandleFunc("/", a.middleware(a.handleUI))

	return &http.Server{
		Addr:              a.Cfg.Server.Internal.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
	}
}

func (a *App) handleLive(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (a *App) handleReady(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if a.SealedMode || a.Keyring == nil || a.Keyring.Sealed() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"sealed"}`))
		return
	}
	if a.Store != nil {
		if err := a.Store.Ping(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"not_ready"}`))
			return
		}
	}
	_, _ = w.Write([]byte(`{"status":"ready"}`))
}

func (a *App) middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		// Request ID
		traceID := r.Header.Get("X-Request-Id")
		if traceID == "" {
			traceID = fmt.Sprintf("%d", time.Now().UnixNano())
		}
		w.Header().Set("X-Request-Id", traceID)

		// Sealed mode: only health endpoints (AT-10)
		if a.SealedMode || a.Keyring == nil || a.Keyring.Sealed() {
			if r.URL.Path == "/health/live" || r.URL.Path == "/health/ready" {
				next(w, r)
				return
			}
			writeProblem(w, http.StatusServiceUnavailable, "sealed", "system is sealed; unseal required")
			return
		}
		next(w, r)
	}
}

func (a *App) handleUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>OpenTPRM</title></head><body>
<h1>OpenTPRM</h1><p>Self-hosted third-party risk management.</p>
<p><a href="/api/v1/openapi.json">OpenAPI</a></p></body></html>`)
}

func (a *App) handleAPI(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case path == "/api/v1/openapi.json":
		a.handleOpenAPI(w, r)
	case path == "/api/v1/audit:verify" || path == "/api/v1/audit/verify":
		a.handleAuditVerify(w, r)
	case len(path) >= len("/api/v1/") && path[:len("/api/v1/")] == "/api/v1/":
		a.routeAPI(w, r)
	default:
		writeProblem(w, http.StatusNotFound, "not_found", "not found")
	}
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
}

func writeProblem(w http.ResponseWriter, status int, typ, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":   "https://opentprm.local/problems/" + typ,
		"title":  http.StatusText(status),
		"status": status,
		"detail": detail,
	})
}

// ListenAndServeTLS starts Listener A.
func (a *App) ListenAndServeTLS(ctx context.Context, certFile, keyFile string) error {
	srv := a.NewServer()
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if certFile != "" && keyFile != "" {
		return srv.ServeTLS(ln, certFile, keyFile)
	}
	// Development only: HTTP (production Validate refuses missing TLS)
	a.Log.Warn("serving without TLS (development only)")
	return srv.Serve(ln)
}
