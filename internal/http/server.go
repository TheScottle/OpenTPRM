package httpserver

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TheScottle/OpenTPRM/internal/audit"
	"github.com/TheScottle/OpenTPRM/internal/authn"
	"github.com/TheScottle/OpenTPRM/internal/authz"
	"github.com/TheScottle/OpenTPRM/internal/blob"
	"github.com/TheScottle/OpenTPRM/internal/config"
	"github.com/TheScottle/OpenTPRM/internal/crypto"
	"github.com/TheScottle/OpenTPRM/internal/domain/exception"
	"github.com/TheScottle/OpenTPRM/internal/gateway"
	"github.com/TheScottle/OpenTPRM/internal/portal"
	"github.com/TheScottle/OpenTPRM/internal/store"
	"github.com/TheScottle/OpenTPRM/web"
)

// App wires dependencies for Listener A.
type App struct {
	Cfg     config.Config
	Keyring *crypto.Keyring
	Store   *store.Store
	Blobs   *blob.Store
	Audit   *audit.Logger
	PDP     *authz.PDP
	GW      *gateway.Gateway
	Log     *slog.Logger
	Sessions     *authn.SessionStore
	Challenges   *authn.ChallengeStore
	Credentials  *authn.CredentialStore
	BreakGlass   *authn.BreakGlassRegistry
	AS           *authn.AuthorizationServer
	Idempotency  *IdempotencyStore
	Templates    *template.Template
	// AllowDevHeaders permits X-OpenTPRM-* bootstrap auth outside production.
	AllowDevHeaders bool

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
	mux.HandleFunc("/oauth/token", a.middleware(a.handleOAuthToken))
	mux.HandleFunc("/oauth/authorize", a.middleware(a.handleOAuthAuthorize))
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS()))))
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

		// CSRF + Origin checks on state-changing methods (SEC-WEB / SEC-AZ-001).
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			// Allow browser Origin against request Host and configured public_base_url (Unraid LAN URL).
			if authn.CheckOriginRejectsCrossSite(r, a.originAllowedHosts(r)...) {
				writeProblem(w, http.StatusForbidden, "csrf", "cross-site request rejected")
				return
			}
		}
		if a.Sessions != nil && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if c, err := r.Cookie(authn.SessionCookie); err == nil && c.Value != "" {
				sess, err := a.Sessions.LookupByID(r.Context(), c.Value)
				if err == nil {
					token := r.Header.Get(authn.CSRFHeader)
					if token == "" {
						_ = r.ParseForm()
						token = r.FormValue(authn.CSRFFormField)
					}
					if err := authn.ValidateCSRF(sess, token); err != nil {
						writeProblem(w, http.StatusForbidden, "csrf", "csrf validation failed")
						return
					}
				}
			}
		}

		// Session / principal gate (SEC-AZ-001): public allow-list or authenticated principal.
		ac := a.authContext(r)
		if !a.requireAuthOrPublic(w, r, ac) {
			return
		}
		next(w, r)
	}
}

func (a *App) handleUI(w http.ResponseWriter, r *http.Request) {
	a.ensureTemplates()
	ac := a.authContext(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	switch {
	case r.URL.Path == "/login" || r.URL.Path == "/login/":
		a.handleLoginUI(w, r)
	case r.URL.Path == "/logout" || r.URL.Path == "/logout/":
		a.handleLogoutUI(w, r)
	case r.URL.Path == "/bootstrap" || r.URL.Path == "/bootstrap/":
		if !a.bootstrapPending(r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		data := map[string]any{"Title": "First login bootstrap"}
		if err := a.Templates.ExecuteTemplate(w, "bootstrap.tmpl", data); err != nil {
			writeProblem(w, 500, "error", "template render failed")
		}
	case r.URL.Path == "/" || r.URL.Path == "/home":
		data := map[string]any{
			"Title": "Analyst home", "User": ac.PrincipalID, "Roles": ac.Roles,
			"IsAdmin": ac.HasRole("security_administrator") || ac.HasRole("system_administrator"),
		}
		if err := a.Templates.ExecuteTemplate(w, "home.tmpl", data); err != nil {
			writeProblem(w, 500, "error", "template render failed")
		}
	case r.URL.Path == "/vendors" || r.URL.Path == "/vendors/":
		a.handleVendorsUI(w, r, ac)
	case r.URL.Path == "/change-requests" || r.URL.Path == "/change-requests/":
		a.handleChangeRequestUI(w, r, ac)
	case r.URL.Path == "/intakes" || r.URL.Path == "/intakes/":
		a.handleIntakeQueueUI(w, r, ac)
	case r.URL.Path == "/answer-library" || r.URL.Path == "/answer-library/":
		a.handleAnswerLibraryUI(w, r, ac)
	case r.URL.Path == "/exceptions" || r.URL.Path == "/exceptions/":
		a.handleExceptionUI(w, r, ac)
	case r.URL.Path == "/me/agent-grants" || r.URL.Path == "/me/agent-grants/":
		a.handleAgentGrantsUI(w, r, ac)
	case r.URL.Path == "/admin/users" || r.URL.Path == "/admin/users/":
		a.handleAdminUsersUI(w, r, ac)
	case r.URL.Path == "/admin/keys" || r.URL.Path == "/admin/keys/":
		a.handleAdminStubUI(w, r, ac, "keys")
	case r.URL.Path == "/admin/backups" || r.URL.Path == "/admin/backups/":
		a.handleAdminStubUI(w, r, ac, "backups")
	default:
		if strings.HasPrefix(r.URL.Path, "/change-requests/") {
			a.handleChangeRequestUI(w, r, ac)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/exceptions/") {
			a.handleExceptionUI(w, r, ac)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/me/agent-grants/") {
			a.handleAgentGrantsUI(w, r, ac)
			return
		}
		http.NotFound(w, r)
	}
}

func (a *App) handleAnswerLibraryUI(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	ctx := authz.WithContext(r.Context(), ac)
	vendorID := r.URL.Query().Get("vendor_id")
	var (
		entries []store.AnswerLibraryEntry
		vendors []store.Vendor
		vname   string
	)
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		if !a.authorize(w, ac, authz.ActionVendorWrite, authz.Resource{Type: "answer_library", ID: "*"}) {
			return
		}
		entry := store.AnswerLibraryEntry{
			VendorID: r.FormValue("vendor_id"), QuestionKey: r.FormValue("question_key"),
			AnswerJSON: r.FormValue("answer_json"), UpdatedBy: ac.PrincipalID,
		}
		if entry.AnswerJSON == "" {
			entry.AnswerJSON = `""`
		}
		if _, err := a.Store.UpsertAnswerLibrary(ctx, entry); err != nil {
			writeProblem(w, 400, "bad_request", err.Error())
			return
		}
		http.Redirect(w, r, "/answer-library?vendor_id="+urlQueryEscape(entry.VendorID), http.StatusSeeOther)
		return
	}
	if a.Store != nil && ac.Authenticated() {
		vendors, _ = a.Store.ListVendors(ctx)
		if vendorID != "" {
			entries, _ = a.Store.ListAnswerLibrary(ctx, vendorID)
			if v, err := a.Store.GetVendor(ctx, vendorID); err == nil {
				vname = v.LegalName
			}
		}
	}
	canWrite := ac.HasRole("risk_analyst") || ac.HasRole("tprm_program_manager") || ac.HasRole("relationship_owner")
	data := map[string]any{
		"Title": "Answer library", "User": ac.PrincipalID, "Roles": ac.Roles,
		"VendorID": vendorID, "VendorName": vname, "Entries": entries, "Vendors": vendors,
		"CanWrite": canWrite, "CSRFToken": a.csrfForRequest(r),
		"IsAdmin": ac.HasRole("security_administrator") || ac.HasRole("system_administrator"),
	}
	if err := a.Templates.ExecuteTemplate(w, "answer_library.tmpl", data); err != nil {
		writeProblem(w, 500, "error", "template render failed")
	}
}

func urlQueryEscape(s string) string {
	return url.QueryEscape(s)
}

func (a *App) csrfForRequest(r *http.Request) string {
	if a.Sessions == nil {
		return ""
	}
	c, err := r.Cookie(authn.SessionCookie)
	if err != nil || c.Value == "" {
		return ""
	}
	sess, err := a.Sessions.LookupByID(r.Context(), c.Value)
	if err != nil {
		return ""
	}
	tok, err := a.Sessions.IssueCSRF(r.Context(), sess)
	if err != nil {
		return ""
	}
	return tok
}

func (a *App) handleExceptionUI(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	ctx := authz.WithContext(r.Context(), ac)
	path := strings.TrimPrefix(r.URL.Path, "/exceptions/")
	path = strings.Trim(path, "/")

	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		if r.FormValue("action") == "create" || (path == "" && r.FormValue("engagement_id") != "") {
			if !a.authorize(w, ac, authz.ActionVendorWrite, authz.Resource{Type: "exception", ID: "*"}) {
				return
			}
			rec := store.ExceptionRecord{
				EngagementID: r.FormValue("engagement_id"),
				Scope:        r.FormValue("scope"),
				Rationale:    r.FormValue("rationale"),
				Requester:    ac.PrincipalID,
				CreatedBy:    ac.PrincipalID,
				UpdatedBy:    ac.PrincipalID,
			}
			if _, err := a.Store.CreateException(ctx, rec); err != nil {
				writeProblem(w, 400, "bad_request", err.Error())
				return
			}
			http.Redirect(w, r, "/exceptions", http.StatusSeeOther)
			return
		}
		if strings.HasSuffix(path, ":approve") {
			if ac.PrincipalType == authz.PrincipalAgent {
				writeProblem(w, 403, "forbidden", "agents cannot approve")
				return
			}
			id := strings.TrimSuffix(path, ":approve")
			if !a.authorize(w, ac, authz.ActionExceptionApprove, authz.Resource{Type: "exception", ID: id}) {
				return
			}
			if a.Store == nil || a.Keyring == nil {
				writeProblem(w, 503, "unavailable", "store unavailable")
				return
			}
			residual := r.FormValue("residual_rating")
			if residual == "" {
				residual = "high"
			}
			conds := []string{}
			if c := strings.TrimSpace(r.FormValue("conditions")); c != "" {
				conds = append(conds, c)
			}
			payload := exception.Payload{
				ExceptionID:    id,
				ApproverID:     ac.PrincipalID,
				ResidualRating: residual,
				Conditions:     conds,
				DecidedAt:      time.Now().UTC(),
				EvidenceHashes: []string{},
			}
			body, err := payload.CanonicalJSON()
			if err != nil {
				writeProblem(w, 500, "error", "canonical failed")
				return
			}
			sig, err := a.Keyring.SignEd25519(body)
			if err != nil {
				writeProblem(w, 500, "error", "sign failed")
				return
			}
			sigHex := hex.EncodeToString(sig)
			_, err = a.Store.ApproveException(ctx, id, ac.PrincipalID, payload, sigHex)
			if err != nil {
				status := 422
				if err == store.ErrSOD2RequesterApprover {
					status = 403
				}
				writeProblem(w, status, "approve_failed", err.Error())
				return
			}
			http.Redirect(w, r, "/exceptions", http.StatusSeeOther)
			return
		}
	}

	var items []store.ExceptionRecord
	if a.Store != nil && ac.Authenticated() {
		items, _ = a.Store.ListExceptions(ctx, "")
	}
	canWrite := ac.HasRole("risk_analyst") || ac.HasRole("tprm_program_manager") || ac.HasRole("relationship_owner")
	data := map[string]any{
		"Title": "Exceptions", "User": ac.PrincipalID, "Roles": ac.Roles, "Items": items,
		"CanApprove": ac.HasRole("approver"), "CanWrite": canWrite,
		"CSRFToken": a.csrfForRequest(r),
		"IsAdmin":   ac.HasRole("security_administrator") || ac.HasRole("system_administrator"),
	}
	if err := a.Templates.ExecuteTemplate(w, "exceptions.tmpl", data); err != nil {
		writeProblem(w, 500, "error", "template render failed")
	}
}

func (a *App) handleAgentGrantsUI(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	ctx := authz.WithContext(r.Context(), ac)
	path := strings.TrimPrefix(r.URL.Path, "/me/agent-grants/")
	path = strings.Trim(path, "/")

	if r.Method == http.MethodPost && strings.HasSuffix(path, ":revoke") {
		id := strings.TrimSuffix(path, ":revoke")
		if a.Store == nil {
			writeProblem(w, 503, "unavailable", "store unavailable")
			return
		}
		if _, err := a.Store.RevokeAgentClientForOwner(ctx, id, ac.PrincipalID); err != nil {
			writeProblem(w, 422, "revoke_failed", err.Error())
			return
		}
		http.Redirect(w, r, "/me/agent-grants", http.StatusSeeOther)
		return
	}

	var items []store.AgentClient
	if a.Store != nil && ac.Authenticated() {
		all, _ := a.Store.ListAgentClients(ctx)
		for _, c := range all {
			if c.OwnerUserID == ac.PrincipalID {
				items = append(items, c)
			}
		}
	}
	data := map[string]any{
		"Title": "My agent grants", "User": ac.PrincipalID, "Roles": ac.Roles, "Items": items,
		"CSRFToken": a.csrfForRequest(r),
		"IsAdmin": ac.HasRole("security_administrator") || ac.HasRole("system_administrator"),
	}
	if err := a.Templates.ExecuteTemplate(w, "agent_grants.tmpl", data); err != nil {
		writeProblem(w, 500, "error", "template render failed")
	}
}

func (a *App) handleAdminStubUI(w http.ResponseWriter, r *http.Request, ac authz.Context, kind string) {
	if !a.authorize(w, ac, authz.ActionAdminAny, authz.Resource{Type: "admin", ID: "*"}) {
		return
	}
	heading, lede, note := "Admin", "", ""
	switch kind {
	case "keys":
		heading = "Admin keys"
		lede = "Signing and encryption key inventory stub. Rotations are dual-controlled."
		note = "Key actions dual-controlled; rotate API pending. Prefer opentprm sealed start + keyring."
	case "backups":
		heading = "Admin backups"
		lede = "Backup and restore drill status (ARC-013 verify-only)."
		note = "Use opentprm backup|restore --verify-only. Full restore write path remains refused."
	}
	data := map[string]any{
		"Title": heading, "User": ac.PrincipalID, "Heading": heading, "Lede": lede, "Note": note,
		"Items": []map[string]string{},
	}
	if err := a.Templates.ExecuteTemplate(w, "admin.tmpl", data); err != nil {
		writeProblem(w, 500, "error", "template render failed")
	}
}

func (a *App) handleChangeRequestUI(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	ctx := authz.WithContext(r.Context(), ac)
	path := strings.TrimPrefix(r.URL.Path, "/change-requests/")
	path = strings.Trim(path, "/")

	if r.Method == http.MethodPost && (strings.HasSuffix(path, ":approve") || strings.HasSuffix(path, ":reject")) {
		decision := "approved"
		suffix := ":approve"
		if strings.HasSuffix(path, ":reject") {
			decision = "rejected"
			suffix = ":reject"
		}
		id := strings.TrimSuffix(path, suffix)
		if !ac.StepUpFresh() {
			writeProblem(w, 401, "step_up_required", "change-request decision requires WebAuthn step-up")
			return
		}
		if !a.authorize(w, ac, authz.ActionChangeRequestApprove, authz.Resource{Type: "change_request", ID: id}) {
			return
		}
		if a.Store == nil {
			writeProblem(w, 503, "unavailable", "store unavailable")
			return
		}
		currentETag := r.FormValue("current_etag")
		if currentETag == "" {
			currentETag = r.Header.Get("If-Match")
		}
		_, err := a.Store.DecideChangeRequest(ctx, id, decision, ac.PrincipalID, currentETag)
		if err != nil {
			status := 422
			if err == store.ErrStaleChangeRequest {
				status = 409
			}
			writeProblem(w, status, "decide_failed", err.Error())
			return
		}
		http.Redirect(w, r, "/change-requests", http.StatusSeeOther)
		return
	}

	var items []store.ChangeRequest
	if a.Store != nil && ac.Authenticated() {
		items, _ = a.Store.ListChangeRequests(ctx)
	}
	data := map[string]any{
		"Title": "Change requests", "User": ac.PrincipalID, "Roles": ac.Roles, "Items": items,
		"CanApprove": ac.HasRole("approver"),
		"CSRFToken":  a.csrfForRequest(r),
		"IsAdmin":    ac.HasRole("security_administrator") || ac.HasRole("system_administrator"),
	}
	if err := a.Templates.ExecuteTemplate(w, "change_requests.tmpl", data); err != nil {
		writeProblem(w, 500, "error", "template render failed")
	}
}

func (a *App) ensureTemplates() {
	if a.Templates != nil {
		return
	}
	tmpl, err := template.ParseFS(web.TemplateFS, "templates/*.tmpl")
	if err != nil {
		a.Templates = template.Must(template.New("fallback").Parse(`<!DOCTYPE html><html><body><p>OpenTPRM</p></body></html>`))
		return
	}
	a.Templates = tmpl
}

func staticFS() fs.FS {
	sub, err := fs.Sub(web.StaticFS, "static")
	if err != nil {
		return web.StaticFS
	}
	return sub
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

// originAllowedHosts returns Host values that may appear in browser Origin for CSRF checks.
func (a *App) originAllowedHosts(r *http.Request) []string {
	out := make([]string, 0, 3)
	if r != nil && r.Host != "" {
		out = append(out, r.Host)
	}
	if a != nil {
		if u := strings.TrimSpace(a.Cfg.Server.PublicBaseURL); u != "" {
			out = append(out, u)
		}
	}
	if r != nil {
		if xfh := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); xfh != "" {
			// First value only; used when a reverse proxy preserves the external host.
			if i := strings.IndexByte(xfh, ','); i >= 0 {
				xfh = strings.TrimSpace(xfh[:i])
			}
			out = append(out, xfh)
		}
	}
	return out
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

// PortalEnabled reports whether Listener B should start.
func (a *App) PortalEnabled() bool {
	return a.Cfg.Server.Portal.Enabled || a.Cfg.Portal.Enabled
}

// NewPortalServer builds Listener B when portal is enabled.
func (a *App) NewPortalServer() *http.Server {
	ps := portal.NewServer(true)
	if a.Store != nil {
		ps.Store = a.Store
	}
	addr := a.Cfg.Server.Portal.Listen
	if addr == "" {
		addr = "127.0.0.1:9443"
	}
	return &http.Server{
		Addr:              addr,
		Handler:           ps.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13},
	}
}

// ListenAndServeTLS starts Listener A (and Listener B when portal.enabled).
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

	if a.PortalEnabled() {
		psrv := a.NewPortalServer()
		pln, err := net.Listen("tcp", psrv.Addr)
		if err != nil {
			return fmt.Errorf("portal listen: %w", err)
		}
		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_ = psrv.Shutdown(shutdownCtx)
		}()
		go func() {
			pcert, pkey := a.Cfg.Server.Portal.TLS.CertFile, a.Cfg.Server.Portal.TLS.KeyFile
			if pcert == "" {
				pcert, pkey = certFile, keyFile
			}
			var perr error
			if pcert != "" && pkey != "" {
				perr = psrv.ServeTLS(pln, pcert, pkey)
			} else {
				if a.Log != nil {
					a.Log.Warn("portal serving without TLS (development only)")
				}
				perr = psrv.Serve(pln)
			}
			if perr != nil && a.Log != nil && ctx.Err() == nil {
				a.Log.Error("portal server stopped", "err", perr)
			}
		}()
		if a.Log != nil {
			a.Log.Info("portal listener enabled", "listen", psrv.Addr)
		}
	}

	if certFile != "" && keyFile != "" {
		return srv.ServeTLS(ln, certFile, keyFile)
	}
	// Development only: HTTP (production Validate refuses missing TLS)
	a.Log.Warn("serving without TLS (development only)")
	return srv.Serve(ln)
}
