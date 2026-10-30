package httpserver

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TheScottle/OpenTPRM/internal/authn"
	"github.com/TheScottle/OpenTPRM/internal/authz"
	"github.com/TheScottle/OpenTPRM/internal/gateway"
	"github.com/TheScottle/OpenTPRM/internal/mcp"
)

func (a *App) ensureGateway() *gateway.Gateway {
	if a.GW != nil {
		return a.GW
	}
	reg := mcp.DefaultRegistry()
	a.GW = gateway.New(a.PDP, reg)
	return a.GW
}

func (a *App) ensureAS() *authn.AuthorizationServer {
	if a.AS != nil {
		return a.AS
	}
	ttl := authn.AccessTokenTTL
	if a.Cfg.Agents.OAuth.AccessTokenTTL != "" {
		if d, err := time.ParseDuration(a.Cfg.Agents.OAuth.AccessTokenTTL); err == nil {
			ttl = d
		}
	}
	a.AS = authn.NewAuthorizationServer(ttl, a.Cfg.Agents.OAuth.RequireSenderConstraint)
	return a.AS
}

// EnsureASForTest exposes the authorization server for integration tests.
func (a *App) EnsureASForTest() *authn.AuthorizationServer {
	return a.ensureAS()
}

func (a *App) handleMCP(w http.ResponseWriter, r *http.Request) {
	gw := a.ensureGateway()
	s := &mcp.Server{
		Origins: []string{a.Cfg.Server.PublicBaseURL},
		ListFn:  gw.VisibleTools,
		Tasks:   gw.Tasks,
		CallFn: func(req *http.Request, agent, delegator authz.Context, tool string, args json.RawMessage) (json.RawMessage, int, string) {
			res := gw.Call(req.Context(), agent, delegator, tool, args)
			if !res.OK {
				return nil, res.Status, res.Error
			}
			return res.Result, 200, ""
		},
	}
	s.ServeHTTP(w, r)
}

func (a *App) handlePRM(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"resource":                             a.Cfg.Server.PublicBaseURL + "/mcp",
		"authorization_servers":                []string{a.Cfg.Server.PublicBaseURL},
		"scopes_supported":                     []string{"tprm.read", "tprm.content.read", "tprm.suggest", "tprm.change.request", "tprm.restricted.read"},
		"bearer_methods_supported":             []string{"header"},
		"resource_signing_alg_values_supported": []string{"ES256", "EdDSA"},
	})
}

func (a *App) handleASMeta(w http.ResponseWriter, r *http.Request) {
	base := a.Cfg.Server.PublicBaseURL
	writeJSON(w, 200, map[string]any{
		"issuer":                               base,
		"authorization_endpoint":               base + "/oauth/authorize",
		"token_endpoint":                       base + "/oauth/token",
		"code_challenge_methods_supported":     []string{"S256"},
		"dpop_signing_alg_values_supported":    []string{"ES256", "EdDSA"},
		"grant_types_supported":                []string{"authorization_code", "client_credentials", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"private_key_jwt", "none"},
	})
}

func (a *App) handleOAuthAuthorize(w http.ResponseWriter, r *http.Request) {
	as := a.ensureAS()
	q := r.URL.Query()
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		q = r.Form
	}
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	challenge := q.Get("code_challenge")
	method := q.Get("code_challenge_method")
	state := q.Get("state")
	audience := q.Get("resource")
	if audience == "" {
		audience = a.Cfg.Server.PublicBaseURL + "/mcp"
	}
	scopes := strings.Fields(q.Get("scope"))
	if len(scopes) == 0 {
		scopes = []string{"tprm.read"}
	}
	if clientID == "" || redirectURI == "" {
		writeJSON(w, 400, map[string]any{"error": "invalid_request", "error_description": "client_id and redirect_uri required"})
		return
	}
	if _, err := as.Clients.Get(clientID); err != nil {
		writeJSON(w, 400, map[string]any{"error": "unauthorized_client", "error_description": err.Error()})
		return
	}
	if err := as.Clients.ValidateRedirect(clientID, redirectURI); err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	if challenge == "" || strings.ToUpper(method) != "S256" {
		writeJSON(w, 400, map[string]any{"error": "invalid_request", "error_description": "PKCE S256 required"})
		return
	}
	ac := a.authContext(r)
	if !ac.Valid() || ac.PrincipalID == "" || ac.PrincipalID == "anonymous" {
		writeJSON(w, 401, map[string]any{"error": "login_required", "error_description": "authenticate before authorize"})
		return
	}
	code, err := as.Codes.Issue(clientID, ac.PrincipalID, redirectURI, audience, scopes, challenge, method)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	u, err := url.Parse(redirectURI)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid_request"})
		return
	}
	vals := u.Query()
	vals.Set("code", code)
	if state != "" {
		vals.Set("state", state)
	}
	u.RawQuery = vals.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (a *App) handleOAuthToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProblem(w, 405, "method_not_allowed", "POST required")
		return
	}
	as := a.ensureAS()
	_ = r.ParseForm()
	grant := r.FormValue("grant_type")
	if grant == "" {
		grant = "client_credentials"
	}

	dpopThumb, dpopErr := as.ExtractDPoPThumbprint(r)
	if dpopErr != nil {
		status := 401
		w.Header().Set("WWW-Authenticate", `DPoP error="invalid_dpop_proof"`)
		writeJSON(w, status, map[string]any{"error": "invalid_dpop_proof", "error_description": dpopErr.Error()})
		return
	}

	switch grant {
	case "client_credentials":
		clientID := r.FormValue("client_id")
		if clientID == "" {
			clientID = "dev-client"
		}
		audience := r.FormValue("resource")
		if audience == "" {
			audience = a.Cfg.Server.PublicBaseURL + "/mcp"
		}
		scopes := strings.Fields(r.FormValue("scope"))
		if len(scopes) == 0 {
			scopes = []string{"tprm.read"}
		}
		issued, err := as.IssueOpaqueAccessToken(clientID, clientID, audience, scopes, dpopThumb)
		if err != nil {
			status := 400
			if err == authn.ErrMissingDPoP {
				status = 401
				w.Header().Set("WWW-Authenticate", `DPoP error="invalid_dpop_proof"`)
			}
			writeJSON(w, status, map[string]any{"error": "invalid_request", "error_description": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{
			"access_token": issued.AccessToken,
			"token_type":   issued.TokenType,
			"expires_in":   issued.ExpiresIn,
			"scope":        issued.Scope,
		})
	case "authorization_code":
		clientID := r.FormValue("client_id")
		redirectURI := r.FormValue("redirect_uri")
		code := r.FormValue("code")
		verifier := r.FormValue("code_verifier")
		ac, err := as.Codes.Consume(code, clientID, redirectURI, verifier)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": "invalid_grant", "error_description": err.Error()})
			return
		}
		issued, err := as.IssueOpaqueAccessToken(ac.ClientID, ac.UserID, ac.Audience, ac.Scopes, dpopThumb)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": "invalid_request", "error_description": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{
			"access_token": issued.AccessToken,
			"token_type":   issued.TokenType,
			"expires_in":   issued.ExpiresIn,
			"scope":        issued.Scope,
		})
	default:
		writeJSON(w, 400, map[string]any{"error": "unsupported_grant_type"})
	}
}
