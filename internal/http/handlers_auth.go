package httpserver

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/TheScottle/OpenTPRM/internal/audit"
	"github.com/TheScottle/OpenTPRM/internal/authn"
	"github.com/TheScottle/OpenTPRM/internal/authz"
)

func (a *App) handleAuth(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	path := stringsTrimPrefixAPI(r.URL.Path)
	switch {
	case path == "/auth/bootstrap" && r.Method == http.MethodPost:
		a.handleBootstrapConsume(w, r)
	case path == "/auth/password/login" && r.Method == http.MethodPost:
		a.handlePasswordLogin(w, r)
	case path == "/auth/password/change" && r.Method == http.MethodPost:
		a.handlePasswordChange(w, r, ac)
	case path == "/auth/webauthn/enroll/begin" && r.Method == http.MethodPost:
		a.handleWebAuthnEnrollBegin(w, r, ac)
	case path == "/auth/webauthn/enroll/finish" && r.Method == http.MethodPost:
		a.handleWebAuthnEnrollFinish(w, r, ac)
	case path == "/auth/webauthn/login/begin" && r.Method == http.MethodPost:
		a.handleWebAuthnLoginBegin(w, r)
	case path == "/auth/webauthn/login/finish" && r.Method == http.MethodPost:
		a.handleWebAuthnLoginFinish(w, r, "login")
	case path == "/auth/webauthn/step-up/begin" && r.Method == http.MethodPost:
		a.handleWebAuthnStepUpBegin(w, r, ac)
	case path == "/auth/webauthn/step-up/finish" && r.Method == http.MethodPost:
		a.handleWebAuthnLoginFinish(w, r, "step_up")
	case path == "/auth/logout" && r.Method == http.MethodPost:
		a.handleLogout(w, r)
	default:
		writeProblem(w, http.StatusNotFound, "not_found", "unknown auth path")
	}
}

// handleBootstrapConsume enrolls the first Security + System Administrators (OPS-003).
func (a *App) handleBootstrapConsume(w http.ResponseWriter, r *http.Request) {
	if a.Store == nil {
		writeProblem(w, http.StatusServiceUnavailable, "unavailable", "store unavailable")
		return
	}
	var body struct {
		Token                  string `json:"token"`
		SecurityAdminEmail     string `json:"security_admin_email"`
		SystemAdminEmail       string `json:"system_admin_email"`
		SecurityAdminPassword  string `json:"security_admin_password"`
		SystemAdminPassword    string `json:"system_admin_password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeProblem(w, 400, "bad_request", "invalid json")
		return
	}
	if body.Token == "" || body.SecurityAdminEmail == "" || body.SystemAdminEmail == "" {
		writeProblem(w, 400, "bad_request", "token, security_admin_email, and system_admin_email required")
		return
	}
	if body.SecurityAdminPassword == "" || body.SystemAdminPassword == "" {
		writeProblem(w, 400, "bad_request", "security_admin_password and system_admin_password required (min 15 chars)")
		return
	}
	if body.SecurityAdminEmail == body.SystemAdminEmail {
		writeProblem(w, 400, "bad_request", "security and system administrator emails must differ")
		return
	}
	secID, sysID, err := authn.ConsumeBootstrapToken(
		r.Context(), a.Store.DB(), body.Token, body.SecurityAdminEmail, body.SystemAdminEmail,
		body.SecurityAdminPassword, body.SystemAdminPassword, time.Now().UTC(),
	)
	if err == authn.ErrBootstrapUsed {
		writeProblem(w, 409, "bootstrap_used", "bootstrap token already used or expired")
		return
	}
	if err == authn.ErrPasswordPolicy || (err != nil && strings.Contains(err.Error(), "password")) {
		writeProblem(w, 400, "bad_request", err.Error())
		return
	}
	if err != nil {
		writeProblem(w, 400, "bad_request", "bootstrap failed")
		return
	}
	if a.Audit != nil {
		_ = a.Audit.Append(r.Context(), audit.Event{
			Actor: "bootstrap", Action: "bootstrap.admins_enrolled",
			ResourceType: "user", ResourceID: secID + "," + sysID, Decision: "allow",
			DiffRedacted: `{"security_admin_email":"` + body.SecurityAdminEmail + `","system_admin_email":"` + body.SystemAdminEmail + `"}`,
		})
	}
	writeJSON(w, 201, map[string]any{
		"security_administrator_id": secID,
		"system_administrator_id":   sysID,
		"login_url":                 "/login?bootstrap=1",
		"next":                      "sign in at /login with either administrator email and the password you just set",
	})
}

func (a *App) handlePasswordLogin(w http.ResponseWriter, r *http.Request) {
	if a.Store == nil || a.Sessions == nil {
		writeProblem(w, 503, "unavailable", "auth unavailable")
		return
	}
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
			writeProblem(w, 400, "bad_request", "invalid json")
			return
		}
	} else {
		_ = r.ParseForm()
		body.Email = r.FormValue("email")
		body.Password = r.FormValue("password")
	}
	now := time.Now().UTC()
	u, hash, err := authn.GetUserByEmail(r.Context(), a.Store.DB(), body.Email)
	if err == sql.ErrNoRows {
		writeProblem(w, 401, "unauthorized", "invalid credentials")
		return
	}
	if err != nil {
		writeProblem(w, 500, "error", "lookup failed")
		return
	}
	if err := authn.CheckLoginAllowed(u, now); err == authn.ErrAccountLocked {
		writeProblem(w, 423, "locked", "account locked; try again later")
		return
	}
	if err != nil {
		writeProblem(w, 401, "unauthorized", "invalid credentials")
		return
	}
	ok, verr := authn.VerifyPassword(hash, body.Password)
	if verr != nil || !ok {
		_ = authn.RecordLoginFailure(r.Context(), a.Store.DB(), u.ID, now)
		writeProblem(w, 401, "unauthorized", "invalid credentials")
		return
	}
	_ = authn.RecordLoginSuccess(r.Context(), a.Store.DB(), u.ID, now)
	sess, err := a.Sessions.Create(r.Context(), u.ID, 2, u.Roles, u.Email)
	if err != nil {
		writeProblem(w, 500, "error", "session create failed")
		return
	}
	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	authn.SetSessionCookie(w, sess.ID, secure)
	if a.Audit != nil {
		_ = a.Audit.Append(r.Context(), audit.Event{
			Actor: u.ID, Action: "auth.password_login", ResourceType: "session",
			ResourceID: sess.IDHash, Decision: "allow",
		})
	}
	writeJSON(w, 200, map[string]any{
		"session": true, "csrf_token": sess.CSRFToken, "aal": sess.AAL,
		"user_id": u.ID, "email": u.Email, "roles": u.Roles,
		"must_change_password": u.MustChangePassword,
	})
}

func (a *App) handlePasswordChange(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	if !ac.Authenticated() || a.Store == nil {
		writeProblem(w, 401, "unauthorized", "authentication required")
		return
	}
	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeProblem(w, 400, "bad_request", "invalid json")
		return
	}
	user, hash, err := authn.GetUserPasswordHash(r.Context(), a.Store.DB(), ac.PrincipalID)
	if err != nil {
		writeProblem(w, 404, "not_found", "user not found")
		return
	}
	ok, _ := authn.VerifyPassword(hash, body.CurrentPassword)
	if !ok {
		writeProblem(w, 401, "unauthorized", "current password incorrect")
		return
	}
	if err := authn.SetUserPassword(r.Context(), a.Store.DB(), user.ID, body.NewPassword, user.Email, ac.PrincipalID, false); err != nil {
		writeProblem(w, 400, "bad_request", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func stringsTrimPrefixAPI(path string) string {
	const p = "/api/v1"
	if len(path) >= len(p) && path[:len(p)] == p {
		return path[len(p):]
	}
	return path
}

func (a *App) handleWebAuthnEnrollBegin(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	if a.Challenges == nil {
		writeProblem(w, 503, "unavailable", "webauthn unavailable")
		return
	}
	if !ac.Authenticated() {
		writeProblem(w, 401, "unauthorized", "session required to enroll passkey")
		return
	}
	var body struct {
		UserID string `json:"user_id"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body)
	uid := body.UserID
	if uid == "" {
		uid = ac.PrincipalID
	}
	// Self-enroll or admin managing identity.
	if uid != ac.PrincipalID && !ac.HasRole("security_administrator") && !ac.HasRole("system_administrator") {
		writeProblem(w, 403, "forbidden", "cannot enroll passkey for another user")
		return
	}
	ch, err := a.Challenges.EnrollBegin(uid, time.Now().UTC())
	if err != nil {
		writeProblem(w, 500, "error", "challenge issue failed")
		return
	}
	writeJSON(w, 200, map[string]any{"challenge_id": ch.ID, "purpose": ch.Purpose, "expires_at": ch.ExpiresAt, "user_id": uid})
}

func (a *App) handleWebAuthnEnrollFinish(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	if a.Challenges == nil || a.Credentials == nil {
		writeProblem(w, 503, "unavailable", "webauthn unavailable")
		return
	}
	if !ac.Authenticated() {
		writeProblem(w, 401, "unauthorized", "session required to enroll passkey")
		return
	}
	var body struct {
		UserID            string   `json:"user_id"`
		ChallengeID       string   `json:"challenge_id"`
		CredentialID      string   `json:"credential_id"`
		PublicKey         string   `json:"public_key"`
		PublicKeyCOSE     string   `json:"public_key_cose"`
		PublicKeyAlg      int64    `json:"public_key_alg"`
		AAGUID            string   `json:"aaguid"`
		Transports        []string `json:"transports"`
		AttestationFormat string   `json:"attestation_format"`
		Nickname          string   `json:"nickname"`
		Signature         string   `json:"signature"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeProblem(w, 400, "bad_request", "invalid json")
		return
	}
	if body.UserID == "" {
		body.UserID = ac.PrincipalID
	}
	if body.UserID != ac.PrincipalID && !ac.HasRole("security_administrator") && !ac.HasRole("system_administrator") {
		writeProblem(w, 403, "forbidden", "cannot enroll passkey for another user")
		return
	}
	credID, err1 := hex.DecodeString(body.CredentialID)
	sig, err3 := hex.DecodeString(body.Signature)
	if err1 != nil || err3 != nil {
		writeProblem(w, 400, "bad_request", "hex credential_id and signature required")
		return
	}
	var pub, cose, aaguid []byte
	if body.PublicKey != "" {
		var err error
		pub, err = hex.DecodeString(body.PublicKey)
		if err != nil {
			writeProblem(w, 400, "bad_request", "public_key must be hex")
			return
		}
	}
	if body.PublicKeyCOSE != "" {
		var err error
		cose, err = hex.DecodeString(body.PublicKeyCOSE)
		if err != nil {
			writeProblem(w, 400, "bad_request", "public_key_cose must be hex")
			return
		}
	}
	if body.AAGUID != "" {
		var err error
		aaguid, err = hex.DecodeString(body.AAGUID)
		if err != nil {
			writeProblem(w, 400, "bad_request", "aaguid must be hex")
			return
		}
	}
	cred, err := a.Credentials.EnrollFinishRich(r.Context(), a.Challenges, body.UserID, body.ChallengeID, authn.EnrollInput{
		CredentialID: credID, PublicKey: pub, PublicKeyCOSE: cose, PublicKeyAlg: body.PublicKeyAlg,
		AAGUID: aaguid, Transports: body.Transports, AttestationFormat: body.AttestationFormat,
		Nickname: body.Nickname, Signature: sig,
	}, time.Now().UTC())
	if err != nil {
		writeProblem(w, 400, "bad_request", err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{
		"credential_id": body.CredentialID, "user_id": cred.UserID,
		"public_key_alg": cred.PublicKeyAlg, "attestation_format": cred.AttestationFormat,
		"transports": cred.Transports, "nickname": cred.Nickname,
		"has_cose": len(cred.PublicKeyCOSE) > 0,
	})
}

func (a *App) handleWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	if a.Challenges == nil {
		writeProblem(w, 503, "unavailable", "webauthn unavailable")
		return
	}
	var body struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil || body.UserID == "" {
		writeProblem(w, 400, "bad_request", "user_id required")
		return
	}
	ch, err := a.Challenges.LoginBegin(body.UserID, time.Now().UTC())
	if err != nil {
		writeProblem(w, 500, "error", "challenge issue failed")
		return
	}
	writeJSON(w, 200, map[string]any{"challenge_id": ch.ID, "purpose": ch.Purpose, "expires_at": ch.ExpiresAt})
}

func (a *App) handleWebAuthnStepUpBegin(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	if a.Challenges == nil {
		writeProblem(w, 503, "unavailable", "webauthn unavailable")
		return
	}
	uid := ac.PrincipalID
	if uid == "" || uid == "anonymous" {
		var body struct {
			UserID string `json:"user_id"`
		}
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body)
		uid = body.UserID
	}
	if uid == "" || uid == "anonymous" {
		writeProblem(w, 401, "unauthorized", "session or user_id required")
		return
	}
	ch, err := a.Challenges.StepUpBegin(uid, time.Now().UTC())
	if err != nil {
		writeProblem(w, 500, "error", "challenge issue failed")
		return
	}
	writeJSON(w, 200, map[string]any{"challenge_id": ch.ID, "purpose": ch.Purpose, "expires_at": ch.ExpiresAt, "user_id": uid})
}

func (a *App) handleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request, purpose string) {
	if a.Challenges == nil || a.Credentials == nil || a.Sessions == nil {
		writeProblem(w, 503, "unavailable", "webauthn unavailable")
		return
	}
	var body struct {
		UserID       string `json:"user_id"`
		ChallengeID  string `json:"challenge_id"`
		CredentialID string `json:"credential_id"`
		Signature    string `json:"signature"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeProblem(w, 400, "bad_request", "invalid json")
		return
	}
	credID, err1 := hex.DecodeString(body.CredentialID)
	sig, err2 := hex.DecodeString(body.Signature)
	if err1 != nil || err2 != nil {
		writeProblem(w, 400, "bad_request", "hex fields required")
		return
	}
	cred, err := a.Credentials.AssertLogin(r.Context(), a.Challenges, body.UserID, purpose, body.ChallengeID, credID, sig, time.Now().UTC())
	if err != nil {
		writeProblem(w, 401, "unauthorized", err.Error())
		return
	}
	if purpose == "step_up" {
		if c, err := r.Cookie(authn.SessionCookie); err == nil && c.Value != "" {
			if sess, err := a.Sessions.LookupByID(r.Context(), c.Value); err == nil && sess.UserID == body.UserID {
				if err := a.Sessions.RecordStepUp(r.Context(), sess); err != nil {
					writeProblem(w, 500, "error", "step-up persist failed")
					return
				}
				writeJSON(w, 200, map[string]any{"step_up": true, "aal": sess.AAL, "credential_id": hex.EncodeToString(cred.CredentialID)})
				return
			}
		}
	}
	sess, err := a.Sessions.Create(r.Context(), body.UserID, 2, nil, "")
	if err != nil {
		writeProblem(w, 500, "error", "session create failed")
		return
	}
	if purpose == "login" || purpose == "step_up" {
		_ = a.Sessions.RecordStepUp(r.Context(), sess)
	}
	secure := r.TLS != nil
	authn.SetSessionCookie(w, sess.ID, secure)
	writeJSON(w, 200, map[string]any{
		"session": true, "csrf_token": sess.CSRFToken, "aal": sess.AAL,
		"credential_id": hex.EncodeToString(cred.CredentialID), "purpose": purpose,
	})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if a.Sessions == nil {
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	if c, err := r.Cookie(authn.SessionCookie); err == nil && c.Value != "" {
		hash := authn.HashToken(c.Value)
		_ = a.Sessions.Revoke(r.Context(), hash)
	}
	authn.ClearSessionCookie(w, r.TLS != nil)
	writeJSON(w, 200, map[string]any{"ok": true})
}
