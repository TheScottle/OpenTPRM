package httpserver

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/TheScottle/OpenTPRM/internal/authn"
	"github.com/TheScottle/OpenTPRM/internal/authz"
)

func (a *App) handleAuth(w http.ResponseWriter, r *http.Request, ac authz.Context) {
	path := stringsTrimPrefixAPI(r.URL.Path)
	switch {
	case path == "/auth/webauthn/enroll/begin" && r.Method == http.MethodPost:
		a.handleWebAuthnEnrollBegin(w, r)
	case path == "/auth/webauthn/enroll/finish" && r.Method == http.MethodPost:
		a.handleWebAuthnEnrollFinish(w, r)
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

func stringsTrimPrefixAPI(path string) string {
	const p = "/api/v1"
	if len(path) >= len(p) && path[:len(p)] == p {
		return path[len(p):]
	}
	return path
}

func (a *App) handleWebAuthnEnrollBegin(w http.ResponseWriter, r *http.Request) {
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
	ch, err := a.Challenges.EnrollBegin(body.UserID, time.Now().UTC())
	if err != nil {
		writeProblem(w, 500, "error", "challenge issue failed")
		return
	}
	writeJSON(w, 200, map[string]any{"challenge_id": ch.ID, "purpose": ch.Purpose, "expires_at": ch.ExpiresAt})
}

func (a *App) handleWebAuthnEnrollFinish(w http.ResponseWriter, r *http.Request) {
	if a.Challenges == nil || a.Credentials == nil {
		writeProblem(w, 503, "unavailable", "webauthn unavailable")
		return
	}
	var body struct {
		UserID            string   `json:"user_id"`
		ChallengeID       string   `json:"challenge_id"`
		CredentialID      string   `json:"credential_id"`       // hex
		PublicKey         string   `json:"public_key"`          // hex raw Ed25519 (optional if COSE set)
		PublicKeyCOSE     string   `json:"public_key_cose"`     // hex COSE_Key
		PublicKeyAlg      int64    `json:"public_key_alg"`      // COSE alg
		AAGUID            string   `json:"aaguid"`              // hex
		Transports        []string `json:"transports"`
		AttestationFormat string   `json:"attestation_format"`
		Nickname          string   `json:"nickname"`
		Signature         string   `json:"signature"` // hex
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeProblem(w, 400, "bad_request", "invalid json")
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
		// Prefer existing cookie session when present.
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
