package authn_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/TheScottle/OpenTPRM/internal/authn"
	"github.com/TheScottle/OpenTPRM/internal/crypto"
	"github.com/TheScottle/OpenTPRM/internal/store"
	_ "github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/embed"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	kr := crypto.NewSealed()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 7)
	}
	if err := kr.Unseal(key); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.TempDir(), kr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st.DB()
}

func TestSEC_AN_004_SessionHashedIdleAbsolute(t *testing.T) {
	db := openTestDB(t)
	ss := authn.NewSessionStore(db)
	ctx := context.Background()

	// Seed a user for FK
	_, err := db.Exec(`INSERT INTO users(id, principal_type, email, display_name, roles_json, disabled, created_at, created_by, updated_at, updated_by)
		VALUES('u1','workforce','u1@example.com','U','["risk_analyst"]',0,datetime('now'),'t',datetime('now'),'t')`)
	if err != nil {
		t.Fatal(err)
	}

	sess, err := ss.Create(ctx, "u1", 2, []string{"risk_analyst"}, "u1@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(sess.ID) != 64 {
		t.Fatalf("expected 256-bit hex id, got len=%d", len(sess.ID))
	}
	if sess.CSRFToken == "" || sess.CSRFHash == "" {
		t.Fatal("csrf required")
	}
	// Raw ID must not appear in DB
	var n int
	_ = db.QueryRow(`SELECT COUNT(1) FROM sessions WHERE id_hash=?`, sess.ID).Scan(&n)
	if n != 0 {
		t.Fatal("plaintext session id must not be stored")
	}
	_ = db.QueryRow(`SELECT COUNT(1) FROM sessions WHERE id_hash=?`, sess.IDHash).Scan(&n)
	if n != 1 {
		t.Fatal("hashed session missing")
	}

	got, err := ss.LookupByID(ctx, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != "u1" {
		t.Fatalf("user=%s", got.UserID)
	}
	if err := authn.ValidateCSRF(got, sess.CSRFToken); err != nil {
		t.Fatal(err)
	}
	if err := authn.ValidateCSRF(got, "deadbeef"); err != authn.ErrCSRFMismatch {
		t.Fatalf("want csrf mismatch, got %v", err)
	}

	// Idle expiry
	got.LastSeen = time.Now().UTC().Add(-authn.IdleTimeout - time.Minute)
	if err := got.Alive(time.Now().UTC()); err != authn.ErrSessionExpired {
		t.Fatalf("want idle expired, got %v", err)
	}
}

func TestSEC_AN_005_LogoutRevokes(t *testing.T) {
	db := openTestDB(t)
	ss := authn.NewSessionStore(db)
	ctx := context.Background()
	_, _ = db.Exec(`INSERT INTO users(id, principal_type, email, display_name, roles_json, disabled, created_at, created_by, updated_at, updated_by)
		VALUES('u2','workforce','u2@example.com','U','[]',0,datetime('now'),'t',datetime('now'),'t')`)
	sess, err := ss.Create(ctx, "u2", 2, nil, "u2@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := ss.Revoke(ctx, sess.IDHash); err != nil {
		t.Fatal(err)
	}
	if _, err := ss.LookupByID(ctx, sess.ID); err != authn.ErrSessionRevoked && err != authn.ErrInvalidSession {
		// After revoke, Alive returns revoked; Lookup may return that
		if err == nil {
			t.Fatal("revoked session must not resolve")
		}
	}
	n, err := ss.RevokeAllForUser(ctx, "u2")
	if err != nil {
		t.Fatal(err)
	}
	_ = n
}

func TestSEC_AN_003_StepUpWindow(t *testing.T) {
	db := openTestDB(t)
	ss := authn.NewSessionStore(db)
	ctx := context.Background()
	_, _ = db.Exec(`INSERT INTO users(id, principal_type, email, display_name, roles_json, disabled, created_at, created_by, updated_at, updated_by)
		VALUES('u3','workforce','u3@example.com','U','["approver"]',0,datetime('now'),'t',datetime('now'),'t')`)
	sess, err := ss.Create(ctx, "u3", 2, []string{"approver"}, "u3@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if sess.StepUpFresh(time.Now().UTC()) {
		t.Fatal("step-up must be false initially")
	}
	if err := ss.RecordStepUp(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if !sess.StepUpFresh(time.Now().UTC()) {
		t.Fatal("step-up must be fresh")
	}
	sess.StepUpAt = time.Now().UTC().Add(-6 * time.Minute)
	if sess.StepUpFresh(time.Now().UTC()) {
		t.Fatal("step-up must expire after 5 minutes")
	}
}

func TestSEC_AN_006_ChallengeSingleUseAndThrottle(t *testing.T) {
	cs := authn.NewChallengeStore()
	now := time.Now().UTC()
	ch, err := cs.Issue("u1", "step_up", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.Consume(ch.ID, "u1", "step_up", now); err != nil {
		t.Fatal(err)
	}
	if err := cs.Consume(ch.ID, "u1", "step_up", now); err != authn.ErrChallengeExpired {
		t.Fatalf("reuse must fail: %v", err)
	}
	ch2, _ := cs.Issue("u1", "login", now)
	if err := cs.Consume(ch2.ID, "u1", "login", now.Add(authn.ChallengeTTL+time.Second)); err != authn.ErrChallengeExpired {
		t.Fatalf("expired must fail: %v", err)
	}

	th := authn.NewThrottle(3, time.Minute)
	for i := 0; i < 3; i++ {
		if err := th.Allow("ip:1", now); err != nil {
			t.Fatal(err)
		}
	}
	if err := th.Allow("ip:1", now); err != authn.ErrThrottle {
		t.Fatalf("want throttle, got %v", err)
	}
}

func TestOPS_003_BootstrapTokenSelfDestruct(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	token := "bootstrap-test-token-hex"
	if err := authn.RegisterBootstrapToken(ctx, db, token, now); err != nil {
		t.Fatal(err)
	}
	secPass := "security-admin-pass-01"
	sysPass := "system-admin-pass-01xx"
	sec, sys, err := authn.ConsumeBootstrapToken(ctx, db, token, "sec@example.com", "sys@example.com", secPass, sysPass, now)
	if err != nil {
		t.Fatal(err)
	}
	if sec == "" || sys == "" || sec == sys {
		t.Fatalf("need distinct admin ids: %s %s", sec, sys)
	}
	_, _, err = authn.ConsumeBootstrapToken(ctx, db, token, "a@x", "b@x", secPass, sysPass, now)
	if err != authn.ErrBootstrapUsed {
		t.Fatalf("reuse must fail: %v", err)
	}

	// File path helper
	p := filepath.Join(t.TempDir(), "bootstrap.token")
	if err := writeFile0400(p, "file-token"); err != nil {
		t.Fatal(err)
	}
	if err := authn.LoadBootstrapTokenFile(ctx, db, p); err != nil {
		t.Fatal(err)
	}
}

func writeFile0400(path, body string) error {
	return writeRestricted(path, body)
}

func TestSOD_8_BreakGlassRequiresReasonAndStepUp(t *testing.T) {
	reg := authn.NewBreakGlassRegistry()
	now := time.Now().UTC()
	if _, err := reg.Grant("g1", "u1", "", true, now); err != authn.ErrBreakGlassInvalid {
		t.Fatalf("empty reason: %v", err)
	}
	if _, err := reg.Grant("g1", "u1", "incident-42", false, now); err != authn.ErrBreakGlassInvalid {
		t.Fatalf("no step-up: %v", err)
	}
	g, err := reg.Grant("g1", "u1", "incident-42", true, now)
	if err != nil {
		t.Fatal(err)
	}
	if !g.Alerted {
		t.Fatal("SOD-8: must alert security administrators")
	}
	if !reg.Active("u1", now) {
		t.Fatal("grant must be active")
	}
	if reg.Active("u1", now.Add(authn.BreakGlassTTL+time.Minute)) {
		t.Fatal("grant must expire at 60 minutes")
	}
}

func TestSEC_AN_001_OIDCClaimValidation(t *testing.T) {
	cfg := authn.OIDCConfig{
		Issuer:      "https://idp.example/realms/firm",
		ClientID:    "opentprm",
		RequiredACR: []string{"phr"},
		RequiredAMR: []string{"mfa", "otp", "pwd"},
	}
	now := time.Now().UTC()
	good := authn.IDTokenClaims{
		Iss: cfg.Issuer, Aud: []string{cfg.ClientID}, Exp: now.Add(time.Minute),
		Nonce: "n1", Sub: "sub", ACR: "phr", AMR: []string{"pwd", "otp"},
	}
	if err := authn.ValidateIDTokenClaims(cfg, good, "n1", now); err != nil {
		t.Fatal(err)
	}
	badIss := good
	badIss.Iss = "https://evil"
	if err := authn.ValidateIDTokenClaims(cfg, badIss, "n1", now); err != authn.ErrOIDCInvalidIssuer {
		t.Fatalf("issuer: %v", err)
	}
	badAud := good
	badAud.Aud = []string{"other"}
	if err := authn.ValidateIDTokenClaims(cfg, badAud, "n1", now); err != authn.ErrOIDCInvalidAudience {
		t.Fatalf("aud: %v", err)
	}
	exp := good
	exp.Exp = now.Add(-time.Second)
	if err := authn.ValidateIDTokenClaims(cfg, exp, "n1", now); err != authn.ErrOIDCExpired {
		t.Fatalf("exp: %v", err)
	}
	badNonce := good
	if err := authn.ValidateIDTokenClaims(cfg, badNonce, "other", now); err != authn.ErrOIDCNonce {
		t.Fatalf("nonce: %v", err)
	}
	noMFA := good
	noMFA.ACR = ""
	noMFA.AMR = []string{"pwd"}
	cfgStrict := cfg
	cfgStrict.RequiredAMR = []string{"mfa"}
	cfgStrict.RequiredACR = []string{"phr"}
	if err := authn.ValidateIDTokenClaims(cfgStrict, noMFA, "n1", now); err != authn.ErrOIDCMFARequired {
		t.Fatalf("mfa: %v", err)
	}

	v, ch, err := authn.PKCEVerifier()
	if err != nil || v == "" || ch == "" {
		t.Fatalf("pkce: %v %s %s", err, v, ch)
	}
	st := authn.NewAuthStateStore()
	id, err := st.Put("n1", v, now)
	if err != nil {
		t.Fatal(err)
	}
	n, ver, ok := st.Take(id, now)
	if !ok || n != "n1" || ver != v {
		t.Fatal("state take failed")
	}
	if _, _, ok := st.Take(id, now); ok {
		t.Fatal("state must be single-use")
	}
}

func TestSEC_WEB_CSRF_OriginReject(t *testing.T) {
	// Build a minimal request-like check via helper
	// Cross-site Sec-Fetch-Site must reject
	type req struct {
		Method string
		SFS    string
		Origin string
	}
	cases := []struct {
		r      req
		host   string
		reject bool
	}{
		// Empty Origin allowed (form navigations); Sec-Fetch-Site alone must not reject.
		{req{"POST", "cross-site", ""}, "app.local", false},
		// Browser-attested same-origin/same-site always allowed (Sec-Fetch-* is forbidden for JS).
		{req{"POST", "same-origin", "https://evil.example"}, "app.local", false},
		{req{"POST", "same-origin", "https://app.local"}, "app.local", false},
		{req{"GET", "cross-site", ""}, "app.local", false},
		{req{"POST", "same-origin", "https://127.0.0.1:8443"}, "127.0.0.1:8443", false},
		{req{"POST", "same-origin", "https://127.0.0.1:8443"}, "opentprm:8443", false}, // Docker Host rewrite
		{req{"POST", "cross-site", "https://evil.example:8443"}, "127.0.0.1:8443", true},
		{req{"POST", "cross-site", "https://127.0.0.1:8443"}, "127.0.0.1:8443", false},
		{req{"POST", "same-origin", "https://127.0.0.1:8443"}, "localhost:8443", false},
		{req{"POST", "cross-site", "https://localhost:8443"}, "127.0.0.1:8443", false},
	}
	for i, c := range cases {
		r := &httpRequest{method: c.r.Method, sfs: c.r.SFS, origin: c.r.Origin}
		if got := authn.CheckOriginRejectsCrossSite(r.asHTTP(), c.host); got != c.reject {
			t.Fatalf("case %d: got %v want %v", i, got, c.reject)
		}
	}

	// Without same-origin SFS, LAN Origin needs public_base_url when Host is internal.
	hr := (&httpRequest{method: "POST", sfs: "cross-site", origin: "https://192.168.1.50:8443"}).asHTTP()
	hr.Host = "opentprm:8443"
	if !authn.CheckOriginRejectsCrossSite(hr, "opentprm:8443") {
		t.Fatal("internal host alone must not accept LAN Origin when SFS is cross-site")
	}
	if authn.CheckOriginRejectsCrossSite(hr, "opentprm:8443", "https://192.168.1.50:8443") {
		t.Fatal("LAN public_base_url must allow browser Origin")
	}
}

func TestSEC_AN_003_StepUpPersistsAcrossLookup(t *testing.T) {
	db := openTestDB(t)
	ss := authn.NewSessionStore(db)
	ctx := context.Background()
	_, err := db.Exec(`INSERT INTO users(id, principal_type, email, display_name, roles_json, disabled, created_at, created_by, updated_at, updated_by)
		VALUES('u-step','workforce','step@example.com','S','["approver"]',0,datetime('now'),'t',datetime('now'),'t')`)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := ss.Create(ctx, "u-step", 2, []string{"approver"}, "step@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := ss.RecordStepUp(ctx, sess); err != nil {
		t.Fatal(err)
	}
	got, err := ss.LookupByID(ctx, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.StepUpFresh(time.Now().UTC()) {
		t.Fatalf("step_up_at must survive LookupByID, got %#v", got.StepUpAt)
	}
	if got.AAL < 3 {
		t.Fatalf("aal want >=3 got %d", got.AAL)
	}
}
