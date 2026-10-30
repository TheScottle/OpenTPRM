package authn_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"

	"github.com/TheScottle/OpenTPRM/internal/authn"
)

func TestSEC_AN_006_WebAuthnEnrollLoginStepUp(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	_, err := db.Exec(`INSERT INTO users(id, principal_type, email, display_name, roles_json, disabled, created_at, created_by, updated_at, updated_by)
		VALUES('u-wa','workforce','wa@example.com','WA','["risk_analyst"]',0,datetime('now'),'t',datetime('now'),'t')`)
	if err != nil {
		t.Fatal(err)
	}

	challenges := authn.NewChallengeStore()
	creds := authn.NewCredentialStore(db)
	sessions := authn.NewSessionStore(db)
	now := time.Now().UTC()

	pub, priv, err := authn.GenerateDeviceKeypair()
	if err != nil {
		t.Fatal(err)
	}
	credID := []byte{0x01, 0x02, 0x03, 0x04}

	enrollCh, err := challenges.EnrollBegin("u-wa", now)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, []byte(enrollCh.ID))
	cred, err := creds.EnrollFinish(ctx, challenges, "u-wa", enrollCh.ID, credID, pub, sig, now)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(cred.CredentialID) != hex.EncodeToString(credID) {
		t.Fatal("credential id mismatch")
	}
	// Challenge single-use
	if _, err := creds.EnrollFinish(ctx, challenges, "u-wa", enrollCh.ID, credID, pub, sig, now); err != authn.ErrChallengeExpired {
		t.Fatalf("reuse enroll: %v", err)
	}

	loginCh, err := challenges.LoginBegin("u-wa", now)
	if err != nil {
		t.Fatal(err)
	}
	loginSig := ed25519.Sign(priv, []byte(loginCh.ID))
	if _, err := creds.AssertLogin(ctx, challenges, "u-wa", "login", loginCh.ID, credID, loginSig, now); err != nil {
		t.Fatal(err)
	}

	sess, err := sessions.Create(ctx, "u-wa", 2, []string{"risk_analyst"}, "wa@example.com")
	if err != nil {
		t.Fatal(err)
	}
	stepCh, err := challenges.StepUpBegin("u-wa", now)
	if err != nil {
		t.Fatal(err)
	}
	stepSig := ed25519.Sign(priv, []byte(stepCh.ID))
	if _, err := creds.AssertLogin(ctx, challenges, "u-wa", "step_up", stepCh.ID, credID, stepSig, now); err != nil {
		t.Fatal(err)
	}
	if err := sessions.RecordStepUp(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if !sess.StepUpFresh(now) {
		t.Fatal("SEC-AN-003: step-up must be fresh after WebAuthn")
	}

	// Bad signature rejected without consuming the challenge.
	badCh, _ := challenges.LoginBegin("u-wa", now)
	if _, err := creds.AssertLogin(ctx, challenges, "u-wa", "login", badCh.ID, credID, []byte("nope"), now); err != authn.ErrWebAuthnInvalid {
		t.Fatalf("bad sig: %v", err)
	}
	goodSig := ed25519.Sign(priv, []byte(badCh.ID))
	if _, err := creds.AssertLogin(ctx, challenges, "u-wa", "login", badCh.ID, credID, goodSig, now); err != nil {
		t.Fatalf("challenge must remain usable after bad sig: %v", err)
	}
}

func TestSEC_AN_006_WebAuthnCOSEPublicKeyEnrollAssert(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	_, err := db.Exec(`INSERT INTO users(id, principal_type, email, display_name, roles_json, disabled, created_at, created_by, updated_at, updated_by)
		VALUES('u-cose','workforce','cose@example.com','COSE','["risk_analyst"]',0,datetime('now'),'t',datetime('now'),'t')`)
	if err != nil {
		t.Fatal(err)
	}
	challenges := authn.NewChallengeStore()
	creds := authn.NewCredentialStore(db)
	now := time.Now().UTC()
	pub, priv, err := authn.GenerateDeviceKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cose, err := authn.MarshalEd25519COSE(pub)
	if err != nil {
		t.Fatal(err)
	}
	credID := []byte{0x0a, 0x0b, 0x0c, 0x0d}
	enrollCh, err := challenges.EnrollBegin("u-cose", now)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, []byte(enrollCh.ID))
	cred, err := creds.EnrollFinishRich(ctx, challenges, "u-cose", enrollCh.ID, authn.EnrollInput{
		CredentialID: credID, PublicKeyCOSE: cose, Signature: sig,
		AAGUID: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Transports: []string{"internal", "hybrid"}, AttestationFormat: "none", Nickname: "laptop",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(cred.PublicKeyCOSE) == 0 || cred.Nickname != "laptop" || len(cred.Transports) != 2 {
		t.Fatalf("rich enroll: %+v", cred)
	}
	loginCh, err := challenges.LoginBegin("u-cose", now)
	if err != nil {
		t.Fatal(err)
	}
	loginSig := ed25519.Sign(priv, []byte(loginCh.ID))
	if _, err := creds.AssertLogin(ctx, challenges, "u-cose", "login", loginCh.ID, credID, loginSig, now); err != nil {
		t.Fatalf("cose assert: %v", err)
	}
}
