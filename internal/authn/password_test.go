package authn_test

import (
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/authn"
)

func TestPassword_HashVerifyPolicy(t *testing.T) {
	if err := authn.ValidatePasswordPolicy("short", "a@b.com"); err == nil {
		t.Fatal("expected policy error")
	}
	if err := authn.ValidatePasswordPolicy("user@example.com", "user@example.com"); err == nil {
		t.Fatal("email-as-password must fail")
	}
	hash, err := authn.HashPassword("adequate-password-01")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := authn.VerifyPassword(hash, "adequate-password-01")
	if err != nil || !ok {
		t.Fatalf("verify: %v %v", ok, err)
	}
	ok, err = authn.VerifyPassword(hash, "wrong-password-xxxx")
	if err != nil || ok {
		t.Fatalf("mismatch should be false: %v %v", ok, err)
	}
}
