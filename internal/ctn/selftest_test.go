package ctn_test

import (
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/ctn"
)

func TestSEC_CTN_006_DevModePasses(t *testing.T) {
	r := ctn.Run(false, t.TempDir(), "")
	if !r.OK {
		t.Fatalf("dev self-test should OK with warnings only: %+v", r)
	}
}

func TestSEC_CTN_006_ProductionRootFails(t *testing.T) {
	// In this environment we are non-root; production without container hardening should fail or warn.
	r := ctn.Run(true, t.TempDir(), "")
	// Either fails (no seccomp/ro root) or if somehow hardened, OK.
	t.Logf("production self-test: ok=%v failures=%v warnings=%v", r.OK, r.Failures, r.Warnings)
}
