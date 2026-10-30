package sandbox_test

import (
	"path/filepath"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/sandbox"
)

func TestSandboxProbeIsolation(t *testing.T) {
	st := sandbox.ProbeIsolation()
	// Must not panic; Landlock may be degraded in CI.
	if st.LandlockAvailable && st.Degraded {
		t.Fatal("available landlock should not mark degraded on probe alone")
	}
	if !st.LandlockAvailable && !st.Degraded {
		t.Fatal("missing landlock must report degraded")
	}
	t.Logf("isolation: landlock=%v nnp=%v seccomp=%d degraded=%v detail=%s",
		st.LandlockAvailable, st.NoNewPrivs, st.SeccompMode, st.Degraded, st.Detail)
}

func TestSandboxApplyChildHooksEmptyPaths(t *testing.T) {
	// Empty allow-paths: must not apply Landlock restrict_self (would break the test process).
	st, err := sandbox.ApplyChildHooks(sandbox.Constraints{ForbidNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	if st.LandlockApplied {
		t.Fatal("empty allow paths must not apply landlock")
	}
}

func TestSandboxApplyChildHooksWithPathWhenUnavailable(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "doc.bin")
	st, err := sandbox.ApplyChildHooks(sandbox.DefaultConstraints(in))
	if err != nil {
		t.Fatal(err)
	}
	if st.LandlockApplied {
		// If the host actually applied Landlock, further file IO in this process may fail.
		// Skip remainder — CI hosts typically lack Landlock ABI for unprivileged processes.
		t.Skip("landlock applied in-process; skipping further assertions")
	}
	if !st.Degraded {
		t.Fatal("expected degraded when landlock not applied")
	}
}
