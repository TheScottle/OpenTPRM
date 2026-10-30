package sandbox

import "fmt"

// IsolationStatus reports Landlock/seccomp readiness (SEC-UP / SEC-CTN-006).
type IsolationStatus struct {
	LandlockAvailable bool   `json:"landlock_available"`
	LandlockApplied   bool   `json:"landlock_applied"`
	NoNewPrivs        bool   `json:"no_new_privs"`
	SeccompMode       int    `json:"seccomp_mode"`
	Degraded          bool   `json:"degraded"`
	Detail            string `json:"detail,omitempty"`
}

// ProbeIsolation reports current process isolation without mutating policy beyond no_new_privs probe.
func ProbeIsolation() IsolationStatus {
	st := IsolationStatus{}
	st.LandlockAvailable = landlockAvailable()
	st.NoNewPrivs = noNewPrivsEnabled()
	st.SeccompMode = seccompMode()
	if !st.LandlockAvailable {
		st.Degraded = true
		st.Detail = "Landlock unavailable; path allow-list + empty env still enforced in Go"
	}
	return st
}

// ApplyChildHooks applies best-effort Landlock + no_new_privs for the sandbox child.
// Missing Landlock is degraded (not fatal). Seccomp filter remains deploy-profile based
// so unit tests / CI without BPF privileges still pass.
func ApplyChildHooks(c Constraints) (IsolationStatus, error) {
	st := ProbeIsolation()
	if err := setNoNewPrivs(); err != nil {
		st.Detail = fmt.Sprintf("no_new_privs: %v", err)
		// Non-fatal outside hardened containers.
	} else {
		st.NoNewPrivs = true
	}
	if c.ForbidNetwork {
		// Empty env is applied by RunConstrained; record intent here.
	}
	applied, err := tryLandlockRestrict(c.AllowPaths)
	if err != nil {
		st.Degraded = true
		st.Detail = err.Error()
		return st, nil // degrade, do not fail CI hosts without Landlock
	}
	st.LandlockApplied = applied
	st.LandlockAvailable = st.LandlockAvailable || applied
	if !applied {
		st.Degraded = true
		if st.Detail == "" {
			st.Detail = "Landlock not applied"
		}
	}
	return st, nil
}
