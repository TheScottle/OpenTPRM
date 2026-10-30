package sandbox

// DeploySeccompProfile is the container seccomp profile applied around the child
// (SEC-UP / SEC-CTN-006). In-process BPF attach is not required in unit CI.
const DeploySeccompProfile = "deploy/seccomp-opentprm.json"

// ChildPolicy documents the hardened sandbox child expectations.
type ChildPolicy struct {
	SeccompProfile   string   `json:"seccomp_profile"`
	EmptyEnv         bool     `json:"empty_env"`
	ForbidNetwork    bool     `json:"forbid_network"`
	NoNewPrivs       bool     `json:"no_new_privs"`
	LandlockReadOnly bool     `json:"landlock_read_only"`
	AllowPaths       []string `json:"allow_paths,omitempty"`
}

// ExpectedChildPolicy returns the baseline policy for a constrained job.
func ExpectedChildPolicy(c Constraints) ChildPolicy {
	return ChildPolicy{
		SeccompProfile:   DeploySeccompProfile,
		EmptyEnv:         c.ForbidNetwork,
		ForbidNetwork:    c.ForbidNetwork,
		NoNewPrivs:       true,
		LandlockReadOnly: true,
		AllowPaths:       append([]string(nil), c.AllowPaths...),
	}
}
