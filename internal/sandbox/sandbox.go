package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Job describes an untrusted-file parse job.
type Job struct {
	ID        string
	InputPath string
	Timeout   time.Duration
}

// Constraints are the Landlock/seccomp-oriented policy checks applied before exec.
type Constraints struct {
	// AllowPaths are the only absolute paths the job may read (input + optional out dir).
	AllowPaths []string
	// ForbidNetwork ensures the child starts with an empty environment (no proxy/DNS hints).
	ForbidNetwork bool
}

// DefaultConstraints returns SEC-UP / §11.2 baseline constraints.
func DefaultConstraints(inputPath string) Constraints {
	return Constraints{
		AllowPaths:    []string{inputPath},
		ForbidNetwork: true,
	}
}

// ValidateJob refuses absolute path escape and empty job ids before spawn.
func ValidateJob(job Job, c Constraints) error {
	if strings.TrimSpace(job.ID) == "" {
		return fmt.Errorf("sandbox: job id required")
	}
	if job.InputPath == "" {
		return fmt.Errorf("sandbox: input path required")
	}
	clean := filepath.Clean(job.InputPath)
	if !filepath.IsAbs(clean) {
		return fmt.Errorf("sandbox: input must be absolute")
	}
	if strings.Contains(clean, "..") {
		return fmt.Errorf("sandbox: path escape refused")
	}
	for _, allow := range c.AllowPaths {
		allow = filepath.Clean(allow)
		if clean == allow || strings.HasPrefix(clean, allow+string(os.PathSeparator)) {
			return nil
		}
	}
	if len(c.AllowPaths) == 0 {
		return nil
	}
	return fmt.Errorf("sandbox: path %q outside allow-list", clean)
}

// Run re-execs `opentprm sandbox` with empty environment (SEC-UP / §11.2).
// Seccomp/Landlock are applied by the deploy profile around the child; this layer
// enforces empty env (no network config) and path allow-list checks.
func Run(bin string, job Job) error {
	return RunConstrained(bin, job, DefaultConstraints(job.InputPath))
}

// RunConstrained is Run with explicit Landlock-oriented path policy.
// The child (`opentprm sandbox`) applies Landlock/no_new_privs hooks; the parent
// enforces allow-list validation and empty env (no network config).
func RunConstrained(bin string, job Job, c Constraints) error {
	if err := ValidateJob(job, c); err != nil {
		return err
	}
	if job.Timeout == 0 {
		job.Timeout = 60 * time.Second
	}
	cmd := exec.Command(bin, "sandbox", "--job", job.ID, "--input", job.InputPath)
	for _, p := range c.AllowPaths {
		cmd.Args = append(cmd.Args, "--allow", p)
	}
	if c.ForbidNetwork {
		cmd.Env = []string{} // empty environment — no HTTP_PROXY / resolv hints
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	errCh := make(chan error, 1)
	go func() { errCh <- cmd.Run() }()
	select {
	case err := <-errCh:
		return err
	case <-time.After(job.Timeout):
		_ = cmd.Process.Kill()
		return fmt.Errorf("sandbox timeout")
	}
}

// HasNetworkEnv reports whether the process environment contains proxy/network hints
// (used in tests to assert ForbidNetwork clearing).
func HasNetworkEnv(env []string) bool {
	for _, e := range env {
		u := strings.ToUpper(e)
		if strings.HasPrefix(u, "HTTP_PROXY=") || strings.HasPrefix(u, "HTTPS_PROXY=") ||
			strings.HasPrefix(u, "ALL_PROXY=") || strings.HasPrefix(u, "NO_PROXY=") {
			return true
		}
	}
	return false
}
