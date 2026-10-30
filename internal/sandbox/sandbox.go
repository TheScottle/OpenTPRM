package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

// Job describes an untrusted-file parse job.
type Job struct {
	ID       string
	InputPath string
	Timeout  time.Duration
}

// Run re-execs `opentprm sandbox` with empty environment (SEC-UP / §11.2).
// Seccomp/Landlock are applied by the deploy profile around the child.
func Run(bin string, job Job) error {
	if job.Timeout == 0 {
		job.Timeout = 60 * time.Second
	}
	cmd := exec.Command(bin, "sandbox", job.ID, job.InputPath)
	cmd.Env = []string{} // empty environment
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
