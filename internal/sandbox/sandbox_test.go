package sandbox_test

import (
	"path/filepath"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/sandbox"
)

func TestSandboxValidateJobAllowList(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.bin")
	job := sandbox.Job{ID: "j1", InputPath: in}
	c := sandbox.DefaultConstraints(in)
	if err := sandbox.ValidateJob(job, c); err != nil {
		t.Fatal(err)
	}
	job.InputPath = filepath.Join(dir, "..", "etc", "passwd")
	// Clean may still be absolute under temp; force escape via different root.
	job.InputPath = "/etc/passwd"
	if err := sandbox.ValidateJob(job, c); err == nil {
		t.Fatal("expected allow-list refusal")
	}
	job.ID = ""
	job.InputPath = in
	if err := sandbox.ValidateJob(job, c); err == nil {
		t.Fatal("empty id refused")
	}
}

func TestSandboxForbidNetworkEnv(t *testing.T) {
	if !sandbox.HasNetworkEnv([]string{"HTTP_PROXY=http://evil", "PATH=/bin"}) {
		t.Fatal("expected network env detection")
	}
	if sandbox.HasNetworkEnv([]string{}) {
		t.Fatal("empty env must be clean")
	}
}
