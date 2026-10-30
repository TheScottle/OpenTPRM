package sandbox_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/sandbox"
)

func TestSandboxExtractTXTAndJSON(t *testing.T) {
	dir := t.TempDir()
	txt := filepath.Join(dir, "note.txt")
	if err := os.WriteFile(txt, []byte("hello\x00<script>x</script>\nworld"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := sandbox.ExtractTextFile(txt)
	if err != nil {
		t.Fatal(err)
	}
	if got.MediaType != "text/plain" || len(got.Pages) < 1 {
		t.Fatalf("txt: %+v", got)
	}
	if strings.Contains(got.Pages[0], "<") || strings.Contains(got.Pages[0], "\x00") {
		t.Fatalf("unsafe text leaked: %q", got.Pages[0])
	}
	if !strings.Contains(got.Pages[0], "hello") || !strings.Contains(got.Pages[0], "world") {
		t.Fatalf("body lost: %q", got.Pages[0])
	}

	js := filepath.Join(dir, "doc.json")
	if err := os.WriteFile(js, []byte(`{"control":"AC-1","status":"yes"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	jgot, err := sandbox.ExtractTextFile(js)
	if err != nil {
		t.Fatal(err)
	}
	if jgot.MediaType != "application/json" || !strings.Contains(jgot.Pages[0], "AC-1") {
		t.Fatalf("json: %+v", jgot)
	}
}

func TestSandboxExpectedChildPolicy(t *testing.T) {
	p := sandbox.ExpectedChildPolicy(sandbox.Constraints{AllowPaths: []string{"/tmp/x"}, ForbidNetwork: true})
	if p.SeccompProfile != sandbox.DeploySeccompProfile {
		t.Fatalf("seccomp profile: %s", p.SeccompProfile)
	}
	if !p.EmptyEnv || !p.NoNewPrivs || !p.LandlockReadOnly {
		t.Fatalf("policy: %+v", p)
	}
}
