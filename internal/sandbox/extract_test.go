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

func TestSandboxPDFPageCountStub(t *testing.T) {
	dir := t.TempDir()
	// Minimal two-page PDF-ish markers (not a valid renderable PDF; stub counts markers).
	pdf := "%PDF-1.4\n1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n" +
		"2 0 obj<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>endobj\n" +
		"3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>endobj\n" +
		"4 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>endobj\n" +
		"xref\n0 5\ntrailer<< /Root 1 0 R >>\nstartxref\n0\n%%EOF\n"
	path := filepath.Join(dir, "sample.pdf")
	if err := os.WriteFile(path, []byte(pdf), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := sandbox.ExtractTextFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.MediaType != "application/pdf" || got.PageCount != 2 {
		t.Fatalf("pdf stub: %+v", got)
	}
	if len(got.Pages) != 1 || !strings.Contains(got.Pages[0], "2 page") {
		t.Fatalf("summary: %+v", got.Pages)
	}
	if n := sandbox.CountPDFPages([]byte(pdf)); n != 2 {
		t.Fatalf("CountPDFPages=%d", n)
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
