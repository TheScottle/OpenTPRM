package evidence_test

import (
	"strings"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/domain/evidence"
)

func TestSanitizeViewerTextStripsControlsAndTags(t *testing.T) {
	raw := "hello\x00<script>alert(1)</script>\x01world\n"
	got := evidence.SanitizeViewerText(raw)
	if strings.Contains(got, "<") || strings.Contains(got, ">") {
		t.Fatalf("raw angle brackets leaked: %q", got)
	}
	if strings.Contains(got, "\x00") || strings.Contains(got, "\x01") {
		t.Fatalf("controls leaked: %q", got)
	}
	if !strings.Contains(got, "hello") || !strings.Contains(got, "world") {
		t.Fatalf("body lost: %q", got)
	}
}

func TestRenderViewerHTMLSafe(t *testing.T) {
	html := evidence.RenderViewerHTML(evidence.ViewerPageStub{
		EvidenceID: "ev-1", PageNum: 1, Text: "<script>x</script>\nline", TextSHA256: "abc", Safe: true,
	})
	if strings.Contains(html, "<script>") {
		t.Fatalf("script tag leaked: %s", html)
	}
	if !strings.Contains(html, "OpenTPRM safe viewer") || !strings.Contains(html, "ev-1") {
		t.Fatalf("missing chrome: %s", html)
	}
}
