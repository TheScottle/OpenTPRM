package evidence

import (
	"fmt"
	"html"
	"strings"
	"unicode"
)

// SanitizeViewerText prepares extracted page text for the safe viewer (EVD-007).
// Strips NULs and most C0 controls (keeps \n \t), collapses dangerous HTML, then escapes.
func SanitizeViewerText(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		switch {
		case r == 0:
			continue
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case unicode.IsControl(r):
			continue
		default:
			b.WriteRune(r)
		}
	}
	// Neutralize angle brackets before escape so escaped output has no raw tags.
	s := strings.ReplaceAll(b.String(), "<", "‹")
	s = strings.ReplaceAll(s, ">", "›")
	return html.EscapeString(s)
}

// ViewerPageStub is a minimal safe-viewer payload (server-rendered text; images later).
type ViewerPageStub struct {
	EvidenceID string `json:"evidence_id"`
	PageNum    int    `json:"page_num"`
	Text       string `json:"text"`
	TextSHA256 string `json:"text_sha256,omitempty"`
	Safe       bool   `json:"safe"`
}

// RenderViewerHTML returns a CSP-safe HTML page for the evidence viewer (EVD-007).
// Text must already be SanitizeViewerText-processed (or is re-sanitized here).
func RenderViewerHTML(p ViewerPageStub) string {
	text := SanitizeViewerText(p.Text)
	eid := html.EscapeString(p.EvidenceID)
	sha := html.EscapeString(p.TextSHA256)
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Evidence %s · page %d</title>
<style>
body{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;margin:1.5rem;background:#f7f5f1;color:#1a1a1a}
header{margin-bottom:1rem;border-bottom:1px solid #ccc;padding-bottom:.5rem}
pre{white-space:pre-wrap;word-break:break-word;line-height:1.45}
.meta{color:#555;font-size:.85rem}
</style>
</head>
<body>
<header>
<strong>OpenTPRM safe viewer</strong>
<div class="meta">evidence %s · page %d · sha256 %s · safe=%v</div>
</header>
<pre>%s</pre>
</body>
</html>`, eid, p.PageNum, eid, p.PageNum, sha, p.Safe, text)
}
