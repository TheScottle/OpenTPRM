package evidence

import (
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
