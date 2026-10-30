package sandbox

import (
	"bytes"
	"regexp"
	"unicode"
)

// pageTypeRe finds /Type /Page candidates; CountPDFPages filters out /Pages.
var pageTypeRe = regexp.MustCompile(`/Type\s*/Page`)

// CountPDFPages is a no-CGO best-effort page count for PDF bytes (ADR-0004).
// It scans for /Type /Page object markers and ignores /Pages trees.
func CountPDFPages(raw []byte) int {
	if len(raw) == 0 || !bytes.Contains(raw, []byte("%PDF")) {
		return 0
	}
	matches := pageTypeRe.FindAllIndex(raw, -1)
	n := 0
	for _, m := range matches {
		end := m[1]
		// Reject /Pages (and /PageXxx) — only bare /Page counts.
		if end < len(raw) {
			c := rune(raw[end])
			if c == 's' || unicode.IsLetter(c) {
				continue
			}
		}
		n++
	}
	if n == 0 {
		if m := countPagesTreeCount(raw); m > 0 {
			return m
		}
		return 0
	}
	return n
}

var pagesCountRe = regexp.MustCompile(`/Type\s*/Pages[^>]*?/Count\s+(\d+)`)

func countPagesTreeCount(raw []byte) int {
	m := pagesCountRe.FindSubmatch(raw)
	if len(m) < 2 {
		return 0
	}
	n := 0
	for _, c := range m[1] {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
