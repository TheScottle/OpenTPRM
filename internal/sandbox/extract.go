package sandbox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/TheScottle/OpenTPRM/internal/domain/evidence"
)

// MaxExtractBytes caps PDFium-free text extract in the sandbox child (QST-011 / EVD).
const MaxExtractBytes = 8 << 20

// ExtractResult is PDFium-free page text for TXT/JSON (and PDF page-count stub) inputs.
type ExtractResult struct {
	MediaType string   `json:"media_type"`
	Pages     []string `json:"pages"`
	PageCount int      `json:"page_count,omitempty"`
}

// ExtractTextFile reads an allow-listed absolute path and extracts plain text without PDFium.
// Supports UTF-8 TXT and JSON (pretty-printed keys/values as viewer pages).
func ExtractTextFile(absPath string) (ExtractResult, error) {
	clean := filepath.Clean(absPath)
	if !filepath.IsAbs(clean) {
		return ExtractResult{}, fmt.Errorf("sandbox extract: path must be absolute")
	}
	fi, err := os.Stat(clean)
	if err != nil {
		return ExtractResult{}, err
	}
	if fi.Size() > MaxExtractBytes {
		return ExtractResult{}, fmt.Errorf("sandbox extract: file exceeds %d bytes", MaxExtractBytes)
	}
	raw, err := os.ReadFile(clean)
	if err != nil {
		return ExtractResult{}, err
	}
	ext := strings.ToLower(filepath.Ext(clean))
	switch ext {
	case ".json":
		return extractJSON(raw)
	case ".pdf":
		return extractPDFPageCountStub(raw), nil
	case ".txt", ".text", ".md", ".csv", ".log", "":
		return extractTXT(raw), nil
	default:
		// Sniff: PDF, JSON object/array, else treat as text if valid UTF-8.
		trim := bytes.TrimSpace(raw)
		if bytes.HasPrefix(trim, []byte("%PDF")) {
			return extractPDFPageCountStub(raw), nil
		}
		if len(trim) > 0 && (trim[0] == '{' || trim[0] == '[') {
			if got, err := extractJSON(raw); err == nil {
				return got, nil
			}
		}
		if utf8.Valid(raw) {
			return extractTXT(raw), nil
		}
		return ExtractResult{}, fmt.Errorf("sandbox extract: unsupported media (PDFium-free path supports TXT/JSON; PDF page-count stub only — ADR-0004)")
	}
}

// extractPDFPageCountStub counts /Type /Page markers without CGO or PDFium (ADR-0004).
// It does not extract page text; Pages holds one summary line for viewer metadata.
func extractPDFPageCountStub(raw []byte) ExtractResult {
	n := CountPDFPages(raw)
	summary := fmt.Sprintf("PDF page-count stub (no text extract; ADR-0004): %d page(s)", n)
	return ExtractResult{
		MediaType: "application/pdf",
		Pages:     []string{summary},
		PageCount: n,
	}
}

func extractTXT(raw []byte) ExtractResult {
	safe := evidence.SanitizeViewerText(string(raw))
	pages := splitPages(safe, 4000)
	if len(pages) == 0 {
		pages = []string{""}
	}
	return ExtractResult{MediaType: "text/plain", Pages: pages}
}

func extractJSON(raw []byte) (ExtractResult, error) {
	if !json.Valid(raw) {
		return ExtractResult{}, fmt.Errorf("sandbox extract: invalid JSON")
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, raw, "", "  "); err != nil {
		// Fall back to sanitized raw.
		safe := evidence.SanitizeViewerText(string(raw))
		return ExtractResult{MediaType: "application/json", Pages: splitPages(safe, 4000)}, nil
	}
	safe := evidence.SanitizeViewerText(pretty.String())
	return ExtractResult{MediaType: "application/json", Pages: splitPages(safe, 4000)}, nil
}

func splitPages(s string, maxRunes int) []string {
	if maxRunes < 1 {
		maxRunes = 4000
	}
	runes := []rune(s)
	if len(runes) == 0 {
		return nil
	}
	var out []string
	for len(runes) > 0 {
		n := maxRunes
		if n > len(runes) {
			n = len(runes)
		}
		out = append(out, string(runes[:n]))
		runes = runes[n:]
	}
	return out
}
