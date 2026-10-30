// Package evidence implements the untrusted-content intake pipeline (EVD-*, SEC-UP-*).
package evidence

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Status values for evidence items through quarantine.
type Status string

const (
	StatusReceived           Status = "received"
	StatusQuarantined        Status = "quarantined"
	StatusScanning           Status = "scanning"
	StatusAvailable          Status = "available"
	StatusRejectedMalformed  Status = "rejected_malformed"
	StatusRejectedPolicy     Status = "rejected_policy"
	StatusRejectedLimits     Status = "rejected_limits"
)

// ContentType is identified by magic bytes only (never client MIME).
type ContentType string

const (
	TypePDF  ContentType = "pdf"
	TypePNG  ContentType = "png"
	TypeJPEG ContentType = "jpeg"
	TypeXLSX ContentType = "xlsx"
	TypeDOCX ContentType = "docx"
	TypeCSV  ContentType = "csv"
	TypeTXT  ContentType = "txt"
	TypeJSON ContentType = "json"
	TypeXML  ContentType = "xml"
	TypeZIP  ContentType = "zip"
)

// Limits match §12.5 defaults.
const (
	MaxPDFBytes          = 200 << 20 // 200 MB
	MaxZIPUncompressed   = 200 << 20 // 200 MB
	MaxZIPEntries        = 10_000
	MaxZIPCompressionRatio = 100
	MaxZIPNestingDepth   = 1
	MaxUploadBytes       = 200 << 20
	MaxJSONDepth         = 64
	MaxXMLDepth          = 64
)

// FindingTypeDocumentIntegrity is the EVD-030 / AI-053 finding type.
const FindingTypeDocumentIntegrity = "document_integrity"

var (
	ErrUnsupportedType   = errors.New("unsupported content type")
	ErrSizeLimit         = errors.New("size limit exceeded")
	ErrArchiveBomb       = errors.New("archive exceeds expansion limits")
	ErrIllegalTransition = errors.New("illegal quarantine status transition")
	ErrZipUnsafePath     = errors.New("zip entry path refused")
)

// allowedStatusTransitions is the quarantine status machine.
var allowedStatusTransitions = map[Status][]Status{
	StatusReceived: {
		StatusQuarantined, StatusRejectedMalformed, StatusRejectedLimits, StatusRejectedPolicy,
	},
	StatusQuarantined: {
		StatusScanning, StatusRejectedMalformed, StatusRejectedLimits, StatusRejectedPolicy,
	},
	StatusScanning: {
		StatusAvailable, StatusRejectedMalformed, StatusRejectedLimits, StatusRejectedPolicy, StatusQuarantined,
	},
	StatusAvailable:         {},
	StatusRejectedMalformed: {},
	StatusRejectedPolicy:    {},
	StatusRejectedLimits:    {},
}

// TransitionStatus enforces the quarantine status machine.
func TransitionStatus(from, to Status) (Status, error) {
	for _, s := range allowedStatusTransitions[from] {
		if s == to {
			return to, nil
		}
	}
	return from, fmt.Errorf("%w: %s → %s", ErrIllegalTransition, from, to)
}

// DetectType identifies content by magic bytes (and light structural sniffing).
func DetectType(data []byte) (ContentType, error) {
	if len(data) == 0 {
		return "", ErrUnsupportedType
	}
	switch {
	case bytes.HasPrefix(data, []byte("%PDF")):
		return TypePDF, nil
	case bytes.HasPrefix(data, []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a}):
		return TypePNG, nil
	case bytes.HasPrefix(data, []byte{0xff, 0xd8, 0xff}):
		return TypeJPEG, nil
	case bytes.HasPrefix(data, []byte("PK\x03\x04")), bytes.HasPrefix(data, []byte("PK\x05\x06")):
		// OOXML vs generic ZIP: look for [Content_Types].xml and known parts.
		if isOOXML(data, "word/") {
			return TypeDOCX, nil
		}
		if isOOXML(data, "xl/") {
			return TypeXLSX, nil
		}
		return TypeZIP, nil
	}
	trim := bytes.TrimSpace(data)
	if len(trim) > 0 && (trim[0] == '{' || trim[0] == '[') {
		return TypeJSON, nil
	}
	if bytes.HasPrefix(trim, []byte("<?xml")) || bytes.HasPrefix(trim, []byte("<")) {
		return TypeXML, nil
	}
	if looksLikeCSV(data) {
		return TypeCSV, nil
	}
	if utf8.Valid(data) {
		return TypeTXT, nil
	}
	return "", ErrUnsupportedType
}

func isOOXML(data []byte, dirPrefix string) bool {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return false
	}
	hasCT := false
	hasDir := false
	for _, f := range zr.File {
		name := f.Name
		if name == "[Content_Types].xml" {
			hasCT = true
		}
		if strings.HasPrefix(name, dirPrefix) {
			hasDir = true
		}
	}
	return hasCT && hasDir
}

func looksLikeCSV(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}
	sample := data
	if len(sample) > 4096 {
		sample = sample[:4096]
	}
	lines := bytes.Split(sample, []byte("\n"))
	if len(lines) < 2 {
		return false
	}
	commas := bytes.Count(lines[0], []byte(","))
	return commas >= 1 && bytes.Count(lines[1], []byte(",")) == commas
}

// ValidateUpload applies magic allow-list and size limits before sandboxing.
func ValidateUpload(data []byte) (ContentType, error) {
	if int64(len(data)) > MaxUploadBytes {
		return "", fmt.Errorf("%w: upload %d bytes", ErrSizeLimit, len(data))
	}
	ct, err := DetectType(data)
	if err != nil {
		return "", err
	}
	switch ct {
	case TypePDF:
		if len(data) > MaxPDFBytes {
			return ct, fmt.Errorf("%w: pdf %d bytes", ErrSizeLimit, len(data))
		}
	case TypeZIP, TypeXLSX, TypeDOCX:
		if err := ValidateArchiveLimits(data); err != nil {
			return ct, err
		}
	}
	return ct, nil
}

// ValidateArchiveLimits enforces ZIP entry count, uncompressed size, ratio,
// nesting, and path safety (AT-08 at the validation layer).
func ValidateArchiveLimits(data []byte) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnsupportedType, err)
	}
	if len(zr.File) > MaxZIPEntries {
		return fmt.Errorf("%w: %d entries", ErrArchiveBomb, len(zr.File))
	}
	var uncompressed uint64
	for _, f := range zr.File {
		if err := checkZipPath(f.Name); err != nil {
			return err
		}
		if f.FileInfo().IsDir() {
			continue
		}
		uncompressed += f.UncompressedSize64
		if uncompressed > MaxZIPUncompressed {
			return fmt.Errorf("%w: uncompressed %d bytes", ErrArchiveBomb, uncompressed)
		}
		if f.CompressedSize64 > 0 {
			ratio := float64(f.UncompressedSize64) / float64(f.CompressedSize64)
			if ratio > MaxZIPCompressionRatio && f.UncompressedSize64 > 1<<20 {
				return fmt.Errorf("%w: ratio %.0f:1 on %s", ErrArchiveBomb, ratio, f.Name)
			}
		}
		// Nesting depth 1: refuse nested zip/docx/xlsx members.
		lower := strings.ToLower(f.Name)
		if strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".docx") || strings.HasSuffix(lower, ".xlsx") {
			return fmt.Errorf("%w: nested archive %s", ErrArchiveBomb, f.Name)
		}
	}
	_ = MaxZIPNestingDepth
	return nil
}

func checkZipPath(name string) error {
	if path.IsAbs(name) || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "\\") {
		return fmt.Errorf("%w: absolute %q", ErrZipUnsafePath, name)
	}
	normalized := strings.ReplaceAll(name, "\\", "/")
	for _, part := range strings.Split(normalized, "/") {
		if part == ".." {
			return fmt.Errorf("%w: parent %q", ErrZipUnsafePath, name)
		}
	}
	if strings.Contains(name, "\x00") {
		return fmt.Errorf("%w: nul in %q", ErrZipUnsafePath, name)
	}
	return nil
}

// IntegrityFinding quotes instruction-like or hidden text (EVD-030/031).
type IntegrityFinding struct {
	Type     string
	Quote    string
	Location string
}

var instructionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts)`),
	regexp.MustCompile(`(?i)you\s+are\s+(now\s+)?(a|an)\s+(helpful\s+)?ai`),
	regexp.MustCompile(`(?i)ai\s+reviewer\s*:`),
	regexp.MustCompile(`(?i)system\s*:\s*`),
	regexp.MustCompile(`(?i)do\s+not\s+report\s+(any\s+)?exceptions?`),
	regexp.MustCompile(`(?i)report\s+no\s+exceptions?`),
	regexp.MustCompile(`(?i)disregard\s+(the\s+)?(document|findings?|controls?)`),
	regexp.MustCompile(`(?i)<\s*/?\s*instructions?\s*>`),
}

// DetectInstructionLikeText scans extracted plain text for prompt-injection style
// phrases and returns document_integrity findings (never obeyed).
func DetectInstructionLikeText(text, location string) []IntegrityFinding {
	var out []IntegrityFinding
	for _, re := range instructionPatterns {
		if loc := re.FindStringIndex(text); loc != nil {
			quote := text[loc[0]:loc[1]]
			// Expand quote a little for context, capped.
			start := loc[0]
			end := loc[1]
			if start > 40 {
				start -= 40
			} else {
				start = 0
			}
			if end+40 < len(text) {
				end += 40
			} else {
				end = len(text)
			}
			quote = strings.TrimSpace(text[start:end])
			if utf8.RuneCountInString(quote) > 200 {
				quote = string([]rune(quote)[:200]) + "…"
			}
			out = append(out, IntegrityFinding{
				Type:     FindingTypeDocumentIntegrity,
				Quote:    quote,
				Location: location,
			})
			break // one finding per pattern family hit is enough; continue patterns
		}
	}
	return out
}

// DetectHiddenInstructionMarkers flags near-invisible / off-page markers commonly
// used to hide instructions (white text, tiny font hints in extracted streams).
func DetectHiddenInstructionMarkers(raw []byte, location string) []IntegrityFinding {
	// Lightweight PDF operator / HTML style checks on the byte stream.
	lower := bytes.ToLower(raw)
	var hits []IntegrityFinding
	checks := []struct {
		needle []byte
		label  string
		active bool // active content always becomes a finding
	}{
		{[]byte("1 1 1 rg"), "white-fill", false},
		{[]byte("/crafts 0.001"), "micro-font", false},
		{[]byte("font-size:0"), "css micro-font", false},
		{[]byte("font-size: 0"), "css micro-font", false},
		{[]byte("color:#ffffff"), "white css color", false},
		{[]byte("color: #ffffff"), "white css color", false},
		{[]byte("color:white"), "white css color", false},
		{[]byte("display:none"), "hidden css", false},
		{[]byte("/javascript"), "pdf javascript", true},
		{[]byte("/launch"), "pdf launch action", true},
	}
	seen := map[string]bool{}
	for _, c := range checks {
		needle := bytes.ToLower(c.needle)
		if !bytes.Contains(lower, needle) {
			continue
		}
		if seen[c.label] {
			continue
		}
		seen[c.label] = true
		if c.active {
			hits = append(hits, IntegrityFinding{
				Type:     FindingTypeDocumentIntegrity,
				Quote:    c.label,
				Location: location,
			})
			continue
		}
		idx := bytes.Index(lower, needle)
		start := idx - 200
		if start < 0 {
			start = 0
		}
		end := idx + 200
		if end > len(raw) {
			end = len(raw)
		}
		window := string(raw[start:end])
		if fins := DetectInstructionLikeText(window, location+":"+c.label); len(fins) > 0 {
			hits = append(hits, fins...)
		}
	}
	return hits
}
