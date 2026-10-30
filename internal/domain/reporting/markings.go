// Package reporting implements report/export helpers and GEN-012 classification markings.
package reporting

import (
	"fmt"
	"strings"
)

// DefaultMarkings are used when config labels are empty (GEN-012).
var DefaultMarkings = map[string]string{
	"Privileged":          "Privileged & Confidential — Prepared at the Direction of Counsel",
	"Client-Confidential": "Client-Confidential — Firm Use Only",
	"Confidential":        "Confidential — Internal Use Only",
	"Internal":            "Internal",
}

// ResolveMarking returns the configured banner for a classification label.
func ResolveMarking(label string, configured map[string]string) string {
	label = strings.TrimSpace(label)
	if label == "" {
		label = "Internal"
	}
	if configured != nil {
		if m, ok := configured[label]; ok && strings.TrimSpace(m) != "" {
			return m
		}
	}
	if m, ok := DefaultMarkings[label]; ok {
		return m
	}
	return fmt.Sprintf("%s — Controlled Information", label)
}

// ApplyMarking wraps a report/export/AI body with a classification banner (GEN-012).
func ApplyMarking(label string, configured map[string]string, body string) MarkedDocument {
	marking := ResolveMarking(label, configured)
	return MarkedDocument{
		Classification: label,
		Marking:        marking,
		Body:           body,
		Banner:         marking,
	}
}

// MarkedDocument is a report or export payload with a classification banner.
type MarkedDocument struct {
	Classification string `json:"classification"`
	Marking        string `json:"marking"`
	Banner         string `json:"banner"`
	Body           string `json:"body"`
}

// SensitiveClassification is true for labels that require step-up + second approver on bulk export (RPT-004).
func SensitiveClassification(label string) bool {
	switch strings.TrimSpace(label) {
	case "Client-Confidential", "Privileged":
		return true
	default:
		return false
	}
}

// ReportTypes enumerates supported async report kinds (RPT-001/002/003).
var ReportTypes = map[string]bool{
	"inventory":   true,
	"exceptions":  true,
	"committee":   true,
	"audit_pack":  true,
	"kri":         true,
}
