package questionnaire

import (
	"encoding/json"
	"fmt"
	"strings"
)

// AllowedLicenseTags for STD-006 seed provenance.
var AllowedLicenseTags = map[string]bool{
	"us_government_work": true,
	"cc0":                true,
	"cc_by":              true,
	"cc_by_sa":           true,
	"apache-2.0":         true,
	"mit":                true,
	"bsd":                true,
	"bsd-2-clause":       true,
	"bsd-3-clause":       true,
	"owner_authored":     true,
	"owner-authored":     true,
}

// ValidateProvenanceJSON enforces STD-006 fields on seed / template provenance blobs.
func ValidateProvenanceJSON(raw string) error {
	if strings.TrimSpace(raw) == "" || raw == "{}" {
		return fmt.Errorf("STD-006: provenance required")
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return fmt.Errorf("STD-006: provenance must be JSON object: %w", err)
	}
	get := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := m[k]; ok {
				if s, ok := v.(string); ok {
					return strings.TrimSpace(s)
				}
			}
		}
		return ""
	}
	source := get("source")
	license := strings.ToLower(get("license", "license_tag"))
	url := get("url")
	if source == "" {
		return fmt.Errorf("STD-006: provenance.source required")
	}
	if license == "" {
		return fmt.Errorf("STD-006: provenance.license required")
	}
	if !AllowedLicenseTags[license] {
		return fmt.Errorf("STD-006: license %q not on allow-list", license)
	}
	if url == "" {
		return fmt.Errorf("STD-006: provenance.url required")
	}
	return nil
}
