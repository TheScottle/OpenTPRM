package questionnaire

import (
	"encoding/json"
	"fmt"
	"strings"
)

// OSCALCatalogSkeleton is the minimal catalog subset we import (STD-003 / QST-010).
type OSCALCatalogSkeleton struct {
	Catalog struct {
		UUID     string `json:"uuid"`
		Metadata struct {
			Title string `json:"title"`
		} `json:"metadata"`
		Groups []OSCALGroup `json:"groups"`
		Controls []OSCALControl `json:"controls"`
	} `json:"catalog"`
}

type OSCALGroup struct {
	ID       string         `json:"id"`
	Title    string         `json:"title"`
	Controls []OSCALControl `json:"controls"`
}

type OSCALControl struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// ImportedTemplate is a draft questionnaire skeleton from an open-format import.
type ImportedTemplate struct {
	Name       string            `json:"name"`
	Kind       string            `json:"kind"`
	Semver     string            `json:"semver"`
	Provenance map[string]string `json:"provenance"`
	Questions  []ImportedQuestion `json:"questions"`
}

// ImportedQuestion is one control/question produced by import.
type ImportedQuestion struct {
	Key      string `json:"key"`
	Text     string `json:"text"`
	Type     string `json:"type"`
	Domain   string `json:"domain,omitempty"`
	SourceID string `json:"source_id,omitempty"`
}

// ImportOSCALCatalog maps an OSCAL catalog JSON document into a template skeleton (QST-010).
// It does not evaluate formulas, follow links, or load macros (QST-011).
func ImportOSCALCatalog(raw []byte, provenance map[string]string) (ImportedTemplate, error) {
	if len(raw) > MaxImportBytes {
		return ImportedTemplate{}, fmt.Errorf("OSCAL catalog exceeds size limit")
	}
	var doc OSCALCatalogSkeleton
	if err := json.Unmarshal(raw, &doc); err != nil {
		return ImportedTemplate{}, fmt.Errorf("OSCAL catalog JSON: %w", err)
	}
	if strings.TrimSpace(doc.Catalog.Metadata.Title) == "" && doc.Catalog.UUID == "" {
		return ImportedTemplate{}, fmt.Errorf("OSCAL catalog missing metadata.title")
	}
	var qs []ImportedQuestion
	add := func(c OSCALControl, domain string) error {
		if c.ID == "" {
			return nil
		}
		if len(qs) >= MaxImportQuestions {
			return fmt.Errorf("QST-011: exceeded %d questions", MaxImportQuestions)
		}
		key := strings.ToUpper(strings.ReplaceAll(c.ID, " ", "-"))
		text := c.Title
		if text == "" {
			text = c.ID
		}
		qs = append(qs, ImportedQuestion{
			Key: key, Text: text, Type: "yes_no_partial_na", Domain: domain, SourceID: c.ID,
		})
		return nil
	}
	for _, g := range doc.Catalog.Groups {
		for _, c := range g.Controls {
			if err := add(c, g.ID); err != nil {
				return ImportedTemplate{}, err
			}
		}
	}
	for _, c := range doc.Catalog.Controls {
		if err := add(c, ""); err != nil {
			return ImportedTemplate{}, err
		}
	}
	if len(qs) == 0 {
		return ImportedTemplate{}, fmt.Errorf("OSCAL catalog has no controls")
	}
	prov := provenance
	if prov == nil {
		prov = map[string]string{}
	}
	if prov["license"] == "" {
		prov["license"] = "us_government_work"
	}
	if prov["source"] == "" {
		prov["source"] = "OSCAL catalog import"
	}
	if prov["url"] == "" {
		prov["url"] = "https://github.com/usnistgov/OSCAL"
	}
	name := doc.Catalog.Metadata.Title
	if name == "" {
		name = "OSCAL import " + doc.Catalog.UUID
	}
	out := ImportedTemplate{
		Name: name, Kind: "overlay", Semver: "0.1.0",
		Provenance: prov, Questions: qs,
	}
	if err := ValidateProvenanceJSON(mustProvenanceJSON(out.Provenance)); err != nil {
		return ImportedTemplate{}, err
	}
	return out, nil
}

func mustProvenanceJSON(m map[string]string) string {
	b, _ := json.Marshal(m)
	return string(b)
}
