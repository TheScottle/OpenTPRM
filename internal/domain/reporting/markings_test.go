package reporting

import (
	"strings"
	"testing"
)

func TestGEN_012_ConfigurableMarkings(t *testing.T) {
	cfg := map[string]string{
		"Privileged": "CUSTOM PRIV BANNER",
	}
	doc := ApplyMarking("Privileged", cfg, "committee pack body")
	if doc.Marking != "CUSTOM PRIV BANNER" || doc.Banner != "CUSTOM PRIV BANNER" {
		t.Fatalf("marking: %+v", doc)
	}
	if doc.Body != "committee pack body" || doc.Classification != "Privileged" {
		t.Fatalf("doc: %+v", doc)
	}
	def := ApplyMarking("Client-Confidential", nil, "x")
	if !strings.Contains(def.Marking, "Client-Confidential") {
		t.Fatalf("default marking missing: %q", def.Marking)
	}
}

func TestRPT_004_SensitiveClassification(t *testing.T) {
	if !SensitiveClassification("Privileged") || !SensitiveClassification("Client-Confidential") {
		t.Fatal("expected sensitive")
	}
	if SensitiveClassification("Internal") || SensitiveClassification("Confidential") {
		t.Fatal("internal/confidential are not bulk-sensitive")
	}
}

func TestReportTypesKnown(t *testing.T) {
	if !ReportTypes["exceptions"] || !ReportTypes["committee"] {
		t.Fatal("missing report types")
	}
}
