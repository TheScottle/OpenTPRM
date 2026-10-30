package reporting

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestRPT_002_CommitteeMarkedZipPack(t *testing.T) {
	raw, marking, err := BuildCommitteePack("Client-Confidential", nil, "Q1 committee summary\nsecond approver gate noted")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(marking, "Client-Confidential") {
		t.Fatalf("marking: %q", marking)
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(rc)
		_ = rc.Close()
		names[f.Name] = string(b)
	}
	if _, ok := names["MARKING.txt"]; !ok {
		t.Fatalf("missing MARKING.txt: %v", names)
	}
	sum := names["committee/summary.txt"]
	if !strings.Contains(sum, "Client-Confidential") || !strings.Contains(sum, "second approver") {
		t.Fatalf("summary missing marking/body: %q", sum)
	}
}

func TestRPT_ExportMarkedZipBundle(t *testing.T) {
	raw, _, err := BuildMarkedZip("Internal", nil, []PackFile{
		{Name: "inventory.txt", Content: "vendor-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 40 {
		t.Fatalf("zip too small: %d", len(raw))
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if len(zr.File) < 2 {
		t.Fatalf("want marking+content, got %d", len(zr.File))
	}
}
