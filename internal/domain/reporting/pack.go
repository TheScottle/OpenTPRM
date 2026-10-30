package reporting

import (
	"archive/zip"
	"bytes"
	"fmt"
	"strings"
	"time"
)

// PackFile is one entry in a marked export/committee bundle.
type PackFile struct {
	Name    string
	Content string
}

// BuildMarkedZip builds a ZIP with a MARKING.txt banner plus content files (RPT-002/004).
// Prefer this over heavy PDF libraries until ADR-0004 is revisited.
func BuildMarkedZip(classification string, markings map[string]string, files []PackFile) ([]byte, string, error) {
	marking := ResolveMarking(classification, markings)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	markBody := fmt.Sprintf("%s\nClassification: %s\nGenerated: %s\n",
		marking, classification, time.Now().UTC().Format(time.RFC3339))
	if err := writeZipFile(zw, "MARKING.txt", markBody); err != nil {
		_ = zw.Close()
		return nil, "", err
	}

	for _, f := range files {
		name := strings.TrimSpace(f.Name)
		if name == "" {
			name = "content.txt"
		}
		// Prefix each content file with the marking banner for GEN-012.
		body := marking + "\n\n" + f.Content
		if err := writeZipFile(zw, name, body); err != nil {
			_ = zw.Close()
			return nil, "", err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), marking, nil
}

// BuildCommitteePack returns a marked ZIP for the committee report type.
func BuildCommitteePack(classification string, markings map[string]string, summary string) ([]byte, string, error) {
	if strings.TrimSpace(summary) == "" {
		summary = "Committee pack stub.\nSecond approver required for Client-Confidential bulk exports via /exports/{id}:approve.\n"
	}
	files := []PackFile{
		{Name: "committee/summary.txt", Content: summary},
		{Name: "committee/readme.txt", Content: "OpenTPRM committee export bundle (text pack; PDF via pdfcpu deferred — ADR-0004)."},
	}
	return BuildMarkedZip(classification, markings, files)
}

func writeZipFile(zw *zip.Writer, name, body string) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = w.Write([]byte(body))
	return err
}
