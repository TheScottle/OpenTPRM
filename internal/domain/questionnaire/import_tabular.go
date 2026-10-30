package questionnaire

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/TheScottle/OpenTPRM/internal/domain/evidence"
)

// ColumnMappingProfile maps owner-configured CSV/XLSX columns to question fields (QST-010).
type ColumnMappingProfile struct {
	Name         string `json:"name"`
	KeyColumn    string `json:"key_column"`
	TextColumn   string `json:"text_column"`
	TypeColumn   string `json:"type_column,omitempty"`
	DomainColumn string `json:"domain_column,omitempty"`
	SkipHeader   bool   `json:"skip_header"`
}

// DefaultColumnMapping is used when no deployment profile is supplied.
func DefaultColumnMapping() ColumnMappingProfile {
	return ColumnMappingProfile{
		Name: "default", KeyColumn: "key", TextColumn: "text",
		TypeColumn: "type", DomainColumn: "domain", SkipHeader: true,
	}
}

// ImportCSV builds a template skeleton from generic CSV using a column-mapping profile.
// Cells beginning with = + - @ are rejected (never evaluated) — QST-011 / QST-012.
func ImportCSV(r io.Reader, profile ColumnMappingProfile, provenance map[string]string) (ImportedTemplate, error) {
	if profile.KeyColumn == "" {
		profile = DefaultColumnMapping()
	}
	cr := csv.NewReader(r)
	cr.ReuseRecord = true
	header, err := cr.Read()
	if err != nil {
		return ImportedTemplate{}, fmt.Errorf("csv header: %w", err)
	}
	idx := map[string]int{}
	for i, h := range header {
		idx[strings.ToLower(strings.TrimSpace(h))] = i
	}
	keyCol := strings.ToLower(profile.KeyColumn)
	textCol := strings.ToLower(profile.TextColumn)
	if _, ok := idx[keyCol]; !ok {
		return ImportedTemplate{}, fmt.Errorf("missing key column %q", profile.KeyColumn)
	}
	if _, ok := idx[textCol]; !ok {
		return ImportedTemplate{}, fmt.Errorf("missing text column %q", profile.TextColumn)
	}
	cell := func(rec []string, name string) string {
		i, ok := idx[strings.ToLower(name)]
		if !ok || i >= len(rec) {
			return ""
		}
		return strings.TrimSpace(rec[i])
	}
	var qs []ImportedQuestion
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return ImportedTemplate{}, err
		}
		key := cell(rec, profile.KeyColumn)
		text := cell(rec, profile.TextColumn)
		if key == "" && text == "" {
			continue
		}
		for _, v := range rec {
			if formulaLead(v) {
				return ImportedTemplate{}, fmt.Errorf("QST-011: formula cell refused (not evaluated): %q", truncate(v, 40))
			}
			if utf8.RuneCountInString(v) > MaxImportCellRunes {
				return ImportedTemplate{}, fmt.Errorf("QST-011: cell exceeds %d runes", MaxImportCellRunes)
			}
		}
		if key == "" {
			return ImportedTemplate{}, fmt.Errorf("empty key")
		}
		qtype := cell(rec, profile.TypeColumn)
		if qtype == "" {
			qtype = "yes_no_na"
		}
		qs = append(qs, ImportedQuestion{
			Key: key, Text: text, Type: qtype, Domain: cell(rec, profile.DomainColumn),
		})
		if len(qs) > MaxImportQuestions {
			return ImportedTemplate{}, fmt.Errorf("QST-011: exceeded %d questions", MaxImportQuestions)
		}
	}
	if len(qs) == 0 {
		return ImportedTemplate{}, fmt.Errorf("no questions imported")
	}
	return finishImport("CSV import", "overlay", qs, provenance), nil
}

// ImportXLSX parses OOXML worksheet cell values as text only (QST-010/011).
// Formulas are never evaluated: cells with <f> and no cached <v> are refused;
// formula-leading cached values are refused. Archive limits applied first.
func ImportXLSX(data []byte, profile ColumnMappingProfile, provenance map[string]string) (ImportedTemplate, error) {
	if err := ValidateImportArchive(data); err != nil {
		return ImportedTemplate{}, err
	}
	ct, err := evidence.DetectType(data)
	if err != nil || ct != evidence.TypeXLSX {
		return ImportedTemplate{}, fmt.Errorf("not an XLSX workbook")
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return ImportedTemplate{}, err
	}
	shared := map[int]string{}
	var sheetXML []byte
	for _, f := range zr.File {
		switch {
		case f.Name == "xl/sharedStrings.xml":
			b, err := readZipFile(f, MaxImportUncompressed)
			if err != nil {
				return ImportedTemplate{}, err
			}
			shared, err = parseSharedStrings(b)
			if err != nil {
				return ImportedTemplate{}, err
			}
		case strings.HasPrefix(f.Name, "xl/worksheets/sheet") && strings.HasSuffix(f.Name, ".xml"):
			if sheetXML == nil {
				sheetXML, err = readZipFile(f, MaxImportUncompressed)
				if err != nil {
					return ImportedTemplate{}, err
				}
			}
		case strings.HasSuffix(strings.ToLower(f.Name), ".bin"), strings.Contains(strings.ToLower(f.Name), "vba"):
			return ImportedTemplate{}, fmt.Errorf("QST-011: macros/vba refused")
		}
	}
	if sheetXML == nil {
		return ImportedTemplate{}, fmt.Errorf("XLSX missing worksheet")
	}
	rows, err := parseSheetRows(sheetXML, shared)
	if err != nil {
		return ImportedTemplate{}, err
	}
	if len(rows) < 2 {
		return ImportedTemplate{}, fmt.Errorf("XLSX needs header + data rows")
	}
	var buf bytes.Buffer
	cw := csv.NewWriter(&buf)
	for _, row := range rows {
		_ = cw.Write(row)
	}
	cw.Flush()
	return ImportCSV(&buf, profile, provenance)
}

func finishImport(name, kind string, qs []ImportedQuestion, provenance map[string]string) ImportedTemplate {
	prov := provenance
	if prov == nil {
		prov = map[string]string{}
	}
	if prov["license"] == "" {
		prov["license"] = "owner_authored"
	}
	if prov["source"] == "" {
		prov["source"] = name
	}
	if prov["url"] == "" {
		prov["url"] = "https://example.local/import"
	}
	return ImportedTemplate{
		Name: name, Kind: kind, Semver: "0.1.0",
		Provenance: prov, Questions: qs,
	}
}

func formulaLead(s string) bool {
	s = strings.TrimLeft(s, " \t")
	if s == "" {
		return false
	}
	switch s[0] {
	case '=', '+', '-', '@':
		return true
	}
	if strings.HasPrefix(s, "\t") || strings.HasPrefix(s, "\r") {
		return true
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func readZipFile(f *zip.File, max int) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, int64(max)))
}

func parseSharedStrings(data []byte) (map[int]string, error) {
	type si struct {
		T string `xml:"t"`
	}
	type sst struct {
		SI []si `xml:"si"`
	}
	var doc sst
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	out := make(map[int]string, len(doc.SI))
	for i, s := range doc.SI {
		out[i] = s.T
	}
	return out, nil
}

func parseSheetRows(data []byte, shared map[int]string) ([][]string, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	var rows [][]string
	var cur []string
	var inRow, inC, inV, inF bool
	var cellType, vbuf string
	var hasFormula bool
	flushCell := func() error {
		val := strings.TrimSpace(vbuf)
		if hasFormula && val == "" {
			return fmt.Errorf("QST-011: formula without cached value refused")
		}
		if cellType == "s" {
			var idx int
			_, _ = fmt.Sscanf(val, "%d", &idx)
			val = shared[idx]
		}
		if formulaLead(val) {
			return fmt.Errorf("QST-011: formula cell refused (not evaluated)")
		}
		cur = append(cur, val)
		vbuf = ""
		cellType = ""
		hasFormula = false
		return nil
	}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "row":
				inRow = true
				cur = nil
			case "c":
				inC = true
				for _, a := range t.Attr {
					if a.Name.Local == "t" {
						cellType = a.Value
					}
				}
			case "v":
				inV = true
				vbuf = ""
			case "f":
				inF = true
				hasFormula = true
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "row":
				if inRow {
					rows = append(rows, cur)
				}
				inRow = false
			case "c":
				if inC {
					if err := flushCell(); err != nil {
						return nil, err
					}
				}
				inC = false
			case "v":
				inV = false
			case "f":
				inF = false
			}
		case xml.CharData:
			if inV && !inF {
				vbuf += string(t)
			}
		}
	}
	return rows, nil
}
