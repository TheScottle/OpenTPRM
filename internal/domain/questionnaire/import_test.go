package questionnaire_test

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TheScottle/OpenTPRM/internal/domain/evidence"
	"github.com/TheScottle/OpenTPRM/internal/domain/questionnaire"
)

func TestImportOSCALCatalog(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "seed", "oscal-catalog-min.json"))
	if err != nil {
		t.Fatal(err)
	}
	tpl, err := questionnaire.ImportOSCALCatalog(raw, map[string]string{
		"source":  "NIST OSCAL sample (minimal)",
		"license": "us_government_work",
		"url":     "https://github.com/usnistgov/OSCAL",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tpl.Questions) < 2 {
		t.Fatalf("questions=%d", len(tpl.Questions))
	}
	if tpl.Kind != "overlay" || tpl.Name == "" {
		t.Fatalf("%+v", tpl)
	}
}

func TestImportCSVAndFormulaRefuse(t *testing.T) {
	ok := "key,text,type,domain\nIAM-01,Unique accounts?,yes_no_na,PR.AA\n"
	tpl, err := questionnaire.ImportCSV(strings.NewReader(ok), questionnaire.DefaultColumnMapping(), map[string]string{
		"source": "Owner CSV", "license": "owner_authored", "url": "https://example.local",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tpl.Questions) != 1 || tpl.Questions[0].Key != "IAM-01" {
		t.Fatalf("%+v", tpl)
	}

	bad := "key,text\nX,=cmd|'/c calc'!A0\n"
	if _, err := questionnaire.ImportCSV(strings.NewReader(bad), questionnaire.DefaultColumnMapping(), nil); err == nil {
		t.Fatal("formula cell must be refused")
	}
}

func TestQST_011_ArchiveBombRejected(t *testing.T) {
	// Reuse evidence AT-08 craft path via a nested zip that declares huge size.
	data := craftTinyBombZip()
	err := questionnaire.ValidateImportArchive(data)
	if err == nil {
		t.Fatal("expected QST-011 limit rejection")
	}
	if !errorsIsArchive(err) {
		t.Fatalf("want archive/size error, got %v", err)
	}
}

func TestQST_011_XLSXMacroPathRefused(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	// Minimal OOXML markers so DetectType sees xlsx, plus a vba stream name.
	w, _ := zw.Create("[Content_Types].xml")
	_, _ = w.Write([]byte(`<?xml version="1.0"?><Types></Types>`))
	w, _ = zw.Create("xl/workbook.xml")
	_, _ = w.Write([]byte(`<?xml version="1.0"?><workbook/>`))
	w, _ = zw.Create("xl/vbaProject.bin")
	_, _ = w.Write([]byte("MZ"))
	_ = zw.Close()
	// May fail as not-xlsx (no word/xl content types dance) — still must not succeed import.
	_, err := questionnaire.ImportXLSX(buf.Bytes(), questionnaire.DefaultColumnMapping(), nil)
	if err == nil {
		t.Fatal("expected refusal")
	}
}

func TestImportXLSXHappyPath(t *testing.T) {
	data := buildMinimalXLSX(t, [][]string{
		{"key", "text", "type", "domain"},
		{"CTRL-1", "Is MFA enforced?", "yes_no_na", "PR.AA"},
	})
	tpl, err := questionnaire.ImportXLSX(data, questionnaire.DefaultColumnMapping(), map[string]string{
		"source": "Owner XLSX", "license": "owner_authored", "url": "https://example.local",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tpl.Questions) != 1 || tpl.Questions[0].Key != "CTRL-1" {
		t.Fatalf("%+v", tpl)
	}
}

func errorsIsArchive(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "archive") ||
		strings.Contains(err.Error(), "size") ||
		strings.Contains(err.Error(), "ratio") ||
		strings.Contains(err.Error(), "limit"))
}

func craftTinyBombZip() []byte {
	// Build via evidence test approach: zip with huge declared uncompressed.
	name := []byte("bomb.bin")
	payload := []byte("x")
	var local bytes.Buffer
	local.Write([]byte("PK\x03\x04"))
	writeU16(&local, 20)
	writeU16(&local, 0)
	writeU16(&local, 0)
	writeU16(&local, 0)
	writeU16(&local, 0)
	writeU32(&local, 0) // crc
	writeU32(&local, uint32(len(payload)))
	writeU32(&local, uint32(evidence.MaxZIPUncompressed)+1)
	writeU16(&local, uint16(len(name)))
	writeU16(&local, 0)
	local.Write(name)
	local.Write(payload)
	lb := local.Bytes()
	var central bytes.Buffer
	central.Write([]byte("PK\x01\x02"))
	writeU16(&central, 20)
	writeU16(&central, 20)
	writeU16(&central, 0)
	writeU16(&central, 0)
	writeU16(&central, 0)
	writeU16(&central, 0)
	writeU32(&central, 0)
	writeU32(&central, uint32(len(payload)))
	writeU32(&central, uint32(evidence.MaxZIPUncompressed)+1)
	writeU16(&central, uint16(len(name)))
	writeU16(&central, 0)
	writeU16(&central, 0)
	writeU16(&central, 0)
	writeU16(&central, 0)
	writeU32(&central, 0)
	writeU32(&central, 0)
	central.Write(name)
	cb := central.Bytes()
	var end bytes.Buffer
	end.Write([]byte("PK\x05\x06"))
	writeU16(&end, 0)
	writeU16(&end, 0)
	writeU16(&end, 1)
	writeU16(&end, 1)
	writeU32(&end, uint32(len(cb)))
	writeU32(&end, uint32(len(lb)))
	writeU16(&end, 0)
	out := append(lb, cb...)
	return append(out, end.Bytes()...)
}

func writeU16(b *bytes.Buffer, v uint16) {
	b.WriteByte(byte(v))
	b.WriteByte(byte(v >> 8))
}

func writeU32(b *bytes.Buffer, v uint32) {
	b.WriteByte(byte(v))
	b.WriteByte(byte(v >> 8))
	b.WriteByte(byte(v >> 16))
	b.WriteByte(byte(v >> 24))
}

func buildMinimalXLSX(t *testing.T, rows [][]string) []byte {
	t.Helper()
	var shared []string
	sharedIdx := map[string]int{}
	idxOf := func(s string) int {
		if i, ok := sharedIdx[s]; ok {
			return i
		}
		i := len(shared)
		shared = append(shared, s)
		sharedIdx[s] = i
		return i
	}
	var sheet bytes.Buffer
	sheet.WriteString(`<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)
	for r, row := range rows {
		sheet.WriteString(`<row r="` + itoa(r+1) + `">`)
		for c, val := range row {
			si := idxOf(val)
			ref := colName(c) + itoa(r+1)
			sheet.WriteString(`<c r="` + ref + `" t="s"><v>` + itoa(si) + `</v></c>`)
		}
		sheet.WriteString(`</row>`)
	}
	sheet.WriteString(`</sheetData></worksheet>`)

	var sst bytes.Buffer
	sst.WriteString(`<?xml version="1.0"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">`)
	for _, s := range shared {
		sst.WriteString(`<si><t>` + xmlEscape(s) + `</t></si>`)
	}
	sst.WriteString(`</sst>`)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	files := map[string]string{
		"[Content_Types].xml": `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>
</Types>`,
		"xl/workbook.xml":        `<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/></sheets></workbook>`,
		"xl/worksheets/sheet1.xml": sheet.String(),
		"xl/sharedStrings.xml":     sst.String(),
	}
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}

func colName(i int) string {
	return string(rune('A' + i))
}

func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
