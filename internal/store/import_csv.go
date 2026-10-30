package store

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	"github.com/google/uuid"
)

// BulkImportVendorsCSV imports inventory rows through quarantine-style validation (INV-008).
// Formulas are never evaluated: cells starting with =, +, -, @ are rejected.
func (s *Store) BulkImportVendorsCSV(ctx context.Context, r io.Reader, actor string) ([]ImportRowResult, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	cr := csv.NewReader(r)
	cr.ReuseRecord = true
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("csv header: %w", err)
	}
	idx := map[string]int{}
	for i, h := range header {
		idx[strings.ToLower(strings.TrimSpace(h))] = i
	}
	required := []string{"legal_name"}
	for _, col := range required {
		if _, ok := idx[col]; !ok {
			return nil, fmt.Errorf("missing required column %q", col)
		}
	}

	var results []ImportRowResult
	rowNum := 1
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		rowNum++
		if err != nil {
			results = append(results, ImportRowResult{Row: rowNum, OK: false, Error: err.Error()})
			continue
		}
		cell := func(name string) string {
			i, ok := idx[name]
			if !ok || i >= len(rec) {
				return ""
			}
			return strings.TrimSpace(rec[i])
		}
		legal := cell("legal_name")
		if legal == "" {
			results = append(results, ImportRowResult{Row: rowNum, OK: false, Error: "legal_name required"})
			continue
		}
		fields := []string{legal, cell("lei"), cell("country"), cell("domain"), cell("status")}
		if bad := formulaCell(fields...); bad != "" {
			results = append(results, ImportRowResult{Row: rowNum, OK: false, Error: "formula neutralized: " + bad})
			continue
		}
		status := cell("status")
		if status == "" {
			status = "prospect"
		}
		domain := cell("domain")
		domainsJSON := "[]"
		if domain != "" {
			domainsJSON = `["` + escapeJSONString(domain) + `"]`
		}
		v := Vendor{
			ID:          uuid.Must(uuid.NewV7()).String(),
			LegalName:   legal,
			LEI:         cell("lei"),
			Country:     cell("country"),
			DomainsJSON: domainsJSON,
			Status:      status,
			CreatedBy:   actor,
			UpdatedBy:   actor,
		}
		if err := s.CreateVendor(ctx, v); err != nil {
			results = append(results, ImportRowResult{Row: rowNum, OK: false, Error: err.Error()})
			continue
		}
		results = append(results, ImportRowResult{Row: rowNum, OK: true, VendorID: v.ID})
	}
	return results, nil
}

func formulaCell(vals ...string) string {
	for _, v := range vals {
		if v == "" {
			continue
		}
		switch v[0] {
		case '=', '+', '-', '@':
			return v
		}
	}
	return ""
}

func escapeJSONString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
