package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

const MaxCustomFieldsPerType = 50

// CustomFieldDef is a typed custom field schema entry (INV-006).
type CustomFieldDef struct {
	ID             string   `json:"id"`
	ObjectType     string   `json:"object_type"`
	FieldKey       string   `json:"field_key"`
	FieldType      string   `json:"field_type"` // string|number|boolean|enum|date
	EnumValuesJSON string   `json:"enum_values_json,omitempty"`
	EnumValues     []string `json:"enum_values,omitempty"`
	Required       bool     `json:"required"`
	CreatedBy      string   `json:"created_by"`
	CreatedAt      string   `json:"created_at,omitempty"`
}

// CustomFieldValue is a validated value bound to an object (INV-006).
type CustomFieldValue struct {
	ID         string `json:"id"`
	ObjectType string `json:"object_type"`
	ObjectID   string `json:"object_id"`
	DefID      string `json:"def_id"`
	FieldKey   string `json:"field_key,omitempty"`
	ValueJSON  string `json:"value_json"`
	UpdatedBy  string `json:"updated_by"`
	UpdatedAt  string `json:"updated_at,omitempty"`
}

var allowedFieldTypes = map[string]bool{
	"string": true, "number": true, "boolean": true, "enum": true, "date": true,
}

// CreateCustomFieldDef registers a schema-validated custom field (max 50 per object type).
func (s *Store) CreateCustomFieldDef(ctx context.Context, d CustomFieldDef) error {
	if _, err := RequireAuthz(ctx); err != nil {
		return err
	}
	d.ObjectType = strings.TrimSpace(d.ObjectType)
	d.FieldKey = strings.TrimSpace(d.FieldKey)
	d.FieldType = strings.ToLower(strings.TrimSpace(d.FieldType))
	if d.ObjectType == "" || d.FieldKey == "" {
		return fmt.Errorf("INV-006: object_type and field_key required")
	}
	if !allowedFieldTypes[d.FieldType] {
		return fmt.Errorf("INV-006: unsupported field_type %q", d.FieldType)
	}
	if d.FieldType == "enum" {
		if len(d.EnumValues) == 0 && d.EnumValuesJSON != "" {
			_ = json.Unmarshal([]byte(d.EnumValuesJSON), &d.EnumValues)
		}
		if len(d.EnumValues) == 0 {
			return fmt.Errorf("INV-006: enum fields require enum_values")
		}
		b, _ := json.Marshal(d.EnumValues)
		d.EnumValuesJSON = string(b)
	}
	if d.EnumValuesJSON == "" {
		d.EnumValuesJSON = "[]"
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM custom_field_defs WHERE object_type=?`, d.ObjectType).Scan(&n); err != nil {
		return err
	}
	if n >= MaxCustomFieldsPerType {
		return fmt.Errorf("INV-006: max %d custom fields per object type", MaxCustomFieldsPerType)
	}
	if d.ID == "" {
		d.ID = uuid.Must(uuid.NewV7()).String()
	}
	now := nowUTC()
	_, err := s.db.ExecContext(ctx, `INSERT INTO custom_field_defs(id, object_type, field_key, field_type, enum_values_json, required, created_at, created_by)
		VALUES(?,?,?,?,?,?,?,?)`,
		d.ID, d.ObjectType, d.FieldKey, d.FieldType, d.EnumValuesJSON, boolInt(d.Required), now, d.CreatedBy)
	return err
}

// ListCustomFieldDefs lists definitions for an object type.
func (s *Store) ListCustomFieldDefs(ctx context.Context, objectType string) ([]CustomFieldDef, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, object_type, field_key, field_type, enum_values_json, required, created_by, created_at
		FROM custom_field_defs WHERE object_type=? ORDER BY field_key`, objectType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CustomFieldDef
	for rows.Next() {
		var d CustomFieldDef
		var req int
		if err := rows.Scan(&d.ID, &d.ObjectType, &d.FieldKey, &d.FieldType, &d.EnumValuesJSON, &req, &d.CreatedBy, &d.CreatedAt); err != nil {
			return nil, err
		}
		d.Required = req == 1
		_ = json.Unmarshal([]byte(d.EnumValuesJSON), &d.EnumValues)
		out = append(out, d)
	}
	return out, rows.Err()
}

// SetCustomFieldValue validates and upserts a custom field value (INV-006).
func (s *Store) SetCustomFieldValue(ctx context.Context, v CustomFieldValue) error {
	if _, err := RequireAuthz(ctx); err != nil {
		return err
	}
	var def CustomFieldDef
	var req int
	err := s.db.QueryRowContext(ctx, `SELECT id, object_type, field_key, field_type, enum_values_json, required
		FROM custom_field_defs WHERE id=?`, v.DefID).
		Scan(&def.ID, &def.ObjectType, &def.FieldKey, &def.FieldType, &def.EnumValuesJSON, &req)
	if err == sql.ErrNoRows {
		return fmt.Errorf("INV-006: unknown field def")
	}
	if err != nil {
		return err
	}
	def.Required = req == 1
	_ = json.Unmarshal([]byte(def.EnumValuesJSON), &def.EnumValues)
	if v.ObjectType == "" {
		v.ObjectType = def.ObjectType
	}
	if v.ObjectType != def.ObjectType {
		return fmt.Errorf("INV-006: object_type mismatch")
	}
	if err := validateCustomFieldValue(def, v.ValueJSON); err != nil {
		return err
	}
	now := nowUTC()
	if v.ID == "" {
		v.ID = uuid.Must(uuid.NewV7()).String()
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO custom_field_values(id, object_type, object_id, def_id, value_json, updated_at, updated_by)
		VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(object_type, object_id, def_id) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at, updated_by=excluded.updated_by`,
		v.ID, v.ObjectType, v.ObjectID, v.DefID, v.ValueJSON, now, v.UpdatedBy)
	return err
}

// ListCustomFieldValues returns values for an object.
func (s *Store) ListCustomFieldValues(ctx context.Context, objectType, objectID string) ([]CustomFieldValue, error) {
	if _, err := RequireAuthz(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT v.id, v.object_type, v.object_id, v.def_id, d.field_key, v.value_json, v.updated_by, v.updated_at
		FROM custom_field_values v JOIN custom_field_defs d ON d.id=v.def_id
		WHERE v.object_type=? AND v.object_id=? ORDER BY d.field_key`, objectType, objectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CustomFieldValue
	for rows.Next() {
		var v CustomFieldValue
		if err := rows.Scan(&v.ID, &v.ObjectType, &v.ObjectID, &v.DefID, &v.FieldKey, &v.ValueJSON, &v.UpdatedBy, &v.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ValidateTagsJSON ensures tags is a JSON array of short strings (INV-006).
func ValidateTagsJSON(tagsJSON string) error {
	if tagsJSON == "" {
		return nil
	}
	var tags []string
	if err := json.Unmarshal([]byte(tagsJSON), &tags); err != nil {
		return fmt.Errorf("INV-006: tags must be a JSON string array")
	}
	if len(tags) > MaxCustomFieldsPerType {
		return fmt.Errorf("INV-006: max %d tags", MaxCustomFieldsPerType)
	}
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t == "" || len(t) > 64 {
			return fmt.Errorf("INV-006: invalid tag")
		}
	}
	return nil
}

func validateCustomFieldValue(def CustomFieldDef, valueJSON string) error {
	if strings.TrimSpace(valueJSON) == "" {
		if def.Required {
			return fmt.Errorf("INV-006: required field %s missing", def.FieldKey)
		}
		return nil
	}
	var raw any
	if err := json.Unmarshal([]byte(valueJSON), &raw); err != nil {
		return fmt.Errorf("INV-006: value must be JSON: %w", err)
	}
	switch def.FieldType {
	case "string", "date":
		s, ok := raw.(string)
		if !ok {
			return fmt.Errorf("INV-006: %s expects string", def.FieldKey)
		}
		if def.FieldType == "date" && len(s) < 8 {
			return fmt.Errorf("INV-006: %s expects ISO date", def.FieldKey)
		}
	case "number":
		switch raw.(type) {
		case float64, json.Number:
		default:
			return fmt.Errorf("INV-006: %s expects number", def.FieldKey)
		}
	case "boolean":
		if _, ok := raw.(bool); !ok {
			return fmt.Errorf("INV-006: %s expects boolean", def.FieldKey)
		}
	case "enum":
		s, ok := raw.(string)
		if !ok {
			return fmt.Errorf("INV-006: %s expects enum string", def.FieldKey)
		}
		ok = false
		for _, e := range def.EnumValues {
			if e == s {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("INV-006: %s value not in enum", def.FieldKey)
		}
	}
	return nil
}
