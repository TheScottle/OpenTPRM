-- INV-006 typed custom fields + INV-009 reassessment hint on engagements

CREATE TABLE IF NOT EXISTS custom_field_defs (
  id TEXT PRIMARY KEY,
  object_type TEXT NOT NULL,
  field_key TEXT NOT NULL,
  field_type TEXT NOT NULL,
  enum_values_json TEXT NOT NULL DEFAULT '[]',
  required INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  UNIQUE(object_type, field_key)
);

CREATE TABLE IF NOT EXISTS custom_field_values (
  id TEXT PRIMARY KEY,
  object_type TEXT NOT NULL,
  object_id TEXT NOT NULL,
  def_id TEXT NOT NULL REFERENCES custom_field_defs(id),
  value_json TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  UNIQUE(object_type, object_id, def_id)
);

CREATE INDEX IF NOT EXISTS idx_custom_field_defs_type ON custom_field_defs(object_type);
CREATE INDEX IF NOT EXISTS idx_custom_field_values_obj ON custom_field_values(object_type, object_id);

-- Optional reassessment due date used by INV-009 next-action computation.
-- SQLite lacks IF NOT EXISTS for ADD COLUMN; tolerate re-apply via migration versioning.
ALTER TABLE engagements ADD COLUMN reassessment_due TEXT NOT NULL DEFAULT '';
