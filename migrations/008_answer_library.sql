-- M2 answer library (QST-035)

CREATE TABLE IF NOT EXISTS answer_library (
  id TEXT PRIMARY KEY,
  vendor_id TEXT NOT NULL REFERENCES third_parties(id),
  question_key TEXT NOT NULL,
  answer_json TEXT NOT NULL,
  effective_date TEXT NOT NULL,
  source_instance_id TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'accepted',
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  UNIQUE(vendor_id, question_key)
);

CREATE INDEX IF NOT EXISTS idx_answer_library_vendor ON answer_library(vendor_id);
