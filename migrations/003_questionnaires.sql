-- M2 questionnaires

CREATE TABLE IF NOT EXISTS questionnaire_templates (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'core',
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  row_version INTEGER NOT NULL DEFAULT 1,
  classification TEXT NOT NULL DEFAULT 'Internal',
  restricted INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS template_versions (
  id TEXT PRIMARY KEY,
  template_id TEXT NOT NULL REFERENCES questionnaire_templates(id),
  semver TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft',
  content_hash TEXT NOT NULL DEFAULT '',
  content_json TEXT NOT NULL,
  provenance_json TEXT NOT NULL DEFAULT '{}',
  last_editor TEXT NOT NULL DEFAULT '',
  published_by TEXT NOT NULL DEFAULT '',
  published_at TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  row_version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS questionnaire_instances (
  id TEXT PRIMARY KEY,
  template_version_id TEXT NOT NULL REFERENCES template_versions(id),
  engagement_id TEXT NOT NULL REFERENCES engagements(id),
  assessment_id TEXT NOT NULL DEFAULT '',
  pinned_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft',
  delta_of TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  row_version INTEGER NOT NULL DEFAULT 1,
  classification TEXT NOT NULL DEFAULT 'Internal',
  restricted INTEGER NOT NULL DEFAULT 0,
  allowlist_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS response_revisions (
  id TEXT PRIMARY KEY,
  instance_id TEXT NOT NULL REFERENCES questionnaire_instances(id),
  revision INTEGER NOT NULL,
  answers_json TEXT NOT NULL,
  actor TEXT NOT NULL,
  ts TEXT NOT NULL,
  UNIQUE(instance_id, revision)
);

CREATE TABLE IF NOT EXISTS answer_reviews (
  id TEXT PRIMARY KEY,
  instance_id TEXT NOT NULL REFERENCES questionnaire_instances(id),
  question_key TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  score REAL NOT NULL DEFAULT 0,
  reviewer TEXT NOT NULL DEFAULT '',
  notes TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);
