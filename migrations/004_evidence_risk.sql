-- M3 evidence + M4 risk lifecycle

CREATE TABLE IF NOT EXISTS uploads (
  id TEXT PRIMARY KEY,
  engagement_id TEXT NOT NULL DEFAULT '',
  uploader TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'receiving',
  sha256 TEXT NOT NULL DEFAULT '',
  size_bytes INTEGER NOT NULL DEFAULT 0,
  declared_name TEXT NOT NULL DEFAULT '',
  magic_type TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
  id TEXT PRIMARY KEY,
  engagement_id TEXT NOT NULL REFERENCES engagements(id),
  assessment_id TEXT NOT NULL DEFAULT '',
  upload_id TEXT NOT NULL DEFAULT '',
  evidence_type TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'quarantined',
  blob_id TEXT NOT NULL DEFAULT '',
  sha256 TEXT NOT NULL DEFAULT '',
  freshness_expires TEXT NOT NULL DEFAULT '',
  license_tag TEXT NOT NULL DEFAULT 'internal',
  third_party_licensed INTEGER NOT NULL DEFAULT 0,
  risk_flag INTEGER NOT NULL DEFAULT 0,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  row_version INTEGER NOT NULL DEFAULT 1,
  classification TEXT NOT NULL DEFAULT 'Confidential',
  restricted INTEGER NOT NULL DEFAULT 0,
  allowlist_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS evidence_pages (
  id TEXT PRIMARY KEY,
  evidence_id TEXT NOT NULL REFERENCES evidence(id),
  page_num INTEGER NOT NULL,
  text_content TEXT NOT NULL DEFAULT '',
  text_sha256 TEXT NOT NULL DEFAULT '',
  image_blob_id TEXT NOT NULL DEFAULT '',
  hidden_text_detected INTEGER NOT NULL DEFAULT 0,
  UNIQUE(evidence_id, page_num)
);

CREATE TABLE IF NOT EXISTS soc_reviews (
  id TEXT PRIMARY KEY,
  evidence_id TEXT NOT NULL UNIQUE REFERENCES evidence(id),
  review_json TEXT NOT NULL DEFAULT '{}',
  signed_off_by TEXT NOT NULL DEFAULT '',
  signed_off_at TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  row_version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  engagement_id TEXT NOT NULL REFERENCES engagements(id),
  assessment_id TEXT NOT NULL DEFAULT '',
  evidence_id TEXT NOT NULL DEFAULT '',
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL DEFAULT 'medium',
  status TEXT NOT NULL DEFAULT 'open',
  finding_type TEXT NOT NULL DEFAULT 'control_gap',
  controls_json TEXT NOT NULL DEFAULT '[]',
  source TEXT NOT NULL DEFAULT '',
  due_date TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  row_version INTEGER NOT NULL DEFAULT 1,
  classification TEXT NOT NULL DEFAULT 'Internal',
  restricted INTEGER NOT NULL DEFAULT 0,
  allowlist_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS remediation_plans (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES findings(id),
  steps_json TEXT NOT NULL DEFAULT '[]',
  owner TEXT NOT NULL DEFAULT '',
  due_date TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'open',
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS risk_results (
  id TEXT PRIMARY KEY,
  engagement_id TEXT NOT NULL REFERENCES engagements(id),
  assessment_id TEXT NOT NULL DEFAULT '',
  formula_version TEXT NOT NULL DEFAULT 'v1',
  inputs_json TEXT NOT NULL DEFAULT '{}',
  magnitude INTEGER NOT NULL DEFAULT 1,
  likelihood INTEGER NOT NULL DEFAULT 1,
  residual INTEGER NOT NULL DEFAULT 1,
  residual_band TEXT NOT NULL DEFAULT 'low',
  explanation TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS exceptions (
  id TEXT PRIMARY KEY,
  engagement_id TEXT NOT NULL REFERENCES engagements(id),
  scope TEXT NOT NULL DEFAULT '',
  rationale TEXT NOT NULL DEFAULT '',
  requester TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  expires_at TEXT NOT NULL DEFAULT '',
  decision_payload TEXT NOT NULL DEFAULT '',
  decision_signature BLOB,
  approved_by TEXT NOT NULL DEFAULT '',
  approved_at TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  row_version INTEGER NOT NULL DEFAULT 1,
  classification TEXT NOT NULL DEFAULT 'Internal',
  restricted INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS contracts (
  id TEXT PRIMARY KEY,
  engagement_id TEXT NOT NULL REFERENCES engagements(id),
  title TEXT NOT NULL DEFAULT '',
  start_date TEXT NOT NULL DEFAULT '',
  end_date TEXT NOT NULL DEFAULT '',
  renewal_date TEXT NOT NULL DEFAULT '',
  clause_checklist_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  row_version INTEGER NOT NULL DEFAULT 1,
  classification TEXT NOT NULL DEFAULT 'Confidential',
  restricted INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS obligations (
  id TEXT PRIMARY KEY,
  engagement_id TEXT NOT NULL,
  client_id TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'open',
  due_date TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  row_version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS clients (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  row_version INTEGER NOT NULL DEFAULT 1,
  classification TEXT NOT NULL DEFAULT 'Client-Confidential',
  restricted INTEGER NOT NULL DEFAULT 0,
  allowlist_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS client_requirements (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES clients(id),
  text TEXT NOT NULL,
  flowed_to_engagement TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS monitoring_signals (
  id TEXT PRIMARY KEY,
  engagement_id TEXT NOT NULL DEFAULT '',
  third_party_id TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT 'internal',
  payload_ref TEXT NOT NULL DEFAULT '',
  disposition TEXT NOT NULL DEFAULT 'new',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS offboarding_checklists (
  id TEXT PRIMARY KEY,
  engagement_id TEXT NOT NULL UNIQUE REFERENCES engagements(id),
  items_json TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'open',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS legal_holds (
  id TEXT PRIMARY KEY,
  object_type TEXT NOT NULL,
  object_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  released_at TEXT NOT NULL DEFAULT '',
  released_by TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS tombstones (
  id TEXT PRIMARY KEY,
  object_type TEXT NOT NULL,
  object_id TEXT NOT NULL,
  shredded_at TEXT NOT NULL,
  policy TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS vendor_data_keys (
  vendor_id TEXT PRIMARY KEY,
  wrapped_key BLOB NOT NULL,
  created_at TEXT NOT NULL
);
