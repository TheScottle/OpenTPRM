-- M4/M9 reports and exports metadata

CREATE TABLE IF NOT EXISTS exports (
  id TEXT PRIMARY KEY,
  format TEXT NOT NULL DEFAULT 'json',
  scope TEXT NOT NULL DEFAULT '',
  classification TEXT NOT NULL DEFAULT 'Internal',
  marking TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  requester TEXT NOT NULL,
  second_approver TEXT NOT NULL DEFAULT '',
  step_up_required INTEGER NOT NULL DEFAULT 0,
  payload_ref TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  created_by TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_exports_requester ON exports(requester);
