-- M5+ agents, AI, jobs

CREATE TABLE IF NOT EXISTS agent_clients (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  owner_user_id TEXT NOT NULL,
  client_type TEXT NOT NULL DEFAULT 'delegated',
  redirect_uris_json TEXT NOT NULL DEFAULT '[]',
  scope_ceiling_json TEXT NOT NULL DEFAULT '[]',
  tool_allowlist_json TEXT NOT NULL DEFAULT '[]',
  max_classification TEXT NOT NULL DEFAULT 'Confidential',
  network_cidrs_json TEXT NOT NULL DEFAULT '[]',
  budgets_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  row_version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS oauth_grants (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES agent_clients(id),
  user_id TEXT NOT NULL,
  scopes_json TEXT NOT NULL DEFAULT '[]',
  refresh_hash TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS oauth_tokens (
  id_hash TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL REFERENCES oauth_grants(id),
  client_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  scopes_json TEXT NOT NULL DEFAULT '[]',
  audience TEXT NOT NULL,
  dpop_thumbprint TEXT NOT NULL DEFAULT '',
  expires_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ai_suggestions (
  id TEXT PRIMARY KEY,
  engagement_id TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  citations_json TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'proposed',
  agent_client_id TEXT NOT NULL DEFAULT '',
  delegator_id TEXT NOT NULL DEFAULT '',
  accepted_by TEXT NOT NULL DEFAULT '',
  accepted_at TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  classification TEXT NOT NULL DEFAULT 'Internal'
);

CREATE TABLE IF NOT EXISTS change_requests (
  id TEXT PRIMARY KEY,
  action TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  patch_json TEXT NOT NULL,
  patch_sha256 TEXT NOT NULL,
  target_etag TEXT NOT NULL,
  rationale TEXT NOT NULL DEFAULT '',
  citations_json TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'pending_approval',
  agent_client_id TEXT NOT NULL DEFAULT '',
  delegator_id TEXT NOT NULL DEFAULT '',
  rendered_message TEXT NOT NULL DEFAULT '',
  recipients_json TEXT NOT NULL DEFAULT '[]',
  decided_by TEXT NOT NULL DEFAULT '',
  decided_at TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS model_endpoints (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  base_url TEXT NOT NULL,
  api_style TEXT NOT NULL DEFAULT 'openai',
  model_name TEXT NOT NULL,
  model_digest TEXT NOT NULL DEFAULT '',
  local_flag INTEGER NOT NULL DEFAULT 1,
  max_classification TEXT NOT NULL DEFAULT 'Internal',
  secret_ref TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  approved INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS models (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  digest TEXT NOT NULL,
  license TEXT NOT NULL,
  endpoint_id TEXT NOT NULL DEFAULT '',
  approved_jobs_json TEXT NOT NULL DEFAULT '[]',
  eval_results_json TEXT NOT NULL DEFAULT '{}',
  approved INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_call_logs (
  id TEXT PRIMARY KEY,
  endpoint_id TEXT NOT NULL,
  model_digest TEXT NOT NULL,
  template_hash TEXT NOT NULL,
  input_hash TEXT NOT NULL,
  output_hash TEXT NOT NULL,
  tokens INTEGER NOT NULL DEFAULT 0,
  latency_ms INTEGER NOT NULL DEFAULT 0,
  principal TEXT NOT NULL,
  prompt_sealed BLOB,
  output_sealed BLOB,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  payload_ref TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  run_after TEXT NOT NULL,
  lease_until TEXT NOT NULL DEFAULT '',
  error TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS budget_counters (
  id TEXT PRIMARY KEY,
  subject TEXT NOT NULL,
  window_start TEXT NOT NULL,
  requests INTEGER NOT NULL DEFAULT 0,
  tool_calls INTEGER NOT NULL DEFAULT 0,
  content_bytes INTEGER NOT NULL DEFAULT 0,
  suggestions INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS vendor_users (
  id TEXT PRIMARY KEY,
  third_party_id TEXT NOT NULL REFERENCES third_parties(id),
  email TEXT NOT NULL,
  created_at TEXT NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0,
  UNIQUE(third_party_id, email)
);
