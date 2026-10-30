-- M1 inventory / intake / assessment

CREATE TABLE IF NOT EXISTS third_parties (
  id TEXT PRIMARY KEY,
  legal_name TEXT NOT NULL,
  aliases_json TEXT NOT NULL DEFAULT '[]',
  lei TEXT NOT NULL DEFAULT '',
  country TEXT NOT NULL DEFAULT '',
  hq_address TEXT NOT NULL DEFAULT '',
  domains_json TEXT NOT NULL DEFAULT '[]',
  parent_id TEXT NOT NULL DEFAULT '',
  ultimate_parent_id TEXT NOT NULL DEFAULT '',
  public_private TEXT NOT NULL DEFAULT 'private',
  regulated INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'prospect',
  tier INTEGER NOT NULL DEFAULT 0,
  tags_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  row_version INTEGER NOT NULL DEFAULT 1,
  classification TEXT NOT NULL DEFAULT 'Internal',
  restricted INTEGER NOT NULL DEFAULT 0,
  allowlist_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS engagements (
  id TEXT PRIMARY KEY,
  third_party_id TEXT NOT NULL REFERENCES third_parties(id),
  service_description TEXT NOT NULL DEFAULT '',
  service_category TEXT NOT NULL DEFAULT '',
  relationship_owner TEXT NOT NULL DEFAULT '',
  business_unit TEXT NOT NULL DEFAULT '',
  client_ref TEXT NOT NULL DEFAULT '',
  matter_ref TEXT NOT NULL DEFAULT '',
  contract_refs_json TEXT NOT NULL DEFAULT '[]',
  start_date TEXT NOT NULL DEFAULT '',
  end_date TEXT NOT NULL DEFAULT '',
  renewal_date TEXT NOT NULL DEFAULT '',
  spend_band TEXT NOT NULL DEFAULT '',
  data_types_json TEXT NOT NULL DEFAULT '[]',
  highest_classification TEXT NOT NULL DEFAULT 'Internal',
  data_volume_band TEXT NOT NULL DEFAULT '',
  data_locations_json TEXT NOT NULL DEFAULT '[]',
  access_types_json TEXT NOT NULL DEFAULT '[]',
  integration_methods_json TEXT NOT NULL DEFAULT '[]',
  operational_criticality INTEGER NOT NULL DEFAULT 1,
  substitutability INTEGER NOT NULL DEFAULT 3,
  vendor_ai_use TEXT NOT NULL DEFAULT 'unknown',
  vendor_ai_description TEXT NOT NULL DEFAULT '',
  subcontractor_use INTEGER NOT NULL DEFAULT 0,
  inherent_tier INTEGER NOT NULL DEFAULT 0,
  next_action_due TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  row_version INTEGER NOT NULL DEFAULT 1,
  classification TEXT NOT NULL DEFAULT 'Internal',
  restricted INTEGER NOT NULL DEFAULT 0,
  allowlist_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS vendor_contacts (
  id TEXT PRIMARY KEY,
  third_party_id TEXT NOT NULL REFERENCES third_parties(id),
  role TEXT NOT NULL,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  last_verified TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  row_version INTEGER NOT NULL DEFAULT 1,
  classification TEXT NOT NULL DEFAULT 'Internal',
  restricted INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS fourth_party_links (
  id TEXT PRIMARY KEY,
  from_third_party_id TEXT NOT NULL REFERENCES third_parties(id),
  to_third_party_id TEXT NOT NULL REFERENCES third_parties(id),
  role TEXT NOT NULL DEFAULT 'subprocessor',
  source TEXT NOT NULL DEFAULT '',
  data_access TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  row_version INTEGER NOT NULL DEFAULT 1,
  classification TEXT NOT NULL DEFAULT 'Internal',
  restricted INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS object_history (
  id TEXT PRIMARY KEY,
  object_type TEXT NOT NULL,
  object_id TEXT NOT NULL,
  actor TEXT NOT NULL,
  ts TEXT NOT NULL,
  before_json TEXT NOT NULL,
  after_json TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS intakes (
  id TEXT PRIMARY KEY,
  engagement_id TEXT NOT NULL REFERENCES engagements(id),
  answers_json TEXT NOT NULL DEFAULT '{}',
  factor_scores_json TEXT NOT NULL DEFAULT '{}',
  formula_version TEXT NOT NULL DEFAULT 'v1',
  weighted_score REAL NOT NULL DEFAULT 0,
  tier INTEGER NOT NULL DEFAULT 0,
  override_tier INTEGER NOT NULL DEFAULT 0,
  override_justification TEXT NOT NULL DEFAULT '',
  pre_screen TEXT NOT NULL DEFAULT '',
  plan_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'draft',
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  row_version INTEGER NOT NULL DEFAULT 1,
  classification TEXT NOT NULL DEFAULT 'Internal',
  restricted INTEGER NOT NULL DEFAULT 0,
  allowlist_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS assessments (
  id TEXT PRIMARY KEY,
  engagement_id TEXT NOT NULL REFERENCES engagements(id),
  prior_assessment_id TEXT NOT NULL DEFAULT '',
  type TEXT NOT NULL DEFAULT 'onboarding',
  state TEXT NOT NULL DEFAULT 'draft',
  plan_json TEXT NOT NULL DEFAULT '{}',
  residual_rating TEXT NOT NULL DEFAULT '',
  conditions_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  row_version INTEGER NOT NULL DEFAULT 1,
  classification TEXT NOT NULL DEFAULT 'Internal',
  restricted INTEGER NOT NULL DEFAULT 0,
  allowlist_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS assessment_transitions (
  id TEXT PRIMARY KEY,
  assessment_id TEXT NOT NULL REFERENCES assessments(id),
  from_state TEXT NOT NULL,
  to_state TEXT NOT NULL,
  actor TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  ts TEXT NOT NULL
);
