CREATE TABLE IF NOT EXISTS nodes (
  id TEXT PRIMARY KEY,
  slug TEXT,
  domain TEXT NOT NULL UNIQUE,
  port INTEGER NOT NULL DEFAULT 443,
  domain_v4 TEXT,
  domain_v6 TEXT,
  display_name TEXT NOT NULL,
  display_label TEXT,
  public_ipv4 TEXT,
  public_ipv6 TEXT,
  description TEXT,
  buy_url TEXT,
  buy_label TEXT,
  bgp_url TEXT,
  profile_id TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  hidden INTEGER NOT NULL DEFAULT 0,
  maintenance INTEGER NOT NULL DEFAULT 0,
  dynamic_ip INTEGER NOT NULL DEFAULT 0,
  config_version INTEGER NOT NULL DEFAULT 1,
  config_applied_version INTEGER,
  display_order INTEGER,
  agent_public_key TEXT,
  agent_encryption_public_key TEXT,
  version TEXT,
  build_id TEXT,
  capabilities TEXT,
  last_seen_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_slug ON nodes (slug);

CREATE TABLE IF NOT EXISTS node_profiles (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  config_json TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS enroll_tokens (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL,
  node_id TEXT,
  profile_id TEXT,
  auto_approve INTEGER NOT NULL DEFAULT 0,
  max_uses INTEGER NOT NULL DEFAULT 1,
  used_count INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_enroll_tokens_hash
  ON enroll_tokens (token_hash);

CREATE TABLE IF NOT EXISTS certificate_bundles (
  id TEXT PRIMARY KEY,
  domain TEXT NOT NULL,
  version INTEGER NOT NULL,
  domains_json TEXT,
  fingerprint_sha256 TEXT,
  cert_pem TEXT,
  key_pem TEXT,
  ca_pem TEXT,
  cert_expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  active INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS node_certificate_bundles (
  id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL,
  bundle_id TEXT NOT NULL,
  encrypted_payload TEXT NOT NULL,
  recipient_key_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at INTEGER NOT NULL,
  synced_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_node_certificate_bundles_node_created
  ON node_certificate_bundles (node_id, created_at);

CREATE INDEX IF NOT EXISTS idx_node_certificate_bundles_bundle
  ON node_certificate_bundles (bundle_id);

CREATE INDEX IF NOT EXISTS idx_certificate_bundles_domain_active
  ON certificate_bundles (domain, active);

CREATE TABLE IF NOT EXISTS iperf_sessions (
  id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL,
  client_ip_hash TEXT,
  port INTEGER,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  closed_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_iperf_sessions_status_expiry
  ON iperf_sessions (status, expires_at);

CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT PRIMARY KEY,
  bucket TEXT NOT NULL,
  count INTEGER NOT NULL,
  reset_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_reset_at
  ON rate_limits (reset_at);

CREATE TABLE IF NOT EXISTS download_links (
  id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL,
  client_ip_hash TEXT,
  size TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  replaced_at INTEGER,
  extension_count INTEGER NOT NULL DEFAULT 0,
  last_extended_at INTEGER,
  usage_count INTEGER NOT NULL DEFAULT 0,
  last_used_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_download_links_active
  ON download_links (node_id, client_ip_hash, size, status);

CREATE TABLE IF NOT EXISTS operation_audit (
  id TEXT PRIMARY KEY,
  operation_type TEXT NOT NULL,
  node_id TEXT NOT NULL,
  client_ip_hash TEXT,
  status TEXT NOT NULL,
  metadata_json TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  actor TEXT,
  action TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  metadata_json TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  totp_secret TEXT,
  role TEXT NOT NULL DEFAULT 'admin',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_token_hash
  ON admin_sessions (token_hash);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_user_id
  ON admin_sessions (user_id);

CREATE TABLE IF NOT EXISTS used_totp_codes (
  user_id TEXT NOT NULL,
  step INTEGER NOT NULL,
  used_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, step)
);

CREATE INDEX IF NOT EXISTS idx_used_totp_codes_expires_at
  ON used_totp_codes (expires_at);

CREATE TABLE IF NOT EXISTS project_settings (
  key TEXT PRIMARY KEY,
  value_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS runtime_secrets (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS node_init_tokens (
  id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  token_value TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_node_init_tokens_node
  ON node_init_tokens (node_id, created_at);

CREATE TABLE IF NOT EXISTS node_tokens (
  id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER
);

CREATE TABLE IF NOT EXISTS acme_pending_orders (
  id TEXT PRIMARY KEY,
  order_url TEXT NOT NULL,
  finalize_url TEXT NOT NULL,
  csr_der TEXT NOT NULL,
  key_pem TEXT NOT NULL,
  domains_json TEXT NOT NULL,
  challenges_json TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS node_events (
  id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL,
  type TEXT NOT NULL,
  info TEXT,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_node_events_node_created
  ON node_events (node_id, created_at);

CREATE TABLE IF NOT EXISTS task_locks (
  name TEXT PRIMARY KEY,
  locked_until INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
