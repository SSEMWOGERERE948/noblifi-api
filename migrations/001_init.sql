CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  email text UNIQUE NOT NULL,
  password_hash text NOT NULL,
  role text NOT NULL,
  created_at timestamp NOT NULL DEFAULT now(),
  updated_at timestamp NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sites (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  location text NULL,
  created_at timestamp NOT NULL DEFAULT now(),
  updated_at timestamp NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS routers (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  site_id uuid NULL REFERENCES sites(id),
  name text NOT NULL,
  site_name text NULL,
  expected_model text NULL,
  model text NULL,
  serial_number text UNIQUE NULL,
  mac_address text NULL,
  routeros_version text NULL,
  management_ip text NULL,
  api_username text NULL,
  api_password_encrypted text NULL,
  radius_secret_encrypted text NULL,
  wire_guard_tunnel_ip text UNIQUE NULL,
  wire_guard_public_key text UNIQUE NULL,
  wire_guard_status text NOT NULL DEFAULT 'disabled',
  wire_guard_last_seen_at timestamp NULL,
  status text NOT NULL DEFAULT 'pending',
  claim_token text UNIQUE NOT NULL,
  claim_token_expires_at timestamp NULL,
  last_seen_at timestamp NULL,
  provisioned_at timestamp NULL,
  created_at timestamp NOT NULL DEFAULT now(),
  updated_at timestamp NOT NULL DEFAULT now()
);

ALTER TABLE routers ADD COLUMN IF NOT EXISTS wire_guard_tunnel_ip text UNIQUE;
ALTER TABLE routers ADD COLUMN IF NOT EXISTS wire_guard_public_key text UNIQUE;
ALTER TABLE routers ADD COLUMN IF NOT EXISTS wire_guard_status text NOT NULL DEFAULT 'disabled';
ALTER TABLE routers ADD COLUMN IF NOT EXISTS wire_guard_last_seen_at timestamp NULL;

CREATE TABLE IF NOT EXISTS router_setup_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  router_id uuid NOT NULL UNIQUE REFERENCES routers(id) ON DELETE CASCADE,
  current_step text NOT NULL DEFAULT 'remote_access',
  remote_access_method text NULL,
  configuration_method text NULL,
  deployment_status text NOT NULL DEFAULT 'draft',
  error_message text NULL,
  created_at timestamp NOT NULL DEFAULT now(),
  updated_at timestamp NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS router_network_profiles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  router_id uuid NOT NULL UNIQUE REFERENCES routers(id) ON DELETE CASCADE,
  name text NOT NULL,
  radius_server text NOT NULL,
  radius_secret text NOT NULL,
  router_identity text NOT NULL,
  api_username text NOT NULL,
  api_password text NOT NULL,
  hotspot_bridge text NOT NULL,
  staff_bridge text NOT NULL,
  pos_bridge text NOT NULL,
  cctv_bridge text NOT NULL,
  hotspot_subnet text NOT NULL,
  hotspot_gateway text NOT NULL,
  hotspot_pool text NOT NULL,
  staff_subnet text NOT NULL,
  staff_gateway text NOT NULL,
  staff_pool text NOT NULL,
  pos_subnet text NOT NULL,
  pos_gateway text NOT NULL,
  pos_pool text NOT NULL,
  cctv_subnet text NOT NULL,
  cctv_gateway text NOT NULL,
  cctv_pool text NOT NULL,
  hotspot_dns_name text NOT NULL,
  hotspot_portal_name text NOT NULL DEFAULT 'NobliFi WiFi',
  wan_mode text NOT NULL DEFAULT 'dhcp',
  pppoe_username text NULL,
  pppoe_password text NULL,
  disable_www_service boolean NOT NULL DEFAULT true,
  enable_api_service boolean NOT NULL DEFAULT true,
  enable_api_ssl_service boolean NOT NULL DEFAULT true,
  created_at timestamp NOT NULL DEFAULT now(),
  updated_at timestamp NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS router_interfaces (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  router_id uuid NOT NULL REFERENCES routers(id) ON DELETE CASCADE,
  name text NOT NULL,
  type text NULL,
  mac_address text NULL,
  running boolean NOT NULL DEFAULT false,
  disabled boolean NOT NULL DEFAULT false,
  discovered_at timestamp NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS router_port_assignments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  router_id uuid NOT NULL REFERENCES routers(id) ON DELETE CASCADE,
  interface_name text NOT NULL,
  role text NOT NULL,
  bridge_name text NULL,
  vlan_id int NULL,
  created_at timestamp NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS router_config_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  router_id uuid NOT NULL REFERENCES routers(id) ON DELETE CASCADE,
  action text NOT NULL,
  status text NOT NULL,
  request_payload jsonb NULL,
  response_payload jsonb NULL,
  error_message text NULL,
  created_at timestamp NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS plans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  price integer NOT NULL,
  duration_minutes integer NOT NULL,
  data_limit_mb integer NULL,
  upload_speed text NOT NULL,
  download_speed text NOT NULL,
  max_devices integer NOT NULL,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp NOT NULL DEFAULT now(),
  updated_at timestamp NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS vouchers (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code text UNIQUE NOT NULL,
  plan_id uuid NOT NULL REFERENCES plans(id),
  status text NOT NULL DEFAULT 'unused',
  starts_at timestamp NULL,
  expires_at timestamp NULL,
  used_at timestamp NULL,
  created_at timestamp NOT NULL DEFAULT now(),
  updated_at timestamp NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  voucher_id uuid NULL REFERENCES vouchers(id),
  router_id uuid NULL REFERENCES routers(id),
  username text NOT NULL,
  mac_address text NULL,
  ip_address text NULL,
  started_at timestamp NULL,
  stopped_at timestamp NULL,
  upload_bytes bigint NOT NULL DEFAULT 0,
  download_bytes bigint NOT NULL DEFAULT 0,
  status text NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS radcheck (
  id bigserial PRIMARY KEY,
  username text NOT NULL,
  attribute text NOT NULL,
  op varchar(2) NOT NULL DEFAULT '==',
  value text NOT NULL
);

CREATE INDEX IF NOT EXISTS radcheck_username_idx ON radcheck(username);

CREATE TABLE IF NOT EXISTS radreply (
  id bigserial PRIMARY KEY,
  username text NOT NULL,
  attribute text NOT NULL,
  op varchar(2) NOT NULL DEFAULT '=',
  value text NOT NULL
);

CREATE INDEX IF NOT EXISTS radreply_username_idx ON radreply(username);

CREATE TABLE IF NOT EXISTS radacct (
  radacctid bigserial PRIMARY KEY,
  acctsessionid text NOT NULL,
  acctuniqueid text NOT NULL UNIQUE,
  username text NOT NULL,
  groupname text NOT NULL DEFAULT '',
  realm text DEFAULT '',
  nasipaddress inet,
  nasportid text,
  nasporttype text,
  acctstarttime timestamp NULL,
  acctupdatetime timestamp NULL,
  acctstoptime timestamp NULL,
  acctinterval integer NULL,
  acctsessiontime integer NULL,
  acctauthentic text,
  connectinfo_start text,
  connectinfo_stop text,
  acctinputoctets bigint DEFAULT 0,
  acctoutputoctets bigint DEFAULT 0,
  calledstationid text,
  callingstationid text,
  acctterminatecause text,
  servicetype text,
  framedprotocol text,
  framedipaddress inet,
  framedipv6address inet,
  framedipv6prefix inet,
  framedinterfaceid text,
  delegatedipv6prefix inet
);

CREATE INDEX IF NOT EXISTS radacct_username_idx ON radacct(username);
CREATE INDEX IF NOT EXISTS radacct_acctsessionid_idx ON radacct(acctsessionid);
CREATE INDEX IF NOT EXISTS radacct_acctstoptime_idx ON radacct(acctstoptime);

CREATE TABLE IF NOT EXISTS nas (
  id bigserial PRIMARY KEY,
  nasname text NOT NULL UNIQUE,
  shortname text NOT NULL,
  type text NOT NULL DEFAULT 'other',
  ports integer NULL,
  secret text NOT NULL,
  server text,
  community text,
  description text
);
