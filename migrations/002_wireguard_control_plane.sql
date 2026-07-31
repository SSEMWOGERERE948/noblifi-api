CREATE TABLE IF NOT EXISTS wire_guard_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  router_id uuid NOT NULL REFERENCES routers(id),
  operation text NOT NULL,
  status text NOT NULL DEFAULT 'queued',
  public_key text NOT NULL DEFAULT '',
  allowed_ip text NOT NULL DEFAULT '',
  attempt_count integer NOT NULL DEFAULT 0,
  max_attempts integer NOT NULL DEFAULT 5,
  last_error text NOT NULL DEFAULT '',
  locked_by text NOT NULL DEFAULT '',
  locked_at timestamp NULL,
  available_at timestamp NOT NULL DEFAULT now(),
  completed_at timestamp NULL,
  created_at timestamp NOT NULL DEFAULT now(),
  updated_at timestamp NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_wire_guard_jobs_router_id ON wire_guard_jobs(router_id);
CREATE INDEX IF NOT EXISTS idx_wire_guard_jobs_operation ON wire_guard_jobs(operation);
CREATE INDEX IF NOT EXISTS idx_wire_guard_jobs_status ON wire_guard_jobs(status);
CREATE INDEX IF NOT EXISTS idx_wire_guard_jobs_available_at ON wire_guard_jobs(available_at);
CREATE INDEX IF NOT EXISTS idx_wire_guard_jobs_allowed_ip ON wire_guard_jobs(allowed_ip);
CREATE UNIQUE INDEX IF NOT EXISTS idx_wire_guard_jobs_active_unique
  ON wire_guard_jobs(router_id, operation)
  WHERE status IN ('queued', 'claimed', 'applying', 'retrying');

CREATE TABLE IF NOT EXISTS agent_heartbeats (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id text UNIQUE NOT NULL,
  version text NOT NULL DEFAULT '',
  wire_guard_interface text NOT NULL DEFAULT '',
  wireguard_public_key varchar(128) NOT NULL DEFAULT '',
  peer_count integer NOT NULL DEFAULT 0,
  healthy boolean NOT NULL DEFAULT false,
  last_reconciliation timestamp NULL,
  last_seen_at timestamp NOT NULL DEFAULT now(),
  created_at timestamp NOT NULL DEFAULT now(),
  updated_at timestamp NOT NULL DEFAULT now()
);

ALTER TABLE agent_heartbeats
  ADD COLUMN IF NOT EXISTS wireguard_interface text NOT NULL DEFAULT '';

ALTER TABLE agent_heartbeats
  ADD COLUMN IF NOT EXISTS wireguard_public_key varchar(128) NOT NULL DEFAULT '';

ALTER TABLE routers ADD COLUMN IF NOT EXISTS wire_guard_peer_status text NOT NULL DEFAULT 'waiting_for_router_key';
ALTER TABLE routers ADD COLUMN IF NOT EXISTS wire_guard_peer_updated_at timestamp NULL;
ALTER TABLE routers ADD COLUMN IF NOT EXISTS wire_guard_last_handshake_at timestamp NULL;
ALTER TABLE routers ADD COLUMN IF NOT EXISTS wire_guard_last_error text NULL;
ALTER TABLE routers ADD COLUMN IF NOT EXISTS provisioning_status text NOT NULL DEFAULT 'pending';
ALTER TABLE routers ADD COLUMN IF NOT EXISTS provisioning_error text NULL;
ALTER TABLE routers ADD COLUMN IF NOT EXISTS delete_requested_at timestamp NULL;
ALTER TABLE routers ADD COLUMN IF NOT EXISTS deleted_at timestamp NULL;

CREATE INDEX IF NOT EXISTS idx_routers_wire_guard_peer_status ON routers(wire_guard_peer_status);
CREATE INDEX IF NOT EXISTS idx_routers_provisioning_status ON routers(provisioning_status);
CREATE INDEX IF NOT EXISTS idx_routers_deleted_at ON routers(deleted_at);
ALTER TABLE routers DROP CONSTRAINT IF EXISTS routers_wire_guard_tunnel_ip_key;
DROP INDEX IF EXISTS uni_routers_wire_guard_tunnel_ip;
DROP INDEX IF EXISTS idx_routers_wire_guard_tunnel_ip;
CREATE UNIQUE INDEX IF NOT EXISTS idx_routers_wireguard_tunnel_ip_unique
  ON routers (wire_guard_tunnel_ip)
  WHERE wire_guard_tunnel_ip IS NOT NULL
    AND deleted_at IS NULL;
