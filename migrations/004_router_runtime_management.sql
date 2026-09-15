ALTER TABLE routers ADD COLUMN IF NOT EXISTS remote_access_expires_at timestamp NULL;
ALTER TABLE routers ADD COLUMN IF NOT EXISTS uptime_seconds bigint NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_routers_remote_winbox_port_active
  ON routers(remote_winbox_port)
  WHERE remote_winbox_port IS NOT NULL AND deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS router_delete_challenges (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  router_id uuid NOT NULL REFERENCES routers(id) ON DELETE RESTRICT,
  actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  expected_hash text NOT NULL,
  expires_at timestamp NOT NULL,
  used_at timestamp NULL,
  created_at timestamp NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_router_delete_challenges_router_id
  ON router_delete_challenges(router_id);
CREATE INDEX IF NOT EXISTS idx_router_delete_challenges_actor_user_id
  ON router_delete_challenges(actor_user_id);
CREATE INDEX IF NOT EXISTS idx_router_delete_challenges_expires_at
  ON router_delete_challenges(expires_at);
