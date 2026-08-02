CREATE TABLE IF NOT EXISTS radusergroup (
  username text NOT NULL,
  groupname text NOT NULL,
  priority integer NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS radusergroup_username_idx ON radusergroup(username);

CREATE TABLE IF NOT EXISTS radpostauth (
  id bigserial PRIMARY KEY,
  username text NOT NULL,
  pass text,
  reply text,
  authdate timestamp NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS radpostauth_username_idx ON radpostauth(username);
CREATE INDEX IF NOT EXISTS radpostauth_authdate_idx ON radpostauth(authdate);

CREATE OR REPLACE FUNCTION noblifi_consume_voucher_on_radius_accept()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.reply ILIKE 'Access-Accept%' THEN
    UPDATE vouchers
       SET status = 'used',
           used_at = COALESCE(used_at, now()),
           updated_at = now()
     WHERE code = NEW.username
       AND status IN ('unused', 'active');

    DELETE FROM radcheck WHERE username = NEW.username;
    DELETE FROM radreply WHERE username = NEW.username;
    DELETE FROM radusergroup WHERE username = NEW.username;
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS consume_voucher_on_radius_accept ON radpostauth;

CREATE TRIGGER consume_voucher_on_radius_accept
AFTER INSERT ON radpostauth
FOR EACH ROW
EXECUTE FUNCTION noblifi_consume_voucher_on_radius_accept();
