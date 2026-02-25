ALTER TABLE servers
    ADD COLUMN IF NOT EXISTS user_id uuid NULL REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE uptime_monitors
    ADD COLUMN IF NOT EXISTS user_id uuid NULL REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE notification_settings
    ADD COLUMN IF NOT EXISTS user_id uuid NULL REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS user_id uuid NULL REFERENCES users(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_servers_user_id_created_at_desc ON servers (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_uptime_monitors_user_id_created_at_desc ON uptime_monitors (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notification_settings_user_id_created_at_desc ON notification_settings (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_user_id_ts_desc ON alerts (user_id, ts DESC);

ALTER TABLE notification_settings DROP CONSTRAINT IF EXISTS notification_settings_email_key;
ALTER TABLE notification_settings
    ADD CONSTRAINT notification_settings_user_id_email_key UNIQUE (user_id, email);

UPDATE servers
SET user_id = (SELECT id FROM users ORDER BY created_at ASC LIMIT 1)
WHERE user_id IS NULL
  AND 1 = (SELECT COUNT(*) FROM users);

UPDATE uptime_monitors
SET user_id = (SELECT id FROM users ORDER BY created_at ASC LIMIT 1)
WHERE user_id IS NULL
  AND 1 = (SELECT COUNT(*) FROM users);

UPDATE notification_settings
SET user_id = (SELECT id FROM users ORDER BY created_at ASC LIMIT 1)
WHERE user_id IS NULL
  AND 1 = (SELECT COUNT(*) FROM users);

UPDATE alerts a
SET user_id = s.user_id
FROM servers s
WHERE a.user_id IS NULL
  AND a.server_id = s.id
  AND s.user_id IS NOT NULL;

UPDATE alerts a
SET user_id = um.user_id
FROM uptime_monitors um
WHERE a.user_id IS NULL
  AND a.uptime_monitor_id = um.id
  AND um.user_id IS NOT NULL;
