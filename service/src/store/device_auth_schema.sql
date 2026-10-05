CREATE TABLE IF NOT EXISTS cli_authorizations (
    device_hash TEXT PRIMARY KEY,
    user_code TEXT NOT NULL UNIQUE,
    device_name TEXT NOT NULL,
    expected_user TEXT NOT NULL DEFAULT '',
    expires_at BIGINT NOT NULL,
    next_poll BIGINT NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','approved','denied')),
    approved_user TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_cli_authorizations_expiry ON cli_authorizations(expires_at);
